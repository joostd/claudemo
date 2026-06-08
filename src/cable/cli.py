"""Command-line entry point: orchestrates the full hybrid-transport flow.

    1. Generate an ephemeral identity keypair and a random 16-byte QR secret.
    2. Build and display the `FIDO:/...` QR code as ASCII art.
    3. Wait for the phone's BLE advertisement -- a *hard prerequisite* of the
       QR-initiated flow (CTAP 2.3 sctn-hybrid): it is the only source of the
       routing ID (needed to address the tunnel) and the Noise PSK salt.
    4. Connect to the tunnel server (addressed via that routing ID) and run
       the Noise handshake, salted with the decrypted advertisement.
    5. Read the mandatory post-handshake message (cached `getInfo` response).
    6. Wrap the resulting encrypted channel in a `CtapHybridDevice` and
       drive it with `fido2.ctap2.Ctap2` to perform the requested operation.
"""

from __future__ import annotations

import hashlib
import secrets
import time

import cbor2
import click

from . import qr
from .constants import (
    REQUEST_TYPE_GET_ASSERTION,
    REQUEST_TYPE_MAKE_CREDENTIAL,
)
from .crypto import noise
from .crypto.eid import parse_plaintext_eid
from .crypto.kdf import derive_eid_key, derive_psk, derive_tunnel_id
from .device import CtapHybridDevice, _BackgroundLoop
from .transport import ble
from .transport.channel import CableChannel
from .transport.tunnel import TunnelConnection, tunnel_url


def _log(message: str) -> None:
    click.echo(click.style("==> ", fg="cyan", bold=True) + message, err=True)


async def _connect_and_handshake(*, request_type: str, debug_noise: bool):
    """Run the QR-initiated connection flow end to end (CTAP 2.3 sctn-hybrid).

    Returns `(channel, handshake_result)`. Unlike a "best-effort proximity
    check", BLE advertisement reception is a *hard prerequisite* here: the
    decrypted advertisement supplies both the routing ID (to address the
    tunnel) and the salt for the Noise PSK, so nothing else can proceed
    without it.
    """
    qr_secret = secrets.token_bytes(16)
    keypair = noise.generate_keypair()
    peer_identity = noise.serialize_public_key_compressed(keypair.private_key.public_key())

    handshake = qr.HandshakeV2(
        peer_identity=peer_identity,
        secret=qr_secret,
        timestamp=int(time.time()),
        request_type=request_type,
    )
    uri = qr.build_fido_uri(handshake)

    click.echo()
    qr.render_qr_ascii(uri)
    click.echo()
    _log("Scan this QR code with your phone's authenticator app.")
    _log(f"URI: {uri}")
    click.echo()

    eid_key = derive_eid_key(qr_secret)
    _log("Waiting for the phone's BLE advertisement (carries the routing ID and proves proximity)...")
    advert_plaintext = await ble.scan_for_eid(eid_key)
    if advert_plaintext is None:
        raise RuntimeError(
            "no matching BLE advertisement was seen. The QR-initiated hybrid "
            "flow cannot proceed without one -- it is the only source of the "
            "routing ID and the Noise PSK salt (see CTAP 2.3 sctn-hybrid)."
        )
    _log("BLE advertisement received and verified ✓")

    advert = parse_plaintext_eid(advert_plaintext)
    routing_id = advert["routing_id"]
    domain_id = advert["tunnel_server_id"]
    _log(
        f"Decrypted advertisement: nonce={advert['nonce'].hex()} "
        f"routing_id={routing_id.hex().upper()} domain_id={domain_id} "
        f"(plaintext={advert_plaintext.hex()})"
    )

    tunnel_id = derive_tunnel_id(qr_secret)
    _log(f"Derived tunnel_id={tunnel_id.hex().upper()} from qr_secret={qr_secret.hex()}")
    url = tunnel_url(domain_id, routing_id, tunnel_id)

    _log(f"Connecting to tunnel server ({url})...")
    tunnel = await TunnelConnection.connect(url)
    _log(
        f"Connected (selected subprotocol={getattr(tunnel._websocket, 'subprotocol', None)!r}, "
        f"routing-id header={tunnel.routing_id!r}). Starting Noise handshake..."
    )

    def _log_noise_step(step, snapshot):
        _log(f"[noise:{step}] chaining_key={snapshot['chaining_key']} hash={snapshot['hash']}")

    debug_log = _log_noise_step if debug_noise else None

    # The PSK is salted with the full 16-byte decrypted BLE advertisement
    # (CTAP 2.3 sctn-hybrid: "The full BLE advert is included in the PSK
    # derivation to ensure that any future additions to the advert format
    # are automatically authenticated").
    psk = derive_psk(qr_secret, eid=advert_plaintext)

    handshake_state = noise.NoiseHandshake(
        pattern=noise.PATTERN_KN_PSK0,
        role="initiator",
        local_static=keypair,
        psk=psk,
        debug_log=debug_log,
    )

    first_message = handshake_state.write_message()
    _log(f"Sending first handshake message ({len(first_message)} bytes: {first_message.hex()})...")
    await tunnel.send(first_message)
    _log("First handshake message sent; awaiting response...")

    response = await tunnel.recv()
    _log(f"Received handshake response ({len(response)} bytes: {response.hex()}).")
    handshake_state.read_message(response)

    if not handshake_state.is_complete():
        raise RuntimeError(
            "Noise handshake pattern expected more messages than the "
            "two-message exchange implemented here -- protocol assumption "
            "mismatch (see crypto/noise.py HANDSHAKE_PATTERNS)."
        )

    result = handshake_state.finish()
    _log("Noise handshake complete; tunnel is now end-to-end encrypted.")

    channel = CableChannel(tunnel, send_cipher=result.send_cipher, receive_cipher=result.receive_cipher)

    # The authenticator's first message is a bare (non-type-byte-framed) CBOR
    # map carrying its cached authenticatorGetInfo response, sent to save a
    # round trip. We must read and validate it before any typed CTAP exchange
    # begins, or the channel will desync from the authenticator's framing.
    post_handshake = cbor2.loads(await channel.recv_post_handshake())
    if not isinstance(post_handshake, dict) or post_handshake.get(1) is None:
        raise RuntimeError(
            "post-handshake message did not contain a cached authenticatorGetInfo "
            "response (CBOR map key 1) -- protocol framing mismatch."
        )
    _log("Received post-handshake message (cached authenticatorGetInfo response).")

    return channel, result


def _client_data_hash(challenge: bytes) -> bytes:
    return hashlib.sha256(challenge).digest()


@click.group()
def main() -> None:
    """FIDO client over hybrid transport (caBLE v2): talk CTAP2 to a phone."""


@main.command("qr")
@click.option("--request-type", type=click.Choice(["ga", "mc"]), default=REQUEST_TYPE_GET_ASSERTION)
def show_qr(request_type: str) -> None:
    """Display the FIDO:/ QR code only, without connecting to anything."""
    qr_secret = secrets.token_bytes(16)
    keypair = noise.generate_keypair()
    handshake = qr.HandshakeV2(
        peer_identity=noise.serialize_public_key_compressed(keypair.private_key.public_key()),
        secret=qr_secret,
        timestamp=int(time.time()),
        request_type=request_type,
    )
    uri = qr.build_fido_uri(handshake)
    click.echo()
    qr.render_qr_ascii(uri)
    click.echo()
    click.echo(f"URI: {uri}")


@main.command("get-info")
@click.option("--debug-noise", is_flag=True, help="Log Noise handshake transcript values.")
def get_info(debug_noise: bool) -> None:
    """Connect to a phone and print its authenticatorGetInfo response."""
    _run_session(
        request_type=REQUEST_TYPE_GET_ASSERTION,
        debug_noise=debug_noise,
        action=lambda ctap2: click.echo(ctap2.info),
    )


@main.command("get-assertion")
@click.option("--rp-id", required=True)
@click.option("--challenge", required=True, help="Challenge string (will be SHA-256 hashed).")
@click.option("--debug-noise", is_flag=True, help="Log Noise handshake transcript values.")
def get_assertion(rp_id: str, challenge: str, debug_noise: bool) -> None:
    """Request a CTAP2 GetAssertion from the phone."""

    def action(ctap2):
        response = ctap2.get_assertion(rp_id, _client_data_hash(challenge.encode()))
        click.echo(response)

    _run_session(
        request_type=REQUEST_TYPE_GET_ASSERTION,
        debug_noise=debug_noise,
        action=action,
    )


@main.command("make-credential")
@click.option("--rp-id", required=True)
@click.option("--rp-name", default="")
@click.option("--user-id", required=True, help="User ID string (will be UTF-8 encoded).")
@click.option("--user-name", required=True)
@click.option("--challenge", required=True, help="Challenge string (will be SHA-256 hashed).")
@click.option("--debug-noise", is_flag=True, help="Log Noise handshake transcript values.")
def make_credential(
    rp_id: str,
    rp_name: str,
    user_id: str,
    user_name: str,
    challenge: str,
    debug_noise: bool,
) -> None:
    """Request a CTAP2 MakeCredential from the phone."""

    def action(ctap2):
        response = ctap2.make_credential(
            client_data_hash=_client_data_hash(challenge.encode()),
            rp={"id": rp_id, "name": rp_name or rp_id},
            user={"id": user_id.encode(), "name": user_name},
            key_params=[{"type": "public-key", "alg": -7}],
        )
        click.echo(response)

    _run_session(
        request_type=REQUEST_TYPE_MAKE_CREDENTIAL,
        debug_noise=debug_noise,
        action=action,
    )


def _run_session(*, request_type, debug_noise, action) -> None:
    from fido2.ctap import CtapError
    from fido2.ctap2.base import Ctap2
    from websockets.exceptions import WebSocketException

    loop = _BackgroundLoop()
    device = None
    try:
        try:
            channel, _result = loop.run(
                _connect_and_handshake(
                    request_type=request_type,
                    debug_noise=debug_noise,
                )
            )

            device = CtapHybridDevice(channel, background_loop=loop)
            ctap2 = Ctap2(device)
            action(ctap2)
        except (OSError, WebSocketException) as exc:
            raise click.ClickException(f"could not reach the tunnel server: {exc}") from exc
        except CtapError as exc:
            raise click.ClickException(f"authenticator returned an error: {exc}") from exc
        except (NotImplementedError, RuntimeError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
    finally:
        if device is not None:
            device.close()
        else:
            loop.stop()


if __name__ == "__main__":
    main()
