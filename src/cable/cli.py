"""Command-line entry point: orchestrates the full hybrid-transport flow.

    1. Generate an ephemeral P-256 keypair and a random 16-byte QR secret.
    2. Build and display the `FIDO:/...` QR code as ASCII art.
    3. Connect to the tunnel server and run the Noise handshake.
    4. (best-effort, non-blocking) scan for the phone's BLE advertisement.
    5. Wrap the resulting encrypted channel in a `CtapHybridDevice` and
       drive it with `fido2.ctap2.Ctap2` to perform the requested operation.
"""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time

import click

from . import qr
from .constants import (
    REQUEST_TYPE_GET_ASSERTION,
    REQUEST_TYPE_MAKE_CREDENTIAL,
)
from .crypto import noise
from .crypto.kdf import derive_psk, derive_tunnel_id
from .device import CtapHybridDevice, _BackgroundLoop
from .transport import ble
from .transport.tunnel import TunnelConnection, tunnel_url

DEFAULT_TUNNEL_DOMAIN_ID = 0  # cable.ua5v.com (Google)


def _log(message: str) -> None:
    click.echo(click.style("==> ", fg="cyan", bold=True) + message, err=True)


async def _connect_and_handshake(
    *, request_type: str, domain_id: int, debug_noise: bool, no_ble: bool
):
    """Run steps 2-4 of the flow; returns (tunnel, handshake_result)."""
    qr_secret = secrets.token_bytes(16)
    keypair = noise.generate_keypair()

    handshake = qr.HandshakeV2(
        peer_identity=keypair.public_bytes,
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

    ble_task = None
    if not no_ble:
        from .crypto.kdf import derive_eid_key

        _log("Listening for the phone's BLE advertisement (best-effort proximity check)...")
        ble_task = asyncio.ensure_future(ble.scan_for_eid(derive_eid_key(qr_secret)))

    tunnel_id = derive_tunnel_id(qr_secret)
    url = tunnel_url(domain_id, tunnel_id)

    _log(f"Connecting to tunnel server ({url})...")
    tunnel = await TunnelConnection.connect(url)
    _log("Connected. Waiting for phone to join and starting Noise handshake...")

    def _log_noise_step(step, snapshot):
        _log(f"[noise:{step}] chaining_key={snapshot['chaining_key']} hash={snapshot['hash']}")

    debug_log = _log_noise_step if debug_noise else None

    # The PSK is salted with the (as-yet-unknown) EID in the reference
    # implementation; for the QR-initiated flow without a confirmed BLE
    # advertisement we fall back to deriving it salted with the QR secret
    # alone. This is one of the documented points of protocol uncertainty
    # (see crypto/noise.py and CLAUDE.md) -- adjust here if real-device
    # testing shows the phone expects EID-salted PSK derivation instead.
    psk = derive_psk(qr_secret, eid=b"")

    handshake_state = noise.NoiseHandshake(
        pattern=noise.PATTERN_KN_PSK0,
        role="initiator",
        local_static=keypair,
        local_ephemeral=keypair,
        psk=psk,
        debug_log=debug_log,
    )

    first_message = handshake_state.write_message()
    await tunnel.send_message(0x01, first_message)

    response = await tunnel.recv_message()
    handshake_state.read_message(response.payload)

    if not handshake_state.is_complete():
        raise RuntimeError(
            "Noise handshake pattern expected more messages than the "
            "two-message exchange implemented here -- protocol assumption "
            "mismatch (see crypto/noise.py HANDSHAKE_PATTERNS)."
        )

    result = handshake_state.finish()
    _log("Noise handshake complete; tunnel is now end-to-end encrypted.")

    if ble_task is not None:
        if ble_task.done() and ble_task.result() is not None:
            _log("BLE proximity check: matching advertisement seen ✓")
        else:
            ble_task.cancel()
            _log("BLE proximity check: no matching advertisement seen (continuing anyway)")

    return tunnel, result


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
        peer_identity=keypair.public_bytes,
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
@click.option("--domain-id", type=int, default=DEFAULT_TUNNEL_DOMAIN_ID)
@click.option("--no-ble", is_flag=True, help="Skip the BLE proximity check.")
@click.option("--debug-noise", is_flag=True, help="Log Noise handshake transcript values.")
def get_info(domain_id: int, no_ble: bool, debug_noise: bool) -> None:
    """Connect to a phone and print its authenticatorGetInfo response."""
    _run_session(
        request_type=REQUEST_TYPE_GET_ASSERTION,
        domain_id=domain_id,
        no_ble=no_ble,
        debug_noise=debug_noise,
        action=lambda ctap2: click.echo(ctap2.info),
    )


@main.command("get-assertion")
@click.option("--rp-id", required=True)
@click.option("--challenge", required=True, help="Challenge string (will be SHA-256 hashed).")
@click.option("--domain-id", type=int, default=DEFAULT_TUNNEL_DOMAIN_ID)
@click.option("--no-ble", is_flag=True, help="Skip the BLE proximity check.")
@click.option("--debug-noise", is_flag=True, help="Log Noise handshake transcript values.")
def get_assertion(rp_id: str, challenge: str, domain_id: int, no_ble: bool, debug_noise: bool) -> None:
    """Request a CTAP2 GetAssertion from the phone."""

    def action(ctap2):
        response = ctap2.get_assertion(rp_id, _client_data_hash(challenge.encode()))
        click.echo(response)

    _run_session(
        request_type=REQUEST_TYPE_GET_ASSERTION,
        domain_id=domain_id,
        no_ble=no_ble,
        debug_noise=debug_noise,
        action=action,
    )


@main.command("make-credential")
@click.option("--rp-id", required=True)
@click.option("--rp-name", default="")
@click.option("--user-id", required=True, help="User ID string (will be UTF-8 encoded).")
@click.option("--user-name", required=True)
@click.option("--challenge", required=True, help="Challenge string (will be SHA-256 hashed).")
@click.option("--domain-id", type=int, default=DEFAULT_TUNNEL_DOMAIN_ID)
@click.option("--no-ble", is_flag=True, help="Skip the BLE proximity check.")
@click.option("--debug-noise", is_flag=True, help="Log Noise handshake transcript values.")
def make_credential(
    rp_id: str,
    rp_name: str,
    user_id: str,
    user_name: str,
    challenge: str,
    domain_id: int,
    no_ble: bool,
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
        domain_id=domain_id,
        no_ble=no_ble,
        debug_noise=debug_noise,
        action=action,
    )


def _run_session(*, request_type, domain_id, no_ble, debug_noise, action) -> None:
    from fido2.ctap import CtapError
    from fido2.ctap2.base import Ctap2
    from websockets.exceptions import WebSocketException

    loop = _BackgroundLoop()
    device = None
    try:
        try:
            tunnel, result = loop.run(
                _connect_and_handshake(
                    request_type=request_type,
                    domain_id=domain_id,
                    debug_noise=debug_noise,
                    no_ble=no_ble,
                )
            )

            device = CtapHybridDevice(
                tunnel,
                send_cipher=result.send_cipher,
                receive_cipher=result.receive_cipher,
                background_loop=loop,
            )
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
