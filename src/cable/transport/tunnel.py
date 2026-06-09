"""Raw WebSocket connection to a caBLE tunnel server.

Once a phone scans the QR code, it connects to a "tunnel server" -- a
WebSocket relay -- and the desktop connects to the same server/routing
address. The tunnel itself is a dumb byte pipe: every binary WebSocket frame
is either a Noise handshake message or (after the handshake) an encrypted,
padded, type-byte-framed application message -- see `transport.channel` for
that layer. `TunnelConnection` only handles the raw frame plumbing.
"""

from __future__ import annotations

import hashlib
import struct

import websockets

from ..constants import (
    KNOWN_TUNNEL_DOMAINS,
    TUNNEL_DOMAIN_BASE32_CHARS,
    TUNNEL_DOMAIN_HASH_PREFIX,
    TUNNEL_DOMAIN_TLDS,
    TUNNEL_ROUTING_ID_HEADER,
    TUNNEL_SUBPROTOCOL,
)


def decode_tunnel_server_domain(domain_id: int) -> str:
    """Compute the tunnel server hostname for a 'computed' domain ID (>= 256).

    CTAP 2.3 §11.5 `decodeTunnelServerDomain` / Chromium `DecodeDomain`:
    SHA-256(prefix || domain_id_LE16 || 0x00), first 8 bytes as uint64 LE;
    bottom 2 bits select the TLD, remaining bits are base32-encoded to form
    the label; the full hostname is "cable.<label>.<tld>".
    """
    if domain_id < 256:
        raise ValueError(
            f"domain_id {domain_id} is in the assigned range (0..255); "
            "use KNOWN_TUNNEL_DOMAINS for those IDs"
        )
    template = bytearray(31)
    template[:28] = TUNNEL_DOMAIN_HASH_PREFIX
    struct.pack_into("<H", template, 28, domain_id)
    digest = hashlib.sha256(bytes(template)).digest()
    result = struct.unpack_from("<Q", digest)[0]  # first 8 bytes as uint64 LE
    tld = TUNNEL_DOMAIN_TLDS[result & 3]
    result >>= 2
    label: list[str] = []
    while result != 0:
        label.append(TUNNEL_DOMAIN_BASE32_CHARS[result & 31])
        result >>= 5
    return "cable." + "".join(label) + "." + tld


def tunnel_url(domain_id: int, routing_id: bytes, tunnel_id: bytes) -> str:
    """Build the tunnel server WebSocket URL for a QR-initiated connection.

    Per CTAP 2.3 sctn-hybrid, the path is `/cable/connect/<routing id
    (hex)>/<tunnel id (hex)>`; the routing ID comes from the decrypted BLE
    advertisement (it cannot be known before that advertisement is seen).
    """
    if domain_id < 256:
        try:
            domain = KNOWN_TUNNEL_DOMAINS[domain_id]
        except KeyError as exc:
            raise ValueError(
                f"tunnel server domain id {domain_id} is in the assigned range (0..255) "
                f"but not present in KNOWN_TUNNEL_DOMAINS {sorted(KNOWN_TUNNEL_DOMAINS)}"
            ) from exc
    else:
        domain = decode_tunnel_server_domain(domain_id)
    # Chromium's `GetConnectURL` builds this path with `base::HexEncode`,
    # which produces *uppercase* hex digits (see v2_handshake.cc) -- both
    # sides must compute byte-identical URLs for the tunnel server to pair
    # them, so the case matters.
    return f"wss://{domain}/cable/connect/{routing_id.hex().upper()}/{tunnel_id.hex().upper()}"


class TunnelConnection:
    """Async context manager wrapping a caBLE tunnel server WebSocket.

    Exposes only raw binary-frame send/receive: the spec requires "messages
    are exchanged in binary WebSocket frames and no other frame types are
    permitted on the connection," with no tunnel-level framing of its own --
    all higher-level structure (Noise handshake messages, then encrypted
    type-byte-framed application messages) lives in the frame payloads.
    """

    def __init__(self, websocket) -> None:
        self._websocket = websocket
        self.routing_id: str | None = self._extract_routing_id(websocket)

    @staticmethod
    def _extract_routing_id(websocket) -> str | None:
        headers = getattr(websocket, "response_headers", None) or getattr(
            websocket, "response", None
        )
        if headers is None:
            return None
        try:
            return headers[TUNNEL_ROUTING_ID_HEADER]
        except (KeyError, TypeError):
            return None

    @classmethod
    async def connect(cls, url: str) -> "TunnelConnection":
        websocket = await websockets.connect(url, subprotocols=[TUNNEL_SUBPROTOCOL])
        return cls(websocket)

    async def __aenter__(self) -> "TunnelConnection":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    async def close(self) -> None:
        await self._websocket.close()

    async def send(self, data: bytes) -> None:
        await self._websocket.send(data)

    async def recv(self) -> bytes:
        frame = await self._websocket.recv()
        if isinstance(frame, str):
            frame = frame.encode("utf-8")
        return frame


__all__ = ["TunnelConnection", "tunnel_url", "decode_tunnel_server_domain"]
