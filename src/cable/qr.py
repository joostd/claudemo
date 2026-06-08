"""HandshakeV2 payload encoding and ASCII QR-code rendering.

The desktop side of hybrid transport advertises itself by displaying a QR
code containing a `FIDO:/<digits>` URI. The digits are a base10 encoding
(see `base10`) of a CBOR-encoded `HandshakeV2` map (see `constants` for the
field layout).
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field

import cbor2
import pyqrcode

from . import base10
from .constants import (
    FIDO_URI_PREFIX,
    HANDSHAKE_FIELD_KNOWN_DOMAINS_COUNT,
    HANDSHAKE_FIELD_PEER_IDENTITY,
    HANDSHAKE_FIELD_REQUEST_TYPE,
    HANDSHAKE_FIELD_SECRET,
    HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS,
    HANDSHAKE_FIELD_SUPPORTS_LINKING_INFO,
    HANDSHAKE_FIELD_TIMESTAMP,
    KNOWN_TUNNEL_DOMAINS,
    QR_PEER_IDENTITY_SIZE,
    QR_SECRET_SIZE,
    REQUEST_TYPE_GET_ASSERTION,
    TRANSPORT_CHANNEL_WEBSOCKET,
)


@dataclass
class HandshakeV2:
    """The payload encoded into a hybrid-transport QR code."""

    peer_identity: bytes  # 33-byte compressed X9.62 P-256 public key point
    secret: bytes = field(default=b"")  # 16 random "QR secret" bytes
    timestamp: int = field(default_factory=lambda: int(time.time()))
    request_type: str = REQUEST_TYPE_GET_ASSERTION
    known_domains_count: int = len(KNOWN_TUNNEL_DOMAINS)
    supports_linking_info: bool = False
    supported_transports: list[int] = field(default_factory=lambda: [TRANSPORT_CHANNEL_WEBSOCKET])

    def __post_init__(self) -> None:
        if len(self.secret) != QR_SECRET_SIZE:
            raise ValueError(
                f"QR secret must be {QR_SECRET_SIZE} bytes, got {len(self.secret)}"
            )
        if len(self.peer_identity) != QR_PEER_IDENTITY_SIZE:
            raise ValueError(
                f"peer identity must be a {QR_PEER_IDENTITY_SIZE}-byte compressed "
                f"public key, got {len(self.peer_identity)} bytes"
            )


def encode_handshake(handshake: HandshakeV2) -> bytes:
    """CBOR-encode a `HandshakeV2` as the caBLE v2 wire format expects."""
    cbor_map = {
        HANDSHAKE_FIELD_PEER_IDENTITY: handshake.peer_identity,
        HANDSHAKE_FIELD_SECRET: handshake.secret,
        HANDSHAKE_FIELD_KNOWN_DOMAINS_COUNT: handshake.known_domains_count,
        HANDSHAKE_FIELD_TIMESTAMP: handshake.timestamp,
        HANDSHAKE_FIELD_SUPPORTS_LINKING_INFO: handshake.supports_linking_info,
        HANDSHAKE_FIELD_REQUEST_TYPE: handshake.request_type,
        HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS: list(handshake.supported_transports),
    }
    return cbor2.dumps(cbor_map, canonical=True)


def decode_handshake(data: bytes) -> HandshakeV2:
    """Inverse of `encode_handshake`, mainly useful for tests/debugging."""
    cbor_map = cbor2.loads(data)
    return HandshakeV2(
        peer_identity=cbor_map[HANDSHAKE_FIELD_PEER_IDENTITY],
        secret=cbor_map[HANDSHAKE_FIELD_SECRET],
        known_domains_count=cbor_map[HANDSHAKE_FIELD_KNOWN_DOMAINS_COUNT],
        timestamp=cbor_map[HANDSHAKE_FIELD_TIMESTAMP],
        supports_linking_info=cbor_map[HANDSHAKE_FIELD_SUPPORTS_LINKING_INFO],
        request_type=cbor_map[HANDSHAKE_FIELD_REQUEST_TYPE],
        supported_transports=list(cbor_map[HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS]),
    )


def build_fido_uri(handshake: HandshakeV2) -> str:
    """Build the `FIDO:/<digits>` URI string for a `HandshakeV2`."""
    cbor_bytes = encode_handshake(handshake)
    return FIDO_URI_PREFIX + base10.encode(cbor_bytes)


def render_qr_ascii(uri: str, *, out=None) -> None:
    """Render `uri` as an ANSI-art QR code to a stream (default: stdout).

    `FIDO:/<digits>` URIs only ever contain characters from the QR
    alphanumeric character set, so we can pin `mode='alphanumeric'` (denser
    encoding, smaller code) and `error='L'` (least redundancy, smaller code).
    """
    if out is None:
        out = sys.stdout

    code = pyqrcode.create(uri, mode="alphanumeric", error="L")
    out.write(code.terminal(quiet_zone=1))


__all__ = [
    "HandshakeV2",
    "encode_handshake",
    "decode_handshake",
    "build_fido_uri",
    "render_qr_ascii",
]
