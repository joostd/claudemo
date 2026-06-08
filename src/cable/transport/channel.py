"""Encrypted, padded, type-framed application channel over a caBLE tunnel.

Per CTAP 2.3 sctn-hybrid "Data Transfer", once the Noise handshake completes
every message is built as `[type byte] || payload`, padded to a multiple of
`TRANSPORT_PADDING_GRANULARITY` bytes (final byte = padding length minus
one), and AES-256-GCM encrypted with the per-direction traffic cipher and a
big-endian counter nonce -- with the *whole* padded plaintext (type byte
included) inside the ciphertext. Each encrypted blob is one binary WebSocket
frame. `CableChannel` wraps a raw `TunnelConnection` plus the two derived
traffic ciphers to provide that abstraction.

The very first message from the authenticator -- the "post-handshake"
message containing its cached `authenticatorGetInfo` response -- is the
exception: it is encrypted/padded the same way but carries *no* type byte
(it's a bare CBOR map). `recv_post_handshake` reads it before any typed
messages are exchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.noise import CipherState, pad_message, unpad_message
from .tunnel import TunnelConnection


@dataclass
class CableMessage:
    frame_type: int
    payload: bytes


class CableChannel:
    """The encrypted application-message channel established post-handshake."""

    def __init__(self, tunnel: TunnelConnection, *, send_cipher: CipherState, receive_cipher: CipherState) -> None:
        self._tunnel = tunnel
        self._send_cipher = send_cipher
        self._receive_cipher = receive_cipher

    async def _send_plaintext(self, plaintext: bytes) -> None:
        ciphertext = self._send_cipher.encrypt_with_ad(b"", pad_message(plaintext))
        await self._tunnel.send(ciphertext)

    async def _recv_plaintext(self) -> bytes:
        ciphertext = await self._tunnel.recv()
        return unpad_message(self._receive_cipher.decrypt_with_ad(b"", ciphertext))

    async def recv_post_handshake(self) -> bytes:
        """Read the raw post-handshake message (a bare CBOR map, no type byte)."""
        return await self._recv_plaintext()

    async def send_message(self, frame_type: int, payload: bytes = b"") -> None:
        await self._send_plaintext(bytes([frame_type]) + payload)

    async def recv_message(self) -> CableMessage:
        plaintext = await self._recv_plaintext()
        if not plaintext:
            raise ValueError("received empty cable message (missing type byte)")
        return CableMessage(frame_type=plaintext[0], payload=plaintext[1:])

    async def close(self) -> None:
        await self._tunnel.close()


__all__ = ["CableChannel", "CableMessage"]
