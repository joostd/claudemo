"""Validate `CableChannel`'s padding + type-byte framing layered over a raw
tunnel, using a passthrough cipher so the encryption itself isn't on test --
only the plaintext shape (padding, type byte) that goes in/comes out of it.
"""

import asyncio

import pytest

from cable.constants import CableFrameType
from cable.crypto.noise import CipherState, pad_message, unpad_message
from cable.transport.channel import CableChannel, CableMessage


class _PassthroughCipher(CipherState):
    def encrypt_with_ad(self, ad, plaintext):
        return plaintext

    def decrypt_with_ad(self, ad, ciphertext):
        return ciphertext


class _FakeTunnel:
    def __init__(self, incoming=None):
        self._incoming = list(incoming or [])
        self.sent: list[bytes] = []
        self.closed = False

    async def send(self, data):
        self.sent.append(data)

    async def recv(self):
        if not self._incoming:
            raise asyncio.CancelledError("no more fake frames")
        return self._incoming.pop(0)

    async def close(self):
        self.closed = True


def _channel(incoming=None):
    tunnel = _FakeTunnel(incoming)
    return tunnel, CableChannel(tunnel, send_cipher=_PassthroughCipher(), receive_cipher=_PassthroughCipher())


@pytest.mark.asyncio
async def test_send_message_pads_and_prefixes_type_byte():
    tunnel, channel = _channel()

    await channel.send_message(CableFrameType.CTAP, b"hello")

    assert len(tunnel.sent) == 1
    assert unpad_message(tunnel.sent[0]) == bytes([CableFrameType.CTAP]) + b"hello"


@pytest.mark.asyncio
async def test_recv_message_splits_frame_type_and_payload():
    plaintext = bytes([CableFrameType.CTAP]) + b"world"
    _, channel = _channel(incoming=[pad_message(plaintext)])

    message = await channel.recv_message()

    assert message == CableMessage(frame_type=CableFrameType.CTAP, payload=b"world")


@pytest.mark.asyncio
async def test_recv_message_rejects_empty_frame():
    _, channel = _channel(incoming=[pad_message(b"")])

    with pytest.raises(ValueError):
        await channel.recv_message()


@pytest.mark.asyncio
async def test_recv_post_handshake_returns_raw_unpadded_plaintext():
    _, channel = _channel(incoming=[pad_message(b"\xa1\x01\x02")])

    assert await channel.recv_post_handshake() == b"\xa1\x01\x02"


@pytest.mark.asyncio
async def test_close_closes_underlying_tunnel():
    tunnel, channel = _channel()

    await channel.close()

    assert tunnel.closed is True


def test_pad_unpad_round_trip_across_lengths():
    for length in range(0, 70):
        plaintext = bytes(range(length % 256)) if length else b""
        plaintext = plaintext[:length] if len(plaintext) >= length else plaintext + b"\x00" * (length - len(plaintext))
        padded = pad_message(plaintext)
        assert len(padded) % 32 == 0
        assert len(padded) >= len(plaintext) + 1
        assert unpad_message(padded) == plaintext
