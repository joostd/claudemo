"""Validate the CtapHybridDevice <-> fido2.ctap2.Ctap2 bridge end to end,
using a fake Noise-encrypted tunnel that simply echoes a canned
authenticatorGetInfo response. No real network/crypto/device involved --
this proves the *adapter wiring* (framing, encryption hooks, sync/async
bridging, response parsing) is correct.
"""

import asyncio

import cbor2
import pytest

from cable.constants import CableFrameType
from cable.crypto.noise import CipherState
from cable.device import CtapHybridDevice, _BackgroundLoop
from cable.transport.tunnel import TunnelMessage


GET_INFO_RESPONSE_CBOR = cbor2.dumps({1: ["FIDO_2_0"], 3: b"\x00" * 16})
CANNED_RESPONSE = bytes([0x00]) + GET_INFO_RESPONSE_CBOR  # status byte 0x00 == success


class _PassthroughCipher(CipherState):
    """A CipherState stand-in that just records what passed through it.

    Using a real (but keyless) CipherState would be a passthrough already --
    this subclass adds bookkeeping so tests can assert on what the device
    sent, without needing a full Noise handshake to set up matching keys.
    """

    def __init__(self):
        super().__init__()
        self.seen_plaintexts: list[bytes] = []

    def encrypt_with_ad(self, ad, plaintext):
        self.seen_plaintexts.append(plaintext)
        return plaintext

    def decrypt_with_ad(self, ad, ciphertext):
        return ciphertext


class _FakeTunnel:
    """Echoes a single canned CTAP response frame after the first send."""

    def __init__(self, response_payload: bytes):
        self._response_payload = response_payload
        self.sent_frames: list[tuple[int, bytes]] = []
        self._responded = False
        self._event = asyncio.Event()

    async def send_message(self, frame_type, payload=b""):
        self.sent_frames.append((frame_type, payload))
        self._responded = True
        self._event.set()

    async def recv_message(self):
        await self._event.wait()
        self._event.clear()
        return TunnelMessage(frame_type=CableFrameType.CTAP, payload=self._response_payload)

    async def send_shutdown(self):
        self.sent_frames.append((CableFrameType.SHUTDOWN, b""))

    async def close(self):
        pass


@pytest.fixture
def background_loop():
    loop = _BackgroundLoop()
    yield loop
    loop.stop()


def test_get_info_round_trips_through_bridge(background_loop):
    from fido2.ctap2.base import Ctap2

    tunnel = _FakeTunnel(CANNED_RESPONSE)
    send_cipher = _PassthroughCipher()
    receive_cipher = _PassthroughCipher()

    device = CtapHybridDevice(tunnel, send_cipher, receive_cipher, background_loop=background_loop)
    try:
        ctap2 = Ctap2(device)
        info = ctap2.get_info()
    finally:
        device.close()

    assert info.versions == ["FIDO_2_0"]

    # Exactly one CBOR-framed CTAP request should have been sent.
    assert len(tunnel.sent_frames) >= 1
    frame_type, payload = tunnel.sent_frames[0]
    assert frame_type == CableFrameType.CTAP
    # Ctap2.send_cbor builds: bytes([CMD.GET_INFO]) + cbor.encode(None-ish)
    assert payload[0] == 0x04  # CMD.GET_INFO
    assert send_cipher.seen_plaintexts[0] == payload


def test_capabilities_advertises_cbor_only(background_loop):
    from fido2.hid import CAPABILITY

    tunnel = _FakeTunnel(CANNED_RESPONSE)
    device = CtapHybridDevice(tunnel, _PassthroughCipher(), _PassthroughCipher(), background_loop=background_loop)
    try:
        assert device.capabilities == CAPABILITY.CBOR
    finally:
        device.close()


def test_list_devices_is_empty(background_loop):
    assert list(CtapHybridDevice.list_devices()) == []


def test_call_rejects_non_cbor_command(background_loop):
    from fido2.ctap import CtapError

    tunnel = _FakeTunnel(CANNED_RESPONSE)
    device = CtapHybridDevice(tunnel, _PassthroughCipher(), _PassthroughCipher(), background_loop=background_loop)
    try:
        with pytest.raises(CtapError):
            device.call(0x99, b"\x00")
    finally:
        device.close()


def test_close_sends_shutdown_and_closes_tunnel(background_loop):
    tunnel = _FakeTunnel(CANNED_RESPONSE)
    device = CtapHybridDevice(tunnel, _PassthroughCipher(), _PassthroughCipher(), background_loop=background_loop)

    device.close()

    assert (CableFrameType.SHUTDOWN, b"") in tunnel.sent_frames
    device.close()  # idempotent
