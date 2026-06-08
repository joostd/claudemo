"""Validate the CtapHybridDevice <-> fido2.ctap2.Ctap2 bridge end to end,
using a fake encrypted channel that simply echoes a canned
authenticatorGetInfo response. No real network/crypto/device involved --
this proves the *adapter wiring* (framing, sync/async bridging, response
parsing) is correct.
"""

import asyncio

import cbor2
import pytest

from cable.constants import CableFrameType
from cable.device import CtapHybridDevice, _BackgroundLoop
from cable.transport.channel import CableMessage


GET_INFO_RESPONSE_CBOR = cbor2.dumps({1: ["FIDO_2_0"], 3: b"\x00" * 16})
CANNED_RESPONSE = bytes([0x00]) + GET_INFO_RESPONSE_CBOR  # status byte 0x00 == success


class _FakeChannel:
    """Echoes a single canned CTAP response message after the first send."""

    def __init__(self, response_payload: bytes):
        self._response_payload = response_payload
        self.sent_messages: list[tuple[int, bytes]] = []
        self._event = asyncio.Event()
        self.closed = False

    async def send_message(self, frame_type, payload=b""):
        self.sent_messages.append((frame_type, payload))
        self._event.set()

    async def recv_message(self):
        await self._event.wait()
        self._event.clear()
        return CableMessage(frame_type=CableFrameType.CTAP, payload=self._response_payload)

    async def close(self):
        self.closed = True


@pytest.fixture
def background_loop():
    loop = _BackgroundLoop()
    yield loop
    loop.stop()


def test_get_info_round_trips_through_bridge(background_loop):
    from fido2.ctap2.base import Ctap2

    channel = _FakeChannel(CANNED_RESPONSE)

    device = CtapHybridDevice(channel, background_loop=background_loop)
    try:
        ctap2 = Ctap2(device)
        info = ctap2.get_info()
    finally:
        device.close()

    assert info.versions == ["FIDO_2_0"]

    # Exactly one CBOR-framed CTAP request should have been sent.
    assert len(channel.sent_messages) >= 1
    frame_type, payload = channel.sent_messages[0]
    assert frame_type == CableFrameType.CTAP
    # Ctap2.send_cbor builds: bytes([CMD.GET_INFO]) + cbor.encode(None-ish)
    assert payload[0] == 0x04  # CMD.GET_INFO


def test_capabilities_advertises_cbor_only(background_loop):
    from fido2.hid import CAPABILITY

    channel = _FakeChannel(CANNED_RESPONSE)
    device = CtapHybridDevice(channel, background_loop=background_loop)
    try:
        assert device.capabilities == CAPABILITY.CBOR
    finally:
        device.close()


def test_list_devices_is_empty(background_loop):
    assert list(CtapHybridDevice.list_devices()) == []


def test_call_rejects_non_cbor_command(background_loop):
    from fido2.ctap import CtapError

    channel = _FakeChannel(CANNED_RESPONSE)
    device = CtapHybridDevice(channel, background_loop=background_loop)
    try:
        with pytest.raises(CtapError):
            device.call(0x99, b"\x00")
    finally:
        device.close()


def test_close_sends_shutdown_and_closes_channel(background_loop):
    channel = _FakeChannel(CANNED_RESPONSE)
    device = CtapHybridDevice(channel, background_loop=background_loop)

    device.close()

    assert (CableFrameType.SHUTDOWN, b"") in channel.sent_messages
    assert channel.closed is True
    device.close()  # idempotent
