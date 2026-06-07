import asyncio

import pytest

from cable.constants import CableFrameType
from cable.transport.tunnel import TunnelConnection, tunnel_url


class _FakeWebSocket:
    def __init__(self, incoming=None, response_headers=None):
        self._incoming = list(incoming or [])
        self.sent: list[bytes] = []
        self.closed = False
        self.response_headers = response_headers or {}

    async def send(self, data):
        self.sent.append(data)

    async def recv(self):
        if not self._incoming:
            raise asyncio.CancelledError("no more fake frames")
        return self._incoming.pop(0)

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_send_message_prefixes_frame_type():
    ws = _FakeWebSocket()
    tunnel = TunnelConnection(ws)

    await tunnel.send_message(CableFrameType.CTAP, b"\x01\x02\x03")

    assert ws.sent == [bytes([CableFrameType.CTAP]) + b"\x01\x02\x03"]


@pytest.mark.asyncio
async def test_recv_message_splits_frame_type_and_payload():
    ws = _FakeWebSocket(incoming=[bytes([CableFrameType.CTAP]) + b"hello"])
    tunnel = TunnelConnection(ws)

    message = await tunnel.recv_message()

    assert message.frame_type == CableFrameType.CTAP
    assert message.payload == b"hello"


@pytest.mark.asyncio
async def test_recv_message_rejects_empty_frame():
    ws = _FakeWebSocket(incoming=[b""])
    tunnel = TunnelConnection(ws)

    with pytest.raises(ValueError):
        await tunnel.recv_message()


@pytest.mark.asyncio
async def test_send_shutdown_uses_shutdown_frame_type():
    ws = _FakeWebSocket()
    tunnel = TunnelConnection(ws)

    await tunnel.send_shutdown()

    assert ws.sent == [bytes([CableFrameType.SHUTDOWN])]


@pytest.mark.asyncio
async def test_close_closes_underlying_websocket():
    ws = _FakeWebSocket()
    tunnel = TunnelConnection(ws)

    await tunnel.close()

    assert ws.closed is True


def test_extracts_routing_id_header():
    ws = _FakeWebSocket(response_headers={"X-caBLE-Routing-ID": "abc123"})
    tunnel = TunnelConnection(ws)
    assert tunnel.routing_id == "abc123"


def test_tunnel_url_known_domain():
    url = tunnel_url(0, b"\x00" * 16)
    assert url == "wss://cable.ua5v.com/cable/connect/" + ("00" * 16)


def test_tunnel_url_unknown_domain_raises():
    with pytest.raises(NotImplementedError):
        tunnel_url(999, b"\x00" * 16)
