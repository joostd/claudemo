import asyncio

import pytest

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
async def test_send_passes_raw_bytes_through():
    ws = _FakeWebSocket()
    tunnel = TunnelConnection(ws)

    await tunnel.send(b"\x01\x02\x03")

    assert ws.sent == [b"\x01\x02\x03"]


@pytest.mark.asyncio
async def test_recv_returns_raw_frame_bytes():
    ws = _FakeWebSocket(incoming=[b"hello"])
    tunnel = TunnelConnection(ws)

    assert await tunnel.recv() == b"hello"


@pytest.mark.asyncio
async def test_recv_decodes_text_frames_to_bytes():
    ws = _FakeWebSocket(incoming=["hello"])
    tunnel = TunnelConnection(ws)

    assert await tunnel.recv() == b"hello"


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
    url = tunnel_url(0, b"\xaa" * 3, b"\x00" * 16)
    assert url == "wss://cable.ua5v.com/cable/connect/" + ("aa" * 3) + "/" + ("00" * 16)


def test_tunnel_url_unknown_domain_raises():
    with pytest.raises(NotImplementedError):
        tunnel_url(999, b"\xaa" * 3, b"\x00" * 16)
