"""WebSocket connection to a caBLE tunnel server, with caBLE message framing.

Once a phone scans the QR code, it connects to a "tunnel server" -- a
WebSocket relay -- and the desktop connects to the same server/routing
address. All subsequent traffic (the Noise handshake, then encrypted CTAP2
commands) flows as binary WebSocket frames, each prefixed with a single
"message type" byte (see `constants.CableFrameType`).
"""

from __future__ import annotations

from dataclasses import dataclass

import websockets

from ..constants import (
    CableFrameType,
    KNOWN_TUNNEL_DOMAINS,
    TUNNEL_ROUTING_ID_HEADER,
    TUNNEL_SUBPROTOCOL,
)


def tunnel_url(domain_id: int, tunnel_id: bytes) -> str:
    """Build the tunnel server WebSocket URL for a known domain + tunnel ID."""
    try:
        domain = KNOWN_TUNNEL_DOMAINS[domain_id]
    except KeyError as exc:
        raise NotImplementedError(
            f"tunnel server domain id {domain_id} is not one of the known "
            f"domains {sorted(KNOWN_TUNNEL_DOMAINS)}; 'computed' domain "
            "derivation for higher IDs is not implemented (its hashing "
            "scheme is not confirmed against any reference)."
        ) from exc
    return f"wss://{domain}/cable/connect/{tunnel_id.hex()}"


@dataclass
class TunnelMessage:
    frame_type: int
    payload: bytes


class TunnelConnection:
    """Async context manager wrapping a caBLE tunnel server WebSocket."""

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

    async def send_message(self, frame_type: int, payload: bytes = b"") -> None:
        await self._websocket.send(bytes([frame_type]) + payload)

    async def recv_message(self) -> TunnelMessage:
        frame = await self._websocket.recv()
        if isinstance(frame, str):
            frame = frame.encode("utf-8")
        if not frame:
            raise ValueError("received empty tunnel frame (missing message-type byte)")
        return TunnelMessage(frame_type=frame[0], payload=frame[1:])

    async def send_shutdown(self) -> None:
        await self.send_message(CableFrameType.SHUTDOWN)


__all__ = ["TunnelConnection", "TunnelMessage", "tunnel_url"]
