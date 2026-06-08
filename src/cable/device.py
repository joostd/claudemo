"""Bridge from the encrypted caBLE channel to `python-fido2`'s CTAP2 layer.

`fido2.ctap2.base.Ctap2` implements all CTAP2 command construction/response
parsing (GetInfo, MakeCredential, GetAssertion, error translation, ...) on
top of a `fido2.ctap.CtapDevice`, whose only required behaviour is:

  - a `capabilities` bit-flag property
  - a *synchronous*, blocking `call(cmd, data, event, on_keepalive) -> bytes`

Concretely, `Ctap2.send_cbor` builds `request = bytes([subcommand]) +
cbor.encode(args)`, calls `device.call(CTAPHID.CBOR, request, ...)`, and
expects back `bytes([status]) + cbor.encode(response)`.

`CtapHybridDevice` below is a thin adapter over a `CableChannel`
(`transport.channel`, which already handles Noise encryption, padding, and
type-byte framing): it sends the opaque `data` blob as a `CTAP` (0x01)
message, waits for the matching response message, and hands the raw payload
back -- letting `Ctap2` handle everything else. The only nontrivial part is
bridging the synchronous `call()` interface to the underlying async channel,
done here via a dedicated background event-loop thread.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Callable, Iterator

from fido2.ctap import CtapDevice, CtapError
from fido2.hid import CAPABILITY, CTAPHID

from .constants import CableFrameType
from .transport.channel import CableChannel

# Generous default: several phone-side flows (user presence, biometric
# prompts, ...) can take a while, and unlike USB/NFC there is no caBLE-tunnel
# equivalent of a CTAP keepalive to reset an inactivity timer against.
DEFAULT_CALL_TIMEOUT = 120.0


class _BackgroundLoop:
    """Runs an asyncio event loop on a dedicated thread for its lifetime."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def run(self, coro, *, timeout: float | None = None):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5.0)
        self._loop.close()


class CtapHybridDevice(CtapDevice):
    """A `CtapDevice` that transports CTAP2 over an encrypted caBLE channel."""

    def __init__(
        self,
        channel: CableChannel,
        *,
        call_timeout: float = DEFAULT_CALL_TIMEOUT,
        background_loop: "_BackgroundLoop | None" = None,
    ) -> None:
        self._channel = channel
        self._call_timeout = call_timeout
        self._owns_loop = background_loop is None
        self._loop = background_loop or _BackgroundLoop()
        self._closed = False

    # -- CtapDevice interface ------------------------------------------------

    @property
    def capabilities(self) -> int:
        # Hybrid transport only ever carries CTAP2/CBOR -- there is no
        # equivalent of the legacy U2F "msg"/"wink" HID commands.
        return CAPABILITY.CBOR

    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: "threading.Event | None" = None,
        on_keepalive: "Callable[[int], None] | None" = None,
    ) -> bytes:
        if cmd != CTAPHID.CBOR:
            raise CtapError(CtapError.ERR.INVALID_COMMAND)

        # `on_keepalive` has no caBLE-tunnel equivalent we know of (see
        # module docstring on DEFAULT_CALL_TIMEOUT) -- it is intentionally
        # never invoked here, and we rely on a generous timeout instead.
        del on_keepalive

        try:
            return self._loop.run(self._call_async(data, event), timeout=self._call_timeout)
        except asyncio.TimeoutError as exc:
            raise CtapError(CtapError.ERR.TIMEOUT) from exc

    async def _call_async(self, data: bytes, event: "threading.Event | None") -> bytes:
        await self._channel.send_message(CableFrameType.CTAP, data)

        # `asyncio.shield` protects the in-flight `recv_message()` from being
        # cancelled by `wait_for`'s per-iteration timeout (which exists only
        # to let us re-check `event` periodically) -- but the shielded task
        # must be *reused* across iterations, not recreated, or two
        # overlapping `recv()` calls would race on the same channel/websocket
        # ("cannot call recv while another coroutine is already running recv").
        recv_task = asyncio.ensure_future(self._channel.recv_message())
        try:
            while True:
                if event is not None and event.is_set():
                    raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)

                try:
                    message = await asyncio.wait_for(asyncio.shield(recv_task), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                if message.frame_type == CableFrameType.SHUTDOWN:
                    raise CtapError(CtapError.ERR.OTHER)
                if message.frame_type != CableFrameType.CTAP:
                    # Unrecognised/Update frames: discard and wait for the
                    # actual CTAP response on a fresh receive.
                    recv_task = asyncio.ensure_future(self._channel.recv_message())
                    continue

                return message.payload
        finally:
            if not recv_task.done():
                recv_task.cancel()

    @classmethod
    def list_devices(cls) -> Iterator["CtapHybridDevice"]:
        # Hybrid-transport authenticators are never "discovered" -- a
        # connection is always initiated by displaying a QR code.
        return iter(())

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._loop.run(self._channel.send_message(CableFrameType.SHUTDOWN), timeout=5.0)
        except Exception:
            pass
        try:
            self._loop.run(self._channel.close(), timeout=5.0)
        except Exception:
            pass
        if self._owns_loop:
            self._loop.stop()


__all__ = ["CtapHybridDevice", "DEFAULT_CALL_TIMEOUT"]
