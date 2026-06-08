"""BLE advertisement scanning for the QR-initiated hybrid-transport flow.

A phone authenticator broadcasts a BLE advertisement carrying an Encrypted
Identifier (EID, see `crypto.eid`) that a nearby desktop can recognize using
key material derived from the QR secret. Per CTAP 2.3 sctn-hybrid this is
*not* a mere proximity nicety: receiving and decrypting it is the **only**
way the desktop learns the routing ID (needed to address the tunnel) and
the connection nonce (the full plaintext salts the Noise PSK), so the
QR-initiated flow cannot proceed without it -- callers should treat a `None`
result as a hard failure, not "proceed anyway".

`scan_for_eid` itself stays resilient at the *mechanism* level: anything that
prevents scanning from running at all (no BLE adapter, missing OS
permissions, `bleak` not installed, an unexpected scanner error) resolves to
`None` rather than raising, just like an ordinary scan timeout with no
matching advertisement -- the caller is responsible for deciding what `None`
means for the flow it's driving.
"""

from __future__ import annotations

import asyncio
import logging

from ..constants import BLE_SERVICE_UUIDS, EID_ENCRYPTED_SIZE
from ..crypto.eid import decrypt_and_verify_eid

logger = logging.getLogger(__name__)

DEFAULT_SCAN_TIMEOUT = 15.0


def _candidate_payloads(advertisement_data) -> list[bytes]:
    """Extract plausible 20-byte EID candidates from BLE service data."""
    candidates: list[bytes] = []
    service_data = getattr(advertisement_data, "service_data", None) or {}
    for uuid_str, payload in service_data.items():
        try:
            short_uuid = int(uuid_str[4:8], 16) if len(uuid_str) > 8 else int(uuid_str, 16)
        except ValueError:
            short_uuid = None
        if short_uuid is not None and short_uuid not in BLE_SERVICE_UUIDS:
            continue
        if isinstance(payload, (bytes, bytearray)) and len(payload) == EID_ENCRYPTED_SIZE:
            candidates.append(bytes(payload))
    return candidates


async def scan_for_eid(eid_key: bytes, *, timeout: float = DEFAULT_SCAN_TIMEOUT) -> bytes | None:
    """Scan for a BLE advertisement matching `eid_key`.

    Returns the decrypted 16-byte plaintext EID on success, or `None` if no
    matching advertisement was seen (including when scanning isn't possible
    at all in this environment). Never raises.
    """
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.warning("bleak is not installed; skipping BLE proximity check")
        return None

    found: "asyncio.Future[bytes]" = asyncio.get_event_loop().create_future()

    def _on_detection(_device, advertisement_data) -> None:
        if found.done():
            return
        for candidate in _candidate_payloads(advertisement_data):
            plaintext = decrypt_and_verify_eid(eid_key, candidate)
            if plaintext is not None:
                found.set_result(plaintext)
                return

    try:
        async with BleakScanner(detection_callback=_on_detection):
            try:
                return await asyncio.wait_for(found, timeout=timeout)
            except asyncio.TimeoutError:
                logger.info("BLE proximity check timed out after %.0fs; proceeding without it", timeout)
                return None
    except Exception as exc:  # pragma: no cover - depends on local BLE stack/permissions
        logger.warning("BLE proximity check unavailable (%s); proceeding without it", exc)
        return None


__all__ = ["scan_for_eid", "DEFAULT_SCAN_TIMEOUT"]
