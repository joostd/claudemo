"""HKDF-SHA256 derivations of session secrets from the QR secret.

caBLE v2 derives several pieces of key material from the random 16-byte "QR
secret" embedded in the handshake QR code, using HKDF-SHA256 with a 4-byte
little-endian integer (a `DerivedValueType`, see `constants`) as the `info`
parameter.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..constants import (
    DerivedValueType,
    EID_KEY_SIZE,
    PSK_SIZE,
    TUNNEL_ID_SIZE,
    derived_value_info_bytes,
)


def _hkdf_sha256(*, salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or None,
        info=info,
    ).derive(ikm)


def derive_eid_key(qr_secret: bytes) -> bytes:
    """Derive the 64-byte EID key (32-byte AES key || 32-byte HMAC key)."""
    return _hkdf_sha256(
        salt=b"",
        ikm=qr_secret,
        info=derived_value_info_bytes(DerivedValueType.EID_KEY),
        length=EID_KEY_SIZE,
    )


def derive_tunnel_id(qr_secret: bytes) -> bytes:
    """Derive the 16-byte tunnel ID used to address the tunnel server."""
    return _hkdf_sha256(
        salt=b"",
        ikm=qr_secret,
        info=derived_value_info_bytes(DerivedValueType.TUNNEL_ID),
        length=TUNNEL_ID_SIZE,
    )


def derive_psk(qr_secret: bytes, eid: bytes) -> bytes:
    """Derive the 32-byte pre-shared key mixed into the Noise handshake.

    Salted with the (encrypted) EID bytes observed over BLE / used to address
    the tunnel, keyed by the QR secret.
    """
    return _hkdf_sha256(
        salt=eid,
        ikm=qr_secret,
        info=derived_value_info_bytes(DerivedValueType.PSK),
        length=PSK_SIZE,
    )


def derive_paired_secret(*_args, **_kwargs) -> bytes:
    raise NotImplementedError(
        "PairedSecret derivation (DerivedValueType.PAIRED_SECRET) is part of "
        "the contact/pairing flow, not the QR-initiated flow, and has not "
        "been implemented."
    )


def derive_identity_key_seed(*_args, **_kwargs) -> bytes:
    raise NotImplementedError(
        "IdentityKeySeed derivation (DerivedValueType.IDENTITY_KEY_SEED) is "
        "part of the contact/pairing flow, not the QR-initiated flow, and "
        "has not been implemented."
    )


def derive_per_contact_id_secret(*_args, **_kwargs) -> bytes:
    raise NotImplementedError(
        "PerContactIDSecret derivation (DerivedValueType.PER_CONTACT_ID_SECRET) "
        "is part of the contact/pairing flow, not the QR-initiated flow, and "
        "has not been implemented."
    )


__all__ = [
    "derive_eid_key",
    "derive_tunnel_id",
    "derive_psk",
    "derive_paired_secret",
    "derive_identity_key_seed",
    "derive_per_contact_id_secret",
]
