"""BLE Encrypted Identifier (EID) construction, encryption and verification.

The phone authenticator broadcasts a BLE advertisement containing an
"Encrypted Identifier" that lets a desktop holding the QR secret recognize it
(confirming physical proximity) without either side revealing anything to
bystanders. See `constants` for the exact byte layout.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import constant_time, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..constants import (
    EID_ENCRYPTED_SIZE,
    EID_HMAC_TAG_SIZE,
    EID_KEY_AES_PORTION,
    EID_KEY_HMAC_PORTION,
    EID_KEY_SIZE,
    EID_NONCE_OFFSET,
    EID_NONCE_SIZE,
    EID_PLAINTEXT_SIZE,
    EID_RESERVED_BYTE,
    EID_ROUTING_ID_OFFSET,
    EID_ROUTING_ID_SIZE,
    EID_TUNNEL_SERVER_ID_OFFSET,
    EID_TUNNEL_SERVER_ID_SIZE,
)


def build_plaintext_eid(*, nonce: bytes, routing_id: bytes, tunnel_server_id: int) -> bytes:
    """Assemble the 16-byte plaintext EID structure."""
    if len(nonce) != EID_NONCE_SIZE:
        raise ValueError(f"nonce must be {EID_NONCE_SIZE} bytes, got {len(nonce)}")
    if len(routing_id) != EID_ROUTING_ID_SIZE:
        raise ValueError(f"routing_id must be {EID_ROUTING_ID_SIZE} bytes, got {len(routing_id)}")
    if not 0 <= tunnel_server_id < (1 << (8 * EID_TUNNEL_SERVER_ID_SIZE)):
        raise ValueError("tunnel_server_id out of range for 16-bit little-endian field")

    out = bytearray(EID_PLAINTEXT_SIZE)
    out[0] = EID_RESERVED_BYTE
    out[EID_NONCE_OFFSET : EID_NONCE_OFFSET + EID_NONCE_SIZE] = nonce
    out[EID_ROUTING_ID_OFFSET : EID_ROUTING_ID_OFFSET + EID_ROUTING_ID_SIZE] = routing_id
    out[EID_TUNNEL_SERVER_ID_OFFSET : EID_TUNNEL_SERVER_ID_OFFSET + EID_TUNNEL_SERVER_ID_SIZE] = (
        tunnel_server_id.to_bytes(EID_TUNNEL_SERVER_ID_SIZE, "little")
    )
    return bytes(out)


def parse_plaintext_eid(plaintext: bytes) -> dict:
    """Split a 16-byte plaintext EID back into its component fields."""
    if len(plaintext) != EID_PLAINTEXT_SIZE:
        raise ValueError(f"plaintext EID must be {EID_PLAINTEXT_SIZE} bytes, got {len(plaintext)}")
    return {
        "reserved": plaintext[0],
        "nonce": plaintext[EID_NONCE_OFFSET : EID_NONCE_OFFSET + EID_NONCE_SIZE],
        "routing_id": plaintext[EID_ROUTING_ID_OFFSET : EID_ROUTING_ID_OFFSET + EID_ROUTING_ID_SIZE],
        "tunnel_server_id": int.from_bytes(
            plaintext[
                EID_TUNNEL_SERVER_ID_OFFSET : EID_TUNNEL_SERVER_ID_OFFSET
                + EID_TUNNEL_SERVER_ID_SIZE
            ],
            "little",
        ),
    }


def _split_eid_key(eid_key: bytes) -> tuple[bytes, bytes]:
    if len(eid_key) != EID_KEY_SIZE:
        raise ValueError(f"EID key must be {EID_KEY_SIZE} bytes, got {len(eid_key)}")
    return eid_key[EID_KEY_AES_PORTION], eid_key[EID_KEY_HMAC_PORTION]


def _hmac_tag(hmac_key: bytes, ciphertext: bytes) -> bytes:
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ciphertext)
    return h.finalize()[:EID_HMAC_TAG_SIZE]


def encrypt_eid(eid_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a 16-byte plaintext EID into its 20-byte advertised form.

    ciphertext = AES-256-ECB(plaintext); output = ciphertext || HMAC-SHA256(ciphertext)[:4]
    """
    if len(plaintext) != EID_PLAINTEXT_SIZE:
        raise ValueError(f"plaintext EID must be {EID_PLAINTEXT_SIZE} bytes, got {len(plaintext)}")

    aes_key, hmac_key = _split_eid_key(eid_key)
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = _hmac_tag(hmac_key, ciphertext)
    return ciphertext + tag


def decrypt_and_verify_eid(eid_key: bytes, candidate: bytes) -> bytes | None:
    """Attempt to decrypt and verify a 20-byte advertised EID.

    Returns the 16-byte plaintext on success, or `None` if the HMAC tag does
    not verify (i.e. this advertisement was not produced with `eid_key`).
    """
    if len(candidate) != EID_ENCRYPTED_SIZE:
        return None

    ciphertext, tag = candidate[:EID_PLAINTEXT_SIZE], candidate[EID_PLAINTEXT_SIZE:]
    aes_key, hmac_key = _split_eid_key(eid_key)

    expected_tag = _hmac_tag(hmac_key, ciphertext)
    if not constant_time.bytes_eq(expected_tag, tag):
        return None

    cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


__all__ = [
    "build_plaintext_eid",
    "parse_plaintext_eid",
    "encrypt_eid",
    "decrypt_and_verify_eid",
]
