import pytest

from cable.constants import EID_ENCRYPTED_SIZE, EID_PLAINTEXT_SIZE
from cable.crypto import eid, kdf


def _eid_key():
    return kdf.derive_eid_key(b"\x13" * 16)


def test_build_and_parse_round_trip():
    nonce = b"\xaa" * 10
    routing_id = b"\xbb" * 3
    plaintext = eid.build_plaintext_eid(nonce=nonce, routing_id=routing_id, tunnel_server_id=0x1234)
    assert len(plaintext) == EID_PLAINTEXT_SIZE

    parsed = eid.parse_plaintext_eid(plaintext)
    assert parsed["reserved"] == 0
    assert parsed["nonce"] == nonce
    assert parsed["routing_id"] == routing_id
    assert parsed["tunnel_server_id"] == 0x1234


def test_build_validates_field_sizes():
    with pytest.raises(ValueError):
        eid.build_plaintext_eid(nonce=b"short", routing_id=b"\x00" * 3, tunnel_server_id=0)
    with pytest.raises(ValueError):
        eid.build_plaintext_eid(nonce=b"\x00" * 10, routing_id=b"bad-len", tunnel_server_id=0)
    with pytest.raises(ValueError):
        eid.build_plaintext_eid(nonce=b"\x00" * 10, routing_id=b"\x00" * 3, tunnel_server_id=1 << 16)


def test_encrypt_decrypt_round_trip():
    key = _eid_key()
    plaintext = eid.build_plaintext_eid(nonce=b"\x01" * 10, routing_id=b"\x02" * 3, tunnel_server_id=7)

    encrypted = eid.encrypt_eid(key, plaintext)
    assert len(encrypted) == EID_ENCRYPTED_SIZE

    recovered = eid.decrypt_and_verify_eid(key, encrypted)
    assert recovered == plaintext


def test_decrypt_rejects_tampered_ciphertext():
    key = _eid_key()
    plaintext = eid.build_plaintext_eid(nonce=b"\x01" * 10, routing_id=b"\x02" * 3, tunnel_server_id=7)
    encrypted = bytearray(eid.encrypt_eid(key, plaintext))
    encrypted[0] ^= 0xFF

    assert eid.decrypt_and_verify_eid(key, bytes(encrypted)) is None


def test_decrypt_rejects_wrong_key():
    plaintext = eid.build_plaintext_eid(nonce=b"\x01" * 10, routing_id=b"\x02" * 3, tunnel_server_id=7)
    encrypted = eid.encrypt_eid(_eid_key(), plaintext)

    other_key = kdf.derive_eid_key(b"\x99" * 16)
    assert eid.decrypt_and_verify_eid(other_key, encrypted) is None


def test_decrypt_rejects_wrong_length():
    key = _eid_key()
    assert eid.decrypt_and_verify_eid(key, b"\x00" * 5) is None
