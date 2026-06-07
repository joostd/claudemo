import struct

import pytest

from cable.constants import DerivedValueType, EID_KEY_SIZE, PSK_SIZE, TUNNEL_ID_SIZE, derived_value_info_bytes
from cable.crypto import kdf


def test_info_bytes_are_little_endian():
    assert derived_value_info_bytes(DerivedValueType.EID_KEY) == bytes([0x00, 0x00, 0x00, 0x01])
    assert derived_value_info_bytes(DerivedValueType.TUNNEL_ID) == bytes([0x00, 0x00, 0x00, 0x02])
    assert derived_value_info_bytes(DerivedValueType.PSK) == bytes([0x00, 0x00, 0x00, 0x03])
    # Round trip through struct to be doubly sure about endianness.
    assert struct.unpack("<I", derived_value_info_bytes(DerivedValueType.EID_KEY))[0] == DerivedValueType.EID_KEY


def test_output_lengths():
    secret = b"\x00" * 16
    assert len(kdf.derive_eid_key(secret)) == EID_KEY_SIZE
    assert len(kdf.derive_tunnel_id(secret)) == TUNNEL_ID_SIZE
    assert len(kdf.derive_psk(secret, eid=b"\x01" * 20)) == PSK_SIZE


def test_outputs_distinct_per_purpose():
    secret = b"\x42" * 16
    eid_key = kdf.derive_eid_key(secret)
    tunnel_id = kdf.derive_tunnel_id(secret)
    psk = kdf.derive_psk(secret, eid=b"\x01" * 20)

    assert eid_key[:TUNNEL_ID_SIZE] != tunnel_id
    assert eid_key[:PSK_SIZE] != psk
    assert tunnel_id != psk[:TUNNEL_ID_SIZE]


def test_deterministic():
    secret = b"\x99" * 16
    assert kdf.derive_eid_key(secret) == kdf.derive_eid_key(secret)
    assert kdf.derive_tunnel_id(secret) == kdf.derive_tunnel_id(secret)
    assert kdf.derive_psk(secret, eid=b"x") == kdf.derive_psk(secret, eid=b"x")


def test_psk_depends_on_salt():
    secret = b"\x77" * 16
    assert kdf.derive_psk(secret, eid=b"a" * 20) != kdf.derive_psk(secret, eid=b"b" * 20)


@pytest.mark.parametrize(
    "fn",
    [kdf.derive_paired_secret, kdf.derive_identity_key_seed, kdf.derive_per_contact_id_secret],
)
def test_unimplemented_derivations_raise(fn):
    with pytest.raises(NotImplementedError):
        fn()
