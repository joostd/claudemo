import pytest

from cable import base10
from cable.constants import BASE10_CHUNK_DIGIT_WIDTHS


@pytest.mark.parametrize("length", range(0, 30))
def test_round_trip_random_lengths(length):
    data = bytes((i * 37 + 11) % 256 for i in range(length))
    digits = base10.encode(data)
    assert base10.decode(digits) == data


@pytest.mark.parametrize("size,width", sorted(BASE10_CHUNK_DIGIT_WIDTHS.items()))
def test_single_chunk_digit_width(size, width):
    data = bytes([0xFF] * size)
    digits = base10.encode(data)
    assert len(digits) == width
    assert base10.decode(digits) == data


def test_zero_padding_preserved():
    # A small little-endian value should still produce a fixed-width,
    # zero-padded digit string -- not a "shortened" decimal representation.
    data = b"\x01" + b"\x00" * 6  # 7 bytes, little-endian value == 1
    digits = base10.encode(data)
    assert digits == "1".zfill(BASE10_CHUNK_DIGIT_WIDTHS[7])
    assert base10.decode(digits) == data


def test_empty():
    assert base10.encode(b"") == ""
    assert base10.decode("") == b""


def test_decode_rejects_non_digits():
    with pytest.raises(ValueError):
        base10.decode("12a")


def test_decode_rejects_unmatched_remainder():
    # 4 leftover digits cannot match any chunk width in the table.
    with pytest.raises(ValueError):
        base10.decode("1" * 17 + "1" * 4)


def test_chunk_boundary_spanning_lengths():
    # Exercise lengths that require multiple chunks of mixed sizes
    # (e.g. 8 = 7+1, 13 = 7+6, 20 = 7+7+6, ...).
    for length in (8, 9, 10, 11, 12, 13, 14, 15, 20, 21, 28):
        data = bytes((i * 53 + 7) % 256 for i in range(length))
        assert base10.decode(base10.encode(data)) == data
