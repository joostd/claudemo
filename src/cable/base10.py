"""base10 encoding used to embed binary HandshakeV2 CBOR into a FIDO:/ URI.

caBLE v2 QR codes encode their payload as a string of decimal digits (so the
QR code can use the compact "numeric" encoding mode). Input bytes are
processed in chunks; each chunk size has a fixed output digit-string width
(zero-padded), and each chunk's bytes are interpreted as a little-endian
unsigned integer. See `constants.BASE10_CHUNK_DIGIT_WIDTHS` for the table.

We implement `decode` first, directly from the chunk-width table (treating it
as the canonical definition), and derive `encode` as its mathematical
inverse -- then prove the relationship via round-trip tests.
"""

from __future__ import annotations

from .constants import BASE10_CHUNK_DIGIT_WIDTHS, BASE10_MAX_CHUNK_SIZE

# Reverse lookup: output digit-string width -> input chunk size in bytes.
_WIDTH_TO_CHUNK_SIZE: dict[int, int] = {
    width: size for size, width in BASE10_CHUNK_DIGIT_WIDTHS.items()
}


def _chunk_plan(num_bytes: int) -> list[int]:
    """Return the sequence of chunk sizes (in bytes) used to consume `num_bytes`.

    Greedily consumes the largest chunk size that fits, falling back to
    smaller chunk sizes for the remainder -- matching how a byte string of
    arbitrary length is split into the largest-first chunks defined by the
    table.
    """
    sizes = sorted(BASE10_CHUNK_DIGIT_WIDTHS, reverse=True)
    plan: list[int] = []
    remaining = num_bytes
    while remaining > 0:
        for size in sizes:
            if size <= remaining:
                plan.append(size)
                remaining -= size
                break
        else:
            raise ValueError(f"cannot encode a remainder of {remaining} byte(s)")
    return plan


def encode(data: bytes) -> str:
    """Encode bytes into a base10 digit string per the chunk table."""
    if not data:
        return ""

    digits: list[str] = []
    offset = 0
    for size in _chunk_plan(len(data)):
        chunk = data[offset : offset + size]
        offset += size
        width = BASE10_CHUNK_DIGIT_WIDTHS[size]
        value = int.from_bytes(chunk, "little")
        digits.append(str(value).zfill(width))
    return "".join(digits)


def decode(digits: str) -> bytes:
    """Decode a base10 digit string back into bytes per the chunk table."""
    if not digits:
        return b""
    if not digits.isdigit():
        raise ValueError("base10 input must contain only decimal digits")

    out = bytearray()
    pos = 0
    total = len(digits)
    widths = sorted(_WIDTH_TO_CHUNK_SIZE, reverse=True)
    while pos < total:
        remaining = total - pos
        for width in widths:
            if width <= remaining:
                chunk_size = _WIDTH_TO_CHUNK_SIZE[width]
                group = digits[pos : pos + width]
                pos += width
                value = int(group)
                out += value.to_bytes(chunk_size, "little")
                break
        else:
            raise ValueError(
                f"leftover {remaining} digit(s) do not match any known chunk width"
            )
    return bytes(out)


__all__ = ["encode", "decode", "BASE10_MAX_CHUNK_SIZE"]
