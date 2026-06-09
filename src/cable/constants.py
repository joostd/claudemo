"""Protocol constants for FIDO hybrid transport (caBLE v2).

There is no official published specification for caBLE v2's wire format.
The values below were taken from the most complete open-source
reimplementation, the Rust `webauthn-authenticator-rs` crate
(https://github.com/kanidm/webauthn-rs, `webauthn-authenticator-rs/src/cable/`),
whose authors derived them by reverse-engineering Chromium's
`device/fido/cable/` C++ implementation. Treat these as best-effort and
subject to correction against a real device/tunnel server.

All of these are centralized here so that any single value can be corrected
in one place if real-device testing reveals a discrepancy.
"""

from __future__ import annotations

import struct

# --- HandshakeV2 CBOR map field indices (the QR payload) -------------------
#
# The QR code encodes a CBOR map with small-integer keys:
HANDSHAKE_FIELD_PEER_IDENTITY = 0  # bytes: ephemeral P-256 public key (compressed or uncompressed point)
HANDSHAKE_FIELD_SECRET = 1  # bytes: 16 random "QR secret" bytes
HANDSHAKE_FIELD_KNOWN_DOMAINS_COUNT = 2  # uint: number of known tunnel server domains
HANDSHAKE_FIELD_TIMESTAMP = 3  # uint: unix seconds, used for replay protection
HANDSHAKE_FIELD_SUPPORTS_LINKING_INFO = 4  # bool: can perform state-assisted transactions
HANDSHAKE_FIELD_REQUEST_TYPE = 5  # text: "ga" (GetAssertion) or "mc" (MakeCredential)
HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS = 6  # array of ints: supported data-transfer channels

REQUEST_TYPE_GET_ASSERTION = "ga"
REQUEST_TYPE_MAKE_CREDENTIAL = "mc"

# Values for HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS (CTAP 2.3 sctn-hybrid).
TRANSPORT_CHANNEL_WEBSOCKET = 0
TRANSPORT_CHANNEL_BLE = 1

QR_SECRET_SIZE = 16  # bytes
QR_PEER_IDENTITY_SIZE = 33  # compressed X9.62 P-256 public key, per CTAP 2.3 sctn-hybrid

# --- base10 encoding chunk table --------------------------------------------
#
# The CBOR-encoded HandshakeV2 bytes are encoded into a decimal digit string
# (so they fit cleanly in a "FIDO:/<digits>" URI / QR code alphanumeric mode).
# Input bytes are consumed in chunks; each chunk size maps to a fixed output
# digit-string width (zero padded), and chunks are interpreted little-endian.
#
# Maps: input chunk size in bytes -> output digit-string width
BASE10_CHUNK_DIGIT_WIDTHS: dict[int, int] = {
    7: 17,
    6: 15,
    5: 13,
    4: 10,
    3: 8,
    2: 5,
    1: 3,
}
BASE10_MAX_CHUNK_SIZE = max(BASE10_CHUNK_DIGIT_WIDTHS)

FIDO_URI_PREFIX = "FIDO:/"

# --- Noise protocol -----------------------------------------------------------
#
# caBLE v2 uses a non-standard Noise cipher suite combination: P-256 ECDH
# (rather than the more common X25519), AES-256-GCM AEAD, SHA-256 hash, with
# a pre-shared key mixed in at the start of the handshake ("psk0" modifier).
#
# The protocol name strings below are the canonical Noise identifiers for
# this suite; they are used as the Noise `protocol_name` for `h`/`ck`
# initialization (padded to 32 bytes with trailing NUL as per the Noise spec
# when used as the initial hash input for hash functions with a 32-byte block).
NOISE_PROTOCOL_KN = b"Noise_KNpsk0_P256_AESGCM_SHA256\0"
NOISE_PROTOCOL_NK = b"Noise_NKpsk0_P256_AESGCM_SHA256\0"

assert len(NOISE_PROTOCOL_KN) == 32
assert len(NOISE_PROTOCOL_NK) == 32

# Each handshake is preceded by a caBLE-specific "prologue" that mixes a
# single discriminator byte -- identifying which side's static key is being
# pre-shared -- followed by that static key itself (CTAP 2.3 sctn-hybrid:
# `ns.mixHash([]byte{0 or 1}); ns.mixHashPoint(...)`). This is *not* the
# standard Noise pre-message mechanism.
NOISE_PROLOGUE_BYTE_RESPONDER_STATIC = 0  # NKpsk0: responder's key is pre-shared
NOISE_PROLOGUE_BYTE_INITIATOR_STATIC = 1  # KNpsk0: initiator's key is pre-shared

NOISE_DH_PUBLIC_KEY_SIZE = 65  # uncompressed P-256 point: 0x04 || X (32) || Y (32)
NOISE_HASH_SIZE = 32  # SHA-256 digest size
NOISE_AEAD_KEY_SIZE = 32  # AES-256
NOISE_AEAD_TAG_SIZE = 16
NOISE_AEAD_NONCE_SIZE = 12

# Post-handshake transport messages are padded to a multiple of this many
# bytes (final byte = number of preceding padding bytes, minus one) before
# being AES-256-GCM encrypted. 32 is the spec-recommended granularity.
TRANSPORT_PADDING_GRANULARITY = 32

# --- HKDF "info" derivation constants ----------------------------------------
#
# Various session secrets are derived from the QR secret (and other inputs)
# via HKDF-SHA256, using a 4-byte little-endian integer as the `info`
# parameter, where only the low-order byte (the purpose number) is non-zero.
# Each `DerivedValueType` below corresponds to one such derivation purpose.


class DerivedValueType:
    EID_KEY = 1
    TUNNEL_ID = 2
    PSK = 3
    PAIRED_SECRET = 4
    IDENTITY_KEY_SEED = 5
    PER_CONTACT_ID_SECRET = 6


def derived_value_info_bytes(value_type: int) -> bytes:
    """Pack a DerivedValueType integer as the 4-byte little-endian HKDF info."""
    return struct.pack("<I", value_type)


EID_KEY_SIZE = 64  # bytes (split into 32-byte AES key + 32-byte HMAC key)
EID_KEY_AES_PORTION = slice(0, 32)
EID_KEY_HMAC_PORTION = slice(32, 64)

TUNNEL_ID_SIZE = 16
PSK_SIZE = 32

# --- Tunnel server ------------------------------------------------------------

TUNNEL_SUBPROTOCOL = "fido.cable"
TUNNEL_ROUTING_ID_HEADER = "X-caBLE-Routing-ID"

# Domains assigned a small integer ID in the QR's `known_domains_count` /
# advertised tunnel-server-id scheme. Only the well-known domains (IDs 0 and 1)
# are implemented; "computed" domains (ID >= 256, derived via hashing) are not.
KNOWN_TUNNEL_DOMAINS: dict[int, str] = {
    0: "cable.ua5v.com",   # Google
    1: "cable.auth.com",   # Apple
    261: "cable.pyzci7hxyjsvc.org",  # custom Pi tunnel server (domain_id 0x0105)
}

# --- Post-handshake message framing ------------------------------------------
#
# After the Noise handshake completes, every message sent over the tunnel is
# prefixed with a single type byte.


class CableFrameType:
    SHUTDOWN = 0x00
    CTAP = 0x01
    UPDATE = 0x02


# --- BLE advertisement / Encrypted Identifier (EID) --------------------------
#
# The phone authenticator broadcasts a BLE advertisement containing an
# "Encrypted Identifier" (EID) that the desktop can recognize using key
# material derived from the QR secret, confirming physical proximity.
#
# Plaintext EID layout (16 bytes):
#   byte 0       : reserved, always 0x00
#   bytes 1-10   : 10-byte random nonce (authenticator-generated)
#   bytes 11-13  : 3-byte routing ID (assigned by the tunnel server)
#   bytes 14-15  : 2-byte little-endian tunnel server ID
#
# Encrypted EID = AES-256-ECB(plaintext) || HMAC-SHA256(ciphertext)[:4]
#   (20 bytes total)
EID_PLAINTEXT_SIZE = 16
EID_RESERVED_BYTE = 0
EID_NONCE_OFFSET = 1
EID_NONCE_SIZE = 10
EID_ROUTING_ID_OFFSET = 11
EID_ROUTING_ID_SIZE = 3
EID_TUNNEL_SERVER_ID_OFFSET = 14
EID_TUNNEL_SERVER_ID_SIZE = 2

EID_HMAC_TAG_SIZE = 4
EID_ENCRYPTED_SIZE = EID_PLAINTEXT_SIZE + EID_HMAC_TAG_SIZE  # 20

# BLE GATT service UUIDs that hybrid-transport authenticators advertise under.
BLE_SERVICE_UUID_FIDO = 0xFFF9  # current FIDO2 hybrid transport service UUID
BLE_SERVICE_UUID_GOOGLE_LEGACY = 0xFDE2  # legacy Google / iOS 16 service UUID
BLE_SERVICE_UUIDS = (BLE_SERVICE_UUID_FIDO, BLE_SERVICE_UUID_GOOGLE_LEGACY)
