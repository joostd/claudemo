"""Generic Noise Protocol Framework handshake state machine.

caBLE v2 uses a non-standard Noise cipher suite: P-256 ECDH (rather than the
far more common X25519), AES-256-GCM AEAD, SHA-256 hashing, and a pre-shared
key mixed in at the start of the handshake (the "psk0" modifier). The
canonical protocol names are `Noise_KNpsk0_P256_AESGCM_SHA256` (desktop/
initiator role, who already knows the phone's static public key from a prior
pairing -- "K") and `Noise_NKpsk0_P256_AESGCM_SHA256` (the symmetric
responder-side view, "N" = no static key known yet for that party).

For the QR-initiated flow implemented here, the *desktop* generates a fresh
ephemeral keypair and places its public part in the QR code; the *phone*
already effectively "knows" who it's talking to once it scans the code. This
module models the desktop as the Noise *initiator*. Exactly which token
pattern (`KN` vs `NK`, and the precise message sequencing) Chromium uses for
the QR flow is one of the least-documented parts of the protocol -- see the
module-level `HANDSHAKE_PATTERNS` table, which isolates that uncertainty to a
single, easily-corrected data structure rather than scattering assumptions
through imperative code.

This implementation follows the Noise Protocol Framework specification
(https://noiseprotocol.org/noise.html) revision 34's symmetric-state /
handshake-state algorithms, generalized so that the token pattern is
data-driven and the DH/cipher/hash primitives are pluggable.
"""

from __future__ import annotations

import hmac as _hmac_mod
from dataclasses import dataclass, field
from typing import Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ..constants import (
    NOISE_AEAD_NONCE_SIZE,
    NOISE_AEAD_TAG_SIZE,
    NOISE_DH_PUBLIC_KEY_SIZE,
    NOISE_HASH_SIZE,
    NOISE_PROTOCOL_KN,
    NOISE_PROTOCOL_NK,
)

# ---------------------------------------------------------------------------
# Message patterns
#
# Each pattern is a list of "messages"; each message is a list of tokens.
# Supported tokens: "e" (emit/consume an ephemeral public key), "s" (emit/
# consume a static public key), "ee"/"es"/"se"/"ss" (DH operations), and
# "psk" (mix in the pre-shared key). Pre-message tokens (keys known before
# the handshake starts) are listed separately.
#
# These tables encode our best-effort understanding of the `KNpsk0`/`NKpsk0`
# patterns as applied by caBLE v2. If real-device testing shows a mismatch,
# only this table -- not the surrounding state-machine code -- should need
# to change.
# ---------------------------------------------------------------------------

HandshakeRole = str  # "initiator" or "responder"

PATTERN_KN_PSK0 = {
    "name": NOISE_PROTOCOL_KN,
    # "KN": the initiator's static key is known to the responder ahead of
    # time (sent as a pre-message, "K"); the responder has no static key at
    # all ("N"). The canonical Noise_KN pattern is:
    #   -> s          (pre-message)
    #   -> e
    #   <- e, ee, se
    # `psk0` prefixes the very first message with a "psk" token.
    "pre_messages": {"initiator": ["s"], "responder": []},
    "messages": [
        {"sender": "initiator", "tokens": ["psk", "e"]},
        {"sender": "responder", "tokens": ["e", "ee", "se"]},
    ],
}

PATTERN_NK_PSK0 = {
    "name": NOISE_PROTOCOL_NK,
    "pre_messages": {"initiator": [], "responder": ["s"]},
    "messages": [
        {"sender": "initiator", "tokens": ["psk", "e", "es"]},
        {"sender": "responder", "tokens": ["e", "ee"]},
    ],
}

HANDSHAKE_PATTERNS = {
    "KNpsk0": PATTERN_KN_PSK0,
    "NKpsk0": PATTERN_NK_PSK0,
}


# ---------------------------------------------------------------------------
# DH adapter: P-256 over `cryptography`
# ---------------------------------------------------------------------------


@dataclass
class KeyPair:
    private_key: ec.EllipticCurvePrivateKey
    public_bytes: bytes  # uncompressed point, NOISE_DH_PUBLIC_KEY_SIZE bytes


def generate_keypair() -> KeyPair:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = serialize_public_key(private_key.public_key())
    return KeyPair(private_key=private_key, public_bytes=public_bytes)


def keypair_from_private_bytes(scalar: bytes) -> KeyPair:
    private_key = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())
    return KeyPair(private_key=private_key, public_bytes=serialize_public_key(private_key.public_key()))


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(encoded) != NOISE_DH_PUBLIC_KEY_SIZE:
        raise ValueError(f"unexpected P-256 public key encoding length: {len(encoded)}")
    return encoded


def deserialize_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    if len(data) != NOISE_DH_PUBLIC_KEY_SIZE:
        raise ValueError(f"P-256 public key must be {NOISE_DH_PUBLIC_KEY_SIZE} bytes, got {len(data)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def dh(private_key: ec.EllipticCurvePrivateKey, public_key_bytes: bytes) -> bytes:
    """Perform ECDH and return the raw shared X-coordinate as Noise expects."""
    peer_public_key = deserialize_public_key(public_key_bytes)
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key


# ---------------------------------------------------------------------------
# Symmetric state (CipherState + SymmetricState from the Noise spec)
# ---------------------------------------------------------------------------


def _hkdf2(chaining_key: bytes, input_key_material: bytes) -> tuple[bytes, bytes]:
    """Noise `HKDF(chaining_key, input_key_material, 2)` -> (output1, output2)."""
    output = HKDFExpand(algorithm=hashes.SHA256(), length=64, info=b"").derive(
        _hmac_extract(chaining_key, input_key_material)
    )
    return output[:32], output[32:]


def _hkdf3(chaining_key: bytes, input_key_material: bytes) -> tuple[bytes, bytes, bytes]:
    """Noise `HKDF(chaining_key, input_key_material, 3)` -> (output1, output2, output3)."""
    prk = _hmac_extract(chaining_key, input_key_material)
    t1 = _hmac(prk, b"\x01")
    t2 = _hmac(prk, t1 + b"\x02")
    t3 = _hmac(prk, t2 + b"\x03")
    return t1, t2, t3


def _hmac_extract(salt: bytes, ikm: bytes) -> bytes:
    """HMAC-based-extract step (as used by Noise's HKDF, per RFC 5869)."""
    return _hmac_mod.new(salt, ikm, "sha256").digest()


def _hmac(key: bytes, data: bytes) -> bytes:
    return _hmac_mod.new(key, data, "sha256").digest()


@dataclass
class CipherState:
    key: bytes | None = None
    nonce: int = 0

    def initialize(self, key: bytes) -> None:
        self.key = key
        self.nonce = 0

    def has_key(self) -> bool:
        return self.key is not None

    def _nonce_bytes(self) -> bytes:
        # Noise nonces are 64-bit little-endian counters placed in the low
        # bits of a 96-bit (12-byte) AEAD nonce, per the spec's AESGCM
        # convention (4 zero bytes followed by the 8-byte LE counter).
        nonce = b"\x00\x00\x00\x00" + self.nonce.to_bytes(8, "little")
        assert len(nonce) == NOISE_AEAD_NONCE_SIZE
        return nonce

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.key is None:
            return plaintext
        ciphertext = AESGCM(self.key).encrypt(self._nonce_bytes(), plaintext, ad)
        self.nonce += 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.key is None:
            return ciphertext
        plaintext = AESGCM(self.key).decrypt(self._nonce_bytes(), ciphertext, ad)
        self.nonce += 1
        return plaintext


@dataclass
class SymmetricState:
    chaining_key: bytes
    hash_value: bytes
    cipher: CipherState = field(default_factory=CipherState)

    @classmethod
    def initialize(cls, protocol_name: bytes) -> "SymmetricState":
        if len(protocol_name) <= NOISE_HASH_SIZE:
            h = protocol_name + b"\x00" * (NOISE_HASH_SIZE - len(protocol_name))
        else:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(protocol_name)
            h = digest.finalize()
        return cls(chaining_key=h, hash_value=h)

    def mix_key(self, input_key_material: bytes) -> None:
        ck, temp_k = _hkdf2(self.chaining_key, input_key_material)
        self.chaining_key = ck
        self.cipher.initialize(temp_k)

    def mix_hash(self, data: bytes) -> None:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.hash_value + data)
        self.hash_value = digest.finalize()

    def mix_key_and_hash(self, input_key_material: bytes) -> None:
        ck, temp_h, temp_k = _hkdf3(self.chaining_key, input_key_material)
        self.chaining_key = ck
        self.mix_hash(temp_h)
        self.cipher.initialize(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt_with_ad(self.hash_value, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt_with_ad(self.hash_value, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> tuple[CipherState, CipherState]:
        temp_k1, temp_k2 = _hkdf2(self.chaining_key, b"")
        c1, c2 = CipherState(), CipherState()
        c1.initialize(temp_k1)
        c2.initialize(temp_k2)
        return c1, c2


# ---------------------------------------------------------------------------
# Handshake state machine
# ---------------------------------------------------------------------------


@dataclass
class HandshakeResult:
    send_cipher: CipherState
    receive_cipher: CipherState
    handshake_hash: bytes


class NoiseHandshake:
    """Drives a Noise handshake for a given pattern, role, and key material.

    Each protocol message is produced/consumed by `write_message`/
    `read_message`, keeping the byte-level wire format isolated from the
    cryptographic bookkeeping -- both are independently inspectable, and a
    transcript of intermediate `chaining_key`/`hash_value` values can be
    dumped for debugging (see `debug_log`).
    """

    def __init__(
        self,
        *,
        pattern: dict,
        role: HandshakeRole,
        local_static: KeyPair | None = None,
        local_ephemeral: KeyPair | None = None,
        remote_static_public: bytes | None = None,
        psk: bytes,
        prologue: bytes = b"",
        debug_log: Callable[[str, dict], None] | None = None,
    ) -> None:
        if role not in ("initiator", "responder"):
            raise ValueError(f"invalid role: {role!r}")

        self.pattern = pattern
        self.role = role
        self.psk = psk
        self.debug_log = debug_log or (lambda *_: None)

        self.symmetric = SymmetricState.initialize(pattern["name"])
        self.symmetric.mix_hash(prologue)

        self.local_static = local_static
        self.local_ephemeral = local_ephemeral
        self.remote_static_public = remote_static_public
        self.remote_ephemeral_public: bytes | None = None

        self._message_index = 0
        self._apply_pre_messages()

    # -- setup -------------------------------------------------------------

    def _apply_pre_messages(self) -> None:
        peer_role = "responder" if self.role == "initiator" else "initiator"
        for owner_role in ("initiator", "responder"):
            for token in self.pattern["pre_messages"].get(owner_role, []):
                if token != "s":
                    raise ValueError(f"unsupported pre-message token: {token!r}")
                if owner_role == self.role:
                    if self.local_static is None:
                        raise ValueError("pattern requires a local static key that was not provided")
                    self.symmetric.mix_hash(self.local_static.public_bytes)
                elif owner_role == peer_role:
                    if self.remote_static_public is None:
                        raise ValueError("pattern requires a remote static key that was not provided")
                    self.symmetric.mix_hash(self.remote_static_public)
        self.debug_log("pre_messages", self._snapshot())

    def _snapshot(self) -> dict:
        return {
            "chaining_key": self.symmetric.chaining_key.hex(),
            "hash": self.symmetric.hash_value.hex(),
        }

    # -- message processing -------------------------------------------------

    def write_message(self, payload: bytes = b"") -> bytes:
        message = self._next_message(expected_sender=self.role)
        out = bytearray()
        for token in message["tokens"]:
            out += self._write_token(token)
        out += self.symmetric.encrypt_and_hash(payload)
        self.debug_log(f"write_message[{self._message_index - 1}]", self._snapshot())
        return bytes(out)

    def read_message(self, data: bytes) -> bytes:
        peer_role = "responder" if self.role == "initiator" else "initiator"
        message = self._next_message(expected_sender=peer_role)
        offset = 0
        for token in message["tokens"]:
            offset = self._read_token(token, data, offset)
        plaintext = self.symmetric.decrypt_and_hash(data[offset:])
        self.debug_log(f"read_message[{self._message_index - 1}]", self._snapshot())
        return plaintext

    def _next_message(self, *, expected_sender: str) -> dict:
        if self._message_index >= len(self.pattern["messages"]):
            raise RuntimeError("handshake already complete: no more messages in pattern")
        message = self.pattern["messages"][self._message_index]
        if message["sender"] != expected_sender:
            raise RuntimeError(
                f"out-of-order handshake message: expected sender "
                f"{expected_sender!r}, pattern says {message['sender']!r}"
            )
        self._message_index += 1
        return message

    def is_complete(self) -> bool:
        return self._message_index >= len(self.pattern["messages"])

    def finish(self) -> HandshakeResult:
        if not self.is_complete():
            raise RuntimeError("cannot finish: handshake messages remain")
        c1, c2 = self.symmetric.split()
        if self.role == "initiator":
            send_cipher, receive_cipher = c1, c2
        else:
            send_cipher, receive_cipher = c2, c1
        return HandshakeResult(
            send_cipher=send_cipher,
            receive_cipher=receive_cipher,
            handshake_hash=self.symmetric.hash_value,
        )

    # -- token handlers ------------------------------------------------------

    def _write_token(self, token: str) -> bytes:
        if token == "e":
            if self.local_ephemeral is None:
                self.local_ephemeral = generate_keypair()
            self.symmetric.mix_hash(self.local_ephemeral.public_bytes)
            return self.local_ephemeral.public_bytes
        if token == "s":
            if self.local_static is None:
                raise ValueError("pattern requires a local static key that was not provided")
            return self.symmetric.encrypt_and_hash(self.local_static.public_bytes)
        if token == "psk":
            self.symmetric.mix_key_and_hash(self.psk)
            return b""
        if token in ("ee", "es", "se", "ss"):
            self.symmetric.mix_key(self._dh_for_token(token))
            return b""
        raise ValueError(f"unsupported handshake token: {token!r}")

    def _read_token(self, token: str, data: bytes, offset: int) -> int:
        if token == "e":
            key_bytes = data[offset : offset + NOISE_DH_PUBLIC_KEY_SIZE]
            if len(key_bytes) != NOISE_DH_PUBLIC_KEY_SIZE:
                raise ValueError("truncated handshake message: missing ephemeral public key")
            self.remote_ephemeral_public = key_bytes
            self.symmetric.mix_hash(key_bytes)
            return offset + NOISE_DH_PUBLIC_KEY_SIZE
        if token == "s":
            has_key = self.symmetric.cipher.has_key()
            key_len = NOISE_DH_PUBLIC_KEY_SIZE + (NOISE_AEAD_TAG_SIZE if has_key else 0)
            encrypted = data[offset : offset + key_len]
            if len(encrypted) != key_len:
                raise ValueError("truncated handshake message: missing static public key")
            self.remote_static_public = self.symmetric.decrypt_and_hash(encrypted)
            return offset + key_len
        if token == "psk":
            self.symmetric.mix_key_and_hash(self.psk)
            return offset
        if token in ("ee", "es", "se", "ss"):
            self.symmetric.mix_key(self._dh_for_token(token))
            return offset
        raise ValueError(f"unsupported handshake token: {token!r}")

    def _dh_for_token(self, token: str) -> bytes:
        """Resolve a DH token (`ee`/`es`/`se`/`ss`) to the key pair to use.

        Token semantics (from the initiator's perspective; the responder
        applies the mirrored interpretation -- both resolve to the same
        shared secret):
          ee: local ephemeral, remote ephemeral
          es: initiator's ephemeral/static (whichever it has) with responder's static/ephemeral
          se: the mirror of `es`
          ss: local static, remote static
        """
        first, second = token[0], token[1]
        local_key = {
            "e": self.local_ephemeral,
            "s": self.local_static,
        }
        remote_key = {
            "e": self.remote_ephemeral_public,
            "s": self.remote_static_public,
        }

        # In Noise notation `xy` always means "DH(initiator's x, responder's
        # y key)". For the initiator that's DH(local_x, remote_y); for the
        # responder it's DH(local_y, remote_x).
        if self.role == "initiator":
            local = local_key[first]
            remote = remote_key[second]
        else:
            local = local_key[second]
            remote = remote_key[first]

        if local is None or remote is None:
            raise RuntimeError(f"missing key material to perform DH({token})")
        return dh(local.private_key, remote)


__all__ = [
    "HANDSHAKE_PATTERNS",
    "PATTERN_KN_PSK0",
    "PATTERN_NK_PSK0",
    "KeyPair",
    "generate_keypair",
    "keypair_from_private_bytes",
    "serialize_public_key",
    "deserialize_public_key",
    "dh",
    "CipherState",
    "SymmetricState",
    "HandshakeResult",
    "NoiseHandshake",
]
