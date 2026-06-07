import pytest

from cable.crypto import noise


def _run_loopback(pattern, *, initiator_has_static, responder_has_static):
    """Drive a full handshake between an in-process initiator/responder pair.

    This proves internal self-consistency of the symmetric-state machine and
    token interpretation -- both sides must derive identical transport keys
    and be able to exchange ciphertext. It does **not** prove byte-for-byte
    compatibility with Chromium's implementation (see crypto/noise.py and
    CLAUDE.md for that caveat); no real-world test vectors are publicly
    available for this non-standard cipher suite.
    """
    psk = b"\x24" * 32

    initiator_static = noise.generate_keypair() if initiator_has_static else None
    responder_static = noise.generate_keypair() if responder_has_static else None

    initiator = noise.NoiseHandshake(
        pattern=pattern,
        role="initiator",
        local_static=initiator_static,
        remote_static_public=(responder_static.public_bytes if responder_static else None),
        psk=psk,
    )
    responder = noise.NoiseHandshake(
        pattern=pattern,
        role="responder",
        local_static=responder_static,
        remote_static_public=(initiator_static.public_bytes if initiator_static else None),
        psk=psk,
    )

    parties = {"initiator": initiator, "responder": responder}
    for message in pattern["messages"]:
        sender = parties[message["sender"]]
        receiver = parties["responder" if message["sender"] == "initiator" else "initiator"]

        payload = b"hello from " + message["sender"].encode()
        wire = sender.write_message(payload)
        recovered = receiver.read_message(wire)
        assert recovered == payload

    assert initiator.is_complete()
    assert responder.is_complete()
    return initiator.finish(), responder.finish()


@pytest.mark.parametrize(
    "pattern,initiator_has_static,responder_has_static",
    [
        (noise.PATTERN_NK_PSK0, False, True),
        (noise.PATTERN_KN_PSK0, True, False),
    ],
)
def test_loopback_handshake_derives_symmetric_keys(pattern, initiator_has_static, responder_has_static):
    initiator_result, responder_result = _run_loopback(
        pattern,
        initiator_has_static=initiator_has_static,
        responder_has_static=responder_has_static,
    )

    assert initiator_result.handshake_hash == responder_result.handshake_hash
    # Each side's "send" cipher must match the other's "receive" cipher.
    assert initiator_result.send_cipher.key == responder_result.receive_cipher.key
    assert initiator_result.receive_cipher.key == responder_result.send_cipher.key


@pytest.mark.parametrize(
    "pattern,initiator_has_static,responder_has_static",
    [
        (noise.PATTERN_NK_PSK0, False, True),
        (noise.PATTERN_KN_PSK0, True, False),
    ],
)
def test_loopback_post_handshake_transport_round_trip(pattern, initiator_has_static, responder_has_static):
    initiator_result, responder_result = _run_loopback(
        pattern,
        initiator_has_static=initiator_has_static,
        responder_has_static=responder_has_static,
    )

    plaintext = b"authenticatorGetInfo response payload"
    ciphertext = initiator_result.send_cipher.encrypt_with_ad(b"", plaintext)
    assert responder_result.receive_cipher.decrypt_with_ad(b"", ciphertext) == plaintext

    reply = b"authenticatorGetAssertion request payload"
    reply_ciphertext = responder_result.send_cipher.encrypt_with_ad(b"", reply)
    assert initiator_result.receive_cipher.decrypt_with_ad(b"", reply_ciphertext) == reply


def test_p256_dh_round_trip():
    a = noise.generate_keypair()
    b = noise.generate_keypair()

    assert noise.dh(a.private_key, b.public_bytes) == noise.dh(b.private_key, a.public_bytes)


def test_serialize_deserialize_public_key_round_trip():
    keypair = noise.generate_keypair()
    restored = noise.deserialize_public_key(keypair.public_bytes)
    assert noise.serialize_public_key(restored) == keypair.public_bytes


def test_cipher_state_requires_key_before_real_encryption():
    # Per the Noise spec, encrypt/decrypt with no key set is a passthrough
    # (used before the first DH establishes a shared secret).
    state = noise.CipherState()
    assert state.encrypt_with_ad(b"ad", b"plaintext") == b"plaintext"
    assert state.decrypt_with_ad(b"ad", b"plaintext") == b"plaintext"
