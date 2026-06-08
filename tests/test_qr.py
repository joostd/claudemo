import io

import cbor2

from cable import base10, qr
from cable.constants import (
    FIDO_URI_PREFIX,
    HANDSHAKE_FIELD_PEER_IDENTITY,
    HANDSHAKE_FIELD_REQUEST_TYPE,
    HANDSHAKE_FIELD_SECRET,
    HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS,
    QR_PEER_IDENTITY_SIZE,
    QR_SECRET_SIZE,
    TRANSPORT_CHANNEL_WEBSOCKET,
)


def _sample_handshake():
    return qr.HandshakeV2(
        peer_identity=b"\x02" + b"\x01" * (QR_PEER_IDENTITY_SIZE - 1),  # plausible compressed P-256 point shape
        secret=b"\x02" * QR_SECRET_SIZE,
        timestamp=1_700_000_000,
        request_type="ga",
    )


def test_handshake_rejects_bad_secret_size():
    import pytest

    with pytest.raises(ValueError):
        qr.HandshakeV2(peer_identity=b"\x02" + b"\x00" * 32, secret=b"\x00" * 5)


def test_handshake_rejects_bad_peer_identity_size():
    import pytest

    with pytest.raises(ValueError):
        qr.HandshakeV2(peer_identity=b"\x04" + b"\x00" * 64, secret=b"\x00" * QR_SECRET_SIZE)


def test_handshake_default_supported_transports_is_websocket_only():
    handshake = _sample_handshake()
    assert handshake.supported_transports == [TRANSPORT_CHANNEL_WEBSOCKET]


def test_encode_handshake_cbor_shape():
    handshake = _sample_handshake()
    encoded = qr.encode_handshake(handshake)
    decoded = cbor2.loads(encoded)

    assert isinstance(decoded, dict)
    assert decoded[HANDSHAKE_FIELD_PEER_IDENTITY] == handshake.peer_identity
    assert decoded[HANDSHAKE_FIELD_SECRET] == handshake.secret
    assert decoded[HANDSHAKE_FIELD_REQUEST_TYPE] == "ga"
    assert decoded[HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS] == handshake.supported_transports
    assert isinstance(decoded[HANDSHAKE_FIELD_PEER_IDENTITY], bytes)
    assert isinstance(decoded[HANDSHAKE_FIELD_SECRET], bytes)
    assert isinstance(decoded[HANDSHAKE_FIELD_SUPPORTED_TRANSPORTS], list)


def test_encode_decode_handshake_round_trip():
    handshake = _sample_handshake()
    encoded = qr.encode_handshake(handshake)
    decoded = qr.decode_handshake(encoded)
    assert decoded == handshake


def test_build_fido_uri_format():
    handshake = _sample_handshake()
    uri = qr.build_fido_uri(handshake)

    assert uri.startswith(FIDO_URI_PREFIX)
    digits = uri[len(FIDO_URI_PREFIX):]
    assert digits.isdigit()

    # The URI must base10-decode back to exactly the CBOR bytes we encoded.
    assert base10.decode(digits) == qr.encode_handshake(handshake)


def test_render_qr_ascii_smoke():
    buf = io.StringIO()
    qr.render_qr_ascii("FIDO:/12345", out=buf)
    output = buf.getvalue()

    assert output.strip()
    # ASCII-art QR codes (non-tty path) are rendered with these block characters.
    assert any(ch in output for ch in "█▄▀ ")
