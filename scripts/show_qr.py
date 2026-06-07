#!/usr/bin/env python3
"""Manual verification helper: generate and display a hybrid-transport QR
code without connecting to anything (no network, no phone needed).

Usage:
    python scripts/show_qr.py [ga|mc]
"""

from __future__ import annotations

import secrets
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent / "src"))

from cable import qr  # noqa: E402
from cable.crypto import noise  # noqa: E402
from cable.constants import REQUEST_TYPE_GET_ASSERTION, REQUEST_TYPE_MAKE_CREDENTIAL, QR_SECRET_SIZE  # noqa: E402


def main() -> None:
    request_type = REQUEST_TYPE_GET_ASSERTION
    if len(sys.argv) > 1:
        request_type = {"ga": REQUEST_TYPE_GET_ASSERTION, "mc": REQUEST_TYPE_MAKE_CREDENTIAL}[sys.argv[1]]

    keypair = noise.generate_keypair()
    handshake = qr.HandshakeV2(
        peer_identity=keypair.public_bytes,
        secret=secrets.token_bytes(QR_SECRET_SIZE),
        timestamp=int(time.time()),
        request_type=request_type,
    )
    uri = qr.build_fido_uri(handshake)

    print()
    qr.render_qr_ascii(uri)
    print()
    print(f"URI ({len(uri)} chars): {uri}")


if __name__ == "__main__":
    main()
