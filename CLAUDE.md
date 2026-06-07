# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A command-line FIDO client (`cable`) that acts as the "desktop" side of FIDO's
**hybrid transport** (caBLE v2): it displays a `FIDO:/...` QR code as ASCII
art, a phone scans it, and the two sides exchange CTAP2 commands
(GetInfo / MakeCredential / GetAssertion) over an encrypted tunnel.

## Commands

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[test]"

.venv/bin/pytest                      # run the test suite
.venv/bin/pytest tests/test_noise.py  # run a single test file
.venv/bin/pytest tests/test_noise.py::test_loopback_handshake_derives_symmetric_keys -k KN  # single test

.venv/bin/python -m pyflakes src/cable tests scripts   # lint (no other linter configured)

.venv/bin/cable qr                          # display a QR code only -- no network/phone needed
.venv/bin/cable get-info [--no-ble]          # full flow: connect to a phone, print GetInfo
.venv/bin/cable get-assertion --rp-id ... --challenge ...
.venv/bin/cable make-credential --rp-id ... --user-id ... --user-name ... --challenge ...
python scripts/show_qr.py [ga|mc]            # manual QR-display helper, no install required
```

## Architecture

Source lives under `src/cable/`. The CTAP2 *semantics* (command construction,
response parsing, error translation) are entirely delegated to Yubico's
`fido2` library (`fido2.ctap2.Ctap2`); this codebase's job is purely to
**transport** opaque CTAP2 byte blobs through an encrypted hybrid-transport
tunnel. The bridge between the two is `device.CtapHybridDevice`, a
`fido2.ctap.CtapDevice` subclass whose `call()` Noise-encrypts/frames/sends a
request and decrypts the response.

Data flow for one CTAP2 round-trip:

```
Ctap2.get_assertion(...)
  -> Ctap2.send_cbor(cmd, args)         [fido2: builds bytes([cmd]) + cbor(args)]
  -> CtapHybridDevice.call(CTAPHID.CBOR, request)
       Noise-encrypt(request)
       tunnel.send_message(CableFrameType.CTAP, ciphertext)   [transport/tunnel.py]
       ... await response frame ...
       Noise-decrypt(ciphertext) -> bytes([status]) + cbor(response)
  -> Ctap2.send_cbor unpacks status/CBOR -> typed response object
```

Module layout (each is independently unit-tested -- see "Protocol uncertainty" below):

- `constants.py` -- **every** protocol magic number/string, centralized with
  citations. If real-device testing reveals a wrong byte-level assumption,
  this is almost always the only file that needs to change.
- `base10.py` -- the custom decimal encoding used to embed binary CBOR into
  the `FIDO:/<digits>` URI (decoder implemented first as the canonical
  definition; encoder derived as its provable inverse).
- `qr.py` -- `HandshakeV2` CBOR payload + ASCII QR rendering (`qrcode`).
- `crypto/kdf.py` -- HKDF-SHA256 derivations of session secrets from the QR
  secret (EID key, tunnel ID, PSK, ...).
- `crypto/eid.py` -- BLE "Encrypted Identifier" build/encrypt/verify.
- `crypto/noise.py` -- a **generic, pattern-table-driven** Noise Protocol
  state machine (`Noise_KNpsk0_P256_AESGCM_SHA256` / `..._NKpsk0_...`) over
  P-256 ECDH + AES-256-GCM + SHA-256. The token sequences live in
  `HANDSHAKE_PATTERNS`/`PATTERN_KN_PSK0`/`PATTERN_NK_PSK0` so a wrong pattern
  assumption requires changing only that table, not the surrounding crypto
  plumbing. Supports a `debug_log` callback (wired to `--debug-noise`) that
  dumps `chaining_key`/`hash` after every message for transcript comparison.
- `transport/tunnel.py` -- WebSocket connection to the relay ("tunnel
  server") plus the single-byte message-type framing
  (`constants.CableFrameType`).
- `transport/ble.py` -- best-effort, **never-blocking** BLE proximity check
  (the phone can connect via the tunnel regardless of whether this succeeds;
  every failure mode here -- no adapter, no permissions, timeout, no match --
  resolves to `None`, "proceed without confirmation").
- `device.py` -- `CtapHybridDevice`, the `CtapDevice` adapter described
  above. Bridges the synchronous `CtapDevice.call` interface to the async
  tunnel via a dedicated background event-loop thread
  (`_BackgroundLoop` + `asyncio.run_coroutine_threadsafe`).
- `cli.py` -- `click`-based subcommands (`qr`, `get-info`, `get-assertion`,
  `make-credential`) and orchestration of the end-to-end flow.

## Protocol uncertainty -- read before "fixing" the crypto/wire-format code

**There is no official published specification for caBLE v2.** Every
byte-level constant in `constants.py` (CBOR field IDs, the base10 chunking
table, the Noise protocol-name strings, HKDF info constants, tunnel URL
format, message framing bytes, BLE EID layout) was reverse-engineered from
the most complete open-source reimplementation, the Rust
`webauthn-authenticator-rs` crate (`github.com/kanidm/webauthn-rs`), whose
own authors describe their implementation as incomplete. Chromium's
`device/fido/cable/` C++ source is the only "more canonical" reference, and
it is not practical to consult byte-for-byte from this environment.

Concretely, this means:
- `base10.py`, `crypto/kdf.py`, `crypto/eid.py`, and `qr.py` are
  high-confidence: they're pure data transforms/derivations with full
  round-trip test coverage, and the only way they can be "wrong" is if the
  *constants* in `constants.py` are wrong (in which case a real phone will
  reject the QR code -- use `--dump`-style debugging by comparing
  `qr.encode_handshake()` output against a working reference client).
- `crypto/noise.py` is the **highest-risk** module: the exact token pattern
  for the QR-initiated flow (`KNpsk0` vs. `NKpsk0`, message ordering, what
  salts the PSK) is the least-documented part of the protocol. It is
  structured so that fixing a wrong assumption means editing
  `HANDSHAKE_PATTERNS` (and possibly the PSK-derivation call site in
  `cli._connect_and_handshake`), not rewriting the symmetric-state machine.
- `transport/ble.py` cannot be exercised at all without real BLE hardware, a
  real phone, and OS Bluetooth permissions -- it is intentionally optional
  and non-blocking.
- The "computed" tunnel-domain scheme for domain IDs >= 256 is **not**
  implemented (`transport.tunnel.tunnel_url` raises `NotImplementedError`);
  only the two well-known domains (`cable.ua5v.com`, `cable.auth.com`) work.

When debugging real-device interop, the most useful tool is running the Rust
`webauthn-authenticator-rs` reference side-by-side (instrumented to dump the
same intermediate values `--debug-noise` exposes here) and diffing
transcripts for identical inputs.

## Testing strategy

Everything that can be validated **offline** (no phone, no real tunnel
server, no BLE hardware) has real test coverage: encoding/derivation
round-trips, a Noise loopback handshake between an initiator and an in-test
mirror "responder" (proves internal self-consistency, *not*
Chromium-compatibility), mocked-websocket framing tests, and a fake-tunnel
test proving the full `CtapHybridDevice` <-> `Ctap2` bridge. What it
*cannot* prove -- because it requires a real phone and a real tunnel
server -- is byte-for-byte wire compatibility; that's the residual risk
documented above.
