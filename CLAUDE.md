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
.venv/bin/cable get-info                     # full flow: connect to a phone, print GetInfo
.venv/bin/cable get-assertion --rp-id ... --challenge ...
.venv/bin/cable make-credential --rp-id ... --user-id ... --user-name ... --challenge ...
python scripts/show_qr.py [ga|mc]            # manual QR-display helper, no install required
```

## Architecture

Source lives under `src/cable/`. The CTAP2 *semantics* (command construction,
response parsing, error translation) are entirely delegated to Yubico's
`fido2` library (`fido2.ctap2.Ctap2`); this codebase's job is purely to
**transport** opaque CTAP2 byte blobs through an encrypted hybrid-transport
channel. The bridge between the two is `device.CtapHybridDevice`, a
`fido2.ctap.CtapDevice` subclass whose `call()` sends a `CableMessage` over
the channel and waits for the matching response.

Data flow for one CTAP2 round-trip:

```
Ctap2.get_assertion(...)
  -> Ctap2.send_cbor(cmd, args)         [fido2: builds bytes([cmd]) + cbor(args)]
  -> CtapHybridDevice.call(CTAPHID.CBOR, request)
       channel.send_message(CableFrameType.CTAP, request)   [transport/channel.py]
         -> pad([type byte] || request); AES-256-GCM-encrypt; tunnel.send(ciphertext)
       ... await response message ...
         <- tunnel.recv(); AES-256-GCM-decrypt; unpad -> [type byte] || payload
       -> bytes([status]) + cbor(response)
  -> Ctap2.send_cbor unpacks status/CBOR -> typed response object
```

Note that the type byte lives *inside* the encrypted, padded plaintext (it is
part of what gets AES-GCM-sealed), not as a cleartext prefix on the WebSocket
frame -- each binary WebSocket frame is exactly one opaque ciphertext blob.

Module layout (each is independently unit-tested -- see "Protocol uncertainty" below):

- `constants.py` -- **every** protocol magic number/string, centralized with
  citations. If real-device testing reveals a wrong byte-level assumption,
  this is almost always the only file that needs to change.
- `base10.py` -- the custom decimal encoding used to embed binary CBOR into
  the `FIDO:/<digits>` URI (decoder implemented first as the canonical
  definition; encoder derived as its provable inverse).
- `qr.py` -- `HandshakeV2` CBOR payload (33-byte compressed P-256
  `peer_identity`, 16-byte `secret`, integer list of `supported_transports`,
  ...) + terminal QR rendering via `pyqrcode`'s `QRCode.terminal()`
  (alphanumeric mode, error correction `L` -- `FIDO:/<digits>` URIs only ever
  use the QR alphanumeric character set, so this yields the smallest code).
- `crypto/kdf.py` -- HKDF-SHA256 derivations of session secrets from the QR
  secret (EID key, tunnel ID, PSK, ...), keyed by small-integer purpose codes
  (1/2/3/...) packed as 4-byte *little-endian* `info` (`DerivedValueType`).
- `crypto/eid.py` -- BLE "Encrypted Identifier" build/encrypt/verify.
- `crypto/noise.py` -- a **generic, pattern-table-driven** Noise-like
  state machine (`Noise_KNpsk0_P256_AESGCM_SHA256` / `..._NKpsk0_...`) over
  P-256 ECDH + AES-256-GCM + SHA-256, with the caBLE-specific deviations from
  textbook Noise baked into the pattern tables and shared helpers rather than
  scattered through the state machine:
  - a **prologue** step (`PATTERN_*["prologue_owner"]`/`["prologue_byte"]`):
    `mixHash([0 or 1])` then `mixHash` of the *uncompressed* (65-byte X9.62)
    static public key owned by whichever side the pattern designates --
    the same encoding used for every in-handshake DH token, even though the
    QR only ever conveys that key in compressed (33-byte) form -- before any
    tokens run;
  - the `"e"` token both `mixHash`es **and** `mixKey`s the raw ephemeral
    public-key bytes (not just `mixHash`, as plain Noise would do);
  - `pad_message`/`unpad_message` (granularity `TRANSPORT_PADDING_GRANULARITY`
    = 32, last byte = padding length minus one) belong conceptually to
    transport encryption (post-handshake), not the handshake itself, but live
    here alongside `CipherState`;
  - `CipherState` builds its AEAD nonce as a big-endian 4-byte counter plus an
    all-zero remainder, but the counter's *placement* depends on context
    (confirmed against Chromium's `device/fido/cable/{noise,v2_handshake}.cc`
    -- getting this backwards causes silent AEAD authentication failure on the
    very first encrypted handshake payload, which manifests on the peer as an
    immediate abort): `Noise::EncryptAndHash`/`DecryptAndHash` (driving
    `SymmetricState.cipher` during the handshake) place the counter in the
    *first* 4 bytes (`counter_prefix=True`), while `Crypter::ConstructNonce`
    (the post-handshake transport ciphers returned by `SymmetricState.split`)
    place it in the *last* 4 bytes (`counter_prefix=False`, the default).

  The token sequences live in `HANDSHAKE_PATTERNS`/`PATTERN_KN_PSK0`/
  `PATTERN_NK_PSK0` so a wrong pattern assumption requires changing only that
  table. Supports a `debug_log` callback (wired to `--debug-noise`) that dumps
  `chaining_key`/`hash` after every message (including the prologue step) for
  transcript comparison.
- `transport/tunnel.py` -- `TunnelConnection`, a thin WebSocket connection to
  the relay ("tunnel server") that ships/receives **raw opaque byte frames**
  (no framing of its own -- see `transport/channel.py` for that layer) plus
  `tunnel_url(domain_id, routing_id, tunnel_id)` for addressing it.
- `transport/channel.py` -- `CableChannel`/`CableMessage`: the encrypted,
  padded, type-byte-framed application layer described in the data-flow
  diagram above, layered on top of a raw `TunnelConnection` plus the two
  per-direction traffic `CipherState`s produced by the handshake. Also exposes
  `recv_post_handshake()` for the one bare (type-byte-less) CBOR message that
  precedes normal typed traffic (see below).
- `transport/ble.py` -- BLE EID scanning. Per CTAP 2.3 sctn-hybrid, receiving
  and decrypting the phone's advertisement is a **hard prerequisite** of the
  QR-initiated flow -- it is the *only* source of the routing ID (needed to
  address the tunnel) and the connection nonce (which salts the Noise PSK), so
  the orchestration in `cli.py` treats a `None` result as a hard failure. The
  scan function itself stays resilient at the *mechanism* level though
  (missing adapter/permissions/`bleak`, scanner errors, plain timeouts all
  resolve to `None` rather than raising) -- it's the caller's job to decide
  what `None` means for the flow it's driving.
- `device.py` -- `CtapHybridDevice`, the `CtapDevice` adapter described
  above. Bridges the synchronous `CtapDevice.call` interface to the async
  `CableChannel` via a dedicated background event-loop thread
  (`_BackgroundLoop` + `asyncio.run_coroutine_threadsafe`).
- `cli.py` -- `click`-based subcommands (`qr`, `get-info`, `get-assertion`,
  `make-credential`) and orchestration of the end-to-end flow: generate
  ephemeral keypair + QR secret -> display QR -> **block on the BLE
  advertisement** -> derive routing ID / tunnel ID / PSK (salted with the full
  16-byte decrypted advert) from it -> connect to the tunnel and run the Noise
  handshake -> read and validate the mandatory post-handshake message (cached
  `getInfo`) -> wrap the channel in `CtapHybridDevice` and drive it with a
  `fido2.ctap2.Ctap2` seeded from that cached `getInfo` (`_ctap2_from_cached_info`,
  bypassing `Ctap2.__init__`'s own `authenticatorGetInfo` round trip -- the
  cached response was sent precisely to make that redundant, and at least one
  real authenticator, iOS, closes the tunnel outright if asked again anyway).
  That cached `getInfo` is parsed leniently (`_lenient_info_from_dict`):
  confirmed that iOS includes newer/draft fields (`encIdentifier`,
  `pinComplexityPolicyURL`, `encCredStoreState`) shaped differently than this
  `fido2` version's `Info` dataclass expects (arrays/maps where it wants
  `bytes`), which makes the strict `Info.from_dict` abort the entire parse --
  fields it can't parse are dropped instead, since `Ctap2` only ever consults
  the well-established core fields.

## Protocol uncertainty -- read before "fixing" the crypto/wire-format code

CTAP 2.3 §11.5 "Hybrid transports" is the canonical reference for this
protocol, and the implementation has been audited against its text directly
(not just against open-source reimplementations) -- see the spec's Go
pseudocode for `showQRCode`/`encodeQRContents`/`digitEncode`, `awaitAdvert`/
`trialDecrypt`, `derive`/`keyPurpose*`, `decodeTunnelServerDomain`/
`connectToPhone`, `doQRHandshake`/`doHandshake`, `cableConn.Write`/`Read`/
`setupAEAD`, `readPostHandshakeMessage`, and `sendCTAP2Request` for the
ground truth behind every module below.

Residual risk is therefore much lower than "reverse-engineered from an
incomplete reimplementation," but real-device interop (a real phone, a real
tunnel server, real BLE hardware) remains untested from this environment:
- `base10.py`, `crypto/kdf.py`, `crypto/eid.py`, `qr.py`, `crypto/noise.py`
  (handshake *and* transport-encryption helpers), and the
  `transport/tunnel.py` + `transport/channel.py` framing are all implemented
  directly from the spec text and have full round-trip / loopback / mocked
  test coverage corresponding to their spec pseudocode.
- `transport/ble.py` cannot be exercised at all without real BLE hardware, a
  real phone, and OS Bluetooth permissions.
- The "computed" tunnel-domain scheme for domain IDs >= 256 (§11.5
  `decodeTunnelServerDomain`'s hash-based branch) is **not** implemented
  (`transport.tunnel.tunnel_url` raises `NotImplementedError`); only the
  well-known domains (`cable.ua5v.com`, `cable.auth.com`) are wired up.

If real-device testing still reveals a mismatch, the most useful tool is
`--debug-noise`'s `chaining_key`/`hash` transcript dump, diffed against an
instrumented reference client (e.g. Chromium's `device/fido/cable/` or the
Rust `webauthn-authenticator-rs` crate) for identical inputs.

## Testing strategy

Everything that can be validated **offline** (no phone, no real tunnel
server, no BLE hardware) has real test coverage: encoding/derivation
round-trips, a Noise-handshake loopback between an initiator and an in-test
mirror "responder" (proves internal self-consistency *and* spec-pseudocode
fidelity for the parts exercisable without a real peer -- prologue, extra
`mixKey`, PSK mixing, transport-key derivation), padding round-trips, mocked-
tunnel framing tests for both `TunnelConnection` (raw bytes) and
`CableChannel` (encryption/padding/type-byte layer), and a fake-channel test
proving the full `CtapHybridDevice` <-> `Ctap2` bridge. What it *cannot*
prove -- because it requires a real phone and a real tunnel server -- is
byte-for-byte wire compatibility with an actual Chromium/phone
authenticator; that's the residual risk documented above.
