#!/usr/bin/env python3
"""Standalone tool: download the largeBlobArray from a USB security key.

Talks directly to a locally attached authenticator over USB CTAPHID using
Yubico's `fido2` library (`fido2.hid` for USB transport, `fido2.ctap2.Ctap2`
+ `fido2.ctap2.blob.LargeBlobs` for the CTAP2.1 `authenticatorLargeBlobs`
command) -- no caBLE/hybrid transport, no phone, no `cable` package.

Requires only `pip install fido2`.

Usage:
    python3 largeBlobArray.py                          # list attached FIDO USB devices
    python3 largeBlobArray.py --list

    python3 largeBlobArray.py --dump                    # dump the raw largeBlobArray
    python3 largeBlobArray.py --dump --output blobs.cbor

    python3 largeBlobArray.py --large-blob-key <hex>     # decrypt one credential's blob
    python3 largeBlobArray.py --large-blob-key <hex> --output blob.bin

    python3 largeBlobArray.py --serial <serial> --dump   # pick a specific device
    python3 largeBlobArray.py --pin 1234 --dump          # supply a PIN (rarely needed to read)
"""

from __future__ import annotations

import argparse
import sys

from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice, list_devices


def find_devices() -> list[CtapHidDevice]:
    return list(list_devices())


def describe(device: CtapHidDevice) -> str:
    d = device.descriptor
    return f"{d.product_name or 'unknown'} (serial={d.serial_number or '?'}, path={d.path!r})"


def select_device(devices: list[CtapHidDevice], serial: str | None) -> CtapHidDevice:
    if serial:
        for device in devices:
            if device.descriptor.serial_number == serial:
                return device
        sys.exit(f"error: no attached device with serial {serial!r}")

    if len(devices) == 1:
        return devices[0]

    sys.exit(
        f"error: {len(devices)} FIDO USB devices attached; pass --serial to pick one:\n"
        + "\n".join(f"  - {describe(d)}" for d in devices)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="List attached FIDO USB devices and exit.")
    parser.add_argument("--dump", action="store_true", help="Dump the entire (raw, per-credential-encrypted) largeBlobArray.")
    parser.add_argument("--large-blob-key", help="Hex-encoded largeBlobKey; decrypts and prints just that credential's blob.")
    parser.add_argument("--serial", help="Serial number of the device to use, if more than one is attached.")
    parser.add_argument("--pin", help="PIN, only needed if the authenticator requires UV to read (uncommon).")
    parser.add_argument("--output", help="Write the result to a file instead of stdout.")
    args = parser.parse_args()

    devices = find_devices()

    if args.list or not (args.dump or args.large_blob_key):
        if not devices:
            print("no FIDO USB devices found", file=sys.stderr)
            sys.exit(1)
        for device in devices:
            print(describe(device))
        return

    if not devices:
        sys.exit("error: no FIDO USB devices found")

    device = select_device(devices, args.serial)

    try:
        ctap2 = Ctap2(device)

        if not LargeBlobs.is_supported(ctap2.info):
            sys.exit("error: authenticator does not support the largeBlobs CTAP2.1 extension")

        pin_uv_protocol = pin_uv_token = None
        if args.pin:
            client_pin = ClientPin(ctap2)
            pin_uv_protocol = client_pin.protocol
            pin_uv_token = client_pin.get_pin_token(args.pin, permissions=ClientPin.PERMISSION.LARGE_BLOB_WRITE)

        large_blobs = LargeBlobs(ctap2, pin_uv_protocol, pin_uv_token)

        if args.large_blob_key:
            key = bytes.fromhex(args.large_blob_key)
            blob = large_blobs.get_blob(key)
            if blob is None:
                sys.exit("error: no large blob found for the given --large-blob-key")
            if args.output:
                with open(args.output, "wb") as f:
                    f.write(blob)
                print(f"wrote {len(blob)} bytes to {args.output}", file=sys.stderr)
            else:
                sys.stdout.buffer.write(blob)
            return

        entries = large_blobs.read_blob_array()
        print(f"{len(entries)} entries in largeBlobArray", file=sys.stderr)
        if args.output:
            import cbor2

            with open(args.output, "wb") as f:
                f.write(cbor2.dumps(entries))
            print(f"wrote raw CBOR array to {args.output}", file=sys.stderr)
        else:
            for i, entry in enumerate(entries):
                print(f"[{i}] {entry}")
    except CtapError as exc:
        sys.exit(f"error: authenticator returned an error: {exc}")
    finally:
        device.close()


if __name__ == "__main__":
    main()
