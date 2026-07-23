#!/usr/bin/env python3
"""Recompute the expected measured-boot PCR[8]/PCR[9] from the reproducible
boot-module manifest — the external verifier for `make smoke-tpm`.

The kernel (src/kernel/tpm.c) measures, into the SHA-256 PCR bank:

  PCR[8] <- extend( H )  where
            H = SHA256( "horus-measured-boot-v1"
                        || for each manifest entry, in table order:
                             path_bytes || be32(size) || sha256[32] )
  PCR[9] <- extend( each manifest entry's sha256, in table order )

A TPM PCR starts at 32 zero bytes and `extend(d)` sets PCR <- SHA256(PCR || d).
This script replays that math purely from src/kernel/boot_module_manifest.h, so a
match against the guest-printed values proves the guest measured exactly the
reproducible manifest — not merely that it printed a plausible-looking hash.

Usage: tpm_expected_pcr.py [path/to/boot_module_manifest.h]
Prints: PCR8=<hex> PCR9=<hex>
"""
import hashlib
import re
import sys

KERNEL_ID_TAG = b"horus-measured-boot-v1"


def parse_manifest(path):
    """Return [(dest_path, size, digest_bytes), ...] in file order."""
    text = open(path, "r").read()
    # Each entry: { "dest", <size>u, {0x..,0x..,...} }
    entry_re = re.compile(
        r'\{\s*"([^"]*)"\s*,\s*(\d+)u\s*,\s*\{([^}]*)\}\s*\}', re.S)
    count_re = re.search(r'BOOT_MODULE_DIGEST_COUNT\s*\(\(uint32_t\)(\d+)u\)', text)
    count = int(count_re.group(1)) if count_re else None

    entries = []
    for m in entry_re.finditer(text):
        dest, size, digest_str = m.group(1), int(m.group(2)), m.group(3)
        by = [int(b, 16) for b in re.findall(r'0x[0-9a-fA-F]{1,2}', digest_str)]
        if len(by) != 32:
            continue
        entries.append((dest, size, bytes(by)))

    # A module-free build emits one zero sentinel with COUNT == 0; drop it.
    if count is not None:
        entries = entries[:count]
    return entries


def be32(v):
    return bytes([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def extend(pcr, measurement):
    return hashlib.sha256(pcr + measurement).digest()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "src/kernel/boot_module_manifest.h"
    entries = parse_manifest(path)

    # H for PCR[8]
    ser = bytearray(KERNEL_ID_TAG)
    for dest, size, digest in entries:
        ser += dest.encode()
        ser += be32(size)
        ser += digest
    h = hashlib.sha256(bytes(ser)).digest()

    zero = b"\x00" * 32
    pcr8 = extend(zero, h)

    pcr9 = zero
    for _dest, _size, digest in entries:
        pcr9 = extend(pcr9, digest)

    print("PCR8=%s PCR9=%s" % (pcr8.hex(), pcr9.hex()))


if __name__ == "__main__":
    main()
