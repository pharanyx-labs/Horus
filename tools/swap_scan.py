#!/usr/bin/env python3
"""Search a disk image's Horus swap partition for a plaintext marker.

The swap store's self-test (SWAP_SELFTEST) seals pages carrying the marker into
the partition and leaves them there. Sealed, they are ciphertext and the marker
cannot appear; written in the clear (the SWAP_SEAL_OFF arm), it appears in
every one of them. The partition is found from the image's own GPT by the Horus
swap type, so the search covers exactly the blocks the kernel may write.

    swap_scan.py IMAGE --expect absent|present

Exit 0 when the marker's presence is as expected, 1 when it is not, 2 when the
image has no Horus swap partition (which proves nothing either way).
"""
import argparse
import struct
import sys

SWAP_TYPE = bytes([0x3e, 0x4a, 0x1c, 0x7b, 0x2d, 0x5f, 0x8a, 0x4e,
                   0x9c, 0x61, 0x0d, 0x2f, 0x3a, 0x4b, 0x5c, 0x6e])
MARKER = b"HORUS-SWAP-PLAINTEXT-MARKER-"


def swap_range(f):
    f.seek(512)
    hdr = f.read(92)
    if hdr[0:8] != b"EFI PART":
        return None
    entries_lba, num, size = struct.unpack_from("<QII", hdr, 72)
    f.seek(entries_lba * 512)
    table = f.read(num * size)
    for i in range(num):
        e = table[i * size:(i + 1) * size]
        if e[0:16] == SWAP_TYPE:
            first, last = struct.unpack_from("<QQ", e, 32)
            return first * 512, (last + 1) * 512
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--expect", choices=("absent", "present"), required=True)
    a = ap.parse_args()
    with open(a.image, "rb") as f:
        r = swap_range(f)
        if r is None:
            print(f"swap_scan: {a.image} has no Horus swap partition")
            return 2
        start, end = r
        f.seek(start)
        hits, carry, pos = 0, b"", start
        while pos < end:
            chunk = f.read(min(1 << 20, end - pos))
            if not chunk:
                break
            buf = carry + chunk
            hits += buf.count(MARKER)
            carry = buf[-(len(MARKER) - 1):]
            pos += len(chunk)
    print(f"swap_scan: {hits} plaintext marker(s) in the swap partition, "
          f"bytes {start}..{end} of {a.image}")
    ok = (hits == 0) if a.expect == "absent" else (hits > 0)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
