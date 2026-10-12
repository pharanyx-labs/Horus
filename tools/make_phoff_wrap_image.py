#!/usr/bin/env python3
"""Build a program image whose ELF header puts the program headers just short of
4 GiB into the file -- the witness fixture for LIMITATIONS 1.28 (SECURITY.md S84).

WHAT IT IS AIMED AT. staged_image_span_pages sizes the premap from the staged
image's program headers, on the spawn path, BEFORE the Rust validators see the
image. Until 2026-10-12 it bounded them with `e_phoff + 64 > staged_bytes()` in
32 bits, so an e_phoff within 64 bytes of 2^32 wrapped the sum to a small number,
passed, and the headers were read about 4 GiB past the staging buffer in kernel
context. Every other parse of the image refuses the offset; this one read first.

WHAT IS CHANGED. One field: e_phoff, set to PHOFF. It still fits in 32 bits, so
elf64_narrow accepts it and the 32-bit sum is what decides. Every other byte is
the image `mkheadered` wrote, so a refusal for any other reason would be the
container's or the validator's, not the bound's, and a correct kernel refuses it
in the validator (the headers are not in the file).
"""
import struct
import sys

HDR_BYTES = 44          # include/program_abi.h: magic, entry, size, name[32]
HORUS_MAGIC = 0x55524F48

# 2^32 - 16: e_phoff + 64 is 0x30 in 32 bits, 48, which any real image exceeds.
PHOFF = 0xFFFFFFF0


def main(src, dst):
    blob = open(src, 'rb').read()
    if len(blob) < HDR_BYTES:
        sys.exit(f"{src}: shorter than a container header")
    magic, _entry, size = struct.unpack_from('<III', blob, 0)
    if magic != HORUS_MAGIC:
        sys.exit(f"{src}: not a Horus .bin (magic {magic:#x})")
    if HDR_BYTES + size != len(blob):
        sys.exit(f"{src}: header says {size} payload bytes, file holds "
                 f"{len(blob) - HDR_BYTES}")
    if size <= (PHOFF + 64) & 0xFFFFFFFF:
        sys.exit(f"{src}: a {size}-byte payload would not pass the wrapped bound")

    img = bytearray(blob)
    p = HDR_BYTES                       # the payload: a static-PIE ELF64
    if img[p:p + 4] != b'\x7fELF' or img[p + 4] != 2:
        sys.exit(f"{src}: payload is not an ELF64")
    e_phnum = struct.unpack_from('<H', img, p + 56)[0]
    if e_phnum == 0 or e_phnum > 8:
        # staged_image_span_pages returns before the bound for these, and the
        # fixture would then witness nothing.
        sys.exit(f"{src}: e_phnum {e_phnum} never reaches the bound")

    struct.pack_into('<Q', img, p + 32, PHOFF)
    open(dst, 'wb').write(bytes(img))
    print(f"{dst}: e_phoff {PHOFF:#x} in a {size}-byte payload with "
          f"{e_phnum} program headers")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit("usage: make_phoff_wrap_image.py <in.bin> <out.bin>")
    main(sys.argv[1], sys.argv[2])
