#!/usr/bin/env python3
"""Build a program image whose ELF program headers declare MORE FILE than the
image contains -- the witness fixture for SECURITY.md S84.

WHY A FIXTURE AND NOT A TRUNCATION. A truncated container (`make
smoke-proc-truncated-image-control`) is refused by arm_image_from_user before the
ELF parses run at all, so it cannot reach the bound this fixture is aimed at.
This image's container is perfectly self-consistent: the header's `size` is
exactly the payload that follows it, and `len` matches. Only the ELF inside lies,
and it lies about the one thing the loader used to check against the wrong
number -- how much file there is.

WHAT IS CHANGED. Exactly two fields of one PT_LOAD: the p_filesz and p_memsz of
the segment reaching furthest into the file, raised so that
`p_offset + p_filesz` lands OVERREACH_BYTES past the end of the payload. Nothing
else moves -- magic, entry, size, name, every other program header and every byte
of the payload are the image `mkheadered` wrote. An image that failed to load for
some unrelated malformation would witness nothing.

p_memsz is raised with p_filesz because the loader refuses p_memsz < p_filesz
(-10), which is a refusal for the wrong reason: the point is to be accepted up to
the bound under test and refused only by it.

WHY THE OVERREACH IS SMALL. The premap is sized from the same program headers
(staged_image_span_pages) and clamped to USER_IMAGE_MAX_PAGES; a segment large
enough to exceed the premap fails on an unmapped page (-15) instead, which is
again the wrong refusal. One page past the end is enough: under
ELF_LOAD_BOUND_STAGING=1 the loader copies that page out of the shared staging
region into the new task, and under the fix it answers -11.
"""
import struct
import sys

OVERREACH_BYTES = 4096

HDR_BYTES = 44          # include/program_abi.h: magic, entry, size, name[32]
HORUS_MAGIC = 0x55524F48


def main(src, dst):
    blob = open(src, 'rb').read()
    if len(blob) < HDR_BYTES:
        sys.exit(f"{src}: shorter than a container header")
    magic, entry, size = struct.unpack_from('<III', blob, 0)
    if magic != HORUS_MAGIC:
        sys.exit(f"{src}: not a Horus .bin (magic {magic:#x})")
    if HDR_BYTES + size != len(blob):
        sys.exit(f"{src}: header says {size} payload bytes, file holds "
                 f"{len(blob) - HDR_BYTES}")

    img = bytearray(blob)
    p = HDR_BYTES                       # the payload: a static-PIE ELF64
    if img[p:p + 4] != b'\x7fELF' or img[p + 4] != 2:
        sys.exit(f"{src}: payload is not an ELF64")

    e_phoff = struct.unpack_from('<Q', img, p + 32)[0]
    e_phnum = struct.unpack_from('<H', img, p + 56)[0]
    phentsize = struct.unpack_from('<H', img, p + 54)[0]
    if phentsize != 56:
        sys.exit(f"{src}: unexpected e_phentsize {phentsize}")

    # The PT_LOAD reaching furthest into the file is the one to inflate: raising
    # any other could still leave its extent inside the payload.
    best = None
    for i in range(e_phnum):
        ph = p + e_phoff + i * phentsize
        p_type = struct.unpack_from('<I', img, ph)[0]
        if p_type != 1:                 # PT_LOAD
            continue
        p_offset, = struct.unpack_from('<Q', img, ph + 8)
        p_filesz, = struct.unpack_from('<Q', img, ph + 32)
        end = p_offset + p_filesz
        if best is None or end > best[0]:
            best = (end, ph, p_offset)
    if best is None:
        sys.exit(f"{src}: no PT_LOAD to inflate")

    _, ph, p_offset = best
    want_filesz = size - p_offset + OVERREACH_BYTES
    p_memsz, = struct.unpack_from('<Q', img, ph + 40)
    struct.pack_into('<Q', img, ph + 32, want_filesz)
    struct.pack_into('<Q', img, ph + 40, max(p_memsz, want_filesz))

    open(dst, 'wb').write(bytes(img))
    print(f"{dst}: p_offset {p_offset} + p_filesz {want_filesz} = "
          f"{p_offset + want_filesz}, {OVERREACH_BYTES} bytes past a "
          f"{size}-byte payload")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit("usage: make_overreach_image.py <in.bin> <out.bin>")
    main(sys.argv[1], sys.argv[2])
