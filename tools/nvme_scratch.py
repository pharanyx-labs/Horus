#!/usr/bin/env python3
"""The scratch disk `make smoke-nvme` hands the ring-3 NVMe driver, and the
host-side check of what the driver wrote to it.

    tools/nvme_scratch.py make   <image>   # 16 MiB, signature + fresh nonce in block 0
    tools/nvme_scratch.py verify <image>   # block 1 holds what nvmed derives from the nonce

WHY THE CHECK IS MADE HERE, OUTSIDE THE GUEST. nvmed reads back the block it
wrote and compares, but a driver that wrote to the wrong block, or whose write
never left the controller, reads back exactly what it wrote and passes its own
test. The image file after QEMU exits is the medium; only a check of the file
says the write reached it. NVME_WRITE_WRONG_LBA is the arm that shows the
in-guest check alone cannot tell.

WHY A NONCE. A constant pattern would let a stale image from an earlier run, or
a driver that writes a compiled-in block without reading block 0, satisfy the
check. A fresh nonce per run means block 1 can only be right if the driver read
block 0 of THIS image and wrote what it derived.

The layout must match userspace/nvmed.c (SCRATCH_MAGIC, WRITTEN_MAGIC, NONCE_OFF,
the pattern loop). Block size is 512, QEMU's default for -device nvme.
"""
import os
import sys

SIZE = 16 * 1024 * 1024
BLOCK = 512
SCRATCH_MAGIC = b"HORUS-NVME-SCRATCH-V1\0"
WRITTEN_MAGIC = b"HORUS-NVME-WRITTEN-V1\0"
NONCE_OFF = 32
NONCE_LEN = 16
WRITE_LBA = 1


def expected_block(nonce: bytes) -> bytes:
    b = bytearray(BLOCK)
    b[0:len(WRITTEN_MAGIC)] = WRITTEN_MAGIC
    b[NONCE_OFF:NONCE_OFF + NONCE_LEN] = nonce
    for i in range(NONCE_OFF + NONCE_LEN, BLOCK):
        b[i] = nonce[i % NONCE_LEN] ^ ((i * 31 + 7) & 0xFF)
    return bytes(b)


def make(path: str) -> int:
    nonce = os.urandom(NONCE_LEN)
    block0 = bytearray(BLOCK)
    block0[0:len(SCRATCH_MAGIC)] = SCRATCH_MAGIC
    block0[NONCE_OFF:NONCE_OFF + NONCE_LEN] = nonce
    with open(path, "wb") as f:
        f.write(block0)
        f.truncate(SIZE)
    print(f"NVME SCRATCH: made {path}, nonce {nonce.hex()}")
    return 0


def verify(path: str) -> int:
    with open(path, "rb") as f:
        block0 = f.read(BLOCK)
        f.seek(WRITE_LBA * BLOCK)
        got = f.read(BLOCK)
    if not block0.startswith(SCRATCH_MAGIC):
        print("NVME SCRATCH: FAIL block 0 lost its signature")
        return 1
    nonce = block0[NONCE_OFF:NONCE_OFF + NONCE_LEN]
    if got != expected_block(nonce):
        what = "is still empty" if got == bytes(BLOCK) else "holds something else"
        print(f"NVME SCRATCH: FAIL block {WRITE_LBA} {what}")
        return 1
    print(f"NVME SCRATCH: PASS block {WRITE_LBA} holds the write derived from nonce {nonce.hex()}")
    return 0


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("make", "verify"):
        print(__doc__.splitlines()[0], file=sys.stderr)
        print("usage: nvme_scratch.py make|verify <image>", file=sys.stderr)
        return 2
    return make(sys.argv[2]) if sys.argv[1] == "make" else verify(sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
