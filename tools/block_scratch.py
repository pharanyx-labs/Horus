#!/usr/bin/env python3
"""The scratch disk a ring-3 storage driver's gate hands it, and the host-side
check of what the driver wrote to it.

    tools/block_scratch.py make   <kind> <image> [MiB]  # signature + fresh nonce in block 0
    tools/block_scratch.py verify <kind> <image> [log]  # the written run holds what the
                                                        # driver derives from the nonce

<kind> is `nvme` (userspace/nvmed.c, `make smoke-nvme`), `sd`
(userspace/sdhcid.c, `make smoke-sdhcid`) or `blk` (userspace/blktest.c, `make
smoke-blkproto`, through either driver). Each kind's layout must match what
writes it: the magics, NONCE_OFF, the run it writes, and the pattern loop.

THE BLK KIND'S RUN IS AT SECTOR 2048, the start of the extent blktest binds to
its first client, who writes at ITS sector 0. A driver that took the client's
sector as the device's would write sectors 0-7 instead, overwriting this image's
block 0 and passing every check made in the guest; only this one sees it.

WHY THE CHECK IS MADE HERE, OUTSIDE THE GUEST. A driver reads back the blocks it
wrote and compares, but a driver that wrote to the wrong block, or whose write
never left the controller, reads back exactly what it wrote and passes its own
test. The image file after QEMU exits is the medium; only a check of the file
says the write reached it. NVME_WRITE_WRONG_LBA and SDHCID_WRITE_WRONG_LBA are
the arms that show the in-guest check alone cannot tell.

WHY A NONCE. A constant pattern would let a stale image from an earlier run, or
a driver that writes a compiled-in block without reading block 0, satisfy the
check. A fresh nonce per run means the run can only be right if the driver read
block 0 of THIS image and wrote what it derived.

THE SD KIND ALSO PLANTS BLOCK 100, and checks the CAPACITY the driver reported.
Block 0 is address 0 whether a card takes block numbers or byte offsets, so a
read of it cannot show the addressing mode is wrong; block 100 is somewhere else
entirely in the wrong unit, and sdhcid refuses to go on unless it holds this
image's nonce. The capacity is decoded from the card's CSD (or an eMMC's
extended CSD), where a decoder off by the CRC byte's eight bits reads a
plausible number and a wrong one; only a comparison with the size of the image
QEMU was given can catch that, so `verify sd` takes the guest's serial log and
requires the driver's `capacity N sectors` line to equal the image.

The block size is 512: QEMU's default for -device nvme, and the SD sector.
"""
import os
import re
import sys

BLOCK = 512
NONCE_OFF = 32
NONCE_LEN = 16

KINDS = {
    # The NVMe driver writes one block.
    "nvme": dict(scratch=b"HORUS-NVME-SCRATCH-V1\0", written=b"HORUS-NVME-WRITTEN-V1\0",
                 read_lba=None, write_lba=1, write_count=1, default_mib=16),
    # sdhcid writes a run of eight sectors, one 4 KiB filesystem block, in one
    # multi-block command, which is the transfer the kernel's storage makes.
    "sd": dict(scratch=b"HORUS-SDHC-SCRATCH-V1\0", written=b"HORUS-SDHC-WRITTEN-V1\0",
               read_magic=b"HORUS-SDHC-BLOCK100-V1\0", read_lba=100,
               write_lba=8, write_count=8, default_mib=64),
    # blktest's first client writes eight sectors at the start of its extent.
    "blk": dict(scratch=b"HORUS-BLKP-SCRATCH-V1\0", written=b"HORUS-BLKP-WRITTEN-V1\0",
                read_lba=None, write_lba=2048, write_count=8, default_mib=64),
}


def expected_sector(k: dict, nonce: bytes, index: int) -> bytes:
    """Sector `index` of the written run. Index 0 is the pattern nvmed has
    always written; later sectors differ from it and from each other, so a
    driver that fed one sector to the whole run, or put sectors out of order,
    fails."""
    b = bytearray(BLOCK)
    w = k["written"]
    b[0:len(w)] = w
    b[NONCE_OFF:NONCE_OFF + NONCE_LEN] = nonce
    for i in range(NONCE_OFF + NONCE_LEN, BLOCK):
        b[i] = nonce[i % NONCE_LEN] ^ ((i * 31 + 7) & 0xFF) ^ ((index * 13) & 0xFF)
    return bytes(b)


def make(k: dict, path: str, mib: int) -> int:
    nonce = os.urandom(NONCE_LEN)
    block0 = bytearray(BLOCK)
    block0[0:len(k["scratch"])] = k["scratch"]
    block0[NONCE_OFF:NONCE_OFF + NONCE_LEN] = nonce
    with open(path, "wb") as f:
        f.write(block0)
        if k["read_lba"] is not None:
            planted = bytearray(BLOCK)
            planted[0:len(k["read_magic"])] = k["read_magic"]
            planted[NONCE_OFF:NONCE_OFF + NONCE_LEN] = nonce
            f.seek(k["read_lba"] * BLOCK)
            f.write(planted)
        f.truncate(mib * 1024 * 1024)
    print(f"BLOCK SCRATCH: made {path}, {mib} MiB, nonce {nonce.hex()}")
    return 0


def verify(k: dict, kind: str, path: str, log: str | None) -> int:
    with open(path, "rb") as f:
        block0 = f.read(BLOCK)
        f.seek(k["write_lba"] * BLOCK)
        got = f.read(BLOCK * k["write_count"])
        size = os.fstat(f.fileno()).st_size
    if not block0.startswith(k["scratch"]):
        print("BLOCK SCRATCH: FAIL block 0 lost its signature")
        return 1
    nonce = block0[NONCE_OFF:NONCE_OFF + NONCE_LEN]
    for n in range(k["write_count"]):
        lba = k["write_lba"] + n
        sector = got[n * BLOCK:(n + 1) * BLOCK]
        if sector != expected_sector(k, nonce, n):
            what = "is still empty" if sector == bytes(BLOCK) else "holds something else"
            print(f"BLOCK SCRATCH: FAIL block {lba} {what}")
            return 1
    last = k["write_lba"] + k["write_count"] - 1
    span = f"block {k['write_lba']}" if last == k["write_lba"] else f"blocks {k['write_lba']}-{last}"
    if kind == "sd":
        if log is None:
            print("BLOCK SCRATCH: FAIL `verify sd` needs the guest's serial log for the capacity")
            return 2
        with open(log, "rb") as f:
            text = f.read().decode("latin-1")
        m = re.search(r"SDHCID: (?:SD card|eMMC), capacity (\d+) sectors", text)
        if not m:
            print("BLOCK SCRATCH: FAIL the driver reported no capacity")
            return 1
        if int(m.group(1)) != size // BLOCK:
            print(f"BLOCK SCRATCH: FAIL capacity {m.group(1)} sectors is not the card's own {size // BLOCK}")
            return 1
    print(f"BLOCK SCRATCH: PASS {span} hold the write derived from nonce {nonce.hex()}")
    return 0


def main() -> int:
    a = sys.argv[1:]
    if len(a) < 3 or a[0] not in ("make", "verify") or a[1] not in KINDS:
        print(__doc__.splitlines()[0], file=sys.stderr)
        print("usage: block_scratch.py make|verify nvme|sd|blk <image> [MiB|log]", file=sys.stderr)
        return 2
    k = KINDS[a[1]]
    if a[0] == "make":
        return make(k, a[2], int(a[3]) if len(a) > 3 else k["default_mib"])
    return verify(k, a[1], a[2], a[3] if len(a) > 3 else None)


if __name__ == "__main__":
    sys.exit(main())
