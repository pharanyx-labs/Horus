#!/usr/bin/env python3
"""Build and tamper with GPT disk images for make smoke-gpt-volume (S114).

WHY A SCRIPT AND NOT sgdisk. The gate needs one exact layout and one exact
forgery, and sgdisk would be a new package on every CI runner (gdisk) for two
calls. GPT is small enough to write by hand, and writing it here means the test
states the bytes it relies on instead of trusting a tool's defaults.

  gpt_image.py build OUT VOLUME   OUT: a GPT disk; partition 1 an ESP-typed
                                  filler of 64 MiB, partition 2 a Horus swap of
                                  64 MiB, partition 3 the Horus volume holding
                                  the bytes of VOLUME (a whole-device volume
                                  image another boot wrote). Both headers and
                                  both entry arrays, CRCs correct.
  gpt_image.py tamper IMG         Move the volume entry's start onto the swap
                                  partition WITHOUT recomputing the entry array's
                                  CRC: the edit somebody with the disk in their
                                  hands makes, and the one the kernel must refuse.

The layout is the one the installer writes (docs/design/installed-system.md
section 6), so the gate mounts from the shape a real install produces.
"""
import os
import struct
import sys
import uuid
import zlib

SECTOR = 512
ENTRY = 128
NENTRIES = 128
ESP = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
SWAP = uuid.UUID("7b1c4a3e-5f2d-4e8a-9c61-0d2f3a4b5c6e")    # rust/src/gpt.rs HORUS_SWAP_TYPE
VOLUME = uuid.UUID("7b1c4a3e-5f2d-4e8a-9c61-0d2f3a4b5c6d")  # rust/src/gpt.rs HORUS_VOLUME_TYPE
MIB = 1024 * 1024 // SECTOR   # sectors per MiB


def entry(type_guid, first, last, name):
    return (type_guid.bytes_le + uuid.uuid4().bytes_le + struct.pack("<QQQ", first, last, 0)
            + name.encode("utf-16-le").ljust(72, b"\0"))


def header(my_lba, alt_lba, first_usable, last_usable, entries_lba, entries_crc, disk_guid):
    h = struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0,
                    my_lba, alt_lba, first_usable, last_usable, disk_guid,
                    entries_lba, NENTRIES, ENTRY, entries_crc)
    crc = zlib.crc32(h)
    return h[:16] + struct.pack("<I", crc) + h[20:]


def build(out, volume):
    vol_bytes = os.path.getsize(volume)
    if vol_bytes % 4096:
        sys.exit(f"{volume}: not a whole number of 4 KiB blocks")
    vol_sectors = vol_bytes // SECTOR
    esp = (1 * MIB, 65 * MIB - 1)
    swap = (65 * MIB, 129 * MIB - 1)
    vol = (129 * MIB, 129 * MIB + vol_sectors - 1)
    total = vol[1] + 1 + 1 * MIB              # 1 MiB of room for the backup table
    table_sectors = NENTRIES * ENTRY // SECTOR  # 32
    entries = (entry(ESP, *esp, "EFI system") + entry(SWAP, *swap, "Horus swap")
               + entry(VOLUME, *vol, "Horus volume")).ljust(NENTRIES * ENTRY, b"\0")
    ecrc = zlib.crc32(entries)
    disk_guid = uuid.uuid4().bytes_le
    first_usable, last_usable = 34, total - 34
    backup_lba = total - 1
    with open(out, "wb") as f:
        f.truncate(total * SECTOR)
        # Protective MBR: one partition of type 0xEE covering the disk.
        mbr = bytearray(SECTOR)
        mbr[446:462] = struct.pack("<BBBBBBBBII", 0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF,
                                   1, min(total - 1, 0xFFFFFFFF))
        mbr[510:512] = b"\x55\xaa"
        f.seek(0); f.write(mbr)
        f.seek(1 * SECTOR)
        f.write(header(1, backup_lba, first_usable, last_usable, 2, ecrc, disk_guid))
        f.seek(2 * SECTOR); f.write(entries)
        f.seek((backup_lba - table_sectors) * SECTOR); f.write(entries)
        f.seek(backup_lba * SECTOR)
        f.write(header(backup_lba, 1, first_usable, last_usable, backup_lba - table_sectors,
                       ecrc, disk_guid))
        with open(volume, "rb") as v:
            f.seek(vol[0] * SECTOR)
            while chunk := v.read(1 << 20):
                f.write(chunk)
    print(f"[gpt] {out}: volume at sectors {vol[0]}..{vol[1]} "
          f"(block {vol[0] // 8}, {vol_sectors // 8} blocks)")


def tamper(img):
    with open(img, "r+b") as f:
        f.seek(2 * SECTOR)
        entries = bytearray(f.read(NENTRIES * ENTRY))
        for i in range(NENTRIES):
            e = entries[i * ENTRY:(i + 1) * ENTRY]
            if e[:16] == VOLUME.bytes_le:
                first, last = struct.unpack_from("<QQ", e, 32)
                new_first = 65 * MIB        # the swap partition's start, 4 KiB aligned
                struct.pack_into("<Q", entries, i * ENTRY + 32, new_first)
                f.seek(2 * SECTOR); f.write(entries)
                print(f"[gpt] {img}: volume entry moved {first} -> {new_first}, "
                      f"entry CRC left as it was")
                return
    sys.exit(f"{img}: no Horus volume entry to tamper with")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "build":
        build(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "tamper":
        tamper(sys.argv[2])
    else:
        sys.exit(__doc__)
