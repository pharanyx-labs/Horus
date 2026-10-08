#!/usr/bin/env python3
"""Change one byte of a file inside a built ISO, in place (make smoke-install-esp-pin).

  tamper_iso_file.py ISO PATH OFFSET

The edit somebody with the install stick in their hands makes: the file's bytes
change and NOTHING ELSE does, so the measured boot image and the pin inside it
are untouched and still name the original. xorriso reports where the file's
extent starts; the byte at OFFSET within it is inverted.
"""
import subprocess
import sys

iso, path, off = sys.argv[1], sys.argv[2], int(sys.argv[3])
out = subprocess.run(["xorriso", "-indev", iso, "-find", path, "-exec", "report_lba", "--"],
                     capture_output=True, text=True, check=True).stdout
lines = [l for l in out.splitlines() if l.startswith("File data lba:")]
if len(lines) != 1:
    sys.exit(f"tamper: expected one extent for {path}, got {len(lines)}:\n{out}")
# "File data lba:  0 ,  <start lba> , <blocks> , <bytes> , '<path>'"
fields = [f.strip() for f in lines[0].split(":", 1)[1].split(",")]
lba, nbytes = int(fields[1]), int(fields[3])
if not 0 <= off < nbytes:
    sys.exit(f"tamper: offset {off} is outside {path} ({nbytes} bytes)")
with open(iso, "r+b") as f:
    f.seek(lba * 2048 + off)
    b = f.read(1)
    f.seek(lba * 2048 + off)
    f.write(bytes([b[0] ^ 0xFF]))
print(f"[tamper] {iso}: {path} byte {off} inverted (lba {lba})")
