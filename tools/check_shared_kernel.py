#!/usr/bin/env python3
"""Refuse a shared kernel whose hash or stamp is not the one this build asked for.

The hash is an argument. A file that travelled beside the image is not
authority: whoever can replace the image can replace that file, and the check
would then pass on the substituted pair. The producing job's declared hash is
what the caller passes in.

The stamp is compared as bytes. A kernel built with one more flag is a
different kernel even when the elf the attacker left in place still hashes to
the value the job expects. On 2026-08-20 a stale KSP_GUARD_INJECT image was
booted and the defect looked like a real reproduction.

Hash first, then stamp. A tampered elf fails on `shared-kernel: hash` while
the stamp is still the one this build would write. A tampered stamp fails on
`shared-kernel: stamp` while the elf still matches. Neither result is repaired
by compiling a replacement.

Exit 0 only after both comparisons succeed. An empty file, a missing file, or
a hash that is not 64 lowercase hex digits is a refusal.
"""
import argparse
import hashlib
import pathlib
import re
import sys

HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def refuse(kind, detail):
    print(f"shared-kernel: {kind} {detail}".rstrip())
    return 1


def regular_nonempty(path, label):
    """A symlink is not the file it names. The caller asked for this path."""
    if not path.exists() or path.is_symlink() or not path.is_file():
        return refuse("missing", label)
    if path.stat().st_size == 0:
        return refuse("empty", label)
    return 0


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--kernel", required=True)
    p.add_argument("--stamp", required=True)
    p.add_argument("--expect-stamp", required=True)
    p.add_argument("--expect-hash", required=True)
    args = p.parse_args(argv)

    kernel = pathlib.Path(args.kernel)
    stamp = pathlib.Path(args.stamp)
    expect_stamp = pathlib.Path(args.expect_stamp)
    expect_hash = args.expect_hash.strip()

    for path, label in (
        (kernel, "kernel"),
        (stamp, "stamp"),
        (expect_stamp, "expect-stamp"),
    ):
        rc = regular_nonempty(path, label)
        if rc:
            return rc

    if not HASH_RE.fullmatch(expect_hash):
        return refuse("hash", "the expected hash is not 64 lowercase hex digits")

    digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    if digest != expect_hash:
        return refuse("hash", f"elf is {digest}, this build asked for {expect_hash}")

    got = stamp.read_bytes()
    want = expect_stamp.read_bytes()
    if got != want:
        return refuse("stamp", "the image was built with different flags")

    print("shared-kernel: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
