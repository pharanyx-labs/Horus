#!/usr/bin/env python3
"""Fail the build if an ABI struct differs between the two headers.

Seven structs cross the ring-3 boundary and are written down TWICE -- once in
`src/include/kernel.h` for the kernel and once in `include/syscall.h` for
userspace -- because the two headers are compiled into different worlds and
neither includes the other. `struct dev_info`, `shlib_info`, `untyped_info`,
`cap_info`, `horus_timespec`, `boot_module_info`, `task_exit_info`.

Nothing compared them. The 2026-08-30 audit found all seven in agreement, so this
is a latent risk rather than a live defect -- and that is the moment to gate it,
because the failure mode is silent and the tree already knows the shape:
`check_capslots.py` exists because the cspace slot map is written twice and
drifted, and `CAPSLOT_DEBUG` was added as a number `CAPSLOT_UNTYPED` already
held.

WHAT DRIFT WOULD DO HERE. Every one of these structs is filled by the kernel and
copied to a user buffer with `copy_to_user`, sized by the KERNEL's definition. If
userspace's copy is shorter, the kernel writes past the end of a ring-3 buffer
that ring 3 sized correctly against the header it was given. If a field moves,
the caller reads a different field than the kernel wrote -- and for `dev_info`
that is the MMIO ranges a driver is about to map, while for `cap_info` it is the
rights and serial a supervisor is about to make a decision on. Neither shows up
as a compile error, because neither compiler sees both files.

The comparison is on the sequence of (type, name) pairs, which catches a field
added, removed, renamed, retyped or reordered. It deliberately does NOT check
sizeof or offsets: those are properties of a compilation, not of a header, and
the two are compiled with different flags. A `_Static_assert` on `sizeof` in each
header would be the stronger check and is worth having; it is not what this is.

Exit 0 if every shared struct agrees, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL_H = ROOT / "src" / "include" / "kernel.h"
SYSCALL_H = ROOT / "include" / "syscall.h"

# Declared rather than discovered, so that a struct DISAPPEARING from one header
# is a failure too. Discovery would silently start checking nothing.
SHARED = [
    "dev_info",
    "shlib_info",
    "untyped_info",
    "cap_info",
    "horus_timespec",
    "boot_module_info",
    "task_exit_info",
]

FIELD = re.compile(r"^\s+((?:const\s+)?[A-Za-z_][A-Za-z_0-9]*)\s+([A-Za-z_][A-Za-z_0-9]*)\s*(\[[^\]]*\])?\s*;")


def fields(path, name):
    """The (type, name, array) triples of `struct name`, or None if absent."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r"^struct\s+" + re.escape(name) + r"\s*\{(.*?)^\};", text,
                  re.S | re.M)
    if not m:
        return None
    out = []
    for line in m.group(1).split("\n"):
        # Skip comment-only lines; a trailing comment after a field is fine
        # because the regex anchors on the semicolon.
        if line.strip().startswith(("/*", "*", "//")):
            continue
        f = FIELD.match(line)
        if f:
            out.append((f.group(1), f.group(2), f.group(3) or ""))
    return out


def main():
    problems = []
    checked = 0
    for name in SHARED:
        k = fields(KERNEL_H, name)
        s = fields(SYSCALL_H, name)
        if k is None:
            problems.append(f"struct {name}: not found in {KERNEL_H.relative_to(ROOT)}")
            continue
        if s is None:
            problems.append(f"struct {name}: not found in {SYSCALL_H.relative_to(ROOT)}")
            continue
        checked += 1
        if k != s:
            problems.append(f"struct {name}: the two headers disagree")
            for i in range(max(len(k), len(s))):
                a = k[i] if i < len(k) else None
                b = s[i] if i < len(s) else None
                if a != b:
                    fmt = lambda t: "(absent)" if t is None else f"{t[0]} {t[1]}{t[2]}"
                    problems.append(f"    field {i}: kernel.h has {fmt(a)}, "
                                    f"syscall.h has {fmt(b)}")

    print(f"shared ABI structs : {len(SHARED)}")
    print(f"  compared         : {checked}")

    if problems:
        print("\nFAIL: an ABI struct is not the same in both headers\n")
        for p in problems:
            print(f"  - {p}")
        print("\nThe kernel fills these and copies them to a ring-3 buffer sized by "
              "the OTHER definition. Neither compiler sees both files.")
        return 1

    print("\nPASS: every shared ABI struct is identical in both headers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
