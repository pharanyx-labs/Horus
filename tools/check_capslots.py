#!/usr/bin/env python3
"""Fail the build if the cspace slot map is inconsistent.

The map is written down TWICE — `src/include/kernel.h` for the kernel and
`include/syscall.h` for ring 3 — and nothing compared them. Two ways that bites:

  1. a new CAPSLOT_* silently reuses a number another one already holds. On
     2026-08-23 `CAPSLOT_DEBUG` was added as 18, which `CAPSLOT_UNTYPED` already
     was; the delegation then wrote a CAP_DEBUG into the slot init keeps its
     CAP_UNTYPED in. It presented as "the capability did not arrive", which is
     the friendly version — the unfriendly one is a capability arriving where
     something else was expected and being used as it.
  2. the two headers drift, so ring 3 addresses a different slot than the kernel
     gates on, and the mismatch shows up as an authorisation failure nobody can
     explain from either file alone.

Two rules, matching those:

  1. within a header, no two CAPSLOT_* names share a number
  2. a name defined in BOTH headers has the same number in both

A name in only one header is fine and deliberate: some slots are ring-3
conventions the kernel never names, and vice versa.

Exit 0 if consistent, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADERS = [ROOT / "src" / "include" / "kernel.h", ROOT / "include" / "syscall.h"]
SLOT = re.compile(r"^#define\s+(CAPSLOT_[A-Z0-9_]+)\s+(\d+)", re.M)


def main():
    problems = []
    maps = {}

    for h in HEADERS:
        found = {}
        by_number = {}
        for name, num in SLOT.findall(h.read_text()):
            n = int(num)
            found[name] = n
            by_number.setdefault(n, []).append(name)
        maps[h.name] = found
        for n, names in sorted(by_number.items()):
            if len(names) > 1:
                problems.append(
                    f"{h.name}: slot {n} is claimed by {', '.join(sorted(names))} "
                    f"-- one cspace slot, two meanings"
                )

    (a_name, a), (b_name, b) = maps.items()
    for name in sorted(set(a) & set(b)):
        if a[name] != b[name]:
            problems.append(
                f"{name}: {a_name} says {a[name]}, {b_name} says {b[name]} -- "
                f"ring 3 would address a different slot than the kernel gates on"
            )

    print(f"slots in {a_name:<10}: {len(a)}")
    print(f"slots in {b_name:<10}: {len(b)}")
    print(f"defined in both      : {len(set(a) & set(b))}")

    if problems:
        print("\nFAIL: the cspace slot map is inconsistent\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nPASS: no slot is claimed twice, and both headers agree on every shared name")
    return 0


if __name__ == "__main__":
    sys.exit(main())
