#!/usr/bin/env python3
"""A keyboard layout that nothing types on is a layout nobody has tested.

WHAT THIS REFUSES. Three lists have to agree, and nothing made them:

  1. `ps2_layouts[]`            in include/ps2_scancode.h   -- what exists
  2. `EXPECT`                   in tools/keymap_session.py  -- what is asserted
  3. `smoke-keymap-<name>`      in the Makefile             -- what CI runs

Adding a layout is meant to be a row in (1). The whole point of the framework is
that the reader does not change -- but that also means a new layout compiles,
links, ships and is selectable by KEYMAP with NOTHING checking that a single key
on it produces the right character. The tables are the part most likely to be
wrong, because they are 87 bytes of punctuation typed by hand, and they are also
the part no compiler can check.

So this makes the three lists one list. Add a layout and the build fails until it
is asserted and run; delete one and the build fails until its test goes too.

WHY A CHECKER AND NOT A CONVENTION. "Remember to add a test" is the rule that was
already in force when a US-only table shipped to a UK machine. A rule only a
reader enforces fails silently, which is the argument CLAUDE.md makes for every
other checker in this directory.

Falsified by tools/test_check_keymaps.sh, in all four directions including the
one that must stay silent.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "include" / "ps2_scancode.h"
HARNESS = ROOT / "tools" / "keymap_session.py"
MAKEFILE = ROOT / "Makefile"


def layouts_in_header(text):
    m = re.search(r"ps2_layouts\[\]\s*=\s*\{(.*?)\n\};", text, re.S)
    if not m:
        return None
    return [n for n in re.findall(r'\{\s*"([a-z0-9_-]+)"\s*,', m.group(1))]


def expectations_in_harness(text):
    m = re.search(r"^EXPECT\s*=\s*\{(.*?)^\}", text, re.S | re.M)
    if not m:
        return None, None
    body = m.group(1)
    names = re.findall(r'^\s*"([a-z0-9_-]+)"\s*:', body, re.M)
    widths = {}
    for name, row in re.findall(r'^\s*"([a-z0-9_-]+)"\s*:\s*\[(.*?)\],\s*$', body, re.M | re.S):
        # count top-level commas + 1, which is enough for the flat lists used here
        widths[name] = row.count(",") + 1
    keys = re.search(r"^KEYS\s*=\s*\[(.*?)^\]", text, re.S | re.M)
    nkeys = len(re.findall(r"^\s*\(\[", keys.group(1), re.M)) if keys else None
    return names, (widths, nkeys)


def targets_in_makefile(text):
    return re.findall(r"^smoke-keymap-([a-z0-9_-]+):", text, re.M)


def main():
    problems = []
    header = HEADER.read_text(encoding="utf-8")
    harness = HARNESS.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    declared = layouts_in_header(header)
    if declared is None:
        print("FAIL: could not find ps2_layouts[] in include/ps2_scancode.h -- the shape of "
              "that table changed, and this checker is now measuring nothing")
        return 1
    if not declared:
        print("FAIL: ps2_layouts[] is empty")
        return 1

    asserted, (widths, nkeys) = expectations_in_harness(harness)
    if asserted is None:
        print("FAIL: could not find EXPECT in tools/keymap_session.py -- the shape of that "
              "table changed, and this checker is now measuring nothing")
        return 1

    targets = [t for t in targets_in_makefile(makefile) if not t.endswith("-control")]

    for name in declared:
        if name not in asserted:
            problems.append(f"layout '{name}' exists in ps2_layouts[] but no row in "
                            f"tools/keymap_session.py's EXPECT asserts what its keys produce")
        if name not in targets:
            problems.append(f"layout '{name}' exists in ps2_layouts[] but no "
                            f"`smoke-keymap-{name}` target builds and boots it")
    for name in asserted:
        if name not in declared:
            problems.append(f"EXPECT has a row for '{name}', which is not a layout in "
                            f"ps2_layouts[] -- a test for a keyboard that does not exist")
    for name in targets:
        if name not in declared:
            problems.append(f"`smoke-keymap-{name}` builds a layout that is not in "
                            f"ps2_layouts[]; KEYMAP={name} would silently fall back to us")

    # Every row must cover every key, or a layout is asserted on fewer keys than
    # the harness presses and the extra ones are compared against nothing.
    if nkeys:
        for name, w in sorted(widths.items()):
            if w != nkeys:
                problems.append(f"EXPECT['{name}'] has {w} entries but KEYS presses {nkeys} "
                                f"-- that layout is asserted on the wrong number of keys")

    if problems:
        print("FAIL: check_keymaps")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). A layout is three things that must agree: a row in "
              f"ps2_layouts[], a row in EXPECT, and a smoke-keymap-<name> target.")
        return 1

    print(f"  layouts            : {len(declared)} ({', '.join(declared)})")
    print(f"  keys asserted each : {nkeys}")
    print("\nPASS: every keyboard layout is asserted and run")
    return 0


if __name__ == "__main__":
    sys.exit(main())
