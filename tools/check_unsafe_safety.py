#!/usr/bin/env python3
"""Fail the build if a production `unsafe` in the security core has no `# Safety`.

Carries SECURITY.md S54: every `unsafe` in the security core states what its
caller must uphold.

CLAUDE.md section 7 requires: "`unsafe` only at the FFI boundary, with a
`# Safety` comment stating the caller's obligations." That rule was asserted and
not enforced. The 2026-08-29 audit counted 29 of 49 production `unsafe` blocks
with no `# Safety` clause anywhere above them, concentrated in the two modules
the kernel trusts most: capability.rs (10 of 14) and memory.rs (6 of 6, with the
string "# Safety" appearing nowhere in the file).

WHY THAT MATTERS MORE HERE THAN IN ORDINARY RUST. Every one of these functions is
called from C, and C cannot be made to uphold anything the Rust side does not
write down. `rust_cap_revoke_global` needs every cspace in the system in its
`spaces` array or a revoke misses a derived copy; `rust_page_ref_inc` needs
`page_lock` held or two CPUs race a non-atomic read-modify-write on a refcount
that decides when a page is freed. Neither obligation was stated, and neither is
visible from the signature.

WHAT THIS DOES NOT CHECK, stated so nobody mistakes a green run for more than it
is. It checks that an obligation is WRITTEN, never that it is TRUE, complete, or
upheld by any caller. A `# Safety` clause reading "none" would satisfy it. It is
a floor -- the author had to think about the contract and say so -- and Miri and
the Kani proofs are what actually test the code beneath.

Scope is `rust/src/*.rs`, production code only: everything from the first
`#[cfg(test)]` or `mod tests` onward is skipped, because a test that constructs a
deliberately malformed cspace is exercising the boundary rather than crossing it.

Exit 0 if every production `unsafe` is documented, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "rust" / "src"

# WHAT COUNTS AS A SITE, AND WHERE ITS CLAUSE LIVES.
#
# `unsafe` appears in two shapes and only one of them takes a clause:
#
#   1. an `unsafe fn` -- an ITEM. Its contract is what a caller must uphold, so
#      it needs a `/// # Safety` section in its own doc comment.
#   2. an `unsafe { ... }` BLOCK inside a function body. The obligation there is
#      discharged by the surrounding code, and the argument belongs in the
#      enclosing item's docs. `with_rng` is the example: the block is sound
#      because `RNG_LOCK` is held two lines above, and that reasoning is written
#      on the function.
#
# So a block is satisfied by its enclosing item's clause, and the scan walks up
# to that item rather than a fixed number of lines. The first version of this
# file did use a fixed 30-line window, and its own falsification harness caught
# what that costs: an undocumented FFI export placed just below a documented one
# INHERITED the neighbour's clause and passed, because the previous `# Safety`
# was 21 lines up. A checker that reads one item's contract as another's is worse
# than no checker, since it certifies precisely the case it cannot see.
#
# LOOKBACK bounds the walk so a malformed file cannot make it run away.
LOOKBACK = 120

ITEM_START = re.compile(r"^\s*(pub\s+)?(unsafe\s+)?(extern\s+\"C\"\s+)?fn\b")
DOC_OR_ATTR = re.compile(r"^\s*(///|//|#\[)")


def production_lines(path):
    """Lines before the test module, and the index they start at."""
    lines = path.read_text(encoding="utf-8").split("\n")
    for i, line in enumerate(lines):
        if re.match(r"\s*#\[cfg\(test\)\]", line) or re.match(r"\s*mod tests\b", line):
            return lines[:i]
    return lines


def main():
    problems = []
    total = 0
    for path in sorted(SRC.glob("*.rs")):
        lines = production_lines(path)
        for i, line in enumerate(lines):
            if not re.search(r"\bunsafe\b", line):
                continue
            if line.lstrip().startswith("//"):
                continue
            total += 1

            # Walk up to the start of the enclosing item, then read its doc
            # block. For an `unsafe fn` that is the line itself.
            start = i
            if not ITEM_START.match(line):
                for j in range(i - 1, max(-1, i - 1 - LOOKBACK), -1):
                    if ITEM_START.match(lines[j]):
                        start = j
                        break
                else:
                    start = i

            doc = []
            for j in range(start - 1, max(-1, start - 1 - LOOKBACK), -1):
                if DOC_OR_ATTR.match(lines[j]) or lines[j].strip() == "":
                    doc.append(lines[j])
                    continue
                break

            if not any("# Safety" in d for d in doc):
                rel = path.relative_to(ROOT)
                problems.append(f"{rel}:{i + 1}: {line.strip()[:80]}")

    print(f"production `unsafe` sites : {total}")
    print(f"  documented              : {total - len(problems)}")
    print(f"  undocumented            : {len(problems)}")

    if problems:
        print("\nFAIL: an `unsafe` in the security core states no caller obligation\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). Add a `/// # Safety` clause saying what "
              f"the caller must uphold -- CLAUDE.md section 7.")
        return 1

    print("\nPASS: every production `unsafe` states the caller's obligations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
