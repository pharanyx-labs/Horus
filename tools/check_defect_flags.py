#!/usr/bin/env python3
"""Fail the build if the defect-flag table in docs/BUILDING.md is not complete.

docs/BUILDING.md states, of its "Defect-reproducing builds" table: "This table
is the complete list -- if you add a control arm, it belongs here in the same
commit, because a control arm nobody can find is one nobody will re-run."

That sentence was false when it was written. On 2026-08-21, two members of the
Makefile's DEFECT_FLAGS list -- RESUME_RSP_INJECT_PRECLAIM (which drives
smoke-resume-guard-preclaim) and WAL_CRASHTEST -- had no row in it. One of them
appeared nowhere in the file at all. The claim had gone stale in exactly the way
every hand-maintained claim in this repository has gone stale: silently, because
nothing derived it.

This is the same class of defect that tools/check_doc_claims.py exists to catch
for numeric claims, and the fix is the same shape. Derive the list from the
Makefile -- the only artifact that decides which flags are real -- and compare.

Two rules:

  1. every flag in DEFECT_FLAGS has a row in the docs/BUILDING.md table
  2. every flag named by a table row is still a member of DEFECT_FLAGS
     (so a retired flag cannot linger as a row nobody can build)

Rule 2 matters as much as rule 1: a table listing a flag that no longer exists
sends a reader to reproduce a defect with a build that will not reproduce it,
and they will read the resulting silence as evidence of a fix.

Exit 0 if complete, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "Makefile"
BUILDING = ROOT / "docs" / "BUILDING.md"

# Instrumentation flags that tune an arm rather than selecting one. They take a
# value, are meaningless alone, and are documented in the prose of the row for
# the flag they modify -- so requiring a row of their own would be noise. Each
# is listed with the flag whose row must carry it, and that is checked too.
TUNING = {
    "KFAULT_INJECT_TICKS": "KFAULT_INJECT",
    "KSTACK_RACE_WIDEN_SPINS": "KSTACK_RACE_WIDEN",
    "KSTACK_RACE_WIDEN_CPUMASK": "KSTACK_RACE_WIDEN",
    "SPAWN_STAGE_WIDEN_SPINS": "SPAWN_STAGE_WIDEN",
    "SPAWN_STAGE_WIDEN_WINDOWS": "SPAWN_STAGE_WIDEN",
    "RESUME_RSP_INJECT_VALUE": "RESUME_RSP_INJECT",
}


def defect_flags(mk: str) -> list[str]:
    """The DEFECT_FLAGS assignment, honouring backslash continuations."""
    m = re.search(r"^DEFECT_FLAGS\s*=\s*((?:.*\\\n)*.*)$", mk, re.M)
    if not m:
        print("FAIL: no DEFECT_FLAGS assignment found in the Makefile")
        sys.exit(1)
    body = m.group(1).replace("\\\n", " ")
    return sorted(set(re.findall(r"[A-Z][A-Z0-9_]+", body)))


def documented(doc: str) -> set[str]:
    """Flag names appearing in a table row's first cell, `FLAG` or `FLAG=1`."""
    return {
        m.group(1)
        for m in re.finditer(r"^\|\s*`([A-Z][A-Z0-9_]+)(?:=[^`]*)?`\s*\|", doc, re.M)
    }


def main():
    mk = MAKEFILE.read_text()
    doc = BUILDING.read_text()

    flags = defect_flags(mk)
    rows = documented(doc)
    problems = []

    for f in flags:
        if f in TUNING:
            continue
        if f not in rows:
            problems.append(f"{f}: in DEFECT_FLAGS, but has no row in the table")

    for f in sorted(rows - set(flags)):
        # Build-configuration flags (SMP, DEBUG_SHELL) share the file but not
        # this claim, and they are recognisable by being assigned in the
        # Makefile without being DEFECT_FLAGS members. Anything else with a row
        # names a flag no build defines -- which is the case worth catching, so
        # it must NOT be skipped for being absent from the Makefile. An earlier
        # draft of this loop bailed on exactly that condition and could not fail
        # rule 2 at all; it was caught by falsifying the arm rather than by
        # reading the code, which is the whole argument for doing that.
        if f in TUNING:
            continue
        if re.search(rf"^\s*{f}\s*[:?+]?=", mk, re.M):
            continue  # an ordinary build knob, documented in its own table
        problems.append(f"{f}: has a table row, but is not in DEFECT_FLAGS")

    for tune, owner in sorted(TUNING.items()):
        if tune not in mk:
            continue
        if not re.search(rf"`{tune}(?:=[^`]*)?`", doc):
            problems.append(f"{tune}: tunes {owner}, but is named nowhere in the table")

    print(f"DEFECT_FLAGS members : {len(flags)}")
    print(f"  documented rows    : {len([f for f in flags if f in rows])}")
    print(f"  tuning parameters  : {len([f for f in flags if f in TUNING])}")

    if problems:
        print("\nFAIL: the defect-flag table is not the complete list it claims to be\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). Fix docs/BUILDING.md, or the Makefile.")
        return 1
    print("\nPASS: every defect flag is documented, and every documented flag is real")
    return 0


if __name__ == "__main__":
    sys.exit(main())
