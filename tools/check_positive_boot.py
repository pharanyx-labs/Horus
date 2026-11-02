#!/usr/bin/env python3
"""The positive-boot census matches the table. Roadmap 4.21.

A row of SECURITY.md is witnessed only by a positive boot when its witness
names at least one `make` target and names no control arm, no defect flag
and no host proof (a CI job, cargo, a tool under tools/, or Kani). The boot
reached a marker. That is not an arm that puts the defect back.

The census in .github/positive-boot.yml is that set of ids, and nothing else.
The table stays the registry. This file is only the list the table cannot
mark on its own, and the checker is what stops the list drifting. Deriving
the set and comparing it is the whole check. It does not add an arm, and it
does not edit a witness.

A parser that reads no property rows must fail. An empty census is a legal
answer only when the table really has no such row, and a table this checker
could not read is not that answer.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_invariants  # noqa: E402

# Below the live table on purpose. The derived count of properties is
# TESTS.md's, not this floor. A reading that returns nothing, or a stub,
# must not compare equal to an empty census and pass.
PARSE_FLOOR = 100

CENSUS = ".github/positive-boot.yml"
ROW_LINE = re.compile(r"^  - (S\d+[a-z]?): (\S.*)$")
MAKE = re.compile(r"`make [^`]+`")
ARM = re.compile(r"-control\b|\barms?:|\b[A-Z][A-Z0-9_]{3,}=1\b")
HOST = re.compile(r"CI job `|cargo |\btools/|\bkani\b", re.I)


def positive_boot(witness):
    if not MAKE.search(witness):
        return False
    if ARM.search(witness):
        return False
    if HOST.search(witness):
        return False
    return True


def read_census(path):
    """id -> reason. A line that is not a comment, a blank, or a row is an error."""
    if not os.path.isfile(path):
        return None, ["positive-boot: %s is missing" % CENSUS]
    ids = []
    reasons = {}
    problems = []
    saw_header = False
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            if raw == "" or raw.startswith("#"):
                continue
            if raw == "rows:":
                if saw_header:
                    problems.append("positive-boot: %s:%d repeats the rows header" % (CENSUS, lineno))
                saw_header = True
                continue
            m = ROW_LINE.match(raw)
            if not m:
                problems.append("positive-boot: %s:%d is not a census row" % (CENSUS, lineno))
                continue
            sid, reason = m.group(1), m.group(2).strip()
            if sid in reasons:
                problems.append("positive-boot: %s is listed twice" % sid)
            reasons[sid] = reason
            ids.append(sid)
    if not saw_header:
        problems.append("positive-boot: %s has no rows header" % CENSUS)
    return reasons, problems


def main():
    problems = []
    rows, order = check_invariants.parse_security()
    if len(order) < PARSE_FLOOR:
        problems.append(
            "positive-boot: parsed %d property rows, below the floor of %d"
            % (len(order), PARSE_FLOOR)
        )
    derived = []
    for sid in order:
        if positive_boot(rows[sid][2]):
            derived.append(sid)
    census, census_problems = read_census(os.path.join(check_invariants.ROOT, CENSUS))
    problems.extend(census_problems)
    if census is None:
        for p in problems:
            print(p)
        return 1
    derived_set = set(derived)
    census_set = set(census)
    for sid in derived:
        if sid not in census_set:
            problems.append(
                "positive-boot: %s is only a positive boot and is not on the census" % sid
            )
    for sid in census:
        if sid not in rows:
            problems.append("positive-boot: %s is on the census and is not a property" % sid)
        elif sid not in derived_set:
            problems.append(
                "positive-boot: %s is on the census but is not only a positive boot" % sid
            )
    if problems:
        for p in problems:
            print(p)
        return 1
    print("positive-boot: %d rows, census matches" % len(derived))
    return 0


if __name__ == "__main__":
    sys.exit(main())
