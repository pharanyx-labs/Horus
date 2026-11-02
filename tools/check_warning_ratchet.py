#!/usr/bin/env python3
"""The default kernel build's warnings may shrink and may not grow. Roadmap 4.18.

The kernel is not built with -Werror. This checker is the ratchet instead.
A warning is the file, the flag and the function the compiler named. Line
numbers are not part of it: they move when a comment is added and the warning
has not. The baseline is that set. The log and the baseline must be the same
set, so a warning the compiler has stopped emitting has to leave the baseline
in the same change.

Growth is decided against the baseline on main, not against the copy in the
change. Adding a warning and a baseline line together matches locally and is
still a growth. The first time the baseline exists, main has no copy and
--establish is the only legal way to accept the set. A run that was given
neither a parent nor --establish fails. An unreadable log fails. Neither
result is a pass.

The checker does not delete a warning, and it does not run the compiler.
"""
import argparse
import os
import re
import sys

WARN = re.compile(
    r"^(?P<file>\S+?):(?P<line>\d+):(?P<col>\d+):\s+warning:\s+(?P<msg>.*?)\s+\[(?P<flag>-W[A-Za-z0-9_+=-]+)\]\s*$"
)
# GCC quotes the function with ASCII quotes, or with the locale's single
# quotes. Both are the same warning.
NAME = re.compile(r"[\u2018`']([^'\u2019`]+)[\u2019`']")
ENTRY = re.compile(r"^(\S+)\s+(-W\S+)\s+(\S+)$")
CEILING = re.compile(r"^ceiling:\s*(\d+)\s*$")


def norm_file(path):
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def warnings_in(log_path):
    if not os.path.isfile(log_path):
        return None, ["warning-ratchet: %s is missing" % log_path]
    found = set()
    problems = []
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            m = WARN.match(raw)
            if not m:
                continue
            name_m = NAME.search(m.group("msg"))
            if not name_m:
                problems.append(
                    "warning-ratchet: %s:%d names no function, so it cannot be baselined"
                    % (log_path, lineno)
                )
                continue
            found.add((norm_file(m.group("file")), m.group("flag"), name_m.group(1)))
    return found, problems


def baseline_in(path):
    if not os.path.isfile(path):
        return None, None, ["warning-ratchet: %s is missing" % path]
    entries = set()
    ceiling = None
    problems = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            raw = line.rstrip("\n")
            if raw == "" or raw.startswith("#"):
                continue
            c = CEILING.match(raw)
            if c:
                if ceiling is not None:
                    problems.append("warning-ratchet: %s:%d repeats the ceiling" % (path, lineno))
                ceiling = int(c.group(1))
                continue
            m = ENTRY.match(raw)
            if not m:
                problems.append("warning-ratchet: %s:%d is not a baseline row" % (path, lineno))
                continue
            item = (norm_file(m.group(1)), m.group(2), m.group(3))
            if item in entries:
                problems.append("warning-ratchet: %s lists %s twice" % (path, m.group(3)))
            entries.add(item)
    if ceiling is None:
        problems.append("warning-ratchet: %s has no ceiling" % path)
    elif ceiling != len(entries):
        problems.append(
            "warning-ratchet: %s ceiling is %d and the file lists %d"
            % (path, ceiling, len(entries))
        )
    return entries, ceiling, problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log")
    ap.add_argument("--baseline", required=True)
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--parent", help="baseline file from main")
    group.add_argument(
        "--establish",
        action="store_true",
        help="main has no baseline yet; accept this set as the ceiling",
    )
    args = ap.parse_args()

    problems = []
    # Argparse would also refuse this, and its usage text is not a finding the
    # harness can recognise. A run with neither flag is the case a missing
    # parent file must not be able to resemble.
    if not args.parent and not args.establish:
        problems.append("warning-ratchet: neither a parent baseline nor --establish")
    current, perr = warnings_in(args.log)
    problems.extend(perr)
    base, _ceiling, berr = baseline_in(args.baseline)
    problems.extend(berr)
    if current is None or base is None:
        for p in problems:
            print(p)
        return 1
    if current != base:
        for item in sorted(current - base):
            problems.append("warning-ratchet: new warning %s %s %s" % item)
        for item in sorted(base - current):
            problems.append("warning-ratchet: baseline entry is no longer emitted %s %s %s" % item)
    if args.parent:
        parent, _pc, perr = baseline_in(args.parent)
        problems.extend(perr)
        if parent is not None and base is not None and not base <= parent:
            for item in sorted(base - parent):
                problems.append("warning-ratchet: ceiling grew by %s %s %s" % item)
    if problems:
        for p in problems:
            print(p)
        return 1
    print("warning-ratchet: %d warning(s), ceiling holds" % len(base))
    return 0


if __name__ == "__main__":
    sys.exit(main())
