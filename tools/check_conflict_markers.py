#!/usr/bin/env python3
"""Fail if any tracked file still carries a merge-conflict marker.

WHY THIS EXISTS. #465 merged to `main` on 2026-09-25 with a resolved-by-accident
conflict in `docs/LIMITATIONS.md` section 5.6: the opening marker, the same line
twice and the closing marker, left behind by a merge whose two sides differed only
in a derived count. Every job was green. Nothing in the tree reads a file for
markers: the compiler would have refused one in C, but Markdown, YAML and HTML
render them as text, and the prose, claims and site checkers each look for
something else. It was found a day later, by accident, while applying another
branch on top.

WHAT IS A MARKER. Git writes each one at column 0, as exactly seven characters
followed by a space and a label, or by the end of the line:

  1. the opening marker, seven `<`
  2. the separator, seven `=` and nothing else on the line
  3. the closing marker, seven `>`
  4. the base marker `diff3` style writes, seven `|`

The separator alone is the one a partial resolution tends to leave, since it has
no label to catch the eye. The price of rule 2 is that a Markdown setext heading
underlined with exactly seven `=` is refused; underline it with any other number.

WHAT IS SCANNED. Every file `git ls-files` names (the index, so a new file must be
staged, as for the rest of the local sweep), skipping any whose first 8 KiB hold a
NUL byte, which is how git itself tells binary from text.

Exit 0 when clean, 1 when any marker is found.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

RULES = (
    ("1", re.compile(rb"^<{7}(?: |$)"), "an opening conflict marker"),
    ("2", re.compile(rb"^={7}$"), "a conflict separator"),
    ("3", re.compile(rb"^>{7}(?: |$)"), "a closing conflict marker"),
    ("4", re.compile(rb"^\|{7}(?: |$)"), "a diff3 base marker"),
)


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                         capture_output=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def main():
    problems = []
    scanned = 0
    for rel in tracked_files():
        path = ROOT / rel
        try:
            data = path.read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            # Deleted in the working tree but still in the index, or a submodule.
            continue
        if b"\0" in data[:8192]:
            continue
        scanned += 1
        for n, line in enumerate(data.split(b"\n"), 1):
            line = line.rstrip(b"\r")
            for rule, pat, what in RULES:
                if pat.match(line):
                    problems.append(f"{rel}:{n}: rule {rule}, {what}")
    print(f"text files scanned: {scanned}")
    if problems:
        print("\nFAIL: a merge-conflict marker is in the tree\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). Resolve the conflict; if a line is meant to look "
              "like this, change it (see the docstring).")
        return 1
    print("\nPASS: no merge-conflict marker in any tracked text file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
