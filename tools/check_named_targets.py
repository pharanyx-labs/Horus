#!/usr/bin/env python3
"""Fail the build if a file names a `make` target that does not exist.

THE DEFECT THIS CATCHES is a comment or a document telling a reader to run a
gate that cannot be run. It is the quietest kind of stale claim in this
repository: the reader who follows it gets `No rule to make target`, which reads
as their own mistake, and the reader who does not follow it takes the sentence at
face value -- so a check nobody can run looks exactly like a check that passes.

IT WAS MEASURED BEFORE IT WAS WRITTEN, which is the only reason it exists. On
2026-09-09 the tree held five of them:

  - src/kernel/scheduler.c said `make smoke-pipe-cspace-order-control` beside
    the ordering it protects. That target had never existed; the flag it names
    had no arm at all, which is what made the sentence worth checking.
  - src/kernel/capability.c said `smoke-captest-cspaceless-control`
    (it is `smoke-cap-lookup-control`).
  - src/kernel/syscall_hw.c said `smoke-irq-ack-control`
    (it is `smoke-captest-irq-ack-control`).
  - src/kernel/sdhci.c said `smoke-sdhci-card` (it is `smoke-sdhci-detect`).
  - docs/BUILDING.md described a pair against `smoke-resume-guard-preclaim-control`
    (the other arm is `smoke-resume-guard-legacy`).

Four were near-misses of a real name, which is the failure mode a hand sweep is
worst at: the sentence reads correctly, and only running it disagrees.

WHAT IS SCANNED, AND WHY THE HISTORY IS NOT. Every tracked file except
docs/history/ and CHANGES.md, which are records of what was true when written --
a retired target named in an entry from August is correct history, and rewriting
it would be the opposite of what those files are for. The fixtures in the
checker self-tests are exempted by name below, with the reason, because they
plant deliberately-absent targets in order to falsify their own checkers.

TWO REFERENCE FORMS, and both were measured. `make <target>` is the one that
found all five. Backticked `` `smoke-x` `` currently resolves everywhere, so
including it costs nothing today and stops the next stale reference from hiding
behind a missing "make". A C comment may wrap a reference across lines, so
comment continuations are joined before matching -- the capability.c case above
is exactly that shape and the first draft of this checker missed it.

A NAME THAT NO LONGER RESOLVES DOES NOT GET A CODE SPAN. Recording a stale name
is often the right thing -- TESTS.md's row for this checker lists the four it
found -- and a backticked one would be a finding of its own. The convention is
that a code span is a thing a reader can run, so a retired or mistaken name is
written as plain prose. That is why this file's own header, which quotes five of
them, is in the exemption list below: it is the one place where the names have to
appear as they were written.

Exit 0 if every named target exists, 1 otherwise.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Paths whose smoke-* references are not claims about the current tree.
SKIP_PREFIXES = ("docs/history/",)
SKIP_FILES = {"CHANGES.md"}

# Files that name absent targets ON PURPOSE, with the reason. Each one mutates a
# copy of the tree to prove its checker notices; the planted names must not
# exist, which is the point of them.
EXEMPT = {
    "tools/test_check_gate_pairs.sh": "plants absent targets to falsify check_gate_pairs.py",
    "tools/test_check_invariants.sh": "plants absent targets to falsify check_invariants.py",
    "tools/check_named_targets.py":   "this file quotes the five stale names it was written for",
    "tools/test_check_named_targets.sh": "plants absent targets to falsify this checker",
    "tools/test_check_claude_md.sh":   "plants absent targets to falsify check_claude_md.py",
}

TARGET = r"smoke-[a-z0-9]+(?:-[a-z0-9]+)*"
REF_MAKE = re.compile(r"make\s+(" + TARGET + r")")
REF_TICK = re.compile(r"`(" + TARGET + r")`")
# A C comment continuation: newline, optional indent, a leading '*', optional
# indent. Joined before matching so `See make\n * smoke-x` is one reference.
#
# TWO JOINS, because a comment can wrap a target name at a hyphen. `make
# smoke-syscall-\n * coverage` is one name to a reader and two tokens to a
# regex; joining it with a space invents `smoke-syscall`, which does not exist,
# and the checker reports a stale reference that is not one. So a line ending in
# a hyphen joins with NOTHING and every other continuation joins with a space.
# Measured: userspace/execprobe.c is exactly that shape, and the first draft of
# this file reported it.
CONT_HYPHEN = re.compile(r"-\n[ \t]*\*?[ \t]*")
CONT = re.compile(r"\n[ \t]*\*?[ \t]*")


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.split("\n")
    return [f for f in out if f]


def targets() -> set[str]:
    mk = (ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^(smoke-[a-z0-9-]+):", mk, re.M))


def main() -> int:
    defined = targets()
    if not defined:
        print("FAIL: no smoke-* targets found in the Makefile -- the parser is wrong,")
        print("      and a checker that finds nothing to compare against passes vacuously.")
        return 1

    problems = []
    scanned = 0
    refs = 0
    for rel in tracked_files():
        if rel in SKIP_FILES or rel in EXEMPT:
            continue
        if any(rel.startswith(p) for p in SKIP_PREFIXES):
            continue
        path = ROOT / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue          # binary or unreadable: nothing to claim
        scanned += 1
        joined = CONT.sub(" ", CONT_HYPHEN.sub("-", text))
        for pat in (REF_MAKE, REF_TICK):
            for m in pat.finditer(joined):
                refs += 1
                name = m.group(1)
                if name in defined:
                    continue
                # Report the line by searching the ORIGINAL text, so a joined
                # reference still points at where the reader will find it.
                line = 1
                first = name.split("-")[0] if "\n" in name else name
                for n, l in enumerate(text.split("\n"), 1):
                    if name in l or (name.rsplit("-", 1)[0] in l and first in l):
                        line = n
                        break
                problems.append((rel, line, name))

    # Deduplicate: one report per (file, target).
    seen = set()
    unique = []
    for rel, line, name in problems:
        if (rel, name) in seen:
            continue
        seen.add((rel, name))
        unique.append((rel, line, name))

    print(f"files scanned      : {scanned}")
    print(f"target references  : {refs}")
    print(f"targets defined    : {len(defined)}")
    print(f"exempted files     : {len(EXEMPT)}")

    if unique:
        print()
        print("FAIL: a file names a make target that does not exist")
        print()
        for rel, line, name in sorted(unique):
            print(f"  - {rel}:{line}: `{name}`")
        print()
        print("A gate nobody can run reads exactly like a gate that passes. Fix the")
        print("name, or add the target -- one of the five this checker was written for")
        print("turned out to be a gate that should have existed and now does.")
        return 1

    print()
    print("PASS: every make target named in the tree exists")
    return 0


if __name__ == "__main__":
    sys.exit(main())
