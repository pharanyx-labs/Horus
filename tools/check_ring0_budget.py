#!/usr/bin/env python3
"""Every object linked into kernel.elf is classified, and `core` stays inside its budget.

WHY THIS EXISTS. "Shrink ring 0" was a recommendation with no subject. The
kernel is 37 linked objects, and nothing in the tree said which of them are the
security core and which are passengers -- so the same target was met or missed
depending on which files you counted and whether you counted comments. The seven
files one reviewer named come to 13,977 physical lines but 6,318 code lines; a
budget stated against the wrong one of those is not a measurement, it is a
rhetorical position.

THE CLASSIFICATION IS THE DELIVERABLE. The budget is a ratchet on top of it. The
rule that actually bites is that an object linked into kernel.elf and NOT listed
in .github/ring0-classification.yml fails the build: adding to ring 0 becomes a
decision somebody wrote down, rather than a side effect of adding a file. That is
the same argument .github/gate-pairs.yml makes about classifying targets --
intent is not recoverable from the Makefile.

CODE LINES, NOT PHYSICAL LINES, and the reason is not convenience. CLAUDE.md
section 7 requires long explanatory comments, and ring 0 here is about half
comment and blank by line -- the `WHY THIS DID NOT WORK IN JULY` block in
scheduler.c is cited in that section as an exemplar. A budget on physical lines
would create pressure to delete exactly the text that makes this kernel
auditable: a perverse incentive dressed as rigour. selftest.c makes the same
point from the other end -- 4,807 physical lines that are nearly free in the
shipped image, and would dominate any budget counted in lines of tree.

WHAT THIS DOES NOT CLAIM. That `core` is verified, or verifiable, or small. It
is 9,676 code lines, which is a lot; the value here is that the number exists,
has a boundary somebody chose, and cannot move without a commit that says so.
The eviction of `driver` and `service` is roadmap 2.6, 2.7 and the entries added
alongside this file -- not something a checker can do.

Carries S87. Exit 0 if every linked object is classified and core is within
budget, 1 otherwise.
"""
import pathlib
import re
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".github" / "ring0-classification.yml"
CLASSES = ("core", "driver", "service", "selftest")


def linked_sources():
    """The sources behind every object on kernel.elf's link line.

    Read from `make -n` rather than a glob of src/kernel/*.c, because those are
    different sets: minimal_secure_stubs.c and ramfs.c live in the tree and are
    linked only under a control arm, and a glob would demand they be classified
    as though they ship.
    """
    out = subprocess.run(["make", "-n", "kernel.elf"], cwd=ROOT,
                         capture_output=True, text=True).stdout
    objs = [t for line in out.splitlines() if line.startswith("ld ")
            for t in line.split() if t.endswith(".o")]
    srcs = set()
    for obj in objs:
        for ext in (".c", ".S"):
            cand = ROOT / (obj[:-2] + ext)
            if cand.exists():
                srcs.add(cand.relative_to(ROOT).as_posix())
                break
    return srcs


def code_lines(rel):
    """Non-blank, non-comment lines. See the header for why this and not `wc -l`."""
    path = ROOT / rel
    text = path.read_text(errors="replace")
    if path.suffix == ".c":
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//[^\n]*", "", text)
    else:
        text = re.sub(r"(?m)^\s*[#/].*$", "", text)
    return len([ln for ln in text.splitlines() if ln.strip()])


def main():
    manifest = yaml.safe_load(MANIFEST.read_text()) or {}
    classify = manifest.get("classify") or {}
    budget = manifest.get("core_budget_loc")

    problems = []
    if budget is None:
        problems.append("core_budget_loc is not set in .github/ring0-classification.yml")

    listed = {}
    for cls in CLASSES:
        for rel in classify.get(cls) or []:
            if rel in listed:
                problems.append(f"{rel} is classified twice ({listed[rel]} and {cls})")
            listed[rel] = cls
    for cls in classify:
        if cls not in CLASSES:
            problems.append(f"unknown class '{cls}' -- expected one of {', '.join(CLASSES)}")

    linked = linked_sources()

    # SELF-CHECK. Every rule below is vacuous against an empty link line: if
    # `make -n` stops naming objects, an unclassified file cannot be detected and
    # core measures 0, which is under any budget. A checker that reports a clean
    # tree because it parsed nothing is the failure this repository keeps finding.
    if len(linked) < 20:
        problems.append(
            f"resolved only {len(linked)} linked sources from `make -n kernel.elf`, "
            f"which is fewer than this kernel has ever had. The link line has "
            f"probably stopped parsing -- fix that rather than lowering this "
            f"bound, because every rule here is vacuous without it")

    for rel in sorted(linked - set(listed)):
        problems.append(
            f"{rel} is linked into kernel.elf and is not classified. Add it to "
            f".github/ring0-classification.yml under core, driver, service or "
            f"selftest -- putting code in ring 0 is a decision, and this is where "
            f"it gets written down")
    for rel in sorted(set(listed) - linked):
        problems.append(
            f"{rel} is classified but is not linked into kernel.elf. Remove the "
            f"entry, or the file is being kept alive by a stale manifest")

    totals = {cls: 0 for cls in CLASSES}
    for rel, cls in listed.items():
        if rel in linked:
            totals[cls] += code_lines(rel)

    if budget is not None and totals["core"] > budget:
        problems.append(
            f"core is {totals['core']} code lines, over its budget of {budget} by "
            f"{totals['core'] - budget}. Either the new code belongs in driver or "
            f"service, or the verified core genuinely grew -- raise the budget in "
            f"the same commit and say why")

    if problems:
        print("FAIL: check_ring0_budget")
        for p in problems:
            print("  - " + p)
        return 1

    width = max(len(c) for c in CLASSES)
    for cls in CLASSES:
        n = len([1 for r, c in listed.items() if c == cls and r in linked])
        print(f"  {cls:<{width}}  {totals[cls]:6d} code lines  ({n} files)")
    print(f"  {'total':<{width}}  {sum(totals.values()):6d}")
    print(f"\nPASS: every linked object is classified; core {totals['core']} "
          f"within budget {budget}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
