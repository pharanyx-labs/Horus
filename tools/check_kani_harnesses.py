#!/usr/bin/env python3
"""Fail the build if a Kani proof is not classified as gating or excused.

Thirteen `#[kani::proof]` harnesses existed and NONE of them ran on a pull
request: the `kani` job was `workflow_dispatch`-only and carried
`continue-on-error: true` on both steps, so it could not have failed one even
if it had. A proof nobody runs is a comment with a solver attached.

Four rules:

  1. every harness in the crate is in `gating` or `manual`, never neither
  2. never both
  3. every name listed exists in the crate (no rotted entries)
  4. a `manual` entry gives a substantive reason

Exit 0 if sound, 1 otherwise.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".github" / "kani-harnesses.yml"
SOURCES = sorted((ROOT / "rust" / "src").glob("*.rs"))

# `#[kani::proof]`, then any further attributes (#[kani::unwind(n)]), then the fn.
HARNESS = re.compile(
    r"#\[kani::proof\]\s*(?:#\[[^\]]*\]\s*)*fn\s+([A-Za-z_][A-Za-z0-9_]*)"
)


def harnesses():
    found = {}
    for src in SOURCES:
        for name in HARNESS.findall(src.read_text()):
            found[name] = src.name
    return found


def main():
    found = harnesses()
    man = yaml.safe_load(MANIFEST.read_text()) or {}
    gating = list(man.get("gating") or [])
    manual = dict(man.get("manual") or {})

    problems = []

    for name in sorted(set(gating) & set(manual)):
        problems.append(f"{name}: listed as both gating and manual")

    for name, src in sorted(found.items()):
        if name not in gating and name not in manual:
            problems.append(
                f"{name} ({src}): a proof in neither list -- put it in `gating`, "
                f"or in `manual` with the reason it cannot run on every PR"
            )

    for name in sorted(set(gating) | set(manual)):
        if name not in found:
            problems.append(
                f"{name}: listed but no #[kani::proof] by that name exists -- "
                f"the entry has rotted, or the harness was renamed"
            )

    for name, reason in sorted(manual.items()):
        if not reason or len(str(reason).split()) < 6:
            problems.append(f"{name}: excused from gating with no substantive reason")

    print(f"kani proofs in rust/src : {len(found)}")
    print(f"  gating                : {len(gating)}")
    print(f"  manual (with a reason): {len(manual)}")

    if problems:
        print("\nFAIL: the Kani proofs and their classification disagree\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). The crate is the truth; fix "
              f".github/kani-harnesses.yml, or the harness.")
        return 1
    print("\nPASS: every Kani proof either gates a merge or is excused with a reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
