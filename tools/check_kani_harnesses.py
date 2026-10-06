#!/usr/bin/env python3
"""Fail the build if a Kani proof would not run on a pull request.

Thirteen `#[kani::proof]` harnesses existed and NONE of them ran on a pull
request: the `kani` job was `workflow_dispatch`-only and carried
`continue-on-error: true` on both steps, so it could not have failed one even
if it had. A proof nobody runs is a comment with a solver attached.

From 2026-08-23 the manifest let a proof be excused to that job with a written
reason, and two were. On 2026-10-06 both were made to finish, the job was
deleted, and with it any place an excused proof could run, so excusing one is
now refused outright.

Three rules:

  1. every harness in the crate is in `gating`
  2. nothing is excused: the manifest has no list but `gating`
  3. every name listed exists in the crate (no rotted entries)

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

    problems = []

    for key in sorted(k for k in man if k != "gating"):
        problems.append(
            f"`{key}`: the manifest may hold only `gating` -- no job runs a "
            f"proof listed anywhere else, so it would never be checked"
        )

    for name, src in sorted(found.items()):
        if name not in gating:
            problems.append(
                f"{name} ({src}): a proof not in `gating` -- add it, so the "
                f"`kani-bounded` job runs it on every pull request"
            )

    for name in sorted(set(gating)):
        if name not in found:
            problems.append(
                f"{name}: listed but no #[kani::proof] by that name exists -- "
                f"the entry has rotted, or the harness was renamed"
            )

    print(f"kani proofs in rust/src : {len(found)}")
    print(f"  gating                : {len(gating)}")

    if problems:
        print("\nFAIL: the Kani proofs and the list the CI job runs disagree\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). The crate is the truth; fix "
              f".github/kani-harnesses.yml, or the harness.")
        return 1
    print("\nPASS: every Kani proof gates a merge")
    return 0


if __name__ == "__main__":
    sys.exit(main())
