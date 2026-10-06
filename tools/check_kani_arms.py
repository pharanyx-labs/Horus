#!/usr/bin/env python3
"""Fail the build if the Kani control-arm registry has rotted.

`tools/kani_arms.py` runs each arm in `.github/kani-arms.yml` nightly and needs
Kani and minutes per arm. This is the cheap half that runs on every pull
request: it checks, without a solver, that every arm could still be applied,
so a change that moves an arm's anchor text fails the same day rather than in
that night's run, and that no proof quietly lacks an arm.

Five rules:

  1. every arm names a harness the gating list (.github/kani-harnesses.yml) has
  2. every arm's file exists under rust/, its find text occurs there exactly
     once, and its replacement differs from it
  3. every gating harness has an arm, or is in `unarmed` with a reason
  4. nothing is both armed and in `unarmed`, and `unarmed` names only real
     harnesses (the list can only shrink: an entry whose harness now has an
     arm must be removed)
  5. arm ids are unique

Exit 0 if sound, 1 otherwise.
"""
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARMS = ROOT / ".github" / "kani-arms.yml"
HARNESSES = ROOT / ".github" / "kani-harnesses.yml"


def main():
    reg = yaml.safe_load(ARMS.read_text()) or {}
    arms = reg.get("arms") or []
    unarmed = dict(reg.get("unarmed") or {})
    gating = set((yaml.safe_load(HARNESSES.read_text()) or {}).get("gating") or [])

    problems = []
    if not gating:
        problems.append("the gating list in .github/kani-harnesses.yml is empty: nothing to check against")

    ids = [a.get("id") for a in arms]
    for i in sorted({i for i in ids if ids.count(i) > 1}):
        problems.append(f"arm id {i!r} is used more than once")

    armed = set()
    for a in arms:
        aid, h, f = a.get("id"), a.get("harness"), a.get("file", "")
        find, repl = a.get("find"), a.get("replace")
        if h not in gating:
            problems.append(f"{aid}: names harness {h!r}, which the gating list does not have")
        armed.add(h)
        p = ROOT / f
        if not f.startswith("rust/") or not p.is_file():
            problems.append(f"{aid}: file {f!r} is not a file under rust/")
            continue
        if not find:
            problems.append(f"{aid}: has no find text")
            continue
        n = p.read_text().count(find)
        if n != 1:
            problems.append(f"{aid}: its find text occurs {n} times in {f}, not once -- the code moved; update the arm")
        if repl is None or repl == find:
            problems.append(f"{aid}: its replacement is missing or identical to the find text, so it mutates nothing")

    for h in sorted(gating - armed - set(unarmed)):
        problems.append(f"{h}: a gating proof with no control arm -- add one to .github/kani-arms.yml, or list it under `unarmed` with the reason")
    for h in sorted(armed & set(unarmed)):
        problems.append(f"{h}: has an arm and is also listed as unarmed -- remove it from `unarmed`")
    for h, why in sorted(unarmed.items()):
        if h not in gating:
            problems.append(f"{h}: listed as unarmed but is not a gating proof")
        if not why or len(str(why).split()) < 4:
            problems.append(f"{h}: listed as unarmed with no substantive reason")

    print(f"control arms          : {len(arms)}")
    print(f"  proofs with an arm  : {len(armed & gating)} of {len(gating)}")
    print(f"  unarmed, with reason: {len(unarmed)}")
    if problems:
        print("\nFAIL: the Kani control-arm registry and the tree disagree\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nPASS: every arm still applies, and every proof has one or a reason it does not")
    return 0


if __name__ == "__main__":
    sys.exit(main())
