#!/usr/bin/env python3
"""Fail the build if a gate or its control arm is structurally unsound.

The control-arm discipline is this project's answer to "would this gate fail if
the property broke". It only works if the pairs stay intact, and nothing checked
that until 2026-08-21, when `smoke-ksp-guard-control` was found to have no
positive counterpart at all: an arm that proved the guard COULD fire, with
nothing asking whether it stayed silent on a legal value. That is the same
missing direction which let the resume-%rsp guard ship a bound rejecting the IST
stacks and redden ten CI gates at once.

CLASSIFICATION IS DECLARED, NOT INFERRED, since 2026-08-30. This file used to
decide "is this a control arm" by testing for the substring `control` in the
target NAME, and four falsification arms are named otherwise, so they counted as
base gates and both published figures were wrong. Three derivations were tried
and each fails differently (see the header of .github/gate-pairs.yml); the
distinction is a statement about INTENT and is not recoverable from the Makefile.
So every smoke-* target is named in that manifest, and rule 5 below refuses one
that is not.

Five rules, each of which has been violated at least once in this tree:

  1. every control arm extends a base gate that exists   (the orphan above)
  2. every control arm is actually invoked by CI          (an arm nobody runs rots)
  3. every gate is invoked by CI or another target, or is
     listed in .github/gate-exceptions.yml with a reason  (silent local-only gates)
  4. an exception names a real target and gives a reason  (no empty placeholders)
  5. every smoke-* target is classified in gate-pairs.yml (no silent default)

Exit 0 if sound, 1 otherwise.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "Makefile"
EXCEPTIONS = ROOT / ".github" / "gate-exceptions.yml"
PAIRS = ROOT / ".github" / "gate-pairs.yml"
WORKFLOWS = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
    ROOT / ".github" / "workflows" / "ruleset-audit.yml",
]


def main():
    mk = MAKEFILE.read_text()
    targets = sorted(set(re.findall(r"^(smoke-[a-z0-9-]+):", mk, re.M)))

    pairs = yaml.safe_load(PAIRS.read_text()) or {}
    declared_arms = pairs.get("control_arms") or {}
    declared_gates = list(pairs.get("gates") or [])

    # Rule 5. A target absent from the manifest would otherwise be classified by
    # a default, and every default is wrong for some target: that is the whole
    # reason this file no longer guesses.
    unclassified = [t for t in targets
                    if t not in declared_arms and t not in declared_gates]
    stale = [t for t in list(declared_arms) + declared_gates if t not in targets]

    controls = [t for t in targets if t in declared_arms]
    gates = [t for t in targets if t in declared_gates]

    ci_text = "\n".join(w.read_text() for w in WORKFLOWS if w.exists())
    run_in_ci = set(re.findall(r"make\s+(smoke-[a-z0-9-]+)", ci_text))
    # A target invoked by another make target counts as reachable: several gates
    # are the inner arm of a stress wrapper that CI runs instead.
    via_make = set(re.findall(r"\$\(MAKE\)[^\n]*?\b(smoke-[a-z0-9-]+)\b", mk))
    reachable = run_in_ci | via_make

    exc = yaml.safe_load(EXCEPTIONS.read_text()) if EXCEPTIONS.exists() else {}
    not_in_ci = dict((exc or {}).get("not_in_ci") or {})

    problems = []

    # 5. everything is classified, and nothing stale is classified
    for t in unclassified:
        problems.append(
            f"{t}: not classified in .github/gate-pairs.yml -- say whether it is "
            f"a control arm (and which gate it extends) or a base gate. It is not "
            f"inferred, because every default is wrong for some target"
        )
    for t in stale:
        problems.append(f"{t}: classified in gate-pairs.yml but no such Makefile target")

    # 1. no orphan control arms: the declared base must be a declared gate
    for c in controls:
        base = declared_arms.get(c)
        if base in (None, "", "none"):
            problems.append(
                f"{c}: control arm with no base gate -- it proves the check CAN "
                f"fire, and nothing asks whether it stays silent when it should"
            )
        elif base not in declared_gates:
            problems.append(
                f"{c}: names `{base}` as its base gate, which is not a declared gate"
            )
        elif base not in targets:
            problems.append(f"{c}: names `{base}` as its base gate, which does not exist")

    # 2. control arms must run
    for c in controls:
        if c not in reachable:
            problems.append(f"{c}: control arm is never invoked by CI or another target")

    # 3. gates must run, or be excused
    for g in gates:
        if g not in reachable and g not in not_in_ci:
            problems.append(
                f"{g}: never invoked by CI or another target -- wire it up, or "
                f"add it to .github/gate-exceptions.yml with a reason"
            )

    # 4. exceptions must be real and substantive
    for name, reason in sorted(not_in_ci.items()):
        if name not in targets:
            problems.append(f"{name}: excused in gate-exceptions.yml but no such target")
        elif name in reachable:
            problems.append(
                f"{name}: excused as not-in-CI but IS invoked -- the reason is stale"
            )
        if not reason or len(str(reason).split()) < 5:
            problems.append(f"{name}: excused with no substantive reason")

    print(f"smoke targets     : {len(targets)}")
    print(f"  control arms    : {len(controls)}")
    print(f"  gates           : {len(gates)}")
    print(f"  excused from CI : {len(not_in_ci)}")

    if problems:
        print("\nFAIL: a gate or control arm is structurally unsound\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s).")
        return 1
    print("\nPASS: every control arm has a base gate, and every gate runs or is excused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
