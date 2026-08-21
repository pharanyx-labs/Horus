#!/usr/bin/env python3
"""Fail the build if a gate or its control arm is structurally unsound.

The control-arm discipline is this project's answer to "would this gate fail if
the property broke". It only works if the pairs stay intact, and nothing checked
that until now. On 2026-08-21 `smoke-ksp-guard-control` was found to have no
positive counterpart at all: an arm that proved the guard COULD fire, with
nothing asking whether it stayed silent on a legal value. That is the same
missing direction which let the resume-%rsp guard ship a bound rejecting the IST
stacks and redden ten CI gates at once.

Four rules, each of which has been violated at least once in this tree:

  1. every control arm extends a base gate that exists   (the orphan above)
  2. every control arm is actually invoked by CI          (an arm nobody runs rots)
  3. every gate is invoked by CI or another target, or is
     listed in .github/gate-exceptions.yml with a reason  (silent local-only gates)
  4. an exception names a real target and gives a reason  (no empty placeholders)

Exit 0 if sound, 1 otherwise.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "Makefile"
EXCEPTIONS = ROOT / ".github" / "gate-exceptions.yml"
WORKFLOWS = [
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
    ROOT / ".github" / "workflows" / "ruleset-audit.yml",
]


def main():
    mk = MAKEFILE.read_text()
    targets = sorted(set(re.findall(r"^(smoke-[a-z0-9-]+):", mk, re.M)))
    controls = [t for t in targets if "control" in t]
    gates = [t for t in targets if "control" not in t]

    ci_text = "\n".join(w.read_text() for w in WORKFLOWS if w.exists())
    run_in_ci = set(re.findall(r"make\s+(smoke-[a-z0-9-]+)", ci_text))
    # A target invoked by another make target counts as reachable: several gates
    # are the inner arm of a stress wrapper that CI runs instead.
    via_make = set(re.findall(r"\$\(MAKE\)[^\n]*?\b(smoke-[a-z0-9-]+)\b", mk))
    reachable = run_in_ci | via_make

    exc = yaml.safe_load(EXCEPTIONS.read_text()) if EXCEPTIONS.exists() else {}
    not_in_ci = dict((exc or {}).get("not_in_ci") or {})

    problems = []

    # 1. no orphan control arms
    for c in controls:
        # the base is the longest gate name this control arm extends
        base = None
        for g in gates:
            if c.startswith(g + "-") and (base is None or len(g) > len(base)):
                base = g
        if base is None:
            problems.append(
                f"{c}: control arm with no base gate -- it proves the check CAN "
                f"fire, and nothing asks whether it stays silent when it should"
            )

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
