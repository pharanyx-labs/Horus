#!/usr/bin/env python3
"""Refuse a multi-boot gate that cannot tell a dead boot from a passing one.

A gate that boots N times and asserts a marker is ABSENT is satisfied by N
boots that never happened. Two merge-blocking gates were in exactly that state
until 2026-08-30 -- see .github/gate-evidence.yml for the measurement.

Four rules:

  1. Every smoke-* target that boots more than once is classified in
     .github/gate-evidence.yml, under `liveness:` or `exempt:`. "More than once"
     counts boot-harness invocations, not loop syntax: four targets boot twice
     by writing the call out twice, and keying on loops would skip them.
  2. A `liveness:` target's declared marker and floor are both DEFINED as
     Makefile variables.
  3. A `liveness:` target's declared marker is READ BY A GREP, and its floor is
     COMPARED AGAINST in a numeric shell test. Not merely present: the first
     version of this rule accepted mere presence and passed a tree whose
     comparison had become `-lt 0`, because the floor was still named in the
     failure message.
  4. Every target named in the manifest still exists in the Makefile, and an
     `exempt:` reason is non-empty.

Rule 3 is the one that matters. Rules 1 and 2 are satisfiable by a manifest
entry alone, so a checker with only those would pass a tree in which the floor
was deleted from the recipe -- which is precisely how the original defect would
come back.
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = ROOT / "Makefile"
MANIFEST = ROOT / ".github" / "gate-evidence.yml"

# "Boots more than once" is the population, and it is deliberately NOT defined
# as "has a loop". Four targets (smoke-fs-persist, smoke-fs-wal and the two
# syscall-coverage targets) boot twice by writing the invocation out twice, and
# a rule keyed on loop syntax would skip them silently -- a false negative in
# the rule whose whole job is to refuse silence. So the test is on the number of
# boot-harness invocations, with the loop forms folded in for the targets that
# invoke the harness once inside a loop.
# Both spellings of the same loop. `$$(seq` is what a Makefile recipe writes;
# `$(seq` is what the same loop looks like inside a tools/*.sh script, and until
# the script bodies were folded in there was no reason for this pattern to know
# the difference. tools/stress_boot.sh loops STRESS_RUNS boots that way, so
# without the second form smoke-console-smp-stress and smoke-sched-invariants-
# stress read as single-boot gates -- which is the false NEGATIVE that appeared
# when whole-line comments stopped being counted, and is why this pattern was
# checked in both directions rather than only against the targets it flagged.
LOOP_RE = re.compile(r"for \w+ in \$\$?\(seq|while \[ \$\$?\w+ -lt|until \[")
HARNESS_RE = re.compile(r"smoke_test\.sh|session_test\.py|run_with_swtpm\.sh")

# A RECIPE THAT DELEGATES ITS BOOTS TO A SCRIPT WAS INVISIBLE HERE until
# 2026-08-31. This file counted boot-harness invocations in the Makefile recipe,
# so `smoke-merkle-replay` -- three boots, all of them inside
# tools/merkle_replay.sh -- counted as booting ONCE and was never asked how it
# knows those boots ran. That is the exact silence the file exists to refuse,
# reappearing one level of indirection down: the rule was right and its reach was
# not. So a recipe that calls a tools/*.sh script is read WITH that script's text
# folded in, and the script's boots count as the target's.
SCRIPT_RE = re.compile(r"tools/([A-Za-z0-9_.\-]+\.sh)")
# A BOOT HARNESS IS NEVER EXPANDED, and there are two of them: smoke_test.sh and
# run_with_swtpm.sh, which advertises the same contract. Each boots ONCE and each
# polls the serial log in a `while` loop of its own, so folding either in makes
# every target that calls it look like a multi-boot one -- the rule inverted. The
# first version of this change did exactly that, and the three swtpm targets were
# its false positives.
NOT_EXPANDED = {"smoke_test.sh", "run_with_swtpm.sh"}


def strip_comments(text):
    """Drop whole-line shell comments.

    A script that MENTIONS a boot harness in its header prose is not a script
    that calls it twice. tools/smoke_tpm.sh names run_with_swtpm.sh in a comment
    above the one line that runs it, and counting both made smoke-tpm and
    smoke-tpm-tamper look like two-boot gates.
    """
    return "\n".join(l for l in text.split("\n") if not l.lstrip().startswith("#"))


def expand_scripts(body, seen=None):
    """Recipe text with the text of any tools/*.sh script it calls appended."""
    seen = seen or set()
    text = body
    for name in SCRIPT_RE.findall(body):
        if name in seen or name in NOT_EXPANDED:
            continue
        seen.add(name)
        path = ROOT / "tools" / name
        if path.exists():
            text += "\n" + expand_scripts(strip_comments(path.read_text()), seen)
    return text


def boots_more_than_once(body):
    body = expand_scripts(body)
    return bool(LOOP_RE.search(body)) or len(HARNESS_RE.findall(body)) > 1


def recipes():
    """{target: recipe text} for every target in the Makefile."""
    out, cur = {}, None
    for line in MAKEFILE.read_text().split("\n"):
        m = re.match(r"^([A-Za-z0-9_.\-]+):(?!=)", line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
        elif cur is not None:
            if line.startswith("\t"):
                out[cur].append(line)
            elif line.strip():
                cur = None
    return {t: "\n".join(b) for t, b in out.items()}


def make_variables():
    """Names assigned at the top level of the Makefile (`X = ...` or `X ?= ...`)."""
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)\s*[?:]?=", MAKEFILE.read_text(), re.M))


def main():
    man = yaml.safe_load(MANIFEST.read_text()) or {}
    liveness = man.get("liveness") or {}
    exempt = man.get("exempt") or {}
    bodies = recipes()
    variables = make_variables()
    errors = []

    multiboot = sorted(t for t, b in bodies.items()
                     if t.startswith("smoke-") and boots_more_than_once(b))

    # Rule 1
    for t in multiboot:
        if t not in liveness and t not in exempt:
            errors.append(
                f"{t}: boots more than once and is not classified in "
                f".github/gate-evidence.yml. Declare how it tells a boot that "
                f"ran from one that died, under `liveness:` or `exempt:`.")

    # Rule 4 (manifest hygiene)
    for t in list(liveness) + list(exempt):
        if t not in bodies:
            errors.append(f"{t}: named in gate-evidence.yml but no such Makefile target.")
    for t, reason in exempt.items():
        if not (reason or "").strip():
            errors.append(f"{t}: exempt with no reason. Say which mechanism it uses.")

    # Rules 2 and 3
    for t, spec in liveness.items():
        if t not in bodies:
            continue
        body = bodies[t]
        for kind in ("marker", "floor"):
            name = (spec or {}).get(kind)
            if not name:
                errors.append(f"{t}: `liveness:` entry has no `{kind}:`.")
                continue
            if name not in variables:
                errors.append(
                    f"{t}: declares {kind} {name}, which is not a Makefile variable.")
            # Presence anywhere is NOT enough, and this is not a hypothetical:
            # the first version of this rule tested exactly that and passed a
            # tree whose comparison had been replaced by `-lt 0`, because the
            # floor was still named in the failure message ("floor is $(...)").
            # A floor quoted in an echo is as broken as one never mentioned. So
            # the marker must be read by a grep, and the floor must appear in a
            # numeric shell comparison.
            uses = [ln for ln in body.split("\n") if f"$({name})" in ln]
            if not uses:
                errors.append(
                    f"{t}: declares {kind} {name} but the recipe never reads it. "
                    f"A floor that is defined and never read is the defect, not the fix.")
            elif kind == "floor" and not any(
                    re.search(r"\[[^]]*-(lt|le|gt|ge)\b", ln) for ln in uses):
                errors.append(
                    f"{t}: declares floor {name}, but the recipe only mentions it "
                    f"(in a message, say) and never compares against it.")
            elif kind == "marker" and not any("grep" in ln for ln in uses):
                errors.append(
                    f"{t}: declares marker {name}, but no grep in the recipe reads it, "
                    f"so no boot is ever scored as live.")

    if errors:
        print("FAIL: a multi-boot gate cannot distinguish a dead boot from a pass")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(f"multi-boot smoke targets : {len(multiboot)}")
    print(f"  liveness-floored    : {len(liveness)}")
    print(f"  exempt (declared)   : {len(exempt)}")
    print("\nPASS: every multi-boot gate says how it knows the boots ran")
    return 0


if __name__ == "__main__":
    sys.exit(main())
