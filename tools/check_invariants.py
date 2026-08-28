#!/usr/bin/env python3
"""Bind every security property in SECURITY.md to a witness that exists — roadmap 4.12, [F-4.1].

WHAT THIS ATTACKS. Finding [C-1] was a documented property with no test binding it
to the code. The same shape recurred on 2026-08-28: S16 ("a task cannot read
another's XMM register file") had a literal em-dash in its witness column, against
`fpu_save`/`fpu_restore` — real code, called on every ring transition, exercised by
nothing. It survived every prior sweep because those sweeps looked for gates that
were ABSENT or VACUOUS, and this gate was neither. Nobody had asked, mechanically,
"which claims have no witness at all".

WHY THIS DERIVES FROM SECURITY.md RATHER THAN DUPLICATING IT. The obvious design is
a hand-written invariants.yaml naming each property, its code and its test. That is
a second copy of claims that already exist in a table, and a second copy is what
[H-3] is: two descriptions of one thing, drifting. SECURITY.md's table is already
machine-readable (id | statement | enforced by | witness), so it IS the registry.
The manifest holds only what the table cannot express — properties witnessed by
something other than a make target or a CI job, each with a written reason.

SIX RULES, each with its own control arm in tools/test_check_invariants.sh:

  R1  every property has a witness that resolves to something real
  R2  every `make X` named as a witness is a target that exists
  R3  every witness target runs in CI, or is excused in gate-exceptions.yml
  R4  every control-arm flag named is in DEFECT_FLAGS, so it is stamped at boot
  R5  ids are unique, and the numeric ones are contiguous from 1
  R6  no exemption is stale — for an unknown id, or for one that now resolves

R4 is the subtle one. A witness column that names `FOO_UNGUARDED=1` is claiming the
property is falsifiable on demand; if that flag is not in DEFECT_FLAGS, the boot
banner will not stamp it, and a measurement taken under it cannot be told apart
from one taken without it. That is how a stale KSP_GUARD_INJECT once turned a [G-9]
campaign into a false reproduction.
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def read(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as f:
        return f.read()

ROW = re.compile(r"^\|\s*(S\d+[a-z]?)\s*\|(.*)$")

def parse_security():
    """id -> (statement, enforced_by, witness). The table IS the registry."""
    out = {}
    order = []
    for line in read("SECURITY.md").split("\n"):
        m = ROW.match(line)
        if not m:
            continue
        sid = m.group(1)
        # Split on UNESCAPED pipes only. A rights expression in a cell is written
        # `CAP_RIGHT_WRITE \| CAP_RIGHT_EXEC`, and a naive split on "|" chops the
        # row there -- which silently truncated S26's witness to "WRITE\" and
        # reported it as unwitnessed. A registry that invents findings is worse
        # than no registry, because the first thing anyone does with a false one
        # is learn to skim past it.
        cols = [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", line)]
        # ['', 'Sn', statement, enforced, witness, '']
        if len(cols) < 5:
            continue
        out[sid] = (cols[2], cols[3], cols[4])
        order.append(sid)
    return out, order

def make_targets():
    return set(re.findall(r"^([A-Za-z0-9_.-]+):", read("Makefile"), re.M))

def ci_jobs():
    jobs = set()
    for fn in sorted(os.listdir(os.path.join(ROOT, ".github/workflows"))):
        if not fn.endswith((".yml", ".yaml")):
            continue
        # Job ids are two-space-indented keys under `jobs:`; parsed textually so
        # this needs no YAML dependency and cannot fail on an anchor it dislikes.
        body = read(os.path.join(".github/workflows", fn))
        injobs = False
        for line in body.split("\n"):
            if re.match(r"^jobs:\s*$", line):
                injobs = True
                continue
            if injobs:
                if re.match(r"^\S", line):
                    injobs = False
                    continue
                m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
                if m:
                    jobs.add(m.group(1))
    return jobs

def ci_text():
    return "".join(
        read(os.path.join(".github/workflows", fn))
        for fn in sorted(os.listdir(os.path.join(ROOT, ".github/workflows")))
        if fn.endswith((".yml", ".yaml"))
    )

def defect_flags():
    m = re.search(r"^DEFECT_FLAGS\s*=(.*?)(?=\n[A-Za-z#])", read("Makefile"), re.S | re.M)
    return set(re.findall(r"\b([A-Z][A-Z0-9_]{3,})\b", m.group(1))) if m else set()

def gate_exceptions():
    try:
        return read(".github/gate-exceptions.yml")
    except OSError:
        return ""

def manifest():
    """Exemptions only: id -> {witnessed_by, reason}. Deliberately tiny."""
    try:
        body = read(".github/invariants.yml")
    except OSError:
        return {}
    out, cur = {}, None
    for line in body.split("\n"):
        m = re.match(r"^  ([A-Za-z0-9]+):\s*$", line)
        if m:
            cur = m.group(1)
            out[cur] = {}
            continue
        m = re.match(r"^    (witnessed_by|reason):\s*(?:>-)?\s*(.*)$", line)
        if m and cur:
            out[cur][m.group(1)] = m.group(2).strip()
            continue
        m = re.match(r"^      (.+)$", line)
        if m and cur:
            for k in ("reason", "witnessed_by"):
                if k in out[cur] and out[cur][k] == "":
                    out[cur][k] = m.group(1).strip()
                    break
            else:
                if "reason" in out[cur]:
                    out[cur]["reason"] += " " + m.group(1).strip()
    return out

def witness_tokens(cell, targets, jobs):
    """Everything in a witness cell that could name a runnable thing."""
    mk = set(re.findall(r"`make ([A-Za-z0-9_.-]+)`", cell))
    mk |= set(re.findall(r"\bmake ([A-Za-z0-9_.-]+)", cell))
    bare = set(re.findall(r"`([a-z][a-z0-9-]{3,})`", cell))
    mk |= {b for b in bare if b in targets}
    jb = {b for b in bare if b in jobs}
    flags = set(re.findall(r"`([A-Z][A-Z0-9_]{3,})=1`", cell))
    return mk, jb, flags

def main():
    sec, order = parse_security()
    targets, jobs, flags_ok = make_targets(), ci_jobs(), defect_flags()
    ci, exc, exempt = ci_text(), gate_exceptions(), manifest()
    problems = []

    for sid in order:
        _stmt, _enf, wit = sec[sid]
        mk, jb, flags = witness_tokens(wit, targets, jobs)

        # R2 — a witness naming a target that does not exist is worse than none:
        # it reads as bound and is not.
        for t in sorted(mk):
            if t not in targets:
                problems.append(f"R2 {sid}: witness names `make {t}`, which is not a Makefile target")

        # R3 — and a target nothing runs is a witness only in principle.
        for t in sorted(mk & targets):
            if not re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(t), ci) and t not in exc:
                problems.append(f"R3 {sid}: witness `make {t}` is run by no workflow and is not in gate-exceptions.yml")

        # R4 — an unstamped arm makes its own measurements unreadable.
        for f in sorted(flags):
            if f not in flags_ok:
                problems.append(f"R4 {sid}: control arm `{f}=1` is not in DEFECT_FLAGS, so a boot under it is not stamped")

        # R1 — the rule this exists for.
        resolved = bool((mk & targets) or jb)
        if not resolved and sid not in exempt:
            problems.append(f"R1 {sid}: no witness resolves to a make target or a CI job, and there is no exemption")
        if not resolved and sid in exempt:
            e = exempt[sid]
            if len((e.get("reason") or "").split()) < 8:
                problems.append(f"R1 {sid}: exemption needs a reason of at least eight words")
            if not e.get("witnessed_by"):
                problems.append(f"R1 {sid}: exemption must say what it IS witnessed by")

    # R5 — ids unique and contiguous.
    if len(order) != len(set(order)):
        dupes = sorted({s for s in order if order.count(s) > 1})
        problems.append(f"R5 duplicate invariant ids: {', '.join(dupes)}")
    nums = sorted({int(re.match(r"S(\d+)", s).group(1)) for s in order})
    gaps = [n for n in range(1, (nums[-1] if nums else 0) + 1) if n not in nums]
    if gaps:
        problems.append(f"R5 gap in the invariant numbering: S{', S'.join(str(g) for g in gaps)}")

    # R6 — an exemption that has outlived its reason is a claim nobody rechecks.
    for sid in sorted(exempt):
        if sid not in sec:
            problems.append(f"R6 exemption for {sid}, which is not in SECURITY.md")
            continue
        mk, jb, _ = witness_tokens(sec[sid][2], targets, jobs)
        if (mk & targets) or jb:
            problems.append(f"R6 exemption for {sid} is stale: it now has a real witness")

    print(f"invariants in SECURITY.md : {len(order)}")
    print(f"  witnessed by a target   : {sum(1 for s in order if witness_tokens(sec[s][2], targets, jobs)[0] & targets)}")
    print(f"  witnessed by a CI job   : {sum(1 for s in order if witness_tokens(sec[s][2], targets, jobs)[1])}")
    print(f"  exempted, with a reason : {len(exempt)}")
    print(f"distinct witness targets  : {len({t for s in order for t in witness_tokens(sec[s][2], targets, jobs)[0] & targets})}")

    if problems:
        print("\nFAIL: a security property is not bound to a witness that exists\n")
        for p in problems:
            print("  - " + p)
        print(f"\n{len(problems)} problem(s). SECURITY.md is the registry; fix the row, or")
        print("add an exemption with a written reason to .github/invariants.yml.")
        return 1
    print("\nPASS: every security property has a witness, and every witness exists and runs")
    return 0

if __name__ == "__main__":
    sys.exit(main())
