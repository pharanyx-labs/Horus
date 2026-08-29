#!/usr/bin/env python3
"""Drop required status checks that no workflow on the base branch can produce.

A required context whose job does not exist on `main` can never report, so every
pull request against `main` is blocked on it forever — a repository-wide merge
freeze, and one that looks like an ordinary red check rather than a
misconfiguration.

That is exactly what happened on 2026-08-16: `--sync-ruleset` was run from a
feature branch, so it wrote the *intended* required list — including the
`ci-gating` job itself — while `main` still had no such job. The classification
was right about where the repository was going and wrong about where it was.

The rule this encodes: **never require a context the base branch cannot produce.**
Promote a job in the same change that introduces it, or after it has landed —
never before.

Run it, then re-run `check_ci_gating.py --sync-ruleset` once the missing jobs are
on `main` to restore the full set.

    tools/prune_unsatisfiable_checks.py            # report only
    tools/prune_unsatisfiable_checks.py --apply    # write the ruleset

Needs a `gh` token with Administration rights, like `--sync-ruleset`.
"""
import json
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit("prune_unsatisfiable_checks: PyYAML is required (pip install pyyaml)")

RULESET = "repos/pharanyx-labs/Horus/rulesets/21815299"
BASE = "origin/main"
WORKFLOWS = [".github/workflows/ci.yml", ".github/workflows/codeql.yml"]


def contexts_on_base():
    """Every status-check context the workflows on BASE can produce."""
    out = set()
    for wf in WORKFLOWS:
        try:
            raw = subprocess.run(["git", "show", f"{BASE}:{wf}"],
                                 capture_output=True, text=True, check=True).stdout
        except subprocess.CalledProcessError:
            continue  # workflow does not exist on the base branch
        doc = yaml.safe_load(raw)
        for jid, spec in (doc.get("jobs") or {}).items():
            name = spec.get("name", jid)
            matrix = spec.get("strategy", {}).get("matrix", {})
            matrix = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
            if not matrix:
                out.add(name)
                continue
            key, values = next(iter(matrix.items()))
            token = "${{ matrix." + key + " }}"
            for v in values:
                out.add(name.replace(token, str(v)))
    return out


def main():
    apply = "--apply" in sys.argv

    subprocess.run(["git", "fetch", "-q", "origin", "main"], check=False)
    producible = contexts_on_base()
    if not producible:
        sys.exit(f"could not read any workflow from {BASE} — refusing to guess")

    rs = json.loads(subprocess.run(["gh", "api", RULESET],
                                   capture_output=True, text=True, check=True).stdout)
    rule = next((r for r in rs["rules"]
                 if r["type"] == "required_status_checks"), None)
    if rule is None:
        sys.exit("ruleset has no required_status_checks rule")

    p = rule["parameters"]
    live = [c["context"] for c in p["required_status_checks"]]
    keep = sorted(c for c in live if c in producible)
    drop = sorted(c for c in live if c not in producible)

    print(f"required contexts live on the ruleset : {len(live)}")
    print(f"producible by workflows on {BASE}      : {len(producible)}")
    for c in drop:
        print(f"  UNSATISFIABLE (would block every PR): {c}")
    if not drop:
        print("\nnothing to prune — every required context can be produced")
        return 0
    if not apply:
        print(f"\n{len(drop)} would be dropped, {len(keep)} kept. Re-run with --apply to write.")
        return 0

    p["required_status_checks"] = [{"context": c} for c in keep]
    body = {
        "name": rs["name"],
        "target": rs["target"],
        "enforcement": rs["enforcement"],
        "conditions": rs["conditions"],
        "rules": rs["rules"],
        "bypass_actors": rs.get("bypass_actors", []),
    }
    proc = subprocess.run(["gh", "api", "--method", "PUT", RULESET, "--input", "-"],
                          input=json.dumps(body), capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"PUT failed: {proc.stderr.strip()}", file=sys.stderr)
        return 1

    now = json.loads(subprocess.run(["gh", "api", RULESET],
                                    capture_output=True, text=True, check=True).stdout)
    live_now = sorted(c["context"] for r in now["rules"]
                      if r["type"] == "required_status_checks"
                      for c in r["parameters"]["required_status_checks"])
    if live_now != keep:
        print("POST-WRITE MISMATCH — re-read the ruleset by hand", file=sys.stderr)
        return 1
    print(f"\nOK: ruleset now requires {len(live_now)} contexts, all producible by {BASE}")
    print("Re-run `check_ci_gating.py --sync-ruleset` once the missing jobs land on main.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
