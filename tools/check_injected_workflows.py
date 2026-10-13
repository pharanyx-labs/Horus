#!/usr/bin/env python3
"""Fail when GitHub runs a workflow on this repository that the tree does not account for.

docs/LIMITATIONS.md 5.7: tools/check_ci_gating.py sees .github/workflows/, and
GitHub can also inject DYNAMIC workflows (paths under `dynamic/`) that no commit
contains. One did, from 2026-09-19 to 2026-09-20. This reads the live list and
holds it to .github/injected-workflows.yml:

  1. every workflow GitHub reports is a file in .github/workflows/ or an entry
     in the record;
  2. an entry with `may_run: false` has no run after its `last_run`;
  3. every entry is one GitHub still reports.

    tools/check_injected_workflows.py                 # live, through `gh api`
    tools/check_injected_workflows.py --state FILE    # a recorded state (the harness)

The live mode needs a token that may read the repository's Actions metadata:
the maintainer's `gh` login locally, or `actions: read` on the scheduled job's
token. Without one it FAILS: a check that cannot see the list has checked
nothing, and saying PASS would be the defect this repository keeps finding in
checkers that went quiet.

A state file is JSON: {"workflows": [{"path": ..., "state": ...}],
"latest_runs": {path: ISO time or null}}, the shape the live mode builds.
"""
import argparse
import json
import os
import subprocess
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("FAIL: PyYAML is required (pip install pyyaml)")
    sys.exit(2)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
RECORD = os.path.join(ROOT, ".github", "injected-workflows.yml")
REPO = os.environ.get("GITHUB_REPOSITORY", "pharanyx-labs/Horus")


def gh_json(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh api {path}: {out.stderr.strip() or 'failed'}")
    return json.loads(out.stdout)


def live_state():
    """The workflows GitHub reports, and the latest run of each dynamic one."""
    wf = gh_json(f"repos/{REPO}/actions/workflows?per_page=100")
    workflows = [{"path": w["path"], "state": w["state"], "id": w["id"]}
                 for w in wf.get("workflows", [])]
    if wf.get("total_count", len(workflows)) != len(workflows):
        raise RuntimeError("more workflows than one page; the list would be partial")
    latest = {}
    for w in workflows:
        if w["path"].startswith(".github/workflows/"):
            continue
        runs = gh_json(f"repos/{REPO}/actions/workflows/{w['id']}/runs?per_page=1")
        r = runs.get("workflow_runs") or []
        latest[w["path"]] = r[0]["created_at"] if r else None
    return {"workflows": workflows, "latest_runs": latest}


def check(state, record):
    problems = []
    injected = (record or {}).get("injected") or {}
    reported = {w["path"] for w in state.get("workflows", [])}
    if not reported:
        problems.append("GitHub reported no workflows at all; the list is empty, not clean")

    # 1. Accounted for: a file in the tree, or a recorded decision.
    for path in sorted(reported):
        if path.startswith(".github/workflows/"):
            if not os.path.isfile(os.path.join(ROOT, path)):
                problems.append(f"{path} is reported by GitHub but is not in the tree")
        elif path not in injected:
            problems.append(f"{path} is a workflow GitHub runs that no commit contains and "
                            f".github/injected-workflows.yml does not record")

    # 2. Stopped means stopped.
    for path, entry in sorted(injected.items()):
        entry = entry or {}
        if not entry.get("reason"):
            problems.append(f"{path}: the record gives no reason for it")
        if entry.get("may_run") is False:
            last = entry.get("last_run")
            if not last:
                problems.append(f"{path}: may_run is false and no last_run is recorded to hold it to")
                continue
            ran = (state.get("latest_runs") or {}).get(path)
            # ISO 8601 UTC strings of one shape compare correctly as text.
            if ran and str(ran) > str(last):
                problems.append(f"{path} ran at {ran}, after its recorded last run {last}: "
                                f"a workflow the project stopped has started again")
        elif entry.get("may_run") is not True:
            problems.append(f"{path}: may_run must be true or false")

    # 3. No stale entries.
    for path in sorted(injected):
        if path not in reported:
            problems.append(f"{path} is recorded in .github/injected-workflows.yml but GitHub "
                            f"no longer reports it; remove the entry")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", help="a recorded state (JSON) instead of the live list")
    ap.add_argument("--record", default=RECORD, help=argparse.SUPPRESS)
    a = ap.parse_args()

    with open(a.record) as f:
        record = yaml.safe_load(f)
    try:
        if a.state:
            with open(a.state) as f:
                state = json.load(f)
        else:
            state = live_state()
    except (RuntimeError, OSError, ValueError) as e:
        print(f"FAIL: could not read the workflow list: {e}")
        print("  This needs a token that may read Actions metadata; without the list,"
              " nothing was checked.")
        return 1

    problems = check(state, record)
    n = len(state.get("workflows", []))
    if problems:
        print("FAIL: check_injected_workflows")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"PASS: all {n} workflows GitHub runs are in the tree or recorded, and none "
          f"recorded as stopped has run again")
    return 0


if __name__ == "__main__":
    sys.exit(main())
