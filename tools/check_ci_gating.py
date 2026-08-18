#!/usr/bin/env python3
"""Assert every CI job is either merge-gating or exempted with a written reason.

Finding [C-6]: the required-status-check list lives in branch ruleset 19007209,
which no commit touches. So a job added to ci.yml lands in the advisory set by
default, and nothing asks whether it should have. That is how `smoke-captest` —
the named witness for eight of SECURITY.md's S-properties — sat advisory for
months, and how the two [I-10] durability gates landed advisory on the same day
the defect they witness was fixed.

This makes the classification a checked-in artifact (.github/ci-gating.yml) in
which every job must be listed explicitly, and fails the build when ci.yml and
that file disagree. There is deliberately NO default: defaulting is the bug.
It does not, and cannot, edit the ruleset: reading one needs Administration
permissions that the workflow GITHUB_TOKEN does not have. `--print-required`
emits the list to sync by hand, and `--check-ruleset` verifies it locally where a
maintainer token is available.

Exit status is 0 only when every job is classified and every advisory entry names
a real job and carries a reason.
"""
import argparse
import json
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit("check_ci_gating: PyYAML is required (pip install pyyaml)")

# Workflows whose jobs must all be classified. codeql.yml is included because
# CodeQL is a security gate: leaving it out of this mechanism would reproduce
# exactly the omission the mechanism exists to prevent. pages.yml is excluded
# deliberately -- it publishes the site on merge to main and does not run on
# pull requests, so it has no status to gate one with.
#
# ruleset-audit.yml is ALSO schedule-only and so, by the pages.yml reasoning
# alone, would be excluded too. It is included anyway, for a reason pages.yml
# does not have: it is the job that verifies this file against the live ruleset,
# and listing it here means deleting it cannot be quiet. An entry naming a job
# that no longer exists is an error, so removing the audit trips `ci-gating` on
# the next push. A security control that can be dropped without anything
# noticing is the shape of [C-6] itself.
WORKFLOWS = [".github/workflows/ci.yml", ".github/workflows/codeql.yml",
             ".github/workflows/ruleset-audit.yml"]
CI_YML = ".github/workflows/ci.yml"
GATING_YML = ".github/ci-gating.yml"
RULESET = "repos/pharanyx-labs/Horus/rulesets/19007209"


# GitHub truncates a check-run name to this many characters when it publishes it
# as a status-check context. Not documented in the REST reference; measured off
# the wire (a 105-char job name came back as 97 chars + "...").
CONTEXT_MAX = 100


def load_jobs(path):
    """Map job id -> list of status-check contexts it produces.

    A matrix job produces one context per combination, named by expanding the
    job's `name:` template. Only the single-key matrix form ci.yml actually uses
    is handled; anything more exotic is reported rather than guessed at, because
    silently mis-expanding a name would drop a real job out of the comparison.
    """
    doc = yaml.safe_load(open(path))
    out = {}
    for jid, spec in doc["jobs"].items():
        name = spec.get("name", jid)
        matrix = spec.get("strategy", {}).get("matrix", {})
        matrix = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
        if not matrix:
            out[jid] = [name]
            continue
        if len(matrix) != 1:
            sys.exit(f"check_ci_gating: job '{jid}' has a multi-key matrix; "
                     f"teach this script how to expand it rather than guessing")
        key, values = next(iter(matrix.items()))
        token = "${{ matrix." + key + " }}"
        if token not in name:
            sys.exit(f"check_ci_gating: job '{jid}' has matrix key '{key}' but its "
                     f"name does not interpolate it, so its contexts are not derivable")
        out[jid] = [name.replace(token, str(v)) for v in values]
    return out


def read_ruleset():
    raw = subprocess.run(["gh", "api", RULESET], capture_output=True,
                         text=True, check=True).stdout
    return json.loads(raw)


def sync_ruleset(want):
    """Write `want` into the ruleset's required_status_checks, changing nothing else.

    Everything but the context list is copied back verbatim, so enforcement,
    conditions and — importantly — bypass_actors survive the round trip. A PUT
    that dropped bypass_actors would silently alter who can push past the rules,
    which is a security change disguised as a CI change.
    """
    rs = read_ruleset()
    rule = next((r for r in rs["rules"]
                 if r["type"] == "required_status_checks"), None)
    if rule is None:
        print("ruleset has no required_status_checks rule", file=sys.stderr)
        return 1

    p = rule["parameters"]
    old = sorted(c["context"] for c in p["required_status_checks"])
    promotions = sorted(set(want) - set(old))
    demotions = sorted(set(old) - set(want))
    if not promotions and not demotions:
        print(f"ruleset already matches: {len(old)} required contexts")
        return 0

    print(f"required contexts: {len(old)} -> {len(want)}")
    print(f"strict policy    : {p.get('strict_required_status_checks_policy')}")
    print(f"bypass actors    : {len(rs.get('bypass_actors', []))} (preserved)")
    for c in promotions:
        print(f"  + {c}")
    for c in demotions:
        print(f"  - {c}")

    p["required_status_checks"] = [{"context": c} for c in want]
    body = {
        "name": rs["name"],
        "target": rs["target"],
        "enforcement": rs["enforcement"],
        "conditions": rs["conditions"],
        "rules": rs["rules"],
        "bypass_actors": rs.get("bypass_actors", []),
    }
    proc = subprocess.run(["gh", "api", "--method", "PUT", RULESET,
                           "--input", "-"],
                          input=json.dumps(body), capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"PUT failed: {proc.stderr.strip()}", file=sys.stderr)
        return 1

    live = sorted(c["context"] for r in read_ruleset()["rules"]
                  if r["type"] == "required_status_checks"
                  for c in r["parameters"]["required_status_checks"])
    if live != want:
        print(f"POST-WRITE MISMATCH: ruleset has {len(live)}, expected {len(want)}",
              file=sys.stderr)
        return 1
    print(f"\nOK: ruleset now requires {len(live)} contexts (verified by re-reading it)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--print-required", action="store_true",
                    help="print the required contexts, one per line, and exit")
    ap.add_argument("--check-ruleset", action="store_true",
                    help="also diff against the live ruleset (needs an admin gh token)")
    ap.add_argument("--sync-ruleset", action="store_true",
                    help="WRITE the required list into the ruleset (needs an admin "
                         "gh token). Prints the promotions and demotions first.")
    args = ap.parse_args()

    jobs = {}
    for wf in WORKFLOWS:
        for jid, contexts in load_jobs(wf).items():
            if jid in jobs:
                sys.exit(f"check_ci_gating: job id '{jid}' is defined in more than "
                         f"one workflow; ids must be unique across {WORKFLOWS}")
            jobs[jid] = contexts
    gating = yaml.safe_load(open(GATING_YML)) or {}
    advisory = gating.get("advisory") or {}
    required_ids = set(gating.get("required") or [])

    problems = []

    # The whole point: a job in NEITHER list is an unanswered gating question, and
    # answering it by default is what produced [C-6]. Adding a job to ci.yml must
    # therefore fail the build until someone classifies it.
    for jid in sorted(jobs):
        in_req, in_adv = jid in required_ids, jid in advisory
        if not in_req and not in_adv:
            problems.append(f"job '{jid}' is in neither list — decide whether it "
                            f"gates a merge, and if not, write down why")
        elif in_req and in_adv:
            problems.append(f"job '{jid}' is in both lists")

    # GitHub truncates a status-check context to 100 characters, and the ruleset
    # stores the context it actually SEES. A job name longer than that therefore
    # publishes one string and gets audited against another: this script would
    # report the full name as permanently "missing", and anyone resolving that by
    # pasting the full name into the ruleset would require a context no run can
    # ever produce -- every PR blocked forever on a check that cannot report.
    #
    # Found the day smoke-cr3-reclaim (104) and smoke-exec-reenter (105) became
    # the first two jobs to cross it, which is also exactly why they were the two
    # that could not be promoted. Checked here rather than left as folklore.
    for jid in sorted(jobs):
        for ctx in jobs[jid]:
            if len(ctx) > CONTEXT_MAX:
                problems.append(
                    f"job '{jid}' has a {len(ctx)}-character name; GitHub "
                    f"truncates a status-check context at {CONTEXT_MAX}, so the "
                    f"ruleset can never match it. Shorten the name.")

    # An entry naming a job that no longer exists is how this file would rot into
    # fiction, so it is an error rather than a warning.
    for jid in sorted(required_ids):
        if jid not in jobs:
            problems.append(f"required job '{jid}' is not defined in any workflow")
    for jid in sorted(advisory):
        if jid not in jobs:
            problems.append(f"advisory job '{jid}' is not defined in any workflow")
        reason = (advisory.get(jid) or "").strip()
        if len(reason) < 40:
            problems.append(f"advisory job '{jid}' has no substantive reason "
                            f"(got {len(reason)} chars; say why, with a finding id)")

    required, advisory_ctx = [], []
    for jid, contexts in sorted(jobs.items()):
        (advisory_ctx if jid in advisory else required).extend(contexts)

    if args.print_required:
        for c in sorted(required):
            print(c)
        return 0

    if args.sync_ruleset:
        if problems:
            print("refusing to sync: fix the classification first", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        return sync_ruleset(sorted(required))

    # What the summary below says about the ruleset. Stays "NOT READ" unless the
    # API call actually returned a required_status_checks rule, so a green log can
    # never imply a comparison that did not happen -- the point being that a run
    # which failed to read the ruleset must not look, at a glance, like one that
    # read it and found it correct. A failed read also lands in `problems` and
    # exits non-zero; this is about what the LOG says, not what the exit code does.
    ruleset_state = "NOT READ"

    if args.check_ruleset:
        try:
            raw = subprocess.run(["gh", "api", RULESET], capture_output=True,
                                 text=True, check=True).stdout
            rules = json.loads(raw)["rules"]
            live = None
            for r in rules:
                if r["type"] == "required_status_checks":
                    live = sorted(c["context"] for c in
                                  r["parameters"]["required_status_checks"])
            if live is None:
                problems.append("ruleset has no required_status_checks rule")
                ruleset_state = "no required_status_checks rule"
            else:
                missing = sorted(set(required) - set(live))
                extra = sorted(set(live) - set(required))
                for c in missing:
                    problems.append(f"ruleset is MISSING required context: {c}")
                for c in extra:
                    problems.append(f"ruleset requires a context this file does not: {c}")
                ruleset_state = (f"{len(live)} required contexts, matches"
                                 if not missing and not extra else
                                 f"{len(live)} required contexts, DIVERGED "
                                 f"({len(missing)} missing, {len(extra)} unexpected)")
        except subprocess.CalledProcessError as e:
            problems.append(f"could not read the ruleset: {e.stderr.strip()}")

    print(f"jobs across {len(WORKFLOWS)} workflows      : {len(jobs)}")
    print(f"status-check contexts      : {len(required) + len(advisory_ctx)}")
    print(f"  required (gating)        : {len(required)}")
    print(f"  advisory (with a reason) : {len(advisory_ctx)}")
    for jid in sorted(advisory):
        if jid in jobs:
            print(f"      - {jid}")
    if args.check_ruleset:
        print(f"live ruleset {RULESET.rsplit('/', 1)[-1]}      : {ruleset_state}")

    if problems:
        print("\nFAIL: CI gating is not fully classified\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(f"\nEvery job in {', '.join(WORKFLOWS)}\nmust be listed in {GATING_YML}: under "
              f"`required:`\nif it gates a merge, or under `advisory:` with the "
              f"reason it does not.\nThere is no default — defaulting is how "
              f"[C-6] happened.", file=sys.stderr)
        return 1

    print("\nPASS: every CI job is classified — merge-gating, or exempted with a reason")
    return 0


if __name__ == "__main__":
    sys.exit(main())
