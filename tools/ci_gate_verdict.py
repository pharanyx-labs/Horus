#!/usr/bin/env python3
"""The verdict of the one required check: did every required CI job succeed?

The branch ruleset requires the `gates` job in ci.yml and (from its own
workflow) CodeQL's `analyze`, and nothing else. `gates` lists every required
ci.yml job under `needs:`, runs whatever they did (`if: always()`), and hands
this script `toJSON(needs)` in $NEEDS. `tools/check_ci_gating.py` proves the
`needs:` list is exactly `.github/ci-gating.yml`'s required jobs, so this script
does not re-derive the list: its whole job is the verdict.

WHY THE VERDICT IS "success", AND ONLY "success". A job's result is one of
success, failure, cancelled or skipped. The last two are how a required check
gets bypassed without ever going red: GitHub reports a SKIPPED check as
satisfying a required status, so an aggregator that only looked for "failure"
would pass a run in which a gate was skipped by an `if:`, never scheduled, or
cancelled by a newer push. Anything that is not an affirmative success is a
failure here, and so is anything this script does not recognise.

WHY THE NUMBER IS PRINTED. A green verdict over zero jobs is the vacuous pass
CLAUDE.md section 8 warns about: an empty or unparsable $NEEDS is refused, and
the count is in the log so a run can be read, not trusted.

Standard library only: this runs on a bare runner with nothing installed.
Exit status is 0 only when every listed job succeeded.
"""
import json
import os
import sys


def verdict(raw):
    """Return (ok, lines). `raw` is the JSON text of `toJSON(needs)`."""
    try:
        needs = json.loads(raw)
    except (TypeError, ValueError) as e:
        return False, [f"$NEEDS is not JSON ({e}); refusing to call that a pass"]
    if not isinstance(needs, dict) or not needs:
        return False, ["$NEEDS names no jobs; a verdict over nothing is not a pass"]

    lines, bad = [], []
    for jid in sorted(needs):
        entry = needs[jid]
        result = entry.get("result") if isinstance(entry, dict) else None
        lines.append(f"  {result!s:10} {jid}")
        if result != "success":
            bad.append((jid, result))

    if bad:
        lines.append("")
        lines.append(f"FAIL: {len(bad)} of {len(needs)} required jobs did not succeed:")
        for jid, result in bad:
            lines.append(f"  - {jid}: {result}")
        return False, lines
    lines.append("")
    lines.append(f"PASS: all {len(needs)} required jobs succeeded")
    return True, lines


def main():
    ok, lines = verdict(os.environ.get("NEEDS"))
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
