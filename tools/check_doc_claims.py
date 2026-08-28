#!/usr/bin/env python3
"""Fail the build when a document states a number the tree contradicts.

Every count written into a document in this repository has gone stale within
days. The 2026-08-19 audit found nine wrong across five files -- CI job counts,
context counts, the required set, the capability-suite check count -- while two
other files carried the same numbers correctly, which is the only reason anyone
noticed. CLAUDE.md has said "re-derive every number you cite" the whole time. A
rule only a reader enforces fails silently, and silence is what it failed with.

So the derivable claims are derived here and compared against every place that
states them (.github/doc-claims.yml), and the `doc-claims` CI job gates it.

Two checks, and the second is the one that catches prose:

  counts     -- a value computed from the source of truth, against every
                declared occurrence. A declared occurrence that MATCHES NOTHING
                is also an error: otherwise rewording a sentence would delete
                the check silently along with the claim, which is the failure
                mode in miniature.

  forbidden  -- text that was true once. Correcting a fact means adding its old
                phrasing here, so it cannot return in another file later. It is
                a ratchet, one line per correction.

                A match inside quotation marks or a markdown code span is
                ignored. This project's house style is to record the wrong thing
                when correcting it -- "this paragraph previously said X" -- and a
                blanket ban would forbid exactly the practice that makes a
                correction auditable. Quoted text is being reported, not
                asserted. Assert it and the ratchet bites; quote it and you are
                already doing the right thing.

Everything is derived statically. No network, no QEMU, no ruleset read -- the
ruleset comparison needs Administration:read and belongs to `ruleset-audit`.
`captest_checks` is counted out of the source rather than off the wire; the two
were verified equal (100) on 2026-08-19, and a boot to re-confirm it is what
`smoke-captest` already is.

Exit status is 0 only when every declared claim matches and no forbidden
phrasing appears.
"""
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("check_doc_claims: PyYAML is required (pip install pyyaml)")

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Reused rather than reimplemented: a second copy of the context-expansion rules
# would be one more thing to drift, and drift is the subject.
from check_ci_gating import load_jobs, WORKFLOWS, CI_YML, GATING_YML  # noqa: E402
from check_syscall_coverage import implemented  # noqa: E402

CLAIMS_YML = ".github/doc-claims.yml"
# The development log is a frozen record of what was written on the day it was
# written, which is the entire reason to keep it. Entries there assert things
# that were true then and are not now -- that IS the content -- so the ratchet
# must not scan it, for the same reason it already skips quoted text: the log
# is reporting a past state, not asserting a present one. Numeric claims are
# excluded from it too, by never declaring an occurrence in it.
HISTORICAL = "docs/history/"
MAKEFILE = "Makefile"
CAPTEST = "userspace/captest.c"
FRAMETEST = "userspace/frametest.c"


def _grep_count(path, pattern):
    return len([1 for line in Path(path).read_text().splitlines()
                if re.match(pattern, line)])


def _inside_quotes(line, idx):
    """True if `idx` falls inside a quoted span on this line.

    Both `"..."` and a markdown code span count. An odd number of the delimiter
    before the position means the match opened inside one.

    Backticks were added after this checker flagged its own documentation: the
    falsification table in TESTS.md names the retired phrasing in a code span,
    which is how markdown quotes a literal. A phrase inside a code span is being
    named, not asserted, exactly as a phrase inside quotation marks is.

    Deliberately naive: it does not track spans across lines, so a phrase quoted
    over a line break is still reported. Reporting one correction too many is
    the safe direction -- the cost is a pattern tightened by hand, and the
    alternative is a ratchet with a hole in it.
    """
    return (line.count('"', 0, idx) % 2 == 1
            or line.count("`", 0, idx) % 2 == 1)


SYSCALL_COVERAGE_YML = ".github/syscall-coverage.yml"


def _syscalls_implemented():
    """Entries in the dispatch table with a real handler, in the SHIP build.

    Imported rather than reimplemented. This was a second copy of the regex, and
    it inherited both of the original's blind spots: it read the table as flat
    text, so three entries that exist only under a defect arm or a selftest flag
    counted as shipped, and it matched only `[SYS_NAME]`, so seven entries
    written as bare numbers were invisible. Two copies of a derivation are two
    things to drift, and drift is this file's whole subject.
    """
    return len(implemented())


def derive():
    """Every value the manifest may refer to, computed from the tree."""
    jobs_by_wf = {wf: load_jobs(wf) for wf in WORKFLOWS}
    all_jobs = {jid: ctx for wf in WORKFLOWS for jid, ctx in jobs_by_wf[wf].items()}
    contexts = [c for ctxs in all_jobs.values() for c in ctxs]

    gating = yaml.safe_load(Path(GATING_YML).read_text())
    advisory_ids = set(gating.get("advisory") or {})
    advisory_ctx = [c for jid, ctxs in all_jobs.items() if jid in advisory_ids
                    for c in ctxs]

    return {
        "ci_jobs": len(jobs_by_wf[CI_YML]),
        "all_jobs": len(all_jobs),
        "contexts": len(contexts),
        "advisory": len(advisory_ctx),
        "required": len(contexts) - len(advisory_ctx),
        # ^smoke-<name>: in the Makefile. The inner target of a control arm is
        # deliberately NOT named smoke-* so it does not inflate this.
        "smoke_targets": _grep_count(MAKEFILE, r"smoke-[a-z0-9-]*:"),
        "control_arms": _grep_count(MAKEFILE, r"smoke-[a-z0-9-]*-control[a-z0-9-]*:"),
        # Base gates: every smoke-* target that is not a control arm. This is the
        # number a reader means by "integration targets that boot a kernel and
        # assert a marker" -- the control arms are the falsification OF those, and
        # counting them together conflates the two layers. Declared 2026-08-28
        # because site/index.html had said 68 since the count was 68, with nothing
        # to notice it becoming 88.
        "gates": (_grep_count(MAKEFILE, r"smoke-[a-z0-9-]*:")
                  - _grep_count(MAKEFILE, r"smoke-[a-z0-9-]*-control[a-z0-9-]*:")),
        "captest_checks": _grep_count(CAPTEST, r"\s*check\("),
        # frametest's parent-side checks. Declared 2026-08-27 because this exact
        # number had already gone stale: TESTS.md said 17 while the wire said 31.
        # Anchored to a line that STARTS with the call so the `static void
        # check(...)` definition is not counted -- a deriver that includes the
        # definition is off by one in a way nobody notices until the count is
        # used to decide something.
        "frametest_checks": _grep_count(FRAMETEST, r"^\s+check\("),
        # The DELEGATE's checks. Declared 2026-08-28 because SECURITY.md said 8
        # and TESTS.md said 5 against a live 9 -- two documents disagreeing with
        # each other and both with the tree, which is what an underived count
        # does when the test grows.
        "framepeer_checks": _grep_count(
            str(Path(__file__).resolve().parent.parent / "userspace/framepeer.c"),
            r"^\s+check\("),
        # Syscall handler-entry coverage. Both halves are derived rather than
        # written down, because both move whenever a syscall is added or a
        # workload starts covering one -- and a coverage number that has to be
        # edited by hand is a coverage number that will be wrong. The measured
        # count lives in .github/syscall-coverage.yml, which
        # tools/check_syscall_coverage.py has already proved equals the boot.
        # Every SYS_* number the ABI defines, implemented or not. Distinct from
        # syscalls_implemented (which evaluates the preprocessor for the SHIP
        # build): the difference between the two IS the fail-closed property the
        # public page describes, so both halves have to be derived or the
        # sentence can drift while still reading as consistent.
        "syscall_numbers": _grep_count(
            str(Path(__file__).resolve().parent.parent / "src/include/kernel.h"),
            r"^#define\s+SYS_[A-Z0-9_]+\s+\d+"),
        "syscalls_implemented": _syscalls_implemented(),
        "syscalls_covered": len(
            (yaml.safe_load(Path(SYSCALL_COVERAGE_YML).read_text()) or {}).get(
                "covered") or []),
        # The OTHER half of the same ratio, and the half that was not gated
        # until 2026-08-27. Every document that states "55 of 81" goes on to
        # say how many are left, and that second number was written by hand.
        # It was 25 in two files and 33 in a third -- three numbers for one
        # quantity, none of them right, and no gate could see any of them
        # because only the numerator was declared. A ratio is two claims.
        "syscalls_uncovered": len(
            (yaml.safe_load(Path(SYSCALL_COVERAGE_YML).read_text()) or {}).get(
                "uncovered") or {}),
    }


def main():
    claims = yaml.safe_load(Path(CLAIMS_YML).read_text())
    live = derive()
    problems = []
    checked = 0

    for claim in claims.get("counts") or []:
        cid, key = claim["id"], claim["derive"]
        if key not in live:
            problems.append(f"claim '{cid}' derives '{key}', which this script "
                            f"does not compute")
            continue
        want = live[key]
        for occ in claim["occurrences"]:
            path, pat = occ["file"], occ["pattern"]
            text = Path(path).read_text()
            found = re.findall(pat, text)
            if not found:
                problems.append(
                    f"{path}: claim '{cid}' is declared here but its pattern "
                    f"matches nothing. Either the sentence was reworded (update "
                    f"the pattern in {CLAIMS_YML}) or the claim was deleted "
                    f"(remove the occurrence).")
                continue
            for got in found:
                checked += 1
                if int(got) != want:
                    problems.append(
                        f"{path}: says {got} for {cid} ({claim['describe']}), "
                        f"live value is {want}")

    for rule in claims.get("forbidden") or []:
        pat = re.compile(rule["pattern"])
        for path in sorted(set(
                subprocess.run(["git", "ls-files", "*.md", "*.html", "*.yml"],
                               capture_output=True, text=True,
                               check=True).stdout.split())):
            if path in (CLAIMS_YML,) or path.startswith(HISTORICAL):
                continue
            try:
                text = Path(path).read_text()
            except (OSError, UnicodeDecodeError):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                for m in pat.finditer(line):
                    if _inside_quotes(line, m.start()):
                        continue
                    problems.append(
                        f"{path}:{n}: forbidden phrasing "
                        f"/{rule['pattern']}/ -- {' '.join(rule['reason'].split())}")
                    break

    print(f"derived values : " + ", ".join(f"{k}={v}" for k, v in sorted(live.items())))
    print(f"claims checked : {checked} numeric occurrences, "
          f"{len(claims.get('forbidden') or [])} forbidden phrasings")

    if problems:
        print("\nFAIL: the documentation and the tree disagree\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). The tree is the truth; fix the "
              f"document, or the pattern in {CLAIMS_YML} if the wording moved.")
        return 1

    print("\nPASS: every declared claim matches the tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
