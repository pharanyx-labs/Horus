#!/usr/bin/env python3
"""Fail the build if a gate-asserted marker is emitted in more than one write.

THE HAZARD. The serial console is shared by every ring-3 task and by the kernel.
A marker printed as `out("X: FAIL "); out(detail);` is two writes, so another
task's output can land between them and split the exact string a gate asserts
on. The gate then times out looking for something that WAS printed, in pieces --
which reports an infrastructure failure for a run where the defect reproduced
perfectly. That is the worst way for a check to be wrong: it is indistinguishable
from a broken runner, and the natural response is to re-run it.

WHY THIS IS A CHECKER AND NOT A SWEEP. It has been swept by hand once, on
2026-08-31, after `smoke-init-provision-control` failed on a split marker. That
sweep found ten instances, fixed all ten, and `docs/LIMITATIONS.md` 2.6a recorded
the limitation as closed with the note that "the property is enforced
structurally instead". It was not: nothing enforced it, and the sweep had missed
at least two.

It missed `userspace/captest.c` because it searched for the shape it had just
fixed -- `report(prefix); report(detail);` over `libhorus`'s helpers -- and
captest has a private `out()` and does not include `libhorus.h` at all. Ten
`smoke-captest-*-control` arms assert a contiguous `CAPTEST: FAIL <detail>`, so
every one of them was one unlucky interleave from a spurious red.

It stayed invisible for a day because the captest image had exactly one ring-3
writer. `auditprobe` joined it on 2026-09-01 (S71) and CI reddened on the next
PR with the marker split across two lines. A latent defect and a second writer
are the same defect; only one of them is observable.

WHAT IT CHECKS. For every consecutive run of single-write console calls, if the
first call's string literal is a strict prefix of a marker some gate asserts as
one contiguous string, that is a split marker and the build fails. Gate markers
are read from the Makefile's REQUIRE_MARKER / FAIL_MARKER / ABSENT_MARKER /
EXPECT_STALL and from the marker literals in tools/*.py.

WHAT IT DELIBERATELY DOES NOT CHECK. Informational output that no gate asserts:
splitting `[tpm] sealed blob pub=... priv=...` costs a reader nothing and
rewriting all 42 such sites would be churn with no property behind it. The rule
is not "never write twice", it is "never emit a GATED marker in pieces".

Exit 0 if every gate-asserted marker is a single write, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# One call == one write to the shared console.
EMIT = r"(?:out|kput|print|println|report|con_write|sys_write|kfault_str)\s*\("
EMIT_LINE = re.compile(r"^\s*(?:" + EMIT + r")")
LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')

# Allowed: a site may be excused only with a written reason.
EXEMPT = {
    # (path, first-literal) -> reason
}


def gate_markers():
    """Every string a gate requires to appear contiguously on the wire."""
    markers = set()
    mk = (ROOT / "Makefile").read_text(errors="ignore")
    for m in re.finditer(
        r"(?:REQUIRE_MARKER|FAIL_MARKER|ABSENT_MARKER|EXPECT_STALL)=(['\"])(.+?)\1", mk
    ):
        markers.add(m.group(2))
    for p in (ROOT / "tools").glob("*.py"):
        if p.name == pathlib.Path(__file__).name:
            continue
        t = p.read_text(errors="ignore")
        for m in re.finditer(
            r"['\"]([A-Z][A-Z0-9_]+(?:TEST|PROBE|SELFTEST|TRACE|CACHE)?: [^'\"]{4,})['\"]", t
        ):
            markers.add(m.group(1))
    return markers


def emit_runs(path):
    """Consecutive single-write console calls, as (line_no, [statements])."""
    lines = path.read_text(errors="ignore").split("\n")
    runs, cur = [], []
    for i, ln in enumerate(lines, 1):
        if EMIT_LINE.match(ln) and ln.rstrip().endswith(";"):
            cur.append((i, ln.strip()))
        else:
            if len(cur) >= 2:
                runs.append(cur)
            cur = []
    if len(cur) >= 2:
        runs.append(cur)
    return runs


def main():
    markers = gate_markers()
    sources = []
    for root in ("userspace", "src/kernel"):
        for p in sorted((ROOT / root).rglob("*.c")):
            if "ports/" in str(p):          # vendored third-party
                continue
            sources.append(p)

    problems = []
    runs_seen = 0
    for p in sources:
        rel = p.relative_to(ROOT)
        for run in emit_runs(p):
            runs_seen += 1
            lits = LITERAL.findall(run[0][1])
            if not lits:
                continue
            first = lits[0].replace("\\n", "\n")
            if len(first) < 6:
                continue
            for mkr in markers:
                if mkr.startswith(first) and mkr != first.rstrip():
                    if (str(rel), first) in EXEMPT:
                        break
                    problems.append(
                        f"{rel}:{run[0][0]} emits {first!r} and then continues in "
                        f"{len(run) - 1} more write(s); a gate asserts "
                        f"{mkr!r} as one contiguous string"
                    )
                    break

    print(f"gate-asserted markers   : {len(markers)}")
    print(f"multi-write console runs: {runs_seen}")

    if problems:
        print("\nFAIL: a gated marker is emitted in more than one write\n")
        for pr in problems:
            print(f"  - {pr}")
        print(
            "\nAnother task's output can land between the writes and split the "
            "string.\nBuild the marker as one string and write it once "
            "(libhorus has kput_marker()).\nSee docs/LIMITATIONS.md 2.6a."
        )
        return 1

    print("\nPASS: every gate-asserted marker reaches the console in one write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
