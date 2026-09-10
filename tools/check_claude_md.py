#!/usr/bin/env python3
"""Check that CLAUDE.md's references still resolve: targets, paths, flags, symbols.

WHY THIS EXISTS. CLAUDE.md is the operating manual every session reads first, and
it is **gitignored and untracked** -- so no CI job, no reviewer and no other
checker in this tree has ever seen it. It went stale exactly the way an unchecked
document goes stale: on 2026-09-10 it still described two defect flags as having
"no gate, deliberately" hours after both were gated, and three of its
line-number references pointed at unrelated code.

IT IS DEVELOPER-LOCAL BY DESIGN, AND IT IS NOT A CI JOB. The file it checks is
not in the repository, so in CI this would be a check that cannot fail -- which
this project does not ship. It exits 0 with a note when CLAUDE.md is absent, and
it earns its place in the local pre-commit sweep (`for f in tools/check_*.py`)
where the file does exist. Do not add it to .github/workflows.

WHAT IT CHECKS. Only references, not prose:

  1. every `make X` names a real Makefile target
  2. every path in a code span exists (by full path, or by basename in prose)
  3. every ALL_CAPS knob in a code span is a real build flag or Makefile variable
  4. every symbol or comment the file names is still in the file it names it in
  5. no line-number citations at all -- CLAUDE.md's own rule, because a line
     number is the reference that goes stale silently while still looking right

Rule 4 matches on a WORD BOUNDARY rather than a substring. Renaming `foo` to
`foo_RENAMED` leaves `foo` in the file, so a substring test passes over exactly
the mutation it exists to catch; the self-test's arm reported NOT CAUGHT until
this was fixed.

Exit 0 if every reference resolves, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "CLAUDE.md"
MAKEFILE = ROOT / "Makefile"

# ALL_CAPS tokens that are neither defect flags nor Makefile variables: harness
# environment knobs and the one English word this file spells in caps.
KNOWN_KNOBS = {
    "SMOKE_TIMEOUT", "STRESS_RUNS", "SESSION_DISK_IOPS", "SESSION_DISK_BPS",
    "SESSION_SERIAL_LOG", "SOURCE_DATE_EPOCH", "DEFECT_FLAGS", "SYSCALL_TABLE_SIZE",
    "DIRTY",
}

# Symbols and comments the file names in prose, and where each must still live.
# A rename that misses one of these leaves the manual pointing at nothing.
NAMED = (
    ("current_user_is_admin", "src/kernel/kusers.c"),
    ("cap_install_object", "src/kernel/capability.c"),
    ("rust_cap_lookup", "src/kernel/capability.c"),
    ("scheduler_init", "src/kernel/scheduler.c"),
    ("WHY THIS DID NOT WORK IN JULY", "src/kernel/scheduler.c"),
    ("_Static_assert(SYSCALL_TABLE_SIZE", "src/kernel/syscall.c"),
)

# Files CLAUDE.md tells the reader to run or read. Named here rather than parsed
# out of the prose, because "the file says to run X" is the claim being checked.
REFERENCED = (
    ".github/gate-pairs.yml", ".github/gate-exceptions.yml", ".github/doc-claims.yml",
    ".github/CODEOWNERS", ".github/workflows/pages.yml", ".claude/settings.json",
    "tools/graph_refresh.sh", "tools/ffi_edges.py", "tools/check_base_gate_reddens.sh",
    "tools/check_split_markers.py", "tools/check_gate_pairs.py", "tools/check_defect_flags.py",
    "tools/check_doc_claims.py", "tools/check_ci_gating.py", "tools/stress_boot.sh",
    "tools/test_security_gates.sh", "tools/session_test.py", "tools/installer_session.py",
    "docs/BUILDING.md", "docs/LIMITATIONS.md", "TESTS.md", "SECURITY.md", "site/index.html",
)

PATH_SPAN = re.compile(r"`([A-Za-z0-9_./-]+\.(?:c|h|rs|py|sh|md|yml|html|toml|json))`")
KNOB_SPAN = re.compile(r"`([A-Z][A-Z0-9_]{3,})(?:=[^`]*)?`")
LINE_CITE = re.compile(r"[A-Za-z0-9_./-]+\.(?:c|h|rs|py|sh|md|yml|html):\d+")


def defect_flags(mk: str) -> set:
    m = re.search(r"^DEFECT_FLAGS\s*=\s*((?:.*\\\n)*.*)$", mk, re.M)
    if not m:
        return set()
    return set(re.findall(r"[A-Z][A-Z0-9_]+", m.group(1).replace("\\\n", " ")))


def main() -> int:
    if not DOC.exists():
        print("SKIP: no CLAUDE.md in this working tree (it is gitignored, so a")
        print("      fresh clone has none). Nothing to check.")
        return 0

    text = DOC.read_text(encoding="utf-8")
    mk = MAKEFILE.read_text(encoding="utf-8")
    targets = set(re.findall(r"^([A-Za-z0-9_.-]+):", mk, re.M))
    flags = defect_flags(mk)
    problems = []

    # 1. make targets, only where the file actually tells you to run one: inside
    #    a code span or a fenced bash block. "make a build pass" is prose.
    spans = re.findall(r"`([^`\n]+)`", text)
    fenced = "\n".join(re.findall(r"```bash\n(.*?)```", text, re.S)).split("\n")
    seen = set()
    for chunk in spans + fenced:
        for m in re.finditer(r"\bmake ([a-z0-9][a-z0-9-]*)", chunk):
            t = m.group(1)
            seen.add(t)
            if t != "help" and t not in targets:
                problems.append(f"names `make {t}`, which is not a Makefile target")

    # 2. paths
    for m in PATH_SPAN.finditer(text):
        p = m.group(1)
        if (ROOT / p).exists():
            continue
        if "/" not in p and list(ROOT.rglob(p)):
            continue                      # named by basename in prose
        problems.append(f"names `{p}`, which does not exist")

    # 3. build knobs
    for m in KNOB_SPAN.finditer(text):
        f = m.group(1)
        if (f in KNOWN_KNOBS or f in flags
                or f.startswith(("SYS_", "CAP_"))
                or re.fullmatch(r"[0-9A-F]{8,}", f)
                or re.search(rf"^{f}\s*[:?+]?=", mk, re.M)):
            continue
        problems.append(f"names `{f}`, which is not a build flag or a Makefile variable")

    # 4. symbols
    for sym, where in NAMED:
        target = ROOT / where
        if not target.exists():
            problems.append(f"names {where}, which does not exist")
            continue
        pat = re.escape(sym) + (r"\b" if sym.isidentifier() else "")
        if not re.search(pat, target.read_text(encoding="utf-8")):
            problems.append(f"names `{sym}`, which is no longer in {where}")

    # 5. files it tells you to run or read
    for p in REFERENCED:
        if not (ROOT / p).exists():
            problems.append(f"tells the reader to use {p}, which does not exist")

    # 6. its own rule about line numbers
    for m in LINE_CITE.finditer(text):
        problems.append(f"cites a line number ({m.group(0)}), which CLAUDE.md forbids: "
                        f"name the symbol or the heading instead")

    print(f"make targets referenced : {len(seen)}")
    print(f"paths referenced        : {len(set(PATH_SPAN.findall(text)))}")
    print(f"symbols pinned          : {len(NAMED)}")

    if problems:
        print()
        print("FAIL: CLAUDE.md refers to something that is no longer there")
        print()
        for p in sorted(set(problems)):
            print(f"  - {p}")
        print()
        print("CLAUDE.md is the file every session reads first and the only one no")
        print("CI job can see. Fix the reference, or the thing it names.")
        return 1

    print()
    print("PASS: every reference CLAUDE.md makes still resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
