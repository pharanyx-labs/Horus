#!/usr/bin/env python3
"""Compare measured syscall handler-entry coverage against .github/syscall-coverage.yml.

Reads one or more serial logs from SYSCALL_COVERAGE=1 boots, extracts the
`SYSCOV <n>` lines the kernel emits on first entry into each handler body, and
diffs the union against the manifest.

Why "entered" and not "succeeded": see the header of the manifest. The short
version is that `captest` asserts capability REFUSALS, which return before the
handler runs, so a syscall can be named by the suite and have its body never
execute -- which is how issue #176 hid behind 100 passing checks.

Usage: check_syscall_coverage.py <serial.log> [<serial.log> ...]
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".github" / "syscall-coverage.yml"
TABLE_SRC = ROOT / "src" / "kernel" / "syscall.c"
NUM_SRC = ROOT / "src" / "include" / "kernel.h"


class TableError(Exception):
    """The dispatch table says something this deriver refuses to guess at."""


# The ship build defines none of the flags that guard a dispatch entry, and the
# three coverage workloads (SYSCALL_COVERAGE, +CAPTEST_SELFTEST, +COREUTILS_MODULES)
# define none of them either -- so the set of entries the measurement can possibly
# enter is the unguarded set. Passing a different set is how you would ask "what
# would a RAMFS_SLOT3_GATE build dispatch", which is a question about a defect arm
# rather than about the kernel that ships.
SHIP_MACROS = frozenset()

_ENTRY = re.compile(r"\[\s*([A-Za-z0-9_]+)\s*\]\s*=\s*\{\s*([A-Za-z0-9_]+)")
_IFDEF = re.compile(r"#\s*ifdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")
_IFNDEF = re.compile(r"#\s*ifndef\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")
_IF_DEFINED = re.compile(r"#\s*if\s+(!)?\s*defined\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$")


def _table_lines():
    src = TABLE_SRC.read_text()
    start = src.index("static const syscall_desc_t syscall_table[")
    tbl = src[start:]
    return tbl[: tbl.index("\n};")].splitlines()


def scan_table(defined=SHIP_MACROS):
    """Split the dispatch table into what this build compiles and what it does not.

    Returns (active, guarded): `active` maps syscall name -> handler for the
    entries that survive the preprocessor under `defined`; `guarded` maps name ->
    the flag that keeps it out.

    The preprocessor is EVALUATED rather than ignored. Reading the table as flat
    text counted every conditionally-compiled entry as shipped -- three of them
    (SYS_OPEN, SYS_PREEMPT_TRACE, SYS_IRQ_POLICY_INFO) exist only under a defect
    arm or a selftest flag -- so `implemented` described no build that has ever
    run. The manifest recorded that blind spot next to SYS_OPEN and named the
    wrong three, which is what an unenforced note is worth.

    Fails closed twice over. An `#if` form this does not understand raises rather
    than being assumed true, and a bare numeric index raises rather than being
    skipped: `[7]` used to mean five live handlers no coverage rule could name.
    """
    active, guarded = {}, {}
    # Each frame: (this branch compiles, the flag responsible, some branch has).
    stack = []
    for raw in _table_lines():
        line = raw.strip()
        if line.startswith("#"):
            m = _IFDEF.match(line)
            if m:
                stack.append((m.group(1) in defined, m.group(1)))
                continue
            m = _IFNDEF.match(line)
            if m:
                stack.append((m.group(1) not in defined, m.group(1)))
                continue
            m = _IF_DEFINED.match(line)
            if m:
                neg, flag = m.group(1), m.group(2)
                live = (flag in defined) if not neg else (flag not in defined)
                stack.append((live, flag))
                continue
            if re.match(r"#\s*else\s*$", line):
                if not stack:
                    raise TableError("#else with no open conditional")
                live, flag = stack[-1]
                stack[-1] = (not live, flag)
                continue
            if re.match(r"#\s*endif\b", line):
                if not stack:
                    raise TableError("#endif with no open conditional")
                stack.pop()
                continue
            raise TableError(
                f"unsupported preprocessor directive in the dispatch table: "
                f"{line!r} -- teach scan_table to evaluate it rather than "
                f"letting it be assumed true"
            )

        m = _ENTRY.match(line)
        if not m:
            continue
        index, handler = m.group(1), m.group(2)
        if handler in ("0", "NULL"):
            continue
        if index.isdigit():
            raise TableError(
                f"dispatch entry [{index}] is a bare number -- a syscall the "
                f"coverage manifest cannot name is one nothing can require "
                f"evidence for. Give it a SYS_ name in src/include/kernel.h"
            )
        live = all(x[0] for x in stack)
        if live:
            active[index] = handler
        else:
            guarded[index] = next(flag for ok, flag in reversed(stack) if not ok)
    if stack:
        raise TableError("unterminated conditional in the dispatch table")
    return active, guarded


def implemented(defined=SHIP_MACROS):
    """Syscall names with a real handler in the build described by `defined`."""
    return sorted(scan_table(defined)[0])


def numbers():
    hdr = NUM_SRC.read_text()
    return {
        m.group(1): int(m.group(2))
        for m in re.finditer(r"#define\s+(SYS_[A-Z0-9_]+)\s+(\d+)", hdr)
    }


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2

    seen = set()
    for path in argv[1:]:
        try:
            text = pathlib.Path(path).read_text(errors="replace")
        except OSError as exc:
            print(f"FAIL: cannot read serial log {path}: {exc}")
            return 1
        hits = re.findall(r"SYSCOV (\d+)", text)
        if not hits:
            # A log with no SYSCOV lines at all means the boot was not a
            # SYSCALL_COVERAGE build, or never got far enough to run one
            # syscall. Either way the union below would be silently short and
            # every `covered` entry would look like a regression -- so refuse
            # rather than report 43 spurious failures.
            print(f"FAIL: {path} contains no SYSCOV lines -- was it built with "
                  f"SYSCALL_COVERAGE=1, and did it boot?")
            return 1
        seen.update(int(h) for h in hits)

    man = yaml.safe_load(MANIFEST.read_text()) or {}
    declared_cov = list(man.get("covered") or [])
    declared_unc = dict(man.get("uncovered") or {})
    declared_cond = dict(man.get("conditional") or {})
    num = numbers()
    try:
        active, guarded = scan_table()
    except TableError as exc:
        print(f"FAIL: {exc}")
        return 1
    impl = sorted(active)

    problems = []

    # Guarded entries are not part of the build the measurement runs, so they
    # cannot be `covered` or `uncovered` -- but they must still be declared, or a
    # syscall could leave the ship build with nothing noticing. The flag is part
    # of the declaration: `conditional` naming the wrong one is how you would end
    # up believing a defect arm still gates something it no longer does.
    for n, flag in sorted(guarded.items()):
        if n in declared_cov or n in declared_unc:
            problems.append(
                f"{n} is compiled only under {flag}, so no tracked workload can "
                f"enter it -- declare it under `conditional`, not covered/uncovered"
            )
        elif n not in declared_cond:
            problems.append(
                f"{n} is compiled only under {flag} and is not declared under "
                f"`conditional` -- say so, with the flag and a reason"
            )
        elif str(declared_cond[n].get("flag")) != flag:
            problems.append(
                f"{n} is declared conditional on {declared_cond[n].get('flag')} "
                f"but the table guards it with {flag}"
            )

    for n, entry in sorted(declared_cond.items()):
        if n not in guarded:
            where = "unconditional in the ship build" if n in active else "absent"
            problems.append(
                f"{n} is declared conditional on {entry.get('flag')} but is "
                f"{where} -- a syscall that stopped being flag-guarded is a "
                f"change in shipped surface, not a documentation detail"
            )
        reason = entry.get("reason") if isinstance(entry, dict) else None
        if not reason or len(str(reason).split()) < 4:
            problems.append(f"{n} is conditional with no substantive reason")

    # A number on the wire that no active entry claims means the log came from a
    # build this derivation does not describe -- the measurement and the manifest
    # would then be talking about two different kernels.
    active_nums = {num[n] for n in impl if n in num}
    for got in sorted(seen - active_nums):
        problems.append(
            f"SYSCOV {got} was measured but no dispatch entry active in the ship "
            f"build has that number -- the serial log is from a different build"
        )

    dup = set(declared_cov) & set(declared_unc)
    for n in sorted(dup):
        problems.append(f"{n} is in both `covered` and `uncovered`")

    for n in sorted(impl):
        if n not in declared_cov and n not in declared_unc:
            problems.append(
                f"{n} has a handler but is in neither list -- decide whether a "
                f"tracked workload should enter it, and if not, write down why"
            )

    known = set(impl)
    for n in sorted(set(declared_cov) | set(declared_unc)):
        if n not in known:
            problems.append(
                f"{n} is listed but has no handler in the dispatch table"
            )

    for n in sorted(declared_cov):
        if n in num and num[n] not in seen:
            problems.append(
                f"{n} is declared covered but its handler never ran -- a tracked "
                f"workload stopped exercising it"
            )

    for n in sorted(declared_unc):
        if n in num and num[n] in seen:
            problems.append(
                f"{n} is declared uncovered but its handler DID run -- the reason "
                f"is stale; move it to `covered`"
            )

    for n, reason in sorted(declared_unc.items()):
        if not reason or len(str(reason).split()) < 4:
            problems.append(f"{n} is uncovered with no substantive reason")

    entered = sum(1 for n in impl if n in num and num[n] in seen)
    print(f"implemented syscalls      : {len(impl)}")
    print(f"flag-guarded (not shipped): {len(guarded)}")
    print(f"handler entered (measured): {entered}")
    print(f"declared covered          : {len(declared_cov)}")
    print(f"declared uncovered        : {len(declared_unc)}")

    if problems:
        print("\nFAIL: measured syscall coverage does not match the manifest\n")
        for p in problems:
            print(f"  - {p}")
        print(f"\n{len(problems)} problem(s). The tree is the truth; fix the "
              f"manifest, or the test that stopped covering a syscall.")
        return 1
    print("\nPASS: every implemented syscall is classified, and the measured "
          "coverage matches")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
