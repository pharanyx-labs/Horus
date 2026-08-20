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


def implemented():
    """Syscall names with a non-NULL handler in the dispatch table."""
    src = TABLE_SRC.read_text()
    start = src.index("static const syscall_desc_t syscall_table[")
    tbl = src[start:]
    tbl = tbl[: tbl.index("\n};")]
    out = []
    for name, handler in re.findall(
        r"\[\s*(SYS_[A-Z0-9_]+)\s*\]\s*=\s*\{\s*([A-Za-z0-9_]+)", tbl
    ):
        if handler not in ("0", "NULL"):
            out.append(name)
    return out


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
    num = numbers()
    impl = implemented()

    problems = []

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
