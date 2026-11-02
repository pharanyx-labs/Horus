#!/usr/bin/env python3
"""The Clang nightly links the kernel, and a missing compiler fails it.

The workflow is schedule and workflow_dispatch only. It must run
`make CLANG=1 kernel.elf` and require a non-empty `kernel.elf`. A
`continue-on-error`, a `|| true`, or a Clang switch that leaves the
compiler as GCC is a refusal.

Success prints `clang-nightly: ok`.
"""

import sys
from pathlib import Path

WORKFLOW = Path(".github/workflows/clang-nightly.yml")
MAKEFILE = Path("Makefile")
NEEDLES = (
    "command -v clang",
    "rustup target add x86_64-unknown-none",
    "make CLANG=1 kernel.elf",
    "test -s kernel.elf",
    "set -euo pipefail",
    "workflow_dispatch:",
    "schedule:",
)


def fail(msg):
    print(f"clang-nightly: {msg}")
    return 1


def main():
    try:
        text = WORKFLOW.read_text(encoding="utf-8")
    except OSError:
        return fail("cannot read .github/workflows/clang-nightly.yml")
    try:
        makefile = MAKEFILE.read_text(encoding="utf-8")
    except OSError:
        return fail("cannot read Makefile")
    if "pull_request:" in text:
        return fail("runs on a pull request")
    if "continue-on-error" in text:
        return fail("continue-on-error would hide a missing compiler")
    if "|| true" in text or "||true" in text:
        return fail("a swallowed failure would hide a missing compiler")
    for needle in NEEDLES:
        if needle not in text:
            return fail(f"lost {needle}")
    if "ifeq ($(CLANG),1)" not in makefile:
        return fail("Makefile has no CLANG switch")
    if "CC     = clang" not in makefile or "AS     = clang" not in makefile:
        return fail("CLANG=1 does not select clang")
    # The call-graph report is GCC-only. The Clang branch must not pass it.
    clang_arm = makefile.split("ifeq ($(CLANG),1)", 2)
    if len(clang_arm) < 2:
        return fail("Makefile has no CLANG switch")
    # The first switch selects the compiler. The flag switch is the second.
    if makefile.count("ifeq ($(CLANG),1)") < 2:
        return fail("Makefile does not split the Clang report flags")
    flag_arm = makefile.split("ifeq ($(CLANG),1)")[2]
    else_at = flag_arm.find("else")
    if else_at < 0:
        return fail("the Clang flag switch has no GCC branch")
    clang_flags = flag_arm[:else_at]
    if "-fcallgraph-info" in clang_flags:
        return fail("Clang is asked for a GCC call-graph report")
    if "-fstack-usage" not in clang_flags:
        return fail("Clang build dropped -fstack-usage")
    print("clang-nightly: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
