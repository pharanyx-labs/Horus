#!/usr/bin/env python3
"""Fail the build if any syscall wrapper narrows a user pointer.

Issue #176: sys_dmesg() and sys_audit_digest() passed their buffer as
`(uint32_t)(unsigned long)ptr`. The argument registers are 64-bit, so the cast
was pure loss -- the kernel was handed the low 32 bits of an address the caller
never named, and then walked it in the caller's own address space.

It survived because of where the survivors live. USER_IMAGE_ASLR_BASE is 16 GiB
with 4 TiB of randomisation, so every static and global in every PIE image is
above 4 GiB by construction and always truncated, while a stack buffer sits
around 8 MiB and is never affected. Every caller in the tree passed a stack
buffer, and the two captest checks naming these syscalls both assert a
capability refusal -- which returns before the pointer is read. So a defect that
is 100% reproducible for a whole class of buffer was invisible to a 100-check
conformance suite.

A runtime gate catches it only for the syscalls a probe happens to call. This is
the check that covers ALL of them, including wrappers nothing calls yet: it is a
property of the source, so it is decided at build time.

Exit 0 if every pointer argument reaches the kernel full-width, 1 otherwise.
"""
import re
import sys
import pathlib

HEADER = pathlib.Path(__file__).resolve().parent.parent / "include" / "syscall.h"

# A pointer argument must reach syscall()/syscall6() either through
# SYSCALL_UPTR() or as an explicit 64-bit cast. Anything narrowing is a defect.
NARROWING = re.compile(r"\(\s*(?:uint32_t|unsigned int|int|uint16_t|uint8_t|long)\s*\)")
WRAPPER = re.compile(
    r"static\s+inline[^\n;]*?\b(sys_\w+)\s*\(([^)]*)\)\s*\{(.*?)\n\}", re.S
)
CALL = re.compile(r"syscall6?\s*\((.*?)\)\s*;", re.S)


def split_args(argstr):
    """Split a call's argument list on top-level commas only."""
    out, depth, cur = [], 0, ""
    for ch in argstr:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def main():
    src = HEADER.read_text()

    # The control arm deliberately reintroduces the defect; it must stay the
    # only narrowing definition, and it must be guarded.
    macro_bad = re.search(
        r"#ifdef\s+SYSCALL_PTR_TRUNC32\s*(?:/\*.*?\*/\s*)?#define\s+SYSCALL_UPTR", src, re.S
    )
    macro_good = re.search(
        r"#else\s*#define\s+SYSCALL_UPTR\(p\)\s*\(\(uint64_t\)\(uintptr_t\)\(p\)\)", src, re.S
    )
    problems = []
    if not macro_bad:
        problems.append(
            "SYSCALL_UPTR's narrowing definition is no longer guarded by "
            "#ifdef SYSCALL_PTR_TRUNC32 -- the control arm has become the default"
        )
    if not macro_good:
        problems.append(
            "SYSCALL_UPTR's default definition is not "
            "((uint64_t)(uintptr_t)(p)) -- the fix for #176 has been altered"
        )

    checked = 0
    for m in WRAPPER.finditer(src):
        name, params, body = m.group(1), m.group(2), m.group(3)
        ptr_vars = []
        for p in params.split(","):
            if "*" not in p:
                continue
            var = re.sub(r".*[\*\s](\w+)\s*$", r"\1", p.strip())
            if var:
                ptr_vars.append(var)
        if not ptr_vars:
            continue
        for call in CALL.finditer(body):
            for arg in split_args(call.group(1)):
                for var in ptr_vars:
                    if not re.search(r"\b" + re.escape(var) + r"\b", arg):
                        continue
                    checked += 1
                    a = " ".join(arg.split())
                    if "SYSCALL_UPTR" in a:
                        continue
                    if NARROWING.search(a):
                        problems.append(
                            f"{name}(): pointer `{var}` is narrowed on the way to "
                            f"the kernel -- `{a}`. Use SYSCALL_UPTR({var})."
                        )

    print(f"checked {checked} pointer arguments in {HEADER.name}")
    if problems:
        print("\nFAIL: a user pointer does not reach the kernel full-width\n")
        for p in problems:
            print(f"  - {p}")
        print(
            f"\n{len(problems)} problem(s). The argument registers are 64-bit; "
            "narrowing a pointer hands the kernel an address the caller never named."
        )
        return 1
    print("PASS: every pointer argument reaches the kernel full-width")
    return 0


if __name__ == "__main__":
    sys.exit(main())
