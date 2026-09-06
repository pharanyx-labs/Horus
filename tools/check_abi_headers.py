#!/usr/bin/env python3
"""Fail the build if the kernel and userspace disagree about the syscall ABI.

WHY THIS EXISTS. The syscall numbers and every struct that crosses the ring
boundary are written down TWICE -- once in `src/include/kernel.h` for the kernel
and once in `include/syscall.h` for ring 3 -- and until 2026-09-06 nothing
compared them. They agreed; that was a fact about the tree, not a property of it.

THIS IS S71's DEFECT CLASS. `struct audit_event` was declared twice under one
name, 256 bytes in the kernel and 72 in ring 3, and `h_read_audit` copied the
kernel's size at the kernel's stride into an array sized with the other: every
field misread, and 184 bytes past the array per record. The repair there was to
give that struct one declaration. Thirteen more structs are still in the shape
that produced it, and the numbers are too.

WHAT MAKES IT SILENT. A number that disagrees is usually loud -- the kernel's
dispatch table will not compile against a name it does not have. A STRUCT that
disagrees is not: both sides compile perfectly, `copy_to_user` writes the
kernel's `sizeof` into a buffer the caller sized with the other one, and the
overrun is discovered by whatever was unlucky enough to be next in `.bss`. So
the struct rule is the one that matters, and the number rule is here because a
list with one rule in it is a list somebody will assume is complete.

Two rules, each falsifiable on its own:

  1. every SYS_* number is defined in both headers with the same value
  2. every struct declared in both headers has the same field sequence
  3. every integer constant defined in both headers has the same value

Exit 0 if the two agree, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL = ROOT / "src" / "include" / "kernel.h"
USER = ROOT / "include" / "syscall.h"


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


def syscall_numbers(text):
    return dict(re.findall(r"^#define\s+(SYS_[A-Z0-9_]+)\s+(\d+)", text, re.M))


def int_defines(text):
    """{NAME: value} for every `#define NAME <integer>` at top level.

    Rule 3 exists because rule 2 compares field TEXT, and text can agree while
    layout does not: `mmio[IODEV_MAX_MMIO]` on both sides is identical prose and
    a different struct the moment one header's constant moves. This is the half
    of the array bound that rule 2 cannot see.
    """
    text = strip_comments(text)
    return dict(re.findall(r"^#define\s+([A-Z][A-Z0-9_]*)\s+(\d+)\s*$", text, re.M))


def structs(text):
    """{name: [normalised field, ...]} for every top-level `struct X { ... };`."""
    out = {}
    for m in re.finditer(r"^struct\s+(\w+)\s*\{", text, re.M):
        name = m.group(1)
        i = m.end() - 1
        depth = 0
        for j in range(i, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    body = text[i + 1:j]
                    break
        else:
            continue
        fields = []
        for decl in body.split(";"):
            decl = " ".join(strip_comments(decl).split())
            if decl:
                fields.append(decl)
        out[name] = fields
    return out


def main():
    ktext = KERNEL.read_text()
    utext = USER.read_text()
    problems = []

    # ---- rule 1: the numbers
    kn, un = syscall_numbers(ktext), syscall_numbers(utext)
    for name in sorted(set(kn) - set(un)):
        problems.append("%s is defined in kernel.h (%s) and not in syscall.h" % (name, kn[name]))
    for name in sorted(set(un) - set(kn)):
        problems.append("%s is defined in syscall.h (%s) and not in kernel.h" % (name, un[name]))
    for name in sorted(set(kn) & set(un)):
        if kn[name] != un[name]:
            problems.append("%s is %s in kernel.h and %s in syscall.h" % (name, kn[name], un[name]))

    # ---- rule 3: constants both headers define
    kd, ud = int_defines(ktext), int_defines(utext)
    for name in sorted(set(kd) & set(ud)):
        if kd[name] != ud[name]:
            problems.append("%s is %s in kernel.h and %s in syscall.h" % (name, kd[name], ud[name]))

    # ---- rule 2: the structs that cross the boundary
    ks, us = structs(strip_comments(ktext)), structs(strip_comments(utext))
    shared = sorted(set(ks) & set(us))
    for name in shared:
        if ks[name] != us[name]:
            problems.append(
                "struct %s differs between the headers:\n"
                "    kernel.h  : %s\n"
                "    syscall.h : %s" % (name, ks[name], us[name]))

    print("syscall numbers compared : %d" % len(set(kn) | set(un)))
    print("shared constants compared: %d" % len(set(kd) & set(ud)))
    print("shared structs compared  : %d" % len(shared))

    if problems:
        print("\nFAIL: the kernel and userspace disagree about the syscall ABI\n")
        for p in problems:
            print("  - %s" % p)
        print("\nBoth headers describe ONE interface. Where they differ, ring 3 and the")
        print("kernel are compiled against different layouts and copy_to_user writes one")
        print("into the other -- see SECURITY.md S71 for what that cost last time.")
        return 1

    print("\nPASS: the kernel and userspace agree on every number and shared struct")
    return 0


if __name__ == "__main__":
    sys.exit(main())
