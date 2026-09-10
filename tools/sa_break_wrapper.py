#!/usr/bin/env python3
"""Break check_syscall_abi.py's WRAPPER regex, for arm 4 of its suite.

A standalone file rather than an inline mutation, because the anchor contains
quotes and parentheses that do not survive two levels of shell quoting -- an
earlier attempt produced a shell syntax error inside the arm, which reads like a
broken harness rather than a result. It asserts its anchor, so a moved one fails
the ARM loudly instead of leaving the checker unmodified and the arm reporting
NOT CAUGHT for an unrelated reason.
"""
import pathlib
import sys

p = pathlib.Path("tools/check_syscall_abi.py")
s = p.read_text()
anchor = "WRAPPER = re.compile("
if s.count(anchor) != 1:
    sys.exit(f"anchor appears {s.count(anchor)} times, expected 1")
p.write_text(s.replace(anchor, "WRAPPER = re.compile(chr(0)) or re.compile(", 1))
