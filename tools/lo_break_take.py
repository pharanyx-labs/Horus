#!/usr/bin/env python3
"""Break check_lock_order.py's TAKE regex, for arm 6 of its falsification suite.

A separate file rather than an inline sed, because the mutation has to survive
two levels of shell quoting and an earlier attempt silently edited the docstring
instead of the regex -- GNU sed reads `\\s` as whitespace. It asserts its anchor,
so a moved one fails the ARM loudly instead of leaving the checker unmodified and
the arm reporting NOT CAUGHT for an unrelated reason.
"""
import pathlib
import sys

p = pathlib.Path("tools/check_lock_order.py")
s = p.read_text()
anchor = 'TAKE = re.compile(r"\\bspin_lock'
if s.count(anchor) != 1:
    sys.exit(f"anchor appears {s.count(anchor)} times, expected 1")
p.write_text(s.replace(anchor, 'TAKE = re.compile(r"\\bNOPE_lock'))
