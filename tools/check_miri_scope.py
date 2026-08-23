#!/usr/bin/env python3
"""Fail the build if a Rust test module is neither run under Miri nor excused.

Miri is the only check in this tree that looks for undefined behaviour, and the
`unsafe` it exists for is spread across four modules at the C FFI boundary. A new
module that quietly ends up outside its scope is the same failure as a Kani proof
nobody runs, or a CI job that lands advisory by default -- the check exists, and
simply does not look at the new thing.

Two rules:

  1. every module under rust/src that defines tests is either run by Miri or
     listed in `skip` with a substantive reason
  2. every `skip` entry names a module that exists and actually has tests
     (an entry that has rotted excuses nothing)

`--print-skip-args` emits the `--skip` flags for the test harness, so the CI job
derives its command from this manifest instead of repeating the list. The two
cannot drift if only one of them exists.

Exit 0 if sound, 1 otherwise.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".github" / "miri-scope.yml"
SRC = ROOT / "rust" / "src"


def modules_with_tests():
    found = {}
    for f in sorted(SRC.glob("*.rs")):
        n = len(re.findall(r"#\[test\]", f.read_text()))
        if n:
            found[f.stem] = n
    return found


def main(argv):
    man = yaml.safe_load(MANIFEST.read_text()) or {}
    skip = dict(man.get("skip") or {})

    if "--print-skip-args" in argv:
        # `lib` is the crate root; its tests are named without a module prefix,
        # so a `--skip lib::` would match nothing. Every other module's tests are
        # `<module>::tests::<name>`.
        print(" ".join(f"--skip {m}::" for m in sorted(skip)))
        return 0

    found = modules_with_tests()
    problems = []

    for m, reason in sorted(skip.items()):
        if m not in found:
            problems.append(
                f"{m}: listed in `skip` but rust/src/{m}.rs has no tests (or does "
                f"not exist) -- the entry has rotted"
            )
        if not reason or len(str(reason).split()) < 8:
            problems.append(f"{m}: skipped from Miri with no substantive reason")

    run = sorted(set(found) - set(skip))
    print(f"test modules in rust/src : {len(found)}")
    print(f"  run under Miri         : {len(run)} ({', '.join(run)})")
    print(f"  skipped (with a reason): {len(skip)} ({', '.join(sorted(skip))})")

    if problems:
        print("\nFAIL: the Miri scope and the crate disagree\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nPASS: every test module is run under Miri or excused with a reason")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
