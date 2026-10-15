#!/usr/bin/env python3
"""Fail the build if a capability export of the security core has no Kani proof
(ROADMAP 3.5).

THE GAP THIS CLOSES. The capability algebra is proved function by function in
rust/src/capability.rs, and on 2026-10-14 four of its ten `rust_cap_*` exports
had no harness at all: `rust_cap_alloc_serial`, `rust_cap_transfer`,
`rust_cap_grant_from_user` and `rust_cap_revoke`. Each is reached from C on a
live path (the kernel's own derivations, SYS_CAP_TRANSFER, SYS_CAP_GRANT, a move
and the revocation helper), so each was trusted on the strength of the proofs
of its neighbours. tools/check_kani_harnesses.py checks that every proof gates a
merge; nothing checked that every export HAD a proof.

WHAT IT CHECKS:

  R1  every `#[no_mangle] pub ... extern "C" fn rust_cap_*` or `rust_ipc_*` in
      rust/src/capability.rs is called by name from inside its `kani_proofs`
      module, i.e. from some harness.
  R2  the module exists and holds at least one `#[kani::proof]`, so a renamed or
      deleted module cannot make every export look covered by matching nothing.
  R3  at least MIN_EXPORTS exports were found, so a regex that silently stops
      matching cannot report a clean tree.

Exit 0 if every export is proved, 1 otherwise.
"""
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(os.environ.get("KANI_FFI_ROOT") or pathlib.Path(__file__).resolve().parent.parent)
SRC = ROOT / "rust" / "src" / "capability.rs"
MIN_EXPORTS = 12

EXPORT = re.compile(r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(rust_(?:cap|ipc)_\w+)\s*\(')


def main():
    text = SRC.read_text()
    errs = []
    m = re.search(r"\nmod kani_proofs\s*\{", text)
    if not m:
        print("FAIL: check_kani_ffi")
        print("  - R2 rust/src/capability.rs has no `mod kani_proofs`")
        return 1
    module = text[m.end():]
    body = text[:m.start()]
    if "#[kani::proof]" not in module:
        errs.append("R2 the kani_proofs module holds no #[kani::proof]")
    exports = sorted(set(EXPORT.findall(body)))
    if len(exports) < MIN_EXPORTS:
        errs.append("R3 found %d capability exports, expected at least %d: the pattern has "
                    "stopped matching" % (len(exports), MIN_EXPORTS))
    for name in exports:
        if not re.search(r"\b%s\s*\(" % re.escape(name), module):
            errs.append("R1 %s is exported to C and no Kani harness calls it: prove it" % name)
    print("capability exports: %d, every one called from a harness: %s"
          % (len(exports), "no" if any(e.startswith("R1") for e in errs) else "yes"))
    if errs:
        print("FAIL: check_kani_ffi")
        for e in errs:
            print("  - " + e)
        return 1
    print("PASS: every capability export of the security core has a Kani proof")
    return 0


if __name__ == "__main__":
    sys.exit(main())
