#!/usr/bin/env python3
"""Every symbol the security core exports across the FFI must have a live caller.

WHY THIS EXISTS. `rust/src/` is the no_std security core, and `kernel.elf` links it
with `--whole-archive` and no `--gc-sections` (see the `kernel.elf` recipe in the
Makefile). Every `#[no_mangle] pub extern "C"` symbol is therefore IN THE SHIPPING
BINARY whether or not any C code calls it. Measured on 2026-09-10: 60 exports, and
TWELVE of them had no caller anywhere -- 20% of the security core's entry surface
existing for nobody.

They were not twelve scattered mistakes. They were three clusters:

  1. A Rust user-physical-page allocator `paging.c` never adopted --
     rust_alloc_user_physical_page, rust_free_user_physical_page, and
     rust_page_is_valid_user_phys (the third called only by the first two).
  2. A second, superseded audit chain -- rust_audit_chain_init,
     rust_audit_chain_record, rust_audit_entry_mac. `src/kernel/kaudit.c` uses the
     fs_* and pub_* chains; the chain_* trio was a parallel implementation of the
     tamper-evident chain (S19's subject) that nothing reached.
  3. Singles -- rust_cap_has_rights, rust_cap_revoke_by_values, rust_lineage_bump,
     rust_password_hash (a second password hash beside the live rust_argon2id_hash),
     rust_validate_fs_operation, rust_should_demand_zero.

AND EVERY ONE OF THEM HAD PASSING UNIT TESTS. That is why nobody noticed: the tests
made dead code look maintained. An `unsafe` FFI entry point with no caller is not
neutral under "least privilege by construction" -- its `# Safety` obligations name a
caller that does not exist, so nothing upholds them, and no Kani harness, fuzzer or
gate exercises it. This is the shape CLAUDE.md already records twice, as "a flag can
define a macro nothing reads" and "an arm can pass because it does nothing": from the
outside, an export nobody calls is indistinguishable from one that works.

THREE FALSE ANSWERS THIS CHECKER GAVE WHILE IT WAS BEING WRITTEN, each now an arm in
tools/test_check_ffi_deadsurface.sh, because each would have made it quietly wrong:

  * A `#[no_mangle]` separated from its `fn` by `#[allow(clippy::too_many_arguments)]`
    or a doc comment. The first regex demanded them adjacent and found 56 of 60 --
    it under-reported the very surface it exists to measure, silently. Four ELF
    functions were invisible to it.
  * `return rust_hmac_sha256(...);` read as a prototype declaration rather than a
    call, because the reference ends in `;` and `return` matches a return-type-shaped
    token. That made a symbol with three real callers in `src/kernel/storage.c` look
    dead -- a false positive that would have deleted live code.
  * A symbol named only in a COMMENT counted as a caller. `src/kernel/untyped.c`
    mentions rust_page_ref_dec in prose, and `src/kernel/capability.c` mentions
    rust_lineage_bump -- which is how rust_lineage_bump was recorded as "called once
    by capability.c" when its only reference there is a sentence.

A DECLARATION IS NOT A CALLER, and that distinction is the whole check. Seven of the
twelve were declared in `src/include/kernel.h` and called by nothing; a header
prototype is precisely the artefact that makes a dead export look wired up.

THE OTHER DIRECTION, because a compatibility shim can outlive its subject. C fallback
definitions in `src/kernel/rust_shims.c` (selected by RUST_EXTRA_OBJS for the no-Rust
build arm) are checked for the mirror defect: a `rust_*` function DEFINED there with
no Rust export and no caller is a fallback for a function that never existed.
rust_validate_ipc was exactly that.

Deliberate exceptions live in .github/ffi-exports.yml with a reason each, declared
rather than inferred -- the argument .github/gate-pairs.yml makes about intent. The
only one today is rust_eh_personality, which the Rust ABI requires and which
`src/kernel/rust_memory_stubs.c` defines on the C side.

Carries S86. Exit 0 if every export has a caller, 1 otherwise.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUST_SRC = ROOT / "rust" / "src"
ALLOW = ROOT / ".github" / "ffi-exports.yml"

# Files that DEFINE rust_* symbols for the C side rather than calling them: the
# no-Rust fallback arm and the stubs Rust's ABI requires. Selected by
# RUST_EXTRA_OBJS in the Makefile.
SHIM_FILES = {"src/kernel/rust_shims.c", "src/kernel/rust_memory_stubs.c"}

# `#[no_mangle]`, then any number of further attributes or doc comments, then the
# signature. The intervening-attribute case is not hypothetical: four ELF exports
# carry #[allow(clippy::too_many_arguments)] and a regex demanding adjacency finds
# 56 of 60 without saying so.
EXPORT = re.compile(
    r'#\[no_mangle\]\s*'
    r'(?:(?:#\[[^\]]*\]|///[^\n]*)\s*)*'
    r'pub\s+(?:unsafe\s+)?extern\s+"C"\s+fn\s+(\w+)')

REF = re.compile(r'\b(rust_\w+)\s*\(')

# Words that look like a return type but are not. Without `return`, a real call
# written `return rust_x(...);` is classified as a prototype and its callee is
# reported dead.
NOT_A_TYPE = {"return", "if", "while", "for", "switch", "sizeof",
              "case", "else", "do", "goto"}


def strip_comments(text):
    """Comments are prose, not code. A symbol named in one is not a caller."""
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def _call_end(text, open_paren):
    """Index just past the ')' matching the '(' at open_paren, or -1."""
    depth = 0
    i = open_paren
    while i < len(text):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def rust_exports():
    out = {}
    for path in sorted(RUST_SRC.rglob("*.rs")):
        for m in EXPORT.finditer(path.read_text()):
            out[m.group(1)] = path.relative_to(ROOT).as_posix()
    return out


def c_references():
    """Return (callers, declarations, shim_definitions), each sym -> {file}."""
    callers, decls, shims = {}, {}, {}
    for sub in ("src", "include"):
        base = ROOT / sub
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix not in (".c", ".h"):
                continue
            rel = path.relative_to(ROOT).as_posix()
            text = strip_comments(path.read_text(errors="replace"))
            for m in REF.finditer(text):
                sym = m.group(1)
                end = _call_end(text, m.end() - 1)
                if end < 0:
                    continue
                after = text[end:end + 40].lstrip()
                before = text[:m.start()][-60:]
                prev = re.search(r'([A-Za-z_]\w*)[\s*]+$', before)
                is_decl = (after.startswith(';') and prev is not None
                           and prev.group(1) not in NOT_A_TYPE)
                if rel in SHIM_FILES and after.startswith('{'):
                    shims.setdefault(sym, set()).add(rel)
                elif is_decl:
                    decls.setdefault(sym, set()).add(rel)
                else:
                    callers.setdefault(sym, set()).add(rel)
    return callers, decls, shims


def main():
    allow = yaml.safe_load(ALLOW.read_text()) if ALLOW.exists() else {}
    allowed = dict((allow or {}).get("exempt", {}) or {})

    exports = rust_exports()
    if not exports:
        print("FAIL: no `#[no_mangle] pub extern \"C\"` exports found in rust/src/.\n"
              "\nThe export pattern has stopped matching, so every rule below is\n"
              "vacuous. This is the self-check: a checker whose subject has moved\n"
              "reports a clean tree, which is the one answer it must never give.")
        return 1

    callers, decls, shims = c_references()

    dead = sorted(s for s in exports if s not in callers and s not in allowed)
    orphans = sorted(s for s in shims
                     if s not in exports and s not in callers and s not in allowed)

    print(f"rust exports        : {len(exports)}")
    print(f"with a live caller  : {len(exports) - len(dead) - len(allowed & exports.keys())}")
    print(f"exempted, by name   : {len(allowed)}")
    print(f"shim definitions    : {len(shims)}")

    if not dead and not orphans:
        print("\nPASS: every FFI export the security core ships has a live caller")
        return 0

    print()
    if dead:
        print("FAIL: the security core exports a symbol nothing calls\n")
        for sym in dead:
            where = "declared, never called" if sym in decls else "not even declared"
            print(f"  - {sym}  ({exports[sym]}) -- {where}")
    if orphans:
        print("\nFAIL: a C fallback defines a rust_* symbol that has no Rust export\n"
              "      and no caller -- a shim for a function that never existed\n")
        for sym in orphans:
            print(f"  - {sym}  ({', '.join(sorted(shims[sym]))})")
    print("\n`--whole-archive` with no `--gc-sections` puts every one of these in\n"
          "the shipping binary. An unsafe entry point whose `# Safety` clause names\n"
          "a caller that does not exist has nothing upholding it. Delete it, or\n"
          "declare it in .github/ffi-exports.yml with the reason it must stay.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
