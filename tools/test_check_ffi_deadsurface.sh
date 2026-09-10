#!/usr/bin/env bash
# Falsify tools/check_ffi_deadsurface.py -- one arm per rule, plus the arms that
# ask whether it can fail at all, plus the three false answers it actually gave
# while it was being written.
#
# A checker's first run is against a tree its author has just fixed, so "it
# passes" is the least informative thing it will ever do. Each arm below mutates
# a COPY of the tree and fails the harness if the checker gives the wrong answer.
#
# THREE OF THESE ARMS ARE REGRESSION TESTS FOR REAL MISTAKES, not hypotheticals.
# Arm 5 (an intervening attribute) is the one that matters most: the first
# version of the export regex demanded `#[no_mangle]` be adjacent to `fn`, found
# 56 of 60 exports, and said nothing about the four it could not see -- a checker
# that under-reports its own subject while printing PASS. Arm 6 is the false
# POSITIVE that would have deleted live code: `return rust_hmac_sha256(...);`
# ends in a semicolon, and `return` is shaped like a return type, so a real call
# with three callers in storage.c was read as a prototype declaration.
#
# Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/rust/src" "$1/src/kernel" "$1/src/include" "$1/.github"
  cp "$ROOT/tools/check_ffi_deadsurface.py" "$1/tools/"
  cat > "$1/rust/src/lib.rs" <<'RS'
#[no_mangle]
pub extern "C" fn rust_live_one(x: u32) -> u32 { x }

#[no_mangle]
pub unsafe extern "C" fn rust_live_two(p: *const u8) -> bool { !p.is_null() }
RS
  cat > "$1/src/kernel/user.c" <<'C'
#include "kernel.h"
int caller(void) {
    if (rust_live_one(3) == 3) { return 1; }
    return rust_live_two(0) ? 1 : 0;
}
C
  cat > "$1/src/include/kernel.h" <<'C'
unsigned rust_live_one(unsigned x);
bool rust_live_two(const unsigned char *p);
C
  printf 'exempt: {}\n' > "$1/.github/ffi-exports.yml"
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_ffi_deadsurface.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_ffi_deadsurface.py:"

# 1. THE DEFECT IT WAS WRITTEN FOR: an export the C side never calls.
arm "1" "an export with no C caller" \
    "printf '\n#[no_mangle]\npub extern \"C\" fn rust_orphan(x: u32) -> u32 { x }\n' >> rust/src/lib.rs" \
    caught "rust_orphan"

# 2. THE SILENT DIRECTION. An export that IS called must not be reported; a
#    checker that flags everything satisfies arm 1 and is worthless.
arm "2" "an export with a live caller is left alone" \
    "true" clean

# 3. A DECLARATION IS NOT A CALLER. Seven of the twelve real findings were
#    declared in kernel.h and called by nothing, which is precisely what makes a
#    dead export look wired up.
arm "3" "a header prototype does not count as a caller" \
    "printf '\n#[no_mangle]\npub extern \"C\" fn rust_declared_only(x: u32) -> u32 { x }\n' >> rust/src/lib.rs
     printf 'unsigned rust_declared_only(unsigned x);\n' >> src/include/kernel.h" \
    caught "rust_declared_only"

# 4. A COMMENT IS NOT A CALLER. untyped.c names rust_page_ref_dec in prose and
#    capability.c named rust_lineage_bump in prose -- which is how a symbol with
#    no callers at all was recorded as "called once by capability.c".
arm "4" "a symbol named only in a comment does not count as a caller" \
    "printf '\n#[no_mangle]\npub extern \"C\" fn rust_only_in_a_comment(x: u32) -> u32 { x }\n' >> rust/src/lib.rs
     printf '/* See rust_only_in_a_comment(x) for the rationale. */\n' >> src/kernel/user.c
     printf '// and again: rust_only_in_a_comment(1)\n' >> src/kernel/user.c" \
    caught "rust_only_in_a_comment"

# 5. THE UNDER-REPORTING BUG, as a test. An export whose #[no_mangle] is
#    separated from its `fn` by an attribute or a doc comment must still be seen.
#    The first regex demanded adjacency and silently found 56 of 60.
arm "5" "an export behind an intervening attribute is still seen" \
    "printf '\n#[no_mangle]\n#[allow(clippy::too_many_arguments)]\n/// doc\npub extern \"C\" fn rust_behind_attr(x: u32) -> u32 { x }\n' >> rust/src/lib.rs" \
    caught "rust_behind_attr"

# 6. THE FALSE POSITIVE THAT WOULD HAVE DELETED LIVE CODE. `return rust_x(...);`
#    is a call, not a prototype, even though it ends in a semicolon.
arm "6" "a call written as \`return rust_x(...);\` is a caller, not a declaration" \
    "printf '\n#[no_mangle]\npub extern \"C\" fn rust_tail_called(x: u32) -> u32 { x }\n' >> rust/src/lib.rs
     printf 'unsigned rust_tail_called(unsigned x);\n' >> src/include/kernel.h
     printf 'int tail(void) { return rust_tail_called(1); }\n' >> src/kernel/user.c" \
    clean

# 7. THE OTHER DIRECTION: a C fallback shim for a function that has no Rust
#    export and no caller. rust_validate_ipc was exactly this.
arm "7" "a shim defining a rust_* symbol with no export and no caller" \
    "printf 'int rust_shim_for_nothing(int a) { return a; }\n' > src/kernel/rust_shims.c" \
    caught "rust_shim_for_nothing"

# 8. The declared exemption works...
arm "8a" "an allowlisted export with no caller is permitted" \
    "printf '\n#[no_mangle]\npub extern \"C\" fn rust_abi_required(x: u32) -> u32 { x }\n' >> rust/src/lib.rs
     printf 'exempt:\n  rust_abi_required: required by the ABI, not by us\n' > .github/ffi-exports.yml" \
    clean

# 8b. ...and is not a blanket escape hatch: removing it makes the symbol visible
#     again, so a file cannot be quietly parked there to silence a real finding.
arm "8b" "removing the exemption makes the same export visible again" \
    "printf '\n#[no_mangle]\npub extern \"C\" fn rust_abi_required(x: u32) -> u32 { x }\n' >> rust/src/lib.rs
     printf 'exempt: {}\n' > .github/ffi-exports.yml" \
    caught "rust_abi_required"

# 9. THE SELF-CHECK. Every rule above is vacuous against a regex that has stopped
#    matching: if the export pattern finds nothing, a clean tree is the one
#    answer the checker must never give.
arm "9" "the export pattern matching nothing fails rather than passing vacuously" \
    "printf '' > rust/src/lib.rs" \
    caught "no \`#[no_mangle] pub extern \"C\"\` exports found"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
