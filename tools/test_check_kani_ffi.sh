#!/usr/bin/env bash
# Falsify tools/check_kani_ffi.py: one arm per rule, each a mutation of a copy of
# rust/src/capability.rs that the checker must catch, and the clean tree.
set -u
pass=0; fail=0
OUT=$(mktemp)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH" "$OUT"' EXIT
mkdir -p "$SCRATCH/rust/src"

try() { # name, want(0|1), rule-tag, python mutation of the text in `s`
  local name="$1" want="$2" tag="$3" mut="$4"
  python3 -I - "$mut" <<'PY' > "$SCRATCH/rust/src/capability.rs"
import sys
s = open("rust/src/capability.rs").read()
exec(sys.argv[1])
sys.stdout.write(s)
PY
  KANI_FFI_ROOT="$SCRATCH" python3 tools/check_kani_ffi.py >"$OUT" 2>&1; got=$?
  if [ "$got" = "$want" ] && { [ "$want" = 0 ] || grep -q "^  - $tag" "$OUT"; }; then
    echo "  PASS  $name (exit $got)"; pass=$((pass+1))
  else
    echo "  FAIL  $name (exit $got, wanted $want with $tag)"; sed -n '1,6p' "$OUT"; fail=$((fail+1))
  fi
}

echo "R1 -- an export no harness calls must be CAUGHT"
try "a new unproved export" 1 R1 \
 's = s.replace("\nmod kani_proofs {", "\n#[no_mangle]\npub unsafe extern \"C\" fn rust_cap_zz_unproved(x: u32) -> u32 { x }\n\nmod kani_proofs {", 1)'

echo "R1 -- an export whose only harness is deleted must be CAUGHT"
try "the revoke proof removed" 1 R1 \
 'i = s.index("    fn revoke_empties_the_target_and_its_children_only()"); j = s.index("\n    }\n", i) + 7; s = s[:i] + "    fn revoke_gone() {}\n" + s[j:]'

echo "R2 -- a renamed proofs module must be CAUGHT, not read as every export covered"
try "kani_proofs renamed" 1 R2 's = s.replace("mod kani_proofs {", "mod kani_proofs_renamed {")'

echo "R3 -- a pattern that stops matching must be CAUGHT"
try "extern \"C\" spelt differently" 1 R3 's = s.replace("extern \"C\" fn rust_cap_", "extern \"system\" fn rust_cap_")'

echo "clean -- the unmutated source must PASS"
try "clean tree" 0 none 'pass'

echo
echo "falsification: $pass passed, $fail failed"
[ "$fail" = 0 ]
