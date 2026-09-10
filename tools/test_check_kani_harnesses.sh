#!/usr/bin/env bash
# Falsify tools/check_kani_harnesses.py -- one arm per rule, both silent
# directions, and the self-check.
#
# It exists because the answer to "does this proof run?" had been NO for every
# harness in the crate: the `kani` job was workflow_dispatch-only AND carried
# continue-on-error on both steps, so thirteen proofs of the capability algebra
# could not have failed a build. A proof nobody runs is a comment with a solver
# attached.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/rust/src" "$1/.github"
  cp "$ROOT/tools/check_kani_harnesses.py" "$1/tools/"
  cp "$ROOT/.github/kani-harnesses.yml" "$1/.github/"
  cp "$ROOT"/rust/src/*.rs "$1/rust/src/"
}

arm () {
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_kani_harnesses.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_kani_harnesses.py:"

# ---- RULE 1: a harness in NEITHER list. The whole point -- a new proof must not
#      be able to land without somebody answering "does this run?".
arm "1" "a new harness classified in neither list" \
    "printf '\n#[cfg(kani)]\n#[kani::proof]\nfn kani_test_unclassified() { assert!(true); }\n' >> rust/src/lib.rs" \
    caught "kani_test_unclassified"

# ---- The same, written with an intervening attribute, which is how the real
#      harnesses are spelled (#[kani::unwind(n)]). A regex demanding adjacency
#      would miss exactly the ones that matter.
arm "1b" "an unclassified harness behind #[kani::unwind]" \
    "printf '\n#[cfg(kani)]\n#[kani::proof]\n#[kani::unwind(4)]\nfn kani_test_unwound() { assert!(true); }\n' >> rust/src/lib.rs" \
    caught "kani_test_unwound"

# ---- RULE 2: in BOTH lists. Ambiguous classification is not classification.
arm "2" "a harness listed as both gating and manual" \
    "python3 - <<'PY'
import pathlib, yaml
p = pathlib.Path('.github/kani-harnesses.yml'); d = yaml.safe_load(p.read_text())
name = d['gating'][0]
d.setdefault('manual', {})[name] = 'planted by the falsification suite, a long enough reason'
p.write_text(yaml.safe_dump(d))
PY" \
    caught "both gating and manual"

# ---- RULE 3: a listed name that no longer exists. A rotted entry excuses
#      nothing and makes the manifest look more complete than it is.
arm "3" "a manifest entry naming a harness that does not exist" \
    "python3 - <<'PY'
import pathlib, yaml
p = pathlib.Path('.github/kani-harnesses.yml'); d = yaml.safe_load(p.read_text())
d['gating'].append('kani_proof_that_was_deleted')
p.write_text(yaml.safe_dump(d))
PY" \
    caught "kani_proof_that_was_deleted"

# ---- RULE 4: excused with no substantive reason. Otherwise `manual:` becomes a
#      place to park a proof rather than an argument for not running it.
arm "4" "a manual entry with a token reason" \
    "python3 - <<'PY'
import pathlib, yaml
p = pathlib.Path('.github/kani-harnesses.yml'); d = yaml.safe_load(p.read_text())
name = sorted(d.get('manual') or {})[0]
d['manual'][name] = 'slow'
p.write_text(yaml.safe_dump(d))
PY" \
    caught "no substantive reason"

# ---- THE SILENT DIRECTION. A checker that flags any harness satisfies every arm
#      above and forbids the crate as written.
arm "5" "the real crate and manifest" \
    "true" clean

# ---- THE SELF-CHECK. If the harness pattern stops matching, rule 1 is vacuous.
#      Rule 3 catches it here only because the manifest names harnesses the scan
#      can no longer find -- an accident worth having, and worth asserting, since
#      it is what stands between this checker and a silent pass.
arm "6" "a harness regex that matches nothing does not report a clean crate" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('tools/check_kani_harnesses.py'); s = p.read_text()
a = r'#\[kani::proof\]'
assert s.count(a) == 1, 'anchor moved'
p.write_text(s.replace(a, r'#\[kani::NOPE\]'))
PY
     grep -q 'kani::NOPE' tools/check_kani_harnesses.py" \
    caught

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
