#!/usr/bin/env bash
# Falsify tools/check_invariants.py -- one arm per rule.
#
# A checker is a predicate, and a predicate nobody has seen REJECT anything is
# indistinguishable from `return 0`. This repository has been bitten by that
# exactly: of the first three rules in an earlier checker, two silently could not
# fail. So every rule here is exercised against a tree mutated to break it, and
# the harness fails if the checker stays quiet.
#
# The mutations are applied to a COPY. Nothing here touches the working tree --
# a checker's own test must not be able to leave the repository modified, least
# of all one that runs in CI.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {           # $1 = scratch dir
  mkdir -p "$1/tools" "$1/.github/workflows"
  cp "$ROOT/SECURITY.md" "$ROOT/Makefile" "$1/"
  cp "$ROOT/tools/check_invariants.py" "$1/tools/"
  cp "$ROOT"/.github/workflows/*.yml "$1/.github/workflows/" 2>/dev/null
  for f in gate-exceptions.yml invariants.yml; do
    [ -f "$ROOT/.github/$f" ] && cp "$ROOT/.github/$f" "$1/.github/"
  done
  return 0
}

arm () {              # $1 = rule, $2 = description, $3 = mutation (shell, cwd=$d)
  local rule="$1" desc="$2" mut="$3" d out
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_invariants.py 2>&1)"
  if [ $? -eq 0 ]; then
    echo "  $rule: NOT CAUGHT -- $desc"
    FAILS=$((FAILS+1))
  elif ! grep -q "^  - $rule " <<<"$out"; then
    echo "  $rule: caught, but reported under the wrong rule -- $desc"
    echo "$out" | grep '^  - ' | head -3
    FAILS=$((FAILS+1))
  else
    echo "  $rule: caught -- $desc"
    PASSES=$((PASSES+1))
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_invariants.py, one arm per rule:"

# R1 -- a property whose witness column says nothing runnable. This is S16's
# actual pre-2026-08-28 state: an em-dash against real enforcing code.
arm R1 "a witness column with no runnable witness (S16's real prior state)" \
  "python3 - <<'P'
import re,io
ls=open('SECURITY.md').read().split('\n')
for i,l in enumerate(ls):
    if l.startswith('| S16 |'):
        c=l.split('|'); c[4]=' — '; ls[i]='|'.join(c); break
else: raise SystemExit(1)
open('SECURITY.md','w').write('\n'.join(ls))
P"

# R2 -- a witness naming a target that does not exist. The shape a renamed gate
# leaves behind: the row still reads as bound.
arm R2 "a witness naming a make target that does not exist" \
  "sed -i 's/make smoke-captest/make smoke-captest-renamed-away/' SECURITY.md"

# R3 -- a target that exists but no workflow runs. A witness in principle only.
arm R3 "a witness target that no workflow runs" \
  "printf '\n.PHONY: smoke-orphaned-witness\nsmoke-orphaned-witness:\n\t@true\n' >> Makefile
   sed -i '0,/| S1 |/s/make smoke-captest/make smoke-orphaned-witness/' SECURITY.md"

# R4 -- a control arm named in SECURITY.md but absent from DEFECT_FLAGS, so a
# boot under it is not stamped and its measurements cannot be told apart.
arm R4 "a control-arm flag that DEFECT_FLAGS does not stamp" \
  "sed -i 's/FRAME_INDEX_UNCHECKED/FRAME_INDEX_UNSTAMPED/' SECURITY.md"

# R5a -- two rows claiming one id.
arm R5 "a duplicated invariant id" \
  "python3 - <<'P'
ls=open('SECURITY.md').read().split('\n')
for i,l in enumerate(ls):
    if l.startswith('| S20 |'): ls.insert(i+1, l); break
else: raise SystemExit(1)
open('SECURITY.md','w').write('\n'.join(ls))
P"

# R5b -- a hole in the numbering, which is what two people picking the next
# number at the same time leaves behind after one of them renumbers.
arm R5 "a gap in the invariant numbering" \
  "python3 - <<'P'
ls=[l for l in open('SECURITY.md').read().split('\n') if not l.startswith('| S20 |')]
open('SECURITY.md','w').write('\n'.join(ls))
P"

# R6 -- an exemption for a property that has since acquired a real witness.
arm R6 "an exemption that has outlived its reason" \
  "printf 'exempt:\n  S1:\n    witnessed_by: a thing that is not a job\n    reason: >-\n      this exemption is stale because S1 now names a real make target in its witness column\n' > .github/invariants.yml"

# R6b -- an exemption for an id that is not in the table at all.
arm R6 "an exemption for an unknown invariant id" \
  "printf 'exempt:\n  S999:\n    witnessed_by: nothing at all\n    reason: >-\n      this identifier does not appear anywhere in the security property table\n' > .github/invariants.yml"

echo
echo "arms caught: $PASSES   not caught: $FAILS"
[ "$FAILS" -eq 0 ] || { echo "FAIL: a rule in check_invariants.py cannot fail"; exit 1; }
echo "PASS: every rule rejects a tree that breaks it"
