#!/usr/bin/env bash
# Falsify tools/check_gate_evidence.py -- one arm per rule, plus a clean arm.
#
# The clean arm is not padding. Five "is this caught" arms are all satisfied by
# a checker that rejects every tree, and this repository has shipped a checker
# that could not fail before. The sixth arm asserts the unmutated tree PASSES,
# which is the only one of the six that can catch that.
#
# Rule 3 is the arm that matters most: rules 1 and 2 are satisfiable by a
# manifest entry alone, so a checker with only those would pass a tree in which
# the floor had been deleted from the recipe -- exactly how the vacuous-pass
# defect would return.
#
# Mutations are applied to a COPY. Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/.github"
  cp "$ROOT/Makefile" "$1/"
  cp "$ROOT/tools/check_gate_evidence.py" "$1/tools/"
  cp "$ROOT/.github/gate-evidence.yml" "$1/.github/"
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_gate_evidence.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_gate_evidence.py:"

# R1. A multi-boot target nobody classified. This is the state smoke-exec-reenter
#     and smoke-cr3-reclaim were in when both passed on twenty boots that never
#     happened.
arm R1 "a looping target absent from the manifest" \
  "python3 - <<'EOF'
import re
p='.github/gate-evidence.yml'; s=open(p).read()
s=re.sub(r'  smoke-exec-reenter:\n    marker:.*\n    floor:.*\n', '', s, count=1)
open(p,'w').write(s)
EOF" \
  caught "smoke-exec-reenter"

# R2. A declared floor that is not a Makefile variable at all -- a manifest that
#     names something imaginary reads as protection and is not.
arm R2 "a liveness entry naming a floor that does not exist" \
  "sed -i 's/    floor: EXEC_REENTER_MIN_LIVE/    floor: EXEC_REENTER_MIN_IMAGINARY/' .github/gate-evidence.yml" \
  caught "EXEC_REENTER_MIN_IMAGINARY"

# R3. THE ARM THIS FILE EXISTS FOR. The variable stays defined and the manifest
#     stays correct; only the recipe stops reading the floor. That is the defect
#     returning, and rules 1 and 2 are both still satisfied while it does.
arm R3 "a floor that is defined and declared but never read by the recipe" \
  "python3 - <<'EOF'
s=open('Makefile').read()
old='\tif [ \"\$\$live\" -lt \$(EXEC_REENTER_MIN_LIVE) ]; then \\\\\n'
assert old in s, 'R3 anchor missing'
s=s.replace(old, '\tif [ \"\$\$live\" -lt 0 ]; then \\\\\n', 1)
open('Makefile','w').write(s)
EOF" \
  caught "EXEC_REENTER_MIN_LIVE"

# R4. A manifest entry whose target has been renamed or removed is a stale
#     excuse that keeps reading as coverage.
arm R4 "a manifest entry for a target that does not exist" \
  "sed -i 's/^  smoke-kstack-race:/  smoke-gone-away:/' .github/gate-evidence.yml" \
  caught "smoke-gone-away"

# R5. An exemption with no reason is an exemption nobody can check.
arm R5 "an exempt target with an empty reason" \
  "python3 - <<'EOF'
import re
p='.github/gate-evidence.yml'; s=open(p).read()
s=re.sub(r'(  smoke-session-smp-soak: )>\n(    .*\n)+', r\"\1''\n\", s, count=1)
open(p,'w').write(s)
EOF" \
  caught "smoke-session-smp-soak"

# R6. The direction the five above cannot test: an unmutated tree must PASS.
arm R6 "the tree as committed" "true" clean

echo
echo "arms passed: $PASSES, failed: $FAILS"
[ "$FAILS" -eq 0 ] || exit 1
