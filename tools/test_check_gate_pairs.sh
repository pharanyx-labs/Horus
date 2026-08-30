#!/usr/bin/env bash
# Falsify tools/check_gate_pairs.py -- one arm per rule.
#
# The checker's own history is the argument for this file: it shipped with four
# rules, and rule 1 was silently wrong for four targets because it inferred the
# classification from the target NAME. A rule that infers cannot be trusted
# merely because it passes, so each of the five is exercised against a tree
# mutated to break it, and the harness fails if the checker stays quiet.
#
# Mutations are applied to a COPY. Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/.github/workflows"
  cp "$ROOT/Makefile" "$1/"
  cp "$ROOT/tools/check_gate_pairs.py" "$1/tools/"
  cp "$ROOT"/.github/workflows/*.yml "$1/.github/workflows/"
  cp "$ROOT/.github/gate-exceptions.yml" "$ROOT/.github/gate-pairs.yml" "$1/.github/"
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_gate_pairs.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_gate_pairs.py:"

# R1. An arm whose base gate does not exist. This is smoke-ksp-guard-control's
#     real prior state: an arm proving the check CAN fire, with nothing asking
#     whether it stays silent on a legal value.
arm R1 "a control arm naming a base gate that is not a gate" \
  "sed -i 's/^  smoke-captest-mint-hang-control: smoke-captest\$/  smoke-captest-mint-hang-control: smoke-nonexistent/' .github/gate-pairs.yml" \
  caught "smoke-captest-mint-hang-control"

# R2. An arm nobody runs rots: it can stop reproducing its defect and nothing says so.
arm R2 "a control arm that CI never invokes" \
  "printf '\n.PHONY: smoke-planted-control\nsmoke-planted-control:\n\t@true\n' >> Makefile
   sed -i 's/^control_arms:\$/control_arms:\n  smoke-planted-control: smoke-captest/' .github/gate-pairs.yml" \
  caught "smoke-planted-control"

# R3. A gate nobody runs is a gate that cannot fail.
arm R3 "a base gate that nothing invokes and nothing excuses" \
  "printf '\n.PHONY: smoke-planted-gate\nsmoke-planted-gate:\n\t@true\n' >> Makefile
   sed -i 's/^gates:\$/gates:\n  - smoke-planted-gate/' .github/gate-pairs.yml" \
  caught "smoke-planted-gate"

# R4. An exemption naming a target that does not exist is a stale excuse.
arm R4 "an exception for a target that does not exist" \
  "sed -i 's/^  smoke-sched-invariants:/  smoke-gone-away:/' .github/gate-exceptions.yml" \
  caught "smoke-gone-away"

# R5. THE RULE THIS FILE WAS REWRITTEN FOR. A new target absent from the manifest
#     must not be classified by a default: defaulting to "gate" is how four arms
#     were counted as gates for weeks.
arm R5 "a target absent from gate-pairs.yml" \
  "printf '\n.PHONY: smoke-planted-unclassified\nsmoke-planted-unclassified:\n\t@true\n' >> Makefile" \
  caught "smoke-planted-unclassified"

# R5b. And the reverse: a manifest entry for a target that no longer exists.
arm R5b "a manifest entry whose Makefile target is gone" \
  "sed -i 's/^gates:\$/gates:\n  - smoke-deleted-long-ago/' .github/gate-pairs.yml" \
  caught "smoke-deleted-long-ago"

# R6. The other direction. An unmutated tree must pass, or the six arms above are
#     satisfied by a checker that rejects everything.
arm R6 "an unmutated tree passes" "true" clean

echo
if [ "$FAILS" -ne 0 ]; then echo "FAIL: $FAILS arm(s) wrong ($PASSES passed)"; exit 1; fi
echo "PASS: $PASSES arms -- every rule rejects its own violation, and a sound tree passes"
