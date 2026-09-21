#!/usr/bin/env bash
# Falsify tools/ci_gate_verdict.py: one arm per way a run can fail to be a pass,
# plus the silent direction.
#
# WHY IT EXISTS: since the ruleset requires one aggregated check instead of one
# context per job, this verdict is the single point every gate's result passes
# through. A verdict that says PASS for a skipped or cancelled job, or for an
# empty `needs`, is a bypass of every gate at once, and would look green.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

arm () {  # $1 id, $2 desc, $3 NEEDS json (or the literal UNSET), $4 expect, $5 must-say
  local id="$1" desc="$2" needs="$3" expect="$4" want="${5:-}" out rc
  if [ "$needs" = UNSET ]; then
    out="$(env -u NEEDS python3 "$ROOT/tools/ci_gate_verdict.py" 2>&1)"; rc=$?
  else
    out="$(NEEDS="$needs" python3 "$ROOT/tools/ci_gate_verdict.py" 2>&1)"; rc=$?
  fi
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $id: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $id: caught but did not say $want -- $desc"; FAILS=$((FAILS+1))
    else echo "  $id: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $id: WRONGLY CAUGHT -- $desc"; echo "$out" | tail -3 | sed 's/^/      /'; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $id: passed but did not say $want -- $desc"; FAILS=$((FAILS+1))
    else echo "  $id: pass, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
}

OK='{"result":"success","outputs":{}}'

echo "Falsifying tools/ci_gate_verdict.py:"

# ---- THE SILENT DIRECTION: every job succeeded, and the count is stated.
arm 1 "three jobs, all succeeded" \
    "{\"a\":$OK,\"b\":$OK,\"c\":$OK}" pass "all 3 required jobs succeeded"

# ---- A red gate must redden the verdict.
arm 2 "one job failed" \
    "{\"a\":$OK,\"b\":{\"result\":\"failure\",\"outputs\":{}},\"c\":$OK}" caught "b: failure"

# ---- The bypasses: GitHub counts a skipped check as satisfying a requirement.
arm 3 "one job skipped" \
    "{\"a\":$OK,\"b\":{\"result\":\"skipped\",\"outputs\":{}}}" caught "b: skipped"
arm 4 "one job cancelled" \
    "{\"a\":$OK,\"b\":{\"result\":\"cancelled\",\"outputs\":{}}}" caught "b: cancelled"
arm 5 "a result this script does not know" \
    "{\"a\":$OK,\"b\":{\"result\":\"neutral\",\"outputs\":{}}}" caught "b: neutral"
arm 6 "an entry with no result at all" \
    "{\"a\":$OK,\"b\":{\"outputs\":{}}}" caught "b: None"

# ---- The vacuous passes: nothing to judge is not a pass.
arm 7 "an empty needs object" '{}' caught "names no jobs"
arm 8 "NEEDS not set" UNSET caught "not JSON"
arm 9 "NEEDS not JSON" 'not json' caught "not JSON"
arm 10 "NEEDS a JSON list, not an object" '[1,2]' caught "names no jobs"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
