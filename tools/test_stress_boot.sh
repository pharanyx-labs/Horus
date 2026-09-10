#!/usr/bin/env bash
# Falsify the input guard of tools/stress_boot.sh.
#
# WHAT THAT SCRIPT IS FOR: booting the same ISO many times, because a single green
# run is not evidence of anything. It backs smoke-console-smp-stress and
# smoke-sched-invariants-stress, both required.
#
# WHAT WENT WRONG: `for i in $(seq 1 0)` iterates never. With STRESS_RUNS=0 the
# loop never ran, the failure counters stayed 0, and the verdict printed
# "STRESS PASS: 0 failure(s) within the permitted 0" and exited 0 -- having booted
# nothing. The summary line one row above even said "out of 0": the evidence was
# on the screen and nothing acted on it. Measured on 2026-09-10, which is when the
# guard and this suite were written.
#
# NONE OF THESE ARMS BOOTS ANYTHING, and that is deliberate. The guard runs before
# the first boot, so the arms that must FAIL exit immediately; and the silent
# direction is checked by giving a legitimate run count with a NONEXISTENT ISO and
# requiring the script to get past the count check and fail on the ISO instead.
# That proves the guard admits a real run without spending 30 seconds proving it.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="$ROOT/tools/stress_boot.sh"
PASSES=0; FAILS=0

arm () {  # $1 label, $2 desc, $3 STRESS_RUNS value, $4 expect(caught|admitted)
  local label="$1" desc="$2" runs="$3" expect="$4" out rc
  out="$(cd "$ROOT" && STRESS_RUNS="$runs" STRESS_ALLOW_BUSY=1 \
         bash "$S" /nonexistent-iso-for-the-suite.iso 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    # Refused for the RUN COUNT, before it ever looked at the ISO.
    if [ $rc -ne 0 ] && grep -qE "is not a number|boots nothing" <<<"$out"; then
      echo "  $label: caught -- $desc"; PASSES=$((PASSES+1))
    elif [ $rc -ne 0 ]; then
      echo "  $label: refused, but for the ISO rather than the run count -- $desc"; FAILS=$((FAILS+1))
    else
      echo "  $label: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    fi
  else
    # Admitted by the count guard, then correctly stopped by the missing ISO.
    if grep -qE "is not a number|boots nothing" <<<"$out"; then
      echo "  $label: WRONGLY REFUSED -- $desc"; FAILS=$((FAILS+1))
    elif grep -q "not found" <<<"$out"; then
      echo "  $label: admitted, correctly -- $desc"; PASSES=$((PASSES+1))
    else
      echo "  $label: unclear outcome -- $desc"; head -2 <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
    fi
  fi
}

echo "Falsifying the input guard of tools/stress_boot.sh:"

# ---- THE DEFECT ITSELF. What somebody sets to skip a slow gate for one run, and
#      what an unset shell variable evaluates to in arithmetic.
arm "1"  "zero boots reported as a pass"            0     caught
arm "2"  "a negative run count"                     -3    caught

# ---- THE SAME SHAPE BY ANOTHER ROUTE: seq fails on a non-numeric value, the
#      loop is empty, and the run reports success.
arm "3a" "a non-numeric run count"                  abc   caught
# An EMPTY value is not the defect, and this arm asserts that rather than
# assuming it: `RUNS="${STRESS_RUNS:-20}"` uses `:-`, which substitutes the
# default for unset AND for empty, so STRESS_RUNS="" means twenty boots and not
# zero. Worth an arm precisely because it looks like it should be caught -- the
# expectation here was wrong on the first run, and the script was right.
arm "3b" "an empty run count falls back to the default"  ""  admitted

# ---- THE SILENT DIRECTION, twice. The bound is 1 and not a minimum sample size:
#      STRESS_RUNS=1 is a legitimate check that the harness itself works, and it
#      does measure something. A guard that blocked it would trade a real defect
#      for an obstacle.
arm "4a" "a single boot is a legitimate run"        1     admitted
arm "4b" "the default-sized run"                    20    admitted

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
