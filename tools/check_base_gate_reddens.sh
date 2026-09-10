#!/usr/bin/env bash
# Measure the direction nobody measures: does the BASE gate go red under the flag?
#
# docs/BUILDING.md makes this claim 32 times -- "`make smoke-X` must go red under
# it" -- and until 2026-08-30 NOTHING tested it. Not a target, not a CI job, not a
# checker. Thirty-one written assertions with no measurement behind any of them.
# (Thirty-one when this was written; the thirty-second, SYSCOV_PROBES_ABSENT, was
# added later the same day and measured through this script before it landed. The
# count is derived below rather than read from here -- do not trust this line.)
#
# WHY IT IS NOT IMPLIED BY THE CONTROL ARM. A control arm builds WITH the flag and
# asserts a FAIL marker appears. The base gate builds WITHOUT it and asserts PASS.
# Nobody builds the base gate WITH the flag, so the pair establishes "the defect is
# detectable by the arm", never "the defect is detected by the gate that guards the
# property in the shipping configuration". Those come apart whenever the arm and
# the gate look at different markers, different binaries, or different workloads --
# and an arm that reddens only its own private assertion is a gate that would stay
# green while the property was broken. CLAUDE.md section 2 says to falsify the loop
# in the other direction; this is that, made runnable.
#
# It is NOT wired into CI. Each pair is a clean rebuild plus a boot, so the full
# sweep is hours, which is a poor fit for a per-PR gate and a good fit for a thing
# run deliberately -- before promoting an arm, or when auditing. Run it with no
# arguments for everything, or name flags to run a subset:
#
#   tools/check_base_gate_reddens.sh                       # all pairs
#   tools/check_base_gate_reddens.sh FPU_NO_SAVE FPU_NO_RESTORE
#
# Env: PAIR_TIMEOUT  seconds per pair (default 900; a FAILING boot burns the full
#                    SMOKE_TIMEOUT before the harness gives up, so size this by how
#                    long a failure takes, never by how long a pass takes)
#      SMOKE_TIMEOUT passed through to the gate itself
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
PAIR_TIMEOUT="${PAIR_TIMEOUT:-900}"
WANT=("$@")

# The pairs are DERIVED from docs/BUILDING.md rather than listed here, so this
# cannot drift from the table it is checking -- the same reason check_invariants
# reads SECURITY.md instead of a parallel manifest.
mapfile -t PAIRS < <(python3 - <<'PY'
import re
for l in open('docs/BUILDING.md', encoding='utf-8'):
    if not l.startswith('| `') or 'go red' not in l:
        continue
    m = re.match(r'\| `([A-Z_0-9]+)=1`', l)
    if not m:
        continue                      # cargo-feature arms are not -D flags
    gates = re.findall(r'`?make (smoke-[a-z0-9-]+)` must go red', l)
    if not gates:
        gates = re.findall(r'`(smoke-[a-z0-9-]+)` goes? red', l)
    for g in dict.fromkeys(gates):
        print(f"{m.group(1)} {g}")
PY
)

# THE PAIRS ARE THE MEASUREMENT'S SUBJECT, so an empty list is not "nothing to
# do" -- it is this script having lost the ability to read the table it checks.
# With no pairs the loop below never runs, GREEN stays 0, and the summary prints
# "PASS: every base gate reddens under the flag its table says it must" having
# booted nothing at all. That is the answer this file must never give by
# accident, and it could give it until 2026-09-10: the guard was added when its
# own falsification suite was written, which is the same defect five other
# checkers in this tree turned out to have.
#
# The bound is deliberately far below the real count (88 on 2026-09-10) so that
# retiring arms never trips it; it is here to catch a parser that has gone
# silent, not to police the table's size.
if [ "${#PAIRS[@]}" -lt 20 ]; then
  echo "FAIL: derived only ${#PAIRS[@]} flag/gate pairs from docs/BUILDING.md," >&2
  echo "      which is far fewer than that table has ever held. The row pattern" >&2
  echo "      has probably stopped matching -- fix it rather than lowering this" >&2
  echo "      bound, because every measurement below is vacuous without it." >&2
  exit 1
fi

RED=0; GREEN=0; SKIP=0; ERR=0
declare -a NOT_RED

echo "Measuring: does each base gate go RED under the flag docs/BUILDING.md says it must?"
echo "pairs derived from docs/BUILDING.md: ${#PAIRS[@]}"
echo

for p in "${PAIRS[@]}"; do
  flag="${p%% *}"; gate="${p##* }"
  if [ ${#WANT[@]} -gt 0 ]; then
    match=0; for w in "${WANT[@]}"; do [ "$w" = "$flag" ] && match=1; done
    [ $match -eq 1 ] || { SKIP=$((SKIP+1)); continue; }
  fi
  printf '  %-30s %-24s ' "$flag" "$gate"
  out="$(timeout "$PAIR_TIMEOUT" make --no-print-directory "$gate" "$flag=1" 2>&1)"
  rc=$?
  if [ $rc -eq 124 ]; then
    # A timeout is the gate failing to finish, which for a stall-shaped defect IS
    # red. Reported distinctly so it is never mistaken for a clean assertion.
    echo "RED (timed out -- the gate did not finish)"; RED=$((RED+1))
  elif [ $rc -ne 0 ]; then
    echo "RED"; RED=$((RED+1))
  else
    echo "*** STAYED GREEN ***"; GREEN=$((GREEN+1)); NOT_RED+=("$flag -> $gate")
  fi
done

# A SELECTOR THAT MATCHED NOTHING IS NOT A CLEAN RUN EITHER, and this is the same
# defect one level down. `check_base_gate_reddens.sh SOME_FLAG` where SOME_FLAG
# has no row in the table skipped all 88 pairs and reported "PASS: every base gate
# reddens under the flag its table says it must" -- having built nothing and
# booted nothing. Somebody checking one flag after changing it would have been
# told their change was fine by a script that never looked at it.
#
# Found on 2026-09-10 by this file's own falsification suite, immediately after
# the empty-table guard above was added for the identical reason.
if [ ${#WANT[@]} -gt 0 ] && [ $((RED + GREEN)) -eq 0 ]; then
  echo >&2
  echo "FAIL: named ${WANT[*]} on the command line and matched no pair at all," >&2
  echo "      so nothing was built and nothing was measured. Check the spelling" >&2
  echo "      against the flag column of docs/BUILDING.md -- a run that measures" >&2
  echo "      nothing must not report that everything reddens." >&2
  exit 1
fi

echo
echo "went red      : $RED"
echo "stayed GREEN  : $GREEN"
[ $SKIP -gt 0 ] && echo "skipped       : $SKIP"
if [ $GREEN -ne 0 ]; then
  echo
  echo "FAIL: a documented claim that a gate reddens under a flag is not true:"
  for n in "${NOT_RED[@]}"; do echo "  - $n"; done
  echo
  echo "Either the gate does not witness what the flag breaks -- in which case the"
  echo "arm measures its own assertion and not the property -- or docs/BUILDING.md"
  echo "claims something it should not."
  exit 1
fi
echo
echo "PASS: every base gate reddens under the flag its table says it must"
