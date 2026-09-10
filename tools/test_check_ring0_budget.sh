#!/usr/bin/env bash
# Falsify tools/check_ring0_budget.py -- one arm per rule, both silent
# directions, and the self-check.
#
# The arms run against the REAL tree with a mutated manifest wherever that is
# enough, because the rule under test is a relation between the link line and
# the manifest: a fixture kernel would have to reproduce the Makefile to say
# anything, and a fixture that fails for its own reasons teaches nothing (the
# lesson tools/test_check_claude_md.sh records).
#
# Nothing here can leave the tree modified: every arm restores the manifest.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$ROOT/.github/ring0-classification.yml"
BAK="$(mktemp)"
CHECKER_BAK="$(mktemp)"
cp "$MANIFEST" "$BAK"
cp "$ROOT/tools/check_ring0_budget.py" "$CHECKER_BAK"
trap 'cp "$BAK" "$MANIFEST"; cp "$CHECKER_BAK" "$ROOT/tools/check_ring0_budget.py"; rm -f "$BAK" "$CHECKER_BAK"' EXIT
PASSES=0; FAILS=0

run () {
  if [ "${ARM_NO_CARGO:-0}" = 1 ]; then
    (cd "$ROOT" && env PATH=/usr/bin:/bin python3 tools/check_ring0_budget.py 2>&1)
  else
    (cd "$ROOT" && python3 tools/check_ring0_budget.py 2>&1)
  fi
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" out rc
  cp "$BAK" "$MANIFEST"; cp "$CHECKER_BAK" "$ROOT/tools/check_ring0_budget.py"
  ( cd "$ROOT" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); cp "$BAK" "$MANIFEST"; return; }
  out="$(run)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  cp "$BAK" "$MANIFEST"
}

echo "Falsifying tools/check_ring0_budget.py:"

# ---- THE RULE THAT ACTUALLY BITES. A file linked into kernel.elf that nobody
#      classified. This is how ring 0 grows without a decision.
arm "1" "a linked object nobody classified" \
    "python3 - <<'PY'
import pathlib,yaml
p=pathlib.Path('.github/ring0-classification.yml'); s=p.read_text()
s=s.replace('    - src/kernel/pipe.c            # the other IPC object\n','')
p.write_text(s)
PY" \
    caught "src/kernel/pipe.c"

# ---- THE SILENT DIRECTION. The real tree must pass; a checker that flags
#      everything satisfies arm 1 and is worthless.
arm "2" "the real tree, fully classified and within budget" \
    "true" clean

# ---- The budget itself. Lowering it stands in for code being added to core:
#      same comparison, and it does not require writing C into the tree.
arm "3" "core over its budget" \
    "sed -i 's/^core_budget_loc: .*/core_budget_loc: 9000/' .github/ring0-classification.yml" \
    caught "over its budget"

# ---- Moving a file between classes must MOVE the lines, not just relabel them.
#      If it did not, reclassifying scheduler.c as `service` would silently buy
#      1,940 lines of headroom -- the budget's obvious bypass.
arm "4" "reclassifying a core file out of core actually reduces core" \
    "python3 - <<'PY'
import pathlib
p=pathlib.Path('.github/ring0-classification.yml'); s=p.read_text()
s=s.replace('    - src/kernel/scheduler.c       # the scheduler and the claim invariant (S20)\n','')
s=s.replace('  service:\n','  service:\n    - src/kernel/scheduler.c\n')
s=s.replace('core_budget_loc: 9676','core_budget_loc: 7736')  # 9676 - 1940
p.write_text(s)
PY" \
    clean

# ---- A stale manifest entry: a file classified but no longer linked. Left
#      alone, it makes a deleted file look like it is still being accounted for.
arm "5" "a classified file that is not linked" \
    "sed -i 's|^  selftest:$|  selftest:\\n    - src/kernel/no_such_file.c|' .github/ring0-classification.yml" \
    caught "no_such_file.c"

# ---- Two classes claiming the same file: the totals would double-count it.
arm "6" "a file classified twice" \
    "sed -i 's|^  driver:$|  driver:\\n    - src/kernel/pipe.c|' .github/ring0-classification.yml" \
    caught "classified twice"

# ---- A class nobody defined. Typing `services:` must not silently drop ten
#      files out of the accounting.
arm "7" "an unknown class name" \
    "sed -i 's|^  service:$|  services:|' .github/ring0-classification.yml" \
    caught "unknown class"

# ---- THE SELF-CHECK. Every rule above is vacuous against an empty link line:
#      nothing is unclassified and core measures 0, which is under any budget.
#      Here `make` SUCCEEDS and this file's own parser is what has gone quiet,
#      so there is no stderr to report -- and saying so is the honest answer,
#      distinct from arm 9's, where make itself refused.
arm "8" "a parser that stops matching fails rather than passing vacuously" \
    "sed -i 's|if line.startswith(\"ld \")|if line.startswith(\"NOPE \")|' tools/check_ring0_budget.py" \
    caught "no error explaining why"

# ---- ARM 9, added after this checker failed on CI and could not say why. The
#      Makefile $(error)s at parse time without the bare-metal Rust target, so
#      `make -n` prints NOTHING -- and the first version reported only "resolved
#      only 0 linked sources", which is true, useless, and indistinguishable
#      from a bug in the checker itself. A gate must keep its evidence in the
#      case it goes red; here the evidence is make's stderr.
ARM_NO_CARGO=1 arm "9" "an unparseable Makefile is reported WITH the reason make gave" \
    "true" caught "cargo not found"

# Arm 8 edits the checker itself, so it is restored from a COPY taken at
# startup -- never with `git checkout --`, which restores from the index and
# silently discards unstaged work. That is not hypothetical: an earlier version
# of this line reverted the very fix arm 9 exists to test, and the run that
# followed reported both arms failing for a reason that was no longer in the
# file.

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
