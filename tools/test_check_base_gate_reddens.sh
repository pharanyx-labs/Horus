#!/usr/bin/env bash
# Falsify the half of tools/check_base_gate_reddens.sh that can be falsified
# without booting anything.
#
# WHAT THAT SCRIPT DOES: for every row in docs/BUILDING.md that claims "`make
# smoke-X` must go red under it", build that gate WITH the flag and require it to
# fail. It is the direction nobody measures -- an arm proves the defect is
# detectable BY THE ARM; only the base gate going red proves the property is
# guarded in the shipping configuration.
#
# WHY THE MEASURING HALF HAS NO ARM, said out loud rather than left as a gap. One
# pair is a clean build and a QEMU boot; there are 88, and its own PAIR_TIMEOUT
# default is 900 seconds per pair because a FAILING boot burns the whole smoke
# budget before the harness gives up. Falsifying it end to end would mean
# deliberately breaking a base gate and booting to watch it not redden -- hours
# of machine time to re-derive something the gate itself reports every time it
# runs. What IS armed here is the PARSER, and the parser is where a silent
# failure would hide: with no pairs the loop never runs and the summary prints
# PASS having measured nothing.
#
# That was not hypothetical. Until 2026-09-10 this script had no guard against an
# empty pair list, so a row pattern that stopped matching would have reported
# "PASS: every base gate reddens under the flag its table says it must" while
# booting nothing at all -- the same defect five other checkers in this tree
# turned out to have. Arm 2 is that case, and it failed until the guard existed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

# A fixture with the script, the table it derives from, and a Makefile whose
# targets all succeed. PAIR_TIMEOUT is tiny and no gate here boots: every target
# is `true`, so the script runs end to end in milliseconds and what is being
# tested is which pairs it decided to measure.
mktree () {
  local dst="$1"
  mkdir -p "$dst/tools" "$dst/docs" || return 1
  cp "$ROOT/tools/check_base_gate_reddens.sh" "$dst/tools/" || return 1
  cp "$ROOT/docs/BUILDING.md" "$dst/docs/" || return 1
  # Every smoke target the table names, all trivially green -- so a correctly
  # parsing script reports them all as STAYED GREEN and fails, which is arm 1.
  {
    printf '.PHONY: all\nall:\n\t@true\n'
    grep -oE 'smoke-[a-z0-9-]+' "$ROOT/docs/BUILDING.md" | sort -u | while read -r g; do
      printf '.PHONY: %s\n%s:\n\t@true\n' "$g" "$g"
    done
  } > "$dst/Makefile" || return 1
}

echo "Falsifying tools/check_base_gate_reddens.sh (the parser half):"

# ---- ARM 1: the script's own defect condition. Every gate in the fixture is a
#      no-op that succeeds, so under the flag each one STAYS GREEN -- which is
#      exactly the finding this script exists to report. If it passed here it
#      would not be reporting anything.
d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
out="$(cd "$d" && PAIR_TIMEOUT=20 bash tools/check_base_gate_reddens.sh 2>&1)"; rc=$?
printf '  1: '
if [ $rc -ne 0 ] && grep -q "STAYED GREEN" <<<"$out"; then
  echo "caught -- gates that do not redden under their flag"; PASSES=$((PASSES+1))
else
  echo "NOT CAUGHT -- a table of gates that all stay green was accepted"; FAILS=$((FAILS+1))
fi
_rmtree "$d"

# ---- ARM 2, THE ONE THAT MATTERS: the row pattern stops matching. With no pairs
#      the loop never runs, nothing is measured, and without the guard the
#      summary says PASS.
d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
sed -i 's/must go red/must go PURPLE/g; s/goes red/goes PURPLE/g' "$d/docs/BUILDING.md"
out="$(cd "$d" && PAIR_TIMEOUT=20 bash tools/check_base_gate_reddens.sh 2>&1)"; rc=$?
printf '  2: '
if [ $rc -ne 0 ] && grep -qE "derived only|far fewer" <<<"$out"; then
  echo "caught -- a row pattern that matches nothing fails rather than passing vacuously"; PASSES=$((PASSES+1))
elif [ $rc -eq 0 ]; then
  echo "NOT CAUGHT -- reported success having measured no pairs at all"; FAILS=$((FAILS+1))
else
  echo "caught, but not by the vacuity guard"; grep -m1 . <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
fi
_rmtree "$d"

# ---- ARM 3: a selector naming a flag with NO pair in the table. It skipped all
#      88 and reported PASS -- built nothing, booted nothing, and told whoever
#      ran it that every gate reddens. The second vacuity hole in this script,
#      one level down from arm 2's, and found by this suite on the same day.
d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
out="$(cd "$d" && PAIR_TIMEOUT=20 bash tools/check_base_gate_reddens.sh FLAG_THAT_IS_NOT_IN_THE_TABLE 2>&1)"; rc=$?
printf '  3: '
if [ $rc -ne 0 ] && grep -q "matched no pair" <<<"$out"; then
  echo "caught -- a selector that matches no pair fails rather than passing vacuously"; PASSES=$((PASSES+1))
elif [ $rc -eq 0 ]; then
  echo "NOT CAUGHT -- skipped every pair and reported success"; FAILS=$((FAILS+1))
else
  echo "caught, but not by the selector guard"; grep -m1 . <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
fi
_rmtree "$d"

# ---- ARM 4: the silent direction. A selector naming a flag that IS in the table
#      must measure that one and skip the rest -- the guard above must not make
#      a legitimate single-flag run impossible, which is the way a guard like
#      this usually goes wrong.
d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
flag="$(cd "$d" && python3 - <<'PY2'
import re
for l in open('docs/BUILDING.md', encoding='utf-8'):
    if not l.startswith('| `') or 'go red' not in l: continue
    m = re.match(r'\| `([A-Z_0-9]+)=1`', l)
    if not m: continue
    if re.findall(r'`?make (smoke-[a-z0-9-]+)` must go red', l) or re.findall(r'`(smoke-[a-z0-9-]+)` goes? red', l):
        print(m.group(1)); break
PY2
)"
out="$(cd "$d" && PAIR_TIMEOUT=20 bash tools/check_base_gate_reddens.sh "$flag" 2>&1)"
printf '  4: '
if grep -q "skipped" <<<"$out" && grep -qE "went red +: [1-9]|STAYED GREEN" <<<"$out"; then
  echo "clean, correctly -- naming a real flag measures it and skips the others"; PASSES=$((PASSES+1))
else
  echo "WRONG -- a legitimate single-flag run did not measure its pair ($flag)"; FAILS=$((FAILS+1))
fi
_rmtree "$d"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
