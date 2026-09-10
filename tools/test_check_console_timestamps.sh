#!/usr/bin/env bash
# Falsify tools/check_console_timestamps.py -- one arm per rule, the silent
# directions, and the three broken-boot guards.
#
# This checker takes a serial log as its argument, so every fixture here is a
# synthetic log written from scratch. That is a real advantage over a tree-walking
# checker: the arms test the RULE rather than whatever a boot happened to print,
# and a fixture cannot drift with the kernel.
#
# THE PROPERTY HAS TWO HALVES AND THEY FAIL SEPARATELY: every non-blank line
# between the kernel's first message and the session start carries a
# `[    S.uuuuuu] ` prefix, and the prefixes do not go backwards. A log can be
# fully stamped and still unreadable if the stamps disagree about when now is.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK="$ROOT/tools/check_console_timestamps.py"
PASSES=0; FAILS=0

# Refuse to delete anything that is not a fresh temp directory. See the note in
# tools/test_check_abi_structs.sh: a sibling harness once pointed this at the
# repository's own tools/.
_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

START="Horus secure microkernel (x86_64) booting"
BANNER="Horus Secure Microkernel"

# A clean log: kernel start, three stamped lines, then the session banner.
good_log () {
  printf '[    0.000100] %s\n' "$START"
  printf '[    0.001000] paging: identity map installed\n'
  printf '[    0.002000] sched: ready\n'
  printf '[    1.500000] init: starting, launching shell\n'
  printf '%s\n' "$BANNER"
  printf 'capability-based - privilege-separated\n'
}

arm () {  # $1 rule, $2 desc, $3 log-producer, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" gen="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  eval "$gen" > "$d/serial.log"
  out="$(python3 "$CHECK" "$d/serial.log" 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not say $want -- $desc"; head -2 <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; head -2 <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_console_timestamps.py:"

# ---- RULE 1: an unstamped line inside the window. The defect it exists for --
#      a kernel message that reached the console without going through kmsg().
arm "1" "an unstamped line inside the window" \
    'good_log | sed "3i paging: this one forgot its stamp"' \
    caught "unstamped"

# ---- RULE 2: the stamps go backwards. A fully stamped log can still be
#      unreadable if the stamps disagree about when now is, which is why this
#      fails separately from rule 1.
arm "2" "a timestamp that goes backwards by more than the tolerance" \
    'printf "[    0.000100] %s\n[    2.000000] a\n[    0.500000] b\n%s\n" "$START" "$BANNER"' \
    caught "backwards"

# ---- THE TOLERANCE IS REAL AND MUST NOT FIRE. Three PIT ticks: the ring-3 stamp
#      rounds down where the kernel's does not, so a small backwards step is the
#      system working. An arm that ignored this would make the checker unusable
#      the first time ring 3 printed next to the kernel.
arm "2b" "a backwards step INSIDE the tolerance is not a defect" \
    'printf "[    0.000100] %s\n[    1.000000] a\n[    0.990000] b\n%s\n" "$START" "$BANNER"' \
    clean

# ---- THE SILENT DIRECTION.
arm "3a" "a clean, fully stamped log" 'good_log' clean

# ---- WHAT IS OUTSIDE THE WINDOW IS NOT ITS BUSINESS. The shell's output is not
#      stamped and must not be: the window closes at the banner. This is the
#      property the neofetch banner's row-0 title depends on.
arm "3b" "unstamped lines AFTER the session banner are outside the window" \
    'good_log; printf "horus login: \nuid=0 (root)\n"' \
    clean

# ---- THE THREE BROKEN-BOOT GUARDS. Each is a distinct answer, and the
#      distinction is the point: "nothing was checked" must never read as "PASS".
arm "4a" "a boot that never reached the kernel's first message" \
    'printf "GRUB loading...\nsome noise\n"' \
    caught "broken boot"

arm "4b" "a boot that never reached the session" \
    'printf "[    0.000100] %s\n[    0.002000] paging: ok\n" "$START"' \
    caught "the window has no end"

# The checker also guards an EMPTY window, and that guard is not reachable from
# a real log: the window starts AT the kernel's first message, so it always
# contains at least that line. This arm records the nearest reachable case -- a
# boot that reaches the session immediately -- and that it is correctly clean
# rather than an error. The empty-window branch stays as defence with no arm,
# which is worth saying out loud rather than leaving as an untested line.
arm "4c" "a boot that reaches the session immediately still has the start line in its window" \
    'printf "[    0.000100] %s\n%s\n" "$START" "$BANNER"' \
    clean

# ---- The END_RULE alternative: a banner drawn as a box closes the window on its
#      top rule, not on the title. Kept as a guard for the day somebody puts a
#      rule back above the title.
arm "5" "a box rule closes the window as well as the title text" \
    'printf "[    0.000100] %s\n[    0.002000] paging: ok\n  +----------------+\n  | unstamped box |\n" "$START"' \
    clean

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
