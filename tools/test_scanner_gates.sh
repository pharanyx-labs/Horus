#!/bin/sh
# Falsify the roadmap 4.16 scanners. One planted defect per rule, the
# unmutated tree, and the two silent directions: a control arm the ship
# build does not compile must not fail the scan, and an innocuous file
# must not fail it either. A scanner that rejects everything satisfies the
# planted arms and is still wrong.
#
# Nothing here can leave the tree modified.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PASSES=0
FAILS=0

pass() { echo "  $1: $2"; PASSES=$((PASSES + 1)); }
fail() { echo "  $1: $2"; FAILS=$((FAILS + 1)); }

_rmtree() {
  case "${1:-}" in
    /tmp/*|/var/tmp/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2
       exit 1 ;;
  esac
}

# $1 id, $2 expect (caught|clean), $3 scanner (cppcheck|flawfinder|semgrep), $4 body
arm() {
  id=$1
  expect=$2
  which=$3
  body=$4
  d=$(mktemp -d)
  printf '%s\n' "$body" > "$d/plant.c"
  case "$which" in
    cppcheck) "$ROOT/tools/cppcheck_gate.sh" "$d/plant.c" >/tmp/horus-scan-out 2>&1 ;;
    flawfinder) "$ROOT/tools/flawfinder_gate.sh" "$d/plant.c" >/tmp/horus-scan-out 2>&1 ;;
    semgrep) python3 "$ROOT/tools/semgrep_horus.py" "$d/plant.c" >/tmp/horus-scan-out 2>&1 ;;
    *) fail "$id" "unknown scanner $which"; _rmtree "$d"; return ;;
  esac
  rc=$?
  if [ "$expect" = caught ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT"
      sed -n '1,8p' /tmp/horus-scan-out
    else
      pass "$id" "caught"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc)"
      sed -n '1,12p' /tmp/horus-scan-out
    else
      pass "$id" "clean, correctly"
    fi
  fi
  _rmtree "$d"
}

echo "Falsifying the roadmap 4.16 scanners:"

arm C1 caught cppcheck 'int f(void) { *(volatile int *)0 = 1; return 0; }'

arm C3 caught cppcheck 'int f(void) { int x; return x; }'

# Both ids of the same finding: comparePointers on 2.13, subtractPointers
# on 2.17. A global suppression of either name would let this through on
# the version that uses that name, so the plant is the subtraction itself.
arm C4 caught cppcheck 'int f(void) {
  extern unsigned char a[];
  extern unsigned char b[];
  return (int)(b - a);
}'

arm C2 clean cppcheck 'int f(void) { return 1; }'

arm F1 caught flawfinder '#include <stdio.h>
void f(void) { char b[8]; gets(b); }'

arm F2 clean flawfinder 'int f(void) { return 1; }'

arm S1 caught semgrep 'unsigned long virt_to_phys(void *);
void *PHYS_KVA(unsigned long);
unsigned long mix(unsigned long frame) { return virt_to_phys(PHYS_KVA(frame)); }'

arm S2 caught semgrep 'int current_user_is_admin(void);
void cap_grant_into(void);
void grant(void) {
  if (current_user_is_admin()) {
    cap_grant_into();
  }
}'

arm S3 caught semgrep 'void *memcpy(void *, const void *, unsigned long);
typedef unsigned long uintptr_t;
struct frame { unsigned long rbx; };
void steal(struct frame *r) {
  char buf[8];
  memcpy(buf, (void *)(uintptr_t)r->rbx, 8);
}'

arm S4 caught semgrep 'struct capability *cap_lookup(int, int, int);
void gate(void) { cap_lookup(3, 0, 0); }'

arm S5 clean semgrep '#ifdef LEGACY_SYSCALLS_PRESENT
struct capability *cap_lookup(int, int, int);
void gate(void) { cap_lookup(3, 0, 0); }
#endif
int kept(void) { return 1; }'

arm S6 caught semgrep 'void h_clear(void);
struct row { void (*h)(void); int slot; int rights; int type; };
struct row table[] = {
  [SYS_CLEAR] = { h_clear, 3, 4, 0 },
};'

arm S7 caught semgrep 'typedef unsigned int uint32_t;
void *memcpy(void *, const void *, unsigned long);
void copy_wide(unsigned long len, void *dst, void *src) {
  if ((uint32_t)len < 8)
    memcpy(dst, src, len);
}'

arm S8 clean semgrep 'int f(void) { return 1; }'

echo "  unmutated tree:"
if "$ROOT/tools/cppcheck_gate.sh" >/tmp/horus-scan-out 2>&1; then
  pass T1 "cppcheck clean on the unmutated tree"
else
  fail T1 "cppcheck failed on the unmutated tree"
  sed -n '1,20p' /tmp/horus-scan-out
fi
if "$ROOT/tools/flawfinder_gate.sh" >/tmp/horus-scan-out 2>&1; then
  pass T2 "flawfinder clean on the unmutated tree"
else
  fail T2 "flawfinder failed on the unmutated tree"
  sed -n '1,20p' /tmp/horus-scan-out
fi
if python3 "$ROOT/tools/semgrep_horus.py" >/tmp/horus-scan-out 2>&1; then
  pass T3 "semgrep clean on the unmutated tree"
else
  fail T3 "semgrep failed on the unmutated tree"
  sed -n '1,30p' /tmp/horus-scan-out
fi

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
