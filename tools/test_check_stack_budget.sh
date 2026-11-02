#!/bin/sh
# Falsify tools/check_stack_budget.py. One arm per way the depth can lie.
#
# A frame planted under /tmp is the control arm. The same number of bytes off
# the interrupt path must pass, so this is not a per-function maximum. Nothing
# here edits the kernel, and nothing is planted into the tree.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CHECK="$ROOT/tools/check_stack_budget.py"
PASSES=0
FAILS=0

pass() { echo "  $1: $2"; PASSES=$((PASSES + 1)); }
fail() { echo "  $1: $2"; FAILS=$((FAILS + 1)); }

_rmtree() {
  case "${1:-}" in
    /tmp/*|/var/tmp/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}': not a temp directory" >&2
       exit 1 ;;
  esac
}

# $1 id, $2 expect, $3 description, $4 setup, $5 needle.
# Setup runs in the temp dir and writes args, one checker argument per line.
arm() {
  id=$1
  expect=$2
  desc=$3
  setup=$4
  needle=$5
  d=$(mktemp -d)
  if ! (cd "$d" && "$setup"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  set --
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    set -- "$@" "$line"
  done < "$d/args"
  out=$(python3 "$CHECK" "$@" 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT: $desc"
    elif ! printf '%s\n' "$out" | grep -q "^stack-budget: "; then
      fail "$id" "caught, but not as a stack-budget finding: $desc"
      printf '%s\n' "$out" | head -5
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "caught, but not for the right reason: $desc"
      printf '%s\n' "$out" | head -12
    else
      pass "$id" "caught: $desc"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc): $desc"
      printf '%s\n' "$out" | head -12
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "passed for the wrong reason: $desc"
      printf '%s\n' "$out" | head -12
    else
      pass "$id" "passed: $desc"
    fi
  fi
  _rmtree "$d"
}

copy_reports() {
  dest=$1
  (cd "$ROOT" && find src \( -name '*.su' -o -name '*.ci' \) -print) | while IFS= read -r rel; do
    mkdir -p "$dest/$(dirname "$rel")"
    cp "$ROOT/$rel" "$dest/$rel"
  done
  n=$(find "$dest" -name '*.su' | wc -l)
  [ "$n" -gt 0 ]
}

s_empty() {
  mkdir reports
  printf '%s\n' --reports "$(pwd)/reports" --no-source --root rec --budget 1000 > args
}

s_self() {
  mkdir reports
  printf 'rec.c:1:1:rec\t8000\tstatic\n' > reports/rec.su
  printf '%s\n' 'edge: { sourcename: "rec" targetname: "rec" label: "plant" }' > reports/rec.ci
  printf '%s\n' --reports "$(pwd)/reports" --no-source --root rec --budget 100000 > args
}

s_cycle() {
  mkdir reports
  printf 'a.c:1:1:left\t100\tstatic\n' > reports/a.su
  printf 'a.c:1:1:right\t100\tstatic\n' >> reports/a.su
  printf '%s\n' 'edge: { sourcename: "left" targetname: "right" label: "plant" }' > reports/a.ci
  printf '%s\n' 'edge: { sourcename: "right" targetname: "left" label: "plant" }' >> reports/a.ci
  printf '%s\n' --reports "$(pwd)/reports" --no-source --root left --budget 100000 > args
}

s_chain() {
  mkdir reports
  printf 'a.c:1:1:interrupt_handler64\t96\tstatic\n' > reports/a.su
  printf 'a.c:1:1:rec\t100\tstatic\n' >> reports/a.su
  printf '%s\n' 'edge: { sourcename: "interrupt_handler64" targetname: "rec" label: "plant" }' > reports/a.ci
  printf '%s\n' 'edge: { sourcename: "rec" targetname: "rec" label: "plant" }' >> reports/a.ci
  printf '%s\n' --reports "$(pwd)/reports" --no-source --root interrupt_handler64 --budget 100000 > args
}

s_short() {
  mkdir reports
  printf 'a.c:1:1:rootfn\t40\tstatic\n' > reports/a.su
  printf 'a.c:1:1:leaf\t24\tstatic\n' >> reports/a.su
  printf '%s\n' 'edge: { sourcename: "rootfn" targetname: "leaf" label: "plant" }' > reports/a.ci
  printf '%s\n' --reports "$(pwd)/reports" --no-source --root rootfn --budget 1000 > args
}

# The tree's own reports, plus one planted frame. source stays the real kernel.
plant() {
  id=$1
  expect=$2
  desc=$3
  with_edge=$4
  d=$(mktemp -d)
  if ! copy_reports "$d"; then
    fail "$id" "the tree has no stack reports to copy"
    _rmtree "$d"
    return
  fi
  printf 'plant.c:1:1:planted_deep\t70000\tstatic\n' > "$d/src/plant.su"
  if [ "$with_edge" = yes ]; then
    printf '%s\n' 'edge: { sourcename: "interrupt_handler64" targetname: "planted_deep" label: "plant" }' > "$d/src/plant.ci"
  fi
  echo "  $id: measuring ($desc)"
  out=$(python3 "$CHECK" --reports "$d/src" 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT: $desc"
      printf '%s\n' "$out" | tail -20
    elif ! printf '%s\n' "$out" | grep -q "^stack-budget: over$"; then
      fail "$id" "caught, but not as an over-budget path: $desc"
      printf '%s\n' "$out" | tail -20
    else
      pass "$id" "caught: $desc"
    fi
  else
    depth=$(printf '%s\n' "$out" | sed -n 's/^stack-budget: interrupt_handler64 \([0-9][0-9]*\) of [0-9][0-9]*$/\1/p')
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc): $desc"
      printf '%s\n' "$out" | tail -20
    elif ! printf '%s\n' "$out" | grep -q "^stack-budget: ok$"; then
      fail "$id" "no ok line: $desc"
      printf '%s\n' "$out" | tail -20
    elif [ -z "$depth" ] || [ "$depth" -lt 10000 ]; then
      fail "$id" "interrupt depth '${depth:-missing}' is not the walked path: $desc"
      printf '%s\n' "$out" | tail -20
    else
      pass "$id" "passed: $desc"
    fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_stack_budget.py:"

arm S1 fail "no stack reports at all" s_empty "no .su reports"
arm S2 fail "a self-call with no source bound" s_self "is unbounded"
arm S3 fail "a cycle and no proof the lock is not re-entered" s_cycle "is unbounded"
arm S4 fail "the interrupt root reaches an unbounded self-call" s_chain "is unbounded"
arm S5 pass "a short path under an explicit budget" s_short "stack-budget: rootfn 64 of 1000"

echo "  S6: measuring the unmutated tree"
out=$(python3 "$CHECK" 2>&1)
rc=$?
edges=$(printf '%s\n' "$out" | sed -n 's/^stack-budget: syscall-edges \([0-9][0-9]*\)$/\1/p')
depth=$(printf '%s\n' "$out" | sed -n 's/^stack-budget: interrupt_handler64 \([0-9][0-9]*\) of [0-9][0-9]*$/\1/p')
if [ "$rc" -ne 0 ]; then
  fail S6 "the unmutated tree was refused (rc=$rc)"
  printf '%s\n' "$out" | tail -30
elif ! printf '%s\n' "$out" | grep -q "^stack-budget: ok$"; then
  fail S6 "the unmutated tree did not end ok"
  printf '%s\n' "$out" | tail -30
elif [ -z "$edges" ] || [ "$edges" -lt 50 ]; then
  fail S6 "syscall edges '${edges:-missing}' are not the ship table"
  printf '%s\n' "$out" | tail -30
elif [ -z "$depth" ] || [ "$depth" -lt 10000 ]; then
  fail S6 "interrupt depth '${depth:-missing}' is not the walked path"
  printf '%s\n' "$out" | tail -30
else
  pass S6 "the unmutated tree, $edges syscall edges, interrupt depth $depth"
fi

plant S7 fail "a frame of 70000 bytes on the interrupt path" yes
plant S8 pass "the same frame with no edge from the interrupt path" no

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
