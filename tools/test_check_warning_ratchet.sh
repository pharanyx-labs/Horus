#!/bin/sh
# Falsify tools/check_warning_ratchet.py. One arm per way the ceiling can lie.
#
# The mutations are files under /tmp. Nothing here touches the working tree.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CHECK="$ROOT/tools/check_warning_ratchet.py"
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

# $1 id, $2 expect (fail|pass), $3 description, $4 setup function, $5 needle.
# The setup runs with cwd the temp dir. It may rewrite log and base. If it
# writes args, one checker argument per line, those replace --establish.
# A parent path has to be created here: the caller cannot see this directory.
arm() {
  id=$1
  expect=$2
  desc=$3
  setup=$4
  needle=$5
  d=$(mktemp -d)
  cat > "$d/log" << 'EOF'
src/kernel/smp.c:76:12: warning: 'smp_check_in' defined but not used [-Wunused-function]
src/kernel/smp.c:91:39: warning: 'smp_park_refused' defined but not used [-Wunused-function]
EOF
  cat > "$d/base" << 'EOF'
# ceiling
ceiling: 2
src/kernel/smp.c -Wunused-function smp_check_in
src/kernel/smp.c -Wunused-function smp_park_refused
EOF
  if ! (cd "$d" && "$setup"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  set --
  if [ -f "$d/args" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      set -- "$@" "$line"
    done < "$d/args"
  else
    set -- --establish
  fi
  out=$(python3 "$CHECK" "$d/log" --baseline "$d/base" "$@" 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT: $desc"
    elif ! printf '%s\n' "$out" | grep -q "^warning-ratchet: "; then
      fail "$id" "caught, but not as a warning-ratchet finding: $desc"
      printf '%s\n' "$out" | head -5
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "caught, but not for the right reason: $desc"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "caught: $desc"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc): $desc"
      printf '%s\n' "$out" | head -8
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "passed for the wrong reason: $desc"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "passed: $desc"
    fi
  fi
  _rmtree "$d"
}

w_same() { :; }

w_extra() {
  printf '%s\n' "src/kernel/smp.c:1:1: warning: 'smp_new' defined but not used [-Wunused-function]" >> log
}

w_dropped() {
  cat > base << 'EOF'
# ceiling
ceiling: 3
src/kernel/smp.c -Wunused-function smp_check_in
src/kernel/smp.c -Wunused-function smp_park_refused
src/kernel/smp.c -Wunused-function smp_gone
EOF
}

w_ceiling() {
  python3 -c 'from pathlib import Path; p = Path("base"); p.write_text(p.read_text().replace("ceiling: 2", "ceiling: 9", 1))'
}

w_neither() { : > args; }

w_parent_same() {
  cp base parent
  printf '%s\n' --parent "$(pwd)/parent" > args
}

w_growth() {
  cp base parent
  printf '%s\n' "src/kernel/smp.c:1:1: warning: 'smp_new' defined but not used [-Wunused-function]" >> log
  cat > base << 'EOF'
# ceiling
ceiling: 3
src/kernel/smp.c -Wunused-function smp_check_in
src/kernel/smp.c -Wunused-function smp_park_refused
src/kernel/smp.c -Wunused-function smp_new
EOF
  printf '%s\n' --parent "$(pwd)/parent" > args
}

w_shrink() {
  cat > parent << 'EOF'
# ceiling
ceiling: 3
src/kernel/smp.c -Wunused-function smp_check_in
src/kernel/smp.c -Wunused-function smp_park_refused
src/kernel/smp.c -Wunused-function smp_extra
EOF
  printf '%s\n' --parent "$(pwd)/parent" > args
}

w_quotes() {
  python3 -c 'from pathlib import Path; Path("log").write_text("src/kernel/smp.c:76:12: warning: \u2018smp_check_in\u2019 defined but not used [-Wunused-function]\nsrc/kernel/smp.c:91:39: warning: \u2018smp_park_refused\u2019 defined but not used [-Wunused-function]\n")'
}

w_nameless() {
  printf '%s\n' 'src/kernel/smp.c:1:1: warning: defined but not used [-Wunused-function]' >> log
}

w_empty_base() {
  printf '%s\n' 'ceiling: 0' > base
}

w_missing_parent() {
  printf '%s\n' --parent "$(pwd)/no-such-parent" > args
}

echo "Falsifying tools/check_warning_ratchet.py:"

arm W1 pass "the log and the baseline are the same set" w_same "ceiling holds"
arm W2 fail "a warning the baseline does not list" w_extra "new warning"
arm W3 fail "a baseline row the compiler no longer emits" w_dropped "no longer emitted"
arm W4 fail "the ceiling line does not match the rows" w_ceiling "ceiling is"
arm W5 fail "neither a parent nor --establish" w_neither "neither a parent"
arm W6 pass "main has the same rows" w_parent_same "ceiling holds"
arm W7 fail "a row main does not have, which is growth" w_growth "ceiling grew"
arm W8 pass "main has a row this build no longer emits, which is a shrink" w_shrink "ceiling holds"
arm W9 pass "the compiler quoted the function with locale quotes" w_quotes "ceiling holds"
arm W10 fail "a warning that names no function" w_nameless "names no function"
arm W11 fail "an empty baseline while the log has a warning" w_empty_base "new warning"
arm W12 fail "a parent path that is not there" w_missing_parent "is missing"

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
