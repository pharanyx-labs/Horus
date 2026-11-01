#!/bin/sh
# Falsify tools/check_codeql_scope.py. The unmutated tree passes. Each arm
# puts one defect back: the job calling itself advisory, the build step
# compiling something other than the default kernel, a trusted binary
# dropped from the kernel link, and the same binary dropped from the set
# make actually compiles.
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

mktree() {
  d=$1
  mkdir -p "$d/.github/workflows" "$d/tools"
  cp "$ROOT/.github/workflows/codeql.yml" "$d/.github/workflows/codeql.yml"
  cp "$ROOT/Makefile" "$d/Makefile"
  cp "$ROOT/tools/check_codeql_scope.py" "$d/tools/check_codeql_scope.py"
}

arm() {
  id=$1
  desc=$2
  mut=$3
  expect=$4
  d=$(mktemp -d)
  mktree "$d"
  (cd "$d" && eval "$mut") || { fail "$id" "MUTATION FAILED ($desc)"; _rmtree "$d"; return; }
  out=$(python3 "$d/tools/check_codeql_scope.py" "$d" 2>&1)
  rc=$?
  if [ "$expect" = caught ]; then
    if [ "$rc" -eq 0 ]; then fail "$id" "NOT CAUGHT -- $desc"
    else pass "$id" "caught -- $desc"; fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT -- $desc"
      printf '%s\n' "$out" | head -4
    else
      pass "$id" "clean, correctly -- $desc"
    fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_codeql_scope.py:"

arm 1 "the unmutated workflow and Makefile" "true" clean

arm 2 "the build step compiles one kernel object" \
  "sed -i 's/run: make$/run: make src\\/kernel\\/main.o/' .github/workflows/codeql.yml" \
  caught

arm 3 "the header calls the required job advisory" \
  "printf '\n# Advisory by design\n' >> .github/workflows/codeql.yml" \
  caught

arm 4 "init.bin is dropped from the multiboot link only" \
  "python3 - <<'PY'
from pathlib import Path
p = Path('Makefile')
s = p.read_text()
old = 'src/boot/multiboot.o: userspace/shell.bin userspace/init.bin '
new = 'src/boot/multiboot.o: userspace/shell.bin '
assert old in s, 'link line not found'
p.write_text(s.replace(old, new, 1))
PY" \
  caught

arm 5 "init.bin remains on the link line but is not compiled" \
  "python3 - <<'PY'
from pathlib import Path
p = Path('Makefile')
s = p.read_text()
old = 'SHIPPED_PIE_BINS = userspace/shell.bin userspace/init.bin'
new = 'SHIPPED_PIE_BINS = userspace/shell.bin'
assert old in s
p.write_text(s.replace(old, new, 1))
PY" \
  caught

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
