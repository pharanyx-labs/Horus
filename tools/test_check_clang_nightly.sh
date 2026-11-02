#!/bin/sh
# Falsify tools/check_clang_nightly.py. Mutations are applied to a copy.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
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

mktree() {
  mkdir -p "$1/.github/workflows" "$1/tools"
  cp "$ROOT/.github/workflows/clang-nightly.yml" "$1/.github/workflows/"
  cp "$ROOT/Makefile" "$1/Makefile"
  cp "$ROOT/tools/check_clang_nightly.py" "$1/tools/"
}

arm() {
  id=$1
  expect=$2
  desc=$3
  mut=$4
  needle=$5
  d=$(mktemp -d)
  mktree "$d"
  if ! (cd "$d" && eval "$mut"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  out=$(cd "$d" && python3 tools/check_clang_nightly.py 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT ($desc)"
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "caught, but not as $needle ($desc)"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "caught ($desc)"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc) ($desc)"
      printf '%s\n' "$out" | head -8
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "passed without $needle ($desc)"
    else
      pass "$id" "passed ($desc)"
    fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_clang_nightly.py:"

arm U pass "the unmutated copy" "true" "clang-nightly: ok"

arm R1 fail "the bare-metal Rust target is not added" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/clang-nightly.yml')
t = p.read_text()
old = '        run: rustup target add x86_64-unknown-none\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '', 1))
PY" "lost rustup target add x86_64-unknown-none"

arm C1 fail "the compiler presence check is removed" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/clang-nightly.yml')
t = p.read_text()
old = '          command -v clang\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '', 1))
PY" "lost command -v clang"

arm C2 fail "a failed link is ignored" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/clang-nightly.yml')
t = p.read_text()
old = '          make CLANG=1 kernel.elf\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '          make CLANG=1 kernel.elf || true\n', 1))
PY" "swallowed failure"

arm C3 fail "the job tolerates a failed step" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/clang-nightly.yml')
t = p.read_text()
old = '    runs-on: ubuntu-latest\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, old + '    continue-on-error: true\n', 1))
PY" "continue-on-error"

arm C4 fail "the build is not the Clang one" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/clang-nightly.yml')
t = p.read_text()
old = 'make CLANG=1 kernel.elf'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, 'make kernel.elf', 1))
PY" "lost make CLANG=1 kernel.elf"

arm M1 fail "CLANG=1 still compiles with GCC" "python3 - <<'PY'
from pathlib import Path
p = Path('Makefile')
t = p.read_text()
old = 'CC     = clang\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, 'CC     = gcc\n', 1))
PY" "does not select clang"

echo "clang-nightly harness: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
