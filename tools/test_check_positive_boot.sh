#!/bin/sh
# Falsify tools/check_positive_boot.py. One arm per way the census can lie.
#
# The mutations are applied to a copy. Nothing here touches the working tree.
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
  mkdir -p "$1/tools" "$1/.github"
  cp "$ROOT/SECURITY.md" "$1/"
  cp "$ROOT/tools/check_positive_boot.py" "$ROOT/tools/check_invariants.py" "$1/tools/"
  cp "$ROOT/.github/positive-boot.yml" "$1/.github/"
}

# $1 id, $2 expect (fail|pass), $3 description, $4 mutation (shell, cwd=$d)
arm() {
  id=$1
  expect=$2
  desc=$3
  mut=$4
  d=$(mktemp -d)
  mktree "$d"
  if ! (cd "$d" && eval "$mut"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  out=$(cd "$d" && python3 tools/check_positive_boot.py 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT -- $desc"
    elif ! printf '%s\n' "$out" | grep -q "^positive-boot: "; then
      fail "$id" "caught, but not as a positive-boot finding -- $desc"
      printf '%s\n' "$out" | head -5
    else
      pass "$id" "caught -- $desc"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc) -- $desc"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "passed -- $desc"
    fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_positive_boot.py:"

arm U pass "the unmutated copy" "true"

arm A fail "a new row whose witness is only a boot" "python3 - <<'PY'
from pathlib import Path
p = Path('SECURITY.md')
text = p.read_text()
row = '| S999 | A planted claim with no arm | a mechanism | \`make smoke-aspace\` |\n'
# Insert before the first line that is not a property row after the table.
lines = text.splitlines(keepends=True)
out = []
placed = False
for i, line in enumerate(lines):
    out.append(line)
    if (not placed and line.startswith('| S')
            and i + 1 < len(lines) and not lines[i + 1].startswith('| S')):
        out.append(row)
        placed = True
if not placed:
    raise SystemExit('no insertion point')
p.write_text(''.join(out))
PY"

arm B fail "an id dropped while the row is still only a boot" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/positive-boot.yml')
lines = [ln for ln in p.read_text().splitlines(keepends=True) if not ln.startswith('  - S15:')]
if len(lines) == len(p.read_text().splitlines()):
    raise SystemExit('S15 not removed')
p.write_text(''.join(lines))
PY"

arm C fail "an arm added to a witness that stays on the census" "python3 - <<'PY'
from pathlib import Path
p = Path('SECURITY.md')
lines = p.read_text().splitlines()
hit = False
for i, line in enumerate(lines):
    if line.startswith('| S15 |') and line.rstrip().endswith('|'):
        lines[i] = line.rstrip()[:-1].rstrip() + ' arms: \`smoke-aspace-control\` (\`ASPACE_UNCHECKED=1\`) |'
        hit = True
        break
if not hit:
    raise SystemExit('S15 row missing')
p.write_text('\n'.join(lines) + '\n')
PY"

arm D pass "the same arm, and the id leaves the census" "python3 - <<'PY'
from pathlib import Path
sec = Path('SECURITY.md')
lines = sec.read_text().splitlines()
hit = False
for i, line in enumerate(lines):
    if line.startswith('| S15 |') and line.rstrip().endswith('|'):
        lines[i] = line.rstrip()[:-1].rstrip() + ' arms: \`smoke-aspace-control\` (\`ASPACE_UNCHECKED=1\`) |'
        hit = True
        break
if not hit:
    raise SystemExit('S15 row missing')
sec.write_text('\n'.join(lines) + '\n')
cen = Path('.github/positive-boot.yml')
kept = [ln for ln in cen.read_text().splitlines(keepends=True) if not ln.startswith('  - S15:')]
cen.write_text(''.join(kept))
PY"

arm E fail "a host-only property listed as a positive boot" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/positive-boot.yml')
text = p.read_text()
if '  - S2:' in text:
    raise SystemExit('S2 already listed')
p.write_text(text.rstrip() + '\n  - S2: CI job rust, which is not a boot\n')
PY"

arm F fail "a table too small to be a reading" "python3 - <<'PY'
from pathlib import Path
Path('SECURITY.md').write_text(
    '| # | Claim | Mechanism | Witness |\n'
    '|---|---|---|---|\n'
    '| S1 | one row | a mechanism | \`make smoke-aspace\` |\n'
)
PY"

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
