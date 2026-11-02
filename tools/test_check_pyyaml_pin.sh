#!/bin/sh
# Falsify tools/check_pyyaml_pin.py, then show a substituted wheel is refused.
#
# The mutations are applied to a copy. Nothing here touches the working tree.
# The wheel check needs the network. A download that fails is a failure.
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
  cp "$ROOT/.github/workflows/ci.yml" "$1/.github/workflows/"
  cp "$ROOT/.github/pyyaml-pin.txt" "$1/.github/"
  cp "$ROOT/tools/check_pyyaml_pin.py" "$1/tools/"
}

# $1 id, $2 expect (fail|pass), $3 description, $4 mutation, $5 needle
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
  out=$(cd "$d" && python3 tools/check_pyyaml_pin.py 2>&1)
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

echo "Falsifying tools/check_pyyaml_pin.py:"

arm U pass "the unmutated copy" "true" "pyyaml-pin: ok"

arm H1 fail "an install that does not require hashes" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/ci.yml')
t = p.read_text()
old = '--require-hashes '
if old not in t:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '', 1))
PY" "does not require hashes"

arm H2 fail "an install that does not name the pin file" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/ci.yml')
t = p.read_text()
old = '-r .github/pyyaml-pin.txt'
if old not in t:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, 'pyyaml==6.0.3', 1))
PY" "does not use the pin file"

arm H3 fail "an install that may pull another package" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/ci.yml')
t = p.read_text()
old = '--no-deps '
if old not in t:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '', 1))
PY" "can pull another dependency"

arm P1 fail "the pin names a different version" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/pyyaml-pin.txt')
t = p.read_text()
old = 'pyyaml==6.0.3'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, 'pyyaml==6.0.2', 1))
PY" "requirement is not pyyaml==6.0.3"

arm P2 fail "the pin names a second package" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/pyyaml-pin.txt')
t = p.read_text()
if not t.endswith('\n'):
    t += '\n'
p.write_text(t + 'requests==2.32.0\n')
PY" "expected one requirement"

arm M1 fail "the pin file is missing" "rm .github/pyyaml-pin.txt" "pin: cannot read"

arm I1 fail "a plain version pin is added beside the file" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/ci.yml')
t = p.read_text()
old = '        run: pip install --disable-pip-version-check --require-hashes --no-deps -r .github/pyyaml-pin.txt\n'
extra = old + '        run: pip install pyyaml==6.0.3\n'
if t.count(old) < 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, extra, 1))
PY" "does not require hashes"

echo "Substituted wheel:"
d=$(mktemp -d)
if ! python3 - "$ROOT" "$d" <<'PY'
import hashlib, json, sys, urllib.request
from pathlib import Path
root, dest = Path(sys.argv[1]), Path(sys.argv[2])
pin = (root / ".github/pyyaml-pin.txt").read_text(encoding="utf-8")
recorded = set()
for line in pin.splitlines():
    line = line.split("#", 1)[0]
    token = "--hash=sha256:"
    if token not in line:
        continue
    recorded.add(line.split(token, 1)[1].strip().rstrip("\\").strip())
url = "https://pypi.org/pypi/PyYAML/6.0.3/json"
with urllib.request.urlopen(url, timeout=60) as resp:
    published = {item["digests"]["sha256"] for item in json.load(resp)["urls"]}
if recorded != published:
    extra = sorted(recorded - published)[:1]
    missing = sorted(published - recorded)[:1]
    raise SystemExit(
        "pyyaml-pin: published set differs"
        f" extra={extra} missing={missing}"
    )
print("pyyaml-pin: published set matches")
PY
then
  fail W1 "published hashes do not match the pin"
else
  pass W1 "published hashes match the pin"
fi

good="$d/good"
bad="$d/bad"
okdest="$d/ok"
mkdir -p "$good" "$bad"
# ubuntu runners have python3 -m pip. A developer tree may only have pip3.
if python3 -m pip --version >/dev/null 2>&1; then
  pip_cmd() { python3 -m pip "$@"; }
elif command -v pip3 >/dev/null 2>&1; then
  pip_cmd() { pip3 "$@"; }
else
  fail W2 "pip is not available"
  pip_cmd() { return 127; }
fi
if ! pip_cmd download pyyaml==6.0.3 --no-deps --only-binary=:all: \
    --disable-pip-version-check -d "$good" >"$d/download.txt" 2>&1; then
  fail W2 "could not download the wheel"
  cat "$d/download.txt"
else
  wheel=$(find "$good" -name '*.whl' | head -n 1)
  if [ -z "$wheel" ]; then
    fail W2 "download produced no wheel"
  else
    sum=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$wheel")
    if ! grep -q "$sum" "$ROOT/.github/pyyaml-pin.txt"; then
      fail W2 "downloaded wheel hash is not in the pin"
    else
      pass W2 "downloaded wheel hash is in the pin"
      python3 -c 'import sys; p=sys.argv[1]; d=open(p,"rb").read(); open(sys.argv[2],"wb").write(d[:-1]+bytes([d[-1]^0xFF]))' \
        "$wheel" "$bad/$(basename "$wheel")"
      if pip_cmd install --isolated --disable-pip-version-check \
          --require-hashes --no-deps --no-index --find-links "$bad" \
          --target "$d/refused" -r "$ROOT/.github/pyyaml-pin.txt" \
          >"$d/refused.txt" 2>&1; then
        fail W3 "tampered wheel installed"
      else
        pass W3 "tampered wheel refused"
      fi
      if pip_cmd install --isolated --disable-pip-version-check \
          --require-hashes --no-deps --no-index --find-links "$good" \
          --target "$okdest" -r "$ROOT/.github/pyyaml-pin.txt" \
          >"$d/ok.txt" 2>&1; then
        pass W4 "recorded wheel installs"
      else
        fail W4 "recorded wheel did not install"
        cat "$d/ok.txt"
      fi
    fi
  fi
fi
_rmtree "$d"

echo "pyyaml-pin harness: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
