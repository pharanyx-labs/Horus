#!/usr/bin/env bash
# Falsify tools/check_kani_arms.py -- one arm per rule, the silent direction,
# and the self-check.
#
# The registry it guards is what keeps every Kani proof able to fail: if an arm
# silently stopped applying, or a new proof landed without one, the nightly run
# would report fewer arms and still pass.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/rust/src" "$1/.github"
  cp "$ROOT/tools/check_kani_arms.py" "$1/tools/"
  cp "$ROOT/.github/kani-arms.yml" "$ROOT/.github/kani-harnesses.yml" "$1/.github/"
  cp "$ROOT"/rust/src/*.rs "$1/rust/src/"
}

# Refuse to delete anything that is not a fresh temp directory (the guard every
# sibling suite carries since a loop variable once pointed one at tools/).
_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2
       exit 1 ;;
  esac
}

arm () {
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_kani_arms.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF -- "$want" <<<"$out"; then
      echo "  $rule: caught but did not say '$want' -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

# Edit the registry with a small Python body ($1), given `d` (the parsed YAML).
reg () {
  python3 - "$1" <<'PY'
import pathlib, sys, yaml
p = pathlib.Path('.github/kani-arms.yml'); d = yaml.safe_load(p.read_text())
exec(sys.argv[1])
p.write_text(yaml.safe_dump(d, sort_keys=False))
PY
}

echo "Falsifying tools/check_kani_arms.py:"

arm "1" "an arm naming a proof that does not exist" \
    "reg \"d['arms'][0]['harness'] = 'no_such_proof'\"" caught "no_such_proof"
arm "2a" "an arm on a file outside rust/" \
    "reg \"d['arms'][0]['file'] = 'tools/check_kani_arms.py'\"" caught "not a file under rust/"
arm "2b" "an arm whose find text no longer occurs (the code moved)" \
    "reg \"d['arms'][0]['find'] = 'text that is nowhere in the crate'\"" caught "occurs 0 times"
arm "2c" "an arm whose find text occurs twice (ambiguous)" \
    "python3 - <<'PY'
import pathlib, yaml
a = yaml.safe_load(open('.github/kani-arms.yml'))['arms'][0]
p = pathlib.Path(a['file']); p.write_text(p.read_text() + '\n/*\n' + a['find'] + '\n*/\n')
PY" caught "occurs 2 times"
arm "2d" "an arm whose replacement is its find text" \
    "reg \"d['arms'][0]['replace'] = d['arms'][0]['find']\"" caught "mutates nothing"
arm "3" "a gating proof with no arm and no reason" \
    "reg \"d['arms'] = [a for a in d['arms'] if a['harness'] != 'mint_keeps_the_token']\"" caught "mint_keeps_the_token: a gating proof with no control arm"
arm "4a" "a proof both armed and listed as unarmed" \
    "reg \"d['unarmed'] = {d['arms'][0]['harness']: 'planted by the falsification suite'}\"" caught "also listed as unarmed"
arm "4b" "an unarmed entry naming no real proof" \
    "reg \"d['unarmed'] = {'no_such_proof': 'planted by the falsification suite'}\"" caught "not a gating proof"
arm "4c" "an unarmed entry with a token reason" \
    "reg \"d['arms'] = [a for a in d['arms'] if a['harness'] != 'mint_keeps_the_token']; d['unarmed'] = {'mint_keeps_the_token': 'later'}\"" caught "no substantive reason"
arm "5" "two arms with one id" \
    "reg \"d['arms'][1]['id'] = d['arms'][0]['id']\"" caught "used more than once"

# THE SILENT DIRECTION: the real registry is clean.
arm "6" "the real registry and crate" "true" clean

# THE SELF-CHECK: with no gating list to compare against, rules 1 and 3 would
# pass vacuously; the checker must refuse that rather than report a clean tree.
arm "7" "an empty gating list does not report a clean registry" \
    "python3 -c \"import pathlib; pathlib.Path('.github/kani-harnesses.yml').write_text('gating: []\\n')\"" caught "is empty"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
