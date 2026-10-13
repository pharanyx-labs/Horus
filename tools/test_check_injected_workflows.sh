#!/usr/bin/env bash
# Falsify tools/check_injected_workflows.py -- one arm per rule, plus the silent
# direction, against recorded states rather than the live API. The live mode is
# the same check() over a state it builds with `gh api`; what can be got wrong
# offline is the rules, and every one of them is armed here. The last arm is the
# live mode with no way to reach GitHub, which must fail rather than pass.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK="$ROOT/tools/check_injected_workflows.py"
PY="$(command -v python3)"
PASSES=0; FAILS=0
D="$(mktemp -d)"
trap 'case "$D" in /tmp/*) rm -rf "$D";; esac' EXIT

# The state GitHub reported on 2026-10-13, which the record accounts for.
clean_state () {
  cat <<'EOF'
{"workflows": [
  {"path": ".github/workflows/ci.yml", "state": "active"},
  {"path": ".github/workflows/codeql.yml", "state": "active"},
  {"path": "dynamic/dependabot/dependabot-updates", "state": "active"},
  {"path": "dynamic/agents/github-advanced-security", "state": "active"}],
 "latest_runs": {
  "dynamic/dependabot/dependabot-updates": "2026-10-12T18:37:01Z",
  "dynamic/agents/github-advanced-security": "2026-09-20T11:34:02Z"}}
EOF
}

arm () {  # $1 rule, $2 desc, $3 state-mutation (python on `s`), $4 record-mutation (python on `r`), $5 expect, $6 must-say
  local rule="$1" desc="$2" smut="$3" rmut="$4" expect="$5" want="${6:-}" out rc
  clean_state > "$D/state.json"
  cp "$ROOT/.github/injected-workflows.yml" "$D/record.yml"
  "$PY" - "$D/state.json" "$D/record.yml" <<EOF || { echo "  $rule: MUTATION FAILED -- $desc"; FAILS=$((FAILS+1)); return; }
import json, sys, yaml
sp, rp = sys.argv[1], sys.argv[2]
s = json.load(open(sp)); r = yaml.safe_load(open(rp))
$smut
$rmut
json.dump(s, open(sp, "w")); yaml.safe_dump(r, open(rp, "w"))
EOF
  out="$("$PY" "$CHECK" --state "$D/state.json" --record "$D/record.yml" 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not say '$want' -- $desc"; sed 's/^/      /' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; sed 's/^/      /' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
}

echo "Falsifying tools/check_injected_workflows.py:"

arm "0" "the state GitHub reported, and the record as committed" "pass" "pass" clean

arm "1" "an injected workflow nobody recorded" \
  's["workflows"].append({"path": "dynamic/agents/some-new-reviewer", "state": "active"})' "pass" \
  caught "no commit contains"
arm "1b" "a workflow GitHub says is in the tree and is not" \
  's["workflows"].append({"path": ".github/workflows/gone.yml", "state": "active"})' "pass" \
  caught "is not in the tree"
arm "1c" "GitHub reports nothing at all" 's["workflows"] = []' 'r["injected"] = {}' \
  caught "no workflows at all"

arm "2" "the stopped reviewer runs again" \
  's["latest_runs"]["dynamic/agents/github-advanced-security"] = "2026-10-13T20:00:00Z"' "pass" \
  caught "has started again"
arm "2b" "a stopped entry with no last run to hold it to" "pass" \
  'del r["injected"]["dynamic/agents/github-advanced-security"]["last_run"]' \
  caught "no last_run"
arm "2c" "an entry whose may_run is neither true nor false" "pass" \
  'r["injected"]["dynamic/dependabot/dependabot-updates"]["may_run"] = "sometimes"' \
  caught "must be true or false"
arm "2d" "an entry with no reason" "pass" \
  'r["injected"]["dynamic/dependabot/dependabot-updates"]["reason"] = ""' \
  caught "no reason"

arm "3" "an entry GitHub no longer reports" \
  's["workflows"] = [w for w in s["workflows"] if w["path"] != "dynamic/dependabot/dependabot-updates"]' "pass" \
  caught "no longer reports"

# The live mode with no `gh` to reach GitHub: it must fail, not pass.
out="$(env PATH=/nonexistent "$PY" "$CHECK" 2>&1)"; rc=$?
if [ $rc -ne 0 ] && grep -qF "nothing was checked" <<<"$out"; then
  echo "  4: caught -- the live list cannot be read"; PASSES=$((PASSES+1))
else
  echo "  4: NOT CAUGHT -- the live list cannot be read (rc=$rc)"; FAILS=$((FAILS+1))
fi

echo "$PASSES passed, $FAILS failed"
[ $FAILS -eq 0 ]
