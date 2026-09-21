#!/usr/bin/env bash
# Falsify tools/check_ci_gating.py -- one arm per offline rule, plus the silent
# direction.
#
# WHY IT EXISTS: finding [C-6]. The required-status-check list lives in a branch
# ruleset that no commit touches, so a job added to ci.yml lands in the ADVISORY
# set by default and nothing asks whether it should have. A gate that cannot
# block a merge is a gate that goes red for months and blocks nobody -- which is
# how smoke-captest spent its first weeks.
#
# THE NETWORK RULES ARE NOT ARMED HERE, deliberately. `--check-ruleset` and
# `--sync-ruleset` read and write the live GitHub ruleset; the first needs a
# token and the second is repository administration the sandbox refuses outright.
# Arming them would mean either a network dependency in a source-only suite or a
# mock of the GitHub API, and a mock would test the mock. What IS armed is every
# rule that decides WHAT the ruleset should contain, which is the half a commit
# can get wrong.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

mktree () {
  local dst="$1"
  mkdir -p "$dst/tools" "$dst/.github/workflows" || return 1
  cp "$ROOT/tools/check_ci_gating.py" "$dst/tools/" || return 1
  cp "$ROOT/.github/ci-gating.yml" "$dst/.github/" || return 1
  cp "$ROOT"/.github/workflows/*.yml "$dst/.github/workflows/" || return 1
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect, $5 must-say
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  mktree "$d" || { echo "  $rule: FIXTURE FAILED"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  ( cd "$d" && eval "$mut" ) >/dev/null 2>&1 || { echo "  $rule: MUTATION FAILED -- $desc"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_ci_gating.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not say $want -- $desc"; grep -E "^  -" <<<"$out" | head -2 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep -E "^  -" <<<"$out" | head -3 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_ci_gating.py:"

# ---- THE SILENT DIRECTION.
arm "1" "the real workflows and the real classification" "true" clean

# ---- RULE 1, AND THE WHOLE POINT: a job nobody classified. There is no default,
#      because defaulting is how [C-6] happened.
arm "2" "a new job in neither list" \
    'printf "\n  planted-unclassified:\n    name: \"planted by the falsification suite\"\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n" >> .github/workflows/ci.yml' \
    caught "neither list"

# ---- RULE 2: classified twice. Ambiguous is not classified.
arm "3" "a job in both the required and advisory lists" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p))
name = (d.get("required") or [])[0]
adv = d.get("advisory") or {}
adv[name] = "planted by the falsification suite, a reason long enough to be substantive"
d["advisory"] = adv
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "both lists"

# ---- RULE 3: a classification naming a job that does not exist. A rotted entry
#      makes the list look more complete than it is, and quietly stops gating.
arm "4a" "a required entry naming a job no workflow defines" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p))
d["required"].append("job-that-was-deleted")
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "job-that-was-deleted"

arm "4b" "an advisory entry naming a job no workflow defines" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p))
d.setdefault("advisory", {})["ghost-job"] = "a reason long enough to count as substantive here"
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "ghost-job"

# ---- RULE 4: advisory with a token reason. Otherwise `advisory:` becomes a
#      place to park a job rather than an argument for it not gating.
arm "5" "an advisory entry with a token reason" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p))
adv = d.get("advisory") or {}
name = sorted(adv)[0]
adv[name] = "slow"
d["advisory"] = adv
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "substantive"

# ---- THE AGGREGATOR (2026-09-21). The ruleset requires one context from ci.yml,
#      the aggregator's, so every rule below guards a way for a red gate to stop
#      reaching a merge while every job still reads correctly on its own.
#      Mutations edit the raw text (python str.replace on an exact line), not a
#      YAML round trip, so the rest of the workflow stays byte-identical.
mutate_ci () {  # $1 old text, $2 new text; fails if $1 is not present exactly once
  python3 - "$1" "$2" <<'PY'
import sys
p = ".github/workflows/ci.yml"
s = open(p).read()
old, new = sys.argv[1], sys.argv[2]
assert s.count(old) == 1, f"fixture drift: {old!r} occurs {s.count(old)} times"
open(p, "w").write(s.replace(old, new))
PY
}
export -f mutate_ci 2>/dev/null || true

arm "6" "no aggregator named, so the ruleset would require nothing from ci.yml" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p)); d.pop("aggregator")
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "names no \`aggregator:\`"

arm "7" "the aggregator names a job ci.yml does not define" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p)); d["aggregator"] = "no-such-job"
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "is not a job in"

arm "8" "the aggregator is classified advisory, so nothing requires it" \
    'python3 - <<PY
import yaml
p = ".github/ci-gating.yml"
d = yaml.safe_load(open(p)); d["required"].remove(d["aggregator"])
d["advisory"][d["aggregator"]] = "planted by the falsification suite, a reason long enough to be substantive"
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "is not in \`required:\`"

arm "9" "the aggregator loses if: always(), so a failed gate skips it" \
    'mutate_ci "    if: \${{ always() }}
    needs:" "    needs:"' \
    caught "must be \`always()\`"

arm "10" "a required job is dropped from the aggregator's needs" \
    'mutate_ci "      - smoke-captest
" ""' \
    caught "required job 'smoke-captest' is not in aggregator"

arm "11" "the aggregator needs an advisory job, which is not a required one" \
    'mutate_ci "    needs:
      - " "    needs:
      - fuzz
      - "' \
    caught "which is not a required"

arm "12" "the verdict step is removed, so the aggregator always succeeds" \
    'mutate_ci "        run: python3 tools/ci_gate_verdict.py" "        run: \"true\""' \
    caught "never runs tools/ci_gate_verdict.py"

arm "13" "the verdict is handed something other than every result" \
    'mutate_ci "          NEEDS: \${{ toJSON(needs) }}" "          NEEDS: \"{}\""' \
    caught "is not handed"

arm "14" "the verdict step may fail without failing the aggregator" \
    'mutate_ci "        run: python3 tools/ci_gate_verdict.py" "        run: python3 tools/ci_gate_verdict.py
        continue-on-error: true"' \
    caught "has a step with continue-on-error"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
