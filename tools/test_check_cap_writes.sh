#!/usr/bin/env bash
# Falsify tools/check_cap_writes.py -- one arm per rule, plus the two directions
# that must stay SILENT. Without those two the checker would be unusable rather
# than merely weak: one says the tree it ships with passes, the other says adding
# a cap-write to an ALREADY-declared function does not need a new declaration.
#
# WHY EACH RULE NEEDS ITS OWN ARM. check_doc_claims.py shipped with two of three
# rules unfalsifiable because its own self-test satisfied the rule it was testing
# (CLAUDE.md section 8). The rule most likely to rot here is rule 3: it asks
# whether a function claiming `locked` mentions cap_lock, and every function in
# the shipping tree that claims it does -- so on the tree as it stands the rule
# cannot fire, and a regression in it would be invisible.
#
# NO `git init` IN THE FIXTURE, unlike test_check_doc_claims.sh: this checker
# reads the worktree and never runs git, so an extracted archive is enough. If a
# future rule walks `git ls-files`, this is the line that has to change.
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
  ( cd "$ROOT" && git archive HEAD ) | ( cd "$1" && tar -x ) || return 1
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect, $5 must-say
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  mktree "$d" || { echo "  $rule: FIXTURE FAILED"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  ( cd "$d" && eval "$mut" ) >/dev/null 2>&1 || { echo "  $rule: MUTATION FAILED -- $desc"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_cap_writes.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_cap_writes.py:"

# ---- THE SILENT DIRECTION, and the proof the fixture is complete.
arm "1" "the tree at HEAD, where every cap-write site is declared" "true" clean

# ---- RULE 1, THE DEFECT IT EXISTS FOR: a raw capability store in a function
#      nobody declared. This is the shape of all five sites repaired on
#      2026-09-12, planted in a file that has never held one.
arm "2" "a raw capability store in an undeclared function" \
    'python3 - <<PY
import pathlib
p = pathlib.Path("src/kernel/syscall_fs.c"); t = p.read_text()
t += """
/* planted by the falsification suite */
void planted_raw_cap_store(int pid, unsigned slot) {
    capability_t *cspace = tasks[pid].cspace;
    cspace[slot].type   = CAP_PIPE;
    cspace[slot].rights = CAP_RIGHT_WRITE;
    cspace[slot].serial = 1;
}
"""
p.write_text(t)
PY' \
    caught "UNDECLARED"

# ---- AND THE SECOND SILENT DIRECTION. A cap-write added to a function that is
#      ALREADY declared must NOT fail: the declaration is per function, and a
#      checker that demanded one per STORE would fail on every edit inside the
#      locked path and be turned off within a week.
arm "3" "another cap-write inside an already-declared function" \
    'python3 - <<PY
import pathlib
p = pathlib.Path("src/kernel/capability.c"); t = p.read_text()
old = "    cspace[dest_slot].generation = rust_lineage_current(serial);"
assert t.count(old) >= 1
t = t.replace(old, old + "\n    cspace[dest_slot].badge      = badge;", 1)
p.write_text(t)
PY' \
    clean

# ---- RULE 2: a declaration for a site that is not there. A refactor that moves
#      a store leaves the exemption behind, and an exemption nobody granted on
#      purpose is how a site stops being looked at.
arm "4" "a stale declaration naming a function with no cap-write" \
    'python3 - <<PY
import yaml
p = ".github/cap-write-sites.yml"
d = yaml.safe_load(open(p))
d["sites"].append({"file": "src/kernel/pipe.c", "function": "pipe_read_bytes",
                   "status": "locked", "reason": "planted by the suite"})
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "STALE declaration"

# ---- RULE 3: a site that claims the lock and does not take it. ON THE SHIPPING
#      TREE THIS RULE CANNOT FIRE -- every `locked` function takes cap_lock -- so
#      without this arm a regression in it would be silent. The mutation promotes
#      the control-arm store in h_pipe, which is the one function in the manifest
#      that writes a slot and holds no cap_lock.
arm "5" "a \`locked\` claim on a function that never takes cap_lock" \
    'python3 - <<PY
import yaml
p = ".github/cap-write-sites.yml"
d = yaml.safe_load(open(p))
for s in d["sites"]:
    if s["file"] == "src/kernel/pipe.c" and s["function"] == "h_pipe":
        s["status"] = "locked"
        break
else:
    raise SystemExit("h_pipe entry not found")
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "FALSE \`locked\` claim"

# ---- RULE 4: an open defect with nothing tracking it. The `unlocked` status is
#      the honest one -- it says a site is known-broken -- and it is only honest
#      while a finding ID carries it.
arm "6" "an \`unlocked\` site with no finding tracking it" \
    'python3 - <<PY
import yaml
p = ".github/cap-write-sites.yml"
d = yaml.safe_load(open(p))
for s in d["sites"]:
    if s["status"] == "unlocked":
        s.pop("finding", None)
        break
else:
    raise SystemExit("no unlocked site found")
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "UNTRACKED open defect"

# ---- RULE 4, the other half: a status this checker does not know. A typo in a
#      status would otherwise grant an exemption by being unrecognised.
arm "7" "a status the checker does not recognise" \
    'python3 - <<PY
import yaml
p = ".github/cap-write-sites.yml"
d = yaml.safe_load(open(p))
d["sites"][0]["status"] = "probably-fine"
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "UNKNOWN status"

# ---- AND A MISSING FIELD. A site entry with no reason is a site with no
#      argument, which is the thing this file exists to make impossible.
arm "8" "a site entry with no reason" \
    'python3 - <<PY
import yaml
p = ".github/cap-write-sites.yml"
d = yaml.safe_load(open(p))
d["sites"][0].pop("reason")
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "missing \`reason\`"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
