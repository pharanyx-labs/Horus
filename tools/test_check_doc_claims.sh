#!/usr/bin/env bash
# Falsify tools/check_doc_claims.py -- one arm per rule, the silent direction,
# and the quoting exemption the `forbidden:` ratchet depends on.
#
# WHY IT EXISTS: every number in this repository's docs has gone stale within days
# at least once. The 2026-08-19 audit found nine wrong across five files while two
# other files carried the same numbers correctly -- which is the only reason the
# drift was visible at all. Writing "re-derive every number you cite" into the
# operating manual did not stop it, because a rule only a reader enforces is a
# rule that fails silently.
#
# THE FIXTURE IS THE WHOLE TREE AT HEAD, because this checker derives its values
# from it -- job counts from the workflows, smoke targets from the Makefile,
# check counts from userspace sources. A fixture assembled by guessing which of
# those it needs is a fixture that fails for its own reasons, which teaches
# nothing; arm 1 is what proves this one does not.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

# A GIT REPOSITORY, not just the files: this checker walks `git ls-files` to find
# the documents it scans for forbidden phrasings, so an unpacked archive makes it
# die with "returned non-zero exit status 128" rather than run. The same reason
# tools/test_check_named_targets.sh initialises one.
mktree () {
  ( cd "$ROOT" && git archive HEAD ) | ( cd "$1" && tar -x ) || return 1
  ( cd "$1" && git init -q . && git add -A \
      && git -c user.email=t@t -c user.name=t commit -qm fixture ) || return 1
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect, $5 must-say
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  mktree "$d" || { echo "  $rule: FIXTURE FAILED"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  ( cd "$d" && eval "$mut" ) >/dev/null 2>&1 || { echo "  $rule: MUTATION FAILED -- $desc"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_doc_claims.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_doc_claims.py:"

# ---- THE SILENT DIRECTION, and the proof the fixture is complete.
arm "1" "the tree at HEAD, where every declared claim matches" "true" clean

# ---- RULE 1, THE DEFECT IT EXISTS FOR: a document states a number the tree
#      contradicts. Changed in the DOC, which is the direction that actually
#      happens -- somebody edits prose and the tree moves on without it.
arm "2" "a stated number the tree contradicts" \
    'python3 - <<PY
import re, pathlib, yaml
spec = yaml.safe_load(open(".github/doc-claims.yml"))
occ = spec["counts"][0]["occurrences"][0]
p = pathlib.Path(occ["file"]); t = p.read_text()
m = re.search(occ["pattern"], t)
a, b = m.span(1)
p.write_text(t[:a] + str(int(m.group(1)) + 7) + t[b:])
PY' \
    caught "says"

# ---- RULE 2: a claim declared in a file that no longer states it. Without this,
#      rewording a sentence would silently DELETE the check along with the claim
#      -- the failure mode that makes a ratchet stop ratcheting.
arm "3" "a declared claim whose sentence was reworded away" \
    'python3 - <<PY
import re, pathlib, yaml
spec = yaml.safe_load(open(".github/doc-claims.yml"))
occ = spec["counts"][0]["occurrences"][0]
p = pathlib.Path(occ["file"]); t = p.read_text()
m = re.search(occ["pattern"], t)
p.write_text(t[:m.start()] + "[the sentence that used to be here]" + t[m.end():])
PY' \
    caught "matches nothing"

# ---- RULE 3: a claim deriving a value this script does not compute. A manifest
#      entry naming a deriver that does not exist checks nothing at all.
arm "4" "a claim deriving a value the script does not compute" \
    'python3 - <<PY
import yaml
p = ".github/doc-claims.yml"
d = yaml.safe_load(open(p))
d["counts"].append({"id": "planted", "describe": "planted by the suite",
                    "derive": "no_such_deriver",
                    "occurrences": [{"file": "README.md", "pattern": r"(\d+)"}]})
yaml.safe_dump(d, open(p, "w"))
PY' \
    caught "no_such_deriver"

# ---- RULE 4: the forbidden ratchet. A correction that has been made must not
#      come back, and this is the only part of the manifest that catches PROSE
#      rather than digits.
arm "5" "a retired phrasing reintroduced" \
    'python3 - <<PY
import yaml
spec = yaml.safe_load(open(".github/doc-claims.yml"))
pat = (spec.get("forbidden") or [])[0]["pattern"]
# The pattern is a regex; plant a literal that matches the common case.
lit = pat.replace("\\\\", "")
open("README.md", "a").write("\n" + lit + "\n")
PY' \
    caught "forbidden phrasing"

# ---- AND THE EXEMPTION THAT MAKES THE RATCHET USABLE. A forbidden phrase inside
#      a quoted span or a code span is somebody QUOTING the old wording -- which
#      every `reason:` field in the manifest does, and which the corrections in
#      CHANGES.md do too. Without this the ratchet would forbid explaining
#      itself, and the first correction would make the file unfixable.
arm "6" "a retired phrasing inside a quoted span is not a violation" \
    'python3 - <<PY
import yaml
spec = yaml.safe_load(open(".github/doc-claims.yml"))
pat = (spec.get("forbidden") or [])[0]["pattern"]
lit = pat.replace("\\\\", "")
open("README.md", "a").write("\nIt used to say `" + lit + "`, which was wrong.\n")
PY' \
    clean

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
