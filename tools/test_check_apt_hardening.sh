#!/usr/bin/env bash
# Falsify tools/check_apt_hardening.py -- one arm per thing it claims to do.
#
# This checker went green on its first run against a tree that had just been
# hardened by hand, which is the state in which a checker is indistinguishable
# from `return 0`. It had in fact already earned its keep by catching two apt
# calls in codeql.yml that the manual sweep missed, but that is luck rather than
# evidence, so each rule gets an arm.
#
# Mutations are applied to a COPY. Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/.github/workflows" "$1/.github/actions/apt"
  cp "$ROOT/tools/check_apt_hardening.py" "$1/tools/"
  cp "$ROOT"/.github/workflows/*.yml "$1/.github/workflows/"
  cp "$ROOT/.github/actions/apt/action.yml" "$1/.github/actions/apt/"
}

arm () {   # $1 name, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local name="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $name: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_apt_hardening.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $name: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $name: caught but did not name $want -- $desc"; FAILS=$((FAILS+1))
    else echo "  $name: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $name: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $name: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_apt_hardening.py:"

# A1. The defect itself: a new job copying an old one's inline apt.
arm A1 "a job running apt-get directly is caught and named" \
  "printf '\n  newjob:\n    runs-on: ubuntu-latest\n    steps:\n      - run: sudo apt-get update\n' >> .github/workflows/ci.yml" \
  caught "newjob"

# A2. The exemption must not be a hole: the one job allowed to run apt inline
#     still has to strip the vendor lists.
arm A2 "the exempt job is caught if it stops stripping the vendor lists" \
  "python3 - <<'P'
p='.github/workflows/ci.yml'; s=open(p).read()
i=s.index('sources.list.d')
j=s.rindex('\n',0,i)+1; k=s.index('\n',i)+1
open(p,'w').write(s[:j]+s[k:])
P" \
  caught "does not strip"

# A3. The action losing its strip is the defect returning by the back door: every
#     job would still 'use the hardened path' and the path would no longer harden.
arm A3 "the action is caught if it stops stripping" \
  "sed -i '/sources.list.d/d' .github/actions/apt/action.yml" \
  caught "does not strip"

# A4. `|| true` on the install, which is how a job comes to report success having
#     installed nothing -- the shape this workflow's security job was rescued from.
arm A4 "the action is caught if it tolerates an apt failure" \
  "sed -i 's#retry sudo apt-get update#sudo apt-get update || true#' .github/actions/apt/action.yml" \
  caught "|| true"

# A5. The other direction. An unmutated tree must pass, or the four arms above
#     are satisfied by a checker that rejects everything.
arm A5 "an unmutated tree passes" "true" clean

echo
if [ "$FAILS" -ne 0 ]; then echo "FAIL: $FAILS arm(s) wrong ($PASSES passed)"; exit 1; fi
echo "PASS: $PASSES arms -- the checker catches what it must and passes what it must"
