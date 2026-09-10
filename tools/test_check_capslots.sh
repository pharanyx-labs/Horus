#!/usr/bin/env bash
# Falsify tools/check_capslots.py -- one arm per rule, the silent direction, and
# the self-check.
#
# The defect it exists for is real and dated: on 2026-08-23 CAPSLOT_DEBUG was
# added as 18, which CAPSLOT_UNTYPED already was, and the delegation wrote a
# CAP_DEBUG into the slot init keeps its CAP_UNTYPED in. It presented as "the
# capability did not arrive"; the unfriendly version is a capability arriving
# where something else was expected and being used as it.
#
# Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/src/include" "$1/include"
  cp "$ROOT/tools/check_capslots.py" "$1/tools/"
  cp "$ROOT/src/include/kernel.h" "$1/src/include/"
  cp "$ROOT/include/syscall.h" "$1/include/"
}

# Refuse to delete anything that is not a fresh temp directory.
#
# On 2026-09-10 a sibling suite's fixture helper used `d` as a for-loop variable
# -- the same name `arm` uses for its temp dir, and not declared local -- so the
# loop left d=tools, and this cleanup ran `rm -rf tools` at the REPOSITORY ROOT.
# 87 tracked files, restored from HEAD; the uncommitted work in them was not.
# A harness that can delete a real directory is a hazard whatever the bug that
# points it there, so the guard is on the deletion rather than on that variable.
_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2
       exit 1 ;;
  esac
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_capslots.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_capslots.py:"

# ---- RULE 1: two names, one slot, in the same header. THE 2026-08-23 DEFECT,
#      replayed: CAPSLOT_DEBUG took the number CAPSLOT_UNTYPED already had.
arm "1a" "two CAPSLOT names claiming one number (kernel header)" \
    "printf '\n#define CAPSLOT_COLLIDE 3\n' >> src/include/kernel.h" \
    caught "slot 3 is claimed by"

arm "1b" "the same collision in the ring-3 header" \
    "printf '\n#define CAPSLOT_COLLIDE 8\n' >> include/syscall.h" \
    caught "slot 8 is claimed by"

# ---- RULE 2: the two headers disagree about a shared name. Ring 3 addresses
#      one slot, the kernel gates on another, and neither file says so.
arm "2" "a name defined in both headers with different numbers" \
    "printf '\n#define CAPSLOT_SKEWED 40\n' >> src/include/kernel.h
     printf '\n#define CAPSLOT_SKEWED 41\n' >> include/syscall.h" \
    caught "CAPSLOT_SKEWED"

# ---- THE SILENT DIRECTIONS. A checker that flags any addition satisfies the
#      arms above and forbids the headers as written.
arm "3a" "the real headers, which agree" \
    "true" clean

# ---- A name in ONE header only is deliberate: some slots are ring-3 only and
#      some are kernel-internal. Reporting those would make the checker unusable.
arm "3b" "a name defined in only one header is not a disagreement" \
    "printf '\n#define CAPSLOT_KERNEL_ONLY 44\n' >> src/include/kernel.h" \
    clean

# ---- THE SELF-CHECK. Both rules are vacuous against a regex that matches
#      nothing: no slots parsed means no collisions and no disagreements, and
#      the checker reports a clean tree. This arm failed until the checker grew
#      a guard -- it had none, and was the only one of the three in this suite
#      that could pass by seeing nothing at all.
arm "4" "a slot regex that matches nothing fails rather than passing vacuously" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('tools/check_capslots.py'); s = p.read_text()
a = 'CAPSLOT_[A-Z0-9_]+'
assert s.count(a) == 1, 'anchor moved'
p.write_text(s.replace(a, 'NOPESLOT_[A-Z0-9_]+'))
PY
     grep -q 'NOPESLOT_' tools/check_capslots.py" \
    caught "parsed no CAPSLOT"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
