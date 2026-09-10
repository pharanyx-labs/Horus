#!/usr/bin/env bash
# Falsify tools/check_image_abi.py -- one arm per rule, the silent direction(s), and the
# self-check.
#
# Until 2026-09-03 the `.bin` container was DECLARED four times and PARSED in
# eleven places, and no two copies were connected. Two declarations shared the
# name `struct program_header` and described different things -- 104 bytes with
# magic at offset 96, and 44 bytes with magic at offset 0 -- with no compiler
# seeing both. That is why rule 2 matches on the FIELD SET rather than the name:
# a rename is not a fix, because the defect was four copies rather than four
# names.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

# Refuse to delete anything that is not a fresh temp directory.
#
# On 2026-09-10 this suite's own fixture helper used `d` as a for-loop variable
# -- the same name `arm` uses for its temp dir, and not declared local -- so the
# loop left d=tools and the cleanup ran `rm -rf tools` at the REPOSITORY ROOT.
# 87 tracked files, restored from HEAD; the uncommitted work in them was not.
# A harness that can delete a real directory is a hazard whatever the bug points
# it there, so the guard is on the deletion rather than on that variable.
_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2
       exit 1 ;;
  esac
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" || { echo "  $rule: FIXTURE FAILED"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_image_abi.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep -E '^  ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep -E '^  ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

# The checker walks src/ include/ userspace/ tools/ for .c and .h, skipping
# vendored trees. The fixture mirrors that with tar, excluding the same paths --
# copying userspace/ports would add ~40k lines the checker ignores anyway.
#
# EVERY VARIABLE IS `local`. The first version of this helper used `d` as a
# for-loop variable -- the same name `arm` uses for its temp dir -- and left it
# set to `tools` on return, so the cleanup deleted the repository's tools/.
mktree () {
  local dst="$1"
  ( cd "$ROOT" && tar -c \
      --exclude=ports --exclude=newlib --exclude=third_party --exclude=vendor \
      src include userspace tools 2>/dev/null ) | ( cd "$dst" && tar -x ) || return 1
}

echo "Falsifying tools/check_image_abi.py:"

# ---- RULE 1: a second spelling of the magic. A second spelling is a second
#      parser, which is what LIMITATIONS 2.18 was about.
arm "1" "a second spelling of the container magic" \
    "printf '\nstatic const unsigned magic_again = 0x55524F48;\n' >> src/kernel/main.c" \
    caught "spells the container magic"

# ---- RULE 2: the container redeclared under ANY name. The arm that matters,
#      because two of the four original copies shared a name and a third did not.
arm "2a" "the container redeclared under a different name" \
    "printf '\nstruct totally_different_name { unsigned magic; unsigned entry; unsigned size; char name[32]; };\n' >> src/kernel/main.c" \
    caught "totally_different_name"

arm "2b" "the container redeclared under its historical name" \
    "printf '\nstruct program_header { unsigned magic; unsigned entry; unsigned size; char name[32]; };\n' >> userspace/init.c" \
    caught "program_header"

# ---- THE SILENT DIRECTIONS. Requiring ALL FOUR fields is what keeps this
#      usable: plenty of structs have a `size` or a `name`.
arm "3a" "the real tree, with one declaration and one spelling" "true" clean

arm "3b" "a struct with only some of the container's fields is not a redeclaration" \
    "printf '\nstruct not_the_container { unsigned magic; unsigned size; };\n' >> src/kernel/main.c" \
    clean

# ---- THE SELF-CHECKS. Both rules compare against the one declaration, so they
#      are vacuous without it. This checker already guards all three cases --
#      the arms are what keep the guards.
arm "4a" "the ABI header missing fails rather than passing" \
    "rm -f include/program_abi.h" \
    caught "does not exist"

arm "4b" "the ABI header no longer defining the container fails" \
    "sed -i 's/struct horus_image_header {/struct renamed_away {/' include/program_abi.h
     grep -q renamed_away include/program_abi.h" \
    caught "no longer defines"

arm "4c" "the ABI header no longer spelling the magic fails" \
    "sed -i 's/0x55524F48/0xDEADBEEF/I' include/program_abi.h
     grep -q 0xDEADBEEF include/program_abi.h" \
    caught "no longer spells"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
