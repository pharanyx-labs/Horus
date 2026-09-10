#!/usr/bin/env bash
# Falsify tools/check_abi_structs.py -- one arm per rule, the silent direction(s), and the
# self-check.
#
# Fourteen structs cross the ring-3 boundary written down TWICE, because the two
# headers are compiled into different worlds and neither includes the other. The
# kernel fills them and copies to a ring-3 buffer sized by the OTHER definition,
# so a disagreement is a copy of the wrong length -- and no compiler ever sees
# both files.
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
  out="$(cd "$d" && python3 tools/check_abi_structs.py 2>&1)"; rc=$?
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

# The fixture is two headers. `local` on every variable, because the incident
# above was a helper leaking one into its caller.
mktree () {
  local dst="$1"
  mkdir -p "$dst/tools" "$dst/src/include" "$dst/include" || return 1
  cp "$ROOT/tools/check_abi_structs.py" "$dst/tools/" || return 1
  cp "$ROOT/src/include/kernel.h" "$dst/src/include/" || return 1
  cp "$ROOT/include/syscall.h" "$dst/include/" || return 1
}

echo "Falsifying tools/check_abi_structs.py:"

# ---- RULE 1: the two definitions disagree -- a field of a different type, which
#      moves the offset of everything after it.
#
#      EVERY MUTATION ANCHORS ON `struct cap_info {`, WITH THE BRACE. The first
#      occurrence of `struct cap_info` in include/syscall.h is inside a COMMENT
#      on the SYS_CAP_ENUMERATE #define, so anchoring on the bare name edits
#      prose and leaves the struct untouched -- and the arm then reports NOT
#      CAUGHT for a reason that has nothing to do with the checker. That is how
#      this arm read on its first run.
arm "1a" "a shared struct whose field TYPE differs between headers" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('include/syscall.h'); s = p.read_text()
i = s.index('struct cap_info {'); j = s.index('}', i)
p.write_text(s[:i] + s[i:j].replace('uint32_t', 'uint64_t', 1) + s[j:])
PY" \
    caught "the two headers disagree"

arm "1b" "a shared struct with an extra field on one side" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('include/syscall.h'); s = p.read_text()
i = s.index('struct cap_info {'); j = s.index('}', i)
p.write_text(s[:j] + '    uint32_t planted_extra;\n' + s[j:])
PY" \
    caught "the two headers disagree"

# ---- RULE 2: a struct crossing the boundary that nobody enrolled. The list is
#      DISCOVERED, not typed, because a fixed enumeration goes stale silently --
#      this is the gate that would have caught S71.
arm "2" "a new struct in both headers, enrolled in neither list" \
    "printf '\nstruct newly_shared { uint32_t a; uint32_t b; };\n' >> src/include/kernel.h
     printf '\nstruct newly_shared { uint32_t a; uint32_t b; };\n' >> include/syscall.h" \
    caught "newly_shared"

# ---- RULE 3: an enrolled name that no longer crosses the boundary. An enrolled
#      name that compares nothing is a check that cannot fail.
arm "3" "an enrolled struct removed from one header" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('include/syscall.h'); s = p.read_text()
i = s.index('struct cap_info {'); j = s.index('};', i) + 2
p.write_text(s[:i] + s[j:])
PY" \
    caught "no longer defined in both headers"

# ---- THE SILENT DIRECTIONS.
arm "4a" "the real headers, which agree on all fourteen" "true" clean

arm "4b" "a struct added to only one header is not a boundary struct" \
    "printf '\nstruct kernel_private_thing { uint32_t x; };\n' >> src/include/kernel.h" \
    clean

# ---- SELF-CHECK A: struct discovery goes quiet. Rule 3 catches it, because
#      every enrolled name then looks like it stopped crossing -- an accidental
#      guard, asserted here so it stays one.
arm "5a" "a struct regex that matches nothing does not report a clean tree" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('tools/check_abi_structs.py'); s = p.read_text()
a = 'STRUCT_DEF = re.compile(r\"^(?:typedef'
assert s.count(a) == 1, 'anchor moved'
p.write_text(s.replace(a, 'STRUCT_DEF = re.compile(r\"^NOPE(?:typedef'))
PY
     grep -q 'r\"^NOPE' tools/check_abi_structs.py" \
    caught

# ---- SELF-CHECK B, AND THE ONE THAT MATTERED. If FIELD stops matching, every
#      struct parses as ZERO fields, so all fourteen pairs compare EQUAL and the
#      file reports a clean boundary having read none of their contents. Rule 3
#      does not catch it: the structs are still discovered, only their bodies
#      have gone quiet. This arm failed until the checker grew a guard.
arm "5b" "a field regex that matches nothing fails rather than agreeing vacuously" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('tools/check_abi_structs.py'); s = p.read_text()
a = 'FIELD = re.compile(r\"^'
assert s.count(a) == 1, 'anchor moved'
p.write_text(s.replace(a, 'FIELD = re.compile(r\"^NOPE'))
PY
     grep -q 'FIELD = re.compile(r\"^NOPE' tools/check_abi_structs.py" \
    caught "parsed no fields"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
