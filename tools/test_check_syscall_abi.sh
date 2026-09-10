#!/usr/bin/env bash
# Falsify tools/check_syscall_abi.py -- one arm per rule, the silent direction(s), and the
# self-check.
#
# Issue #176: sys_dmesg() and sys_audit_digest() passed their buffer as
# `(uint32_t)(unsigned long)ptr`. The argument registers are 64-bit, so the cast
# was pure loss. It survived because of WHERE the survivors live --
# USER_IMAGE_ASLR_BASE is 16 GiB, so every static and global sits above 4 GiB and
# is always truncated, while a stack buffer sits near 8 MiB and never is. Every
# caller in the tree passed a stack buffer, and the two captest checks naming
# those syscalls both assert a capability REFUSAL, which returns before the
# pointer is ever read.
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
  out="$(cd "$d" && python3 tools/check_syscall_abi.py 2>&1)"; rc=$?
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

mktree () {
  local dst="$1"
  mkdir -p "$dst/tools" "$dst/include" || return 1
  cp "$ROOT/tools/check_syscall_abi.py" "$dst/tools/" || return 1
  cp "$ROOT/tools/sa_break_wrapper.py" "$dst/tools/" || return 1
  cp "$ROOT/include/syscall.h" "$dst/include/" || return 1
}

echo "Falsifying tools/check_syscall_abi.py:"

# ---- RULE 1: #176 itself, replayed.
arm "1" "a wrapper narrowing a user pointer, exactly as #176 did" \
    "printf '\nstatic inline int sys_planted_narrowing(char *buf, int n) {\n    return (int)syscall(200, (uint32_t)(unsigned long)buf, (uint64_t)n, 0);\n}\n' >> include/syscall.h" \
    caught "sys_planted_narrowing"

# ---- RULE 2: the control arm must stay guarded. If the narrowing definition
#      escapes its #ifdef, the defect becomes the default for every wrapper.
arm "2a" "the narrowing macro no longer guarded by its #ifdef" \
    "sed -i 's/#ifdef SYSCALL_PTR_TRUNC32/#ifdef SYSCALL_PTR_TRUNC32_RENAMED/' include/syscall.h
     grep -q SYSCALL_PTR_TRUNC32_RENAMED include/syscall.h" \
    caught "control arm has become the default"

# ---- RULE 3: the FIX itself must stay. Altering the default is the silent way
#      to reopen #176 for every wrapper at once.
arm "2b" "the default definition of SYSCALL_UPTR altered" \
    "sed -i 's/((uint64_t)(uintptr_t)(p))/((uint32_t)(uintptr_t)(p))/' include/syscall.h
     grep -q '((uint32_t)(uintptr_t)(p))' include/syscall.h" \
    caught "fix for #176 has been altered"

# ---- THE SILENT DIRECTIONS.
arm "3a" "the real header, where 56 pointer arguments pass full-width" "true" clean

arm "3b" "a wrapper using SYSCALL_UPTR is not a narrowing" \
    "printf '\nstatic inline int sys_planted_correct(char *buf, int n) {\n    return (int)syscall(201, SYSCALL_UPTR(buf), (uint64_t)n, 0);\n}\n' >> include/syscall.h" \
    clean

# ---- A narrowed NON-pointer is not this defect: integers pass by value and a
#      cast on one loses nothing the caller named.
arm "3c" "a narrowing cast on a non-pointer argument is not reported" \
    "printf '\nstatic inline int sys_planted_int_cast(int n) {\n    return (int)syscall(202, (uint32_t)n, 0, 0);\n}\n' >> include/syscall.h" \
    clean

# ---- THE SELF-CHECK. The macro rules read the header directly, so they still
#      pass when the WRAPPER pattern stops matching -- rule 1, the one that
#      catches #176, goes silent while the file reports PASS. This arm failed
#      until the checker asserted it had examined some pointer arguments.
arm "4" "a wrapper regex that matches nothing fails rather than passing vacuously" \
    "python3 tools/sa_break_wrapper.py && grep -q 're.compile(chr(0))' tools/check_syscall_abi.py" \
    caught "checked no pointer arguments"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
