#!/usr/bin/env bash
# Falsify tools/check_dispatch_gates.py -- one arm per rule, both silent
# directions, and the two self-checks.
#
# THIS FILE DID NOT EXIST UNTIL 2026-09-10, and SECURITY.md S79 already claimed
# the checker was "falsified in four directions: an un-guarded row, a row guarded
# by an unknown macro, a row in an #else, and a renamed table". Those four were
# done by hand while the checker was written and never again -- a falsification
# claim with no artefact is a historical statement, not a standing guarantee, and
# it is exactly the shape of the claims this repository keeps finding stale. The
# four are arms 1a-1c and 4a here, so the S79 sentence is now re-runnable.
#
# Arms 5a-5d cover rule 3, added the same day: a slot-3 cap_lookup in a handler
# BODY, which is one file over from the table rules 1 and 2 read, and where two
# live ones (kshell.c `clear` and `load`) had been sitting.
#
# Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/src/kernel" "$1/.github"
  cp "$ROOT/tools/check_dispatch_gates.py" "$1/tools/"
  cp "$ROOT/src/kernel/syscall.c" "$1/src/kernel/"
  cp "$ROOT/src/kernel/kspawn.c" "$1/src/kernel/"
  cp "$ROOT/src/kernel/syscall_ipc.c" "$1/src/kernel/"
  cp "$ROOT/.github/slot3-lookups.yml" "$1/.github/"
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_dispatch_gates.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_dispatch_gates.py:"

# ---- RULE 1: a slot-3 dispatch row in the ship build. [C-1]'s decoy, the
#      defect this checker was written for, and the one that came back three
#      times after being swept by hand.
arm "1a" "an un-guarded slot-3 dispatch row" \
    "python3 - <<'PY'
import pathlib
p=pathlib.Path('src/kernel/syscall.c'); s=p.read_text()
anchor='static const syscall_desc_t syscall_table[SYSCALL_TABLE_SIZE] = {\n'
assert anchor in s
s=s.replace(anchor, anchor+'    [SYS_TEST_DECOY] = { h_test_decoy, 3, CAP_RIGHT_WRITE, SC_ANYTYPE },\n', 1)
p.write_text(s)
PY" \
    caught "SYS_TEST_DECOY"

# ---- RULE 2: guarded, but not by a macro the ship build provably lacks. This is
#      how a row could otherwise be smuggled back behind an unrelated #ifdef.
arm "1b" "a slot-3 row behind a macro nobody has vouched for" \
    "python3 - <<'PY'
import pathlib
p=pathlib.Path('src/kernel/syscall.c'); s=p.read_text()
anchor='static const syscall_desc_t syscall_table[SYSCALL_TABLE_SIZE] = {\n'
assert anchor in s
s=s.replace(anchor, anchor+'#ifdef SOME_UNVOUCHED_MACRO\n    [SYS_SNEAKY] = { h_sneaky, 3, CAP_RIGHT_WRITE, SC_ANYTYPE },\n#endif\n', 1)
p.write_text(s)
PY" \
    caught "SYS_SNEAKY"

# ---- The #else arm: a row in the NOT-taken branch of a guard is still shipped.
arm "1c" "a slot-3 row in the #else of a control-arm guard" \
    "python3 - <<'PY'
import pathlib
p=pathlib.Path('src/kernel/syscall.c'); s=p.read_text()
anchor='static const syscall_desc_t syscall_table[SYSCALL_TABLE_SIZE] = {\n'
assert anchor in s
s=s.replace(anchor, anchor+'#ifdef RAMFS_SLOT3_GATE\n    [SYS_A] = { h_a, 8, 0, SC_ANYTYPE },\n#else\n    [SYS_ELSE_DECOY] = { h_else, 3, CAP_RIGHT_WRITE, SC_ANYTYPE },\n#endif\n', 1)
p.write_text(s)
PY" \
    caught "SYS_ELSE_DECOY"

# ---- THE SILENT DIRECTION for rules 1/2. A checker that flags every slot-3 row
#      satisfies all three arms above and is worthless: the control arms must
#      still be allowed to restore one.
arm "2" "the real tree's guarded slot-3 rows are left alone" \
    "true" clean

# ---- SELF-CHECK A: the row regex stops matching. Every rule is vacuous against
#      a parser that has gone quiet, and a clean tree is the one answer this must
#      never give.
arm "4a" "a renamed dispatch table fails rather than passing vacuously" \
    "sed -i 's/syscall_desc_t syscall_table\[/syscall_desc_t syscall_table_renamed[/' src/kernel/syscall.c" \
    caught

# ---- SELF-CHECK B, new with rule 3: the slot-3 CALL regex stops matching.
arm "4b" "a slot-3 call regex that matches nothing fails rather than passing" \
    "sed -i 's|cap_lookup\\\\s\\*|cap_lookup_NOPE\\\\s*|' tools/check_dispatch_gates.py" \
    caught "no literal slot-3 cap_lookup call sites"

# ---- RULE 3: a slot-3 lookup in a handler BODY, in the ship build. kshell.c's
#      `clear` was exactly this, and rules 1 and 2 could not see it.
arm "5a" "a slot-3 cap_lookup in a handler body, unguarded" \
    "printf '\nstatic int h_body_decoy(void) {\n    struct capability *c = cap_lookup(CAPSLOT_FRAME, CAP_FRAME, CAP_RIGHT_WRITE);\n    if (!c) return -1;\n    return 0;\n}\n' >> src/kernel/syscall.c" \
    caught "h_body_decoy"

# ---- The numeric spelling is the same defect. kshell used CAPSLOT_FRAME; the
#      IPC snapshots use the literal 3.
arm "5b" "the same lookup written as the literal 3" \
    "printf '\nstatic int h_numeric_decoy(void) {\n    struct capability *c = cap_lookup(3, CAP_ANYTYPE, CAP_RIGHT_WRITE);\n    if (!c) return -1;\n    return 0;\n}\n' >> src/kernel/syscall.c" \
    caught "h_numeric_decoy"

# ---- A slot-3 lookup named in a COMMENT is not a call site. syscall.c carries
#      two such sentences, and kshell.c now carries one describing the check it
#      retired -- so this arm is load-bearing, not theoretical.
arm "5c" "a slot-3 lookup named only in a comment is not a call site" \
    "printf '\n/* The retired form was cap_lookup(CAPSLOT_FRAME, CAP_FRAME, WRITE). */\n// and again: cap_lookup(3, CAP_ANYTYPE, 0)\n' >> src/kernel/syscall.c" \
    clean

# ---- The exemption is per (file, SYMBOL), not per file: declaring one function
#      must not licence the next slot-3 lookup added to the same file.
arm "5d" "a declared file does not licence a new lookup in another of its functions" \
    "printf '\nstatic int h_ipc_newcomer(void) {\n    struct capability *c = cap_lookup(3, CAP_ANYTYPE, CAP_RIGHT_WRITE);\n    if (!c) return -1;\n    return 0;\n}\n' >> src/kernel/syscall_ipc.c" \
    caught "h_ipc_newcomer"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
