#!/usr/bin/env bash
# Falsify tools/check_lock_order.py -- one arm per rule, the silent direction,
# and the self-check.
#
# Arms mutate a COPY of the tree, because the subject is the kernel sources
# themselves. The manifest is small enough to write per-arm.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/src/kernel" "$1/.github"
  cp "$ROOT/tools/check_lock_order.py" "$1/tools/"
  cp "$ROOT/tools/lo_break_take.py" "$1/tools/"
  cp "$ROOT/.github/lock-order.yml" "$1/.github/"
  cp "$ROOT"/src/kernel/*.c "$1/src/kernel/"
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_lock_order.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_lock_order.py:"

# ---- RULE 1: a nesting nobody argued for. Written across a CALL boundary,
#      because that is the only shape this kernel's real nestings have.
arm "1a" "an undeclared nesting, through a call" \
    "cat >> src/kernel/pipe.c <<'C'
void lo_test_outer(void) {
    spin_lock(&pipe_lock);
    cap_install_object(0, 0, 0);
    spin_unlock(&pipe_lock);
}
C" \
    caught "UNDECLARED nesting pipe_lock -> cap_lock"

# ---- The same defect written directly, both locks in one function.
arm "1b" "an undeclared nesting, taken directly" \
    "cat >> src/kernel/pipe.c <<'C'
void lo_test_direct(void) {
    spin_lock(&pipe_lock);
    spin_lock(&storage_lock);
    spin_unlock(&storage_lock);
    spin_unlock(&pipe_lock);
}
C" \
    caught "UNDECLARED nesting pipe_lock -> storage_lock"

# ---- RULE 2, THE ONE WITH TEETH. A declared nesting is safe only while the
#      reverse is absent. This is the audit's "no page_lock holder enters IPC"
#      turned from a sentence into a gate.
arm "2a" "the reverse of a declared nesting closes a cycle" \
    "cat >> src/kernel/pipe.c <<'C'
void lo_test_reverse(void) {
    spin_lock(&page_lock);
    ipc_publish_pending_block(0, 0, 0);
    spin_unlock(&page_lock);
}
C" \
    caught "CYCLE: endpoint_lock -> page_lock is declared"

arm "2b" "the reverse of the other declared nesting" \
    "cat >> src/kernel/pipe.c <<'C'
void lo_test_reverse2(void) {
    spin_lock(&cap_lock);
    ipc_lock();
    ipc_unlock();
    spin_unlock(&cap_lock);
}
C" \
    caught "CYCLE: endpoint_lock -> cap_lock is declared"

# ---- THE SILENT DIRECTION. The real tree must pass; a checker that flags every
#      nesting satisfies arms 1 and 2 and forbids the kernel as written.
arm "3" "the real tree, whose two nestings are declared" \
    "true" clean

# ---- Removing a declaration must expose the nesting it was covering: the
#      manifest is a record of arguments made, not a place to park a finding.
arm "4" "deleting a declaration exposes the nesting it covered" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('.github/lock-order.yml'); s = p.read_text()
i = s.index('  - outer: endpoint_lock\n    inner: page_lock')
p.write_text(s[:i])
PY" \
    caught "UNDECLARED nesting endpoint_lock -> page_lock"

# ---- A declaration with no reason is not a declaration. Otherwise the manifest
#      becomes a list of names and the argument is never made.
arm "5" "a declaration with no reason does not count" \
    "python3 - <<'PY'
import pathlib, re
p = pathlib.Path('.github/lock-order.yml'); s = p.read_text()
i = s.index('  - outer: endpoint_lock\n    inner: page_lock')
p.write_text(s[:i] + '  - outer: endpoint_lock\n    inner: page_lock\n')
PY" \
    caught "UNDECLARED nesting endpoint_lock -> page_lock"

# ---- THE SELF-CHECK. If no function is seen to take a lock, nothing nests,
#      nothing reverses, and the tree reports clean -- the answer this must
#      never give by accident.
#      Counting lock-taking FUNCTIONS was too weak: with spin_lock broken the
#      surviving ipc_lock() alias still spread endpoint_lock across hundreds of
#      callers through the transitive closure, so the total stayed high while
#      eight of nine locks had gone invisible. The check is per LOCK now, and
#      this arm is what failed until it was.
#      THE MUTATION TARGETS THE TAKE LINE AND VERIFIES THAT LINE. An earlier
#      version used sed with the pattern spin_lock\\s, and GNU sed reads \\s as
#      whitespace -- so it replaced the words "spin_lock " in this checker's
#      DOCSTRING and left the regex untouched. The grep guard then passed,
#      because a change had happened; just not the one under test. A guard must
#      assert THE change, not A change.
arm "6" "a lock regex that matches nothing fails rather than passing vacuously" \
    "python3 tools/lo_break_take.py && grep -q bNOPE_lock tools/check_lock_order.py" \
    caught "no function is seen to take"

# ---- A one-line definition is still a definition. `static inline void
#      ut_lock(void) { spin_lock(&untyped_lock); }` is how untyped.c takes its
#      lock, and the first body parser could not match it -- so two of the nine
#      locks were invisible and every rule was vacuous for them. Caught by the
#      per-lock self-check above on its first run.
arm "7" "a lock taken only from a one-line function definition is still seen" \
    "cat >> src/kernel/pipe.c <<'C'
static inline void lo_oneline_take(void) { spin_lock(&storage_lock); }
void lo_oneline_user(void) {
    spin_lock(&pipe_lock);
    lo_oneline_take();
    spin_unlock(&pipe_lock);
}
C" \
    caught "UNDECLARED nesting pipe_lock -> storage_lock"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
