#!/usr/bin/env bash
# Falsify tools/check_named_targets.py -- one arm per rule, plus the two arms
# that ask whether it can fail at all.
#
# A checker's first run is against a tree its author has just fixed, so "it
# passes" is the least informative thing it will ever do. Each arm below mutates
# a COPY of the tree to break one rule and fails the harness if the checker stays
# quiet; two arms go the other way and fail it if the checker complains about
# something legitimate.
#
# Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {   # a git repo, because the checker walks `git ls-files`
  mkdir -p "$1/tools" "$1/src/kernel" "$1/docs/history"
  cp "$ROOT/Makefile" "$1/"
  cp "$ROOT/tools/check_named_targets.py" "$1/tools/"
  cp "$ROOT/src/kernel/capability.c" "$1/src/kernel/"
  printf 'A history entry may name `make smoke-retired-long-ago`.\n' > "$1/docs/history/DEVLOG-2026.md"
  printf 'A changelog entry may name `make smoke-also-retired`.\n' > "$1/CHANGES.md"
  ( cd "$1" && git init -q . && git add -A && git -c user.email=t@t -c user.name=t commit -qm t )
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_named_targets.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_named_targets.py:"

# 1. The defect it was written for: a comment naming a target that is not there.
arm "1a" "a source comment names an absent target" \
    "printf '/* See make smoke-does-not-exist. */\n' >> src/kernel/capability.c" \
    caught "smoke-does-not-exist"

# 2. The same reference wrapped across a comment continuation -- the shape that
#    made the capability.c case invisible to a grep for 'make smoke-'.
arm "1b" "the reference wraps across a comment line" \
    "printf '/* See make\n * smoke-wrapped-away. */\n' >> src/kernel/capability.c" \
    caught "smoke-wrapped-away"

# 3. The backticked form, with no 'make' in front of it.
arm "1c" "a backticked target name, no 'make'" \
    "printf '/* The gate is \`smoke-backticked-away\`. */\n' >> src/kernel/capability.c" \
    caught "smoke-backticked-away"

# 4. THE OTHER DIRECTION FOR THE HYPHEN JOIN. A name wrapped at a hyphen is one
#    target, not two, and reporting it would be a false positive -- which is
#    exactly what the first draft of the checker did.
arm "2" "a target name wrapped at a hyphen is not a stale reference" \
    "printf '/* See make smoke-cap-\n * lookup-control. */\n' >> src/kernel/capability.c" \
    clean

# 5. A reference that resolves must not be reported, or every arm above is
#    satisfied by a checker that rejects everything.
arm "3" "a reference to a real target is left alone" \
    "printf '/* See make smoke-cap-lookup-control. */\n' >> src/kernel/capability.c" \
    clean

# 6. History is a record of what was true, not a claim about now.
arm "4a" "docs/history/ may name a retired target" \
    "printf 'and \`make smoke-long-gone\` was its arm.\n' >> docs/history/DEVLOG-2026.md" \
    clean
arm "4b" "CHANGES.md may name a retired target" \
    "printf 'and \`make smoke-also-long-gone\` was its arm.\n' >> CHANGES.md" \
    clean

# 7. THE CHECKER MUST HOLD ITS OWN EXEMPTION. Drop the self-test from EXEMPT and
#    the planted names in this very file become findings -- which is what proves
#    the exemption is load-bearing rather than decorative.
arm "5" "removing an exemption makes its planted names visible" \
    "cp '$ROOT/tools/test_check_named_targets.sh' tools/ && git add -A && \
     git -c user.email=t@t -c user.name=t commit -qm f && \
     python3 - <<'P'
import pathlib
p = pathlib.Path('tools/check_named_targets.py'); s = p.read_text()
s = s.replace('    \"tools/test_check_named_targets.sh\": \"plants absent targets to falsify this checker\",\n', '')
p.write_text(s)
P" \
    caught "smoke-does-not-exist"

# 8. And the parser itself: a Makefile it cannot read must fail loudly rather
#    than pass with nothing to compare against.
arm "6" "a Makefile with no smoke targets fails rather than passing vacuously" \
    "sed -i 's/^smoke-/notsmoke-/' Makefile" \
    caught "no smoke-* targets"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ] || exit 1
