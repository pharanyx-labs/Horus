#!/usr/bin/env bash
# Falsify tools/check_claude_md.py -- one arm per rule, plus the two that ask
# whether it can fail at all.
#
# Its first run was against a CLAUDE.md its author had just rewritten, which is
# the least informative run it will ever have. Each arm below plants a broken
# reference in a COPY of the tree and fails the harness if the checker stays
# quiet; two arms go the other way.
#
# Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  # THE WHOLE TRACKED TREE, not a hand-picked subset. The first version of this
  # file copied the files it thought the checker needed and the unmutated-tree
  # arm reported three findings in a row that do not exist in the real tree --
  # rust/src, docs/history, a stand-in for the graph report. A fixture assembled
  # by guessing is a fixture that fails for its own reasons; `git archive` is 9 MB
  # and takes a moment.
  git -C "$ROOT" archive HEAD | tar -x -C "$1"
  # The archive holds COMMITTED files only, so the checker under test -- which is
  # new, or has uncommitted edits -- has to be overlaid from the working tree.
  # Without this the fixture runs whatever was last committed, or nothing at all,
  # and every arm reports a failure that is about the fixture.
  cp "$ROOT/tools/check_claude_md.py" "$1/tools/"
  # CLAUDE.md is gitignored, so the archive has none: copy the real one, which is
  # the file under test.
  [ -f "$ROOT/CLAUDE.md" ] && cp "$ROOT/CLAUDE.md" "$1/"
  # ...and graphify-out/ is gitignored too. The manual names GRAPH_REPORT.md, so
  # the fixture provides one rather than depending on whether this developer has
  # built a graph.
  mkdir -p "$1/graphify-out" && : > "$1/graphify-out/GRAPH_REPORT.md"
  # .claude/ is gitignored in its entirety -- the hook settings the manual names
  # are local, like the manual. Copy them, or the unmutated-tree arm reports a
  # missing file that is sitting right there.
  [ -d "$ROOT/.claude" ] && cp -r "$ROOT/.claude" "$1/"
  true
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
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_claude_md.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_claude_md.py:"

arm "1" "a make target that does not exist" \
    "printf '\nRun \`make smoke-not-a-target\` first.\n' >> CLAUDE.md" \
    caught "smoke-not-a-target"

arm "2" "a path that does not exist" \
    "printf '\nSee \`src/kernel/nosuchfile.c\`.\n' >> CLAUDE.md" \
    caught "nosuchfile.c"

arm "3" "a build flag that does not exist" \
    "printf '\nBuild with \`NO_SUCH_FLAG=1\`.\n' >> CLAUDE.md" \
    caught "NO_SUCH_FLAG"

# 4. THE MUTATION SHAPE THAT MATTERS. Renaming foo -> foo_RENAMED leaves `foo` in
#    the file: a substring test passes over exactly the rename it exists to
#    catch, and this arm reported NOT CAUGHT until the check grew a word
#    boundary. Both shapes are exercised, because only one of them is subtle.
arm "4a" "a named symbol renamed away entirely" \
    "sed -i 's/current_user_is_admin/admin_gate_gone/g' src/kernel/kusers.c" \
    caught "current_user_is_admin"

arm "4b" "a named symbol renamed by SUFFIX, which a substring test would miss" \
    "sed -i 's/current_user_is_admin/current_user_is_admin_RENAMED/g' src/kernel/kusers.c" \
    caught "current_user_is_admin"

arm "5" "a line-number citation, which CLAUDE.md forbids" \
    "printf '\nSee \`src/kernel/scheduler.c:4349\`.\n' >> CLAUDE.md" \
    caught "cites a line number"

arm "6" "a file the manual tells you to run, deleted" \
    "rm -f tools/check_gate_pairs.py" \
    caught "tools/check_gate_pairs.py"

# 7. THE OTHER DIRECTION, twice. An unmutated tree must pass, or every arm above
#    is satisfied by a checker that rejects everything...
arm "7" "an unmutated tree" "true" clean

# ...and the absent-file path must SKIP rather than fail, because that is what CI
# and every fresh clone see: CLAUDE.md is gitignored and is not in the repository.
arm "8" "no CLAUDE.md at all (a fresh clone, and CI)" \
    "rm -f CLAUDE.md" clean

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ] || exit 1
