#!/usr/bin/env bash
# Falsify tools/check_conflict_markers.py: one arm per rule, and the silent
# direction (what git does not write must not be reported, and what the checker
# does not scan is stated rather than assumed).
#
# Every arm copies the tracked tree into a fresh repository and stages it, so the
# baseline is the tree as it stands. The markers are built by `mark` rather than
# written out, so no line of this file begins with one and the checker can scan it.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  ( cd "$ROOT" && git ls-files -z | xargs -0 cp --parents -t "$1" 2>/dev/null )
  ( cd "$1" && git init -q && git add -A )
}

# Refuse to delete anything that is not a fresh temp directory (the 2026-09-10
# `rm -rf tools` incident recorded in tools/test_check_miri_scope.sh).
_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}': not a temp directory" >&2
       exit 1 ;;
  esac
}

# Seven copies of one character.
mark () { printf "%7s" "" | tr ' ' "$1"; }

arm () {
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_conflict_markers.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT: $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not report '$want': $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught: $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT: $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly: $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

# Append a line to a file, on a line of its own even when the file has no final
# newline, and stage it.
add () { printf '\n%s\n' "$2" >> "$1" && git add "$1"; }

echo "Falsifying tools/check_conflict_markers.py:"

# ---- BASELINE. The copied tree must pass, or every "caught" below means nothing.
arm "0" "the tracked tree as it stands" "true" clean

# ---- One arm per rule, each in a different kind of file.
arm "1" "an opening marker in a Markdown doc" \
    'add docs/LIMITATIONS.md "$(mark "<") HEAD"' caught "rule 1"
arm "1" "an opening marker with no label, at the end of a line" \
    'add Makefile "$(mark "<")"' caught "rule 1"
arm "2" "a separator alone in YAML" \
    'add .github/gate-pairs.yml "$(mark "=")"' caught "rule 2"
arm "3" "a closing marker in C" \
    'add src/kernel/kusers.c "$(mark ">") origin/main"' caught "rule 3"
arm "4" "a diff3 base marker in HTML" \
    'add site-src/layout.html "$(mark "|") merged common ancestors"' caught "rule 4"
arm "1" "a CRLF line ending does not hide a marker" \
    'printf "\n%s HEAD\r\n" "$(mark "<")" >> README.md && git add README.md' caught "rule 1"
arm "1" "a new file, once staged, is scanned (line 2: add starts a line)" \
    'add new-note.md "$(mark "<") HEAD"' caught "new-note.md:2"

# ---- The silent direction.
arm "s" "eight '=' (a setext underline of another length)" \
    'add README.md "========"' clean
arm "s" "a marker not at column 0 (git never writes one there)" \
    'add README.md "  $(mark "<") HEAD"' clean
arm "s" "seven '<' followed by a letter, not a space" \
    'add README.md "$(mark "<")x"' clean
arm "s" "a binary file (a NUL in its first 8 KiB) is not read" \
    'printf "\0%s HEAD\n" "$(mark "<")" > blob.dat && git add -f blob.dat' clean
arm "s" "an untracked file is not scanned (stage before the sweep)" \
    'printf "%s HEAD\n" "$(mark "<")" > untracked.md' clean

echo
echo "$PASSES passed, $FAILS failed"
[ $FAILS -eq 0 ]
