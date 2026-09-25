#!/usr/bin/env bash
# Falsify tools/check_prose_style.py: one arm per rule, the silent direction
# (what is not prose must not be reported), and the two masker defects found
# while the checker was written, so neither can come back unnoticed.
#
# Every arm copies the real documentation set, so the baseline is the tree as it
# stands: an arm that is caught was caught for its own mutation, and an arm that
# stays clean shows the mutation is invisible to the checker, as intended.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/rust"
  cp "$ROOT/tools/check_prose_style.py" "$1/tools/"
  cp "$ROOT"/{README.md,SECURITY.md,TESTS.md,CHANGES.md,CONTRIBUTING.md} "$1/"
  cp "$ROOT/rust/KANI.md" "$1/rust/"
  cp -r "$ROOT/site-src" "$1/"
  cp -r "$ROOT/docs" "$1/"
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

arm () {
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_prose_style.py 2>&1)"; rc=$?
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

# Append a paragraph to a file. printf, not echo, so the escapes are ours.
add () { printf '\n%s\n' "$2" >> "$1"; }

echo "Falsifying tools/check_prose_style.py:"

# ---- BASELINE. The copied tree must pass, or every "caught" below means nothing.
arm "0" "the documentation set as it stands" "true" clean

# ---- RULE 1: the em dash character, in Markdown prose.
arm "1" "an em dash in README prose" \
    "add README.md \"The kernel is small $(printf '—') smaller than it was.\"" \
    caught "README.md:"

# ---- RULE 2: the entity, which renders as the same dash on the website.
arm "2" "an &mdash; entity in the website's prose" \
    "sed -i 's#</body>#<p>Small \&mdash; smaller.</p></body>#' site-src/layout.html" \
    caught "rule 2"

# ---- RULE 3: the ASCII stand-in, mid-line and at the end of a line. The sweep's
#      first helper only matched a double hyphen followed by a space, and left
#      every one that ended a line; 3b is that defect.
arm "3a" "a spaced double hyphen mid-line" \
    "add docs/ROADMAP.md 'The gate is green -- for now.'" \
    caught "rule 3"
arm "3b" "a double hyphen ending a line" \
    "add docs/ROADMAP.md \$'The gate is green --\nfor now.'" \
    caught "rule 3"

# ---- RULE 4: an en dash doing an em dash's job.
arm "4" "a spaced en dash" \
    "add SECURITY.md \"The gate is green $(printf '–') for now.\"" \
    caught "rule 4"

# ---- RULE 5: a listed American spelling, including a suffixed form.
arm "5a" "American 'behavior' in prose" \
    "add TESTS.md 'The behavior is fixed.'" \
    caught "behavior"
arm "5b" "a suffixed form reached through a stem ('unauthorized')" \
    "add TESTS.md 'An unauthorized task is refused.'" \
    caught "unauthorized"

# ---- RULE 6: the mark PR #249 left in 21 cells.
arm "6" "a table cell holding only a comma" \
    "add docs/SYSCALLS.md \$'| a | b |\n|---|---|\n| 1 |, |'" \
    caught "rule 6"

# ---- COVERAGE. The set under docs/ is found, not listed; a new file is in it.
arm "7" "an em dash in a new file under docs/" \
    "mkdir -p docs/new && printf 'New $(printf '—') doc.\n' > docs/new/NOTE.md" \
    caught "docs/new/NOTE.md"

# ---- THE SILENT DIRECTION. Code, quotations and ranges are not prose.
arm "8a" "an em dash inside an inline code span" \
    "add README.md \"Run \\\`echo a $(printf '—') b\\\` to see it.\"" \
    clean
arm "8b" "an em dash inside a fenced block" \
    "add README.md \$'\`\`\`\nFAIL $(printf '—') see log\n\`\`\`'" \
    clean
arm "8c" "a verbatim quotation keeps its dash" \
    "add CHANGES.md \"The comment says *\\\"the old address $(printf '—') the classic\\\"*.\"" \
    clean
arm "8d" "an en dash range between code spans" \
    "add docs/LIMITATIONS.md \"The stubs \\\`isr34\\\`$(printf '–')\\\`isr47\\\` exist.\"" \
    clean
arm "8e" "an American identifier in a code span" \
    "add docs/ARCHITECTURE.md 'See \`storage_authorize_format\` and \`color\`.'" \
    clean
arm "8f" "CSS 'color' in the website's style element" \
    "sed -i 's#</head>#<style>p { color: red; }</style></head>#' site-src/layout.html" \
    clean
arm "8g" "a cell of two code spans and a comma is not a mangled dash" \
    "add docs/SYSCALLS.md \$'| a | b |\n|---|---|\n| 1 | \`x\`, \`y\` |'" \
    clean

# ---- THE MASKER DEFECTS. Each hid real prose from the sweep before this
#      checker existed.
#
# 9a: backticks were paired across the whole file, so one stray backtick swapped
#     code and prose for the rest of it; DEVLOG-2026.md hid 179 dashes that way.
#     Pairing is per paragraph now, and a later paragraph must still be checked.
arm "9a" "a stray backtick does not hide the next paragraph" \
    "add docs/BUILDING.md 'A lone \` backtick.'; add docs/BUILDING.md \"Later prose $(printf '—') still checked.\"" \
    caught "docs/BUILDING.md:"
# 9b: every line indented four spaces was treated as an indented code block, and
#     a list item's continuation line is indented exactly like that.
arm "9b" "an em dash on an indented list continuation line" \
    "add CHANGES.md \$'  - An item\n    that continues $(printf '—') here.'" \
    caught "CHANGES.md:"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
