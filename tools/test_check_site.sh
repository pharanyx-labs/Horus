#!/usr/bin/env bash
# Falsify tools/check_site.py: one arm per rule, plus the directions that must stay
# SILENT. Each arm copies site/ and the checker into a temporary tree, plants one
# defect, and requires the checker to fail NAMING that rule. A checker that failed
# for some other reason would pass a lax harness, so the rule is part of what is
# asserted.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

mktree () {
  mkdir -p "$1/tools" && cp -r "$ROOT/site" "$1/" && cp "$ROOT/tools/check_site.py" "$1/tools/"
}

arm () {  # $1 name, $2 desc, $3 mutation, $4 expect (caught|clean), $5 must-say
  local name="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  mktree "$d" || { echo "  $name: FIXTURE FAILED"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  ( cd "$d" && eval "$mut" ) >/dev/null 2>&1 || { echo "  $name: MUTATION FAILED -- $desc"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_site.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $name: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $name: caught but did not say '$want' -- $desc"; grep -E "^  -" <<<"$out" | head -2 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $name: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $name: WRONGLY CAUGHT -- $desc"; grep -E "^  -" <<<"$out" | head -3 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $name: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

# A mutation that changes a heading has to keep the search index current, or R7
# fires too and an arm meant for another rule would pass on the wrong finding.
REINDEX='{ python3 tools/check_site.py --write-index || true; }'

echo "Falsifying tools/check_site.py:"

arm "clean" "the site as it stands" "true" clean

# R1: the shared chrome, edited in one page only.
arm "R1a" "the site header's tagline edited in one page" \
  "sed -i 's|<span>Horus</span>|<span>Horus OS</span>|' site/status.html" caught "R1"
arm "R1b" "the footer edited in one page" \
  "sed -i '0,/<div class=\"foot__in\">/s//<div class=\"foot__in\"><p>extra<\/p>/' site/boot.html" caught "R1"
arm "R1c" "a stylesheet link added to one page's head" \
  "sed -i 's|</head>|<link rel=\"stylesheet\" href=\"assets/site.css\"></head>|' site/run.html" caught "R1"
arm "R1d" "a page without the shared landmarks" \
  "sed -i 's|<footer class=\"foot\">|<footer class=\"foot2\">|' site/why.html" caught "R1"

# R2: a link that goes nowhere.
arm "R2a" "a link to an anchor no page has" \
  "sed -i 's|href=\"why.html\">How capabilities work|href=\"why.html#no-such-section\">How capabilities work|' site/index.html" caught "R2"
arm "R2b" "a link to a page that does not exist" \
  "sed -i 's|<section class=\"part\" aria-labelledby=\"status\">|<section class=\"part\" aria-labelledby=\"status\"><a href=\"state.html\">x</a>|' site/status.html" caught "R2"

# R3: bytes from another origin.
arm "R3a" "a script loaded from a CDN, in every page" \
  "sed -i 's|<script src=\"assets/site.js\"></script>|<script src=\"https://cdn.example.net/site.js\"></script>|' site/*.html" caught "R3"
arm "R3b" "a webfont imported by the stylesheet" \
  "sed -i '1i @import url(\"https://fonts.example.net/css?family=X\");' site/assets/site.css" caught "R3"
arm "R3c" "an image hotlinked from another site" \
  "sed -i 's|<section class=\"honest\"|<img src=\"https://tracker.example.net/p.gif\" alt=\"\"><section class=\"honest\"|' site/index.html" caught "R3"

# R4: structure, reachability and the current-page mark.
arm "R4a" "a page with a second h1" \
  "sed -i '0,/<section class=\"part\"/s//<h1>Another title<\/h1><section class=\"part\"/' site/boot.html" caught "R4"
arm "R4b" "a page no menu reaches" \
  "sed -i 's|<a href=\"testing.html\"[^>]*>[^<]*</a>||' site/*.html" caught "not in the primary navigation"
arm "R4c" "a page whose menus mark another page as current" \
  "sed -i 's| aria-current=\"page\"||g; s|<a href=\"why.html\">|<a href=\"why.html\" aria-current=\"page\">|g' site/run.html" caught "R4"

# R5: the contents rail and heading ids.
arm "R5a" "a heading renamed without its rail entry" \
  "sed -i 's|data-toc=\"Capabilities\"|data-toc=\"Capability tokens\"|' site/why.html && $REINDEX" caught "R5"
arm "R5b" "a new heading with no id" \
  "sed -i '0,/<h2 id=\"capability\"/s//<h3>Unlinked<\/h3><h2 id=\"capability\"/' site/why.html && $REINDEX" caught "R5"

# R6: the reading order.
arm "R6" "a next link that skips a page" \
  "sed -i 's|class=\"pager__next\" href=\"architecture.html\"|class=\"pager__next\" href=\"status.html\"|' site/why.html" caught "R6"

# R7: the search index.
arm "R7" "a search index left stale by a heading edit" \
  "sed -i 's|data-toc=\"Capabilities\"|data-toc=\"Capability tokens\"|' site/why.html && sed -i 's|>Capabilities</a>|>Capability tokens</a>|' site/why.html" caught "R7"

# THE SILENT DIRECTIONS: an ordinary outbound link, and a heading edit made the
# right way (rail and index updated with it), are not defects; a checker that
# flagged them would be switched off rather than obeyed.
arm "S1" "an ordinary link out to another site" \
  "sed -i 's|<section class=\"honest\"|<p><a href=\"https://example.org/\">elsewhere</a></p><section class=\"honest\"|' site/index.html" clean
arm "S2" "a heading renamed with its rail entry and the index regenerated" \
  "sed -i 's|data-toc=\"Capabilities\"|data-toc=\"Capability tokens\"|; s|>Capabilities</a>|>Capability tokens</a>|' site/why.html && $REINDEX" clean

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
