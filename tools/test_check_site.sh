#!/usr/bin/env bash
# Falsify tools/check_site.py: one arm per rule, plus the directions that must stay
# SILENT. Each arm copies the site's sources, output and tools into a temporary
# tree, plants one defect, and requires the checker to fail NAMING that rule. A
# checker that failed for some other reason would pass a lax harness, so the rule
# is part of what is asserted.
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
  mkdir -p "$1/tools" && cp -r "$ROOT/site" "$ROOT/site-src" "$1/" &&
    cp "$ROOT/tools/build_site.py" "$ROOT/tools/check_site.py" "$1/tools/"
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

REBUILD='python3 tools/build_site.py'

echo "Falsifying tools/check_site.py:"

arm "clean" "the site as it stands" "true" clean

# R1: the committed output and the sources disagree, in both directions.
arm "R1a" "a built page edited by hand" \
  'printf "<p>edited in the output</p>\n" >> site/status.html' caught "R1"
arm "R1b" "a source edited and not rebuilt" \
  'sed -i "s/Research-grade/Research grade/" site-src/layout.html' caught "R1"
arm "R1c" "a stray file in site/ that no source produces" \
  'printf "x" > site/stray.html' caught "R1"

# R2: a link that goes nowhere, to a missing anchor and to a missing page.
arm "R2a" "a link to an anchor no page has" \
  "sed -i 's|href=\"why.html\">How capabilities work|href=\"why.html#no-such-section\">How capabilities work|' site-src/pages/index.html && $REBUILD" caught "R2"
arm "R2b" "a link to a page that does not exist" \
  "sed -i 's|href=\"status.html\"|href=\"state.html\"|' site-src/pages/index.html && $REBUILD" caught "R2"

# R3: bytes from another origin, from markup and from the stylesheet.
arm "R3a" "a script loaded from a CDN" \
  "sed -i 's|<script src=\"assets/site.js\"></script>|<script src=\"https://cdn.example.net/site.js\"></script>|' site-src/layout.html && $REBUILD" caught "R3"
arm "R3b" "a webfont imported by the stylesheet" \
  "sed -i '1i @import url(\"https://fonts.example.net/css?family=X\");' site-src/assets/site.css && $REBUILD" caught "R3"
arm "R3c" "an image hotlinked from another site" \
  "sed -i 's|<section class=\"honest\"|<img src=\"https://tracker.example.net/p.gif\" alt=\"\"><section class=\"honest\"|' site-src/pages/index.html && $REBUILD" caught "R3"

# R4: page structure and reachability.
arm "R4a" "a page with a second h1" \
  "sed -i '0,/<section class=\"part\"/s//<h1>Another title<\/h1><section class=\"part\"/' site-src/pages/boot.html && $REBUILD" caught "R4"
arm "R4b" "a page no menu reaches" \
  "sed -i '1s/\"layout\": \"doc\"/\"layout\": \"doc\", \"nav_hidden\": true/' site-src/pages/testing.html && $REBUILD" caught "not in the primary navigation"

# THE SILENT DIRECTIONS: an ordinary outbound link, and a data: URI favicon, are
# not subresources from another origin; a checker that flagged them would be
# switched off rather than obeyed.
arm "S1" "an ordinary link out to another site" \
  "sed -i 's|<section class=\"honest\"|<p><a href=\"https://example.org/\">elsewhere</a></p><section class=\"honest\"|' site-src/pages/index.html && $REBUILD" clean
arm "S2" "the inline data: URI favicon the layout already carries" "true" clean

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
