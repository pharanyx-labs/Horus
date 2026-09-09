#!/usr/bin/env bash
# Falsify tools/check_defect_flags.py -- one arm per rule, and both directions
# of the exemption that rule 3 depends on.
#
# The checker had no self-test until 2026-09-10, which is the day rule 3 found
# two flags that had been defining a macro nothing read: NET_NO_BUSMASTER since
# 2026-08-28 and SDHCI_WRITE_NO_FLUSH since 2026-09-07. A rule written after a
# finding is a rule whose author has just made the tree satisfy it, so each one
# below is exercised against a tree mutated to break it.
#
# Mutations are applied to a COPY. Nothing here can leave the tree modified.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/docs"
  cp "$ROOT/Makefile" "$1/"
  cp "$ROOT/tools/check_defect_flags.py" "$1/tools/"
  cp "$ROOT/docs/BUILDING.md" "$1/docs/"
  cp -r "$ROOT/src" "$ROOT/userspace" "$ROOT/include" "$1/"
  mkdir -p "$1/rust"; cp -r "$ROOT/rust/src" "$1/rust/" 2>/dev/null
  cp "$ROOT"/tools/*.sh "$ROOT"/tools/*.py "$1/tools/" 2>/dev/null
  true
}

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect(caught|clean), $5 must-name
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_defect_flags.py 2>&1)"; rc=$?
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

echo "Falsifying tools/check_defect_flags.py:"

# Rule 1: a flag with no row in the table.
arm "1" "a DEFECT_FLAGS member with no table row" \
    "sed -i 's/^| \`NET_NO_DECODE=1\` |/| \`NET_NO_DECODE_RENAMED=1\` |/' docs/BUILDING.md" \
    caught "NET_NO_DECODE"

# Rule 2: a row naming a flag no build defines.
arm "2" "a table row for a flag that is not in DEFECT_FLAGS" \
    'printf "\n| \140FLAG_THAT_NEVER_WAS=1\140 | invented | none |\n" >> docs/BUILDING.md' \
    caught "FLAG_THAT_NEVER_WAS"

# Rule 3, the one this file was written for: the flag is defined by the build
# and read by nothing. This is exactly the state NET_NO_BUSMASTER shipped in.
arm "3a" "a flag whose #ifdef is gone from the source" \
    "sed -i 's/#elif defined(NET_NO_BUSMASTER)/#elif defined(NET_NO_BUSMASTER_GONE)/g' userspace/netd.c" \
    caught "NET_NO_BUSMASTER"

arm "3b" "the same, in the kernel rather than in ring 3" \
    "sed -i 's/#ifdef SDHCI_WRITE_NO_FLUSH/#ifdef SDHCI_WRITE_NO_FLUSH_GONE/' src/kernel/sdhci.c" \
    caught "SDHCI_WRITE_NO_FLUSH"

# Rule 3, the other direction: a flag whose effect is in the BUILD is declared,
# not reported. Without this the rule would demand an #ifdef for flags that
# correctly have none.
arm "3c" "a declared build-level effect is not a finding" \
    "true" clean

# And the exemption must be load-bearing: drop one and its flag becomes a
# finding. An exemption nobody has watched fire is a line of configuration.
arm "3d" "removing a build-effect declaration makes its flag visible" \
    "python3 - <<'P'
import pathlib
p = pathlib.Path('tools/check_defect_flags.py'); s = p.read_text()
s = s.replace('    \"META_CACHE_TINY\":       \"the Makefile: -DMETA_CACHE_LINES=2, which src/include/kernel.h reads\",\n', '')
p.write_text(s)
P" \
    caught "META_CACHE_TINY"

# The parser itself: a Makefile it cannot read must not pass with nothing to
# compare against.
arm "4" "a Makefile with no DEFECT_FLAGS assignment fails loudly" \
    "sed -i 's/^DEFECT_FLAGS = /DEFECT_FLAGS_RENAMED = /' Makefile" \
    caught "no DEFECT_FLAGS assignment"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ] || exit 1
