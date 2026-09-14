#!/usr/bin/env bash
# Falsify tools/check_keymaps.py -- in every direction, including the silent one.
#
# The checker's whole job is to refuse a layout that nothing tests. A checker
# which cannot fail refuses nothing, and the first run of any checker is against
# a tree its author has just made correct, so passing proves nothing on its own.
#
# EVERY ARM EDITS A COPY. The originals are restored by the trap whatever
# happens, because a half-applied arm left in the tree is a defect introduced by
# a test -- and this edits three files that the build depends on.
set -u
cd "$(dirname "$0")/.."

H=include/ps2_scancode.h
K=tools/keymap_session.py
M=Makefile
BK=$(mktemp -d)
cp "$H" "$BK/h"; cp "$K" "$BK/k"; cp "$M" "$BK/m"
restore() { cp "$BK/h" "$H"; cp "$BK/k" "$K"; cp "$BK/m" "$M"; rm -rf "$BK"; }
trap restore EXIT INT TERM

fail=0
check() {  # check <want:pass|fail> <description>
    local want=$1 desc=$2
    if python3 tools/check_keymaps.py >/dev/null 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then
        echo "  [ OK ] $desc (checker $got, as it must)"
    else
        echo "  [FAIL] $desc -- checker $got, expected $want"
        fail=1
    fi
}

echo "falsifying tools/check_keymaps.py:"

# THE SILENT DIRECTION FIRST. If the tree as committed does not pass, every
# result below is meaningless -- the arms would "fail" for the wrong reason.
check pass "the tree as committed"

# A layout that exists and is tested by nothing: the defect this is FOR.
python3 - "$H" <<'PY'
import io,sys
p=sys.argv[1]; s=io.open(p,encoding="utf-8").read()
s=s.replace('    { "uk", ps2_uk_lower, ps2_uk_upper, 0 },',
            '    { "uk", ps2_uk_lower, ps2_uk_upper, 0 },\n    { "de", ps2_us_lower, ps2_us_upper, 0 },',1)
io.open(p,"w",encoding="utf-8").write(s)
PY
check fail "a layout added to ps2_layouts[] with no EXPECT row and no target"
cp "$BK/h" "$H"

# The reverse: an assertion for a keyboard that does not exist.
python3 - "$K" <<'PY'
import io,sys
p=sys.argv[1]; s=io.open(p,encoding="utf-8").read()
s=s.replace('    "uk": ["\\\\", "|", "#",  "~", \'"\', "@", ""],',
            '    "uk": ["\\\\", "|", "#",  "~", \'"\', "@", ""],\n    "fr": ["", "", "", "", "", "", ""],',1)
io.open(p,"w",encoding="utf-8").write(s)
PY
check fail "an EXPECT row for a layout that is not in ps2_layouts[]"
cp "$BK/k" "$K"

# A layout asserted and declared, but never built and booted.
python3 - "$M" <<'PY'
import io,sys
p=sys.argv[1]; s=io.open(p,encoding="utf-8").read()
s=s.replace("smoke-keymap-uk:\n","smoke-keymap-uk-DISABLED:\n",1)
io.open(p,"w",encoding="utf-8").write(s)
PY
check fail "a layout with no smoke-keymap-<name> target"
cp "$BK/m" "$M"

# A row that covers fewer keys than the harness presses: the extra keys would be
# compared against nothing, which is a gate quietly narrowing itself.
python3 - "$K" <<'PY'
import io,sys
p=sys.argv[1]; s=io.open(p,encoding="utf-8").read()
s=s.replace('    "us": ["",   "",  "\\\\", "|", "@", \'"\', "#"],',
            '    "us": ["",   "",  "\\\\", "|", "@"],',1)
io.open(p,"w",encoding="utf-8").write(s)
PY
check fail "an EXPECT row asserting fewer keys than KEYS presses"
cp "$BK/k" "$K"

# And silent again at the end, which proves the restores above actually restored.
check pass "the tree again, after every arm was undone"

echo
if [ "$fail" = 0 ]; then echo "CHECK_KEYMAPS_FALSIFICATION: PASS"; else echo "CHECK_KEYMAPS_FALSIFICATION: FAIL"; fi
exit "$fail"
