#!/usr/bin/env bash
# Falsify tools/check_console_font.py: one arm per rule, and the tree as
# committed first, since every arm below is meaningless if that does not pass.
#
# EVERY ARM EDITS A COPY. The originals are restored by the trap whatever
# happens: both files are compiled into the kernel and console_server, and a
# half-applied arm left in the tree is a defect introduced by a test.
set -u
cd "$(dirname "$0")/.."

F=include/console_font.h
C=userspace/console_server.c
BK=$(mktemp -d)
cp "$F" "$BK/f"; cp "$C" "$BK/c"
restore() { cp "$BK/f" "$F"; cp "$BK/c" "$C"; rm -rf "$BK"; }
trap restore EXIT INT TERM

fail=0
check() {  # check <want:pass|fail> <description> [text the FAIL must contain]
    local want=$1 desc=$2 needle=${3:-}
    local out got
    if out=$(python3 tools/check_console_font.py 2>&1); then got=pass; else got=fail; fi
    if [ "$got" != "$want" ]; then
        echo "  [FAIL] $desc: checker $got, expected $want"
        echo "$out" | head -5 | sed 's/^/         /'
        fail=1
    elif [ -n "$needle" ] && ! grep -qF -- "$needle" <<<"$out"; then
        # Red for the wrong reason is not this rule firing.
        echo "  [FAIL] $desc: checker failed, but not with \"$needle\""
        echo "$out" | head -5 | sed 's/^/         /'
        fail=1
    else
        echo "  [ OK ] $desc (checker $got, as it must)"
    fi
}

# edit <file> <old> <new>: replace exactly one occurrence, or abort the arm loudly.
edit() {
    python3 - "$1" "$2" "$3" <<'PY' || { echo "  [FAIL] arm could not be applied"; exit 1; }
import io, sys
p, old, new = sys.argv[1:]
s = io.open(p, encoding="utf-8").read()
if s.count(old) != 1:
    sys.exit("arm text found %d times in %s" % (s.count(old), p))
io.open(p, "w", encoding="utf-8").write(s.replace(old, new))
PY
}

echo "falsifying tools/check_console_font.py:"

check pass "the tree as committed"

# Rule 1: a malformed entry, one row short.
edit "$F" "[0xC4] = {0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00}," "[0xC4] = {0x00,0x00,0x00,0xFF,0x00,0x00,0x00},"
check fail "rule 1: an 8x8 entry with seven rows" "7 rows, wanted 8"
cp "$BK/f" "$F"

# Rule 2: a printable ASCII letter blanked in the 8x8.
edit "$F" "['z'] = {0x00,0x00,0x7C,0x08,0x10,0x20,0x7C,0x00}," "['z'] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},"
check fail "rule 2: 'z' drawn blank in the 8x8" "no glyph for 'z'"
cp "$BK/f" "$F"

# Rule 3, the defect this checker is for: the 8x8 loses a glyph the 8x16 has.
# The full block is the kernel's progress bar and is not an acs_to_cp437
# target, so only rule 3 can catch it.
edit "$F" "[0xDB] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},   /* full block */" ""
check fail "rule 3: the 8x8 without the progress bar's full block" "0xDB has a glyph in font_8x16 and none in font_8x8"
cp "$BK/f" "$F"

# Rule 3, the other direction: the 8x16 loses one the 8x8 has.
edit "$F" "    [0xAF] = {0x00,0x00,0x00,0x00,0xD8,0x6C,0x36,0x6C,0xD8,0x00,0x00,0x00,0x00,0x00,0x00,0x00},   /* right guillemet */" ""
check fail "rule 3: the 8x16 without a glyph the 8x8 draws" "0xAF has a glyph in font_8x8 and none in font_8x16"
cp "$BK/f" "$F"

# Rule 4: the box translation gains a target neither font draws. Rule 3 is
# silent here, since the two tables still agree; only rule 4 can see it.
edit "$C" "        case 'a': return 0xB1u;   /* chequerboard */" "        case 'a': return 0xB1u;   /* chequerboard */
        case 'o': return 0xE9u;"
check fail "rule 4: acs_to_cp437 returns a code point neither font draws" "acs_to_cp437 can return 0xE9"
cp "$BK/c" "$C"

# Rule 4's own guard: the translation renamed, so there is nothing to check.
edit "$C" "static uint8_t acs_to_cp437(uint8_t c) {" "static uint8_t acs_to_glyph(uint8_t c) {"
check fail "rule 4: acs_to_cp437 not found" "acs_to_cp437 was not found"
cp "$BK/c" "$C"

if [ $fail -ne 0 ]; then
    echo "test_check_console_font: FAIL"
    exit 1
fi
echo "test_check_console_font: PASS (every rule fires, and the committed tree passes)"
