#!/usr/bin/env python3
"""Both console fonts draw the same characters, and draw every one the console sends.

include/console_font.h holds two tables. font_8x8 is uploaded into the VGA font
plane by the kernel and is what a BIOS boot in text mode renders; font_8x16 is
what the framebuffer console blits, in the kernel and in console_server. A code
point with no entry is drawn BLANK, not from the ROM font: the upload replaces
all 256 entries of the font plane, and the blitter has nothing else to draw.

Until 2026-09-25 the 8x8 had nothing above 0x7F. console_server translates the
installer's box-drawing letters into CP437 line glyphs, and the kernel's format
progress bar is 0xDB and 0xB0, so on a text-mode boot the installer had no frame
and the progress bar was two brackets with nothing between them. The 8x16 had
had those glyphs since 2026-09-23, and every framebuffer gate passed. Nothing
compared the two tables, and the defect is invisible on the wire: the serial
line carries the letters, never the glyphs.

Rules (each has an arm in tools/test_check_console_font.sh):

  1. every entry has the table's row count (8 or 16 bytes, each 0x00-0xFF);
  2. every printable ASCII character, 0x21 to 0x7E, has ink in both tables;
  3. a code point with ink in one table has ink in the other;
  4. every code point acs_to_cp437 in userspace/console_server.c can return
     has ink in both tables. Rule 3 alone would pass with the glyph missing
     from both, which is exactly how the 8x16 started.

Exit 0 and one PASS line; 1 and a FAIL line per violation.
"""
import re
import sys

FONT = "include/console_font.h"
CONSOLE = "userspace/console_server.c"


def table(src, name, height):
    """{code point: [row bytes]} for one table, and a list of malformed entries."""
    m = re.search(r"static const uint8_t %s\[256\]\[%d\] = \{(.*?)\n\};" % (name, height),
                  src, re.S)
    if not m:
        return None, ["%s: the table %s[256][%d] was not found" % (FONT, name, height)]
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    glyphs, bad = {}, []
    for key, vals in re.findall(r"\[\s*('(?:\\.|[^'])'|0[xX][0-9A-Fa-f]+|\d+)\s*\]\s*=\s*\{([^}]*)\}",
                                body):
        if key.startswith("'"):
            ch = key[1:-1]
            cp = ord(ch[1]) if ch.startswith("\\") else ord(ch)
        else:
            cp = int(key, 0)
        try:
            rows = [int(v.strip(), 0) for v in vals.split(",") if v.strip()]
        except ValueError:
            bad.append("%s %s[0x%02X]: a row that is not a number" % (FONT, name, cp))
            continue
        if len(rows) != height or any(r < 0 or r > 0xFF for r in rows):
            bad.append("%s %s[0x%02X]: %d rows, wanted %d bytes of 0x00-0xFF"
                       % (FONT, name, cp, len(rows), height))
            continue
        glyphs[cp] = rows
    return glyphs, bad


def inked(t):
    return {cp for cp, rows in t.items() if any(rows)}


def acs_targets(src):
    m = re.search(r"static uint8_t acs_to_cp437\(uint8_t c\)\s*\{(.*?)\n\}", src, re.S)
    if not m:
        return None
    return {int(v, 16) for v in re.findall(r"return\s+(0x[0-9A-Fa-f]+)u?\s*;", m.group(1))}


def main():
    try:
        font = open(FONT, encoding="utf-8").read()
        con = open(CONSOLE, encoding="utf-8").read()
    except OSError as e:
        print("check_console_font: FAIL %s" % e)
        return 1
    errs = []
    t8, b8 = table(font, "font_8x8", 8)
    t16, b16 = table(font, "font_8x16", 16)
    errs += b8 + b16
    if t8 is None or t16 is None:
        for e in errs:
            print("check_console_font: FAIL " + e)
        return 1
    i8, i16 = inked(t8), inked(t16)

    for cp in range(0x21, 0x7F):
        for name, ink in (("font_8x8", i8), ("font_8x16", i16)):
            if cp not in ink:
                errs.append("%s has no glyph for %r (0x%02X): printable ASCII is drawn blank"
                            % (name, chr(cp), cp))

    for cp in sorted(i16 - i8):
        errs.append("0x%02X has a glyph in font_8x16 and none in font_8x8: a text-mode "
                    "boot draws it blank" % cp)
    for cp in sorted(i8 - i16):
        errs.append("0x%02X has a glyph in font_8x8 and none in font_8x16: a framebuffer "
                    "console draws it blank" % cp)

    targets = acs_targets(con)
    if not targets:
        errs.append("%s: acs_to_cp437 was not found, or returns no code point; the "
                    "box-drawing translation cannot be checked" % CONSOLE)
    else:
        for cp in sorted(targets):
            for name, ink in (("font_8x8", i8), ("font_8x16", i16)):
                if cp not in ink:
                    errs.append("acs_to_cp437 can return 0x%02X, and %s has no glyph for it"
                                % (cp, name))

    if errs:
        for e in errs:
            print("check_console_font: FAIL " + e)
        return 1
    print("check_console_font: PASS %d code points drawn by both fonts, including all %d "
          "that acs_to_cp437 returns" % (len(i8), len(targets)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
