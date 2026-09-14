/* ps2_scancode.h -- PS/2 scancode set 1 -> ASCII, shared by the kernel's early
 * console reader and the ring-3 console_server that takes over from it.
 *
 * WHY THIS IS A SHARED HEADER AND NOT TWO TABLES. Both sides read the same
 * controller and must agree on what a keystroke means: the kernel drives the
 * keyboard from boot until console_server takes the console, and console_server
 * drives it from then on. A user does not know where that line is, and a
 * password typed either side of it must produce the same bytes. Two copies of a
 * 58-entry table would agree on the day they were written and drift after --
 * and the way that failure presents is a password that is accepted at one prompt
 * and refused at the next, which is close to undiagnosable from a bug report.
 *
 * IT IS PURE LOGIC AND HOLDS NO AUTHORITY. No ports are touched here; the caller
 * has already read the byte from wherever it is entitled to read it, and passes
 * it in. The state is the caller's, one instance per reader, so the kernel's
 * shift state and console_server's cannot interfere -- which matters, because
 * exactly one of them is reading at any moment and the other's state is stale by
 * definition.
 *
 * SCANCODE SET 1, which is what the 8042 translates to by default and what both
 * QEMU and every PC-compatible controller present unless asked otherwise. A make
 * code is 0x00-0x7F; the break code is the make code | 0x80. Extended keys are
 * prefixed 0xE0.
 */
#ifndef HORUS_PS2_SCANCODE_H
#define HORUS_PS2_SCANCODE_H

/* Modifier make codes (break = | 0x80). */
#define PS2_SC_LCTRL   0x1D
#define PS2_SC_LSHIFT  0x2A
#define PS2_SC_RSHIFT  0x36
#define PS2_SC_LALT    0x38   /* with the 0xE0 prefix this is right alt: AltGr */
#define PS2_SC_CAPS    0x3A
#define PS2_SC_E0      0xE0

/* The ISO 102nd key: the extra key between left shift and Z that every ISO
 * keyboard has and no ANSI one does. On UK it carries `\` and `|`. It is the
 * reason PS2_SC_MAX is 0x56 and not 0x39. */
#define PS2_SC_ISO102  0x56

/* Highest scancode the tables cover. Anything above it yields PS2_KEY_NONE
 * rather than an arbitrary byte -- returning something plausible for a key
 * nobody pressed is worse than returning nothing.
 *
 * IT WAS 0x39 (space) UNTIL 2026-09-14, AND THAT WAS THE WHOLE OF A REAL BUG:
 * the ISO 102nd key is 0x56, so on every ISO keyboard the key carrying `\` and
 * `|` was dropped before the lookup ever happened. Reported from an IdeaPad 1
 * 14IGL05 (UK) as "I cannot type | into the shell", which the shell does support
 * -- it runs pipelines. The range now reaches 0x56 so that key is addressable at
 * all; the gap between 0x3A and 0x55 is spelled out below rather than skipped,
 * so the keypad and the function keys are a table edit away rather than another
 * range change. */
#define PS2_SC_MAX     PS2_SC_ISO102

/* ps2_feed returns either a character (1..0x7F) or one of these, which are
 * deliberately above the byte range so they cannot collide with one. A caller
 * that only wants characters -- the kernel's early line reader -- tests
 * `< 0x100` and ignores the rest, which is what it did before these existed.
 *
 * ONLY THE KEYS A TERMINAL DECODER ACTUALLY ACCEPTS ARE HERE. Page Up and Page
 * Down are absent on purpose although the hardware sends them: userspace/tui.c
 * decodes ESC [ A/B/C/D/H/F and the numeric ESC [ n ~ forms for Home and End,
 * and anything else it reads as a BARE ESC -- which in the installer means
 * "cancel this screen". Emitting a sequence the decoder does not know would
 * turn Page Down into a cancel on the screen that chooses which disk to erase.
 * A key that does nothing is correct; a key that cancels is a defect. */
#define PS2_KEY_NONE   0
#define PS2_KEY_UP     0x101
#define PS2_KEY_DOWN   0x102
#define PS2_KEY_RIGHT  0x103
#define PS2_KEY_LEFT   0x104
#define PS2_KEY_HOME   0x105
#define PS2_KEY_END    0x106

/* ---- layouts ---------------------------------------------------------------
 *
 * A LAYOUT IS DATA, NOT CODE, and that is the point of this section. Before
 * 2026-09-14 there was one pair of tables wired straight into the lookup, so a
 * keyboard that was not US/ANSI produced wrong characters for several keys and
 * nothing at all for the one key ANSI does not have. Adding a keyboard is now
 * adding a `struct ps2_layout` and a line in ps2_layouts[]; nothing in ps2_feed
 * changes.
 *
 * EVERY LEVEL IS INDEXED BY MAKE CODE, 0x00..PS2_SC_MAX, so a level is a plain
 * lookup and never a search. A '\0' means "this key produces no character at
 * this level" -- an unassigned code, a modifier, or a key whose character is not
 * ASCII. That last case is real and deliberate: UK Shift+3 is a pound sign and
 * AltGr+4 a euro sign, neither of which fits in the char this console deals in,
 * so both are '\0' and the key does nothing rather than producing a wrong byte.
 * Say what that costs rather than papering over it: on a UK keyboard, Shift+3
 * types nothing.
 *
 * THE GAP IS SPELLED OUT so the two levels of a layout cannot disagree about its
 * width, and so the keypad becomes one edit rather than a range change. */
#define PS2_GAP_3A_55 \
    "\0\0\0\0\0\0\0\0\0\0"   /* 0x3A caps, 0x3B..0x44 F1-F10        */ \
    "\0\0\0\0\0\0\0\0\0\0"   /* 0x45 num, 0x46 scroll, keypad 7..4  */ \
    "\0\0\0\0\0\0\0\0"       /* keypad 5..0, '.', 0x54, 0x55        */

/* 0x00..0x39, then the gap, then 0x56. Split across literals where a hex escape
 * would otherwise swallow the next digit -- "\x1b1" is one character 0x1b1, not
 * ESC followed by '1'. */
#define PS2_ROW_US_LOWER \
    "\0\x1b" "1234567890-=\b\t" "qwertyuiop[]\n\0" "asdfghjkl;'`\0\\" "zxcvbnm,./\0*\0 "
#define PS2_ROW_US_UPPER \
    "\0\x1b" "!@#$%^&*()_+\b\t" "QWERTYUIOP{}\n\0" "ASDFGHJKL:\"~\0|" "ZXCVBNM<>?\0*\0 "

/* UK ISO. Five keys differ from US and one exists that US does not have:
 *
 *   0x03  2      "   (US @)
 *   0x04  3      -   (US #; UK is a pound sign, not ASCII, so nothing)
 *   0x28  '      @   (US ' ")
 *   0x29  `      -   (US ` ~; UK shifted is a not sign, not ASCII)
 *   0x2B  #      ~   (US \ |)
 *   0x56  \      |   the ISO 102nd key, which US does not have at all
 *
 * Note where `\` and `|` went: on this keyboard they are NOT on 0x2B. That is
 * why a UK machine running the US tables could still produce `|` -- from the
 * key left of Enter, labelled `#` -- which is exactly the kind of "it works if
 * you press the wrong key" that made the bug confusing to report. */
#define PS2_ROW_UK_LOWER \
    "\0\x1b" "1234567890-=\b\t" "qwertyuiop[]\n\0" "asdfghjkl;'`\0#" "zxcvbnm,./\0*\0 "
#define PS2_ROW_UK_UPPER \
    "\0\x1b" "!\"\0$%^&*()_+\b\t" "QWERTYUIOP{}\n\0" "ASDFGHJKL:@\0\0~" "ZXCVBNM<>?\0*\0 "

/* One keyboard. `altgr` is the third level (right alt, 0xE0 0x38) and is NULL
 * for both layouts shipped today, because neither produces an ASCII character
 * that way: UK AltGr gives a euro sign, a broken bar and accented letters, none
 * of which this console can represent. It is in the struct and honoured by
 * ps2_feed because the layouts that need it next -- German and French put @, \,
 * |, { and } on AltGr -- are exactly the ones "expand to other keyboards" means,
 * and the alternative is that adding one of those changes ps2_feed instead of
 * adding a row here. It is a hook with no user yet, and that is stated rather
 * than hidden: the first layout to fill it is also the first to test it. */
struct ps2_layout {
    const char *name;    /* what the build selects and the boot log prints */
    const char *lower;   /* unshifted                                      */
    const char *upper;   /* shift held                                     */
    const char *altgr;   /* right alt held; NULL if the layout has no level*/
};

static const char ps2_us_lower[] = PS2_ROW_US_LOWER PS2_GAP_3A_55 "\0";
static const char ps2_us_upper[] = PS2_ROW_US_UPPER PS2_GAP_3A_55 "\0";
static const char ps2_uk_lower[] = PS2_ROW_UK_LOWER PS2_GAP_3A_55 "\\";
static const char ps2_uk_upper[] = PS2_ROW_UK_UPPER PS2_GAP_3A_55 "|";

/* EVERY LEVEL IS THE SAME WIDTH AS THE SCANCODE RANGE, checked here rather than
 * trusted. A table one byte short reads past its end for the ISO key -- which is
 * the LAST entry, so it is the one a miscount hits first. */
_Static_assert(sizeof(ps2_us_lower) == PS2_SC_MAX + 2, "ps2_us_lower must cover 0x00..PS2_SC_MAX");
_Static_assert(sizeof(ps2_us_upper) == PS2_SC_MAX + 2, "ps2_us_upper must cover 0x00..PS2_SC_MAX");
_Static_assert(sizeof(ps2_uk_lower) == PS2_SC_MAX + 2, "ps2_uk_lower must cover 0x00..PS2_SC_MAX");
_Static_assert(sizeof(ps2_uk_upper) == PS2_SC_MAX + 2, "ps2_uk_upper must cover 0x00..PS2_SC_MAX");

static const struct ps2_layout ps2_layouts[] = {
    { "us", ps2_us_lower, ps2_us_upper, 0 },
    { "uk", ps2_uk_lower, ps2_uk_upper, 0 },
};
#define PS2_LAYOUT_COUNT ((int)(sizeof(ps2_layouts) / sizeof(ps2_layouts[0])))

/* The build's default, as a NAME rather than an index, so a layout can be added
 * anywhere in the table without silently changing what an existing build
 * selects. KEYMAP=uk sets it; see docs/BUILDING.md. */
#ifndef PS2_LAYOUT_DEFAULT
#define PS2_LAYOUT_DEFAULT "us"
#endif

/* Look a layout up by name. Returns the US layout for a name nothing matches,
 * because a console that refuses to map any key at all is worse than one mapping
 * the wrong ones: the second can be typed at and corrected, the first cannot. */
static inline const struct ps2_layout *ps2_layout_by_name(const char *name)
{
    if (name) {
        for (int i = 0; i < PS2_LAYOUT_COUNT; i++) {
            const char *a = ps2_layouts[i].name, *b = name;
            while (*a && *a == *b) { a++; b++; }
            if (*a == 0 && *b == 0) return &ps2_layouts[i];
        }
    }
    return &ps2_layouts[0];
}

static inline const struct ps2_layout *ps2_layout_default(void)
{
    return ps2_layout_by_name(PS2_LAYOUT_DEFAULT);
}

/* One reader's modifier state. Zero-initialised is the correct starting state:
 * no modifier held, caps off, no pending prefix. */
struct ps2_state {
    unsigned char shift;   /* either shift key is down                         */
    unsigned char ctrl;    /* either control key is down                       */
    unsigned char altgr;   /* right alt (0xE0 0x38) is down                    */
    unsigned char caps;    /* caps lock is latched on                          */
    unsigned char e0;      /* the previous byte was the 0xE0 extended prefix   */
    /* NULL means the build's default, so a caller that zero-initialises its
     * state -- which both readers do -- gets a working keyboard without knowing
     * this field exists. Resolved on use rather than at init because there is no
     * init: the state is a plain struct the caller owns. */
    const struct ps2_layout *layout;
};

/* Feed one scancode. Returns a character (1..0x7F), one of the PS2_KEY_* codes
 * above, or PS2_KEY_NONE for a byte that produces neither -- a break code, a
 * modifier, or a code outside the table. 0 is "nothing to deliver", never a key.
 *
 * THE EXTENDED KEYS ARE WHY THIS RETURNS AN int. The installer's disk menu is
 * driven by the arrows (tui_menu reads TUI_KEY_UP / TUI_KEY_DOWN), so a
 * keyboard that dropped them would let a person at the machine type the fields
 * and not choose which disk to install onto -- most of a usable installer, and
 * the wrong most. Returning them symbolically lets the ring-3 console expand
 * each into the ESC [ A sequence a serial terminal sends, so the TUI's decoder
 * handles both inputs with one path and no special case.
 *
 * Delete (0xE0 0x53) comes back as the character 0x7F rather than a symbol,
 * because it already IS a character every reader here understands: con_getline
 * treats it as a backspace and tui_getkey maps it to TUI_KEY_BACKSP.
 *
 * CAPS LOCK APPLIES TO LETTERS ONLY, and shift inverts it. That is the platform
 * convention every terminal follows: caps lock on and shift held gives 'a', not
 * 'A', and neither affects the digit row. Applying caps to the whole table --
 * the obvious one-line version -- turns caps lock into a shift lock and makes
 * the number row unusable while it is on. */
static inline int ps2_feed(struct ps2_state *st, unsigned char sc)
{
    if (st->e0) {
        st->e0 = 0;
        /* Track the RIGHT control key, whose make code is 0xE0 0x1D: without
         * this, releasing right-control leaves ctrl stuck down for a reader
         * that only ever saw the prefix. */
        if (sc == PS2_SC_LCTRL)          { st->ctrl = 1; return PS2_KEY_NONE; }
        if (sc == (PS2_SC_LCTRL | 0x80)) { st->ctrl = 0; return PS2_KEY_NONE; }
        /* RIGHT ALT IS ALTGR ON EVERY LAYOUT THAT HAS ONE, and is tracked even
         * though no shipped layout fills that level yet: a held modifier whose
         * release is never seen is the bug that leaves a keyboard stuck, and
         * tracking it costs two lines whether or not a table uses it. */
        if (sc == PS2_SC_LALT)           { st->altgr = 1; return PS2_KEY_NONE; }
        if (sc == (PS2_SC_LALT | 0x80))  { st->altgr = 0; return PS2_KEY_NONE; }
        switch (sc) {
            case 0x53: return 0x7F;              /* Delete  */
            case 0x48: return PS2_KEY_UP;
            case 0x50: return PS2_KEY_DOWN;
            case 0x4D: return PS2_KEY_RIGHT;
            case 0x4B: return PS2_KEY_LEFT;
            case 0x47: return PS2_KEY_HOME;
            case 0x4F: return PS2_KEY_END;
            default:   return PS2_KEY_NONE;      /* incl. every break code */
        }
    }
    if (sc == PS2_SC_E0) { st->e0 = 1; return PS2_KEY_NONE; }

    if (sc == PS2_SC_LSHIFT || sc == PS2_SC_RSHIFT)               { st->shift = 1; return PS2_KEY_NONE; }
    if (sc == (PS2_SC_LSHIFT | 0x80) || sc == (PS2_SC_RSHIFT | 0x80)) { st->shift = 0; return PS2_KEY_NONE; }
    if (sc == PS2_SC_LCTRL)          { st->ctrl = 1; return PS2_KEY_NONE; }
    if (sc == (PS2_SC_LCTRL | 0x80)) { st->ctrl = 0; return PS2_KEY_NONE; }
    /* Caps latches on the MAKE code only. Toggling on both make and break would
     * turn every press into an on-then-off pair and leave the lamp's state and
     * the reader's permanently opposed. */
    if (sc == PS2_SC_CAPS)           { st->caps = !st->caps; return PS2_KEY_NONE; }

    if (sc & 0x80) return PS2_KEY_NONE;       /* any other break code         */
    if (sc > PS2_SC_MAX) return PS2_KEY_NONE; /* a key outside the table      */

    const struct ps2_layout *ly = st->layout ? st->layout : ps2_layout_default();

#ifdef PS2_LAYOUT_IGNORED
    /* CONTROL ARM -- never ship. The reader as it stood before 2026-09-14: one
     * hardcoded US layout, and a range that stopped at space. Both halves of the
     * defect are restored together because they were one defect: on an ISO
     * keyboard the `\`/`|` key is 0x56 and is dropped here, while `"`, `@`, `#`
     * and `~` come back as their US counterparts. */
    if (sc > 0x39) return PS2_KEY_NONE;
    ly = &ps2_layouts[0];
#endif

    /* ALTGR FIRST, because it is a level and not a modifier of one: on the
     * layouts that have it, AltGr+key is its own character and neither shift nor
     * the unshifted table has any say. A layout without the level falls through
     * to shift/unshifted, so holding right alt on US or UK types what the key
     * would have typed anyway rather than nothing. */
    char c;
    if (st->altgr && ly->altgr) {
        c = ly->altgr[sc];
    } else {
        c = st->shift ? ly->upper[sc] : ly->lower[sc];
    }
    if (c == 0) return PS2_KEY_NONE;

    if (st->caps && c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    else if (st->caps && c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');

    /* Control characters last, so Ctrl-Shift-C is Ctrl-C and not a separate key.
     * Only the letters produce one: Ctrl-1 is not a control character on any
     * terminal, and mapping it to 0x01 would send a keystroke nobody typed. */
    if (st->ctrl) {
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 1);
        else if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 1);
        else return PS2_KEY_NONE;
    }
    return (int)(unsigned char)c;
}

/* The escape sequence a serial terminal would have sent for `key`, or NULL for
 * anything that is not one of the PS2_KEY_* codes.
 *
 * Here rather than in the console server because it is the other half of the
 * mapping above and the two have to agree: every code ps2_feed can return must
 * either be a character or have a sequence here, and the only way to keep that
 * true is to write them next to each other. NUL-terminated so a caller can walk
 * it a byte at a time. */
static inline const char *ps2_key_escape(int key)
{
    switch (key) {
        case PS2_KEY_UP:    return "\x1b[A";
        case PS2_KEY_DOWN:  return "\x1b[B";
        case PS2_KEY_RIGHT: return "\x1b[C";
        case PS2_KEY_LEFT:  return "\x1b[D";
        case PS2_KEY_HOME:  return "\x1b[H";
        case PS2_KEY_END:   return "\x1b[F";
        default:            return (const char *)0;
    }
}

#endif /* HORUS_PS2_SCANCODE_H */
