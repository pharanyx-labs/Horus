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
#define PS2_SC_CAPS    0x3A
#define PS2_SC_E0      0xE0

/* Highest scancode the tables below cover (space). Anything above it is a key
 * this console has no character for -- a function key, the keypad -- and yields
 * PS2_KEY_NONE rather than an arbitrary byte. Returning something plausible for
 * a key nobody pressed is worse than returning nothing. */
#define PS2_SC_MAX     0x39

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

/* Index by make code. A '\0' entry means "no character": either an unassigned
 * code or a modifier, both of which are handled before the lookup. Split across
 * literals where a hex escape would otherwise swallow the next digit --
 * "\x1b1" is the single character 0x1b1, not ESC followed by '1'. Left unsized
 * so the tables carry their terminator: each is PS2_SC_MAX+1 = 58 entries plus
 * the NUL, and a static assert below refuses a table that has drifted. */
static const char ps2_map_lower[] =
    "\0\x1b" "1234567890-=\b\t" "qwertyuiop[]\n\0" "asdfghjkl;'`\0\\" "zxcvbnm,./\0*\0 ";
static const char ps2_map_upper[] =
    "\0\x1b" "!@#$%^&*()_+\b\t" "QWERTYUIOP{}\n\0" "ASDFGHJKL:\"~\0|" "ZXCVBNM<>?\0*\0 ";

_Static_assert(sizeof(ps2_map_lower) == PS2_SC_MAX + 2, "ps2_map_lower must cover 0x00..PS2_SC_MAX");
_Static_assert(sizeof(ps2_map_upper) == PS2_SC_MAX + 2, "ps2_map_upper must cover 0x00..PS2_SC_MAX");

/* One reader's modifier state. Zero-initialised is the correct starting state:
 * no modifier held, caps off, no pending prefix. */
struct ps2_state {
    unsigned char shift;   /* either shift key is down                         */
    unsigned char ctrl;    /* either control key is down                       */
    unsigned char caps;    /* caps lock is latched on                          */
    unsigned char e0;      /* the previous byte was the 0xE0 extended prefix   */
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

    char c = st->shift ? ps2_map_upper[sc] : ps2_map_lower[sc];
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
