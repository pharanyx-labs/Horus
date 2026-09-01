/* Exercise libhorus's TUI against its own buffers.
 *
 * WHAT THIS TESTS AND WHY IT IS NOT A SCREENSHOT
 *
 * Every property here is invisible on a terminal. A correct damage diff and a
 * full repaint draw the identical picture; a missing bounds check draws the
 * identical picture too, right up until it corrupts something. So the assertions
 * are on the BYTE COUNT the library hands the console and on the contents of its
 * own cells -- both of which a control arm can move and a screen cannot show.
 *
 * It needs no terminal to look at, which is what makes it runnable headless.
 */
#include "syscall.h"
#include "libhorus.h"
#include "tui.h"

static int checks, failures;

/* Markers go through the CONSOLE SERVER, not through kput.
 *
 * console_server owns the serial hardware in this build, so a ring-3 kput goes
 * to a kernel console that is no longer the wire and the marker never appears --
 * which is exactly how the first run of this test failed: TUI_SELFTEST: begin
 * on serial, then silence, with every check having actually run. consoletest
 * has the same shape and for the same reason.
 *
 * One request per marker, so it is one write and cannot be split by another
 * task's output (docs/LIMITATIONS.md 2.6a). */
static struct con_request  say_rq;
static struct con_response say_rp;

static void say(const char *a, const char *b)
{
    unsigned n = 0;
    for (const char *c = a; c && *c && n < CON_IO_MAX - 1; c++) say_rq.data[n++] = (uint8_t)*c;
    for (const char *c = b; c && *c && n < CON_IO_MAX - 1; c++) say_rq.data[n++] = (uint8_t)*c;
    say_rq.data[n++] = '\n';
    say_rq.magic = CON_PROTO_MAGIC;
    say_rq.op    = CON_OP_WRITE;
    say_rq.len   = n;
    for (int t = 0; t < 32; t++) {
        if (sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &say_rq, sizeof(say_rq), &say_rp) >= 0) return;
        sys_yield();
    }
}

static void check(int ok, const char *what)
{
    if (ok) { checks++; return; }
    say("TUITEST: FAIL ", what);
    failures++;
}

void _start(void)
{
    if (tui_begin() != 0) {
        /* No server: kput is the only path left, and is correct here. */
        kput("TUITEST: FAIL no-console-server\n");
        sys_exit();
    }

    /* --- 1. the first flush paints, the second emits nothing --------------
     * front is seeded unequal to any real cell so the opening frame is a full
     * repaint; with nothing changed after it, a correct diff emits zero. */
    tui_clear();
    tui_flush();
    tui_test_reset();
    tui_flush();
    check(tui_test_emitted() == 0, "an unchanged screen still emitted bytes");

    /* --- 2. one changed cell costs a handful of bytes ---------------------
     * A cursor address, an attribute and one character. Sixty is generous for
     * that and nowhere near the ~2000 a full repaint of 24x80 needs, so the
     * bound distinguishes the two without being brittle about the exact
     * escapes. This is the check TUI_NO_DAMAGE_DIFF=1 breaks. */
    tui_putc(3, 5, 'X', TUI_A_NORMAL);
    tui_test_reset();
    tui_flush();
    {
        unsigned n = tui_test_emitted();
        check(n > 0,  "a changed cell emitted nothing");
        check(n < 60, "a one-cell change repainted the screen");
    }

    /* --- 3. the cell that changed is the cell that was asked for ---------- */
    check(tui_test_cell(3, 5) == 'X', "the cell written is not the cell asked for");
    check(tui_test_cell(3, 6) == ' ', "a neighbouring cell was disturbed");

    /* --- 4. out-of-range writes are discarded ----------------------------
     * Every drawing call funnels through one bounds check, so this covers the
     * lot. With the check removed the write lands in the buffers somewhere and
     * the next flush notices, which is exactly what TUI_CLAMP_OFF=1 shows. */
    tui_flush();
    tui_test_reset();
    tui_putc(tui_rows(),      0, 'A', TUI_A_NORMAL);   /* one row past the end */
    tui_putc(0,  tui_cols(),     'B', TUI_A_NORMAL);   /* one column past      */
    tui_putc(-1,             0, 'C', TUI_A_NORMAL);
    tui_putc(0,             -1, 'D', TUI_A_NORMAL);
    tui_flush();
    check(tui_test_emitted() == 0, "an out-of-range write reached the buffer");

    /* --- 5. a field truncates rather than overrunning its width ----------
     * A menu's columns must not shift when their text does, and a long string
     * must not spill into the next field. */
    tui_field(6, 0, 5, "abcdefghij", TUI_A_NORMAL);
    check(tui_test_cell(6, 4) == 'e', "a field did not fill its width");
    check(tui_test_cell(6, 5) == ' ', "a field overran its width");
    tui_field(6, 0, 5, "ab", TUI_A_NORMAL);
    check(tui_test_cell(6, 2) == ' ', "a short field did not pad");

    /* A buffer of exactly `width` bytes with NO terminator -- a fixed field in a
     * form, which is what this function is for. CodeQL flagged the original
     * `s[i] && i < width` here as cpp/offset-use-before-range-check: it read
     * s[width] before the bound short-circuited.
     *
     * THIS CHECK DOES NOT DETECT THAT OVER-READ, and saying so matters. The byte
     * read past the end only fed the loop condition, so the rendered output was
     * identical either way; the fault was memory safety, invisible without a
     * sanitiser. What this pins is the BEHAVIOUR -- exactly `width` cells from a
     * non-terminated buffer -- so a later change cannot alter the semantics
     * unnoticed. The gate for the over-read itself is CodeQL, which runs on
     * every pull request and is what caught it. */
    {
        static const char exact[5] = { 'v', 'w', 'x', 'y', 'z' };   /* no NUL */
        tui_field(7, 0, 5, exact, TUI_A_NORMAL);
        check(tui_test_cell(7, 0) == 'v', "a non-terminated field lost its first cell");
        check(tui_test_cell(7, 4) == 'z', "a non-terminated field lost its last cell");
        check(tui_test_cell(7, 5) == ' ', "a non-terminated field overran its width");
    }

    /* --- 6. the key decoder ---------------------------------------------
     * Fed exact bytes rather than whatever a terminal sends, so the arrows and
     * the truncation cases are deterministic. */
    {
        static const uint8_t up[]    = { 0x1B, '[', 'A' };
        static const uint8_t down[]  = { 0x1B, 'O', 'B' };
        static const uint8_t home[]  = { 0x1B, '[', '1', '~' };
        static const uint8_t cut[]   = { 0x1B, '[' };        /* burst ends mid-sequence */
        static const uint8_t lone[]  = { 0x1B };
        static const uint8_t plain[] = { 'q' };
        static const uint8_t ret[]   = { '\r' };
        static const uint8_t bs[]    = { 0x7F };

        tui_test_feed(up,    sizeof(up));    check(tui_getkey() == TUI_KEY_UP,    "ESC [ A is not UP");
        tui_test_feed(down,  sizeof(down));  check(tui_getkey() == TUI_KEY_DOWN,  "ESC O B is not DOWN");
        tui_test_feed(home,  sizeof(home));  check(tui_getkey() == TUI_KEY_HOME,  "ESC [ 1 ~ is not HOME");
        tui_test_feed(plain, sizeof(plain)); check(tui_getkey() == 'q',           "a printable key is not itself");
        tui_test_feed(ret,   sizeof(ret));   check(tui_getkey() == TUI_KEY_ENTER, "CR is not ENTER");
        tui_test_feed(bs,    sizeof(bs));    check(tui_getkey() == TUI_KEY_BACKSP,"DEL is not BACKSPACE");
        /* The two that matter for robustness: a sequence the burst cut short,
         * and a bare ESC. Both must yield a key rather than waiting for bytes
         * that are not coming. */
        tui_test_feed(cut,  sizeof(cut));    check(tui_getkey() == TUI_KEY_ESC,   "a truncated escape did not yield ESC");
        tui_test_feed(lone, sizeof(lone));   check(tui_getkey() == TUI_KEY_ESC,   "a bare ESC did not yield ESC");
    }

    /* --- 7. the cursor is diffed like a cell ------------------------------
     * It is state the TERMINAL holds and the buffers do not, so the question is
     * the same one section 1 asks about cells: does an unchanged request cost
     * bytes? Checked here and not only in section 1 because a cursor emitted
     * unconditionally would ALSO break section 1, and then two checks would be
     * failing for one cause with no way to tell which rule was lost. */
    tui_flush();
    tui_test_reset();
    tui_flush();
    check(tui_test_emitted() == 0, "an unchanged cursor still emitted bytes");

    tui_cursor(4, 9);
    tui_test_reset();
    tui_flush();
    check(tui_test_emitted() > 0, "a moved cursor emitted nothing");
    tui_test_reset();
    tui_flush();
    check(tui_test_emitted() == 0, "an unmoved cursor re-emitted its position");

    /* Out of range means HIDDEN, not clamped to an edge. A cursor parked
     * somewhere the caller did not ask for is a lie about where the next
     * character lands, which in a password field is worse than none. */
    tui_cursor(tui_rows(), 0);
    tui_test_reset();
    tui_flush();
    check(tui_test_emitted() > 0, "hiding the cursor emitted nothing");

    /* --- 8. a line editor bounded by the smaller of two bounds -------------
     * `cap` is what the caller's memory holds; `width` is what the person can
     * see. The editor takes the minimum, so a field is exactly as long as it
     * looks -- and neither bound may be the only one enforced. */
    {
        /* THE BUFFER IS DELIBERATELY LARGER THAN `cap`, WITH A GUARD AFTER IT.
         * The overrun this checks for is a write past the capacity the caller
         * declared, and detecting it needs somewhere for the write to land that
         * is still inside an object we own -- adjacency between two separate
         * arrays is the linker's business, not the language's, so the guard
         * lives in the SAME array. `cap` is 4; bytes 4..31 must never move. */
        static char box[32];
        for (int i = 0; i < 32; i++) box[i] = '#';

        /* Twelve printable characters into a four-byte capacity, in a field
         * twenty wide, so `width` cannot be what stops it. */
        static const uint8_t typed[] = { 'a','b','c','d','e','f','g','h','i','j','k','l', '\r' };
        tui_test_feed(typed, sizeof(typed));
        int rc = tui_input(9, 0, 20, box, 4, 0);

        check(rc == 0, "enter did not end the input");
        check(tui_test_keys_left() == 0, "the editor returned with keys unread");
        check(box[0] == 'a' && box[1] == 'b' && box[2] == 'c',
              "the editor did not keep the characters that fit");
        check(box[3] == 0, "the editor did not terminate within its capacity");
        /* The guard. This is the check TUI_INPUT_UNBOUNDED=1 breaks. */
        {
            int intact = 1;
            for (int i = 4; i < 32; i++) if (box[i] != '#') intact = 0;
            check(intact, "an input overran the buffer it was given");
        }
    }

    /* Backspace removes exactly one character and clears exactly one cell.
     * Asserted on the CELL as well as the buffer: an editor that shortened its
     * string without repainting leaves the removed character on the screen,
     * which for a masked field means the screen and the buffer disagree about
     * how long the password is. */
    {
        static char line[16];
        static const uint8_t typed[] = { 'x','y','z', 0x7F, '\r' };
        tui_test_feed(typed, sizeof(typed));
        check(tui_input(10, 0, 8, line, sizeof(line), 0) == 0, "enter did not end the input");
        check(line[0] == 'x' && line[1] == 'y' && line[2] == 0,
              "backspace did not remove exactly one character");
        check(tui_test_cell(10, 2) == ' ', "backspace left its character on the screen");
    }

    /* ESC empties the buffer rather than handing back a partial answer, so a
     * caller that ignores the return value gets nothing instead of half. */
    {
        static char line[16];
        static const uint8_t typed[] = { 'n','o', 0x1B };
        tui_test_feed(typed, sizeof(typed));
        check(tui_input(11, 0, 8, line, sizeof(line), 0) == -1, "esc did not cancel the input");
        check(line[0] == 0, "a cancelled input left a partial answer in the buffer");
    }

    /* --- 9. a masked field never puts the secret in a cell -----------------
     * The whole property, and it is invisible from the caller's side: `buf` is
     * identical either way, so only the CELLS can tell a masked field from an
     * echoing one. This is what TUI_INPUT_ECHO_SECRET=1 breaks. */
    {
        static char secret[16];
        static const uint8_t typed[] = { 'h','u','n','t','2', '\r' };
        tui_test_feed(typed, sizeof(typed));
        check(tui_input(12, 3, 10, secret, sizeof(secret), TUI_IN_MASK) == 0,
              "enter did not end the masked input");
        check(secret[0] == 'h' && secret[4] == '2' && secret[5] == 0,
              "a masked field did not return what was typed");
        check(tui_test_cell(12, 3) == '*' && tui_test_cell(12, 7) == '*',
              "a masked field did not draw its mask");
        /* Named as its own check rather than folded into the one above: "it
         * drew stars" and "it did not draw the secret" are the same sentence
         * only while the alphabet excludes '*'. */
        check(tui_test_cell(12, 3) != 'h' && tui_test_cell(12, 7) != '2',
              "a masked field showed its characters");
        /* And the cells past the content are blank, not stars: a mask that
         * padded to the field width would disclose nothing about the text but
         * would lie about its LENGTH, and the length of a password is worth
         * something to somebody watching the screen. */
        check(tui_test_cell(12, 8) == ' ', "a masked field padded with its mask");
    }

    /* --- 10. a menu's selection stays inside the caller's array ------------
     * The clamp is a bounds check on the CALLER: it indexes items[*sel] after
     * this returns, and for the installer that array is the list of disks it is
     * about to destroy one of. So the assertion is on the returned index, not
     * on the screen -- an unclamped menu draws exactly the same picture, since
     * every cell it paints is clamped by tui_putc anyway. */
    {
        static const char *const items[] = { "sda", "sdb", "sdc" };
        int sel = 0;

        /* Four DOWNs against three items: the fourth must do nothing. */
        static const uint8_t down4[] = {
            0x1B,'[','B', 0x1B,'[','B', 0x1B,'[','B', 0x1B,'[','B', '\r'
        };
        tui_test_feed(down4, sizeof(down4));
        check(tui_menu(14, 0, 12, items, 3, &sel) == 0, "enter did not end the menu");
        check(tui_test_keys_left() == 0, "the menu returned with keys unread");
        check(sel == 2, "a menu selected past its last item");

        /* And the other end, which a single-direction arm would miss. */
        static const uint8_t up4[] = {
            0x1B,'[','A', 0x1B,'[','A', 0x1B,'[','A', 0x1B,'[','A', '\r'
        };
        tui_test_feed(up4, sizeof(up4));
        check(tui_menu(14, 0, 12, items, 3, &sel) == 0, "enter did not end the menu");
        check(sel == 0, "a menu selected before its first item");

        /* ESC leaves the caller's selection alone. A menu that wrote its
         * in-progress cursor back on cancel would turn "I changed my mind" into
         * a choice. */
        sel = 1;
        static const uint8_t esc_after_move[] = { 0x1B,'[','B', 0x1B };
        tui_test_feed(esc_after_move, sizeof(esc_after_move));
        check(tui_menu(14, 0, 12, items, 3, &sel) == -1, "esc did not cancel the menu");
        check(sel == 1, "a cancelled menu wrote back its selection");

        /* Degenerate input is refused rather than guessed at. */
        check(tui_menu(14, 0, 12, items, 0, &sel) == -1, "an empty menu was not refused");
        check(tui_menu(14, 0, 12, 0, 3, &sel) == -1, "a menu with no items was not refused");
    }

    tui_end();

    /* The asserted markers go out as ONE write each, and the counts follow on
     * their own line -- docs/LIMITATIONS.md 2.6a: a marker split across two
     * writes can be cut in half by another task's output. */
    if (failures) {
        say("TUITEST: FAIL", "");
        sys_exit();
    }
    say("TUITEST: PASS", "");
    sys_exit();
}
