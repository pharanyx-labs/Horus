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
