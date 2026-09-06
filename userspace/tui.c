/* Full-screen text UI over the console server. See include/tui.h for why this
 * exists rather than a port of ncurses, for what it deliberately lacks, and for
 * why the 2026-09-06 work grew rendering and layout but left the number of
 * blocking input loops at two. */
#include "tui.h"
#include "syscall.h"
#include "libhorus.h"

/* One cell: a byte, and the attribute that byte is drawn with.
 *
 * The attribute widened from 8 bits to 16 on 2026-09-06 to carry a foreground,
 * a background and the ACS flag, which takes the pair of buffers from 3,840
 * bytes of .bss to 15,360. That is the whole cost of colour, it is still
 * statically sized, and nothing here allocates -- a TUI that cannot allocate
 * cannot fail to allocate, which was the reason for the fixed buffers and is
 * unaffected by how wide a cell is. */
struct cell { uint16_t attr; char ch; char pad; };

static struct cell back[CON_ROWS][CON_COLS];
static struct cell front[CON_ROWS][CON_COLS];
static int g_rows = CON_ROWS;
static int g_cols = CON_COLS;
static int g_active = 0;

static struct con_request  rq;   /* static: these are 256 bytes each and a */
static struct con_response rp;   /* ring-3 stack is not the place for them */

static uint8_t kbuf[CON_IO_MAX];
static unsigned klen, kpos;

/* Where the visible cursor should be, and where the terminal was last told it
 * is. Two variables rather than one for the same reason `front` exists beside
 * `back`: tui_flush emits only differences, and without a record of what the
 * terminal was last told, "has the cursor moved" is unanswerable and the only
 * safe answer is to re-send it on every flush -- which puts bytes on the wire
 * for an unchanged screen, the one thing tui_flush is built not to do. A
 * negative row means hidden, and hidden is the state tui_begin establishes. */
static int cur_r = -1, cur_c = -1;      /* requested */
static int shown_r = -1, shown_c = -1;  /* last sent */

/* ---- transport ---------------------------------------------------------- */

/* One console request, with the bounded retry the shell uses: a full mailbox is
 * transient and worth yielding for, but it must not become a hang. Returns the
 * server's rc, or -1. */
static int con_call(uint32_t op, const uint8_t *data, uint32_t len)
{
    rq.magic = CON_PROTO_MAGIC;
    rq.op    = op;
    rq.len   = len;
    for (uint32_t i = 0; i < len && i < CON_IO_MAX; i++) rq.data[i] = data[i];

    for (int tries = 0; tries < 32; tries++) {
        int rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &rq, sizeof(rq), &rp);
        if (rc >= 0) {
            if (rp.magic != CON_PROTO_MAGIC) return -1;
            return rp.rc;
        }
        sys_yield();
    }
    return -1;
}

/* Emit bytes verbatim, chunked to what one request carries. */
static void raw_write(const char *s, unsigned len)
{
    unsigned off = 0;
    while (off < len) {
        unsigned n = len - off;
        if (n > CON_IO_MAX) n = CON_IO_MAX;
        if (con_call(CON_OP_WRITE_RAW, (const uint8_t *)(s + off), n) != (int)n) return;
        off += n;
    }
}

/* ---- a bounded output buffer -------------------------------------------
 *
 * tui_flush builds its escape sequences here and drains when full. A fixed
 * buffer with an explicit drain is what keeps the whole path free of
 * allocation, and the drain-on-full means a full-screen repaint costs several
 * requests rather than needing one enormous one. */
static char  obuf[CON_IO_MAX];
static unsigned olen;

#ifdef TUI_SELFTEST
/* Bytes handed to the console since the last reset. The self-test asserts on
 * this because damage diffing is INVISIBLE on screen: a correct flush and a
 * full repaint show the same picture, and only the byte count tells them
 * apart. Compiled only under the self-test, so the shipping library carries
 * neither the counter nor the branch. */
static unsigned g_emitted;
/* And the bytes themselves, which is a different question from how many.
 *
 * Whether a flush left the terminal in the line-drawing charset is not visible
 * in a cell, not visible in a return value, and not visible in the COUNT -- a
 * flush that forgot its restore emits FEWER bytes, so a count-based check would
 * read the defect as an improvement. Only the stream shows it. Bounded and
 * dropped on overflow rather than wrapped: a partial tail would let a check
 * pass on bytes that were never sent. */
static char g_out[4096];
static unsigned g_outlen;
unsigned tui_test_emitted(void)   { return g_emitted; }
void     tui_test_reset(void)     { g_emitted = 0; g_outlen = 0; }
char     tui_test_cell(int r, int c)
{
    if (r < 0 || r >= CON_ROWS || c < 0 || c >= CON_COLS) return 0;
    return back[r][c].ch;
}
uint16_t tui_test_attr(int r, int c)
{
    if (r < 0 || r >= CON_ROWS || c < 0 || c >= CON_COLS) return 0;
    return back[r][c].attr;
}
unsigned tui_test_out(char *out, unsigned max)
{
    unsigned n = g_outlen < max ? g_outlen : max;
    for (unsigned i = 0; i < n; i++) out[i] = g_out[i];
    return n;
}
/* Inject a key burst, so the decoder is tested against exact byte sequences
 * rather than against whatever a terminal happens to send. */
void tui_test_feed(const uint8_t *b, unsigned n)
{
    if (n > sizeof(kbuf)) n = sizeof(kbuf);
    for (unsigned i = 0; i < n; i++) kbuf[i] = b[i];
    klen = n; kpos = 0;
}
/* Unread keys left in the injected burst. The interaction tests assert this is
 * zero after a fed sequence: an input loop that returned early leaves keys
 * behind, and its RESULT can still be the expected one -- a menu that ignored
 * every arrow and returned the initial selection looks identical to a menu that
 * clamped correctly, unless somebody asks whether the arrows were consumed. */
unsigned tui_test_keys_left(void) { return klen - kpos; }
#endif

static void oflush(void)
{
    if (olen) {
#ifdef TUI_SELFTEST
        g_emitted += olen;
        for (unsigned i = 0; i < olen && g_outlen < sizeof(g_out); i++)
            g_out[g_outlen++] = obuf[i];
#endif
        raw_write(obuf, olen);
        olen = 0;
    }
}
static void oput(char c)  { if (olen == sizeof(obuf)) oflush(); obuf[olen++] = c; }
static void oputs(const char *s) { for (; *s; s++) oput(*s); }

/* Decimal, no varargs, no libc. Values here are row/column numbers and SGR
 * codes: small, non-negative, and bounded by the screen. */
static void oputn(unsigned v)
{
    char tmp[8]; int n = 0;
    if (v == 0) { oput('0'); return; }
    while (v && n < (int)sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n--) oput(tmp[n]);
}

/* CUP: move the cursor. 1-based, as the terminal counts. */
static void ocup(int row, int col)
{
    oputs("\033["); oputn((unsigned)row + 1); oput(';');
    oputn((unsigned)col + 1); oput('H');
}

/* SGR. One reset followed by everything this cell wants, so the emitter never
 * has to remember which attributes are currently on -- the reset is what makes
 * a per-cell attribute independent of the cell before it.
 *
 * THE COLOUR CLAMP IS THE SAFETY-RELEVANT LINE HERE. A foreground of 9 would
 * emit `38`, which is not a colour but the extended-colour INTRODUCER: the
 * terminal would then read the following parameters -- including this
 * sequence's terminator and whatever text came after it -- as arguments to a
 * 256-colour or truecolour selector. A wrong colour is cosmetic; a swallowed
 * escape puts the terminal into a state where subsequent output is neither
 * displayed nor recoverable, on the program that is about to ask whether to
 * erase a disk. Out of range is treated as "the terminal's default", which is
 * the fail-closed answer: it draws something legible rather than nothing. */
static void osgr(uint16_t attr)
{
    oputs("\033[0");
    if (attr & TUI_A_BOLD)      oputs(";1");
    if (attr & TUI_A_DIM)       oputs(";2");
    if (attr & TUI_A_UNDERLINE) oputs(";4");
    if (attr & TUI_A_REVERSE)   oputs(";7");

    unsigned fg = (unsigned)(attr & 0x0Fu);
    unsigned bg = (unsigned)((attr >> 4) & 0x0Fu);
    if (fg >= 1u && fg <= 8u) { oput(';'); oputn(29u + fg); }   /* 1..8 -> 30..37 */
    if (bg >= 1u && bg <= 8u) { oput(';'); oputn(39u + bg); }   /* 1..8 -> 40..47 */
    oput('m');
}

/* ---- the G0 charset, and the restore that must not be forgotten ---------
 *
 * Line drawing is done the way a VT100 does it and the way ncurses drives one:
 * shift G0 to DEC Special Graphics, send ordinary letters, shift back. `q` is
 * then a horizontal line and `x` a vertical one.
 *
 * THE RESTORE IS THE PART THAT MATTERS. A flush that ends while G0 is still
 * graphics does not corrupt this library's next screen -- every cell it draws
 * carries its own charset decision -- it corrupts everything that is NOT this
 * library: the task's own kput output, the marker lines the smoke gates read,
 * the shell prompt after tui_end. All of those become line-drawing glyphs, and
 * the failure looks like a broken terminal rather than like a bug here.
 *
 * TUI_ACS_NO_RESTORE=1 removes the restore and is the control arm. It is a
 * single function so the arm removes it from BOTH callers at once -- the end of
 * a flush and tui_end -- because a restore present at one of the two would let
 * the arm pass for the wrong reason. */
static int g_graphics;                  /* is the terminal's G0 currently ACS? */

static void ographics(void)
{
    if (g_graphics) return;
    oputs("\033(0");
    g_graphics = 1;
}

static void oascii(void)
{
    if (!g_graphics) return;
#ifndef TUI_ACS_NO_RESTORE
    oputs("\033(B");
#else
    /* CONTROL ARM -- never ship. The shift back to ASCII is not EMITTED, and the
     * bookkeeping below still runs -- so the library believes the terminal is in
     * ASCII while the terminal is still drawing lines. That asymmetry is the
     * defect being reproduced: forgetting the escape, not forgetting the
     * variable. Dropping both would be worse than the bug and weaker as an arm,
     * because `ographics` would then never see a transition and no box would be
     * drawn at all -- the arm would fail by producing no line drawing rather
     * than by failing to restore, which is a different defect wearing this
     * one's name.
     *
     * Nothing in a cell, in a return value, or in the emitted byte COUNT shows
     * this -- the count goes DOWN -- so the witness reads the emitted stream.
     * See make smoke-tui-acs-control. */
#endif
    g_graphics = 0;
}

/* ---- session ------------------------------------------------------------ */

int tui_begin(void)
{
    int rc = con_call(CON_OP_WINSZ, (const uint8_t *)"", 0);
    if (rc < 0) return -1;                 /* no console server: draw nothing */

    int rows = (rc >> 16) & 0xFFFF;
    int cols = rc & 0xFFFF;
    /* Trust the server's answer only as far as our buffers go. A geometry
     * larger than the compiled maximum is clamped rather than believed: the
     * buffers are what bound every write below, so they are what must bound
     * this. */
    g_rows = (rows > 0 && rows <= CON_ROWS) ? rows : CON_ROWS;
    g_cols = (cols > 0 && cols <= CON_COLS) ? cols : CON_COLS;

    for (int r = 0; r < CON_ROWS; r++)
        for (int c = 0; c < CON_COLS; c++) {
            back[r][c].ch = ' ';  back[r][c].attr = TUI_A_NORMAL;
            /* front is seeded with a value no cell can hold, so the first
             * flush repaints everything rather than assuming the terminal
             * already shows spaces. */
            front[r][c].ch = '\0'; front[r][c].attr = 0xFFFFu;
        }
    olen = 0;
    g_active = 1;
    /* Both halves of the cursor diff start HIDDEN, and both are set here rather
     * than only the requested one: the escape below is what makes `shown_*`
     * true, so a session begun twice cannot inherit a stale belief about where
     * the terminal's cursor is. */
    cur_r = cur_c = shown_r = shown_c = -1;
    /* The charset belief is reset the same way and for the same reason: a
     * session begun twice must not assume the terminal is still where the last
     * one left it. Asserted rather than assumed -- the explicit restore below
     * is what makes `g_graphics = 0` true. */
    g_graphics = 1;
    oascii();
    oputs("\033[?25l");                    /* hide the cursor */
    oputs("\033[2J");                      /* clear, so the terminal agrees */
    oflush();
    return 0;
}

void tui_end(void)
{
    if (!g_active) return;
    olen = 0;
    cur_r = cur_c = shown_r = shown_c = -1;
    oascii();                              /* never hand back a graphics G0 */
    osgr(TUI_A_NORMAL);
    ocup(g_rows - 1, 0);
    oputs("\033[?25h");                    /* show the cursor again */
    oput('\n');
    oflush();
    g_active = 0;
}

int tui_rows(void) { return g_rows; }
int tui_cols(void) { return g_cols; }

/* ---- drawing ------------------------------------------------------------ */

/* THE ONE PLACE COORDINATES ARE CHECKED. Every writer goes through it, so a
 * caller cannot address outside the buffers however it computes its numbers.
 * TUI_CLAMP_OFF=1 removes the check, which is what the control arm needs to
 * show the check is doing something. */
static inline int in_screen(int row, int col)
{
#ifdef TUI_CLAMP_OFF
    (void)row; (void)col;
    return 1;
#else
    return row >= 0 && row < g_rows && col >= 0 && col < g_cols;
#endif
}

void tui_clear(void)
{
    for (int r = 0; r < CON_ROWS; r++)
        for (int c = 0; c < CON_COLS; c++) {
            back[r][c].ch = ' '; back[r][c].attr = TUI_A_NORMAL;
        }
}

void tui_putc(int row, int col, char ch, uint16_t attr)
{
    if (!in_screen(row, col)) return;
    /* Control characters would move the terminal's cursor out from under the
     * diff, so they are replaced rather than emitted. A cell holds one glyph.
     *
     * ACS cells are exempt from nothing: every DEC Special Graphics byte this
     * library names is itself printable ASCII (`q`, `x`, `l`...), so the same
     * test is correct for both and there is no second rule to keep in step. */
    if ((unsigned char)ch < 0x20 || (unsigned char)ch == 0x7F) ch = ' ';
    back[row][col].ch   = ch;
    back[row][col].attr = attr;
}

void tui_text(int row, int col, const char *s, uint16_t attr)
{
    if (!s) return;
    /* Bounded by the screen as well as by the terminator: tui_putc discards
     * anything off-screen anyway, so a runaway string can only waste time --
     * but a loop with two ways to stop is one fewer thing to reason about. */
    for (int i = 0; i < CON_COLS && s[i]; i++) tui_putc(row, col + i, s[i], attr);
}

void tui_field(int row, int col, int width, const char *s, uint16_t attr)
{
    if (width <= 0) return;
    int i = 0;
    /* THE BOUND COMES FIRST, and the order is the whole point.
     *
     * This read `s[i] && i < width`, which dereferences before it checks --
     * so a caller passing a buffer of exactly `width` bytes with no terminator
     * (a fixed field in a form, say, which is precisely what this function is
     * for) had s[width] read one byte past the end before the bound
     * short-circuited. CodeQL caught it as cpp/offset-use-before-range-check on
     * the pull request that introduced it; nothing in the self-test would have,
     * because every string it passes is NUL-terminated well inside the width. */
    if (s) for (; i < width && s[i]; i++) tui_putc(row, col + i, s[i], attr);
    for (; i < width; i++) tui_putc(row, col + i, ' ', attr);
}

void tui_fill(int row, int col, int height, int width, char ch, uint16_t attr)
{
    if (height <= 0 || width <= 0) return;
    for (int r = 0; r < height; r++)
        for (int c = 0; c < width; c++)
            tui_putc(row + r, col + c, ch, attr);
}

/* Draw a box with the terminal's own line-drawing glyphs.
 *
 * WHY DEC SPECIAL GRAPHICS AND NOT UTF-8. A cell in this library holds ONE
 * byte. The UTF-8 encoding of a box character is three, so drawing with them
 * would mean either widening every cell to hold a multi-byte glyph or storing a
 * cell whose width lies about how many columns it occupies -- and a cell that
 * lies about its width breaks the damage diff, which addresses the terminal by
 * column number. ACS keeps one byte per column, which is the invariant the
 * whole diff rests on, and it is what ncurses does on this terminal for the
 * same reason. The cost is the charset shift, and the shift's restore is the
 * property oascii exists to guarantee. */
void tui_box(int row, int col, int height, int width, uint16_t attr)
{
    if (height < 2 || width < 2) return;
    uint16_t a = (uint16_t)(attr | TUI_A_ACS);
    for (int c = 1; c < width - 1; c++) {
        tui_putc(row, col + c, TUI_ACS_HLINE, a);
        tui_putc(row + height - 1, col + c, TUI_ACS_HLINE, a);
    }
    for (int r = 1; r < height - 1; r++) {
        tui_putc(row + r, col, TUI_ACS_VLINE, a);
        tui_putc(row + r, col + width - 1, TUI_ACS_VLINE, a);
    }
    tui_putc(row, col, TUI_ACS_ULCORNER, a);
    tui_putc(row, col + width - 1, TUI_ACS_URCORNER, a);
    tui_putc(row + height - 1, col, TUI_ACS_LLCORNER, a);
    tui_putc(row + height - 1, col + width - 1, TUI_ACS_LRCORNER, a);
}

/* ---- text layout -------------------------------------------------------- */

static int ulen(const char *s)
{
    int n = 0;
    while (s && s[n] && n < CON_COLS * CON_ROWS) n++;
    return n;
}

void tui_center(int row, const char *s, uint16_t attr)
{
    if (!s) return;
    int n = ulen(s);
    int col = (g_cols - n) / 2;
    if (col < 0) col = 0;      /* wider than the screen: start at the left and
                                * let tui_putc discard the tail, rather than
                                * starting at a negative column and discarding
                                * the HEAD, which loses the words that identify
                                * the line. */
    tui_text(row, col, s, attr);
}

int tui_wrap(int row, int col, int width, int max_rows, const char *s, uint16_t attr)
{
    if (!s || width <= 0 || max_rows <= 0) return 0;

    int used = 0;
    int i = 0;

    while (s[i] && used < max_rows) {
        while (s[i] == ' ') i++;                 /* no line starts with a space */
        if (!s[i]) break;

        /* How much of what remains fits, and where the last space inside that
         * span was. `brk` stays 0 for a single word longer than the column. */
        int take = 0, brk = 0;
        while (s[i + take] && take < width) {
            if (s[i + take] == ' ') brk = take;
            take++;
        }

        if (s[i + take] && brk > 0) {
            take = brk;                          /* break at the space */
        } else if (s[i + take]) {
#ifdef TUI_WRAP_NO_BREAK
            /* CONTROL ARM -- never ship. A word longer than the column is
             * emitted whole instead of broken at `width`, so it runs out of its
             * column and across whatever is beside it. This is the ordinary wrap
             * bug: the space-breaking path is the one that gets tested, and the
             * no-space case is the one that gets forgotten.
             *
             * It is bounded by the SCREEN, not unbounded -- tui_putc still
             * discards past the last column -- for the reason TUI_INPUT_UNBOUNDED
             * keeps its width bound: the mistake being reproduced is trusting one
             * bound, not writing off the end of memory. The witness is a cell
             * past `col + width` on the same row, which is where the frame's
             * right-hand edge lives. See make smoke-tui-wrap-control. */
            while (s[i + take]) take++;
#else
            /* A single word wider than the column, broken at the column. It is
             * `take == width` already, so there is nothing to do but say so. */
#endif
        }

        for (int k = 0; k < take; k++)
            tui_putc(row + used, col + k, s[i + k], attr);

        i += take;
        used++;
    }
    return used;
}

void tui_cursor(int row, int col)
{
    /* Clamped to the screen like every other coordinate, and a negative or
     * out-of-range request means HIDDEN rather than clamped-to-an-edge. Putting
     * the cursor somewhere the caller did not ask for would be a lie about where
     * the next character lands, which in a password field is worse than no
     * cursor at all. */
    if (row < 0 || row >= g_rows || col < 0 || col >= g_cols) {
        cur_r = cur_c = -1;
        return;
    }
    cur_r = row;
    cur_c = col;
}

/* ---- flush -------------------------------------------------------------- */

/* Emit only what changed. The cursor is re-addressed when the run of changed
 * cells breaks, the attribute is re-emitted only when it differs from what was
 * last set, and the charset is shifted only when a cell's ACS-ness differs from
 * the terminal's current G0 -- so a screen where one field changed costs one
 * CUP and a few bytes rather than a full repaint.
 *
 * TUI_NO_DAMAGE_DIFF=1 repaints everything unconditionally. That is the control
 * arm: the self-test asserts the emitted byte count for a one-cell change, and
 * a full repaint blows past it. */
void tui_flush(void)
{
    if (!g_active) return;
    olen = 0;

    int last_attr = -1;
    int cursor_r = -1, cursor_c = -1;

    for (int r = 0; r < g_rows; r++) {
        for (int c = 0; c < g_cols; c++) {
#ifndef TUI_NO_DAMAGE_DIFF
            if (back[r][c].ch == front[r][c].ch &&
                back[r][c].attr == front[r][c].attr) continue;
#endif
            if (r != cursor_r || c != cursor_c) { ocup(r, c); cursor_r = r; cursor_c = c; }
            if ((int)back[r][c].attr != last_attr) {
                osgr(back[r][c].attr); last_attr = (int)back[r][c].attr;
            }
            /* The charset is decided per cell and changed only on a boundary,
             * so a run of box edge costs one shift rather than one per glyph. */
            if (back[r][c].attr & TUI_A_ACS) ographics(); else oascii();
            oput(back[r][c].ch);
            cursor_c++;                       /* the terminal advanced it too */
            front[r][c] = back[r][c];
        }
    }

    /* THE RESTORE, unconditional and before the cursor. Everything that reads
     * this terminal next -- the next screen, this task's kput, the login prompt
     * after tui_end -- is entitled to an ASCII G0, and the last cell drawn is
     * routinely a box edge. */
    oascii();

    /* The cursor, diffed like the cells and emitted LAST -- the cell loop moves
     * the terminal's cursor as a side effect of writing, so positioning it
     * before the loop would be undone by the first character written. */
    if (cur_r != shown_r || cur_c != shown_c) {
        if (cur_r < 0) {
            oputs("\033[?25l");
        } else {
            ocup(cur_r, cur_c);
            oputs("\033[?25h");
        }
        shown_r = cur_r;
        shown_c = cur_c;
    }
    oflush();
}

/* ---- interactions -------------------------------------------------------
 *
 * Two loops over tui_getkey, and the file will not grow a third without a
 * program that needs one that cannot be composed from these. Both share the
 * same three obligations, which is why they are stated once here rather than
 * twice below.
 *
 * THEY MUST TERMINATE WITHOUT A KEY. tui_getkey returns TUI_KEY_NONE for two
 * different things: a control byte the decoder deliberately ignores, and a
 * console that did not answer at all (kfill's con_call failed after its bounded
 * retry). The second is permanent -- the endpoint is gone, or the server is --
 * and a loop that kept asking would be the G-8 wedge wearing a user interface:
 * a task spinning inside an input call prints nothing, so "the installer is
 * waiting for you" and "the installer is dead" look identical on a serial line.
 * So consecutive NONEs are counted and the loop gives up at IDLE_LIMIT. A human
 * cannot produce 256 ignorable control bytes in a row without also producing a
 * printable one, which resets the count; a dead console produces nothing else,
 * ever.
 *
 * THEY REDRAW BEFORE THEY BLOCK, never after. The screen must show the state the
 * next keystroke will act on, so every path that changes state falls through to
 * one draw-and-flush at the top of the loop rather than each branch painting for
 * itself -- which is how a backspace comes to clear the character before it and
 * leave the one after.
 *
 * THEY OWN NO BUFFER. tui_input writes into the caller's array and nowhere else,
 * so there is no second copy of a password for the library to forget to erase.
 * That is the reason `cap` is a parameter rather than a fixed maximum here.
 */
#define TUI_IDLE_LIMIT 256

int tui_input(int row, int col, int width, char *buf, int cap, unsigned flags)
{
    if (!buf || cap < 1) return -1;
    buf[0] = 0;
    if (width <= 0) return -1;

    /* THE FIELD IS THE BOUND, and it is the smaller of the two on purpose.
     * `cap - 1` is what the caller's memory can hold; `width` is what the person
     * can see. Taking the minimum is what makes "a field is exactly as long as
     * it looks" true in both directions -- a caller cannot be handed more than
     * it asked for, and a person cannot type a character that is not on the
     * screen in front of them. */
    int limit = cap - 1;
    if (width < limit) limit = width;
    if (limit < 0) limit = 0;

    int len = 0;
    int idle = 0;

    for (;;) {
        /* Draw the field, then say where the next character lands. Masked
         * fields draw '*' and the clear text never reaches a cell -- not the
         * back buffer, not the front buffer, and therefore not the wire. */
        for (int i = 0; i < width; i++) {
            char ch = ' ';
            if (i < len) {
#ifdef TUI_INPUT_ECHO_SECRET
                /* CONTROL ARM -- never ship. The mask dropped, so a password
                 * field paints what was typed. Nothing about the RETURNED value
                 * changes, which is the whole difficulty: the caller cannot tell,
                 * and neither can a test that only inspects `buf`. The witness
                 * has to look at the cells. See make smoke-tui-mask-control. */
                ch = buf[i];
#else
                ch = (flags & TUI_IN_MASK) ? '*' : buf[i];
#endif
            }
            tui_putc(row, col + i, ch, TUI_A_REVERSE);
        }
        tui_cursor(row, col + (len < width ? len : width - 1));
        tui_flush();

        int k = tui_getkey();
        if (k == TUI_KEY_NONE) {
            if (++idle >= TUI_IDLE_LIMIT) { buf[0] = 0; return -1; }
            continue;
        }
        idle = 0;

        if (k == TUI_KEY_ENTER) { buf[len] = 0; return 0; }
        if (k == TUI_KEY_ESC) {
            /* Emptied rather than left holding a partial answer: a caller that
             * ignores the return value gets nothing, not half of something. */
            buf[0] = 0;
            return -1;
        }
        if (k == TUI_KEY_BACKSP) {
            if (len > 0) { len--; buf[len] = 0; }
            continue;
        }
        if (k >= 0x20 && k < 0x7F) {
#ifdef TUI_INPUT_UNBOUNDED
            /* CONTROL ARM -- never ship. The `cap` bound dropped; only the
             * visible width still stops the loop, so a caller that passed a
             * small buffer and a wide field is written past the end of it.
             *
             * Deliberately leaves the WIDTH bound in place. Removing both would
             * make the arm reproduce something no realistic mistake does -- an
             * unbounded write -- where the mistake this guards against is the
             * ordinary one of trusting a single bound. See
             * make smoke-tui-bound-control. */
            if (len < width) buf[len++] = (char)k;
#else
            if (len < limit) buf[len++] = (char)k;
            /* else: DISCARDED, and discarded at the head of the buffer rather
             * than silently dropped at the end. A field that accepted a
             * character it could not store would show one thing and return
             * another. */
#endif
            continue;
        }
        /* Anything else -- arrows, tab, home -- is not an edit in a one-line
         * field and is ignored rather than guessed at. */
    }
}

int tui_menu(int row, int col, int width, const char *const *items, int n, int *sel)
{
    if (!items || !sel || n <= 0) return -1;

    int cur = *sel;
    if (cur < 0) cur = 0;
    if (cur >= n) cur = n - 1;

    int idle = 0;

    for (;;) {
        for (int i = 0; i < n; i++)
            tui_field(row + i, col, width, items[i],
                      i == cur ? TUI_A_REVERSE : TUI_A_NORMAL);
        /* No cursor in a menu: the highlight IS the selection, and a second
         * indicator that could disagree with it is a second thing to get
         * wrong. */
        tui_cursor(-1, -1);
        tui_flush();

        int k = tui_getkey();
        if (k == TUI_KEY_NONE) {
            if (++idle >= TUI_IDLE_LIMIT) return -1;
            continue;
        }
        idle = 0;

        if (k == TUI_KEY_ENTER) { *sel = cur; return 0; }
        if (k == TUI_KEY_ESC)   return -1;   /* *sel untouched */

        if (k == TUI_KEY_UP)   cur--;
        if (k == TUI_KEY_DOWN) cur++;
        if (k == TUI_KEY_HOME) cur = 0;
        if (k == TUI_KEY_END)  cur = n - 1;

#ifndef TUI_MENU_UNCLAMPED
        /* THE CLAMP IS A BOUNDS CHECK ON THE CALLER'S ARRAY, not on this one.
         * Everything drawn above is clamped by tui_putc regardless, so an
         * out-of-range `cur` paints nothing and looks like a menu with nothing
         * selected -- harmless here. What is not harmless is that the caller
         * indexes items[*sel] after this returns, and for the installer that
         * array is the list of disks it is about to destroy one of. Removing
         * this does not corrupt the TUI; it corrupts the program using it, which
         * is exactly why the arm for it asserts on the returned INDEX rather
         * than on the screen. */
        if (cur < 0)  cur = 0;
        if (cur >= n) cur = n - 1;
#endif
    }
}

/* ---- input -------------------------------------------------------------- */

/* CON_OP_READ_RAW blocks for at least one byte and then returns the whole
 * immediately-available burst, so a three-byte arrow arrives in one reply. That
 * is what lets this decode from a buffer instead of reading again mid-sequence
 * -- and therefore what stops a truncated escape from becoming a hang: if the
 * burst ends early the sequence is simply not recognised and ESC is returned.
 */
/* Declared above the output helpers so the self-test hook can reach them. */

static int kfill(void)
{
    if (kpos < klen) return 1;
    int rc = con_call(CON_OP_READ_RAW, (const uint8_t *)"", CON_IO_MAX);
    if (rc <= 0) return 0;
    if (rc > (int)sizeof(kbuf)) rc = (int)sizeof(kbuf);   /* never trust a length */
    for (int i = 0; i < rc; i++) kbuf[i] = rp.data[i];
    klen = (unsigned)rc; kpos = 0;
    return 1;
}

int tui_getkey(void)
{
    if (!kfill()) return TUI_KEY_NONE;
    uint8_t b = kbuf[kpos++];

    if (b == '\r' || b == '\n') return TUI_KEY_ENTER;
    if (b == 0x7F || b == 0x08) return TUI_KEY_BACKSP;
    if (b == '\t')              return TUI_KEY_TAB;

    if (b != 0x1B) {
        if (b < 0x20) return TUI_KEY_NONE;     /* other control bytes: ignored */
        return (int)b;                         /* printable, as itself */
    }

    /* An escape. Everything below reads only what is already in the burst; a
     * sequence cut short is reported as a bare ESC, which is a real key. */
    if (kpos >= klen) return TUI_KEY_ESC;
    uint8_t c1 = kbuf[kpos];
    if (c1 != '[' && c1 != 'O') return TUI_KEY_ESC;
    kpos++;
    if (kpos >= klen) return TUI_KEY_ESC;

    uint8_t c2 = kbuf[kpos++];
    switch (c2) {
        case 'A': return TUI_KEY_UP;
        case 'B': return TUI_KEY_DOWN;
        case 'C': return TUI_KEY_RIGHT;
        case 'D': return TUI_KEY_LEFT;
        case 'H': return TUI_KEY_HOME;
        case 'F': return TUI_KEY_END;
        default: break;
    }
    /* A numeric form such as ESC [ 1 ~ . Consume to the terminator so the tail
     * is not mistaken for keystrokes, bounded by what is in the burst. */
    if (c2 >= '0' && c2 <= '9') {
        uint8_t n = (uint8_t)(c2 - '0');
        while (kpos < klen && kbuf[kpos] >= '0' && kbuf[kpos] <= '9') {
            n = (uint8_t)(n * 10 + (kbuf[kpos++] - '0'));
        }
        if (kpos < klen && kbuf[kpos] == '~') {
            kpos++;
            if (n == 1 || n == 7) return TUI_KEY_HOME;
            if (n == 4 || n == 8) return TUI_KEY_END;
        }
    }
    return TUI_KEY_ESC;
}
