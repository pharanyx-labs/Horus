/* Full-screen text UI over the console server. See include/tui.h for why this
 * exists rather than a port of ncurses, and for what it deliberately lacks. */
#include "tui.h"
#include "syscall.h"
#include "libhorus.h"

/* One cell. Kept to two bytes so the pair of buffers is 2 * 24 * 80 = 3840
 * bytes of .bss and nothing has to be allocated. */
struct cell { char ch; uint8_t attr; };

static struct cell back[CON_ROWS][CON_COLS];
static struct cell front[CON_ROWS][CON_COLS];
static int g_rows = CON_ROWS;
static int g_cols = CON_COLS;
static int g_active = 0;

static struct con_request  rq;   /* static: these are 256 bytes each and a */
static struct con_response rp;   /* ring-3 stack is not the place for them */

static uint8_t kbuf[CON_IO_MAX];
static unsigned klen, kpos;

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
unsigned tui_test_emitted(void)   { return g_emitted; }
void     tui_test_reset(void)     { g_emitted = 0; }
char     tui_test_cell(int r, int c)
{
    if (r < 0 || r >= CON_ROWS || c < 0 || c >= CON_COLS) return 0;
    return back[r][c].ch;
}
/* Inject a key burst, so the decoder is tested against exact byte sequences
 * rather than against whatever a terminal happens to send. */
void tui_test_feed(const uint8_t *b, unsigned n)
{
    if (n > sizeof(kbuf)) n = sizeof(kbuf);
    for (unsigned i = 0; i < n; i++) kbuf[i] = b[i];
    klen = n; kpos = 0;
}
#endif

static void oflush(void)
{
    if (olen) {
#ifdef TUI_SELFTEST
        g_emitted += olen;
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

static void osgr(uint8_t attr)
{
    oputs("\033[0");
    if (attr & TUI_A_BOLD)    oputs(";1");
    if (attr & TUI_A_DIM)     oputs(";2");
    if (attr & TUI_A_REVERSE) oputs(";7");
    oput('m');
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
            front[r][c].ch = '\0'; front[r][c].attr = 0xFF;
        }
    olen = 0;
    g_active = 1;
    oputs("\033[?25l");                    /* hide the cursor */
    oputs("\033[2J");                      /* clear, so the terminal agrees */
    oflush();
    return 0;
}

void tui_end(void)
{
    if (!g_active) return;
    olen = 0;
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

void tui_putc(int row, int col, char ch, uint8_t attr)
{
    if (!in_screen(row, col)) return;
    /* Control characters would move the terminal's cursor out from under the
     * diff, so they are replaced rather than emitted. A cell holds one glyph. */
    if ((unsigned char)ch < 0x20 || (unsigned char)ch == 0x7F) ch = ' ';
    back[row][col].ch   = ch;
    back[row][col].attr = attr;
}

void tui_text(int row, int col, const char *s, uint8_t attr)
{
    if (!s) return;
    for (int i = 0; s[i]; i++) tui_putc(row, col + i, s[i], attr);
}

void tui_field(int row, int col, int width, const char *s, uint8_t attr)
{
    if (width <= 0) return;
    int i = 0;
    if (s) for (; s[i] && i < width; i++) tui_putc(row, col + i, s[i], attr);
    for (; i < width; i++) tui_putc(row, col + i, ' ', attr);
}

void tui_box(int row, int col, int height, int width, uint8_t attr)
{
    if (height < 2 || width < 2) return;
    for (int c = 1; c < width - 1; c++) {
        tui_putc(row, col + c, '-', attr);
        tui_putc(row + height - 1, col + c, '-', attr);
    }
    for (int r = 1; r < height - 1; r++) {
        tui_putc(row + r, col, '|', attr);
        tui_putc(row + r, col + width - 1, '|', attr);
    }
    tui_putc(row, col, '+', attr);
    tui_putc(row, col + width - 1, '+', attr);
    tui_putc(row + height - 1, col, '+', attr);
    tui_putc(row + height - 1, col + width - 1, '+', attr);
}

/* ---- flush -------------------------------------------------------------- */

/* Emit only what changed. The cursor is re-addressed when the run of changed
 * cells breaks, and the attribute is re-emitted only when it differs from what
 * was last set -- so a screen where one field changed costs one CUP and a few
 * bytes rather than a full repaint.
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
            oput(back[r][c].ch);
            cursor_c++;                       /* the terminal advanced it too */
            front[r][c] = back[r][c];
        }
    }
    oflush();
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
