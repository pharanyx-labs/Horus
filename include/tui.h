/* A small full-screen text UI for ring 3, over the console server.
 *
 * WHY THIS AND NOT NCURSES
 *
 * ncurses brings terminfo, a compiled terminal database, and decades of
 * compatibility surface for terminals Horus will never meet. The whole argument
 * of this kernel is a small auditable TCB, and while a TUI is ring-3 code that
 * holds no capability of its own, an installer built on it will be the program
 * that formats disks and sets the first root password. The code between a
 * keystroke and that decision should be code someone has read.
 *
 * Horus talks to exactly one kind of terminal: a VT/ANSI console on the far end
 * of a serial line, reported as a fixed CON_ROWS x CON_COLS (console_proto.h
 * says why the geometry is fixed). Targeting only that removes the database and
 * most of the library with it.
 *
 * WHAT IT ADDS TO THE ATTACK SURFACE: nothing. Every operation is a
 * CON_OP_WRITE_RAW / CON_OP_READ_RAW / CON_OP_WINSZ request on the console
 * endpoint the calling task already holds. There is no new syscall, no kernel
 * change, and no privilege here that a task with the console capability did not
 * already have. A task without that capability cannot draw, which is the same
 * refusal it already gets for printing.
 *
 * WHAT IT DELIBERATELY DOES NOT HAVE
 *
 *   - No allocation. Two static CON_ROWS x CON_COLS cell buffers, front and
 *     back. A TUI that cannot allocate cannot fail to allocate.
 *   - No varargs. No printf-style formatting anywhere, so there is no format
 *     string to get wrong and no way for caller data to be read as a format.
 *   - No unbounded loops over input. A key burst is read once and decoded from
 *     a buffer; a partial or malformed escape sequence yields TUI_KEY_ESC
 *     rather than a wait for bytes that may never come.
 *   - No cursor state the caller has to maintain. Coordinates are explicit and
 *     clamped, so an out-of-range write is a no-op rather than a corruption.
 */
#ifndef HORUS_TUI_H
#define HORUS_TUI_H

#include <stdint.h>
#include "console_proto.h"

/* Attributes. Deliberately a small set: these are the SGR codes a VT100 has,
 * and anything richer would be a claim about terminals we cannot check. */
#define TUI_A_NORMAL    0x00u
#define TUI_A_BOLD      0x01u
#define TUI_A_REVERSE   0x02u
#define TUI_A_DIM       0x04u

/* Decoded keys. Printable input is returned as its own byte value (< 0x80), so
 * a caller can test `k < 0x80` for "this is a character". Everything else is
 * above that range and cannot collide with it. */
#define TUI_KEY_NONE    0x100
#define TUI_KEY_UP      0x101
#define TUI_KEY_DOWN    0x102
#define TUI_KEY_LEFT    0x103
#define TUI_KEY_RIGHT   0x104
#define TUI_KEY_ENTER   0x105
#define TUI_KEY_ESC     0x106
#define TUI_KEY_BACKSP  0x107
#define TUI_KEY_HOME    0x108
#define TUI_KEY_END     0x109
#define TUI_KEY_TAB     0x10A

/* Begin a session: query the console geometry, clear both buffers, hide the
 * cursor. Returns 0, or -1 if the console server did not answer -- in which
 * case nothing was drawn and the caller should fall back to line output rather
 * than proceed blind. */
int  tui_begin(void);

/* End a session: show the cursor, move to the last row, leave the terminal in a
 * state a shell can use. Safe to call without a matching tui_begin. */
void tui_end(void);

/* The geometry tui_begin obtained. Always within CON_ROWS x CON_COLS. */
int  tui_rows(void);
int  tui_cols(void);

/* Drawing writes to the BACK buffer; nothing reaches the terminal until
 * tui_flush. All coordinates are clamped: a write outside the screen is
 * discarded, never wrapped and never written past the buffer. */
void tui_clear(void);
void tui_putc(int row, int col, char ch, uint8_t attr);
void tui_text(int row, int col, const char *s, uint8_t attr);
/* Draw `s` into a field of exactly `width` columns, padding with spaces and
 * truncating what does not fit. Menus need columns that do not shift when the
 * text changes length, and truncation here is what stops a long string from
 * overwriting a neighbouring field. */
void tui_field(int row, int col, int width, const char *s, uint8_t attr);
void tui_box(int row, int col, int height, int width, uint8_t attr);

/* Emit the difference between the back and front buffers and make the back
 * buffer current. Only changed cells are addressed and written. */
void tui_flush(void);

/* Block for one key and return it. Never returns a partial escape sequence. */
int  tui_getkey(void);

#ifdef TUI_SELFTEST
/* Test hooks. Present only under TUI_SELFTEST: the shipping library exposes no
 * way to read its buffers or inject input. */
unsigned tui_test_emitted(void);
void     tui_test_reset(void);
char     tui_test_cell(int r, int c);
void     tui_test_feed(const uint8_t *b, unsigned n);
#endif

#endif /* HORUS_TUI_H */
