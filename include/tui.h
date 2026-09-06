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
 *
 * ---- WHAT GREW ON 2026-09-06, AND WHAT DID NOT ---------------------------
 *
 * The rule this file has always stated -- "a program that has to be READ before
 * it is trusted does not get a widget set" -- still holds, and the 2026-09-06
 * work was shaped by it rather than around it. THERE ARE STILL EXACTLY TWO
 * INTERACTIONS, tui_input and tui_menu, and the count is the point: every
 * blocking loop over a keyboard is a place an installer can be made to do
 * something its operator did not ask for, so the number of them is a number
 * worth being able to state.
 *
 * What grew is RENDERING FIDELITY and TEXT LAYOUT, and neither adds a loop over
 * input or a piece of state a caller has to maintain:
 *
 *   - Colour, as four more bits in the attribute word that osgr already emits.
 *     No new call, no new control flow, one more clause in one function.
 *   - Line drawing, as a glyph table in tui_box plus a charset shift in
 *     tui_flush. The terminal draws the lines; we choose different bytes.
 *   - tui_center and tui_wrap, which exist BY SUBTRACTION. installer.c placed
 *     every line of prose with a hand-counted column number, and a hand-counted
 *     column is a thing that is silently wrong after an edit to the sentence
 *     above it. Moving that arithmetic here removes more code from the program
 *     being audited than it adds to the library, which is the only ground on
 *     which this file grows at all.
 *
 * A FORM LAYER WAS DESIGNED AND REJECTED, and the reason is recorded because
 * the next person to want one will want it for the same good reason. Tabbing
 * between fields, re-editing an answer, validating as you type: all of that is
 * genuinely friendlier than asking three questions in a row. It is also a third
 * blocking input loop, holding a caller's array of field descriptors, deciding
 * on the caller's behalf which field the next keystroke edits. The installer
 * needs the BEHAVIOUR and does not need it here: it gets the same result from a
 * review screen built out of the two interactions above -- tui_menu to choose
 * what to correct, tui_input to correct it -- written in installer.c, where the
 * logic that decides what an operator just consented to is in the file a
 * reviewer of that consent is already reading.
 */
#ifndef HORUS_TUI_H
#define HORUS_TUI_H

#include <stdint.h>
#include "console_proto.h"

/* ---- attributes ---------------------------------------------------------
 *
 * Sixteen bits: a foreground in 0..3, a background in 4..7, and flags above
 * them. Attributes are passed and stored as uint16_t; the type is spelled out
 * at every boundary rather than typedef'd, so a reader never has to look up
 * what an attr_t is.
 *
 * NINE COLOUR VALUES, AND BRIGHT IS BOLD. A default plus the eight ANSI
 * colours, which is what a VT100 has. There is no separate bright set because a
 * VT100 made bold text bright and this way the two cannot disagree -- one bit
 * asks for emphasis and the terminal decides what emphasis looks like, which is
 * also the right answer on a terminal whose palette we cannot see.
 *
 * VALUES ABOVE TUI_C_WHITE ARE TREATED AS DEFAULT, and that check is not
 * tidiness. SGR 38 and 48 are the extended-colour introducers: they consume the
 * parameters that follow them, so a foreground of 9 would emit `38` and swallow
 * the rest of the sequence -- turning a wrong colour into a corrupted escape
 * and, from there, into bytes the terminal renders as text. The clamp is in
 * osgr, at the one place a colour becomes a number on the wire. */
#define TUI_C_DEFAULT   0u
#define TUI_C_BLACK     1u
#define TUI_C_RED       2u
#define TUI_C_GREEN     3u
#define TUI_C_YELLOW    4u
#define TUI_C_BLUE      5u
#define TUI_C_MAGENTA   6u
#define TUI_C_CYAN      7u
#define TUI_C_WHITE     8u

#define TUI_FG(c)       ((uint16_t)((c) & 0x0Fu))
#define TUI_BG(c)       ((uint16_t)(((c) & 0x0Fu) << 4))

#define TUI_A_NORMAL    0x0000u
#define TUI_A_BOLD      0x0100u
#define TUI_A_DIM       0x0200u
#define TUI_A_REVERSE   0x0400u
#define TUI_A_UNDERLINE 0x0800u

/* The cell's byte is a DEC Special Graphics glyph rather than ASCII: tui_flush
 * shifts the terminal's G0 charset around runs of these. Set by tui_box; a
 * caller can set it with the TUI_ACS_* glyphs below, and nothing else in the
 * library produces it. See tui_box for why the terminal draws the lines instead
 * of us sending UTF-8. */
#define TUI_A_ACS       0x1000u

/* The DEC Special Graphics bytes this library uses, named. These are the same
 * glyphs ncurses calls ACS_HLINE and friends, and the same single-byte encoding
 * -- which is the reason for choosing this over UTF-8 box characters: a cell
 * holds ONE byte, and a three-byte UTF-8 glyph would either need a wider cell
 * or a cell whose width lies about the column it occupies. */
#define TUI_ACS_HLINE   'q'
#define TUI_ACS_VLINE   'x'
#define TUI_ACS_ULCORNER 'l'
#define TUI_ACS_URCORNER 'k'
#define TUI_ACS_LLCORNER 'm'
#define TUI_ACS_LRCORNER 'j'
#define TUI_ACS_LTEE    't'
#define TUI_ACS_RTEE    'u'
#define TUI_ACS_TTEE    'w'
#define TUI_ACS_BTEE    'v'
#define TUI_ACS_PLUS    'n'
#define TUI_ACS_BLOCK   '0'
#define TUI_ACS_DIAMOND '`'
#define TUI_ACS_BULLET  '~'

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

/* End a session: restore the ASCII charset, show the cursor, move to the last
 * row, leave the terminal in a state a shell can use. Safe to call without a
 * matching tui_begin. */
void tui_end(void);

/* The geometry tui_begin obtained. Always within CON_ROWS x CON_COLS. */
int  tui_rows(void);
int  tui_cols(void);

/* Drawing writes to the BACK buffer; nothing reaches the terminal until
 * tui_flush. All coordinates are clamped: a write outside the screen is
 * discarded, never wrapped and never written past the buffer. */
void tui_clear(void);
void tui_putc(int row, int col, char ch, uint16_t attr);
void tui_text(int row, int col, const char *s, uint16_t attr);
/* Draw `s` into a field of exactly `width` columns, padding with spaces and
 * truncating what does not fit. Menus need columns that do not shift when the
 * text changes length, and truncation here is what stops a long string from
 * overwriting a neighbouring field. */
void tui_field(int row, int col, int width, const char *s, uint16_t attr);
void tui_box(int row, int col, int height, int width, uint16_t attr);

/* Fill a rectangle with one character. The background of a panel, and the drawn
 * part of a bar -- both of which used to be a loop at the call site. */
void tui_fill(int row, int col, int height, int width, char ch, uint16_t attr);

/* ---- text layout, which exists by subtraction ---------------------------
 *
 * Both of these were arithmetic in installer.c, done by hand at every call. A
 * hand-counted centre is wrong the moment somebody edits the string, and a
 * hand-counted wrap is wrong the moment somebody edits the sentence -- silently,
 * on a screen that asks an operator to confirm destroying a disk. */

/* Centre `s` on `row` within the screen's width. */
void tui_center(int row, const char *s, uint16_t attr);

/* Draw `s` word-wrapped into a column `width` wide starting at (row, col), using
 * at most `max_rows` rows. Returns the number of rows used.
 *
 * A WORD LONGER THAN `width` IS BROKEN AT `width`, not allowed to run past it.
 * Overrunning is the classic wrap bug and it is not a cosmetic one here: the
 * column this draws into has a box edge to its right and, on the review screen,
 * a value to its left, so text that leaves its column corrupts the frame a
 * reader is using to tell one field from another. */
int  tui_wrap(int row, int col, int width, int max_rows, const char *s, uint16_t attr);

/* Place the visible cursor, or hide it. A negative row or column hides it.
 *
 * The cursor is state the TERMINAL holds and the cell buffers do not, so it is
 * diffed the same way cells are: tui_flush emits a position (and a show/hide)
 * only when the request has changed since the last flush. Emitting it every
 * time would put bytes on the wire for an unchanged screen, which is the one
 * thing tui_flush is built not to do.
 *
 * It exists for tui_input below: a field a person is typing into has to say
 * where the next character will land, and a hidden cursor in a form reads as a
 * hung program. */
void tui_cursor(int row, int col);

/* Emit the difference between the back and front buffers and make the back
 * buffer current. Only changed cells are addressed and written.
 *
 * IT ALWAYS LEAVES THE TERMINAL IN THE ASCII CHARSET. Line drawing works by
 * shifting G0 to DEC Special Graphics around a run of box cells, and a flush
 * that ended inside that shift would render every subsequent byte -- this
 * library's next screen, the task's own kput output, the login prompt after
 * tui_end -- as line-drawing glyphs. The shift is emitted per run and the
 * restore is unconditional at the end. */
void tui_flush(void);

/* Discard the library's belief about what the terminal is showing, so the next
 * tui_flush repaints every cell.
 *
 * WHY THIS HAS TO EXIST. The damage diff rests on one assumption: that nothing
 * writes to this terminal except tui_flush. That assumption is FALSE for every
 * program here that also emits marker lines, because those go out as cooked
 * CON_OP_WRITE requests to the same UART, landing at wherever the terminal's
 * cursor happens to be -- in the middle of a password field, as it turned out.
 * The library cannot see that, so `front` still says those cells are correct and
 * the next flush skips them. The text stays on the screen, through every
 * subsequent screen, until something else happens to write that exact cell.
 *
 * Measured on 2026-09-06 by rendering the installer's own serial stream through
 * a VT emulator: `*******INSTALLER: waiting on the user password again` drawn
 * across the password row of a live install. No gate saw it -- every installer
 * gate asserts on the markers themselves, which are on the wire either way, and
 * the TUI self-test asserts on cells the library owns. It is only visible to
 * somebody looking at the screen.
 *
 * A caller that writes to the terminal behind the library's back says so with
 * this. It is deliberately the CALLER's job rather than a wrapper the library
 * offers for printing: routing marker output through the TUI would put a second
 * output path inside it, and the whole argument for this file is that it has
 * one. */
void tui_invalidate(void);

/* Block for one key and return it. Never returns a partial escape sequence. */
int  tui_getkey(void);

/* ---- Two interactions, and only two -------------------------------------
 *
 * The count has not changed and is not expected to. Each is a loop over
 * tui_getkey with an explicit bound, and each returns rather than blocking
 * forever if the console stops answering -- an input loop with no way out is the
 * same wedge a permanent IPC refusal retried in a loop is (see the IPC retry
 * contract in syscall.h). A caller wanting something richer -- a form, a field
 * to go back and correct -- composes these two in its own file; see the note at
 * the top of this header for why that is the right place for it.
 */

/* Mask what is typed: draw one '*' per character instead of the character.
 * The clear text goes into the caller's buffer and NEVER into a cell, so it is
 * not in the front buffer, not on the wire, and not recoverable from a screen
 * scrape. An installer sets the first root password with this. */
#define TUI_IN_MASK     0x01u

/* Edit one line inside a field of exactly `width` columns.
 *
 * Returns 0 with `buf` NUL-terminated when ENTER is pressed, or -1 when ESC is
 * pressed or the console stops answering -- and on -1 `buf` is emptied rather
 * than left holding a partial answer, because a caller that ignores the return
 * value should get nothing rather than half of something.
 *
 * `cap` is the size of `buf` INCLUDING the terminator. The content is bounded
 * by `cap - 1` and by `width`, whichever is smaller: **a field is exactly as
 * long as it looks.** There is no horizontal scrolling, deliberately -- a field
 * whose contents you cannot see is a field you cannot check before pressing
 * enter, which is precisely the moment an installer must not be guessed at.
 * Input past the bound is discarded, not truncated silently at the end. */
int  tui_input(int row, int col, int width, char *buf, int cap, unsigned flags);

/* Choose one of `n` items drawn from `row` down, `*sel` in and out.
 *
 * Returns 0 with `*sel` set on ENTER, or -1 on ESC / a console that stops
 * answering, leaving `*sel` as it was. The selection is CLAMPED to 0..n-1: up
 * at the top and down at the bottom do nothing. That is a bounds check on the
 * caller's array as much as on this one -- the caller indexes `items[*sel]`
 * after this returns, and for an installer that array is the list of disks it
 * is about to destroy one of. */
int  tui_menu(int row, int col, int width, const char *const *items, int n, int *sel);

#ifdef TUI_SELFTEST
/* Test hooks. Present only under TUI_SELFTEST: the shipping library exposes no
 * way to read its buffers, read its output, or inject input. */
unsigned tui_test_emitted(void);
void     tui_test_reset(void);
char     tui_test_cell(int r, int c);
uint16_t tui_test_attr(int r, int c);
void     tui_test_feed(const uint8_t *b, unsigned n);
/* How many keys are still unread in the injected burst. The interaction tests
 * assert this is ZERO after a fed sequence: a loop that returned early has left
 * keys behind, and its result would then be right for the wrong reason. */
unsigned tui_test_keys_left(void);
/* The BYTES handed to the console since the last reset, copied out.
 *
 * Every other hook here reads the library's own state; this one reads what the
 * terminal was actually told, and some properties exist only there. Whether a
 * flush left the terminal in the line-drawing charset is not visible in a cell,
 * in a return value, or in the byte COUNT -- only in whether the stream ends
 * with the restore. Returns the number of bytes copied, capped at `max`. */
unsigned tui_test_out(char *out, unsigned max);
#endif

#endif /* HORUS_TUI_H */
