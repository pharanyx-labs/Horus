/* termtest — proves the console raw ("full-screen") terminal layer end to end.
 *
 * A curses program (and nano) drives the console like a real VT/ANSI terminal:
 * query the window size, switch to raw mode (no echo, no line editing), emit
 * cursor/clear escape sequences, and read key bytes one at a time. This exercises
 * exactly that path against the ring-3 console_server's new raw ops:
 *
 *   1. ioctl(TIOCGWINSZ)  -> CON_OP_WINSZ   (geometry)
 *   2. tcsetattr(raw)     -> g_console_raw = 1
 *   3. write(escape+text) -> CON_OP_WRITE_RAW (verbatim, no \n->\r\n)
 *   4. read(1 byte)       -> CON_OP_READ_RAW  (un-echoed, un-edited)
 *   5. tcsetattr(cooked)  -> restore, then report the key.
 *
 * Driven by tools/term_session.py (make smoke-term): it runs termtest, sends one
 * key over serial, and asserts on the geometry, the echoed key code, and PASS.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/termios.h>
#include <sys/ioctl.h>

int main(void) {
    struct winsize ws;
    ws.ws_row = ws.ws_col = 0;
    ioctl(0, TIOCGWINSZ, &ws);
    printf("TERM: size %dx%d\n", ws.ws_col, ws.ws_row);   /* cooked mode */
    fflush(stdout);

    struct termios old, raw;
    if (tcgetattr(0, &old) != 0) { printf("TERMRAW_SELFTEST: FAIL tcgetattr\n"); return 1; }
    raw = old;
    cfmakeraw(&raw);
    tcsetattr(0, TCSANOW, &raw);

    /* In raw mode: an ANSI clear+home escape followed by a prompt, emitted
     * verbatim so a real terminal on the far end renders it. */
    const char *msg = "\x1b[2J\x1b[HTERM: raw mode; press a key\r\n";
    write(1, msg, strlen(msg));

    unsigned char c = 0;
    int n = read(0, &c, 1);          /* one un-echoed key byte */

    tcsetattr(0, TCSANOW, &old);     /* restore cooked mode */

    printf("\nTERM: read %d byte(s), key=0x%02x\n", n, (unsigned)c);
    printf(n == 1 ? "TERMRAW_SELFTEST: PASS\n" : "TERMRAW_SELFTEST: FAIL\n");
    fflush(stdout);
    return n == 1 ? 0 : 1;
}
