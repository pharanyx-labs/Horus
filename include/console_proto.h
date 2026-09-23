#ifndef HORUS_CONSOLE_PROTO_H
#define HORUS_CONSOLE_PROTO_H

/* IPC protocol between clients and the userspace console server (Phase 6, driver
 * privilege separation — the console moved out of ring 0).
 *
 * The console server owns the console hardware directly: it maps the VGA text
 * framebuffer into its own address space (SYS_MAP_PHYS), runs in/out on the
 * serial UART and VGA registers natively (SYS_IOPORT_GRANT / TSS I/O bitmap), and
 * (for input, a later job) is woken by the keyboard IRQ (SYS_IRQ_REGISTER). A
 * client sends one request and blocks for the reply with SYS_IPC_CALL on
 * CON_EP_REQ; the server does recv(CON_EP_REQ), process, then
 * SYS_IPC_REPLY_TO(CON_EP_REQ), which routes the reply to that request's
 * kernel-recorded sender — so concurrent clients never collide on a shared reply
 * endpoint (the same model as the filesystem server, see include/fs_proto.h).
 *
 * Transport is the kernel's single-slot endpoint mailbox (IPC_MSG_MAX = 256), so
 * both structs below must stay <= 256 bytes. See docs/design/console-server.md.
 */

#include <stdint.h>

#define CON_PROTO_MAGIC   0x48435052u   /* "HCPR" */

/* The console service's request endpoint OBJECT index.
 *
 * As with FS_EP_REQ, userspace no longer names this in a syscall (audit finding
 * C-1): IPC takes cspace SLOTS and the kernel derives the object from the
 * capability there. A client reaches the console through CAPSLOT_CONSOLE_EP,
 * which init delegates to the shell and do_spawn propagates (send-only) to every
 * child. CON_EP_REP is gone — replies land on the caller's private reply
 * endpoint. */
#define CON_EP_REQ   6   /* client -> server requests (object index, not a slot) */

/* Operations. */
#define CON_OP_WRITE    1   /* data[len]  -> rc = bytes written; emit bytes to the console
                             * (cooked: '\n' is expanded to '\r\n' on serial) */
#define CON_OP_GETLINE  2   /* len = max  -> data[rc], rc = line length; read one edited,
                             * echoed line from the console (up to Enter) */
#define CON_OP_GETPASS  3   /* len = max  -> data[rc], rc = line length; as GETLINE but the
                             * echo is masked ('*'), for password entry */

/* Raw ("full-screen") terminal mode. The interactive console is a real VT/ANSI
 * terminal on the far end of the serial line (nc / xterm / the test harness), so
 * a curses program running on Horus drives it by passing escape sequences through
 * verbatim and reading key bytes with no echo or line editing. termios raw mode
 * (see userspace/newlib_glue) routes read()/write() on the console through these. */
#define CON_OP_READ_RAW  4  /* len = max -> data[rc]; up to `len` raw input bytes with NO echo
                             * and NO line editing. Blocks until >=1 byte, then returns the
                             * whole immediately-available burst (so ESC-[-A arrives together) */
#define CON_OP_WRITE_RAW 5  /* data[len] -> rc = bytes written; emit bytes VERBATIM (no
                             * '\n'->'\r\n' translation), for escape sequences + screen output */
#define CON_OP_WINSZ     6  /* (no payload) -> rc = (rows<<16)|cols; the console's size */

/* THE MACHINE'S OWN SCREEN, WHICH CON_OP_WRITE_RAW NEVER REACHED.
 *
 * WRITE_RAW above emits to the serial line and nothing else, on the reasoning
 * that a curses program targets the VT terminal on the far end of it. That
 * reasoning holds for every machine the gates run on and fails for the machine
 * this system is carried to: an IdeaPad 1 14IGL05 has no serial port, so the
 * installer drew its screens into a UART that is not there and the operator saw
 * a boot log that appeared to stop. Found 2026-09-22 by driving the installer
 * blind on that laptop, where pressing Enter advanced every marker while
 * nothing was ever painted.
 *
 * A FULL-SCREEN PROGRAM SENDS CELLS HERE, NOT ESCAPE SEQUENCES. The library
 * already keeps a cell grid and a damage diff, so it sends the cells it has
 * already computed and the server paints them on whichever display the machine
 * has. Escape sequences still go to serial through WRITE_RAW, from the same one
 * walk of the same buffer, so a machine with a serial terminal is unchanged and
 * a machine with a screen is no longer blind. Parsing a VT stream in the server
 * was the alternative and was rejected: a parser mis-renders where a mis-sent
 * cell simply fails.
 *
 * THE PAYLOAD IS A SEQUENCE OF SPANS, each a five-byte header then its text:
 *
 *     row, col, attr_lo, attr_hi, n, ch[n]
 *
 * `row` and `col` place the span's first cell, `attr` is the tui.h attribute
 * word (TUI_FG/TUI_BG/TUI_A_*) in little-endian order, and `n` is how many
 * characters follow. A span never wraps: the whole of it must fit on its row.
 *
 * EVERY FIELD IS CHECKED BY THE SERVER AND NOT BY THE SENDER. This arrives from
 * another ring-3 task, which is hostile by assumption, and a span that does not
 * fit the grid would otherwise be a write past the shadow buffer. A malformed
 * span stops the whole request rather than being skipped: a sender that got one
 * span wrong has lost track of the screen, and painting the rest of its message
 * would put half a correction on the display. */
#define CON_OP_DRAW_CELLS 9 /* data[len] = spans (see above) -> rc = cells painted,
                             * or SYS_ERR_INVAL if any span is malformed */

/* The boot log ends here. Until this arrives, the server puts a
 * "[    S.uuuuuu] " prefix on every line of CON_OP_WRITE output and on its own
 * status lines, continuing the timestamped log the kernel was printing before
 * the console changed hands. After it, bytes go through verbatim, because the
 * console is no longer a log -- it is a terminal, and a timestamp in front of a
 * shell prompt, an echoed keystroke or a column of `ls -l` is wrong rather than
 * merely noisy.
 *
 * init sends it once, immediately before it launches the shell (or, on an
 * uninstalled machine, before the installer's first raw write). A server that
 * never receives it keeps stamping, which is the right failure: an image whose
 * init is replaced by a self-test client -- INIT_FS_SELFTEST, and every
 * smoke-* workload that never reaches a login prompt -- prints nothing BUT a
 * boot log. Serving any input request has the same effect, as a backstop: a
 * console someone is typing at is a terminal whether or not anyone said so. */
/* WHICH TASK MAY READ A PASSWORD FROM THIS CONSOLE (S93).
 *
 * `len` carries the task id. Sent once by `init`, immediately before it resumes
 * the shell -- the moment at which init is the only ring-3 task in the system
 * holding a console client capability, so nothing can get in first.
 *
 * THE RULE IS "UNSET, OR THE OWNER". An owner that has not been set yet may be
 * set by anybody, which is the bootstrap; once set, only the current owner may
 * change it. That makes the boot-time registration safe without the server
 * having to recognise init, which it cannot do and should not learn to: knowing
 * "this sender is init" would be authority by identity, and the thing being
 * registered is precisely the authority.
 *
 * GETPASS is the only operation this gates, and that is the whole of the
 * finding rather than a first slice of it. Every task the shell spawns inherits
 * a send-only console capability -- that is how `ls` gets a stdout -- so before
 * this, any program a person ran could sit in a loop on CON_OP_GETPASS and
 * receive the password typed at the next `sudo` prompt. GETLINE and READ_RAW
 * stay open because `cat` with no arguments and the installer's own TUI read
 * through them; closing those needs a foreground-ownership model, which is
 * recorded in docs/LIMITATIONS.md rather than half-built here. */
#define CON_OP_SET_INPUT_OWNER 8  /* len = task id -> rc = 0, or SYS_ERR_PERM */

#define CON_OP_BOOT_DONE 7  /* (no payload) -> rc = 0; stop stamping: the session begins */

#define CON_IO_MAX   200  /* max payload bytes per write request */
#define CON_LINE_MAX 128  /* max input line (incl. NUL); matches the kernel's h_get_line */

/* The console's reported size in raw mode. A serial console has no reliable
 * queryable geometry, so Horus reports a fixed, conventional 80x24 (curses reads
 * this via ioctl(TIOCGWINSZ)); the VGA text grid is 80x50 but the serial terminal
 * is the interactive surface a full-screen app targets. */
#define CON_ROWS  24
#define CON_COLS  80

struct con_request {
    uint32_t magic;                 /* CON_PROTO_MAGIC */
    uint32_t op;
    uint32_t len;                   /* WRITE: payload length; GETLINE/GETPASS: max line len */
    uint8_t  data[CON_IO_MAX];      /* write payload (WRITE only) */
};                                  /* 12 + 200 = 212 <= 256 */

struct con_response {
    uint32_t magic;                 /* CON_PROTO_MAGIC */
    int32_t  rc;                    /* WRITE: bytes written; GETLINE/GETPASS: line length;
                                     * negative SYS_ERR_* on failure */
    uint8_t  data[CON_LINE_MAX];    /* the input line (GETLINE/GETPASS), NUL-terminated */
};                                  /* 8 + 128 = 136 <= 256 */

#endif /* HORUS_CONSOLE_PROTO_H */
