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
