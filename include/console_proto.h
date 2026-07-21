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
 * both structs below must stay <= 256 bytes. See docs/proposals/console-server.md.
 */

#include <stdint.h>

#define CON_PROTO_MAGIC   0x48435052u   /* "HCPR" */

/* Well-known endpoint indices for the console service (distinct from the FS
 * server's 4/5 so the two can run side by side). Requests go to CON_EP_REQ;
 * replies are routed back to each caller by identity via SYS_IPC_REPLY_TO, so
 * CON_EP_REP is only the endpoint a client parks its SYS_IPC_CALL block on. */
#define CON_EP_REQ   6   /* client -> server requests */
#define CON_EP_REP   7   /* client's SYS_IPC_CALL reply-wait endpoint */

/* Operations. */
#define CON_OP_WRITE    1   /* data[len]  -> rc = bytes written; emit bytes to the console */
#define CON_OP_GETLINE  2   /* len = max  -> data[rc], rc = line length; read one edited,
                             * echoed line from the console (up to Enter) */
#define CON_OP_GETPASS  3   /* len = max  -> data[rc], rc = line length; as GETLINE but the
                             * echo is masked ('*'), for password entry */

#define CON_IO_MAX   200  /* max payload bytes per write request */
#define CON_LINE_MAX 128  /* max input line (incl. NUL); matches the kernel's h_get_line */

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
