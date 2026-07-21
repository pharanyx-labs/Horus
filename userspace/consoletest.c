/* Console self-test client (CONSOLE_SELFTEST builds only).
 *
 * Connects to the userspace console server over IPC and asks it to write a line
 * to the console. The server emits that line to the serial port with its own
 * hands (native out), so the success marker appearing on serial is proof of the
 * whole ring-3 console output path: client -> IPC -> console_server -> hardware,
 * with no kernel console code involved. On an IPC/protocol error the client
 * prints a FAIL marker through the kernel console (the only path it has).
 *
 * This mirrors how fsclient first proved the filesystem server over IPC. See
 * include/console_proto.h and docs/proposals/console-server.md.
 */

#include "syscall.h"
#include "console_proto.h"

static void kput(const char *s) { unsigned n = 0; while (s[n]) n++; sys_write(1, s, n); }
static void umemset(void *d, int v, unsigned n) { uint8_t *p = d; while (n--) *p++ = (uint8_t)v; }
static void umemcpy(void *d, const void *s, unsigned n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static unsigned uslen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }

/* Busy-wait in ring 3 between IPC retries so the timer preempts us and runs the
 * server (a cooperative yield cannot switch two ring-3 tasks). */
static void spin_delay(void) { for (volatile unsigned i = 0; i < 40000u; i++) { } }

/* One request/reply round-trip; retries while the request mailbox is momentarily
 * full (another request in flight) or the server is not yet serving. */
static int rpc(struct con_request *rq, struct con_response *rp) {
    rq->magic = CON_PROTO_MAGIC;
    int r;
    while ((r = sys_ipc_call(CON_EP_REQ, CON_EP_REP, rq, sizeof(*rq), rp)) < 0) spin_delay();
    if (rp->magic != CON_PROTO_MAGIC) return -102;
    return rp->rc;
}

void _start(void) {
    /* The payload IS the success marker: the server writes it to serial natively,
     * so its appearance proves the ring-3 console served this write end-to-end. */
    static const char *msg = "CONSOLE_SELFTEST: PASS\n";

    struct con_request  rq;
    struct con_response rp;
    umemset(&rq, 0, sizeof(rq));
    rq.op  = CON_OP_WRITE;
    unsigned n = uslen(msg); if (n > CON_IO_MAX) n = CON_IO_MAX;
    umemcpy(rq.data, msg, n);
    rq.len = n;

    int rc = rpc(&rq, &rp);
    if (rc != (int)n) { kput("CONSOLE_SELFTEST: FAIL rc\n"); sys_exit(); }

    sys_exit();
}
