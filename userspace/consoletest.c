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
 * include/console_proto.h and docs/design/console-server.md.
 */

#include "syscall.h"
#include "console_proto.h"
#include "libhorus.h"


/* Busy-wait in ring 3 between IPC retries so the timer preempts us and runs the
 * server (a cooperative yield cannot switch two ring-3 tasks). */

/* One request/reply round-trip; retries while the request mailbox is momentarily
 * full (another request in flight) or the server is not yet serving. */
static int rpc(struct con_request *rq, struct con_response *rp) {
    rq->magic = CON_PROTO_MAGIC;
    /* The retry contract (transient only, and bounded) lives in
     * libhorus's ipc_call_retry. It used to be written out here, and in
     * fsclient.c, from the same finding -- G-8 signature C, where the old
     * `while (r < 0)` retried SYS_ERR_PERM forever and turned a capability
     * refusal into an unkillable hang. Two copies of a rule is one copy from
     * drifting. */
    int r = ipc_call_retry(CAPSLOT_CONSOLE_EP, 0, rq, sizeof(*rq), rp);
    if (r < 0) return r;
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
