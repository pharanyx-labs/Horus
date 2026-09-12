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

/* Emit a marker through the console SERVER, which writes to serial natively.
 * See the note in _start: kput cannot be seen once the server owns the console. */
static void say(const char *m) {
    struct con_request  q;
    struct con_response r;
    umemset(&q, 0, sizeof(q));
    q.op  = CON_OP_WRITE;
    unsigned k = uslen(m); if (k > CON_IO_MAX) k = CON_IO_MAX;
    umemcpy(q.data, m, k);
    q.len = k;
    (void)rpc(&q, &r);
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

    /* ---- S93: a console client is not entitled to read a password ---------
     *
     * This task holds exactly what every task the shell spawns holds -- one
     * send-only console capability, inherited so that it has a stdout. Before
     * 2026-09-12 that also bought the right to sit on CON_OP_GETPASS and
     * collect the password typed at the next `sudo` prompt, from any program a
     * person had run.
     *
     * OWNERSHIP IS CLAIMED FOR SOMEBODY ELSE FIRST, and that is what makes the
     * refusal below mean anything. The server fails closed on an UNSET owner,
     * so a probe that simply asked would be refused for the wrong reason -- it
     * would prove the fail-closed default and say nothing about the gate. So
     * the owner is set to a task id that is not this one, and the refusal is
     * then specifically "you are not the owner".
     *
     * Setting it is allowed here because in a CONSOLE_SELFTEST build there is
     * no init and no shell, so the owner is still unset and the bootstrap rule
     * applies -- the same rule, exercised from the other side. */
    /* MARKERS GO THROUGH THE SERVER, not through kput.
     *
     * kput reaches print(), which is klog-only once a ring-3 console server owns
     * the hardware -- so everything this probe said with it landed in the ring
     * buffer and nothing reached serial. The first run of this gate timed out
     * with no CONSOLE_PASS line at all, which looked like the code not running.
     * CONSOLE_SELFTEST: PASS above is visible for exactly this reason: the
     * SERVER writes it with its own hands. */
    uint32_t me = sys_getpid();
    umemset(&rq, 0, sizeof(rq));
    rq.op  = CON_OP_SET_INPUT_OWNER;
    rq.len = me + 1;                  /* deliberately not us */
    if (rpc(&rq, &rp) != 0) { say("CONSOLE_PASS: FAIL could-not-set-owner\n"); sys_exit(); }

    /* Said BEFORE the request, because under CONSOLE_PASS_UNGATED the server
     * serves it and blocks in the read, so nothing after this line is reached.
     * The arm asserts this marker present and the verdict below absent, which
     * is the same shape smoke-captest-getline-control uses: a task admitted to
     * a console read prints nothing, so absence is the evidence. */
    say("CONSOLE_PASS: asking for a password as a non-owner\n");

    umemset(&rq, 0, sizeof(rq));
    rq.op  = CON_OP_GETPASS;
    rq.len = 16;
    int prc = rpc(&rq, &rp);
    if (prc == SYS_ERR_PERM) say("CONSOLE_PASS: PASS refused a non-owner\n");
    else                     say("CONSOLE_PASS: FAIL a non-owner was served\n");

    sys_exit();
}
