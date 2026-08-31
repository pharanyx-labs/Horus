/* Blocking-receive self-test SERVER (RECVBLOCK_SELFTEST builds only).
 *
 * Roadmap 1.3's last piece. SYS_IPC_RECV returns IPC_AGAIN on an empty queue, so
 * a server with nothing to do polls; SYS_IPC_RECV_BLOCK sleeps instead. This
 * proves the difference is real rather than nominal.
 *
 * ---- What is asserted, and why each check can fail -------------------------
 *
 * 1. The call NEVER returns IPC_AGAIN. That is the API contract, and a
 *    "blocking" receive that still hands back "try again" would silently leave
 *    every server polling.
 *
 * 2. EXACTLY ONE receive syscall per message. This is the check that witnesses
 *    the SLEEP, and it is the reason the client below wastes real time before
 *    each send: a polling receiver would have to return, and be called again,
 *    many times across that window, so `calls` would exceed `RB_MESSAGES`. A
 *    receive that spun in the kernel instead of descheduling would also pass
 *    check 1 — this is the one it cannot pass by accident.
 *
 * 3. The woken server holds the ONE-SHOT REPLY RIGHT. This is the interesting
 *    half: a blocking receive is completed by the SENDER's syscall, on the
 *    sender's CPU, so the CAP_REPLY has to be minted into a cspace that is not
 *    the current one. Get that wrong and the server receives a request it has no
 *    authority to answer — a receive that is not equivalent to the polling one.
 *    sys_ipc_reply_to needs that capability and fails with SYS_ERR_PERM without
 *    it, so a successful reply is the witness.
 *
 * The client blocks in SYS_IPC_CALL for each reply, so a missing or misrouted
 * reply wedges the test rather than passing it quietly.
 */

#include "syscall.h"
#include "libhorus.h"

#define RB_MESSAGES 4
#define RB_PAYLOAD  16


static void fail(const char *what) {
    kput_marker("RECVBLOCK_SELFTEST: FAIL ", what);
    sys_exit();
}

void _start(void) {
    unsigned char buf[RB_PAYLOAD];
    int got = 0;
    int calls = 0;

    while (got < RB_MESSAGES) {
        calls++;
        int rc = sys_ipc_recv_block(CAPSLOT_CONSOLE_EP, buf, sizeof(buf));

        /* Check 1. Exact code, never `< 0`: IPC_AGAIN is the specific thing this
         * syscall exists to never return, and `< 0` would also swallow a
         * capability refusal, which is a different bug entirely. */
        if (rc == IPC_AGAIN) fail("recv-block-returned-IPC_AGAIN");
        if (rc < 0)          fail("recv-block-refused");
        if (rc != RB_PAYLOAD) fail("recv-block-wrong-length");
        got++;

        /* Check 3. The reply right must have been minted by the WAKE, into this
         * task's cspace, by a syscall running in the sender's context. */
        int rr = sys_ipc_reply_to(CAPSLOT_CONSOLE_EP, buf, RB_PAYLOAD);
        if (rr == SYS_ERR_PERM) fail("woken-server-holds-no-reply-right");
        if (rr < 0)             fail("reply-to-failed");
    }

    /* Check 2. The sleep itself. */
    if (calls != RB_MESSAGES) fail("server-polled-instead-of-sleeping");

    kput("RECVBLOCK_SELFTEST: PASS\n");
    sys_exit();
}
