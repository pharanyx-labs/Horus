/* Blocking-receive self-test CLIENT (RECVBLOCK_SELFTEST builds only).
 *
 * Sends RB_MESSAGES requests to the endpoint recvblocksrv is receiving on, with
 * a deliberately long ring-3 delay before each one.
 *
 * The delay is the instrument, not padding. The server's central assertion is
 * that it made exactly one receive syscall per message; that only distinguishes
 * a sleeping receiver from a polling one if there is a real window in which a
 * polling receiver would be forced to go round its loop. Sending immediately
 * would let a poll loop score one call per message too, and the test would pass
 * against the very implementation it exists to rule out.
 *
 * sys_ipc_call blocks until the server's reply arrives, so a reply that is
 * dropped, misrouted, or never authorised stalls this client rather than being
 * mistaken for success.
 */

#include "syscall.h"

#define RB_MESSAGES 4
#define RB_PAYLOAD  16

static void kput(const char *s) { unsigned n = 0; while (s[n]) n++; sys_write(1, s, n); }

/* Busy-wait in ring 3: a cooperative yield cannot switch between two ring-3
 * tasks, so the timer preemption is what hands the CPU to the server. Sized so
 * that a polling server would go round its loop many times across the window. */
static void spin_delay(void) { for (volatile unsigned i = 0; i < 400000u; i++) { } }

void _start(void) {
    unsigned char req[RB_PAYLOAD];
    unsigned char rep[RB_PAYLOAD];

    for (unsigned i = 0; i < RB_PAYLOAD; i++) req[i] = (unsigned char)('a' + (i & 15));

    for (int m = 0; m < RB_MESSAGES; m++) {
        /* Leave the server with an empty queue for long enough that a poller
         * would have to spin. */
        spin_delay();

        int rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, req, RB_PAYLOAD, rep);
        if (rc < 0) {
            /* Retry only what the contract says is retryable: IPC_AGAIN. A
             * permanent refusal looped on here would turn an authority error
             * into an unkillable wedge (the G-8 trap). */
            unsigned tries = 0;
            while (rc == IPC_AGAIN) {
                if (++tries > 200000u) { kput("RECVBLOCK_SELFTEST: FAIL client-call-timeout\n"); sys_exit(); }
                spin_delay();
                rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, req, RB_PAYLOAD, rep);
            }
            if (rc < 0) { kput("RECVBLOCK_SELFTEST: FAIL client-call-refused\n"); sys_exit(); }
        }
    }

    sys_exit();
}
