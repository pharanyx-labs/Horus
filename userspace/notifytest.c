#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/*
 * NOTIFY_SELFTEST driver. The kernel (notify_selftest) spawns two instances of
 * this program, each holding a slot-3 endpoint capability (READ|WRITE) that gates
 * SYS_NOTIFY (WRITE) and SYS_WAIT_NOTIFY (READ). They rendezvous on notification
 * slot 0. The spawn argument selects the role: 0 = waiter, 1 = sender.
 *
 * The sender fires a single known badge with SYS_NOTIFY; the waiter blocks in
 * SYS_WAIT_NOTIFY and must receive that exact badge back. Because only one badge
 * is ever sent, the expected value is deterministic regardless of which task the
 * scheduler runs first: if the waiter blocks first, the sender's notify wakes it
 * through the kernel's blocked-waiter path (sys_notify patches the waiter's saved
 * rbx); if the sender runs first, the kernel accumulates the badge and the waiter
 * consumes it immediately. Either way the badge must arrive intact — the point of
 * the test is that the badge VALUE reaches userspace (returned in ebx), which is
 * exactly the part the async-notification ABI hinges on.
 */
#define NOTIF_SLOT 0
#define BADGE      0x0000BADEu

void _start(void) {
    uint32_t role = sys_spawn_arg();

    if (role == 1) {
        /* Sender: deliver the badge and exit. */
        sys_notify(NOTIF_SLOT, BADGE);
        sys_exit();
    }

    /* Waiter: block until the badge arrives, then verify it round-tripped. */
    report("NOTIFY_SELFTEST: begin\n");
    uint32_t badge = 0;
    int rc = sys_wait_notify(NOTIF_SLOT, &badge);
    if (rc != 0)        { report("NOTIFY_SELFTEST: FAIL rc\n");    sys_exit(); }
    if (badge != BADGE) { report("NOTIFY_SELFTEST: FAIL badge\n"); sys_exit(); }
    report("NOTIFY_SELFTEST: PASS\n");
    sys_exit();
}
