#include "syscall.h"

/*
 * IRQ_SELFTEST driver. The kernel (irq_selftest) spawns this program with a
 * CAP_IO_DEVICE cap in slot 10 (the SYS_IRQ_REGISTER gate) and a slot-3 endpoint
 * cap (the SYS_WAIT_NOTIFY gate).
 *
 * It proves the IRQ -> userspace notification bridge end-to-end: register the
 * TIMER IRQ (IRQ0, which self-triggers ~100x/s, so no key injection is needed --
 * this is exactly the periodic serial re-poll wake the console server will use),
 * then wait for a real hardware timer interrupt to deliver the exact badge we
 * registered. Prints IRQ_SELFTEST: PASS.
 *
 * Note on the wait loop: this probe is the only runnable task, so when it blocks
 * in SYS_WAIT_NOTIFY the kernel has nothing else to switch to and resumes it
 * immediately (the "retry from ring 3" fallback in ipc_block_switch) rather than
 * deadlock the CPU. Meanwhile the timer IRQ keeps firing and the bridge
 * accumulates the badge on the notification slot, so we retry the wait until the
 * badge arrives. In a real multi-task system (the console server alongside init /
 * fs_server / the shell) the first wait blocks properly and the IRQ wakes it.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

#define NOTIF_SLOT 0
#define IRQ_TIMER  0
#define BADGE      0x0000CAFEu

void _start(void) {
    wr("IRQ_SELFTEST: begin\n");

    if (sys_irq_register(IRQ_TIMER, NOTIF_SLOT, BADGE) != 0) {
        wr("IRQ_SELFTEST: FAIL register\n"); sys_exit();
    }

    /* Wait for a timer interrupt to route a badge to us. Bounded so a broken
     * bridge (no notification ever arrives) fails loudly instead of hanging. */
    uint32_t badge = 0;
    for (long i = 0; i < 200000000L && badge == 0; i++) {
        int rc = sys_wait_notify(NOTIF_SLOT, &badge);
        if (rc != 0) { wr("IRQ_SELFTEST: FAIL rc\n"); sys_exit(); }
    }

    if (badge != BADGE) { wr("IRQ_SELFTEST: FAIL badge\n"); sys_exit(); }

    wr("IRQ_SELFTEST: PASS\n");
    sys_exit();
}
