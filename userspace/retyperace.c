#include "syscall.h"

/*
 * make smoke-retype-race (RETYPE_RACE_SELFTEST only). The retyper of the pair.
 *
 * A retyped object is made unnamed and named a moment later: untyped_retype
 * carves it, drops the untyped lock, and then installs the capability that names
 * it. Until 2026-10-17 a revoke on another CPU could run the object collector in
 * that gap, destroy the object and release its index, and the retype would then
 * install a capability naming the freed index -- one the next retype, by any
 * task, would reuse. This build holds that gap open on every retype this task
 * makes until a sweep has crossed it (RETYPE_WINDOW_WIDEN), while
 * `retyperevoker` on the other CPU revokes as fast as it can.
 *
 * Each round it retypes a frame, an endpoint and a notification and then USES
 * each one: a frame that was collected cannot be mapped, an endpoint cannot be
 * sent to, a notification cannot be signalled. Any of those is the defect.
 */
#define SLOT_UNTYPED  CAPSLOT_UNTYPED
#define SLOT_FRAME    40
#define SLOT_EP       41
#define SLOT_NOTIF    42
#define ROUNDS        12
#define VA_BASE       0x0000000030000000UL
#define SLOT_REV_TCB  29   /* CAP_TCB to retyperevoker; must match selftest.c */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    for (int r = 0; r < ROUNDS; r++) {
        if (sys_retype(SLOT_UNTYPED, KOBJ_FRAME, 1, SLOT_FRAME) != 1) {
            report("RETYPETEST: FAIL retype-frame\n"); sys_exit();
        }
        unsigned long va = VA_BASE + (unsigned long)r * 4096ul;
        if (sys_map_frame(SLOT_FRAME, va, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) {
            report("RETYPETEST: FAIL retyped-object-collected-before-named (frame)\n"); sys_exit();
        }
        *(volatile unsigned long *)va = 0x5245545950455245ul;
        if (*(volatile unsigned long *)va != 0x5245545950455245ul) {
            report("RETYPETEST: FAIL retyped-frame-lost-a-write\n"); sys_exit();
        }

        if (sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_EP) != 1) {
            report("RETYPETEST: FAIL retype-endpoint\n"); sys_exit();
        }
        if (sys_ipc_send(SLOT_EP, "r", 1) != 0) {
            report("RETYPETEST: FAIL retyped-object-collected-before-named (endpoint)\n"); sys_exit();
        }

        if (sys_retype(SLOT_UNTYPED, KOBJ_NOTIFICATION, 1, SLOT_NOTIF) != 1) {
            report("RETYPETEST: FAIL retype-notification\n"); sys_exit();
        }
        if (sys_notify(SLOT_NOTIF, 1) != 0) {
            report("RETYPETEST: FAIL retyped-object-collected-before-named (notification)\n"); sys_exit();
        }
    }
    /* A teardown sweep before the verdict: kill the revoker and wait for it, so
     * a sweep entered from teardown (the path GC_TEARDOWN_UNLOCKED reverts) has
     * run, and halted if it was going to, before PASS can be printed. */
    int rev = (int)sys_spawn_arg();
    if (sys_kill(rev) != 0 || sys_wait(rev) != 0) {
        report("RETYPETEST: FAIL could-not-end-the-revoker\n"); sys_exit();
    }
    report("RETYPETEST: PASS every retyped object survived its window\n");
    sys_exit();
}
