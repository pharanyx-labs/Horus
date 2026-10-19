#include "syscall.h"

/*
 * The counter of make smoke-sched-budget (SCHED_BUDGET_SELFTEST only;
 * docs/design/scheduler.md 3.1, step 4a). schedtest grants it a frame, an
 * untyped region and a copy of a context, binds it to that context and resumes
 * it. It increments word 0 for ever, so schedtest can see from outside whether
 * it runs. The words of the frame:
 *
 *   0  the counter, incremented on every loop
 *   1  schedtest's signal: 1 = go unbound and fork, 3 = stop forking
 *   2  incremented by every child, for ever
 *   4  forks made while unbound
 *   5  a setup refusal, if the unbinding could not be arranged
 *   6  the first refused fork's answer
 *
 * On signal 1 it carves a context of its own, binds ITSELF to it, revokes it
 * (it holds the only name, so the context is destroyed and this task unbound),
 * and forks in a loop. Nothing in between can take the CPU from it, so the forks
 * are made by a task that is running and bound to nothing, deterministically:
 * the moment a revoke lands before its CPU next chooses. A child of an unbound
 * task must be unbound too (create_task), so no child may ever run, and word 2
 * must stay 0. SC_UNBOUND_CREATOR_GETS_ROOT=1 is the defect: the children get
 * the BSP's root and count.
 */
#define SLOT_FRAME  20
#define SLOT_CTX    21   /* a copy of the context schedtest bound it to */
#define SLOT_MINE   22
#define VA          0x0000000030000000ULL

void _start(void) {
    if (sys_map_frame(SLOT_FRAME, VA, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) {
        sys_write(1, "SCHEDTEST: FAIL counter-map\n", 28);
        sys_exit();
    }
    volatile unsigned long *w = (volatile unsigned long *)VA;
    for (;;) {
        w[0]++;
        if (w[1] != 1) continue;
        w[1] = 2;
        int rc = sys_sched_split(SLOT_CTX, CAPSLOT_UNTYPED, SLOT_MINE, 10000, 100000, 0);
        if (rc == 0) rc = sys_sched_bind(sys_getpid(), SLOT_MINE);
        if (rc == 0) rc = sys_cap_revoke(SLOT_MINE);
        if (rc != 0) { w[5] = (unsigned long)(long)rc; continue; }
        /* fork refuses an address space that maps a kernel object's page
         * (S40), so the frame is unmapped around each fork and mapped again
         * after; the child, which inherits the capability and not the mapping,
         * maps it for itself. */
        for (;;) {
            if (w[1] != 2) break;
            (void)sys_unmap_frame(SLOT_FRAME, VA);
            int f = sys_fork();
            (void)sys_map_frame(SLOT_FRAME, VA, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
            if (f == 0) {
                volatile unsigned long *c = (volatile unsigned long *)VA;
                for (;;) c[2]++;
            }
            if (f > 0) w[4]++;
            else if (w[6] == 0) w[6] = (unsigned long)(long)f;   /* the first refusal */
        }
    }
}
