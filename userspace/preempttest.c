#include "syscall.h"

/*
 * Preemption self-test payload (PREEMPT_SELFTEST builds only).
 *
 * Two independent copies of this program are spawned. Each loops forever doing
 * a pure-computation busy spin -- with NO system call that yields the CPU --
 * and then records a trace sample via SYS_PREEMPT_TRACE. Because nothing here
 * voluntarily gives up the CPU, the only way control can move from one copy to
 * the other is the timer preempting it in ring 3. The kernel-side trace handler
 * watches for repeated alternation between the two task ids and prints
 * "PREEMPT_SELFTEST: PASS" once it sees genuine back-and-forth time-slicing.
 *
 * Without preemption the first copy would spin here forever and the second
 * would never run, so the marker would never appear (the smoke harness then
 * fails on timeout).
 */
void _start(void) {
    for (;;) {
        /* Pure compute; volatile so it is not optimized away and performs no
         * syscall (hence no cooperative yield point). Sized so the task spends
         * most of each quantum in ring 3, where the timer can preempt it. */
        volatile unsigned int x = 0;
        for (unsigned int i = 0; i < 300000u; i++) {
            x += i;
        }
        (void)x;
        syscall(SYS_PREEMPT_TRACE, 0, 0, 0);
    }
}
