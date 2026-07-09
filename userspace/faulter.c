#include "syscall.h"

/*
 * Spawned by the process-control self-test to exercise the fault-kill wake path.
 * It registers NO signal handler and immediately executes an illegal instruction
 * (#UD), taking an unhandled ring-3 fault. The kernel's default action tears the
 * task down — which must wake a task blocked in SYS_WAIT on it, exactly as a
 * clean SYS_EXIT would (see interrupt_handler64's fault path -> task_teardown).
 * This is what lets a blocking init relaunch the shell after a *fault*, not just
 * a clean exit.
 */
void _start(void) {
    __asm__ volatile ("ud2");   /* #UD -> SIG_ILL, no handler -> task terminated */
    for (;;) { }                /* unreachable */
}
