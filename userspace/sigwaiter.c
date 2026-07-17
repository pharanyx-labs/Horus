#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/*
 * Spawned by the process-control self-test to exercise async signal delivery to
 * a task blocked in SYS_WAIT. The driver hands us (via the spawn argument) the
 * task id of a forever-looping task, and holds our CAP_TCB from the spawn. We
 * register a handler, then block in sys_wait() on that immortal target — so the
 * ONLY way the wait can return is if a signal interrupts it. The driver signals
 * us: the wait must return SYS_ERR_INTR and the handler must then run. Reaching
 * the "sigwait OK" line proves the blocked wait was interrupted and the queued
 * signal delivered (old behaviour: the signal would never land and we'd hang).
 */
static volatile int got = 0;

static void handler(void) {
    got = 1;
    sys_sigreturn();
}

static void spin(int n) { for (volatile int d = 0; d < n; d++) { } }

void _start(void) {
    uint32_t target = sys_spawn_arg();                /* immortal task id to wait on */
    sys_signal((uintptr_t)&handler);    /* register a handler */
    report("sigwaiter: waiting\n");

    int rc = sys_wait((int)target);                   /* blocks; a signal must interrupt this */
    for (int i = 0; i < 4000 && !got; i++) spin(20000);   /* let the queued signal deliver */

    if (rc != SYS_ERR_INTR) { report("PROC_SELFTEST: FAIL sigwait-notintr\n"); sys_exit(); }
    if (!got)               { report("PROC_SELFTEST: FAIL sigwait-nodeliver\n"); sys_exit(); }
    report("PROC_SELFTEST: sigwait OK\n");
    sys_exit();
}
