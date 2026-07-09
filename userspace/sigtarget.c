#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/*
 * Spawned by the process-control self-test to exercise SYS_SIGNAL (async
 * task-to-task signalling). It registers a signal handler and then spins. The
 * driver holds this task's CAP_TCB (from the spawn) and sends it SIG_USR1; the
 * kernel redirects this task into `handler` on its next return to ring 3. The
 * handler announces the full pass chain — which is only reachable if the signal
 * was actually delivered to the handler (an unhandled signal would instead
 * terminate the task silently) — then exits.
 */
static void handler(void) {
    report("PROC_SELFTEST: PASS exit+kill+spawn+exec+grant+signal\n");
    sys_exit();
}

void _start(void) {
    sys_signal((unsigned)(unsigned long)&handler);   /* register (SYS_SIGACTION) */
    for (;;) { for (volatile int d = 0; d < 20000; d++) { } }  /* await the signal */
}
