#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/*
 * Spawned by the process-control self-test to exercise SYS_SIGNAL (async
 * task-to-task signalling) *and* SYS_SIGMASK (per-signal blocking). The driver
 * holds this task's CAP_TCB (from the spawn) and sends it SIG_USR1.
 *
 * Sequence: register a handler, then BLOCK SIG_USR1 and spin — the driver's
 * signal arrives during this window and must stay pending (masked), so the
 * handler must NOT run yet. After the masked window we assert it did not fire,
 * UNBLOCK SIG_USR1 (which makes the queued signal deliverable), and confirm the
 * handler then runs. Reaching the pass marker therefore proves masking held the
 * signal and unmasking delivered it. The handler returns via sys_sigreturn so
 * the main flow observes the flag.
 *
 * It also registers an alternate signal stack (SYS_SIGALTSTACK) and the handler
 * asserts it is running on it (its %esp lies inside sig_altstk) — end-to-end
 * proof that delivery redirects onto the altstack, not just that registration
 * succeeds.
 */
static volatile int got = 0;
static volatile int on_alt = 0;

/* Alternate signal stack the handler must run on. */
static char sig_altstk[4096];

static void handler(void) {
    uintptr_t sp;
    __asm__ volatile ("mov %%rsp, %0" : "=r"(sp));
    on_alt = (sp >= (uintptr_t)sig_altstk &&
              sp <  (uintptr_t)sig_altstk + sizeof(sig_altstk));
    got = 1;
    sys_sigreturn();   /* resume the interrupted spin loop */
}

static void spin(int n) { for (volatile int d = 0; d < n; d++) { } }

void _start(void) {
    sys_signal((unsigned)(unsigned long)&handler);   /* register (SYS_SIGACTION) */
    sys_sigaltstack(sig_altstk, sizeof(sig_altstk));  /* handler runs on this stack */
    sys_sigmask(SIG_BLOCK, 1u << SIG_USR1);           /* block SIG_USR1 */
    report("sigtarget: masked\n");

    /* Masked window: the driver sends SIG_USR1 here; it must stay pending. */
    for (int i = 0; i < 8000; i++) spin(20000);
    if (got) { report("PROC_SELFTEST: FAIL sig-masked-delivered\n"); sys_exit(); }

    sys_sigmask(SIG_UNBLOCK, 1u << SIG_USR1);         /* unblock -> queued signal deliverable */
    for (int i = 0; i < 12000 && !got; i++) spin(20000);
    if (!got)    { report("PROC_SELFTEST: FAIL sig-unmask-nodeliver\n"); sys_exit(); }
    if (!on_alt) { report("PROC_SELFTEST: FAIL sig-not-on-altstack\n"); sys_exit(); }

    report("PROC_SELFTEST: PASS exit+kill+spawn+exec+grant+image+altstack+signal\n");
    sys_exit();
}
