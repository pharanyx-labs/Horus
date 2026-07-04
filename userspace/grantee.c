#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Ring-3 spin (preemptible) so the timer runs and the driver's grant can land. */
static void settle(void) { for (volatile int d = 0; d < 20000; d++) { } }

/*
 * Spawned by the process-control self-test (proctest) to exercise SYS_CAP_GRANT.
 * The driver holds this task's CAP_TCB (from the spawn) and a CAP_AUDIT; it
 * delegates that CAP_AUDIT into our slot 7. We prove both directions:
 *
 *   (a) delegation works — SYS_READ_AUDIT is gated on a slot-7 CAP_AUDIT and is
 *       denied (SYS_ERR_PERM, negative) until the grant lands, then accepted.
 *   (b) fail-closed upward — we supervise nobody, so we hold no CAP_TCB to any
 *       other task; every grant we attempt must be denied. One success would be
 *       an authority leak.
 */
void _start(void) {
    struct audit_event evbuf[2];

    int used = 0;
    for (int i = 0; i < 8000; i++) {
        if (sys_read_audit(evbuf, 2) >= 0) { used = 1; break; }
        settle();
    }
    if (!used) { report("PROC_SELFTEST: FAIL grant-use\n"); sys_exit(); }

    int me = sys_getpid();
    int leaked = 0;
    for (int t = 1; t < 16; t++) {
        if (t == me) continue;
        if (sys_cap_grant(t, 0, 40) == 0) { leaked = 1; break; }
    }
    if (leaked) { report("PROC_SELFTEST: FAIL grant-authz\n"); sys_exit(); }

    report("PROC_SELFTEST: grant OK\n");
    sys_exit();
}
