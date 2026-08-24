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

    /* (c) A CAP_AUDIT does not buy INTROSPECTION -- roadmap 3.6's second half,
     *     2026-08-24. Until then SYS_GET_TASK_INFO accepted CAP_USER or
     *     CAP_AUDIT as well as CAP_DEBUG, so "do you hold the audit log's keys"
     *     was an answer to "may I see the process list". This task is the one
     *     place that can witness the narrowing: it holds a real, live CAP_AUDIT
     *     -- proved by (a) immediately above, which is why the order matters --
     *     and no CAP_DEBUG at all.
     *
     *     Reading our OWN info must still work: a blanket refusal would satisfy
     *     the cross-task half and is not what was asked for. */
    {
        struct task_info ti;
        int self = sys_getpid();
        if (sys_get_task_info(self, &ti) != 0) {
            report("PROC_SELFTEST: FAIL grant-selfinfo\n"); sys_exit();
        }
        for (int t = 0; t < 16; t++) {
            if (t == self) continue;
            if (sys_get_task_info(t, &ti) == 0) {
                report("PROC_SELFTEST: FAIL grant-audit-bought-introspection\n");
                sys_exit();
            }
        }
    }

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
