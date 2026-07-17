#include "syscall.h"

/*
 * TSD self-test payload (TSD_SELFTEST builds only).
 *
 * With CR4.TSD engaged, a ring-3 RDTSC raises #GP — the kernel delivers that as
 * a fault signal (see interrupt_handler64's ring-3 trap path). This payload
 * registers a fault handler, then executes RDTSC: if TSD is in effect the
 * handler runs and prints the PASS marker; if RDTSC instead returned a
 * timestamp, control falls through to the FAIL marker. The smoke harness exits
 * on whichever marker appears first.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

/* Entered at ring 3 on the fault (the RDTSC #GP). RDTSC is not restartable here
 * (re-running it would fault again), so we report and park rather than
 * sys_sigreturn — the same pattern the signal self-test uses for its fault. */
static void handler(void) {
    wr("TSD_SELFTEST: PASS\n");
    for (;;) { sys_yield(); }
}

void _start(void) {
    if (sys_signal((uintptr_t)&handler) != 0) {
        wr("TSD_SELFTEST: FAIL register\n");
        for (;;) { sys_yield(); }
    }
    wr("TSD_SELFTEST: begin\n");

    /* volatile + output operands keep the compiler from eliding the RDTSC. */
    unsigned lo = 0, hi = 0;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    (void)lo; (void)hi;

    /* Reached only if RDTSC did NOT fault — TSD is not blocking ring 3. */
    wr("TSD_SELFTEST: FAIL not-blocked\n");
    for (;;) { sys_yield(); }
}
