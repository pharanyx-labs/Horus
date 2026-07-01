#include "syscall.h"

/*
 * Signal self-test payload (SIGNAL_SELFTEST builds only).
 *
 * Registers a fault handler, then deliberately dereferences a null pointer.
 * Without signal handling this fault is fatal — the kernel kills the task.
 * With it, the kernel redirects the task into the handler at ring 3, which
 * prints the PASS marker. The smoke harness exits on that marker.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

/* Entered at ring 3 on the fault (ebx = signal number, ecx = fault address).
 * The null write is unrecoverable, so we do NOT sys_sigreturn (that would
 * re-run the faulting instruction and fault again) — we just report and park. */
static void handler(void) {
    wr("SIGNAL_SELFTEST: PASS\n");
    for (;;) { sys_yield(); }
}

void _start(void) {
    if (sys_signal((unsigned)(unsigned long)&handler) != 0) {
        wr("SIGNAL_SELFTEST: FAIL register\n");
        for (;;) { sys_yield(); }
    }
    wr("SIGNAL_SELFTEST: begin\n");

    *(volatile int *)0 = 1;   /* null write -> page fault -> handler runs */

    /* Reached only if the signal was NOT delivered (task would have died). */
    wr("SIGNAL_SELFTEST: FAIL not-delivered\n");
    for (;;) { sys_yield(); }
}
