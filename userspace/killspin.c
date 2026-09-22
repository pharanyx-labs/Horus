#include "syscall.h"

/*
 * Spawned by the process-control self-test (PROC_SELFTEST only) for
 * HORUS-20260921-04 (docs/LIMITATIONS.md 1.21): a task killed while it runs must
 * stop, and must stop touching memory it shares with live tasks.
 *
 * The driver hands it a CAP_FRAME in KILLSPIN_SLOT_FRAME and resumes it. It maps
 * that frame and increments the first word forever, with no system call in the
 * loop, so the only way the kernel can take the CPU back is an interrupt. The
 * driver watches the counter rise (so it is running), kills it, and then
 * requires the counter to stop.
 */
#define KILLSPIN_SLOT_FRAME 20
#define KILLSPIN_VA         0x0000000030000000ULL

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    if (sys_map_frame(KILLSPIN_SLOT_FRAME, KILLSPIN_VA, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) {
        report("PROC_SELFTEST: FAIL killspin-map\n");
        sys_exit();
    }
    volatile unsigned long *ctr = (volatile unsigned long *)KILLSPIN_VA;
    for (;;) (*ctr)++;
}
