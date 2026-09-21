#include "syscall.h"

/*
 * Spawned by the process-control self-test (PROC_SELFTEST only), into the slot a
 * "waiter" just vacated, for HORUS-20260920-02 (docs/LIMITATIONS.md 1.17).
 *
 * It asks for its wait record before it has ever waited. syscall.h promises
 * TASK_EXIT_NONE then, and create_task clears the record, so every byte must be
 * zero: a stale record from the slot's previous occupant would name the task that
 * occupant supervised, and that task's name and faulting rip.
 *
 * The verdict goes back to the driver through HOW this task dies, since the
 * driver cannot read its output: a clean record exits normally, a stale one
 * executes ud2 and dies of a fault. The FAIL line is for the human reading the
 * log, and fails the gate on its own too.
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    struct task_exit_info ei;
    /* Poison first, so a syscall that wrote nothing cannot pass as all-zero. */
    for (unsigned z = 0; z < sizeof(ei); z++) ((unsigned char *)&ei)[z] = 0xA5;
    if (sys_task_exit_info(&ei) != 0) {
        report("PROC_SELFTEST: FAIL exitprobe-rc\n");
        __asm__ volatile ("ud2");
    }
    for (unsigned z = 0; z < sizeof(ei); z++) {
        if (((unsigned char *)&ei)[z] != 0) {
            report("PROC_SELFTEST: FAIL exitprobe-stale-record\n");
            __asm__ volatile ("ud2");
        }
    }
    sys_exit();
}
