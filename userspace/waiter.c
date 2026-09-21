#include "syscall.h"

/*
 * Spawned by the process-control self-test (PROC_SELFTEST only) to leave a
 * completed wait behind in its task slot, for HORUS-20260920-02
 * (docs/LIMITATIONS.md 1.17).
 *
 * It waits on the tid it was spawned with (a suspended "hello" the driver
 * resumes), confirms the wait produced a real record, and exits. Its slot then
 * holds that record in wait_exit_info, which is the state a later task reusing
 * the slot must not inherit. The confirmation is what keeps the test honest: if
 * the wait left nothing behind, a probe finding nothing would prove nothing.
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    int target = (int)sys_spawn_arg();
    if (target <= 0 || sys_wait(target) != 0) {
        report("PROC_SELFTEST: FAIL waiter-wait\n");
        sys_exit();
    }
    struct task_exit_info ei;
    for (unsigned z = 0; z < sizeof(ei); z++) ((char *)&ei)[z] = 0;
    if (sys_task_exit_info(&ei) != 0 || ei.reason != TASK_EXIT_NORMAL || ei.tid != target) {
        report("PROC_SELFTEST: FAIL waiter-record\n");
        sys_exit();
    }
    sys_exit();
}
