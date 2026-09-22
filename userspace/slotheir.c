#include "syscall.h"

/*
 * Spawned by the process-control self-test (PROC_SELFTEST only) to put a task
 * into a freed slot that the DRIVER holds no fresh authority over, for
 * HORUS-20260921-02 (docs/LIMITATIONS.md 1.19).
 *
 * The driver spawns a child, keeps the CAP_TCB the spawn gave it, and lets the
 * child die. It then resumes this task, which spawns "hello" into the lowest
 * free slot -- the dead child's -- and exits WITHOUT resuming it, so the new
 * occupant stays alive (suspended) for as long as the driver needs to probe it.
 * The CAP_TCB for the new occupant went to this task, not the driver; the only
 * TCB the driver holds for that slot number is the stale one naming the dead
 * child. What that stale capability may still do is the whole question.
 *
 * It needs a CAP_UNTYPED to spawn at all, which the driver grants it before
 * resuming it. A failure is reported by name; the driver also checks the slot.
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

void _start(void) {
    int heir = sys_spawn_named("hello");   /* left suspended on purpose */
    if (heir <= 0) report("PROC_SELFTEST: FAIL slotheir-spawn\n");
    sys_exit();
}
