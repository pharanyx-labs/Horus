#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Child spawned by the process-control self-test (proctest) to exercise
 * SYS_EXEC_NAMED. It replaces its own image, in place, with "hello": same task
 * id, same cspace. On success sys_exec_named never returns — control resumes at
 * hello's entry, hello runs and exits, and the task dies under the same pid the
 * driver is watching. Reaching the line after the exec means exec returned,
 * which is a failure by contract, so we shout about it and exit. */
void _start(void) {
    sys_exec_named("hello");
    report("PROC_SELFTEST: FAIL exec-returned\n");
    sys_exit();
}
