#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Child spawned by the process-control self-test (proctest) to exercise
 * SYS_EXEC_NAMED *with arguments*. It replaces its own image, in place, with
 * "argtest" and a full argv: same task id, same cspace. On success the exec
 * never returns — control resumes at argtest's entry, which reads the argv back
 * (proving exec marshalled it), prints "argv OK" and exits, so the task dies
 * under the same pid the driver is watching. Reaching the line after the exec
 * means exec returned, which is a failure by contract. */
void _start(void) {
    char *av[3];
    av[0] = "argtest"; av[1] = "alpha"; av[2] = "bravo";
    sys_exec_named_argv("argtest", 3, av);
    report("PROC_SELFTEST: FAIL exec-returned\n");
    sys_exit();
}
