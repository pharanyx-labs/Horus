#include "syscall.h"

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

static int streq(const char *a, const char *b) {
    int i = 0;
    for (; a[i] && b[i]; i++) if (a[i] != b[i]) return 0;
    return a[i] == b[i];
}

/*
 * Spawned by the process-control self-test with a known argument vector
 * (["argtest", "alpha", "bravo"]) to exercise full argv passing. It reads its
 * arguments back with sys_get_argv() and checks the count, each string, and the
 * NULL terminator. Reaching "argv OK" proves the kernel marshalled the caller's
 * argv onto this task's stack correctly; any mismatch prints a FAIL marker.
 */
void _start(void) {
    char **argv = 0;
    int argc = sys_get_argv(&argv);

    if (argc != 3 || !argv)          { report("PROC_SELFTEST: FAIL argv-count\n");    sys_exit(); }
    if (!streq(argv[0], "argtest"))  { report("PROC_SELFTEST: FAIL argv0\n");         sys_exit(); }
    if (!streq(argv[1], "alpha"))    { report("PROC_SELFTEST: FAIL argv1\n");         sys_exit(); }
    if (!streq(argv[2], "bravo"))    { report("PROC_SELFTEST: FAIL argv2\n");         sys_exit(); }
    if (argv[3] != 0)                { report("PROC_SELFTEST: FAIL argv-nullterm\n"); sys_exit(); }

    report("PROC_SELFTEST: argv OK\n");
    sys_exit();
}
