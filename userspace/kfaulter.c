#include "syscall.h"

/*
 * Spawned by the process-control self-test to make the KERNEL fault on this
 * task's behalf (HORUS-20260920-01, docs/LIMITATIONS.md 1.16). Embedded in
 * PROC_SELFTEST builds; the kernel hook it relies on exists only under
 * KFAULT_RECORD_SELFTEST (`make smoke-kfault-record`).
 *
 * It yields with an address in rbx; the KFAULT_RECORD_SELFTEST hook in h_yield reads
 * address at CPL 0, so the #PF is a supervisor one with this task to blame, and
 * the kernel kills this task for it. argv[1] picks the address:
 *
 *   "user"    0x94, G-8's own address: in the user half, so the exit record
 *             may name it, but the rip is kernel text and must be recorded as 0
 *   "kernel"  an unmapped kernel-half address: neither the rip nor the address
 *             may reach the record
 *
 * Reaching the line after the yield means the kernel did not fault, which is a
 * failure of the test, not of the property; it is reported as such.
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

static int streq(const char *a, const char *b) {
    int i = 0;
    for (; a[i] && b[i]; i++) if (a[i] != b[i]) return 0;
    return a[i] == b[i];
}

void _start(void) {
    char **argv = 0;
    int argc = sys_get_argv(&argv);
    uint64_t addr = 0;
    if (argc == 2 && argv && streq(argv[1], "user"))   addr = 0x94;
    if (argc == 2 && argv && streq(argv[1], "kernel")) addr = 0xffff900000000000ULL;
    if (!addr) { report("PROC_SELFTEST: FAIL kfaulter-argv\n"); sys_exit(); }

    syscall(SYS_YIELD, addr, 0, 0);

    report("PROC_SELFTEST: FAIL kfaulter-no-fault\n");
    sys_exit();
}
