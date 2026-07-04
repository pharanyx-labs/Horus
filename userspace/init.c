#include "syscall.h"

/*
 * Ring-3 init process (PID-1 role).
 *
 * The kernel launches this as the first userspace task and endows it with only
 * the capabilities it needs: CAP_AUDIT (slot 7) to observe its children, and
 * CAP_CONSOLE (slot 8) + CAP_ENCRYPTED_STORAGE (slot 9) to hand to the shell.
 * init then spawns the shell, delegates it those two caps via SYS_CAP_GRANT
 * (authorised because init holds the shell's CAP_TCB from the spawn), and
 * supervises it: if the shell ever exits or faults, init relaunches it. init
 * itself never exits.
 *
 * (fs_server remains launched on demand from the shell, as before; init taking
 * over the servers is a follow-up that needs the server's cap provisioning
 * expressed as delegations.)
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Preemptible ring-3 spin so the timer keeps running while init waits. */
static void settle(void) { for (volatile int d = 0; d < 40000; d++) { } }

/* Slots init holds the delegable caps in, matching the kernel endowment. */
#define CAP_SLOT_CONSOLE 8
#define CAP_SLOT_STORAGE 9

/* Spawn the shell and delegate it the console + storage capabilities. Returns
 * the shell's task id, or a negative value on failure. */
static int launch_shell(void) {
    int sh = sys_spawn_named("shell");
    if (sh <= 0) return -1;
    /* Delegate least privilege into the same slots the shell expects (8/9).
     * Done immediately after the spawn, before the shell needs them for login;
     * init holds a CAP_TCB to the shell from the spawn, so the grants pass. */
    if (sys_cap_grant(sh, CAP_SLOT_CONSOLE, CAP_SLOT_CONSOLE) != 0) return -2;
    if (sys_cap_grant(sh, CAP_SLOT_STORAGE, CAP_SLOT_STORAGE) != 0) return -3;
    return sh;
}

void _start(void) {
    report("init: starting, launching shell\n");

    int sh = launch_shell();
    if (sh < 0) { report("init: FATAL could not launch shell\n"); for (;;) settle(); }

    /* Supervise the shell by polling its liveness (SYS_GET_TASK_INFO, gated on
     * init's CAP_AUDIT). A poll loop rather than a blocking wait keeps init on
     * the proven preemptive path. On exit/fault, relaunch. */
    struct task_info ti;
    for (;;) {
        int alive = (sys_get_task_info(sh, &ti) == 0 && ti.state != 0);
        if (!alive) {
            report("init: shell exited, relaunching\n");
            sh = launch_shell();
            if (sh < 0) { report("init: FATAL relaunch failed\n"); for (;;) settle(); }
        }
        settle();
    }
}
