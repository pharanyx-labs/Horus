#include "syscall.h"

/*
 * Ring-3 init process (PID-1 role).
 *
 * The kernel launches this as the first userspace task and endows it with only
 * the capabilities it needs: CAP_AUDIT (slot 7) to observe its children, and
 * CAP_CONSOLE (slot 8) + CAP_ENCRYPTED_STORAGE (slot 9) to hand to the shell.
 * init then spawns the shell, delegates it those two caps via SYS_CAP_GRANT
 * (authorised because init holds the shell's CAP_TCB from the spawn), and
 * supervises it with a blocking SYS_WAIT: init sleeps until the shell exits or
 * faults, then relaunches it. Blocking (rather than polling) means init consumes
 * no CPU while the shell runs — the shell is the only runnable task. init itself
 * never exits.
 *
 * (fs_server remains launched on demand from the shell, as before; init taking
 * over the servers is a follow-up that needs the server's cap provisioning
 * expressed as delegations.)
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Preemptible ring-3 spin, used only on the fatal fallback paths below (when
 * there is no shell to wait on). */
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

    /* Launch the shell, then block in SYS_WAIT until it exits or faults, and
     * relaunch. SYS_WAIT suspends init on the preemptive block/switch path, so
     * while the shell runs init is off the run queue entirely (no polling). */
    for (;;) {
        int sh = launch_shell();
        if (sh < 0) { report("init: FATAL could not launch shell\n"); for (;;) settle(); }

        sys_wait(sh);   /* returns once the shell task is dead */
        report("init: shell exited, relaunching\n");
    }
}
