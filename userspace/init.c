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

#ifdef INIT_FS_SELFTEST
/* Free slots the kernel endows init with under INIT_FS_SELFTEST (see
 * spawn_initial_userspace_init): two endpoint caps + an all-rights cap that init
 * delegates to the fs_server it launches. */
#define CAP_SLOT_USER       6    /* CAP_USER admin cap (SYS_REGISTER_FS_SERVER gate) */
#define INIT_EP_GATE_SLOT   10   /* CAP_ENDPOINT, object 0        (coarse IPC gate) */
#define INIT_EP_LISTEN_SLOT 11   /* CAP_ENDPOINT, object FS_EP_REQ (server listen)  */
#define INIT_BLOCKDEV_SLOT  12   /* all-rights cap (object-store gate)              */

/* Launch the userspace fs_server and provision it entirely by delegation, then
 * launch the client that drives it and block until the client is done. No direct
 * kernel cap installs: init hands the server all four of its capabilities with
 * SYS_CAP_GRANT (IPC gate, listen endpoint, CAP_USER for registration, and the
 * object-store cap), exactly as a real service manager would. Returns 0 on
 * success, negative on a spawn/grant failure. */
static int provision_and_launch_fs(void) {
    int srv = sys_spawn_named("fs_server");
    if (srv <= 0) return -1;
    if (sys_cap_grant(srv, INIT_EP_GATE_SLOT,   3) != 0) return -2;  /* IPC gate           */
    if (sys_cap_grant(srv, INIT_EP_LISTEN_SLOT, 4) != 0) return -3;  /* listen endpoint    */
    if (sys_cap_grant(srv, CAP_SLOT_USER,       6) != 0) return -4;  /* SYS_REGISTER_FS gate*/
    if (sys_cap_grant(srv, INIT_BLOCKDEV_SLOT,  7) != 0) return -5;  /* object-store gate  */

    int cli = sys_spawn_named("fsclient");
    if (cli <= 0) return -5;
    if (sys_cap_grant(cli, INIT_EP_GATE_SLOT, 3) != 0) return -6;    /* IPC gate          */

    /* Block until the client finishes driving the server (it prints
     * FS_SELFTEST: PASS/FAIL and exits). SYS_WAIT takes init off the run queue so
     * the server + client are time-sliced by the preemptive scheduler. */
    sys_wait(cli);
    return 0;
}
#endif

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
#ifdef INIT_FS_SELFTEST
    /* Boot-time FS integration test: prove init can bring up the userspace
     * fs_server by delegation alone and that the delegated server still serves a
     * client end-to-end. The client's own FS_SELFTEST: PASS marker (asserted by
     * `make smoke-init-fs`) is the proof; init's lines below trace the launch. */
    report("INIT_FS_SELFTEST: init launching + provisioning fs_server by delegation\n");
    if (provision_and_launch_fs() != 0)
        report("INIT_FS_SELFTEST: FAIL init could not provision fs_server\n");
    else
        report("INIT_FS_SELFTEST: init supervised fs client to exit\n");
    for (;;) settle();
#else
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
#endif
}
