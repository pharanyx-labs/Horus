#include "syscall.h"

/*
 * Ring-3 init process (PID-1 role).
 *
 * The kernel launches init as the first userspace task and endows it, from the
 * primordial root cnode, with exactly the capabilities it must wield or delegate
 * onward: CAP_AUDIT (slot 7), CAP_CONSOLE (slot 8) and CAP_ENCRYPTED_STORAGE
 * (slot 9); plus a CAP_USER admin cap (slot 6) and two CAP_ENDPOINT caps (slots
 * 10/11) it hands to the servers it launches.
 *
 * init is the delegation root for the system's servers. At boot it:
 *   1. launches the userspace fs_server and provisions it entirely by delegation
 *      (SYS_CAP_GRANT of the IPC gate, listen endpoint, CAP_USER for
 *      registration, and the object-store cap) — no direct kernel cap installs;
 *   2. launches the shell, delegates it CAP_CONSOLE + CAP_ENCRYPTED_STORAGE, and
 *      supervises it with a blocking SYS_WAIT, relaunching it if it exits/faults.
 *
 * Blocking (rather than polling) on the shell means init consumes no CPU while
 * the session runs. init itself never exits.
 *
 * Under INIT_FS_SELFTEST the shell step is replaced by an automated client that
 * drives the delegated server end-to-end (see _start / `make smoke-init-fs`).
 */

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* Preemptible ring-3 spin, used only on the fatal fallback paths below (when
 * there is no shell to wait on). */
static void settle(void) { for (volatile int d = 0; d < 40000; d++) { } }

/* Slots init holds its delegable caps in, matching the kernel endowment in
 * spawn_initial_userspace_init(). */
#define CAP_SLOT_USER       6    /* CAP_USER admin cap (SYS_REGISTER_FS_SERVER gate) */
#define CAP_SLOT_CONSOLE    8    /* CAP_CONSOLE                                      */
#define CAP_SLOT_STORAGE    9    /* CAP_ENCRYPTED_STORAGE (also the object-store cap)*/
#define INIT_EP_GATE_SLOT   10   /* CAP_ENDPOINT, object 0         (coarse IPC gate) */
#define INIT_EP_LISTEN_SLOT 11   /* CAP_ENDPOINT, object FS_EP_REQ (server listen)   */
#define CAP_SLOT_IO_DEVICE  12   /* CAP_IO_DEVICE (console_server hardware authority) */

/* Launch the userspace fs_server and provision it entirely by delegation: init
 * grants the server all four capabilities it needs — the coarse IPC gate (slot
 * 3), its listen endpoint (slot 4, so SYS_REGISTER_FS_SERVER binds it), the
 * CAP_USER that gates registration (slot 6), and the object-store cap (slot 7) —
 * with no direct kernel cap installs. The grants are authorised because init is
 * uid 0 and holds the server's CAP_TCB from the spawn. Returns the server's task
 * id, or a negative value on a spawn/grant failure. */
static int launch_fs_server(void) {
    int srv = sys_spawn_named("fs_server");
    if (srv <= 0) return -1;
    if (sys_cap_grant(srv, INIT_EP_GATE_SLOT,   3) != 0) return -2;  /* IPC gate            */
    if (sys_cap_grant(srv, INIT_EP_LISTEN_SLOT, 4) != 0) return -3;  /* listen endpoint     */
    if (sys_cap_grant(srv, CAP_SLOT_USER,       6) != 0) return -4;  /* SYS_REGISTER_FS gate */
    if (sys_cap_grant(srv, CAP_SLOT_STORAGE,    7) != 0) return -5;  /* object-store gate   */
    return srv;
}

/* Launch the userspace console_server and delegate it exactly what it needs: the
 * coarse IPC gate (its slot 3, so it can recv requests / reply / notify) and the
 * CAP_IO_DEVICE hardware cap (its slot 10, gating SYS_MAP_PHYS / SYS_IOPORT_GRANT
 * so it can own the VGA framebuffer and the serial/VGA ports). It serves on the
 * well-known endpoint CON_EP_REQ, which a client reaches with its own default
 * endpoint cap — no per-client console grant is needed. Returns the server's task
 * id, or a negative value on failure. */
static int launch_console_server(void) {
    int csrv = sys_spawn_named("console_server");
    if (csrv <= 0) return -1;
    if (sys_cap_grant(csrv, INIT_EP_GATE_SLOT,  3)  != 0) return -2;  /* IPC gate -> slot 3   */
    if (sys_cap_grant(csrv, CAP_SLOT_IO_DEVICE, 10) != 0) return -3;  /* CAP_IO_DEVICE -> 10  */
    return csrv;
}

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
    /* Bring up the filesystem server first, so it is registered and serving by
     * the time the shell (or the test client) issues its first request. */
    int srv = launch_fs_server();
    if (srv < 0) report("init: WARNING fs_server provisioning failed\n");
    else         report("init: fs_server launched and provisioned\n");

#ifdef INIT_FS_SELFTEST
    /* Boot-time FS integration test: prove init brings up fs_server by delegation
     * alone and the delegated server serves a client end-to-end. The client's own
     * FS_SELFTEST: PASS marker (asserted by `make smoke-init-fs`) is the proof. */
    report("INIT_FS_SELFTEST: init launched fs_server by delegation; driving client\n");
    int cli = sys_spawn_named("fsclient");
    if (cli <= 0) { report("INIT_FS_SELFTEST: FAIL spawn-client\n"); for (;;) settle(); }
    if (sys_cap_grant(cli, INIT_EP_GATE_SLOT, 3) != 0) {
        report("INIT_FS_SELFTEST: FAIL grant-client\n"); for (;;) settle();
    }
    sys_wait(cli);   /* block until the client finishes driving the server */
    report("INIT_FS_SELFTEST: init supervised fs client to exit\n");
    for (;;) settle();
#else
    /* Wait until fs_server has finished startup provisioning (it copies the boot
     * modules into /bin, then fires a badge with SYS_NOTIFY). Blocking here — off
     * the run queue — gives fs_server the whole CPU for that block-by-block copy
     * into the encrypted store, instead of it being starved by the shell's
     * unpreemptible ring-0 console read once the shell exists. The badge is
     * accumulated if fs_server signalled first, so this never hangs; a sealed ATA
     * volume simply has nothing to provision yet and signals at once.
     *
     * Notifications are indexed by the notification slot NUMBER (a global badge
     * accumulator), not by an endpoint object, and both syscalls are gated on a
     * slot-3 capability — which every task holds as its default endpoint. So the
     * rendezvous uses slot 3 on both sides (fs_server's FS_GATE_SLOT), the same
     * convention notifytest uses. */
    {
        uint32_t ready_badge = 0;
        sys_wait_notify(3, &ready_badge);
        report("init: fs_server ready\n");
    }

    /* Bring up the ring-3 console server before the shell, so the shell's output
     * goes through it (the shell falls back to the in-kernel console if the server
     * is somehow unreachable, so a console_server failure can never silence login).
     * It owns the console hardware via the delegated CAP_IO_DEVICE. */
    if (launch_console_server() < 0)
        report("init: WARNING console_server launch failed (shell output falls back to kernel console)\n");
    else
        report("init: console_server launched\n");

    report("init: starting, launching shell\n");

    /* Launch the shell, then block in SYS_WAIT until it exits or faults, and
     * relaunch. SYS_WAIT suspends init on the preemptive block/switch path, so
     * while the shell runs init is off the run queue entirely (no polling). The
     * fs_server launched above keeps serving alongside the shell. */
    for (;;) {
        int sh = launch_shell();
        if (sh < 0) { report("init: FATAL could not launch shell\n"); for (;;) settle(); }

        sys_wait(sh);   /* returns once the shell task is dead */
        report("init: shell exited, relaunching\n");
    }
#endif
}
