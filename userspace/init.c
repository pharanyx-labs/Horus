#include "syscall.h"
#include "console_proto.h"
#include "exit_reason.h"   /* format_exit_reason(): shared with proctest, which asserts its text */

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

/* init holds a WRITE-only console client capability in this slot; it delegates a
 * copy to the shell and to the fs self-test client. Declared up here because
 * report() below needs it. Kept in sync with the definition further down. */
#define INIT_CON_CLIENT_SLOT 14

static struct con_request  init_con_rq;   /* static: keep these off init's stack */
static struct con_response init_con_rp;

/* Write through console_server, the single writer. Returns 0 on success, -1 to
 * fall back to the kernel console. Bounded retries on the transient code only:
 * looping on a permanent refusal is the G-8 wedge (see the IPC retry contract). */
static int report_via_server(const char *s, unsigned len) {
    unsigned off = 0;
    while (off < len) {
        unsigned n = len - off;
        if (n > CON_IO_MAX) n = CON_IO_MAX;
        init_con_rq.magic = CON_PROTO_MAGIC;
        init_con_rq.op    = CON_OP_WRITE;
        init_con_rq.len   = n;
        for (unsigned i = 0; i < n; i++) init_con_rq.data[i] = (uint8_t)s[off + i];

        int rc = -1;
        for (int tries = 0; tries < 20000; tries++) {
            rc = sys_ipc_call(INIT_CON_CLIENT_SLOT, 0,
                              &init_con_rq, sizeof(init_con_rq), &init_con_rp);
            if (rc >= 0) break;
            if (!ipc_transient(rc)) return -1;   /* permanent: use the fallback */
            sys_yield();
        }
        if (rc < 0 || init_con_rp.magic != CON_PROTO_MAGIC || init_con_rp.rc != (int)n)
            return -1;
        off += n;
    }
    return 0;
}

/* Report a line, by whichever path can actually reach the console.
 *
 * This used to be sys_write(1, ...) alone, which lands in the kernel's print().
 * print() stops driving the hardware the moment console_server takes ownership
 * (terminal.c: `drive_hw = (console_owner_task == 0)`), so every init message
 * after the handover went to the klog and NOTHING reached the wire -- including
 * report_shell_exit(), the entire point of #130. Measured: a heartbeat printed
 * from init every ~second produced zero lines on serial after the handover, and
 * the handover itself truncated a line mid-word ("init: st[console_server]
 * ready"), which is two writers on one UART.
 *
 * So a shell that died was reported to a log nobody reads while the serial
 * capture showed only a fresh banner -- indistinguishable from the shell having
 * restarted for no reason, which is exactly the ambiguity G-8 has cost days to.
 *
 * The kernel path remains the fallback for before the handover and for a dead
 * server (task teardown releases ownership, so the kernel path re-opens). */
static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    if (sys_console_owned() && report_via_server(s, (unsigned)n) == 0) return;
    sys_write(1, s, (unsigned)n);
}

/* Report why the supervised shell ended, using the record SYS_TASK_EXIT_INFO
 * hands back after a completed sys_wait().
 *
 * This is the whole point of the change: `init` used to print only "shell
 * exited, relaunching", so a shell that was killed by a page fault mid-write
 * was indistinguishable in a serial capture from a kernel that had hung — and
 * G-8 signature A was filed as a livelock on exactly that ambiguity. The kernel
 * cannot print the reason itself once console_server owns the console (kernel
 * print() then only reaches the klog, and writing to the UART anyway is finding
 * #126), so init asks for it and prints it through console_server like any
 * other program.
 *
 * format_exit_reason() is shared with proctest, which asserts the exact text it
 * produces — so this line is known to render correctly before the failure it
 * exists to explain ever happens. */
static void report_shell_exit(void) {
    struct task_exit_info ei;
    for (unsigned z = 0; z < sizeof(ei); z++) ((char *)&ei)[z] = 0;

    if (sys_task_exit_info(&ei) != 0) {
        report("init: shell exited (exit reason unavailable), relaunching\n");
        return;
    }

    char why[192];
    format_exit_reason(why, &ei);

    char line[256];
    int p = 0;
    exr_append_str(line, &p, "init: shell exited: ");
    exr_append_str(line, &p, why);
    exr_append_str(line, &p, "; relaunching\n");
    report(line);
}

/* Preemptible ring-3 spin, used only on the fatal fallback paths below (when
 * there is no shell to wait on). */
static void settle(void) { for (volatile int d = 0; d < 40000; d++) { } }

/* Slots init holds its delegable caps in, matching the kernel endowment in
 * spawn_initial_userspace_init(). */
#define CAP_SLOT_USER       6    /* CAP_USER admin cap (SYS_REGISTER_FS_SERVER gate) */
#define CAP_SLOT_CONSOLE    8    /* CAP_CONSOLE                                      */
#define CAP_SLOT_STORAGE    9    /* CAP_ENCRYPTED_STORAGE (also the object-store cap)*/
#define INIT_FS_LISTEN      11   /* CAP_ENDPOINT FS_EP_REQ,  READ|WRITE (fs listen)  */
#define CAP_SLOT_IO_DEVICE  12   /* CAP_IO_DEVICE (console_server hardware authority) */
#define INIT_CON_LISTEN     13   /* CAP_ENDPOINT CON_EP_REQ, READ|WRITE (con listen) */
#define INIT_CON_CLIENT     14   /* CAP_ENDPOINT CON_EP_REQ, WRITE only (client)     */
#define INIT_NOTIFY         15   /* CAP_NOTIFICATION fs-ready rendezvous             */
#define INIT_KERNEL_LOG     CAPSLOT_KERNEL_LOG   /* CAP_KERNEL_LOG  -> the shell     */
#define INIT_BOOT_MODULE    CAPSLOT_BOOT_MODULE  /* CAP_BOOT_MODULE -> fs_server     */

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
    /* The fs LISTEN capability (carries READ, the receive right) goes to the
     * server and to nobody else — that is what makes it, and only it, able to
     * dequeue requests and answer them with SYS_IPC_REPLY_TO. Clients get a
     * WRITE-only capability from SYS_CONNECT_FS_SERVER instead. */
    if (sys_cap_grant(srv, INIT_FS_LISTEN, CAPSLOT_FS_LISTEN) != 0) return -2;
    if (sys_cap_grant(srv, CAP_SLOT_USER,  CAPSLOT_USER)      != 0) return -3;  /* registration gate */
    if (sys_cap_grant(srv, CAP_SLOT_STORAGE, CAPSLOT_AUDIT)   != 0) return -4;  /* object store      */
    if (sys_cap_grant(srv, INIT_NOTIFY,    CAPSLOT_NOTIFY)    != 0) return -5;  /* ready rendezvous  */
    /* Boot-module read surface. Formerly ambient uid==0 (finding I-1); now an
     * explicit, revocable capability held only by the task that provisions /bin. */
    if (sys_cap_grant(srv, INIT_BOOT_MODULE, CAPSLOT_BOOT_MODULE) != 0) return -6;
    /* Fully endowed: let it run. Spawn leaves a child suspended precisely so this
     * ordering is guaranteed rather than raced (see do_spawn). */
    if (sys_task_resume(srv) != 0) return -7;
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
    /* Console LISTEN capability: the receive right on CON_EP_REQ. Only the
     * console server gets this; clients get the WRITE-only copy below. */
    if (sys_cap_grant(csrv, INIT_CON_LISTEN,    CAPSLOT_CONSOLE_EP) != 0) return -2;
    if (sys_cap_grant(csrv, CAP_SLOT_IO_DEVICE, CAPSLOT_IO_DEVICE)  != 0) return -3;
    if (sys_task_resume(csrv) != 0) return -4;
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
    /* The console CLIENT capability: WRITE only, so the shell can send to the
     * console server but never receive on its endpoint. do_spawn propagates a
     * send-only copy to every utility the shell runs. */
    if (sys_cap_grant(sh, INIT_CON_CLIENT, CAPSLOT_CONSOLE_EP) != 0) return -4;
    /* The kernel log (`dmesg`). Formerly ambient uid==0 (finding I-1). Delegating
     * it explicitly means it can be withdrawn from the shell without changing who
     * the shell is — which an identity check could never do. */
    if (sys_cap_grant(sh, INIT_KERNEL_LOG, CAPSLOT_KERNEL_LOG) != 0) return -5;
    /* `ps` reads other tasks' info, which now requires a real capability rather
     * than uid 0 (finding I-1). CAP_AUDIT is the read-only introspection right. */
    if (sys_cap_grant(sh, CAPSLOT_AUDIT, CAPSLOT_AUDIT) != 0) return -6;
    /* The shell's console capability is granted above; resuming only now is what
     * guarantees it can never start writing before it holds one. That race is
     * what made the shell come up silent under SMP and time out CI. */
    if (sys_task_resume(sh) != 0) return -7;
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
    if (sys_cap_grant(cli, INIT_CON_CLIENT, CAPSLOT_CONSOLE_EP) != 0) {
        report("INIT_FS_SELFTEST: FAIL grant-client\n"); for (;;) settle();
    }
    if (sys_task_resume(cli) != 0) { report("INIT_FS_SELFTEST: FAIL resume-client\n"); for (;;) settle(); }
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
        sys_wait_notify(INIT_NOTIFY, &ready_badge);
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
        /* Read the cause BEFORE relaunching: launch_shell() may be handed the
         * dead shell's task slot, and the record is only guaranteed until this
         * task's next completed wait. */
        report_shell_exit();
    }
#endif
}
