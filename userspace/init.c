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

/* Tell console_server the boot log is over, so it stops putting a
 * "[    S.uuuuuu] " prefix on every line (include/console_proto.h).
 *
 * Sent from here rather than decided by the server, because init is the only
 * task that knows the difference: the server sees CON_OP_WRITE either way, and
 * "the boot has finished" is a fact about what init is about to do next, not
 * about the bytes. Best effort -- a console that keeps timestamping is a cosmetic
 * fault in the session, and blocking the login on it would trade that for a
 * machine nobody can reach. The server also stops on its first read request, so
 * a lost signal costs at most the shell's banner.
 *
 * Nothing is stamped before this call that should not be, and everything after
 * it is session output; the last stamped line of an ordinary boot is
 * "init: starting, launching shell".
 *
 * NO sys_console_owned() GUARD, unlike report(). The first version had one and
 * it did nothing at all: measured 2026-09-06, init reaches this line before
 * console_server's SYS_MAP_PHYS on a uniprocessor boot, so the guard was false
 * every time, the signal was never sent, and the login banner came out
 * timestamped. That is the same race report() has, and the answer here is the
 * opposite one -- report() needs to know which path can reach the wire NOW,
 * while this only needs the server to see it EVENTUALLY, and the endpoint is
 * already delegated whether or not the server has run yet. */
static void console_boot_done(void) {
    init_con_rq.magic = CON_PROTO_MAGIC;
    init_con_rq.op    = CON_OP_BOOT_DONE;
    init_con_rq.len   = 0;
    for (int tries = 0; tries < 20000; tries++) {
        int rc = sys_ipc_call(INIT_CON_CLIENT_SLOT, 0,
                              &init_con_rq, sizeof(init_con_rq), &init_con_rp);
        if (rc >= 0) return;
        if (!ipc_transient(rc)) return;
        sys_yield();
    }
}

/* Tell console_server which task may read a password from the console (S93).
 *
 * Shares init_con_rq/rp with console_boot_done above: init sends both, one at a
 * time, from its own single thread, so one pair of buffers is the honest shape.
 *
 * BOUNDED RETRY AND A REPORTED FAILURE, unlike console_boot_done, which returns
 * on any non-transient error because a missing boot-done only means the log
 * keeps its timestamps. This one decides whether the shell can read a password
 * at all, so the caller is told. Returns 0 when the server accepted it. */
static int console_set_input_owner(uint32_t pid) {
    init_con_rq.magic = CON_PROTO_MAGIC;
    init_con_rq.op    = CON_OP_SET_INPUT_OWNER;
    init_con_rq.len   = pid;
    for (int tries = 0; tries < 20000; tries++) {
        int rc = sys_ipc_call(INIT_CON_CLIENT_SLOT, 0,
                              &init_con_rq, sizeof(init_con_rq), &init_con_rp);
        if (rc >= 0) return init_con_rp.rc == 0 ? 0 : -1;
        if (!ipc_transient(rc)) return -1;
        sys_yield();
    }
    return -1;
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

/* ---- What volume this machine has (roadmap 2.9, S72) ----------------------
 *
 * init asks the kernel, at boot, before anything else runs. Two reasons, and the
 * second is the one this exists for.
 *
 * FIRST, IT IS THE POSITIVE HALF OF THE CAPABILITY. captest probes
 * SYS_STORAGE_INFO and SYS_STORAGE_FORMAT from a task holding no
 * CAP_STORAGE_FORMAT and asserts both are refused -- and a syscall that refused
 * EVERYONE would satisfy those checks exactly as well as one that refuses the
 * right callers. This is the call from a holder, on the wire, saying something
 * that differs between a machine with a disk and a machine without: the arm
 * captest cannot supply from inside its own boot, because the gate names a fixed
 * slot and a task cannot grant itself into one.
 *
 * SECOND, IT IS THE QUESTION AN INSTALLER EXISTS TO ANSWER. "There is a disk
 * here and it carries no Horus volume" is precisely the state in which a machine
 * needs installing, and init is the task that will decide what to launch.
 *
 * ONE write, whole line assembled first: a marker split across two writes can be
 * cut in half by another task's output (docs/LIMITATIONS.md 2.6a), and this one
 * is asserted by a gate.
 */
/* The survey, kept rather than asked for twice: report_storage prints it and
 * machine_needs_install decides on it, and two calls could in principle disagree
 * -- which is a needless way for "what init said" and "what init did" to come
 * apart in a transcript somebody is reading to find out why. */
/* A bound of init's own on how many devices it will describe. It is not
 * ATA_MAX_DRIVES: that is a kernel constant and this is ring 3, which must not
 * trust a count the kernel handed it as a loop bound either. */
#define ATA_SURVEY_MAX 8

static struct storage_info g_si;
static int g_si_valid;

static void report_storage(void) {
    struct storage_info si;
    char line[192];
    int p = 0;

    for (unsigned z = 0; z < sizeof(si); z++) ((char *)&si)[z] = 0;

    if (sys_storage_info(&si) != 0) {
        /* init holds CAP_STORAGE_FORMAT from the primordial endowment, so a
         * refusal here is a real finding rather than a configuration: it means
         * the endowment did not land. Said out loud rather than swallowed. */
        report("INIT_STORAGE: refused -- init holds no CAP_STORAGE_FORMAT\n");
        return;
    }
    g_si = si;
    g_si_valid = 1;

    exr_append_str(line, &p, "INIT_STORAGE: ");
    if (!si.present) {
        /* The ephemeral RAM vdisk. It is a block device by every internal
         * measure and is deliberately not reported as one here: an installer
         * offering to format memory would be offering nonsense. */
        exr_append_str(line, &p, "no persistent volume; this boot runs on the ephemeral store\n");
        report(line);
        return;
    }

    exr_append_str(line, &p, "disk present, ");
    exr_append_num(line, &p, si.total_blocks, 10);
    exr_append_str(line, &p, " blocks of ");
    exr_append_num(line, &p, si.block_size, 10);
    exr_append_str(line, &p, " bytes; ");
    if (si.recognised) exr_append_str(line, &p, "a Horus volume is present\n");
    else               exr_append_str(line, &p, "no Horus volume -- an install is needed\n");
    report(line);

    /* THE ENUMERATION, on lines of its own.
     *
     * A survey that could only ever say "the disk" is what made an installer
     * unable to ask which one. It is reported separately rather than folded into
     * the line above, so the marker every existing gate greps for is unchanged --
     * a gate reading "disk present" is asking a question this does not answer,
     * and rewording its line to carry a second answer is how a passing gate comes
     * to mean something else without anybody editing it.
     *
     * Each device is asked for individually rather than described from the
     * machine-wide survey, because that is the call an installer will make and an
     * enumeration nothing exercises is an enumeration nobody has checked. */
    {
        char dl[192];
        int dp = 0;
        exr_append_str(dl, &dp, "INIT_STORAGE: ");
        exr_append_num(dl, &dp, si.device_count, 10);
        exr_append_str(dl, &dp, " persistent device(s)\n");
        report(dl);
    }
    for (unsigned d = 0; d < si.device_count && d < ATA_SURVEY_MAX; d++) {
        struct storage_info di;
        for (unsigned z = 0; z < sizeof(di); z++) ((char *)&di)[z] = 0;
        if (sys_storage_device(d, &di) != 0) continue;

        char dl[192];
        int dp = 0;
        exr_append_str(dl, &dp, "INIT_STORAGE: device ");
        exr_append_num(dl, &dp, d, 10);
        exr_append_str(dl, &dp, ": ");
        exr_append_num(dl, &dp, di.total_blocks, 10);
        exr_append_str(dl, &dp, " blocks, ");
        exr_append_str(dl, &dp, di.recognised ? "a Horus volume\n" : "blank\n");
        report(dl);
    }

    /* AND ONE PAST THE END, which must be REFUSED rather than answered.
     *
     * A survey that clamped would hand back a complete, well-formed description
     * of a different disk -- no fault, no overrun, and the caller is a program
     * deciding which disk to erase. So the refusal is the property, and a
     * property with no witness is an assertion: this asks for it on every boot
     * that has any devices at all, and the two-disk gate requires the answer. */
    if (si.device_count > 0) {
        struct storage_info past;
        for (unsigned z = 0; z < sizeof(past); z++) ((char *)&past)[z] = 0;
        if (sys_storage_device(si.device_count, &past) == 0)
            report("INIT_STORAGE: FAIL an index past the last device was answered\n");
        else
            report("INIT_STORAGE: an index past the last device was refused\n");
    }
}

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
/* Slots for an endpoint init MAKES rather than one it was handed. Above the
 * primordial endowment on purpose: nothing installs these at boot, so a build
 * where the retype below fails leaves them empty and every use of them is
 * refused, rather than silently resolving something the kernel put there. */
#define INIT_DEV_LISTEN     40   /* CAP_ENDPOINT, retyped: READ|WRITE (listen) */
#define INIT_DEV_CLIENT     41   /* the same endpoint, WRITE only (init as client) */

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

#ifdef INIT_PROVISION_SELFTEST
#include "fs_proto.h"
#include "libhorus.h"

/* PROVISION A SERVER ON AN ENDPOINT INIT CREATED (roadmap 2.4, S59).
 *
 * Every other launcher here delegates an endpoint init was HANDED: kshell
 * installs FS_EP_REQ and CON_EP_REQ into init's cspace from the root cnode at
 * boot, and launch_fs_server passes one of them on. That is delegation, and it
 * is bounded by what the kernel decided to mint before ring 3 existed.
 *
 * This one is different in the way that matters for a mount table: the endpoint
 * DOES NOT EXIST AT BOOT. init retypes a KOBJ_ENDPOINT out of the untyped region
 * its own CAP_UNTYPED names, so the object is paid for from a budget init holds
 * a capability for, and the capability naming it is derived from that untyped
 * rather than installed by the kernel. A supervisor that can do this can bring up
 * a filesystem server nobody anticipated at build time, which is what "provision
 * a mount" means.
 *
 * `docs/ROADMAP.md` 2.4 said init could not do this, and gave as the reason that
 * it "holds no CAP_UNTYPED". It holds one; the claim was stale rather than
 * subtle, and the measurement that settled it is quoted in that file.
 *
 * INIT KEEPS A WRITE-ONLY MINT AND ACTS AS THE CLIENT, which is not a shortcut
 * to avoid writing a probe: it is the tightest statement of the property. The
 * server got READ (the receive right) and init kept WRITE (the send right), so a
 * completed round trip proves BOTH halves of the endpoint reached the task that
 * should have it -- and proves init did not keep the receive right for itself,
 * because a request it could dequeue would answer itself.
 *
 * Returns the server's task id, or a negative value naming the step that failed.
 *
 * `SECURITY.md` **S59**.
 */
static int launch_dev_server(void) {
#ifdef INIT_PROVISION_NO_UNTYPED
    /* CONTROL ARM -- never ship. Retype from a slot init holds no CAP_UNTYPED in,
     * which is the state roadmap 2.4 asserted init was permanently in. The
     * endpoint is never created, so the provisioning stops at step 1 and the
     * server is never reachable.
     *
     * This is what makes the gate a measurement rather than an observation: with
     * it, "init provisioned a server" is shown to DEPEND on init holding untyped
     * memory, instead of being something that happened to work. See
     * make smoke-init-provision-control. */
    if (sys_retype(INIT_DEV_CLIENT, KOBJ_ENDPOINT, 1, INIT_DEV_LISTEN) != 1) return -1;
#else
    /* The endpoint, carved from init's own budget. One object, and the retype
     * returns the count it made. */
    if (sys_retype(CAPSLOT_UNTYPED, KOBJ_ENDPOINT, 1, INIT_DEV_LISTEN) != 1) return -1;
#endif

    /* A WRITE-only copy for init to speak through. Minted BEFORE the listen
     * right is granted away, because a mint needs the source capability and
     * SYS_CAP_GRANT is a delegation rather than a move -- but doing it in this
     * order also means init never holds two send rights it has to reason about. */
    if (sys_cap_mint(INIT_DEV_CLIENT, INIT_DEV_LISTEN, CAP_RIGHT_WRITE) != 0) return -2;

    int srv = sys_spawn_named("dev_server");
    if (srv <= 0) return -3;
    /* The LISTEN right, to the server and to nobody else. */
    if (sys_cap_grant(srv, INIT_DEV_LISTEN, CAPSLOT_FS_LISTEN) != 0) return -4;
    if (sys_task_resume(srv) != 0) return -5;
    return srv;
}

/* Drive one request across the endpoint init made, and report what came back.
 *
 * FS_OP_STAT on the root inode, because that is the operation `hvfs_mount`
 * itself performs to decide whether a mount can be installed -- so a server that
 * answers this is a server a mount table can actually mount. */
static void init_provision_probe(void) {
    int srv = launch_dev_server();
    if (srv <= 0) {
        /* NAME THE STEP. launch_dev_server returns a distinct negative per stage
         * (-1 retype, -2 mint, -3 spawn, -4 grant, -5 resume) and a failure that
         * did not say which is a failure that costs a bisect to read. */
        /* ONE write, not two. This was `report("...stopped at step ")` followed
         * by a second report() with the number -- and the serial console is
         * shared with every other ring-3 task, so fs_server's banner could land
         * between them and split the marker the gate asserts on. It did, on
         * 2026-08-31, producing "stopped at step [fs_server] userspace FS server
         * starting" and a gate that timed out looking for a contiguous string
         * that had been emitted in two pieces. A marker asserted as one string
         * must be written as one string. */
        report(srv == -1 ? "INIT_PROVISION: FAIL provisioning stopped at step 1 (retype the endpoint)\n"
             : srv == -2 ? "INIT_PROVISION: FAIL provisioning stopped at step 2 (mint the client copy)\n"
             : srv == -3 ? "INIT_PROVISION: FAIL provisioning stopped at step 3 (spawn dev_server)\n"
             : srv == -4 ? "INIT_PROVISION: FAIL provisioning stopped at step 4 (grant the listen right)\n"
             : srv == -5 ? "INIT_PROVISION: FAIL provisioning stopped at step 5 (resume the server)\n"
                         : "INIT_PROVISION: FAIL provisioning stopped at step unknown\n");
        return;
    }

    struct fs_request  rq;
    struct fs_response rp;
    umemset(&rq, 0, sizeof(rq));
    rq.magic = FS_PROTO_MAGIC;
    rq.op    = FS_OP_STAT;
    /* dev_server's root inode is 0 (DEV_INO_ROOT). Written as 1 in the first
     * draft, which the server answered with SYS_ERR_NOENT -- and the check
     * caught it, because it asserts the reply is a mountable DIRECTORY rather
     * than merely that a reply arrived. A probe that only checked "something
     * came back" would have passed against the wrong inode. */
    rq.ino   = 0;

    /* ipc_call_retry: retry on a transient only, and bounded -- the contract
     * libhorus owns so each program stops re-deriving it (roadmap 2.5). The
     * server was resumed a moment ago and may not have reached its recv yet. */
    int rc = ipc_call_retry(INIT_DEV_CLIENT, 0, &rq, sizeof(rq), &rp);
    if (rc < 0) {
        report("INIT_PROVISION: FAIL no reply across the endpoint init made\n");
        return;
    }
    if (rp.magic != FS_PROTO_MAGIC || rp.rc != 0 || rp.type != FS_TYPE_DIR) {
        report("INIT_PROVISION: FAIL server answered, but not as a mountable root\n");
        return;
    }
    report("INIT_PROVISION: PASS init retyped an endpoint, provisioned a server on it, and reached it\n");
}
#endif /* INIT_PROVISION_SELFTEST */

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
    /* `ps` and `capview` read other tasks' info, which requires a real capability
     * rather than uid 0 (finding I-1). Until 2026-08-23 that capability was
     * CAP_AUDIT -- which ALSO rotates the audit chain's keys and reads the log,
     * neither of which the shell ever called. The gate was real; it just named
     * far more authority than the caller needed, which is a bundling mistake and
     * survives an ambient-authority sweep untouched.
     *
     * CAP_DEBUG (roadmap 3.6) is observation and nothing else, minted READ-only
     * at the root so no delegation can widen it. Swapping the grant NARROWS the
     * shell: `ps` still works, and the shell can no longer touch the audit log.
     * `smoke-session` runs `ps`, so the narrowing is gated rather than asserted. */
    if (sys_cap_grant(sh, CAPSLOT_DEBUG, CAPSLOT_DEBUG) != 0) return -6;
    /* `useradd` / `userdel`. Until 2026-08-15 these worked because
     * current_user_is_admin() in the kernel accepted uid 0 as an alternative to
     * holding CAP_USER — the last ambient gate from finding I-1, missed because
     * roadmap 0.2's sweep covered syscall.c and syscall_fs.c but not kusers.c
     * (finding H-1). With that fallback gone the shell needs the real capability,
     * so init delegates it here, exactly as it does the kernel log above.
     *
     * The shell holds this for the life of the boot, across every login, so the
     * kernel's possession check cannot by itself express "only while root is at
     * the terminal". That half is enforced in the shell (see the useradd/userdel
     * handlers), which is the same split CAP_KERNEL_LOG uses: the KERNEL asks
     * whether the task holds the authority, the SESSION MANAGER asks whether this
     * user may exercise it. Granting without that check would be a privilege
     * WIDENING versus the uid==0 gate being removed, which is precisely the
     * mistake smoke-session caught when CAP_KERNEL_LOG was delegated. */
    if (sys_cap_grant(sh, CAP_SLOT_USER, CAPSLOT_USER) != 0) return -7;
    /* CAP_UNTYPED, and this grant is what lets the shell run `spawn` at all.
     *
     * Creating a task carves the child's cspace out of an untyped region since
     * 2026-08-30 (audit finding 4.1, roadmap 0.3): a task holding no CAP_UNTYPED
     * cannot spawn, fork or spawn an image. The five task-creating syscalls used
     * to authorise on cspace slot 3, which `create_task` fills in EVERY task, so
     * every task could spawn and the check could not fail.
     *
     * THE GRANT IS THE POINT, NOT A WORKAROUND FOR THE GATE. It makes "may this
     * task create tasks?" a question with an answer that is written down here and
     * revocable, rather than one the kernel answers yes to for everybody. The
     * shell needs it because `spawn` is a shell command; a server that should
     * never fork is now simply not given one, and nothing else has to change.
     *
     * It is the same region init holds -- there is no region splitting yet, so a
     * delegate shares the budget rather than getting a sub-budget. Bounded
     * per-delegate accounting is what a `SYS_UNTYPED_SPLIT` would buy, and is not
     * needed for the authority property this closes. */
    if (sys_cap_grant(sh, CAPSLOT_UNTYPED, CAPSLOT_UNTYPED) != 0) return -9;
    /* WHICH TASK MAY READ A PASSWORD FROM THE CONSOLE (S93), told to the server
     * BEFORE the shell can run -- so the registration is in place before the
     * first `horus login:` prompt, and before any task the shell spawns exists
     * to race it.
     *
     * This is the one moment it can safely be done. init holds a console client
     * capability and, right now, is the only ring-3 task that does: console_server
     * is running, the shell is spawned but suspended, and nothing else has been
     * launched. The server's rule is "unset, or the current owner", so this
     * first registration is accepted and every later attempt by anything other
     * than the shell is refused.
     *
     * A failure is reported and NOT fatal. The server fails closed on an unset
     * owner -- GETPASS is refused rather than served -- so the cost of this not
     * landing is a shell that cannot read a password, which is visible
     * immediately at the login prompt. Killing the boot instead would turn a
     * console-server hiccup into an unbootable machine. */
    if (console_set_input_owner((uint32_t)sh) != 0)
        report("init: WARN could not register the shell as the console input owner; "
               "password entry will be refused\n");

    /* The shell's console capability is granted above; resuming only now is what
     * guarantees it can never start writing before it holds one. That race is
     * what made the shell come up silent under SMP and time out CI. */
    if (sys_task_resume(sh) != 0) return -8;
    return sh;
}

/* Does this machine need installing?
 *
 * FAIL CLOSED IN THE DIRECTION OF NOT INSTALLING. Every uncertainty here -- the
 * survey unreadable, no capability, no disk, a volume already present -- answers
 * NO. The cost of a wrong YES is an installer offering to erase a disk on a
 * machine that did not ask; the cost of a wrong NO is a login prompt on a machine
 * with nothing installed, which is recoverable by looking at it. Those are not
 * symmetric and the code is not symmetric either.
 *
 * `format_on_login` is the STORAGE_AUTOFORMAT case (the S63 control arm): that
 * kernel formats an unrecognised volume at the login prompt by itself, so there
 * is nothing for an installer to do, and launching one would leave a dozen
 * unattended test images waiting forever for a keystroke. */
/* Did the operator ask for the installer?
 *
 * ONE DECISION POINT, TWO INPUTS, and they mean different things. The boot menu
 * is the operator's answer on this boot -- a single image that offers "Install"
 * and "Live boot" has to be told which was chosen, and the boot media is where
 * a person holding the machine makes that choice. INSTALL_ALWAYS is the
 * build-time variant: an image that installs unattended, which the gates need
 * and which no human boots. Collapsing them into one flag would lose that
 * distinction; leaving them as two branches in two places would be worse.
 *
 * ZERO IS LIVE BOOT, and every uncertainty produces zero: no command line, a
 * malformed one, a word the kernel does not recognise. The safe answer is the
 * one that changes nothing on the disk, which is the same direction
 * machine_needs_install() argues for below. */
/* Read ONCE, reported, and answered from afterwards.
 *
 * One call means one value: a mode that could be re-read per question could in
 * principle answer two of them differently, and the questions here decide
 * whether a program that erases disks runs. It is also what makes the boot log
 * honest -- the line below is printed from the same word the decisions use,
 * rather than from a second read that might not agree. */
static uint64_t g_boot_flags_cached;

static void report_boot_mode(void) {
    g_boot_flags_cached = sys_boot_flags();

    /* SAID ON EVERY BOOT, not only the interesting ones. A machine that is about
     * to offer to erase a disk should have said why in its own log, and a
     * machine that did nothing should have said that too -- otherwise the only
     * boots that explain themselves are the ones that went wrong. */
    if (g_boot_flags_cached & BOOT_FLAG_INSTALL)
        report("init: boot mode INSTALL (the installer entry was chosen at the boot menu)\n");
    else if (g_boot_flags_cached & BOOT_FLAG_LIVE)
        report("init: boot mode LIVE (nothing on the disk will be changed)\n");
    else
        report("init: boot mode default (no boot menu; this image decides for itself)\n");
}

static int install_requested(void) {
#ifdef INSTALL_ALWAYS
    return 1;
#else
    return (g_boot_flags_cached & BOOT_FLAG_INSTALL) ? 1 : 0;
#endif
}

/* WHEN THE OPERATOR ASKED AND THE ANSWER IS NO, SAY WHY.
 *
 * Every `return 0` below is a decision not to run the installer, and four of
 * them can fire on a boot where somebody stood at the menu and chose "Install
 * Horus". Until 2026-09-11 all of them were silent: the entry was selected, the
 * installer never appeared, and the machine arrived at a login prompt -- which
 * is indistinguishable from having chosen live boot, and from the menu entry
 * not working at all. Reported on a real laptop, twice, and the second report
 * had to be diagnosed by reading this function rather than the machine.
 *
 * That is the failure this project refuses everywhere else: an act that does
 * nothing and does not say so. `report_boot_mode` already prints what was
 * CHOSEN; these print why the choice could not be honoured, which is the half
 * that was missing.
 *
 * Only on the asked-for path. A boot that never requested an install has
 * nothing to explain, and printing a reason on every ordinary boot would bury
 * the one that matters. */
static int machine_needs_install(void) {
    const int asked = install_requested();

    if (!g_si_valid) {
        if (asked)
            report("init: INSTALL was chosen, but the storage survey could not be read "
                   "(SYS_STORAGE_INFO failed) -- there is nothing to install onto\n");
        return 0;
    }
    if (!g_si.present) {
        /* THE COMMON CASE ON REAL HARDWARE, and worth spelling out rather than
         * reporting as a bare "no disk": this kernel drives ATA PIO and SD/eMMC
         * and nothing else, so a laptop's NVMe or AHCI SSD is not a disk it
         * failed to read -- it is a disk it cannot see at all. An operator who
         * is told "no disk" checks their cabling; one who is told this checks
         * docs/LIMITATIONS.md section 4. */
        if (asked)
            report("init: INSTALL was chosen, but no disk this kernel can drive was found. "
                   "Horus drives ATA PIO and SD/eMMC only -- an NVMe or AHCI SSD is invisible "
                   "to it (docs/LIMITATIONS.md 4). Nothing was written; this is a login prompt.\n");
        return 0;
    }
#ifdef INSTALL_ALWAYS
    /* INSTALL MEDIA. Build with INSTALL_ALWAYS=1 (`make install.iso`) and this
     * image runs the installer on EVERY boot, rather than only on a machine
     * whose disk has no volume -- which is what an installer ISO is for, and the
     * opposite of what the shipping image must do.
     *
     * THE FAIL-CLOSED REASONING ABOVE IS NOT WEAKENED, IT IS RELOCATED. The
     * default build answers NO to every uncertainty because the cost of a wrong
     * YES is an installer offering to erase a disk on a machine that did not
     * ask. An image somebody deliberately wrote to a USB stick and booted DID
     * ask -- that is the whole act -- so the question "should we install?" is
     * answered by the operator having booted this image, and the guard against
     * erasing a disk they still want stays where they can see what they are
     * about to lose: the installer's survey, its review, and its typed word.
     *
     * IT CAN NOW REPLACE AN EXISTING VOLUME (S90, 2026-09-11), and the thing
     * that makes that safe is not this flag.
     *
     * Until then two kernel guards refused it: storage_authorize_format refused
     * a device carrying the MOUNTED volume, and storage_unlock's format branch
     * was reachable only while g_needs_format was set, which is consumed the
     * moment a volume exists. Driving this image through a second install on a
     * disk it had just written answered `INSTALLER: FAIL format refused rc=-22`.
     *
     * The refusal now turns on UNLOCKED rather than mounted. A recognised volume
     * is mounted-but-locked from boot until somebody proves they own it, which
     * is the state install media is always in because it never logs in; an
     * unlocked volume means the machine is being USED, and reformatting it from
     * underneath is still refused in the kernel. The format authorisation became
     * a one-shot token in the same change, because it had been retired by
     * g_needs_format rather than by itself -- see storage_unlock.
     *
     * THE SHIPPING IMAGE IS UNAFFECTED, and the line that does it is four below
     * this comment: without INSTALL_ALWAYS, `g_si.recognised` returns 0 here and
     * the installer is never launched on a machine that has a volume, so nothing
     * on that image is ever granted CAP_STORAGE_FORMAT in that situation. The
     * kernel permits the act; only install media ever asks for it.
     *
     * `format_on_login` is still honoured: that kernel formats an unrecognised
     * volume by itself at the login prompt, so an installer would be racing it. */
    if (g_si.format_on_login) return 0;
    return 1;
#else
    /* THE BOOT MENU'S "INSTALL" ENTRY REACHES HERE, and it is the same act
     * install media performs -- so it gets the same answer, including on a
     * machine that already holds a volume (S90). What it does NOT do is bypass
     * anything: the installer still shows what will be destroyed, still asks
     * every question, and still needs the typed word, which is REPLACE rather
     * than FORMAT when the disk is not empty.
     *
     * Live boot is the default and the fall-through. A machine booted without
     * the token behaves exactly as it did before this existed: the installer
     * runs only where there is a disk carrying no volume. */
    if (asked) {
        if (g_si.format_on_login) {
            /* Reachable only on a kernel built to format at login, which install
             * media is not -- but silent here would be the same defect as above,
             * and the arm that builds such a kernel is one flag away. */
            report("init: INSTALL was chosen, but this kernel formats an unrecognised volume "
                   "at the login prompt by itself, so an installer would be racing it\n");
            return 0;
        }
        return 1;
    }
    /* LIVE WAS ASKED FOR EXPLICITLY, so it is honoured exactly -- including on a
     * blank disk, where this image would otherwise offer to install. That is
     * what makes the menu entry's promise true: an operator who picked "changes
     * nothing on disk" gets a login prompt, not an installer. Without this the
     * two entries behave identically on the machine most likely to be booted
     * from install media, which is a menu that does not mean anything. */
    if (g_boot_flags_cached & BOOT_FLAG_LIVE) return 0;
    if (g_si.recognised)     return 0;   /* a volume is already here */
    if (g_si.format_on_login) return 0;  /* this kernel formats at login by itself */
    return g_si.needs_format ? 1 : 0;
#endif
}

/* Launch the installer and wait for it. Returns the task id, or negative.
 *
 * THE ENDOWMENT IS THE WHOLE SECURITY STATEMENT OF THIS FUNCTION, so it is three
 * grants and no more:
 *
 *   CAP_STORAGE_FORMAT -- survey the disk and destroy what is on it. The one
 *   capability that makes this program what it is, and the one no other task in
 *   the system is given a copy of.
 *
 *   CAP_USER -- set the first root password. Granted rather than inferred:
 *   do_passwd would ALSO accept the installer on the strength of its uid being 0
 *   and equal to the target's, and leaning on that would be trusting a caller for
 *   who it claims to be, which is the pattern this project exists to refuse. The
 *   capability is the authority; the uid is a coincidence of how init spawns.
 *
 *   The console client endpoint -- draw, and read keys. Every task with a console
 *   holds one; it confers nothing an ordinary program lacks.
 *
 * It is NOT given CAP_ENCRYPTED_STORAGE (it must not be able to read the volume
 * it replaces), CAP_UNTYPED (it cannot create a task, so nothing it does outlives
 * it), or CAP_BOOT_MODULE (fs_server copies the base system; see do_install). */
static int launch_installer(void) {
    int in = sys_spawn_named("installer");
    if (in <= 0) return -1;
    if (sys_cap_grant(in, CAPSLOT_STORAGE_FORMAT, CAPSLOT_STORAGE_FORMAT) != 0) return -2;
    if (sys_cap_grant(in, CAP_SLOT_USER, CAPSLOT_USER) != 0) return -3;
    if (sys_cap_grant(in, INIT_CON_CLIENT, CAPSLOT_CONSOLE_EP) != 0) return -4;
    if (sys_task_resume(in) != 0) return -5;
    return in;
}

void _start(void) {
    /* Say what volume this machine has, before anything else runs. See
     * report_storage: it is both the positive arm for CAP_STORAGE_FORMAT and the
     * question that decides whether a machine needs installing. */
    report_storage();

    /* Bring up the filesystem server first, so it is registered and serving by
     * the time the shell (or the test client) issues its first request. */
    int srv = launch_fs_server();
    if (srv < 0) report("init: WARNING fs_server provisioning failed\n");
    else         report("init: fs_server launched and provisioned\n");

#ifdef INIT_PROVISION_SELFTEST
    /* After fs_server, so the ordinary boot is unchanged and this is additive:
     * the property under test is about an endpoint init MAKES, not about the
     * primordial ones, and running it first would prove the same thing while
     * perturbing a boot path several gates depend on. */
    init_provision_probe();
#endif

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

    /* Asked and answered before anything consults it, and unconditionally --
     * including on a machine with no disk, where no install question is ever
     * reached. A boot mode that is only read when it might matter is one that
     * cannot be seen in the log of a boot where it did not. */
    report_boot_mode();

    /* THE INSTALLER RUNS BEFORE THE SHELL AND AFTER THE CONSOLE SERVER, and both
     * halves of that are required. It needs the console server, because the whole
     * program is CON_OP_WRITE_RAW / CON_OP_READ_RAW on that endpoint; and it must
     * finish before a login prompt appears, because a login on a machine with no
     * volume is a prompt nothing can satisfy.
     *
     * init BLOCKS on it rather than supervising it: an installer that died
     * half-way has not left a system to log into, so there is nothing useful to
     * do in parallel. When it returns -- installed, cancelled, or dead -- the
     * shell loop below runs exactly as it always did. */
    if (machine_needs_install()) {
#ifdef INSTALL_ALWAYS
        /* Announced before the installer draws anything. A reader of a boot log
         * -- or of a serial capture from a machine that is now blank -- should
         * be able to see that this image was built to install, rather than infer
         * it from what happened next. */
        report("init: INSTALL MEDIA (INSTALL_ALWAYS): the installer runs on every boot\n");
#endif
        int in = launch_installer();
        if (in < 0) {
            report(in == -1 ? "init: FAIL could not spawn the installer\n"
                 : in == -2 ? "init: FAIL could not delegate CAP_STORAGE_FORMAT\n"
                 : in == -3 ? "init: FAIL could not delegate CAP_USER\n"
                 : in == -4 ? "init: FAIL could not delegate the console endpoint\n"
                            : "init: FAIL could not resume the installer\n");
        } else {
            report("init: this machine has a disk and no volume; running the installer\n");
            sys_wait(in);
            report("init: the installer finished\n");
        }
    }

    report("init: starting, launching shell\n");

    /* The last line of the boot log. From here the console is a terminal. */
    console_boot_done();

#ifdef KDIAG_NOISE
    /* The second writer, on purpose. Not a defect flag: it is the instrument
     * the COM3 diagnostic-channel arms measure with, and it is set in ALL of
     * them.
     *
     * The hazard being measured is a ring-3 task's output landing inside a
     * kernel marker on the shared console UART. The ordinary session cannot
     * measure it, and the reason is worth writing down because two tunings were
     * spent on it: console output stops almost as soon as it starts. After the
     * login prompt the shell blocks reading a character, console_server blocks
     * serving that read, and init's own report() -- which goes through
     * console_server like any other program -- never completes. So ring 3 is
     * silent for all but a fraction of a second around the banner, and a probe
     * firing on a tick count either lands in that window or does not. Measured
     * 2026-09-03: every marker whole on 4 boots in 4 with the probes just
     * before the window, and one split in one boot with them just after it.
     * Tuning an offset until a race lands is not a measurement.
     *
     * So under this flag init does not launch the shell at all: it talks
     * forever instead, and the window is the whole run. What proves the console
     * handover happened is then console_server's own ready line rather than a
     * login prompt -- which is the more direct evidence anyway, being the event
     * itself rather than something that follows it.
     *
     * It goes through console_server, which is what makes it a faithful second
     * writer rather than a privileged one: console_server's ser_puts is a byte
     * loop on COM1 and the kernel writes the same UART from its trap path, so
     * the two interleave at BYTE granularity exactly as they did in CI on
     * 2026-09-02. settle() between lines keeps it from monopolising a CPU. */
    for (;;) {
        report("init: kdiag noise ---------------------------------------\n");
        settle();
    }
#endif

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
