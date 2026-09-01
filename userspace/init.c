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
static int machine_needs_install(void) {
    if (!g_si_valid)         return 0;
    if (!g_si.present)       return 0;   /* the ephemeral store; nothing to install onto */
    if (g_si.recognised)     return 0;   /* a volume is already here */
    if (g_si.format_on_login) return 0;  /* this kernel formats at login by itself */
    return g_si.needs_format ? 1 : 0;
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
