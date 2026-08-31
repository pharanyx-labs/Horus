/* userspace/captest.c — capability + syscall conformance exerciser.
 *
 * Drives the syscall surface and the capability model from ring 3 and asserts on
 * what comes back, so it works as both a regression test (`make smoke-captest`)
 * and a demonstration of what a ring-3 task can and cannot do.
 *
 * The emphasis is on what a *capability* system must get right, which is mostly
 * the refusals. Any kernel can return the right answer to an authorised call; a
 * capability kernel additionally has to refuse the unauthorised one, and refuse
 * it after a revoke, and refuse it for a slot the task never held. So most
 * checks below assert a NEGATIVE result, and each states the authority it is
 * probing rather than just the number it expects.
 *
 * This is a flat (non-newlib) image: no libc, so printing goes through
 * sys_write() and numbers through the small helper here.
 *
 * Prints "CAPTEST: PASS <n> checks" on success, or "CAPTEST: FAIL <what>" and
 * exits on the first failure.
 */

#include "../include/syscall.h"
#include "block_size.h"

/* ---- minimal output -------------------------------------------------- */

static void out(const char *s) {
    uint32_t n = 0;
    while (s[n]) n++;
    sys_write(1, s, n);
}

static void out_dec(uint64_t v) {
    char buf[24];
    int i = (int)sizeof(buf);
    buf[--i] = '\0';
    if (v == 0) buf[--i] = '0';
    while (v && i > 0) { buf[--i] = (char)('0' + (v % 10)); v /= 10; }
    out(&buf[i]);
}

static int checks = 0;

/* Report the first failure and stop: later checks would be reading state the
 * failed one already invalidated. */
static void fail(const char *what) {
    out("CAPTEST: FAIL ");
    out(what);
    out("\n");
    sys_exit();
    for (;;) { }
}

static void check(int ok, const char *what) {
    if (!ok) fail(what);
    checks++;
}

/* ---- capability slot map (see create_task in src/kernel/scheduler.c) ----
 * A freshly spawned task holds: 0 = CAP_TCB (itself), 3 = CAP_FRAME,
 * 4 and 5 = CAP_ENDPOINT. Slot 7 (CAP_BLOCK_DEV) is never granted, which is what
 * makes it a useful negative probe.
 *
 * Slot 6 (CAP_USER admin) is likewise never granted here, which is what makes
 * the section-4b admin probes meaningful. Worth stating WHY, because it is not
 * for the reason it looks like: do_spawn_inner does contain code to propagate
 * CAP_USER from a spawner that holds it, but it calls cap_lookup(6, ...) after
 * load_staged_image_into has already made the CHILD the current task, so the
 * lookup reads the child's freshly-zeroed cspace and never fires (kspawn.c,
 * do_spawn_inner, at the cap6_serial hand-off).
 * Verified rather than assumed: the 4b refusals pass identically whether or not
 * the harness clears the slot.
 */
#define SLOT_TCB_SELF   0
#define SLOT_FRAME      3    /* CAP_FRAME — a live cap, but NOT an endpoint */
#define SLOT_REPLY_EP   4    /* CAP_ENDPOINT: this task's private reply ep (READ|WRITE) */
#define SLOT_CLIENT_EP  5    /* CAP_ENDPOINT: console service, WRITE ONLY (a client cap) */
#define SLOT_BLOCKDEV   7    /* deliberately not held */
#define SLOT_NOTIFY     11   /* CAP_NOTIFICATION */
#define SLOT_SECOND_EP  21   /* CAP_ENDPOINT: a second, distinct endpoint (READ|WRITE) */
#define SLOT_UNTYPED    CAPSLOT_UNTYPED  /* CAP_UNTYPED over the user-facing region */
#define SLOT_RETYPED_EP  40  /* destination for the first SYS_RETYPE  */
#define SLOT_RETYPED_EP2 41  /* destination for the second           */
#define SLOT_RETYPED_EP3 42  /* a third, never received on: proves endpoint
                              * authority does not imply reply authority */
#define SLOT_EMPTY_HI   200  /* never populated */
#define SLOT_SPLIT      50   /* destination for SYS_UNTYPED_SPLIT (section 14) */
#define SLOT_SPLIT_EP   51   /* an endpoint retyped FROM the split sub-region   */
#define SLOT_SPLIT2     52   /* a second split destination, for the refusals    */

/* Non-blocking probe: SYS_WAIT_NOTIFY on a slot that holds no CAP_NOTIFICATION
 * must be refused outright (it returns before any blocking decision is made), so
 * this can never hang the test. */
static int sys_wait_notify_nb(int slot) {
    uint32_t badge = 0;
    return sys_wait_notify(slot, &badge);
}

void _start(void) {
    out("CAPTEST: begin\n");

    /* ---- 1. identity and basic syscalls ------------------------------- */

    int pid = sys_getpid();
    check(pid > 0, "getpid-nonpositive");

    struct task_info ti;
    check(sys_get_task_info(pid, &ti) == 0, "task-info-self");
    check(ti.id == (uint32_t)pid, "task-info-id-mismatch");

    /* (Reading another task's info is admin-gated. That check used to live here
     * behind `if (sys_getuid() != 0)` — which never fires, because this harness
     * runs captest as uid 0. It is now unconditional, in section 4b, where the
     * rest of the "identity is not authority" probes are.) */

    sys_yield();                   /* must return; a task may always yield */
    checks++;

    /* ---- 2. heap: sbrk/brk ------------------------------------------- */

    void *b0 = sys_sbrk(0);
    check(b0 != (void *)-1, "sbrk-query-failed");
    void *b1 = sys_sbrk(4096);
    check(b1 != (void *)-1, "sbrk-grow-failed");
    void *b2 = sys_sbrk(0);
    check((char *)b2 >= (char *)b1, "sbrk-break-went-backwards");

    /* The page just obtained must be usable: a demand-paged heap that reports
     * success and then faults on first touch is the failure this catches. */
    volatile unsigned char *heap = (volatile unsigned char *)b1;
    heap[0] = 0xA5;
    heap[4095] = 0x5A;
    check(heap[0] == 0xA5 && heap[4095] == 0x5A, "heap-page-not-writable");

    /* ---- 3. capability gating: fail-closed on caps we do not hold ----- */

    /* Slot 7 (CAP_BLOCK_DEV) was never granted, so the raw block-device
     * syscalls must refuse. This is the core "no ambient authority" property:
     * being ring 3 is not enough, you must present the capability. */
    /* Static and block-sized: the call must be REFUSED before any copy, so the
     * size is not load-bearing today -- but if that refusal ever regressed, a
     * 512-byte buffer taking a whole block would make the test itself the
     * overflow. */
    static unsigned char blk[HORUS_BLOCK_SIZE];
    check(sys_block_read(0, blk, sizeof(blk)) < 0, "block-read-allowed-without-cap");
    check(sys_block_write(0, blk, sizeof(blk)) < 0, "block-write-allowed-without-cap");

    /* An out-of-range / never-populated slot must be refused, not treated as a
     * wildcard or read out of bounds. */
    check(sys_cap_revoke(SLOT_EMPTY_HI) != 0, "revoke-empty-slot-succeeded");

    /* ---- 4. IPC is capability-ADDRESSED (audit finding C-1) ----------- *
     *
     * The property under test: a task may operate on an IPC object only if it
     * holds a capability OF THE RIGHT TYPE, NAMING THAT OBJECT, carrying the
     * RIGHT for the direction.
     *
     * Every check below failed before the fix. IPC took a raw object index from
     * a register and was gated on "hold something in slot 3" — and slot 3 holds
     * a CAP_FRAME in every task — so any task could receive on, send to, and
     * forge replies on any endpoint in the system, including a server's. The
     * old suite never caught it because it only asserted that HELD capabilities
     * work and UNHELD slots are refused; it never asserted that a capability for
     * one object denies another, nor that a non-endpoint type is refused. */

    char msg[64];

    /* (a) The task's own reply endpoint (slot 4, READ|WRITE) is legitimate: the
     * non-blocking recv either finds nothing (would-block) or a message, but is
     * not refused for lack of authority. */
    int rc = sys_ipc_recv(SLOT_REPLY_EP, msg, sizeof(msg));
    check(rc == -2 || rc >= 0, "ipc-recv-on-held-endpoint-refused");

    /* NOTE ON PRECISION. Every refusal below is asserted as EXACTLY
     * SYS_ERR_PERM (-1), never merely "negative". sys_ipc_recv returns -2 for an
     * empty mailbox, so a `< 0` assertion cannot tell "the kernel refused me" from
     * "the endpoint I was allowed to read happened to be empty" — and under the
     * pre-fix kernel, which treated the argument as a raw object index, these
     * probes hit empty endpoints and returned -2. A `< 0` test therefore passes on
     * BOTH the fixed and the broken kernel and proves nothing. (Confirmed
     * empirically: an earlier draft of this suite used `< 0`, and the whole
     * section still passed with the vulnerable handler restored.) Asserting the
     * exact code is what makes these genuine regression tests. */

    /* (b) A slot holding no capability at all is refused. */
    check(sys_ipc_recv(SLOT_BLOCKDEV, msg, sizeof(msg)) == SYS_ERR_PERM,
          "ipc-recv-on-unheld-slot-allowed");
    check(sys_ipc_recv(SLOT_EMPTY_HI, msg, sizeof(msg)) == SYS_ERR_PERM,
          "ipc-recv-on-empty-slot-allowed");
    check(sys_ipc_send(SLOT_EMPTY_HI, msg, 4) == SYS_ERR_PERM,
          "ipc-send-on-empty-slot-allowed");

    /* (c) THE REGRESSION TEST FOR C-1. Slot 3 holds a CAP_FRAME — a real,
     * live capability, just not an endpoint. It must be refused for every IPC
     * operation. This exact slot was the old authorisation gate, so under the
     * pre-fix kernel all four of these SUCCEEDED and thereby authorised IPC to
     * an arbitrary endpoint. Type confusion is the whole bug. */
    check(sys_ipc_recv(SLOT_FRAME, msg, sizeof(msg)) == SYS_ERR_PERM,
          "ipc-recv-authorised-by-CAP_FRAME");
    check(sys_ipc_send(SLOT_FRAME, msg, 4) == SYS_ERR_PERM,
          "ipc-send-authorised-by-CAP_FRAME");
    check(sys_ipc_reply_to(SLOT_FRAME, msg, 4) == SYS_ERR_PERM,
          "ipc-reply-to-authorised-by-CAP_FRAME");
    check(sys_ipc_sender(SLOT_FRAME, 0) == (uint32_t)-1,
          "ipc-sender-authorised-by-CAP_FRAME");

    /* (d) A WRITE-only capability confers SEND and nothing else — the
     * client/server split that makes a shared service safe.
     *
     * Slot 5 holds a send-only capability to the console service, exactly what a
     * client is given (and what SYS_CONNECT_FS_SERVER mints). The refusals are
     * the C-1 attack itself:
     *   - recv would let a client DEQUEUE other clients' requests to the server,
     *     both disclosing them and starving the real server;
     *   - reply_to would let a client FORGE the server's replies straight into a
     *     victim's blocked SYS_IPC_CALL buffer — forged file contents, forged
     *     permission outcomes, arbitrary bytes served as a program's image.
     * Both require CAP_RIGHT_READ (the receive right), which a client never has. */
    check(sys_ipc_recv(SLOT_CLIENT_EP, msg, sizeof(msg)) == SYS_ERR_PERM,
          "client-cap-allowed-recv-INTERCEPTION");
    check(sys_ipc_reply_to(SLOT_CLIENT_EP, msg, 4) == SYS_ERR_PERM,
          "client-cap-allowed-reply-to-FORGERY");
    check(sys_ipc_sender(SLOT_CLIENT_EP, 0) == (uint32_t)-1,
          "client-cap-allowed-sender-query");

    /* (e) A CAP_NOTIFICATION does not authorise ENDPOINT operations, and an
     * endpoint capability does not authorise NOTIFICATION operations. The two
     * namespaces are separate objects and the type check must keep them so. */
    check(sys_ipc_recv(SLOT_NOTIFY, msg, sizeof(msg)) == SYS_ERR_PERM,
          "notification-cap-authorised-endpoint-recv");
    check(sys_notify(SLOT_REPLY_EP, 0x1u) == SYS_ERR_PERM,
          "endpoint-cap-authorised-notify");
    check(sys_wait_notify_nb(SLOT_REPLY_EP) == SYS_ERR_PERM,
          "endpoint-cap-authorised-wait-notify");

    /* ---- 4b. root is NOT authority (audit finding I-1) ---------------- *
     *
     * captest runs as uid 0 in the self-test harness but is deliberately NOT
     * given the object-store, kernel-log or boot-module capabilities. Every call
     * below used to succeed for any uid-0 task through an ambient
     * `tasks[cur].uid != 0` gate that ran parallel to the capability system —
     * which meant the capability graph was not a complete description of
     * authority. They are now gated on held capabilities, by TYPE, and must be
     * refused however privileged the caller's identity is.
     *
     * Asserted as exactly SYS_ERR_PERM (see the note above): a `< 0` check would
     * also match a legitimate "no such object" and prove nothing. */
    check(sys_getuid() == 0, "captest-not-uid0-so-I-1-checks-are-vacuous");

    unsigned char logbuf[64];
    check(sys_dmesg(logbuf, 0, sizeof(logbuf)) == SYS_ERR_PERM,
          "dmesg-allowed-by-uid0-without-CAP_KERNEL_LOG");
    check(sys_boot_module_info(0, 0) == SYS_ERR_PERM,
          "boot-module-info-allowed-by-uid0-without-CAP_BOOT_MODULE");
    check(sys_boot_module_read(0, 0, logbuf, sizeof(logbuf)) == SYS_ERR_PERM,
          "boot-module-read-allowed-by-uid0-without-CAP_BOOT_MODULE");

    /* The object-store API. These were additionally type-confused: the dispatch
     * table passed the CAP_BLOCK_DEV *type constant* in the RIGHTS field with
     * ctype = SC_ANYTYPE, so the gate really demanded rights 0b1011 on a
     * capability of any type. Now required by type. */
    struct fs_stat st;
    check(sys_fs_stat(0, &st) == SYS_ERR_PERM,
          "fs-stat-allowed-without-CAP_ENCRYPTED_STORAGE");
    check(sys_fs_inode_alloc(1) == SYS_ERR_PERM,
          "inode-alloc-allowed-without-CAP_ENCRYPTED_STORAGE");

    /* The user database (audit finding H-1). SYS_USERADD / SYS_USERDEL /
     * SYS_PASSWD are SC_NONE in the dispatch table, so their only gate is
     * current_user_is_admin() in kusers.c — which, until this change, ended
     * `return tasks[cur].uid == 0`. Roadmap 0.2 swept syscall.c and syscall_fs.c
     * for ambient uid gates and never reached kusers.c, so this one survived
     * while S18, LIMITATIONS 1.2 and ARCHITECTURE G-2 all recorded it as gone.
     *
     * These three are the reason section 4b exists at all: a uid-0 task holding
     * no capability could mint an account with any uid/gid it liked, and uid is
     * precisely the identity fs_server authorises file access against.
     *
     * do_useradd/userdel/passwd return -1 for "not admin" and -2..-5 for their
     * own domain errors, and SYS_ERR_PERM is -1 — so == SYS_ERR_PERM separates
     * refusal from "admitted, then failed on the arguments", which is the
     * distinction the first draft of the C-1 suite got wrong. */
    check(sys_useradd(4242, 4242, "audit") == SYS_ERR_PERM,
          "useradd-allowed-by-uid0-without-CAP_USER");
    check(sys_userdel(0) == SYS_ERR_PERM,
          "userdel-allowed-by-uid0-without-CAP_USER");
    /* A DIFFERENT uid than our own: do_passwd deliberately lets any task change
     * its OWN password without admin, so passwd(self) is not a probe of this
     * gate. uid 1 is the shipped non-root account. */
    check(sys_passwd(1, "not-the-real-password") == SYS_ERR_PERM,
          "passwd-of-another-user-allowed-by-uid0-without-CAP_USER");

    /* Cross-task introspection, which is CAP_USER/CAP_AUDIT-gated. This check
     * used to sit in section 1 behind `if (sys_getuid() != 0)` — and captest runs
     * as uid 0, so it had never once executed. It was dead code that read as
     * coverage. Unconditional here, where it belongs. */
    struct task_info other;
    check(sys_get_task_info(0, &other) != 0,
          "task-info-other-allowed-without-CAP_DEBUG");


    /* ---- 5. signals: own-task operations ----------------------------- */

    /* Masking is a task's own business and always permitted. */
    uint32_t prev = sys_sigmask(SIG_BLOCK, 1u << SIG_USR1);
    (void)prev;
    uint32_t restored = sys_sigmask(SIG_SETMASK, 0);
    check((restored & (1u << SIG_USR1)) != 0, "sigmask-block-not-reflected");

    /* SIG_KILL can never be masked, however it is asked for. */
    sys_sigmask(SIG_BLOCK, 1u << SIG_KILL);
    uint32_t after_kill_mask = sys_sigmask(SIG_SETMASK, 0);
    check((after_kill_mask & (1u << SIG_KILL)) == 0, "sig-kill-was-maskable");

    /* Signalling a task we hold no CAP_TCB for must be refused. Task ids well
     * past MAX_TASKS stand in for "a task we cannot name". */
    check(sys_send_signal(1 << 20, SIG_TERM) < 0, "signal-to-unnameable-task-allowed");

    /* Killing a task we hold no CAP_TCB for must likewise be refused. */
    check(sys_kill(1 << 20) < 0, "kill-to-unnameable-task-allowed");

    /* An alternate signal stack below the kernel's minimum must be refused
     * rather than accepted and later overflowed. */
    static char altstk[SIGSTKSZ_MIN * 2];
    check(sys_sigaltstack(altstk, 16) != 0, "sigaltstack-accepted-undersized");
    check(sys_sigaltstack(altstk, sizeof(altstk)) == 0, "sigaltstack-rejected-valid");
    check(sys_sigaltstack(altstk, 0) == 0, "sigaltstack-disable-failed");

    /* ---- 6. capability grant is descendants-only --------------------- */

    /* SYS_CAP_GRANT may only push a capability *down* into a task we spawned
     * (hold a CAP_TCB for). Granting to a task we do not supervise must fail —
     * otherwise any task could hand authority to any other. */
    check(sys_cap_grant(1 << 20, SLOT_REPLY_EP, 20) != 0,
          "grant-to-unsupervised-task-allowed");

    /* Granting from a slot we hold nothing in must fail too: there is no
     * capability there to delegate. */
    check(sys_cap_grant(pid, SLOT_EMPTY_HI, 21) != 0,
          "grant-from-empty-slot-allowed");

    /* ---- 7. revoke is rights-gated, not possession-gated -------------- */

    /* Revocation requires CAP_RIGHT_REVOKE *on the capability being revoked*.
     * A task's default endpoints carry only READ|WRITE, so holding a capability
     * is explicitly NOT enough to destroy it — otherwise any task handed an
     * endpoint could revoke it out from under the service that delegated it.
     * This is the distinction between having a capability and having authority
     * over it, and it is the one a possession-only model gets wrong. */
    check(sys_cap_revoke(SLOT_SECOND_EP) != 0, "revoke-succeeded-without-revoke-right");

    /* A refused operation must have no side effects: the endpoint it declined to
     * revoke has to still work. A partial revoke that fails the rights check
     * after clearing the slot would pass the check above and break this one. */
    rc = sys_ipc_recv(SLOT_SECOND_EP, msg, sizeof(msg));
    check(rc == -2 || rc >= 0, "endpoint-broken-by-refused-revoke");

    /* The unrelated endpoint is likewise untouched. */
    rc = sys_ipc_recv(SLOT_REPLY_EP, msg, sizeof(msg));
    check(rc == -2 || rc >= 0, "unrelated-endpoint-broken-by-refused-revoke");

    /* ---- 8. the audit log is capability-gated ------------------------ */

    /* Both audit syscalls require a CAP_AUDIT in slot 7, which an ordinary task
     * does not hold. The security-relevant direction is the refusal: the
     * tamper-evident log must not be readable — nor its chain digest sampled —
     * by any task that happens to be running, or the "detector" property is
     * available to whoever is being detected. */
    unsigned char digest[64];
    check(sys_audit_digest(digest) < 0, "audit-digest-allowed-without-cap");
    static struct audit_event ev[2];
    check(sys_read_audit(ev, 2) < 0, "audit-read-allowed-without-cap");

    struct untyped_info uinfo;

    /* ---- 8b. creating a kernel object requires untyped authority ------
     *
     * Roadmap 0.3 / audit finding I-7. Before this, every kernel object was an
     * entry in a fixed .bss array and creating one exercised no authority at
     * all — so "which task may consume kernel memory, and how much" was a
     * question the capability graph could not answer. CAP_UNTYPED is that
     * authority, and SYS_RETYPE is the only way to spend it.
     *
     * captest is endowed with a CAP_UNTYPED over the user-facing region
     * (captest_selftest in src/kernel/selftest.c) precisely so the positive
     * direction is covered too: a suite that only checked refusals would be
     * passed by a kernel whose SYS_RETYPE returned SYS_ERR_PERM unconditionally.
     */

    /* Retype through a slot holding NOTHING. There is no capability to spend,
     * so there is no authority — this is the base case the whole model rests on
     * and it must be PERM, not "created it anyway". */
    check(sys_retype(SLOT_EMPTY_HI, KOBJ_ENDPOINT, 1, 40) == SYS_ERR_PERM,
          "retype-allowed-without-untyped-cap");

    /* Retype through a live capability of the WRONG TYPE. This is the exact
     * shape of finding C-1: a check that a slot holds *something* rather than
     * that it holds the thing that names the resource. Slot 3 holds a CAP_FRAME
     * in every task, so a kernel that gated on possession rather than type would
     * hand every task in the system unlimited object creation. */
    check(sys_retype(SLOT_FRAME, KOBJ_ENDPOINT, 1, 40) == SYS_ERR_PERM,
          "retype-allowed-through-frame-cap");
    check(sys_retype(SLOT_REPLY_EP, KOBJ_ENDPOINT, 1, 40) == SYS_ERR_PERM,
          "retype-allowed-through-endpoint-cap");

    /* The sharpest wrong-type probe available: a CAP_NOTIFICATION whose `object`
     * is 0, which IS a valid untyped region index — the kernel's own cspace
     * reserve. The two capabilities above name objects far outside the untyped
     * index space, so a kernel that dropped the type check would still refuse
     * them on range alone; this one would sail through range and land on
     * UNTYPED_KERNEL. It therefore witnesses two properties at once: retype
     * checks the capability TYPE, and the kernel reserve is unreachable from
     * ring 3 even when something resolves onto its index. */
    check(sys_retype(SLOT_NOTIFY, KOBJ_ENDPOINT, 1, 40) == SYS_ERR_PERM,
          "retype-allowed-through-notification-cap-onto-kernel-reserve");
    check(sys_untyped_info(SLOT_FRAME, &uinfo) == SYS_ERR_PERM,
          "untyped-info-allowed-through-frame-cap");
    check(sys_untyped_info(SLOT_EMPTY_HI, &uinfo) == SYS_ERR_PERM,
          "untyped-info-allowed-without-untyped-cap");

    /* With the capability held, the region is observable. */
    check(sys_untyped_info(SLOT_UNTYPED, &uinfo) == 0, "untyped-info-refused-with-cap");
    check(uinfo.size > 0, "untyped-region-reported-empty");
    check(uinfo.free <= uinfo.size, "untyped-free-exceeds-size");
    uint64_t free_before = uinfo.free;

    /* ...and malformed requests are still refused, one reason at a time. A held
     * capability authorises the OPERATION, never the arguments. */
    check(sys_retype(SLOT_UNTYPED, 0, 1, 40) == SYS_ERR_INVAL,
          "retype-accepted-object-type-0");
    check(sys_retype(SLOT_UNTYPED, 99, 1, 40) == SYS_ERR_INVAL,
          "retype-accepted-unknown-object-type");
    /* A CNode is allocatable by the kernel but has no capability type naming it
     * and no syscall that installs one, so minting one would be authority with
     * no defined meaning. Refused until there is something to refuse it for. */
    check(sys_retype(SLOT_UNTYPED, KOBJ_CNODE, 1, 40) == SYS_ERR_INVAL,
          "retype-accepted-cnode-from-ring3");
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 0, 40) == SYS_ERR_INVAL,
          "retype-accepted-zero-count");
    /* Destination must clear the kernel-reserved slots: a task must not be able
     * to overwrite its own CAP_TCB or CAP_FRAME with a fresh endpoint. */
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, 0) == SYS_ERR_PERM,
          "retype-into-reserved-slot-allowed");
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_FRAME) == SYS_ERR_PERM,
          "retype-into-frame-slot-allowed");
    /* A run that would walk off the end of the cspace is refused OUTRIGHT rather
     * than truncated: a partially-applied allocation leaves the caller unable to
     * say which of its slots were written. */
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 4, 254) == SYS_ERR_RANGE,
          "retype-past-cspace-end-allowed");
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 100000, 40) == SYS_ERR_RANGE,
          "retype-huge-count-allowed");

    /* None of those refusals may have spent any of the budget. A refusal that
     * consumes the resource it refused is a denial-of-service primitive: a task
     * could exhaust its own (or a delegated) region with calls that all failed. */
    check(sys_untyped_info(SLOT_UNTYPED, &uinfo) == 0, "untyped-info-broken-after-refusals");
    check(uinfo.free == free_before, "refused-retype-consumed-untyped-memory");

    /* The positive direction: a held CAP_UNTYPED really does create an object,
     * and the capability it installs really does name a working endpoint. */
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_RETYPED_EP) == 1,
          "retype-endpoint-refused-with-untyped-cap");
    check(sys_untyped_info(SLOT_UNTYPED, &uinfo) == 0, "untyped-info-broken-after-retype");
    check(uinfo.free < free_before, "retype-consumed-no-untyped-memory");

    /* A fresh endpoint is empty, so recv reports "nothing there" (-2) rather
     * than failing the capability check (-1). This is the difference between an
     * object that exists and a capability that resolves to nothing. */
    rc = sys_ipc_recv(SLOT_RETYPED_EP, msg, sizeof(msg));
    check(rc == -2, "retyped-endpoint-not-usable");

    /* Round-trip through it: what we send is what we receive. The object is real
     * storage carved from untyped memory, not a handle onto a shared table. */
    static const char probe[] = "untyped";
    check(sys_ipc_send(SLOT_RETYPED_EP, probe, sizeof(probe)) == 0,
          "retyped-endpoint-send-failed");
    rc = sys_ipc_recv(SLOT_RETYPED_EP, msg, sizeof(msg));
    check(rc == (int)sizeof(probe), "retyped-endpoint-recv-wrong-length");
    check(msg[0] == 'u' && msg[6] == 'd', "retyped-endpoint-corrupted-message");

    /* ---- 8b. the ONE-SHOT REPLY CAPABILITY (roadmap 1.3) ------------------
     *
     * The successful recv above minted a CAP_REPLY into CAPSLOT_REPLY naming the
     * sender of that message — which, here, is this task itself. That capability
     * IS the right to answer that one request, and these checks assert it behaves
     * like a one-shot right rather than a standing permission.
     *
     * Why it matters: the reply used to be routed by the endpoint's mutable
     * `last_sender`, so replying to the correct client was a convention a server
     * had to honour, not something the kernel enforced. Each check below is a
     * property that convention could not provide.
     *
     * Exact codes, never `< 0`: sys_ipc_reply_to returns -2 to mean "retry, the
     * client is still publishing its block", so a `< 0` assertion would pass on a
     * kernel that had merely told us to try again. */

    /* Issuing the reply spends the right. We are not blocked in a CALL, so there
     * is nobody to deliver to and the reply is dropped — but dropped is still
     * ANSWERED, and a right that survived being answered could later land a stale
     * reply on a NEW request from the same client. */
    check(sys_ipc_reply_to(SLOT_RETYPED_EP, probe, sizeof(probe)) == 0,
          "reply-to-unblocked-client-not-dropped");

    /* One-shot: the second reply to the same request has no capability left to
     * authorise it. This is the check that distinguishes a consumed right from a
     * standing permission to reply on this endpoint. */
    check(sys_ipc_reply_to(SLOT_RETYPED_EP, probe, sizeof(probe)) == SYS_ERR_PERM,
          "reply-twice-to-one-request-allowed");

    /* The right stays spent: holding a full READ|WRITE capability on a DIFFERENT
     * endpoint does not resurrect it.
     *
     * Read this check precisely — it is weaker than it first looks, and the
     * weaker reading is the true one. CAPSLOT_REPLY is per-TASK, not
     * per-endpoint, so the endpoint slot passed to sys_ipc_reply_to only selects
     * the READ check; it does not select which reply right is used. This
     * therefore asserts that the slot is still empty after the two replies above,
     * which is a third witness of one-shot consumption — NOT that endpoint
     * authority and reply authority are independent. A version of this comment
     * claimed the latter, and it was wrong: before the replies above consumed the
     * right, this same call would have succeeded and answered the earlier
     * request. */
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_RETYPED_EP3) == 1,
          "third-retype-refused");
    check(sys_ipc_reply_to(SLOT_RETYPED_EP3, probe, sizeof(probe)) == SYS_ERR_PERM,
          "consumed-reply-right-revived-by-other-endpoint");

    /* And it is a DISTINCT object: the task's own reply endpoint must not have
     * received what was sent to the retyped one. A retype that handed back an
     * alias of an existing endpoint would pass every check above. */
    rc = sys_ipc_recv(SLOT_REPLY_EP, msg, sizeof(msg));
    check(rc == -2, "retyped-endpoint-aliases-reply-endpoint");

    /* Retyping again yields yet another distinct object, not the same one. */
    check(sys_retype(SLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_RETYPED_EP2) == 1,
          "second-retype-refused");
    check(sys_ipc_send(SLOT_RETYPED_EP, probe, sizeof(probe)) == 0,
          "retyped-endpoint-send-failed-2");
    rc = sys_ipc_recv(SLOT_RETYPED_EP2, msg, sizeof(msg));
    check(rc == -2, "two-retyped-endpoints-alias-each-other");

    /* ---- 8c. object lifetime is capability-governed -------------------
     *
     * The third property of I-7, and the one that distinguishes this from "the
     * arrays moved": an object exists exactly as long as some capability names
     * it. Revoking the only capability to a retyped endpoint must DESTROY it,
     * not merely make the slot unusable — otherwise objects accumulate forever
     * and the memory bound the untyped region is supposed to enforce leaks away
     * one dead object at a time.
     *
     * `objects` in the region's info is the observable: it counts live objects
     * carved from the region, so it is a direct reading of whether destruction
     * actually happened rather than an inference from a call failing. */
    check(sys_untyped_info(SLOT_UNTYPED, &uinfo) == 0, "untyped-info-broken-before-revoke");
    uint32_t objects_before = uinfo.objects;
    check(objects_before >= 2, "retyped-objects-not-counted");

    /* A retyped object's creator holds REVOKE on it — it is the only holder, so
     * there is nobody the revoke could surprise. (Contrast the delegated
     * endpoints in section 7, which carry READ|WRITE only.) */
    check(sys_cap_revoke(SLOT_RETYPED_EP2) == 0, "revoke-of-own-retyped-endpoint-refused");
    check(sys_untyped_info(SLOT_UNTYPED, &uinfo) == 0, "untyped-info-broken-after-revoke");
    check(uinfo.objects == objects_before - 1, "revoked-endpoint-object-not-destroyed");

    /* The revoked capability is dead, so IPC through it is refused at the
     * capability check (-1), not merely empty (-2). */
    check(sys_ipc_recv(SLOT_RETYPED_EP2, msg, sizeof(msg)) == SYS_ERR_PERM,
          "revoked-retyped-endpoint-still-usable");

    /* And revocation was surgical: the OTHER retyped endpoint is untouched. An
     * implementation that swept by region rather than by object would have
     * destroyed both, and every check so far would still have passed. */
    rc = sys_ipc_recv(SLOT_RETYPED_EP, msg, sizeof(msg));
    check(rc == (int)sizeof(probe), "sibling-retyped-endpoint-destroyed-by-revoke");

    /* ---- 9. invalid input is refused, not fatal ---------------------- */

    /* An unknown syscall number must return an error, not fault the kernel or
     * dispatch through a stale table slot. */
    check((int)syscall(250, 0, 0, 0) < 0, "unknown-syscall-not-refused");

    /* A bad user pointer must come back as an error; the kernel must never
     * dereference it on our behalf. */
    check(sys_get_task_info(pid, (struct task_info *)0x1) != 0,
          "task-info-accepted-bad-pointer");

    /* The roadmap 1.1 audit readout (SYS_IRQ_POLICY_INFO) must be unreachable
     * from a task that was not given it — captest holds no CAP_KERNEL_LOG.
     *
     * Asserted as an EXACT code in each configuration rather than "< 0", which
     * is the lesson the C-1 checks cost: a `< 0` assertion here would pass on a
     * kernel that answered NOSYS when it should have answered PERM, and would
     * therefore not notice the dispatch entry going missing from the audit build
     * — the one thing that would silently disable the instrument.
     *
     * Ship builds: no dispatch entry at all, so the syscall does not exist. That
     * is the security-relevant property, and it is the default configuration. */
    {
        struct irq_policy_info ipi;
#ifdef IRQ_POLICY_AUDIT
        check(sys_irq_policy_info(&ipi) == SYS_ERR_PERM,
              "irq-policy-info-allowed-without-kernel-log-cap");
#else
        check(sys_irq_policy_info(&ipi) == SYS_ERR_NOSYS,
              "irq-policy-info-present-in-ship-kernel");
#endif
    }

    /* ---- roadmap 2.2: the monotonic clock --------------------------------
     *
     * Ambient on purpose (a coarse count of time since boot is not authority
     * over an object), so what is asserted here is the SHAPE of what it hands
     * back rather than a refusal.
     *
     * The resolution check is the security-relevant one. CR4.TSD exists to deny
     * ring 3 a cycle-accurate timer; if `nsec` ever stopped being a multiple of
     * a PIT tick, this syscall would be handing that timer back through the
     * front door, and nothing else in the tree would notice. */
    {
        struct horus_timespec a, b;
        check(sys_clock_gettime(HORUS_CLOCK_MONOTONIC, &a) == 0,
              "clock-monotonic-refused");
        check(a.nsec < 1000000000u, "clock-nsec-out-of-range");
        check((a.nsec % 10000000u) == 0,
              "clock-resolution-finer-than-a-pit-tick");
        check(a.reserved == 0, "clock-reserved-field-not-zeroed");

        /* Monotonic: a second read never goes backwards. Reading twice in a row
         * is a weak test of that, and deliberately so -- a strong one would
         * have to sleep, and there is nothing here to sleep on yet (per-task
         * timers are the rest of roadmap 2.2). What it does catch is a clock
         * that resets, wraps, or reads uninitialised memory. */
        check(sys_clock_gettime(HORUS_CLOCK_MONOTONIC, &b) == 0,
              "clock-second-read-refused");
        check(b.sec > a.sec || (b.sec == a.sec && b.nsec >= a.nsec),
              "clock-went-backwards");

        /* Every other clock id is refused, not approximated: there is no wall
         * clock here, and answering with uptime would be a number shaped like a
         * date with nothing behind it. */
        check(sys_clock_gettime(0, &a) == SYS_ERR_INVAL, "clock-id-0-accepted");
        check(sys_clock_gettime(2, &a) == SYS_ERR_INVAL, "clock-realtime-answered-with-uptime");
        check(sys_clock_gettime(0xFFFFFFFFu, &a) == SYS_ERR_INVAL, "clock-bogus-id-accepted");
    }

    /* ---- roadmap 3.6: reading the capability graph needs CAP_DEBUG --------
     *
     * captest holds no CAP_DEBUG (init delegates it to the shell, not here), so
     * every SYS_CAP_ENUMERATE must be refused by the central gate -- including
     * one aimed at captest's OWN cspace. That last case is the interesting one:
     * "it is my own capability list" is exactly the argument that would make
     * this ambient, and self-inspection is not an exemption the gate offers.
     *
     * The refusal is SYS_ERR_PERM, not NOSYS: the syscall exists, and saying so
     * is fine. What is refused is the authority. */
    {
        struct cap_info ci;
        check(sys_cap_enumerate(0, 0, &ci) == SYS_ERR_PERM,
              "cap-enumerate-without-cap-debug");
        check(sys_cap_enumerate(sys_getpid(), 3, &ci) == SYS_ERR_PERM,
              "cap-enumerate-own-cspace-without-cap-debug");
        /* A bad task id and a bad slot are refused by the SAME gate, before the
         * handler validates anything -- so a caller holding no CAP_DEBUG cannot
         * use the error code to distinguish a live task from a dead one. */
        check(sys_cap_enumerate(9999, 0, &ci) == SYS_ERR_PERM,
              "cap-enumerate-bad-tid-leaks-a-different-error");
        check(sys_cap_enumerate(0, 100000, &ci) == SYS_ERR_PERM,
              "cap-enumerate-bad-slot-leaks-a-different-error");

        /* The two halves of "observing needs CAP_DEBUG" agree (roadmap 3.6,
         * second half): with none of it, neither the cspace readout above nor
         * cross-task SYS_GET_TASK_INFO is permitted -- so re-widening
         * introspection later would have to re-widen both to pass. The
         * task-info self-read in section 1 already proves that syscall works,
         * so a blanket refusal cannot satisfy both.
         *
         * ORDER MATTERS HERE, and it is not obvious: `fail()` calls sys_exit(),
         * so this suite stops at its FIRST failing check, and a control arm sees
         * only that one marker. This check fires under CAP_ENUMERATE_UNGATED too
         * -- placed any earlier in the file it would pre-empt
         * `cap-enumerate-without-cap-debug`, which is the marker
         * `smoke-captest-capenum-control` names, and that arm would time out
         * waiting for a line captest never reached. It did, on 2026-08-24. */
        struct task_info nobody;
        check(sys_get_task_info(0, &nobody) != 0,
              "cap-enumerate-and-task-info-disagree-about-CAP_DEBUG");
    }

    /* ---- console INPUT needs CAP_CONSOLE, not the slot-3 decoy -----------
     *
     * SYS_GET_LINE's dispatch entry declares SC_NONE, so its handler is the only
     * gate -- and until 2026-08-24 that gate accepted an untyped slot-3 lookup as
     * a fallback. Slot 3 is the legacy CAP_FRAME every task is born holding, so
     * this suite qualified: measured before the fix, captest passed the check and
     * BLOCKED inside the console read, which is a stronger statement than being
     * merely eligible -- it was reading what the user types.
     *
     * The refusal must come back IMMEDIATELY, and that is the whole assertion:
     * if the gate ever readmits this task, the call does not return a different
     * code, it does not return at all, and this suite hangs. `smoke-captest`
     * then fails on a timeout rather than a marker -- which is why the control
     * arm for it asserts the ABSENCE of `CAPTEST: PASS` instead of naming a FAIL
     * line, since a blocked task prints nothing.
     *
     * Placed last for the reason recorded above: this check fires under the
     * slot-3 arm, so it must not pre-empt any other arm's marker. */
    {
        static char lb[8];
        check((int)syscall(SYS_GET_LINE, (uint64_t)(uintptr_t)lb, 0, 0) == SYS_ERR_PERM,
              "get-line-without-cap-console");
    }

    /* ---- the BLOCKING receive carries the same authority (roadmap 1.3) ----
     *
     * SYS_IPC_RECV_BLOCK is a second way to receive, so it is a second place the
     * C-1 gate has to hold. A blocking variant that skipped the capability check
     * would reopen the whole finding — and it would do so on the path a SERVER
     * uses, which is exactly where interception matters.
     *
     * Exact codes, never `< 0`: this syscall's own "nothing there" value would be
     * IPC_AGAIN (-2) if it had one, and SYS_ERR_PERM is -1, so `< 0` could not
     * tell "refused" from "allowed, queue empty" — the precise mistake the first
     * C-1 suite made, which passed against a deliberately vulnerable kernel.
     *
     * None of these three can block: two are refused before any queue is
     * consulted, and the third runs against an endpoint known to be non-empty. */

    /* A WRITE-only capability is a CLIENT's. Receiving with it would let a client
     * dequeue the traffic of every other client of that service.
     *
     * The send first is not setup, it is what keeps this check HONEST on a broken
     * kernel. captest is one task, so if the right check were removed the receive
     * would find an empty queue and park forever, and the suite would report a
     * timeout rather than the name of the property that broke — indistinguishable
     * from a real hang, which is the failure mode TESTS.md keeps warning about.
     * With a message already queued, a kernel that wrongly allows this returns a
     * LENGTH, the check fails by name, and the diagnosis is in the log. (WRITE is
     * exactly the right this capability does have, so the send is legitimate.) */
    static const char rbdeny[] = "denied";
    check(sys_ipc_send(SLOT_CLIENT_EP, rbdeny, sizeof(rbdeny)) == 0,
          "recv-block-deny-setup-send-failed");
    check(sys_ipc_recv_block(SLOT_CLIENT_EP, msg, sizeof(msg)) == SYS_ERR_PERM,
          "recv-block-allowed-with-write-only-client-cap");

    /* A live capability of the WRONG TYPE must not authorise IPC either: this is
     * the CAP_FRAME every task holds in slot 3, which is what made the original
     * ambient dispatch-table entry so dangerous. */
    check(sys_ipc_recv_block(SLOT_FRAME, msg, sizeof(msg)) == SYS_ERR_PERM,
          "recv-block-authorised-by-CAP_FRAME");

    /* And an empty slot names nothing at all. */
    check(sys_ipc_recv_block(SLOT_EMPTY_HI, msg, sizeof(msg)) == SYS_ERR_PERM,
          "recv-block-allowed-on-empty-slot");

    /* The positive direction, and the reason it is safe here: a message is
     * queued FIRST, so the blocking receive completes inline and never parks.
     * captest is a single task — a receive that actually blocked would wedge the
     * whole suite, so the send succeeding is a precondition, not a nicety. It is
     * checked, and check() exits on failure, so the recv below is unreachable
     * unless the queue is non-empty.
     *
     * This also witnesses that the inline path returns the message rather than
     * IPC_AGAIN — a blocking receive that answered "try again" on a NON-empty
     * queue would be worse than the polling one.
     *
     * Uses slot 4 (this task's own private reply endpoint) rather than
     * SLOT_SECOND_EP. Slot 21 is BOTH this file's "second endpoint" and the
     * kernel's CAPSLOT_REPLY, so the one-shot reply rights minted and consumed in
     * section 8b have long since overwritten the endpoint capability that was
     * there — by this point slot 21 is NULL and any IPC on it is refused. */
    static const char rbprobe[] = "blocking";
    check(sys_ipc_send(SLOT_REPLY_EP, rbprobe, sizeof(rbprobe)) == 0,
          "recv-block-setup-send-failed");
    rc = sys_ipc_recv_block(SLOT_REPLY_EP, msg, sizeof(msg));
    check(rc == (int)sizeof(rbprobe), "recv-block-inline-wrong-length");
    check(msg[0] == 'b' && msg[7] == 'g', "recv-block-inline-corrupted-message");

    /* ---- device authority: this task holds no CAP_IO_DEVICE (S43) --------
     *
     * The four device syscalls have NO fixed dispatch-table slot -- they take a
     * cspace slot as their first argument and resolve it, exactly as the IPC
     * syscalls do since C-1. That makes the refusal a property of the HANDLER
     * rather than of the table, and this suite is where a handler-side refusal
     * gets its independent witness: `smoke-devcap` asks whether the right device
     * capability reaches the right device, and this asks what happens with no
     * device capability at all.
     *
     * Three slots, because the ways to have no authority are not the same thing:
     * the conventional device slot which this task was never endowed with, a
     * slot holding a live capability of the WRONG type (slot 3's CAP_FRAME --
     * the same decoy that made C-1 reachable), and a slot that has never held
     * anything. A gate that only tested the empty case would pass on a kernel
     * that skipped the type check, and slot 3 is precisely the capability every
     * task already holds, so that kernel would grant the console to everyone.
     *
     * Exact SYS_ERR_PERM, never `< 0`: SYS_ERR_INVAL is what a malformed request
     * returns, and "refused for want of authority" is a different statement from
     * "refused for want of sense". */
    check((int)syscall6(SYS_MAP_PHYS, CAPSLOT_IO_DEVICE, 0xB8000ULL, 0xB8000ULL,
                        4096, MAP_PHYS_WRITE, 0) == SYS_ERR_PERM,
          "map-phys-without-cap-io-device");
    check((int)syscall6(SYS_MAP_PHYS, SLOT_FRAME, 0xB8000ULL, 0xB8000ULL,
                        4096, MAP_PHYS_WRITE, 0) == SYS_ERR_PERM,
          "map-phys-with-wrong-cap-type");
    check((int)syscall6(SYS_MAP_PHYS, SLOT_EMPTY_HI, 0xB8000ULL, 0xB8000ULL,
                        4096, MAP_PHYS_WRITE, 0) == SYS_ERR_PERM,
          "map-phys-from-empty-slot");
    check(sys_ioport_grant(CAPSLOT_IO_DEVICE) == SYS_ERR_PERM,
          "ioport-grant-without-cap-io-device");
    check(sys_irq_register(CAPSLOT_IO_DEVICE, 1, SLOT_NOTIFY, 0x1234) == SYS_ERR_PERM,
          "irq-register-without-cap-io-device");
    {
        /* SYS_DEVICE_INFO discloses a device's BARs and IRQ line. It is READ
         * where the others are WRITE, which is a real rights split and not a
         * softer gate: with no capability at all it is refused just the same,
         * and a task that could read the table without holding a device would
         * have a bus walk. */
        struct dev_info di;
        check(sys_device_info(CAPSLOT_IO_DEVICE, &di) == SYS_ERR_PERM,
              "device-info-without-cap-io-device");
        check(sys_device_info(SLOT_FRAME, &di) == SYS_ERR_PERM,
              "device-info-with-wrong-cap-type");
    }

    /* SYS_DEVICE_ENABLE writes the only configuration-space register ring 3 can
     * reach — the three PCI decode bits, bus mastering among them. On a machine
     * with no IOMMU, bus mastering is authority over ALL of physical memory, so
     * the gate on this call is the difference between "who may make a device a
     * bus master" being a question and being nobody's business (S44). This task
     * holds no device capability and must be refused whatever it asks for. */
    check(sys_device_enable(CAPSLOT_IO_DEVICE, DEV_ENABLE_IO) == SYS_ERR_PERM,
          "device-enable-without-cap-io-device");
    check(sys_device_enable(SLOT_FRAME, DEV_ENABLE_BUSMASTER) == SYS_ERR_PERM,
          "device-enable-with-wrong-cap-type");
    {
        /* SYS_DMA_ADDR needs a device capability AND a frame capability. This
         * task has the second and not the first — exactly the caller the
         * two-capability rule exists to refuse, because a physical address is
         * the kernel's memory layout and nothing else in this ABI reports one.
         * The bus-address half of the rule is witnessed in `smoke-frame`, which
         * has real frames to ask about; here the point is that holding a frame
         * is not by itself a licence to ask. */
        uint64_t bus = 0;
        check(sys_dma_addr(CAPSLOT_IO_DEVICE, SLOT_FRAME, &bus) == SYS_ERR_PERM,
              "dma-addr-without-cap-io-device");
        check(bus == 0, "dma-addr-wrote-through-on-refusal");
    }

    /* SYS_IRQ_ACK unmasks an interrupt line, which is authority: it decides that
     * a device may interrupt this machine again. A registered line is masked by
     * the kernel the moment it fires and stays masked until acknowledged, so the
     * gate on this call is what stops one task re-enabling a line for hardware it
     * does not hold -- including resurrecting a storm that somebody else's dead
     * driver left behind.
     *
     * Exact SYS_ERR_PERM, and the distinction matters here more than usual:
     * SYS_ERR_INVAL is what an unregistered line returns, so "you may not ask" and
     * "there is nothing to acknowledge" are different answers. Under
     * IRQ_ACK_UNGATED the authority check is gone and this task reaches the
     * second answer, which is what the arm detects. */
    check(sys_irq_ack(CAPSLOT_IO_DEVICE, 1) == SYS_ERR_PERM,
          "irq-ack-without-cap-io-device");
    check(sys_irq_ack(SLOT_FRAME, 1) == SYS_ERR_PERM,
          "irq-ack-with-wrong-cap-type");

    /* SYS_POLL_NOTIFY is sys_wait_notify's non-blocking twin, and being
     * non-blocking changes WHEN the answer comes back, never WHO may ask. It
     * takes the same CAP_NOTIFICATION + READ gate, because a poll that skipped it
     * would let any task consume any other task's badges -- finding C-2 arriving
     * in a new syscall, which is what a "convenience" variant invites.
     *
     * Exact SYS_ERR_PERM: IPC_AGAIN (-2) is this call's own "nothing pending",
     * so `< 0` cannot tell refusal from an empty notification. That distinction
     * is what the ungated arm flips. */
    {
        uint32_t pb = 0;
        check(sys_poll_notify(SLOT_FRAME, &pb) == SYS_ERR_PERM,
              "poll-notify-with-wrong-cap-type");
        /* An empty high slot is refused too -- but note it cannot witness a
         * MISSING gate, because ungated the slot is a raw notification index and
         * 200 is out of range, so it fails either way. The wrong-type check above
         * is the discriminating one: slot 3 is a valid index, so an ungated poll
         * SUCCEEDS there. A refusal test only detects a missing gate where the
         * ungated path would otherwise have worked. */
        check(sys_poll_notify(SLOT_EMPTY_HI, &pb) == SYS_ERR_PERM,
              "poll-notify-without-cap");
        /* And the positive: a notification this task DOES hold answers IPC_AGAIN
         * rather than blocking or refusing. Without this the two refusals above
         * are satisfied by a syscall that rejects everything. */
        check(sys_poll_notify(SLOT_NOTIFY, &pb) == IPC_AGAIN,
              "poll-notify-held-should-be-empty");
    }

    /* SYS_MSI_REGISTER programs the register that decides which interrupt a
     * device raises. This task holds no device capability, so it must be refused
     * before any of that is reached — and note the call takes no vector: there is
     * nowhere in the ABI for a caller to name one, which is S47's mechanism
     * rather than its check. What this asserts is the gate in front of it. */
    check(sys_msi_register(CAPSLOT_IO_DEVICE, SLOT_NOTIFY, 0x1234) == SYS_ERR_PERM,
          "msi-register-without-cap-io-device");
    check(sys_msi_register(SLOT_FRAME, SLOT_NOTIFY, 0x1234) == SYS_ERR_PERM,
          "msi-register-with-wrong-cap-type");

    /* ---- 12. a refused capability operation RETURNS ------------------- */

    /* S52. Every other check in this file asks whether an unauthorised call is
     * REFUSED. These ask the question one step earlier: whether the refusal
     * comes back at all.
     *
     * cap_mint() and cap_transfer() used to resolve the caller's SOURCE slot
     * through a helper that spun forever on a NULL lookup, while holding
     * cap_lock with interrupts masked. All three of the inputs that make
     * cap_lookup return NULL -- out of range, empty, or lacking the right -- are
     * chosen by the caller, and h_cap_mint passes rbx/rcx/rdx through without
     * touching them. So the four negative probes below were, until 2026-08-29,
     * four ways for an unprivileged task to stop the machine.
     *
     * The stall is the whole observable: a task wedged inside a syscall prints
     * nothing, so the arm for this asserts the ABSENCE of `CAPTEST: PASS` rather
     * than a FAIL marker, exactly as smoke-captest-getline-control does.
     *
     * The positive probe is not decoration. Without it these four are satisfied
     * by a syscall that refuses everything, and a mint that refuses everything
     * would pass this section while breaking delegation entirely. Slot 40 is the
     * endpoint this task retyped for itself in section 9, so it carries
     * CAP_RIGHT_MINT and a mint from it must SUCCEED. */
    out("CAPTEST: cap-derivation-probes\n");

    /* Empty slot: a valid index naming nothing. */
    check(sys_cap_mint(203, SLOT_EMPTY_HI, CAP_RIGHT_READ) != 0,
          "mint-from-empty-slot-succeeded");
    /* Out of range: past CNODE_SIZE entirely. */
    check(sys_cap_mint(203, 300, CAP_RIGHT_READ) != 0,
          "mint-from-out-of-range-slot-succeeded");
    /* The same two doors into cap_transfer, which had the identical helper. */
    check(sys_cap_transfer(204, SLOT_EMPTY_HI) != 0,
          "transfer-from-empty-slot-succeeded");
    /* SYS_CAP_MOVE is cap_transfer followed by cap_revoke, so it reaches the
     * same resolver by a different syscall number. */
    check(sys_cap_move(205, SLOT_EMPTY_HI) != 0,
          "move-from-empty-slot-succeeded");

    /* The positive: minting from a capability this task holds, with a right that
     * capability carries, must work. */
    check(sys_cap_mint(203, SLOT_RETYPED_EP, CAP_RIGHT_READ) == 0,
          "mint-from-held-capability-refused");
    /* And the delegate is narrower than its source, never wider: a READ-only
     * mint of an endpoint cannot be sent through. */
    check(sys_ipc_send(203, "x", 1) != 0,
          "read-only-minted-endpoint-accepted-a-send");

    /* ---- 13. a handler the dispatch table admits everyone into --------- */

#ifndef SYSCOV_PROBES_ABSENT
    /* THE DISPATCH TABLE IS NOT THE ONLY GATE, AND FOR THESE ENTRIES IT IS NOT A
     * GATE AT ALL. An `SC_NONE` row means the central check in syscall_handler
     * admits every caller and whatever authority the call needs is tested inside
     * the handler -- so the handler BODY is reachable from ring 3 by a task
     * holding nothing. That is a deliberate design (the device family moved this
     * way with S43, because a gate on a fixed slot cannot ask which device a
     * capability names), and it is also where an unentered handler is most
     * expensive: S52 was four ways for an unprivileged task to wedge the machine,
     * sitting behind three SC_NONE rows nothing had ever executed.
     *
     * .github/syscall-coverage.yml measures which handler BODIES a tracked
     * workload enters, and its reasons for these had all described why the
     * SUCCESS path was not reached -- no CAP_UNTYPED to retype a frame from, no
     * pipeline in the session, login reads its password elsewhere. That is the
     * distinction the manifest's own header says it exists to prevent: none of
     * those sentences is about whether the body runs, and for an SC_NONE row the
     * body runs for anybody who asks.
     *
     * So these probes enter twelve of them. Every one asserts that the answer
     * COMES BACK -- S52's question rather than the usual one -- and every one is
     * chosen to leave this task's state exactly as it found it: brk(0) is the
     * QUERY form and does not move the break, the sigaction probe takes the
     * refusal path and returns before sig_handler is written, and the unmap and
     * region probes name slots holding nothing. This section happens to be last
     * today, so nothing would observe a side effect anyway -- which is exactly
     * why the discipline is written down here rather than relied on, since the
     * next section added below it would inherit the damage silently.
     *
     * Falsified by SYSCOV_PROBES_ABSENT=1, which compiles this section out: the
     * coverage gate must then go red naming these syscalls as listed-covered and
     * not entered. Without that arm a promotion that was free all along -- some
     * other workload already entering the body -- would look identical to one
     * these probes earned. */
    out("CAPTEST: sc-none-handler-probes\n");

    /* (a) The frame family. Its dispatch rows carry no slot and no type, so the
     * whole authority is `cap_lookup` + a CAP_FRAME type test inside each
     * handler -- and a task holding nothing reaches all four of them. */

    /* An empty slot names no capability, so the lookup fails and the handler
     * refuses. This is the reachability claim in its plainest form: slot 200 has
     * never held anything, and the call still had to run a handler to say so. */
    check(sys_frame_pages(SLOT_EMPTY_HI) == SYS_ERR_PERM,
          "frame-pages-on-empty-slot-not-refused");
    check(sys_unmap_frame(SLOT_EMPTY_HI, 0x30000000UL) == SYS_ERR_PERM,
          "unmap-frame-on-empty-slot-not-refused");
    check(sys_map_frame(SLOT_EMPTY_HI, 0x30000000UL, CAP_RIGHT_READ) == SYS_ERR_PERM,
          "map-frame-on-empty-slot-not-refused");

    /* The legacy slot-3 CAP_FRAME is the interesting one, because it passes the
     * type test. It is [C-1]'s decoy: a live capability of exactly the right type
     * whose `object` is USER_AREA_BASE, a virtual address rather than an index
     * into the frame table. What refuses it is the BOUND -- frame_phys_by_index
     * answers 0 for anything outside the table -- and not an allowlist, which is
     * the whole reason S26 is a property rather than a coincidence. Under
     * FRAME_INDEX_UNCHECKED=1 this capability maps physical 0x400000 instead. */
    check(sys_frame_pages(SLOT_FRAME) < 0,
          "frame-pages-answered-for-the-legacy-decoy");
    check(sys_map_frame(SLOT_FRAME, 0x30000000UL, CAP_RIGHT_READ) < 0,
          "map-frame-accepted-the-legacy-decoy");

    /* W^X, refused before any capability is consulted: the request is incoherent
     * on its face, so there is nothing to look up. Checked here rather than left
     * to frametest because it is the one refusal on this path that does not
     * depend on holding -- or not holding -- anything. */
    check(sys_map_frame(SLOT_EMPTY_HI, 0x30000000UL,
                        CAP_RIGHT_WRITE | CAP_RIGHT_EXEC) == SYS_ERR_INVAL,
          "map-frame-accepted-write-plus-exec");

    /* A run of zero frames is refused outright rather than treated as a no-op.
     * SYS_MAP_REGION checks the shape of the whole run before touching anything
     * (S35's all-or-nothing rests on that), so this returns without reaching a
     * capability at all. */
    check(sys_map_region(SLOT_EMPTY_HI, 0, 0x30000000UL, CAP_RIGHT_READ) == SYS_ERR_INVAL,
          "map-region-accepted-a-zero-length-run");
    check(sys_map_region(SLOT_EMPTY_HI, 1, 0x30000000UL, CAP_RIGHT_READ) < 0,
          "map-region-on-empty-slot-not-refused");

    /* (b) SYS_READ, and NOT through fd 0. The first draft of this probe read fd
     * 0 and HUNG THE GATE, which is worth recording because it corrects an
     * assumption this file could easily have shipped: SYS_GET_LINE is `covered`
     * by a refusal, so fd 0 looked like the same shape. It is not. h_get_line
     * tests CAP_CONSOLE inside the handler and refuses captest outright;
     * h_read's fd 0 branch tests no authority at all -- it is ambient console
     * input -- and its only early return is console_hw_owned(). No ring-3 server
     * owns the UART in the captest image, so the call went to console_getc()
     * and waited for a keystroke that never came. A syscall that blocks cannot
     * be probed by a test that has to finish; SYS_GET_PASS has no non-blocking
     * branch at all and stays uncovered for that reason, written down in the
     * manifest rather than left as the reason it looks like.
     *
     * fd >= 3 is the branch that matters anyway. It is the fourth [H-3] door --
     * the one the kernel's own comment calls "the one that MOVES BYTES" -- and
     * `cap_lookup(3, CAP_RIGHT_READ)` was satisfied by the legacy CAP_FRAME
     * every task is born holding, so it handed the in-kernel ramfs to any
     * caller. It was retired on 2026-08-22 to a fail-closed SYS_ERR_NOSYS with
     * the live branch kept under RAMFS_SLOT3_GATE, and nothing has checked since
     * that the ship build still refuses it. */
    {
        char lb[8];
        check(sys_read(3, lb, sizeof(lb)) == SYS_ERR_NOSYS,
              "read-fd3-ramfs-door-not-closed");
        /* Neither an input fd nor the retired range: refused as a bad argument,
         * which is the fail-closed default an unhandled fd must take. */
        check(sys_read(1, lb, sizeof(lb)) == -1,
              "read-fd1-not-refused");
    }

    /* (c) Calls that answer about the CALLER, where there is no authority to
     * test because a task asking about itself is not asking for anything. The
     * assertion is that the answer returns and is stable; asserting a particular
     * value would be asserting how init spawned this task, which is not this
     * file's business. Two reads rather than one, because a handler that wedged
     * or corrupted the frame would not produce the same answer twice. */
    check(sys_spawn_arg() == sys_spawn_arg(),
          "spawn-arg-not-stable-across-two-reads");

    /* brk(0) is the QUERY form: it returns the current break without moving it,
     * so this reads captest's heap without disturbing whatever allocates from it.
     * SYS_BRK's uncovered reason was that newlib's allocator uses SYS_SBRK and
     * "brk is the unused half of the pair" -- a statement about callers, which is
     * not the same statement as whether the handler runs. */
    {
        void *b1 = sys_brk((void *)0);
        void *b2 = sys_brk((void *)0);
        check(b1 != (void *)0, "brk-query-returned-a-null-break");
        check(b1 == b2, "brk-query-moved-the-break");
    }

    {
        struct task_exit_info tei;
        check(sys_task_exit_info(&tei) == 0,
              "task-exit-info-refused-a-task-asking-about-itself");
    }

    /* (d) Signal registration, whose gate is that a handler address must lie
     * inside the CALLER'S OWN image -- a bound, not a capability, and the reason
     * it is SC_NONE. Address 0x1000 is below every image this loader places, so
     * the REFUSAL path is the one taken, which is the deliberate choice twice
     * over: it exercises rust_signal_handler_addr_ok, the check that is actually
     * the gate, and it returns before `sig_handler` is assigned, so the probe
     * cannot leave this task holding a handler it did not have. (captest installs
     * none of its own, so a success would be harmless too -- but "harmless
     * because nothing else uses it" is a fact about the rest of the file, and
     * facts like that stop being true when somebody edits the rest of the file.) */
    check((int)syscall(SYS_SIGACTION, 0x1000ULL, 0, 0) == SYS_ERR_INVAL,
          "sigaction-accepted-a-handler-outside-our-own-image");

    /* SYS_SIGRETURN reaches its dispatch-table stub only when the caller is NOT
     * inside a handler -- interrupt_handler64 intercepts it ahead of the table
     * when `in_signal` is set, because resuming replaces the entire live trap
     * frame and has nothing to do with the table's return convention. captest is
     * not in a handler, so this is the stub, and the stub exists to refuse
     * exactly this: a resume with nothing to resume to. */
    check((int)syscall(SYS_SIGRETURN, 0, 0, 0) == SYS_ERR_INVAL,
          "sigreturn-outside-a-handler-not-refused");

    /* (e) A RETIRED syscall, still holding its ABI slot. Registering a userspace
     * block backend meant the kernel calling ring-3 function pointers from ring
     * 0 -- an SMEP violation and a TCB escape -- so syscall 46 was reduced to a
     * body that returns SYS_ERR_NOSYS and its userspace wrapper was deleted. The
     * number stays reserved so it cannot be reused. Nothing had ever checked
     * that it still fails closed, and a reserved number that quietly starts
     * answering is the fail-open this repository reserves numbers to prevent. */
    check((int)syscall(SYS_REGISTER_STORAGE_BACKEND, 0, 0, 0) == SYS_ERR_NOSYS,
          "retired-storage-backend-syscall-answered");

    /* (f) SYS_IPC_REPLY resolves its endpoint from the capability's own object
     * through ipc_ep_from_slot, which is [C-1]'s fix: the authority is the
     * capability, not the slot number. Both doors into it, an empty slot and a
     * live capability of the wrong type, refuse inside the handler. */
    check(sys_ipc_reply(SLOT_EMPTY_HI, "x", 1) == SYS_ERR_PERM,
          "ipc-reply-on-empty-slot-not-refused");
    check(sys_ipc_reply(SLOT_FRAME, "x", 1) == SYS_ERR_PERM,
          "ipc-reply-accepted-a-frame-capability-as-an-endpoint");
#endif /* SYSCOV_PROBES_ABSENT */


    /* ---- 14. a budget can be SUBDIVIDED, not only shared ---------------- */

    /* S57 said a task given a SMALL REGION can spawn a bounded number of times.
     * That was not implementable when it was written: SYS_CAP_GRANT of a
     * CAP_UNTYPED copies a capability naming the SAME region, so a delegate got
     * its grantor's entire budget and "small region" named nothing anybody could
     * mint. SYS_UNTYPED_SPLIT is the missing half, and these checks are what
     * make the sentence true rather than aspirational.
     *
     * THE PARENT MUST PAY. Every check below is about that: a split that handed
     * out a region without charging the parent would be memory conjured from a
     * syscall, which is exactly what roadmap 0.3 exists to prevent. */
    out("CAPTEST: untyped-split\n");
    {
        struct untyped_info before, after, child;
        check(sys_untyped_info(SLOT_UNTYPED, &before) == 0,
              "untyped-info-before-split-failed");

        const uint64_t TAKE = 64u * 1024u;
        check(sys_untyped_split(SLOT_UNTYPED, SLOT_SPLIT, TAKE) == 0,
              "untyped-split-refused-for-a-region-that-had-room");

        /* The child exists and is the size asked for (rounded up to a page --
         * a sub-region that could not back a frame would mean less than it
         * says). */
        check(sys_untyped_info(SLOT_SPLIT, &child) == 0,
              "split-child-has-no-readable-info");
        check(child.size >= TAKE, "split-child-smaller-than-requested");
        check(child.watermark == 0, "split-child-born-with-bytes-spent");

        /* THE PARENT SHRANK BY AT LEAST WHAT THE CHILD GOT. Stated as an
         * inequality rather than equality because the carve is page-aligned, so
         * the parent may lose alignment padding as well -- but it must never
         * lose LESS than it handed over, which is the direction that would mean
         * the split created memory. */
        check(sys_untyped_info(SLOT_UNTYPED, &after) == 0,
              "untyped-info-after-split-failed");
        check(after.free + child.size <= before.free,
              "split-did-not-charge-the-parent");

        /* And the child is spendable: a region that cannot be retyped from is a
         * budget in name only. Both refusals below are otherwise satisfied by a
         * split that hands back a dead region. */
        check(sys_retype(SLOT_SPLIT, KOBJ_ENDPOINT, 1, SLOT_SPLIT_EP) == 1,
              "split-child-cannot-be-retyped-from");

        /* A split larger than the region has left is refused, and refused
         * WITHOUT charging: the caller asked for something it could not pay for
         * and must be no poorer for having asked. */
        struct untyped_info pre_fail, post_fail;
        check(sys_untyped_info(SLOT_SPLIT, &pre_fail) == 0, "child-info-failed");
        check(sys_untyped_split(SLOT_SPLIT, SLOT_SPLIT2, pre_fail.size * 4) < 0,
              "oversized-split-accepted");
        check(sys_untyped_info(SLOT_SPLIT, &post_fail) == 0, "child-info-failed-2");
        check(post_fail.free == pre_fail.free,
              "refused-split-charged-the-caller-anyway");

        /* A slot holding no untyped cannot split, and neither can one holding a
         * capability of the wrong type -- the [C-1] shape, asked of this syscall
         * as captest asks it of every other. */
        check(sys_untyped_split(SLOT_EMPTY_HI, SLOT_SPLIT2, 4096) == SYS_ERR_PERM,
              "split-from-an-empty-slot-succeeded");
        check(sys_untyped_split(SLOT_FRAME, SLOT_SPLIT2, 4096) == SYS_ERR_PERM,
              "split-from-a-frame-capability-succeeded");
        /* A kernel-reserved destination is refused: the low slots are the
         * kernel's endowment, not a caller's to overwrite. */
        check(sys_untyped_split(SLOT_UNTYPED, 1, 4096) == SYS_ERR_PERM,
              "split-into-a-kernel-reserved-slot-succeeded");
        /* Zero bytes is a caller bug, refused rather than treated as a no-op --
         * a zero-length region would be a capability that can never be spent. */
        check(sys_untyped_split(SLOT_UNTYPED, SLOT_SPLIT2, 0) == SYS_ERR_INVAL,
              "zero-length-split-accepted");
    }

    /* ---- done -------------------------------------------------------- */

    out("CAPTEST: PASS ");
    out_dec((uint64_t)checks);
    out(" checks\n");
    sys_exit();
    for (;;) { }
}
