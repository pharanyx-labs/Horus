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
 * 4 and 5 = CAP_ENDPOINT. Slot 7 (CAP_BLOCK_DEV) and slot 6 (CAP_USER admin)
 * are NOT granted by default, which is what makes them useful negative probes.
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
#define SLOT_EMPTY_HI   200  /* never populated */

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

    /* Reading another task's info is admin-gated; task 0 is the kernel's own.
     * Without CAP_USER this must be refused rather than answered. */
    if (sys_getuid() != 0) {
        struct task_info other;
        check(sys_get_task_info(0, &other) != 0, "task-info-other-allowed-without-admin");
    }

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
    unsigned char blk[512];
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

    /* ---- done -------------------------------------------------------- */

    out("CAPTEST: PASS ");
    out_dec((uint64_t)checks);
    out(" checks\n");
    sys_exit();
    for (;;) { }
}
