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
#define SLOT_FRAME      3
#define SLOT_ENDPOINT   4
#define SLOT_ENDPOINT2  5
#define SLOT_BLOCKDEV   7    /* deliberately not held */
#define SLOT_EMPTY_HI   200  /* never populated */

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

    /* ---- 4. IPC is capability-gated ---------------------------------- */

    /* Slot 4 is a real endpoint, so a non-blocking recv on it is legitimate: it
     * either finds nothing (would-block) or a message, but must not be refused
     * for lack of authority. */
    char msg[64];
    int rc = sys_ipc_recv(SLOT_ENDPOINT, msg, sizeof(msg));
    check(rc == -2 || rc >= 0, "ipc-recv-on-held-endpoint-refused");

    /* Slot 7 holds no endpoint, so the same call must be refused. */
    check(sys_ipc_recv(SLOT_BLOCKDEV, msg, sizeof(msg)) < 0,
          "ipc-recv-on-unheld-slot-allowed");

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
    check(sys_cap_grant(1 << 20, SLOT_ENDPOINT, 20) != 0,
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
    check(sys_cap_revoke(SLOT_ENDPOINT2) != 0, "revoke-succeeded-without-revoke-right");

    /* A refused operation must have no side effects: the endpoint it declined to
     * revoke has to still work. A partial revoke that fails the rights check
     * after clearing the slot would pass the check above and break this one. */
    rc = sys_ipc_recv(SLOT_ENDPOINT2, msg, sizeof(msg));
    check(rc == -2 || rc >= 0, "endpoint-broken-by-refused-revoke");

    /* The unrelated endpoint is likewise untouched. */
    rc = sys_ipc_recv(SLOT_ENDPOINT, msg, sizeof(msg));
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
