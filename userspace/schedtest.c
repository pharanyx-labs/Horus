#include "syscall.h"

/*
 * make smoke-sched-budget (SCHED_BUDGET_SELFTEST only): scheduling contexts,
 * docs/design/scheduler.md 3.1, step 4a. S152 and S153.
 *
 * The kernel hands this task what init has: a CAP_UNTYPED and each schedulable
 * CPU's root context at CAPSLOT_SCHED_ROOT_FIRST + cpu. It also holds a CAP_TCB
 * to a suspended spinner (schedspin) at SCHEDTEST_SLOT_SPIN, whose task id is
 * this task's spawn argument.
 *
 * It carves a fifth of the last schedulable CPU, with no slack right, checks
 * every refusal the split and the bind owe, binds the spinner to that fifth,
 * resumes it and waits; the spinner reports the share it saw. Then it revokes
 * the context and checks the fifth went back to the root.
 */
#define SCHEDTEST_SLOT_SPIN   29
#define SCHEDTEST_SLOT_COUNT  30   /* CAP_TCB to schedcount */
#define SLOT_FRAME            44
#define SLOT_CTX2             45
#define SLOT_CTX3             46
#define SLOT_UT_COUNT         47
#define COUNT_VA              0x0000000030000000UL
#define SLOT_CHILD            40
#define SLOT_CHILD_RO         41
#define SLOT_GRANDCHILD       42
#define SLOT_SCRATCH          43

static int checks = 0;

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

static void report_num(long v) {
    char b[24]; int i = 23; b[i] = 0;
    int neg = v < 0; unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
    if (u == 0) b[--i] = '0';
    while (u) { b[--i] = (char)('0' + u % 10); u /= 10; }
    if (neg) b[--i] = '-';
    report(&b[i]);
}

/* One write, so no other task's output can land inside the marker a gate
 * asserts (docs/LIMITATIONS.md 2.6a). */
static void fail(const char *what, long got) {
    char line[160];
    int n = 0;
    const char *parts[2] = { "SCHEDTEST: FAIL ", what };
    for (int p = 0; p < 2; p++)
        for (const char *c = parts[p]; *c && n < 120; c++) line[n++] = *c;
    const char *g = " (got ";
    while (*g) line[n++] = *g++;
    char num[24]; int i = 23; num[i] = 0;
    int neg = got < 0; unsigned long u = neg ? (unsigned long)(-got) : (unsigned long)got;
    if (u == 0) num[--i] = '0';
    while (u) { num[--i] = (char)('0' + u % 10); u /= 10; }
    if (neg) num[--i] = '-';
    for (char *c = &num[i]; *c; c++) line[n++] = *c;
    line[n++] = ')';
    line[n++] = '\n';
    sys_write(1, line, (unsigned)n);
    sys_exit();
}

static void expect(int ok, const char *what, long got) {
    if (!ok) fail(what, got);
    checks++;
}

static unsigned long now_ticks(void) {
    struct horus_timespec ts;
    if (sys_clock_gettime(HORUS_CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (unsigned long)ts.sec * 100ul + ts.nsec / 10000000u;
}

/* Wait `n` ticks of wall time, yielding, so the CPUs keep running the others. */
static void wait_ticks(unsigned long n) {
    unsigned long start = now_ticks();
    while (now_ticks() - start < n) sys_yield();
}

void _start(void) {
    uint32_t arg = sys_spawn_arg();
    int spin  = (int)(arg & 0xFFFF);
    int count = (int)(arg >> 16);
    struct sched_info si;

    /* The last CPU that schedules: its root is the one carved. */
    int cpu = -1;
    for (int c = 7; c >= 0 && cpu < 0; c--)
        if (sys_sched_info(CAPSLOT_SCHED_ROOT_FIRST + (uint32_t)c, &si) == 0) cpu = c;
    expect(cpu >= 0, "no-root-context", cpu);
    uint32_t root = CAPSLOT_SCHED_ROOT_FIRST + (uint32_t)cpu;
    report("SCHEDTEST: carving cpu ");
    report_num(cpu);
    report("\n");

    int rc = sys_sched_info(root, &si);
    expect(rc == 0 && si.share_ppm == 1000000 && si.cpu == (uint32_t)cpu,
           "root-holds-a-whole-cpu", rc ? rc : (long)si.share_ppm);

    /* Malformed requests are refused and take nothing. */
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_SCRATCH, 100001, 100000, 0);
    expect(rc == SYS_ERR_INVAL, "budget-above-period-refused", rc);
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_SCRATCH, 0, 100000, 0);
    expect(rc == SYS_ERR_INVAL, "zero-budget-refused", rc);
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_SCRATCH, 1000, 9999, 0);
    expect(rc == SYS_ERR_INVAL, "period-below-a-tick-refused", rc);
    rc = sys_sched_split(SLOT_SCRATCH, CAPSLOT_UNTYPED, SLOT_CHILD, 1000, 100000, 0);
    expect(rc == SYS_ERR_PERM, "split-from-nothing-refused", rc);

    /* A fifth of the CPU, no slack right. */
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CHILD, 20000, 100000, 0);
    expect(rc == 0, "split-a-fifth", rc);
    rc = sys_sched_info(SLOT_CHILD, &si);
    expect(rc == 0 && si.share_ppm == 200000 && si.budget_us == 20000 &&
           si.cpu == (uint32_t)cpu && !(si.flags & SC_FLAG_SLACK),
           "child-holds-a-fifth", rc ? rc : (long)si.share_ppm);
    rc = sys_sched_info(root, &si);
    expect(rc == 0 && si.share_ppm == 800000, "root-gave-a-fifth", rc ? rc : (long)si.share_ppm);

    /* S152: a split never creates time. The root has four fifths; asking it for
     * more is refused, and the slack right cannot be asked of a child without it. */
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_SCRATCH, 90000, 100000, 0);
    expect(rc == SYS_ERR_NOMEM, "split-beyond-the-share-refused", rc);
    rc = sys_sched_split(SLOT_CHILD, CAPSLOT_UNTYPED, SLOT_GRANDCHILD, 1000, 100000, SC_FLAG_SLACK);
    expect(rc == SYS_ERR_PERM, "slack-right-never-widens", rc);
    rc = sys_sched_info(SLOT_CHILD, &si);
    expect(rc == 0 && si.share_ppm == 200000, "refusals-took-nothing", rc ? rc : (long)si.share_ppm);

    /* Rights: a READ-only copy reports, and can neither split nor bind. */
    rc = sys_cap_mint(SLOT_CHILD_RO, SLOT_CHILD, CAP_RIGHT_READ);
    expect(rc == 0, "mint-read-only", rc);
    rc = sys_sched_info(SLOT_CHILD_RO, &si);
    expect(rc == 0, "read-only-reports", rc);
    rc = sys_sched_split(SLOT_CHILD_RO, CAPSLOT_UNTYPED, SLOT_GRANDCHILD, 1000, 100000, 0);
    expect(rc == SYS_ERR_PERM, "read-only-cannot-split", rc);
    rc = sys_sched_bind(spin, SLOT_CHILD_RO);
    expect(rc == SYS_ERR_PERM, "read-only-cannot-bind", rc);

    /* Binding needs a CAP_TCB to the task: this task holds one for itself and
     * one for the spinner and the counter, and none for any other id. Refused before the
     * target's state is looked at, so whether that id is a live task does not
     * matter. */
    int other = 1;
    while (other == spin || other == count || other == sys_getpid()) other++;
    rc = sys_sched_bind(other, SLOT_CHILD);
    expect(rc == SYS_ERR_PERM, "bind-without-a-tcb-refused", rc);

    /* S153: the spinner runs on its fifth and no more. */
    rc = sys_sched_bind(spin, SLOT_CHILD);
    expect(rc == 0, "bind-the-spinner", rc);
    rc = sys_task_resume(spin);
    expect(rc == 0, "resume-the-spinner", rc);
    rc = sys_wait(spin);
    expect(rc == 0, "wait-for-the-spinner", rc);
    rc = sys_sched_info(SLOT_CHILD, &si);
    expect(rc == 0 && si.consumed_us > 0, "the-fifth-was-charged", rc ? rc : (long)si.consumed_us);
    report("SCHEDTEST: the fifth was charged ");
    report_num((long)si.consumed_us);
    report(" us\n");

    /* Revoking the context gives its share back to the root. */
    rc = sys_cap_revoke(SLOT_CHILD);
    expect(rc == 0, "revoke-the-fifth", rc);
    rc = sys_sched_info(SLOT_CHILD_RO, &si);
    expect(rc == SYS_ERR_PERM, "derived-copy-revoked", rc);
    rc = sys_sched_info(root, &si);
    expect(rc == 0 && si.share_ppm == 1000000, "the-fifth-came-back", rc ? rc : (long)si.share_ppm);

    /* Answer 3 (2026-10-17): a revoked context's tasks stop, and stay stopped
     * when its index is used again. schedcount spins on a context of its own,
     * counting in a frame this task maps too. The context is revoked; the count
     * must stop. Then a new context is carved, which takes the freed index, and
     * the count must STILL not move: a task left bound to a dead index would
     * now be running on the new context's time, which nobody gave it.
     * SC_DESTROY_KEEPS_TASKS=1 is that defect. */
    rc = sys_retype(CAPSLOT_UNTYPED, KOBJ_FRAME, 1, SLOT_FRAME);
    expect(rc == 1, "retype-counter-frame", rc);
    rc = sys_map_frame(SLOT_FRAME, COUNT_VA, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
    expect(rc == 0, "map-counter-frame", rc);
    rc = sys_cap_grant(count, SLOT_FRAME, 20);
    expect(rc == 0, "grant-counter-frame", rc);
    volatile unsigned long *ctr = (volatile unsigned long *)COUNT_VA;
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CTX2, 50000, 100000, 0);
    expect(rc == 0, "split-for-the-counter", rc);
    rc = sys_sched_bind(count, SLOT_CTX2);
    expect(rc == 0, "bind-the-counter", rc);
    /* What the counter needs to unbind itself (schedcount.c): a copy of its
     * context to carve from, and a megabyte of untyped memory for that and for
     * its forks' cspaces. */
    rc = sys_cap_grant(count, SLOT_CTX2, 21);
    expect(rc == 0, "grant-the-counter-its-context", rc);
    rc = sys_untyped_split(CAPSLOT_UNTYPED, SLOT_UT_COUNT, 1u << 20);
    expect(rc == 0, "split-untyped-for-the-counter", rc);
    rc = sys_cap_grant(count, SLOT_UT_COUNT, CAPSLOT_UNTYPED);
    expect(rc == 0, "grant-the-counter-untyped", rc);
    rc = sys_task_resume(count);
    expect(rc == 0, "resume-the-counter", rc);
    wait_ticks(30);
    expect(*ctr > 0, "the-counter-runs-on-its-context", (long)*ctr);

    /* A task whose context is revoked while it runs forks before its CPU next
     * chooses: no child may run (create_task gives a child of an unbound task
     * no context). The counter does it to itself, so the forks land in that
     * moment every time; a round in which none did is retried, up to three. */
    int rounds = 0;
    for (; rounds < 3 && ctr[4] == 0; rounds++) {
        ctr[1] = 1;
        wait_ticks(10);
        expect(ctr[5] == 0, "the-counter-could-unbind-itself", (long)ctr[5]);
        if (ctr[4] == 0) {                /* inconclusive: run it again */
            ctr[1] = 0;
            rc = sys_sched_bind(count, SLOT_CTX2);
            expect(rc == 0, "rebind-the-counter-for-another-round", rc);
            wait_ticks(5);
        }
    }
    expect(ctr[4] > 0, "inconclusive-no-fork-ran-while-unbound-in-three-rounds",
           ctr[6] ? (long)ctr[6] : rounds);
    wait_ticks(30);
    expect(ctr[2] == 0, "no-child-of-an-unbound-task-runs", (long)ctr[2]);
    ctr[1] = 3;                           /* stop forking */
    rc = sys_sched_bind(count, SLOT_CTX2);
    expect(rc == 0, "rebind-the-counter", rc);
    wait_ticks(30);
    unsigned long c1 = *ctr;
    expect(c1 > 0, "the-counter-runs-again-once-bound", (long)c1);
    rc = sys_cap_revoke(SLOT_CTX2);
    expect(rc == 0, "revoke-the-counter-context", rc);
    wait_ticks(5);                       /* its CPU's next tick takes it off */
    unsigned long c2 = *ctr;
    wait_ticks(30);
    unsigned long c3 = *ctr;
    expect(c3 == c2, "a-revoked-context-task-stopped", (long)(c3 - c2));
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CTX3, 50000, 100000, 0);
    expect(rc == 0, "split-a-new-context", rc);
    wait_ticks(30);
    unsigned long c4 = *ctr;
    expect(c4 == c3, "a-revoked-context-task-stays-stopped-when-its-index-is-reused",
           (long)(c4 - c3));

    report("SCHEDTEST: PASS ");
    report_num(checks);
    report(" checks\n");
    sys_exit();
}
