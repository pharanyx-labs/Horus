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
#define SLOT_CTX_FINE         48
#define SLOT_CTX_NINE         49   /* step 3c: nine tenths, for the counter */
#define SLOT_CTX_HOME         50   /* step 3c: a BSP-only context for this task */
#define SLOT_CTX_X            51   /* step 3c: this task's, beside the counter */
#define SLOT_CTX_Y            52   /* step 3c: the counter's, delayed by X */
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

/* The share of its CPU the context at `slot` was charged over the next `n`
 * ticks, in thousandths, or -1. SYS_SCHED_INFO reports to the tick, so over
 * 300 ticks this is good to a few thousandths. */
static long share_permille(uint32_t slot, unsigned long n) {
    struct sched_info si;
    if (sys_sched_info(slot, &si) != 0) return -1;
    unsigned long c0 = si.consumed_us, t0 = now_ticks();
    wait_ticks(n);
    if (sys_sched_info(slot, &si) != 0) return -1;
    unsigned long dt = now_ticks() - t0;
    return dt ? (long)((si.consumed_us - c0) / (dt * 10ul)) : -1;
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

    /* S154 (step 4b): among budgeted work the higher priority runs, and a yield
     * lets in only its equals. The counter is lowered to 100 and this task, at
     * the top, binds itself beside it on the counter's context. Once this task
     * has yielded it can be running only on that context's CPU, so from then on
     * the counter runs only if this task gives way to it, which it must not.
     * PRIO_IGNORED=1 takes the first candidate whatever its priority, and the
     * counter counts. Then this task goes back to the BSP's root. */
    rc = sys_sched_set_priority(count, 100, 100);
    expect(rc == 0, "lower-the-counter", rc);
    rc = sys_sched_get_priority(count);
    expect(rc == ((100 << 8) | 100), "the-counter-was-lowered", rc);
    rc = sys_sched_bind(sys_getpid(), SLOT_CTX2);
    expect(rc == 0, "bind-this-task-beside-the-counter", rc);
    wait_ticks(5);                        /* now on the counter's CPU */
    unsigned long p1 = *ctr;
    wait_ticks(30);
    unsigned long p2 = *ctr;
    rc = sys_sched_bind(sys_getpid(), CAPSLOT_SCHED_ROOT_FIRST);
    expect(rc == 0, "bind-this-task-back-to-the-bsp-root", rc);
    expect(p2 == p1, "a-lower-priority-task-ran-while-a-higher-one-could", (long)(p2 - p1));
    wait_ticks(30);
    expect(*ctr > p2, "the-lowered-counter-runs-again-once-alone", (long)(*ctr - p2));
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

    /* Step 3b: a budget ends when it runs out, not at the next tick. The
     * counter, still on this CPU, is given 1 ms every 100 ms and counts the
     * distinct ticks it runs in over 300 (30 periods). Ended at its deadline it
     * runs in every period, a millisecond each, in about one tick or two. Ended
     * at the next tick, each run takes up to 10 ms and the debt is repaid by
     * about nine periods with none, so it runs in some three periods of the 30
     * and sees about six ticks: DEADLINE_UNARMED=1. Here last, so the index-
     * reuse check above sees no context but its own come and go. */
    rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CTX_FINE, 1000, 100000, 0);
    expect(rc == 0, "split-a-millisecond", rc);
    ctr[7] = 0;
    ctr[1] = 4;
    rc = sys_sched_bind(count, SLOT_CTX_FINE);
    expect(rc == 0, "bind-the-counter-to-a-millisecond", rc);
    wait_ticks(300);
    unsigned long fine = ctr[7];
    ctr[1] = 3;
    report("SCHEDTEST: a millisecond every 100 ms ran in ");
    report_num((long)fine);
    report(" of 300 ticks\n");
    expect(fine >= 15, "a-small-budget-ran-in-bursts-of-a-tick", (long)fine);
    expect(fine <= 90, "a-small-budget-ran-beyond-its-share", (long)fine);
    rc = sys_cap_revoke(SLOT_CTX_FINE);
    expect(rc == 0, "revoke-the-millisecond", rc);
    rc = sys_cap_revoke(SLOT_CTX3);
    expect(rc == 0, "revoke-the-reused-index", rc);

    /* Step 3c: a refill is noticed when it is due. The counter is given 9 ms
     * every 10 ms on its CPU, and this task moves to a context of the BSP that
     * has no slack right, so it cannot run there and notice the refill at its
     * own choices (as its yields did in every phase above). With the refill
     * armed the counter runs nine tenths of the time. Noticed at the CPU's
     * next tick instead, it runs 9 ms of every 19 or so, about half:
     * REFILL_UNARMED=1. Measured under TCG: 903 to 910 in 8 boots, the arm
     * 496. On one CPU there is no CPU to move to; skipped. */
    if (cpu == 0) {
        report("SCHEDTEST: one CPU, the refill checks are skipped\n");
    } else {
        rc = sys_sched_split(CAPSLOT_SCHED_ROOT_FIRST, CAPSLOT_UNTYPED, SLOT_CTX_HOME, 50000, 100000, 0);
        expect(rc == 0, "split-a-bsp-context-for-this-task", rc);
        rc = sys_sched_bind(sys_getpid(), SLOT_CTX_HOME);
        expect(rc == 0, "bind-this-task-to-the-bsp", rc);
        rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CTX_NINE, 9000, 10000, 0);
        expect(rc == 0, "split-nine-tenths", rc);
        rc = sys_sched_bind(count, SLOT_CTX_NINE);
        expect(rc == 0, "bind-the-counter-to-nine-tenths", rc);
        wait_ticks(5);
        long nine = share_permille(SLOT_CTX_NINE, 300);
        rc = sys_sched_bind(sys_getpid(), CAPSLOT_SCHED_ROOT_FIRST);
        expect(rc == 0, "bind-this-task-back-from-the-bsp-context", rc);
        report("SCHEDTEST: nine tenths alone ran ");
        report_num(nine);
        report(" thousandths\n");
        expect(nine >= 750, "a-refill-waited-for-the-next-tick", nine);
        expect(nine <= 950, "nine-tenths-ran-beyond-its-share", nine);
        rc = sys_cap_revoke(SLOT_CTX_NINE);
        expect(rc == 0, "revoke-nine-tenths", rc);
        rc = sys_cap_revoke(SLOT_CTX_HOME);
        expect(rc == 0, "revoke-the-bsp-context", rc);

        /* A run that crosses the end of its period is charged to both. This
         * task, at the top priority, takes 7 ms of every 20 on the counter's
         * CPU; the counter, lowered to 100 above, has 5 ms of every 10. Every
         * other period of the counter's starts while this task runs, so the
         * counter starts 7 ms into it with all 5 left, and its run crosses the
         * period's end before the CPU's next tick (each interrupt pushes that
         * 10 ms out). Split at the end, it runs 3 ms there and 5 in the next:
         * 8 ms in 20, four tenths. Charged whole to the first period, it then
         * has the next period's 5 besides and runs 10 in 20, half:
         * BOUNDARY_UNSPLIT=1. A tick between the start and the end would
         * restamp the run and hide the defect, which is why the periods are
         * this short: a choice charges what ran since the last, so a whole
         * charge gives away only the time since the last choice before the
         * period's end. The same phase sees the counter start at once when
         * this task's budget ends: judged before it was charged, this task
         * looked budgeted still, kept the CPU, and the counter waited for the
         * CPU's next interrupt, under three tenths in all: CHARGE_AFTER_PICK=1.
         * Measured under TCG, 8 boots: 392 to 403; the arms 506 (4 of 4) and
         * 283 to 300 (4 of 4). */
        rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CTX_X, 7000, 20000, 0);
        expect(rc == 0, "split-seven-in-twenty", rc);
        rc = sys_sched_split(root, CAPSLOT_UNTYPED, SLOT_CTX_Y, 5000, 10000, 0);
        expect(rc == 0, "split-five-in-ten", rc);
        rc = sys_sched_bind(count, SLOT_CTX_Y);
        expect(rc == 0, "bind-the-counter-to-five-in-ten", rc);
        rc = sys_sched_bind(sys_getpid(), SLOT_CTX_X);
        expect(rc == 0, "bind-this-task-beside-it", rc);
        wait_ticks(5);
        long half = share_permille(SLOT_CTX_Y, 300);
        rc = sys_sched_bind(sys_getpid(), CAPSLOT_SCHED_ROOT_FIRST);
        expect(rc == 0, "bind-this-task-back-to-the-bsp-root-again", rc);
        report("SCHEDTEST: five in ten, delayed, ran ");
        report_num(half);
        report(" thousandths\n");
        expect(half <= 450, "a-run-across-a-period-end-was-charged-to-one-period", half);
        expect(half >= 345, "a-task-out-of-budget-kept-its-cpu-over-a-lower-priority", half);
        rc = sys_cap_revoke(SLOT_CTX_Y);
        expect(rc == 0, "revoke-five-in-ten", rc);
        rc = sys_cap_revoke(SLOT_CTX_X);
        expect(rc == 0, "revoke-seven-in-twenty", rc);
    }

    report("SCHEDTEST: PASS ");
    report_num(checks);
    report(" checks\n");
    sys_exit();
}
