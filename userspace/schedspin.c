#include "syscall.h"

/*
 * The spinner of make smoke-sched-budget (SCHED_BUDGET_SELFTEST only;
 * docs/design/scheduler.md 3.1, step 4a, S152).
 *
 * schedtest binds this task to a context it carved, then resumes it. It spins
 * for SCHEDSPIN_WALL_TICKS of wall-clock time and counts the distinct 10 ms
 * ticks it saw itself running in, which is the share of the CPU it was given,
 * measured by the task that was given it rather than by the kernel's own
 * accounting. A spinner that never blocks, bound to a fifth of a CPU, sees
 * about a fifth of the ticks; with the budget not enforced it sees nearly all
 * of them, and that is what BUDGET_UNENFORCED=1 must show.
 *
 * Judged here, so the verdict is the spinner's own: the share it saw must be
 * at most SCHEDSPIN_MAX_PCT (the budget, plus a tick of overrun at each end of
 * each burst, plus margin) and at least SCHEDSPIN_MIN_PCT (it ran at all: a
 * spinner that never ran would otherwise pass the bound by saying nothing).
 */
#define SCHEDSPIN_WALL_TICKS 300   /* 3 s */
#define SCHEDSPIN_MAX_PCT    45
#define SCHEDSPIN_MIN_PCT    5

static void report(const char *s) {
    int n = 0; while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

static void report_num(unsigned long v) {
    char b[24]; int i = 23; b[i] = 0;
    if (v == 0) b[--i] = '0';
    while (v) { b[--i] = (char)('0' + v % 10); v /= 10; }
    report(&b[i]);
}

static unsigned long now_ticks(void) {
    struct horus_timespec ts;
    if (sys_clock_gettime(HORUS_CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (unsigned long)ts.sec * 100ul + ts.nsec / 10000000u;
}

void _start(void) {
    unsigned long start = now_ticks(), last = start, seen = 1;
    for (;;) {
        unsigned long t = now_ticks();
        if (t != last) { seen++; last = t; }
        if (t - start >= SCHEDSPIN_WALL_TICKS) break;
    }
    report("SCHEDTEST: spinner saw ");
    report_num(seen);
    report(" of ");
    report_num(SCHEDSPIN_WALL_TICKS);
    report(" ticks\n");
    if (seen * 100 > (unsigned long)SCHEDSPIN_WALL_TICKS * SCHEDSPIN_MAX_PCT)
        report("SCHEDTEST: FAIL budget-overrun the spinner ran on time it was not given\n");
    else if (seen * 100 < (unsigned long)SCHEDSPIN_WALL_TICKS * SCHEDSPIN_MIN_PCT)
        report("SCHEDTEST: FAIL spinner-starved the spinner hardly ran, so the bound measured nothing\n");
    else
        report("SCHEDTEST: budget held\n");
    sys_exit();
}
