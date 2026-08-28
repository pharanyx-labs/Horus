#include "syscall.h"

/*
 * The image a forked child execs INTO -- roadmap 2.3, FORKEXEC_SELFTEST builds
 * only. Half of the `fork` + `exec` pairing; the driver is forkexectest.c, and
 * the reasoning for the whole test lives there.
 *
 * Its job is to be a DIFFERENT program in the same task. It runs after
 * SYS_EXEC_NAMED has replaced the forked child's image in place, so it inherits
 * that child's task id and its cspace and nothing else -- a fresh address space,
 * a fresh stack, and none of the child's variables.
 *
 * ---- IT REPORTS THROUGH THE CAPABILITY GRAPH, NOT THE CONSOLE --------------
 *
 * Every verdict this file reaches is recorded by minting a capability into a
 * known slot, which the driver reads with SYS_CAP_ENUMERATE. The console reports
 * below are commentary for a human reading the boot log; nothing in the gate
 * depends on them, for two reasons.
 *
 * ONE VERDICT PER RUN. A gate decided by pattern-matching two tasks' prose on one
 * wire is decided by whichever line the harness latches first -- which is how the
 * first version of `forktest` printed a FAIL and then a PASS. Recording the
 * finding where the DRIVER can read it keeps the verdict in one place: this task
 * states facts, the driver decides.
 *
 * AND THE CHANNEL IS NOT GUARANTEED TO THIS TASK. In this selftest boot nothing
 * has taken the console, so `sys_write` reaches COM1 through the kernel and even
 * EXEC_RESET_CSPACE=1 can still print -- measured, not assumed. But that is a
 * property of the boot, not of the task: once a ring-3 console server owns the
 * hardware, printing needs the CAP_ENDPOINT in slot 5, which arrives by
 * delegation and is therefore exactly what an exec that rebuilt the cspace would
 * discard. A report that a defect can silence is not a report.
 *
 * The mints are all from slot 0, the CAP_TCB on self that every task is born
 * with, for the matching reason: a signal must not depend on the property being
 * measured. Slot 0 survives even the arm that discards everything else, and it
 * carries CAP_RIGHT_ALL, so it is also the only birth capability SYS_CAP_MINT
 * will accept as a source -- slot 3 and slot 4 lack CAP_RIGHT_MINT, and using
 * one of those made every signal here fail silently while this was being written.
 *
 * FE_SLOT_READY is minted LAST and unconditionally, so it means "I have finished
 * and recorded whatever I found" rather than "I am alive". The driver waits on
 * it and then reads the other two, so a failure here is a missing slot rather
 * than a hang -- and a gate that times out prints no marker at all.
 */

/* Must match userspace/forkexectest.c. */
#define FE_SLOT_READY   27   /* minted last: "my checks are recorded"        */
#define FE_SLOT_ARGV    28   /* the argv staged before the exec survived it  */
#define FE_SLOT_USABLE  29   /* the inherited capability still WORKS         */

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

void _start(void) {
    /* 1. The argv the child staged before the exec must have survived it.
     *
     *    This is what makes the run a fork+exec rather than a fork followed by a
     *    task that happened to start: the strings were copied out of the CHILD's
     *    address space -- itself a copy-on-write clone of its parent's -- while
     *    that space was still live, held in the kernel's staging across a
     *    complete address-space rebuild, and marshalled onto a stack that did not
     *    exist when they were read. Every one of those steps is a place the bytes
     *    could have come from a page the exec had already reclaimed. */
    {
        char **av = 0;
        int ac = sys_get_argv(&av);
        if (ac == 2 && av && streq(av[0], "forkexecee") && streq(av[1], "post-fork")) {
            (void)sys_cap_mint(FE_SLOT_ARGV, CAPSLOT_TCB, CAP_RIGHT_READ);
        } else {
            report("FORKEXEC: FAIL argv\n");
        }
    }

    /* 2. The inherited capability must still WORK, not merely occupy a slot.
     *
     *    SYS_UNTYPED_INFO for forktest's reason: idempotent and READ-only, so the
     *    probe can be repeated and consumes nothing. The capability came to this
     *    task by fork, from a grandparent this program has never met, and then
     *    through an exec -- which is the POSIX property the kernel's exec path
     *    has claimed in a comment since it was written and, until this test,
     *    nothing checked.
     *
     *    The driver checks the same capability's IDENTITY from the outside. Both,
     *    because "the slot still holds something derived from the parent" and
     *    "the thing in the slot still opens the door" are different claims, and
     *    an exec that preserved the graph while breaking the object would satisfy
     *    only the first. */
    {
        struct untyped_info ui;
        if (sys_untyped_info(CAPSLOT_UNTYPED, &ui) == 0) {
            (void)sys_cap_mint(FE_SLOT_USABLE, CAPSLOT_TCB, CAP_RIGHT_READ);
        } else {
            report("FORKEXEC: FAIL exec-lost-inherited-cap\n");
        }
    }

    /* 3. Done. Unconditional and last: this is the barrier the driver waits on,
     *    and it must be reachable from every arm or the arm reports a timeout
     *    instead of a defect. Minting it cannot fail for a reason the driver
     *    would misread -- slot 0 is the birth endowment -- but if it somehow did,
     *    the driver's wait expires with its own named marker. */
    (void)sys_cap_mint(FE_SLOT_READY, CAPSLOT_TCB, CAP_RIGHT_READ);

    /* Park. The driver reads this task's cspace while it is ALIVE and then kills
     * it: a dead task reports every slot empty (see the SYS_CAP_ENUMERATE
     * handler), which would satisfy the driver's "the capability is gone" arm for
     * entirely the wrong reason. Parking rather than exiting is load-bearing. */
    for (;;) sys_yield();
}
