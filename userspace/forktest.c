#include "syscall.h"

/*
 * fork(2) self-test driver -- roadmap 2.3, FORK_SELFTEST builds only.
 *
 * Asserts, entirely from ring 3, the two properties SYS_FORK is supposed to
 * have and the one it is supposed to refuse:
 *
 *   S39  A forked child's memory is a COPY of its parent's, not a share. Each
 *        side sees the bytes that existed at the fork, and neither side's later
 *        writes are visible to the other.
 *   S40  A fork never shares a kernel object's page: a task with a CAP_FRAME
 *        mapped is refused, and refused for THAT reason -- unmapping it makes
 *        the same call succeed.
 *   S41  A forked child inherits its parent's capabilities as DERIVED copies:
 *        each has its own serial and names the parent's capability as its badge,
 *        so the child's authority is a subtree of the parent's and fork adds no
 *        new root to the capability graph.
 *
 * ---- WHY THE TWO DIRECTIONS ARE TESTED DIFFERENTLY -------------------------
 *
 * Child-writes-are-invisible-to-parent is easy and exact: the child writes and
 * exits, the parent sys_wait()s -- a real happens-before -- and then reads. No
 * timing assumption at all.
 *
 * Parent-writes-are-invisible-to-child has no such rendezvous, because a forked
 * child shares nothing through which the two could synchronise (that is the
 * point of the test). Asserting the ABSENCE of a value needs the parent's write
 * to have definitely happened first, so the child spins reading the page for a
 * bounded number of iterations, yielding, while the parent writes immediately
 * after the fork returns. Under a kernel that shared the page writably the child
 * observes the new value and says so; under a correct one it never can, and the
 * spin simply expires. The bound makes the test terminate; it does not make the
 * assertion probabilistic, because a miss is only ever a miss in the direction
 * of PASSING the shared-page arm -- and FORK_SHARE_WRITABLE=1 is run to confirm
 * it does not.
 *
 * Both directions are in fact one PTE operation (clone_user_aspace downgrades
 * the parent's leaf and the child's alike), so an arm that breaks one breaks
 * both; the second check exists because "in fact one operation" is a fact about
 * today's implementation, which is exactly the class of thing this repository
 * has been bitten by asserting.
 *
 * Markers: "FORKTEST: PASS" / "FORKTEST: FAIL <what>". No run may print both: a
 * failing child dies rather than exits, and the parent refuses its verdict on
 * seeing that. See child_fail() for why that mechanism, and what happened
 * without it.
 */

#define FORKTEST_SLOT_FRAME  20   /* must match src/kernel/selftest.c */

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* ---- HOW A CHILD-SIDE FAILURE REACHES THE VERDICT -------------------------
 *
 * A forked child shares NOTHING with its parent through which it could report
 * -- that is the property under test -- so a child that fails cannot simply say
 * so and exit: the parent's sys_wait() would return, the parent would find its
 * own checks satisfied, and the run would print FORKTEST: PASS with a FAIL
 * already on the wire above it. That is not a hypothetical. It is what the first
 * version of this test did under FORK_SHARE_WRITABLE=1, and a gate that emits
 * both verdicts is decided by whichever the harness happens to latch first.
 *
 * So a failing child DIES rather than exits: it writes through a null pointer,
 * which the kernel turns into TASK_EXIT_PAGEFAULT, and the parent reads that
 * back with sys_task_exit_info() after the wait. The one channel a forked child
 * still has to its parent is the manner of its death, and it is enough.
 *
 * The parent's own failures just report and exit -- there is nothing after them
 * that could print a PASS. */
static void child_fail(const char *s) {
    report(s);
    *(volatile unsigned char *)0 = 1;   /* die abnormally; the parent reads why */
    for (;;) sys_yield();               /* unreachable */
}

/* Long enough that the parent's post-fork write lands well inside it on any
 * host this runs on, short enough that a correct kernel's expiry is not felt.
 * The yield is what makes it work at -smp 1: without it the child would hold
 * the CPU until preempted and the parent might not have run at all. */
#define WATCH_ITERS 20000

void _start(void) {
    volatile unsigned char *base = (volatile unsigned char *)sys_sbrk(0x4000);
    if (base == (void *)-1 || base == 0) {
        report("FORKTEST: FAIL sbrk\n"); sys_exit();
    }

    volatile unsigned char *p = base + 0x1000;   /* child writes this one   */
    volatile unsigned char *q = base + 0x2000;   /* parent writes this one  */

    /* Write both BEFORE the fork, so each already has a private frame and the
     * clone is exercising the general non-zero COW path rather than re-sharing
     * the immortal zero page. (The zero-page path is smoke-cow's job.) */
    p[0] = 0xA1;
    q[0] = 0x11;

    int child = sys_fork();
    if (child < 0) { report("FORKTEST: FAIL fork\n"); sys_exit(); }

    if (child == 0) {
        /* ---- the child ---- */

        /* 1. It must see the pre-fork bytes. A clone that handed the child fresh
         *    zeroed pages would be isolated but would not be a fork. `q` is
         *    deliberately NOT checked here: the parent writes it immediately
         *    after the fork, so a shared page shows up in check 3 with a name
         *    that says what happened, rather than here as "lost image". */
        if (p[0] != 0xA1) child_fail("FORKTEST: FAIL child-lost-image\n");

        /* 2. Its own write must stick, on its own private copy. Done BEFORE the
         *    watch below, so that on a shared-page kernel the parent's
         *    parent-clobbered check has something to find -- an arm that kills
         *    the child before it can write would leave that check unexercised. */
        p[0] = 0xB2;
        if (p[0] != 0xB2) child_fail("FORKTEST: FAIL child-write-lost\n");

        /* 3. An inherited capability must actually WORK, not merely occupy a
         *    slot. SYS_UNTYPED_INFO is the probe because it is idempotent and
         *    READ-only -- a retype would consume the region and could not be
         *    repeated. Before this commit the child's cspace held only what
         *    create_task installs plus a console endpoint, so this failed. */
        {
            struct untyped_info ui;
            if (sys_untyped_info(CAPSLOT_UNTYPED, &ui) != 0)
                child_fail("FORKTEST: FAIL child-cannot-use-inherited-cap\n");
        }

        /* 4. The parent's post-fork write must never become visible here. */
        for (int i = 0; i < WATCH_ITERS; i++) {
            if (q[0] != 0x11) child_fail("FORKTEST: FAIL child-saw-parent-write\n");
            sys_yield();
        }
        sys_exit();
    }

    /* ---- the parent ---- */

    /* Immediately, so it is in flight while the child is watching q. */
    q[0] = 0x22;

    if (sys_wait(child) != 0) { report("FORKTEST: FAIL wait\n"); sys_exit(); }

    /* 4. The child wrote 0xB2 over its copy of p. The parent must still read the
     *    value it wrote before the fork. This is the check FORK_SHARE_WRITABLE=1
     *    fails: with the leaves left writable there is one frame, and the child's
     *    write is sitting in it. */
    if (p[0] != 0xA1) {
        report("FORKTEST: FAIL parent-clobbered\n"); sys_exit();
    }
    /* 5. And the parent's own post-fork write is still there -- i.e. the check
     *    above is reading a live page, not a stale mapping. */
    if (q[0] != 0x22) {
        report("FORKTEST: FAIL parent-write-lost\n"); sys_exit();
    }

    /* 6. The child's verdict. Checked AFTER the parent's own memory checks, so a
     *    kernel that fails both reports both -- the parent-side statement of S39
     *    is the one a control arm names, and it would go unexercised if a dead
     *    child short-circuited the run here. */
    {
        struct task_exit_info ti;
        if (sys_task_exit_info(&ti) != 0) {
            report("FORKTEST: FAIL exit-info\n"); sys_exit();
        }
        if (ti.reason != TASK_EXIT_NORMAL) {
            report("FORKTEST: FAIL child-died\n"); sys_exit();
        }
    }

    /* ---- S40: a mapped kernel object refuses the fork -------------------- */

    /* Retype one page of the caller's own untyped region into a KOBJ_FRAME and
     * map it. The frame's page comes from the untyped arena, which is what
     * clone_user_aspace tests for. */
    if (sys_retype(CAPSLOT_UNTYPED, KOBJ_FRAME, 1, FORKTEST_SLOT_FRAME) != 1) {
        report("FORKTEST: FAIL retype\n"); sys_exit();
    }
    unsigned long fva = (unsigned long)(base + 0x3000);
    if (sys_map_frame(FORKTEST_SLOT_FRAME, fva, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) {
        report("FORKTEST: FAIL map-frame\n"); sys_exit();
    }

    int refused = sys_fork();
    if (refused == 0) {
        /* Reached only under FORK_ARENA_UNCHECKED=1: we are the child of a fork
         * that should not have happened. Say so from here, because the parent
         * cannot distinguish "refused" from "succeeded and the child said
         * nothing". Exit rather than continue -- this child shares a kernel
         * object's page with its parent, which is the whole defect. */
        report("FORKTEST: FAIL forked-with-frame-mapped\n");
        sys_exit();
    }
    if (refused > 0) {
        report("FORKTEST: FAIL forked-with-frame-mapped\n");
        (void)sys_wait(refused);
        sys_exit();
    }

    /* And the refusal must be about the FRAME, not about fork having stopped
     * working: unmap and the identical call succeeds. Without this the arm would
     * be satisfied by a kernel whose fork always failed. */
    if (sys_unmap_frame(FORKTEST_SLOT_FRAME, fva) != 0) {
        report("FORKTEST: FAIL unmap-frame\n"); sys_exit();
    }
    int again = sys_fork();
    if (again < 0) { report("FORKTEST: FAIL fork-after-unmap\n"); sys_exit(); }
    if (again == 0) sys_exit();          /* the second child has nothing to do */
    if (sys_wait(again) != 0) { report("FORKTEST: FAIL wait2\n"); sys_exit(); }

    /* ---- S41: the child's capabilities are DERIVED, not duplicated -------
     *
     * Checked STRUCTURALLY, through SYS_CAP_ENUMERATE, rather than by revoking
     * something and seeing what breaks. `cap_info` reports `serial` and `badge`
     * -- the nodes and edges of the derivation graph -- which is precisely the
     * statement being made, and reading it needs no rendezvous between parent and
     * child and no timing assumption at all. Every check below is exact.
     *
     * The three ways to get this wrong each fail a different one:
     *   - no copy at all (the kernel before this commit)  -> not occupied
     *   - a verbatim copy (FORK_CSPACE_FLAT_COPY=1)       -> serial matches
     *   - a copy with no parent edge (ORPHAN_COPY=1)      -> badge does not */
    {
        int me = sys_getpid();

        /* A live child to inspect: it parks, and is killed once read. The
         * earlier children have exited, and a dead task reports every slot
         * empty -- which would pass the "not occupied" check for the wrong
         * reason. */
        int probe = sys_fork();
        if (probe < 0) { report("FORKTEST: FAIL fork-probe\n"); sys_exit(); }
        if (probe == 0) { for (;;) sys_yield(); }

        struct cap_info mine, theirs;
        if (sys_cap_enumerate(me, CAPSLOT_UNTYPED, &mine) != 0 ||
            sys_cap_enumerate(probe, CAPSLOT_UNTYPED, &theirs) != 0) {
            report("FORKTEST: FAIL cap-enumerate\n");
            (void)sys_kill(probe); sys_exit();
        }
        if (!mine.occupied) {           /* the test's own premise */
            report("FORKTEST: FAIL parent-lost-untyped\n");
            (void)sys_kill(probe); sys_exit();
        }
        if (!theirs.occupied) {
            report("FORKTEST: FAIL child-cap-absent\n");
            (void)sys_kill(probe); sys_exit();
        }
        /* ---- THESE FOUR DO NOT SHORT-CIRCUIT, deliberately ---------------
         *
         * Each states a separate rule, and the arms are one per rule -- so an
         * early exit on the first failure would make the later checks
         * unreachable from any arm, which is the definition of a check that
         * cannot fail. FORK_CSPACE_ORPHAN_COPY=1 in particular fails BOTH the
         * badge check and the revoke check below, and it should: the structural
         * statement and its end-to-end consequence are different claims, and a
         * reader wants to see both go red together. They are independent, so
         * continuing past one costs nothing. */
        int bad = 0;

        if (theirs.type != mine.type || theirs.rights != mine.rights) {
            report("FORKTEST: FAIL child-cap-altered\n"); bad = 1;
        }
        /* Its own identity: two capabilities must never share a serial, or a
         * revocation aimed at one nulls the other -- in another task's cspace. */
        if (theirs.serial == mine.serial || theirs.serial == 0) {
            report("FORKTEST: FAIL child-cap-shares-serial\n"); bad = 1;
        }
        /* ...and an edge back to the parent's, which is what makes revocation
         * reach it. Without this the child is a second root of the graph. */
        if (theirs.badge != mine.serial) {
            report("FORKTEST: FAIL child-cap-not-derived\n"); bad = 1;
        }

        /* The consequence, end to end: revoking the parent's capability must
         * sweep the child's copy. The structural check above says the edge
         * exists; this says the sweep actually walks it. Both, because an edge
         * nothing traverses is not a revocation path. */
        if (sys_cap_revoke(CAPSLOT_UNTYPED) != 0) {
            report("FORKTEST: FAIL revoke\n");
            (void)sys_kill(probe); sys_exit();
        }
        if (sys_cap_enumerate(probe, CAPSLOT_UNTYPED, &theirs) != 0) {
            report("FORKTEST: FAIL cap-enumerate2\n");
            (void)sys_kill(probe); sys_exit();
        }
        if (theirs.occupied) {
            report("FORKTEST: FAIL child-cap-survived-revoke\n"); bad = 1;
        }

        (void)sys_kill(probe);
        if (bad) sys_exit();          /* no PASS may follow a FAIL */
    }

    report("FORKTEST: PASS\n");
    sys_exit();
}
