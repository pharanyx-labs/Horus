#include "syscall.h"

/*
 * fork + exec pairing self-test -- roadmap 2.3, FORKEXEC_SELFTEST builds only.
 *
 * `SYS_FORK` (roadmap 2.3, S39/S40/S41) and `SYS_EXEC_NAMED` both existed and
 * were both gated; what nothing exercised was the two in sequence, which is the
 * only sequence a shell ever performs. This drives it end to end and asserts the
 * property the exec path has claimed in a comment since it was written --
 * "capabilities survive the exec, POSIX-style" -- and never had a witness for:
 *
 *   S42  An exec replaces the image, not the authority. The task that comes back
 *        from SYS_EXEC_NAMED holds the SAME capabilities it held going in --
 *        same serial, same badge, same position in the derivation graph -- so a
 *        forked child cannot launder its inherited authority into a new root by
 *        execing, and a revocation aimed at its parent still reaches it.
 *
 * Also re-asserted here, one layer further on than `forktest` can reach:
 *
 *   S39  The parent's memory survives the child's exec. This is not a restatement
 *        for its own sake. `exec_into_armed_image` rebuilds the address space
 *        through `create_user_pagedir`, which RECLAIMS the previous one -- and
 *        the previous one is a copy-on-write clone sharing every physical page
 *        with a parent that is still running. Freeing it drops a reference on
 *        each of those pages, and a reference dropped once too often puts a live
 *        page of the parent's on the free page stack, to be handed out as
 *        somebody's fresh anonymous page. **Nothing else in the tree frees a
 *        cloned address space while its parent lives**: `task_teardown` does not
 *        free the space at all (a dead task's tree is reclaimed later, when its
 *        slot is reused), so a forked child that merely exits never exercises
 *        this. fork-then-exec is the first path that does, and it is reachable
 *        from ring 3 by any task that may fork.
 *
 * ---- HOW THE THREE TASKS RENDEZVOUS, AND WHY IT IS THROUGH THE CSPACE ------
 *
 * A forked child shares no memory with its parent -- that is S39 -- and after
 * the exec it does not even share a program. The one thing the two still have in
 * common is the capability graph, so every synchronisation here is a capability
 * appearing in a slot, read by the other side with SYS_CAP_ENUMERATE. Nothing in
 * this file waits on a clock or on a fixed number of yields to establish an
 * ordering; the spins are bounded only so a failure TERMINATES, and each one
 * reports its own marker on expiry rather than letting the harness time out with
 * nothing on the wire.
 *
 * The signals are deliberately minted from slot 0, the CAP_TCB on self that every
 * task is born with -- never from the inherited capability whose survival is
 * what is being measured. A rendezvous that depends on the property under test
 * cannot report that property's absence: it hangs instead, and a gate that hangs
 * prints no FAIL marker at all. Slot 0 is also the only birth capability
 * SYS_CAP_MINT accepts as a source, because it is the only one carrying
 * CAP_RIGHT_MINT (slot 3 is READ|WRITE|EXEC, slot 4 READ|WRITE).
 *
 * Markers: "FORKEXECTEST: PASS" / "FORKEXECTEST: FAIL <what>", plus
 * "FORKEXEC: FAIL <what>" from either of the other two tasks. No run may print
 * both a PASS and a FAIL -- see forktest.c, where that happened.
 */

/* Must match userspace/forkexecee.c. Chosen above every CAPSLOT_* the kernel
 * assigns, and above CAPSLOT_REPLY (21) and CAPSLOT_FS_EP (20), so nothing the
 * boot protocol installs can occupy one and make an "occupied" answer mean
 * something other than "the task put it there". */
#define FE_SLOT_ALIVE   24   /* the forked child: "I am running, pre-exec"      */
#define FE_SLOT_KEEP    25   /* the capability whose identity must survive exec */
#define FE_SLOT_GO      26   /* the driver grants this to release the child     */
#define FE_SLOT_READY   27   /* forkexecee, minted LAST: "my checks are recorded" */
#define FE_SLOT_ARGV    28   /* forkexecee: the staged argv survived the exec   */
#define FE_SLOT_USABLE  29   /* forkexecee: the inherited capability still WORKS */

/* Bounded so a failure ends the run instead of the harness's timeout ending it.
 * Generous because the wait spans a whole image load -- an address-space rebuild
 * and a loader copy -- not a scheduler hop, and because `smoke-forkexec` runs at
 * -smp 1 where every one of these iterations is also the child's only chance to
 * run. Expiry is a FAIL with its own name, never a silent pass. */
#define SPIN_LIMIT 200000

static void report(const char *s) {
    int n = 0;
    while (s[n]) n++;
    sys_write(1, s, (unsigned)n);
}

/* forktest.c's mechanism, and its reason verbatim: a forked child cannot report
 * a failure by exiting, because the driver would find its own checks satisfied
 * and print PASS underneath the child's FAIL. A failing child dies instead. */
static void child_fail(const char *s) {
    report(s);
    *(volatile unsigned char *)0 = 1;   /* die abnormally */
    for (;;) sys_yield();
}

/* Wait for `slot` of task `tid` to become occupied. Returns 1 on success, 0 on
 * expiry -- the caller names what it was waiting for, because "timed out" alone
 * does not say which of the three tasks failed to arrive. */
static int wait_for_slot(int tid, unsigned slot) {
    struct cap_info ci;
    for (int i = 0; i < SPIN_LIMIT; i++) {
        if (sys_cap_enumerate(tid, slot, &ci) == 0 && ci.occupied) return 1;
        sys_yield();
    }
    return 0;
}

void _start(void) {
    volatile unsigned char *base = (volatile unsigned char *)sys_sbrk(0x2000);
    if (base == (void *)-1 || base == 0) {
        report("FORKEXECTEST: FAIL sbrk\n"); sys_exit();
    }

    /* Written BEFORE the fork so the page is a real private frame rather than
     * the shared immortal zero page: the clone then exercises the general
     * copy-on-write path, which is the one whose refcount the child's exec is
     * about to decrement. */
    volatile unsigned char *p = base + 0x1000;
    p[0] = 0xA1;

    int child = sys_fork();
    if (child < 0) { report("FORKEXECTEST: FAIL fork\n"); sys_exit(); }

    if (child == 0) {
        /* ---- the forked child, before the exec ---- */

        /* Its own copy, on its own page. Under a kernel that shared the page
         * writably this lands in the parent's, and the parent reads it back
         * after the exec -- which is the S39 arm, one exec later than forktest's.
         * Done first so it is in the page before anything can go wrong later. */
        p[0] = 0xB2;

        /* The capability whose IDENTITY the exec must preserve. Minted from the
         * inherited CAP_UNTYPED, so the lineage under test is three deep --
         * driver's untyped -> the child's forked copy -> this mint -- and the
         * revocation at the end has to walk all of it. */
        /* ~0u, not a named set: SYS_CAP_MINT masks the request down to the
         * source's own rights, so "everything the source has" is spelled by
         * asking for everything and letting the algebra reduce it. Ring 3 has no
         * CAP_RIGHT_ALL, deliberately -- a userspace constant for "all rights"
         * is a number that goes stale the day a right is added. */
        if (sys_cap_mint(FE_SLOT_KEEP, CAPSLOT_UNTYPED, ~0u) != 0)
            child_fail("FORKEXEC: FAIL keep-mint\n");

        /* "I am running." From slot 0, not from the capability above: see the
         * header on why a rendezvous must not depend on the property measured. */
        if (sys_cap_mint(FE_SLOT_ALIVE, CAPSLOT_TCB, CAP_RIGHT_READ) != 0)
            child_fail("FORKEXEC: FAIL alive-mint\n");

        /* Hold here until the driver has read FE_SLOT_KEEP's identity. Without
         * this the exec could complete before the pre-exec sample was taken, and
         * "the serial is unchanged" would have nothing to compare against --
         * the check would silently become "the serial is whatever it is". */
        if (!wait_for_slot(sys_getpid(), FE_SLOT_GO))
            child_fail("FORKEXEC: FAIL go-timeout\n");

        {
            char *av[2];
            av[0] = "forkexecee";
            av[1] = "post-fork";
            sys_exec_named_argv("forkexecee", 2, av);
        }
        /* Reaching here means the exec returned, which is a failure by contract:
         * SYS_EXEC_NAMED either replaces the image or leaves it intact and
         * reports why, and this task asked for a name the kernel embeds. */
        child_fail("FORKEXEC: FAIL exec-returned\n");
    }

    /* ---- the driver ---- */

    if (!wait_for_slot(child, FE_SLOT_ALIVE)) {
        report("FORKEXECTEST: FAIL child-never-armed\n"); sys_exit();
    }

    /* The pre-exec sample. Everything after the exec is compared against this,
     * so a failure to read it is fatal to the run rather than a check to skip. */
    struct cap_info pre;
    if (sys_cap_enumerate(child, FE_SLOT_KEEP, &pre) != 0 || !pre.occupied) {
        report("FORKEXECTEST: FAIL pre-sample\n");
        (void)sys_kill(child); sys_exit();
    }

    /* Release the child into the exec. Any capability would do -- what is being
     * delivered is the fact of the grant, not its authority -- and CAP_DEBUG is
     * the one the child already holds a derived copy of, so this adds nothing to
     * what it can reach. */
    if (sys_cap_grant(child, CAPSLOT_DEBUG, FE_SLOT_GO) != 0) {
        report("FORKEXECTEST: FAIL go-grant\n");
        (void)sys_kill(child); sys_exit();
    }

    /* FE_SLOT_READY is minted last and unconditionally by forkexecee, so it means
     * "the execed image finished and recorded what it found", not merely "it is
     * alive". Waiting on anything conditional would turn a defect into a timeout,
     * and a gate that times out prints no marker. */
    if (!wait_for_slot(child, FE_SLOT_READY)) {
        report("FORKEXECTEST: FAIL exec-never-arrived\n");
        (void)sys_kill(child); sys_exit();
    }

    /* ---- S42: the same capabilities, in the same place in the graph -------
     *
     * THESE DO NOT SHORT-CIRCUIT, for forktest.c's reason: each states a separate
     * rule, one control arm aims at each, and an early exit on the first would
     * make the later ones unreachable from any arm -- which is the definition of
     * a check that cannot fail. They are independent, so continuing costs
     * nothing. */
    int bad = 0;

    /* ---- what only the execed side could see -----------------------------
     *
     * forkexecee records these by minting into slots of its own rather than by
     * writing to the console, so that this driver -- and not a harness matching
     * two tasks' prose on one wire -- is what reaches a verdict. See the header
     * of userspace/forkexecee.c. */
    {
        struct cap_info sig;
        if (sys_cap_enumerate(child, FE_SLOT_ARGV, &sig) != 0 || !sig.occupied) {
            report("FORKEXECTEST: FAIL exec-lost-argv\n"); bad = 1;
        }
        if (sys_cap_enumerate(child, FE_SLOT_USABLE, &sig) != 0 || !sig.occupied) {
            report("FORKEXECTEST: FAIL exec-lost-inherited-cap\n"); bad = 1;
        }
    }

    struct cap_info post;
    if (sys_cap_enumerate(child, FE_SLOT_KEEP, &post) != 0) {
        report("FORKEXECTEST: FAIL post-sample\n");
        (void)sys_kill(child); sys_exit();
    }

    /* 1. It is still there. An exec that rebuilds the cspace from the birth
     *    endowment -- the "give the new image a clean slate" instinct, and what
     *    EXEC_RESET_CSPACE=1 does -- fails here and nowhere else. */
    if (!post.occupied) {
        report("FORKEXECTEST: FAIL exec-dropped-inherited-cap\n"); bad = 1;
    } else {
        /* 2. It is the same authority. */
        if (post.type != pre.type || post.rights != pre.rights) {
            report("FORKEXECTEST: FAIL exec-altered-inherited-cap\n"); bad = 1;
        }
        /* 3. It is the SAME capability, not a fresh one that resembles it. A
         *    re-mint would leave every capability derived from this one badging a
         *    serial that no longer exists, so a revocation aimed at THIS would
         *    stop reaching them. */
        if (post.serial != pre.serial) {
            report("FORKEXECTEST: FAIL exec-recreated-inherited-cap\n"); bad = 1;
        }
        /* 4. And it still names its parent. Without the edge the execed task is a
         *    second ROOT of the capability graph holding authority it was
         *    delegated -- finding 3.3's shape, reached by execing instead of by
         *    forking. */
        if (post.badge != pre.badge) {
            report("FORKEXECTEST: FAIL exec-orphaned-inherited-cap\n"); bad = 1;
        }
    }

    /* 5. The consequence, end to end and three generations deep: the driver
     *    revokes its own CAP_UNTYPED, and the sweep must reach a capability that
     *    was minted by a child from a forked copy and then carried through an
     *    exec. The structural checks above say the edges exist; this says the
     *    sweep actually walks them. Both, because an edge nothing traverses is
     *    not a revocation path. */
    if (sys_cap_revoke(CAPSLOT_UNTYPED) != 0) {
        report("FORKEXECTEST: FAIL revoke\n");
        (void)sys_kill(child); sys_exit();
    }
    {
        struct cap_info swept;
        if (sys_cap_enumerate(child, FE_SLOT_KEEP, &swept) != 0) {
            report("FORKEXECTEST: FAIL post-revoke-sample\n");
            (void)sys_kill(child); sys_exit();
        }
        if (swept.occupied) {
            report("FORKEXECTEST: FAIL child-cap-survived-revoke-after-exec\n");
            bad = 1;
        }
    }

    /* ---- S39, one exec later ---------------------------------------------
     *
     * The child wrote 0xB2 over its copy of this page and then execed, which
     * reclaimed the cloned address space that page was shared through. The driver
     * must still read what it wrote before the fork: not the child's byte (the
     * page was never shared) and not a byte from whatever the pool handed out
     * next (the reference was not dropped twice). */
    if (p[0] != 0xA1) {
        report("FORKEXECTEST: FAIL parent-clobbered-by-exec\n"); bad = 1;
    }

    (void)sys_kill(child);
    if (bad) sys_exit();          /* no PASS may follow a FAIL */

    report("FORKEXECTEST: PASS\n");
    sys_exit();
}
