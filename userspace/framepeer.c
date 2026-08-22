/* framepeer -- the delegate half of the frame-capability witness (roadmap 2.1).
 *
 * FRAME_SELFTEST builds only. Spawned suspended and endowed with NOTHING except
 * what frametest.c hands it: one READ-only CAP_FRAME, minted down from
 * frametest's own READ|WRITE capability and delegated with SYS_CAP_GRANT.
 *
 * It exists because the two halves of "shared memory between mutually
 * distrusting tasks" can only be shown from here, and they pull in opposite
 * directions:
 *
 *   POSITIVE -- it must SEE frametest's bytes. Two tasks, two address spaces,
 *   two independently chosen virtual addresses, one physical frame. If this
 *   fails, frames are not shared memory at all and the feature is a private
 *   allocator with extra steps.
 *
 *   NEGATIVE -- it must NOT be able to write them. It holds READ. A writable
 *   mapping obtained from a READ capability is delegation widening authority,
 *   which is the one thing the capability model is not allowed to do.
 *
 * A gate with only the first is passed by a kernel with no permission checks; a
 * gate with only the second is passed by a kernel where nothing works at all.
 * Falsified by FRAME_RIGHTS_UNCHECKED=1, under which the negative check fails.
 *
 * This task prints the pair's marker, because it is the one that can only report
 * after everything on both sides has happened.
 */
#include "syscall.h"
#include "libhorus.h"

/* Deliberately NOT frametest's address. The frame is one physical page; that the
 * two tasks reach it at different virtual addresses is part of what makes it a
 * capability rather than a fixed window -- and the legacy slot-3 CAP_FRAME this
 * change had to defend against was precisely a fixed window. */
#define VA_PEER     0x0000000040000000ULL
#define VA_SPARE    0x0000000040100000ULL

#define SLOT_FRAME  30   /* where frametest grants the READ-only capability */

#define PATTERN_A   0x5A11ED0000C0FFEEULL
#define PATTERN_B   0x0BADF00DDEADBEEFULL

/* How long to wait for the delegation. Bounded, because "retry until it works"
 * turns a capability refusal into an indistinguishable hang -- finding G-8
 * signature C, the same reason libhorus's ipc_call_retry bounds its loop. The
 * parent resumes this task only after granting, so the wait is belt-and-braces
 * against scheduling order rather than the mechanism being relied on. */
#define GRANT_WAIT_TRIES  2000

static int checks;
static int failures;

static void check(int ok, const char *what) {
    if (ok) { checks++; return; }
    kput("FRAMETEST: FAIL ");
    kput(what);
    kput("\n");
    failures++;
}

void _start(void) {
    /* Wait for the capability to arrive, by trying the operation rather than by
     * asking whether the slot is occupied: there is no syscall that reads a
     * capability's contents, and there should not be one. A read-only map is the
     * weakest thing this task is entitled to do with it. */
    int rc = -1;
    for (int i = 0; i < GRANT_WAIT_TRIES; i++) {
        rc = sys_map_frame(SLOT_FRAME, VA_PEER, CAP_RIGHT_READ);
        if (rc == 0) break;
        spin_delay();
    }
    check(rc == 0, "peer-map-readonly");
    if (rc != 0) {
        kputln("FRAMETEST: FAIL peer never received the delegated capability");
        for (;;) sys_yield();
    }

    /* POSITIVE: the same physical page, at a different virtual address, in a
     * different address space. */
    volatile unsigned long long *p = (volatile unsigned long long *)VA_PEER;
    check(p[0] == PATTERN_A && p[1] == PATTERN_B, "peer-sees-shared-bytes");

    /* NEGATIVE: a writable mapping from a READ-only capability. The write is
     * only attempted if the kernel wrongly grants the mapping -- under the base
     * build this returns a refusal and nothing is written, so the check does not
     * depend on catching a fault. Under FRAME_RIGHTS_UNCHECKED=1 the mapping is
     * granted, the store lands, and the read-back proves it did. */
    int wr = sys_map_frame(SLOT_FRAME, VA_SPARE, CAP_RIGHT_READ | CAP_RIGHT_WRITE);
    check(wr < 0, "readonly-delegate-got-writable-mapping");
    if (wr == 0) {
        volatile unsigned long long *w = (volatile unsigned long long *)VA_SPARE;
        w[0] = ~PATTERN_A;
        check(w[0] != ~PATTERN_A, "readonly-delegate-wrote");
    }

    /* The delegate may withdraw its own mapping. Unmapping reduces what this
     * task can reach and therefore needs no right beyond holding the capability
     * -- requiring WRITE here would leave a read-only sharer unable to let go. */
    check(sys_unmap_frame(SLOT_FRAME, VA_PEER) == 0, "peer-unmap");

    /* And having unmapped it, cannot unmap it again: the PTE no longer names
     * this capability's frame. */
    check(sys_unmap_frame(SLOT_FRAME, VA_PEER) < 0, "peer-double-unmap");

    if (failures) {
        kput("FRAMETEST: FAIL ");
        kput_int(failures);
        kputln(" checks failed");
    } else {
        kput("FRAMETEST: PASS ");
        kput_int(checks);
        kputln(" checks");
    }
    for (;;) sys_yield();
}
