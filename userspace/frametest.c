/* frametest -- the ring-3 witness for frame capabilities (roadmap 2.1, F-2.1).
 *
 * FRAME_SELFTEST builds only. Runs as the first of two tasks: this one holds a
 * CAP_UNTYPED and does the creating, mapping and delegating; framepeer.c holds
 * only what this task hands it and proves what a delegate can and cannot do.
 *
 * WHAT IS ACTUALLY UNDER TEST. Not "can a page be mapped" -- that is the easy
 * half and a kernel that mapped anything for anyone would pass it. The checks
 * here are refusals, in the shape docs/AUDIT.md and CLAUDE.md ask for:
 *
 *   - The legacy slot-3 CAP_FRAME. Every task in this system is born holding a
 *     CAP_FRAME, with READ|WRITE|EXEC, whose object is USER_AREA_BASE. It named
 *     a fixed window and authorised nothing, and it is exactly the capability
 *     that made finding C-1 reachable: the pre-C-1 dispatch table gated IPC on
 *     slot 3, so a capability every task happened to hold became universal IPC
 *     authority. Giving CAP_FRAME a meaning put that decoy back in play, and
 *     check (4) is the reason it is safe -- a frame capability names an INDEX
 *     into a table the kernel populates, and USER_AREA_BASE is not one.
 *     Falsified by FRAME_INDEX_UNCHECKED=1, under which this check fails on
 *     every boot.
 *
 *   - The rights floor. A delegate given READ must not obtain a writable
 *     mapping, or "delegation may only ever reduce rights" is a comment rather
 *     than a property. That half is framepeer's; falsified by
 *     FRAME_RIGHTS_UNCHECKED=1.
 *
 *   - W^X. A frame is the first object userspace can point at an address of its
 *     own choosing, so it is the first place userspace could have built a
 *     writable code page.
 *
 * Prints FRAMETEST: PASS <n> checks from ring 3, so the marker on serial is
 * end-to-end proof rather than a claim about a build. Read the count off the
 * wire -- do not trust a number written in a document (CLAUDE.md §3).
 */
#include "syscall.h"
#include "libhorus.h"

/* Where this task maps things. Well clear of the image, the stack at ~8 MiB and
 * the heap at 16 MiB, and page-aligned. VA_SPARE is only ever used for requests
 * that must FAIL, so nothing is ever mapped there and a leftover mapping cannot
 * make a later check pass by accident. */
#define VA_SHARED   0x0000000030000000ULL
#define VA_SPARE    0x0000000030100000ULL
#define VA_KERNEL   0xFFFF800000000000ULL   /* kernel half: must always be refused */

/* Slots this task uses. All above KERNEL_RESERVED_CAPS and clear of the
 * canonical map in syscall.h, so nothing here collides with an endowment. */
#define SLOT_PEER_TCB  29   /* CAP_TCB naming framepeer: the supervisor right  */
#define SLOT_FRAME     30   /* the CAP_FRAME retyped out of untyped memory     */
#define SLOT_FRAME_RO  31   /* a READ-only mint of it, for the delegate        */

/* The pattern the peer must be able to see. Two words, so a peer reading a
 * zeroed page or a stale one cannot pass by coincidence. */
#define PATTERN_A   0x5A11ED0000C0FFEEULL
#define PATTERN_B   0x0BADF00DDEADBEEFULL

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
    kputln("FRAMETEST: begin");

    /* (1) A frame is an ordinary retyped object. No new authority, no new
     * syscall to create one: the CAP_UNTYPED this task was endowed with is what
     * pays for the page, which is the property roadmap 0.3 exists for and the
     * reason frames are carved from untyped memory rather than pulled from the
     * anonymous page allocator. */
    int n = sys_retype(CAPSLOT_UNTYPED, KOBJ_FRAME, 1, SLOT_FRAME);
    check(n == 1, "retype-frame");
    if (n != 1) { kputln("FRAMETEST: FAIL cannot continue"); for (;;) sys_yield(); }

    /* (2) Map it, write, read back. The positive direction: a gate that only
     * ever refuses is satisfied by a kernel that refuses everything, so the
     * legal path has to be exercised too (tools/check_gate_pairs.py enforces
     * exactly this pairing for the smoke targets). */
    check(sys_map_frame(SLOT_FRAME, VA_SHARED, CAP_RIGHT_READ | CAP_RIGHT_WRITE) == 0,
          "map-rw");
    volatile unsigned long long *p = (volatile unsigned long long *)VA_SHARED;
    p[0] = PATTERN_A;
    p[1] = PATTERN_B;
    check(p[0] == PATTERN_A && p[1] == PATTERN_B, "write-read-back");

    /* (3) Mapping twice at the same address is refused rather than silently
     * replacing the entry. A silent replace would drop the old page's reference
     * without anyone releasing it. */
    check(sys_map_frame(SLOT_FRAME, VA_SHARED, CAP_RIGHT_READ) < 0, "map-over-existing");

    /* (4) THE DECOY. Slot 3 holds a live, well-formed CAP_FRAME with
     * READ|WRITE|EXEC that this task did not ask for and cannot refuse -- the
     * kernel installs it in every task at create_task. It must map nothing.
     * Under FRAME_INDEX_UNCHECKED=1 it maps physical 0x400000. */
    check(sys_map_frame(CAPSLOT_FRAME, VA_SPARE, CAP_RIGHT_READ) < 0,
          "legacy-cap-mapped");

    /* (5) W^X. Asked for outright rather than silently dropping a bit: a caller
     * requesting W|X has a wrong model of what it is doing, and a mapping that
     * quietly differs from the request is worse than an error. */
    check(sys_map_frame(SLOT_FRAME, VA_SPARE, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC) < 0,
          "w-and-x-together");

    /* (6) The kernel half. user_pte_slot refuses pml4[256..] independently, so
     * this is the second of two checks; a user mapping installed there would be
     * a ring-3-writable alias of kernel page tables. */
    check(sys_map_frame(SLOT_FRAME, VA_KERNEL, CAP_RIGHT_READ) < 0, "kernel-half-vaddr");

    /* (7) Alignment and the zero page. A misaligned request cannot be honoured
     * by a PTE at all, and address 0 must stay unmapped so a NULL dereference
     * keeps faulting. */
    check(sys_map_frame(SLOT_FRAME, VA_SPARE + 1, CAP_RIGHT_READ) < 0, "misaligned-vaddr");
    check(sys_map_frame(SLOT_FRAME, 0, CAP_RIGHT_READ) < 0, "zero-vaddr");

    /* (8) An empty rights request. It would ask for a present page with no
     * meaning -- x86-64 has no read-disable bit, so "no access" is not a mapping
     * the hardware can express -- and guessing READ on the caller's behalf is
     * the kind of helpfulness that turns into an authority bug. */
    check(sys_map_frame(SLOT_FRAME, VA_SPARE, 0) < 0, "empty-rights");

    /* (9) A capability of the wrong TYPE. Slot 0 is this task's own CAP_TCB:
     * live, fully-righted, and not a frame. This is the C-1 shape stated
     * directly -- liveness is not type, and a gate that only checks the first
     * accepts the second. */
    check(sys_map_frame(CAPSLOT_TCB, VA_SPARE, CAP_RIGHT_READ) < 0, "wrong-type-cap");

    /* (10) An empty slot. Fail closed on a capability that is not there at all,
     * rather than on one that is there and wrong. */
    check(sys_map_frame(SLOT_FRAME_RO, VA_SPARE, CAP_RIGHT_READ) < 0, "empty-slot");

    /* (11) Unmapping an address this task never mapped. Without the frame
     * capability being required for the unmap as well as the map, this would be
     * an arbitrary self-corruption primitive: any task could punch a hole in its
     * own image or stack, pages it holds no frame capability for. */
    check(sys_unmap_frame(SLOT_FRAME, VA_SPARE) < 0, "unmap-never-mapped");

    /* (12) Narrow, then delegate. sys_cap_mint is the only operation ring 3 has
     * that REDUCES rights -- SYS_CAP_GRANT copies the source's rights whole -- so
     * this pair is what "delegation may only ever reduce" looks like from
     * userspace. The peer gets READ and nothing else. */
    check(sys_cap_mint(SLOT_FRAME_RO, SLOT_FRAME, CAP_RIGHT_READ) == 0, "mint-readonly");

    int peer = (int)sys_spawn_arg();
    check(peer > 0, "peer-tid");

    /* The delegation is authorised by the CAP_TCB naming the peer in
     * SLOT_PEER_TCB -- a task may only push capabilities DOWN into a child it
     * supervises, never sideways or up. Being uid 0 would not do: since [H-1]
     * "admin" means holding a CAP_USER, and this task holds none. */
    check(sys_cap_grant(peer, SLOT_FRAME_RO, SLOT_FRAME) == 0, "grant-readonly-to-peer");

    /* The peer is spawned suspended so this task can finish endowing it before
     * it runs; nothing here depends on scheduling order after that point. The
     * peer prints the PASS marker for the pair, because it is the one that can
     * only report after everything above has happened. */
    check(sys_task_resume(peer) == 0, "resume-peer");

    if (failures) {
        kput("FRAMETEST: FAIL ");
        kput_int(failures);
        kputln(" checks failed in the parent");
    } else {
        kput("FRAMETEST: parent OK ");
        kput_int(checks);
        kputln(" checks");
    }

    /* Stay alive: the frame's mapping must persist while the peer reads it, and
     * exiting would tear this address space down. */
    for (;;) sys_yield();
}
