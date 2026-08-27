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

/* The region run. Four pages, well clear of everything above. VA_REGION + 2
 * pages is deliberately occupied before the region map is attempted, so the run
 * fails in the MIDDLE rather than at either end -- a rollback that unwound only
 * the first page, or only the last, would pass a run that failed at index 1. */
#define PAGE_BYTES  0x1000ULL
#define VA_REGION   0x0000000031000000ULL
#define REGION_PAGES 4

/* A second run that must map cleanly, for the positive half of the pair. */
#define VA_REGION_OK 0x0000000032000000ULL

/* The SIZED frame (roadmap 2.1's region object): one capability naming a run of
 * contiguous pages. Four again, so the same middle-page blocking trick works. */
#define VA_SIZED     0x0000000033000000ULL
#define VA_SIZED_OK  0x0000000034000000ULL
#define SIZED_PAGES  4

/* The user (lower) canonical half, so a sized frame can be aimed at its edge.
 * The kernel refuses pml4[256..] independently; this checks that the SPAN is
 * tested, which is a question a one-page frame could not ask. */
#define USER_HALF_LIMIT 0x0000800000000000ULL

/* One past the last cspace slot. The kernel bounds it too; this is the ring-3
 * side asking for a slot that cannot exist. */
#define CNODE_SIZE_PUBLIC 256

/* Slots this task uses. All above KERNEL_RESERVED_CAPS and clear of the
 * canonical map in syscall.h, so nothing here collides with an endowment. */
#define SLOT_PEER_TCB  29   /* CAP_TCB naming framepeer: the supervisor right  */
#define SLOT_FRAME     30   /* the CAP_FRAME retyped out of untyped memory     */
#define SLOT_FRAME_RO  31   /* a READ-only mint of it, for the delegate        */
#define SLOT_REGION    32   /* first of REGION_PAGES consecutive CAP_FRAMEs    */
#define SLOT_SIZED     36   /* one CAP_FRAME naming SIZED_PAGES pages          */
#define SLOT_SIZED_2   37   /* a second, for the span and rollback checks     */

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

    /* (12) THE REGION, AND THE PARTIAL-FAILURE POLICY IT SETTLES (roadmap 2.1).
     *
     * SYS_MAP_REGION is all-or-nothing: if any page of the run cannot be mapped,
     * every page the call already mapped is withdrawn. The argument is in
     * src/kernel/syscall_vm.c; these are the checks that make it a measurement.
     * Note that the policy differs from SYS_RETYPE's on purpose -- retype keeps
     * what it made and returns a count -- so "it matches the other one" is not
     * available as a reason, and the property has to be witnessed directly. */
    check(sys_retype(CAPSLOT_UNTYPED, KOBJ_FRAME, REGION_PAGES, SLOT_REGION)
              == REGION_PAGES, "retype-region-run");

    /* The positive half FIRST. A kernel that refused every region map would pass
     * every rollback check below, which is the failure mode check_gate_pairs.py
     * exists to refuse for smoke targets and which applies just as much inside
     * one. Write a distinct word to each page and read them all back: a run that
     * mapped only the first page, or mapped them all onto one frame, fails. */
    check(sys_map_region(SLOT_REGION, REGION_PAGES, VA_REGION_OK,
                         CAP_RIGHT_READ | CAP_RIGHT_WRITE) == 0, "region-map-whole");
    {
        volatile unsigned long long *q = (volatile unsigned long long *)VA_REGION_OK;
        int all = 1;
        for (int i = 0; i < REGION_PAGES; i++)
            q[(unsigned long)i * (PAGE_BYTES / 8)] = PATTERN_A + (unsigned long long)i;
        for (int i = 0; i < REGION_PAGES; i++)
            if (q[(unsigned long)i * (PAGE_BYTES / 8)] != PATTERN_A + (unsigned long long)i)
                all = 0;
        check(all, "region-every-page-distinct");
    }

    /* The shape of the run is refused before anything is mapped. */
    check(sys_map_region(SLOT_REGION, 0, VA_SPARE, CAP_RIGHT_READ) < 0,
          "region-zero-count");
    check(sys_map_region(SLOT_REGION, 65, VA_SPARE, CAP_RIGHT_READ) < 0,
          "region-over-max");
    check(sys_map_region(SLOT_REGION, REGION_PAGES, VA_KERNEL, CAP_RIGHT_READ) < 0,
          "region-kernel-half");
    check(sys_map_region(SLOT_REGION, REGION_PAGES, VA_SPARE + 1, CAP_RIGHT_READ) < 0,
          "region-misaligned");

    /* ...and those refusals mapped nothing. VA_SPARE has been the target of every
     * request in this program that had to fail, so if it is still free here, none
     * of them installed anything. Probed by mapping it -- which is also the only
     * way to ask "is this address free" without dereferencing it -- and undone
     * immediately, because VA_SPARE's whole job is to stay empty. */
    check(sys_map_frame(SLOT_FRAME, VA_SPARE, CAP_RIGHT_READ) == 0,
          "refusals-mapped-nothing");
    check(sys_unmap_frame(SLOT_FRAME, VA_SPARE) == 0, "spare-restored");

    /* NOW THE PARTIAL FAILURE. Occupy the MIDDLE of the run, so it fails at page
     * 2 of 4 -- an unwind that handled only the first page, or only the last,
     * would pass a run that failed at either end. */
    /* The blocker is the run's OWN page-2 frame, mapped by hand first, and that
     * choice is what makes the over-eager-unwind arm below able to fail at all.
     * An unwind that walks the whole REQUESTED range re-derives each frame from
     * its slot; against a blocker from an unrelated frame it would be stopped by
     * user_unmap_frame_page's expect_phys test on its own, the check would pass
     * under the arm, and the arm would measure nothing -- the same trap the
     * rights floor note in syscall_vm.c describes. Aim at the range logic, not
     * at the guard underneath it. */
    check(sys_map_frame(SLOT_REGION + 2, VA_REGION + 2 * PAGE_BYTES, CAP_RIGHT_READ) == 0,
          "region-blocker-mapped");
    check(sys_map_region(SLOT_REGION, REGION_PAGES, VA_REGION,
                         CAP_RIGHT_READ | CAP_RIGHT_WRITE) < 0, "region-partial-refused");

    /* AND IT INSTALLED NOTHING. Pages 0 and 1 were mapped before the failure at
     * page 2, so they are exactly what the rollback exists to withdraw.
     *
     * Probed WITHOUT touching them. Mapping over a present page is refused (check
     * 3), so a single-page map that SUCCEEDS here proves the address is free. The
     * obvious alternative -- read the page and see whether it faults -- proves the
     * same thing by killing the task, which is a detector that destroys its own
     * evidence and reports a rollback bug as a dead workload.
     *
     * Under FRAME_REGION_NO_ROLLBACK=1 both of these return SYS_ERR_EXIST. */
    check(sys_map_frame(SLOT_REGION, VA_REGION, CAP_RIGHT_READ) == 0,
          "region-rollback-page0");
    check(sys_map_frame(SLOT_REGION + 1, VA_REGION + PAGE_BYTES, CAP_RIGHT_READ) == 0,
          "region-rollback-page1");

    /* THE OTHER DIRECTION, and the one an over-eager unwind fails. The page that
     * CAUSED the refusal was not installed by this call and must survive it. A
     * rollback that cleared the whole REQUESTED range instead of the pages it
     * actually mapped would hand ring 3 a way to destroy any mapping it dislikes
     * by asking to map a region across it -- so this check is a security
     * property, not tidiness. It must still be occupied. */
    check(sys_map_frame(SLOT_REGION + 2, VA_REGION + 2 * PAGE_BYTES, CAP_RIGHT_READ) < 0,
          "region-rollback-ate-blocker");

    /* (13) THE SIZED FRAME — roadmap 2.1's "region object wants a length".
     *
     * One capability naming a run of contiguous pages, rather than a run of
     * capabilities each naming one. That is what a shared buffer actually is,
     * and it is what lets the all-or-nothing unwind cost O(1) state instead of a
     * record per page: the run is contiguous, so page k is at base + k. */
    check(sys_retype_sized(CAPSLOT_UNTYPED, 1, SLOT_SIZED, SIZED_PAGES) == 1,
          "retype-sized-frame");

    /* The length is refused where it has no meaning, rather than ignored. A
     * caller asking for an 8-page endpoint has a wrong model of what it is
     * asking for, and quietly handing it one endpoint leaves that model
     * uncorrected until it matters. */
    check(sys_retype_sized(CAPSLOT_UNTYPED, 1, SLOT_SIZED_2, 0) == 1,
          "sized-zero-means-one");
    check((int)syscall6(SYS_RETYPE, CAPSLOT_UNTYPED, KOBJ_ENDPOINT, 1, 60, 4, 0) < 0,
          "sized-length-on-endpoint");
    check(sys_retype_sized(CAPSLOT_UNTYPED, 1, 60, MAX_FRAME_PAGES + 1) < 0,
          "sized-over-max-pages");

    /* Mapping it maps the WHOLE run, and the pages are DISTINCT. Writing one
     * word per page and reading them all back is what separates a real run from
     * a loop that advanced the virtual cursor and forgot the physical one --
     * which is not a crash but a buffer that silently aliases itself, present
     * and writable and wrong. `FRAME_PAGES_SAME_PHYS=1` is that kernel. */
    check(sys_map_frame(SLOT_SIZED, VA_SIZED_OK, CAP_RIGHT_READ | CAP_RIGHT_WRITE) == 0,
          "map-sized-frame");
    {
        volatile unsigned long long *q = (volatile unsigned long long *)VA_SIZED_OK;
        int distinct = 1;
        for (int i = 0; i < SIZED_PAGES; i++)
            q[(unsigned long)i * (PAGE_BYTES / 8)] = PATTERN_B + (unsigned long long)i;
        for (int i = 0; i < SIZED_PAGES; i++)
            if (q[(unsigned long)i * (PAGE_BYTES / 8)] != PATTERN_B + (unsigned long long)i)
                distinct = 0;
        check(distinct, "sized-pages-distinct");
    }

    /* Unmapping withdraws the whole run too. Probed by mapping a single page
     * over each address: refused while present, accepted once free. The last
     * page is the one a head-only unmap would leave behind. */
    check(sys_unmap_frame(SLOT_SIZED, VA_SIZED_OK) == 0, "unmap-sized-frame");
    check(sys_map_frame(SLOT_FRAME, VA_SIZED_OK, CAP_RIGHT_READ) == 0,
          "sized-unmap-freed-first");
    check(sys_unmap_frame(SLOT_FRAME, VA_SIZED_OK) == 0, "sized-probe-first-restored");
    check(sys_map_frame(SLOT_FRAME, VA_SIZED_OK + (SIZED_PAGES - 1) * PAGE_BYTES,
                        CAP_RIGHT_READ) == 0, "sized-unmap-freed-last");
    check(sys_unmap_frame(SLOT_FRAME, VA_SIZED_OK + (SIZED_PAGES - 1) * PAGE_BYTES) == 0,
          "sized-probe-last-restored");

    /* THE SPAN, which is a question a one-page frame could not ask. An address
     * one page below the user-half limit is legal for a single frame and not for
     * a four-page run: the run walks past the limit. The kernel refuses
     * pml4[256..] independently, so this is the second of two checks — but the
     * first is what turns "it failed part-way and unwound" into one refusal
     * before anything is installed. */
    check(sys_map_frame(SLOT_SIZED, USER_HALF_LIMIT - PAGE_BYTES, CAP_RIGHT_READ) < 0,
          "sized-span-crosses-user-half");

    /* A SIZED frame is refused inside a run of slots. SYS_MAP_REGION maps each
     * slot at the next page, so a sized frame in the middle would make the
     * address of every later slot depend on the length of every earlier
     * capability — an ABI where you cannot say where slot 5 landed without
     * reading slots 0..4. Mapped whole by SYS_MAP_FRAME instead. */
    check(sys_map_region(SLOT_SIZED, 1, VA_SPARE, CAP_RIGHT_READ) < 0,
          "sized-frame-refused-in-region");

    /* And the all-or-nothing policy holds INSIDE one frame. Block the middle
     * page of the run, map the frame, and it must install nothing — the same
     * property SYS_MAP_REGION has across slots, from the one shared unwind.
     * Both fail under FRAME_REGION_NO_ROLLBACK=1. */
    check(sys_map_frame(SLOT_FRAME, VA_SIZED + 2 * PAGE_BYTES, CAP_RIGHT_READ) == 0,
          "sized-blocker-mapped");
    check(sys_map_frame(SLOT_SIZED, VA_SIZED, CAP_RIGHT_READ | CAP_RIGHT_WRITE) < 0,
          "sized-partial-refused");
    check(sys_map_frame(SLOT_SIZED_2, VA_SIZED, CAP_RIGHT_READ) == 0,
          "sized-rollback-page0");
    check(sys_unmap_frame(SLOT_SIZED_2, VA_SIZED) == 0, "sized-rollback-probe-undone");

    /* (14) THE SIZE IS ASKABLE. A frame carries a length; until SYS_FRAME_PAGES
     * only the task that retyped one knew what it was, so a delegate had to be
     * told out of band or discover it by trial-mapping page after page.
     *
     * It reports a property of the OBJECT, not of the capability — nothing about
     * rights, lineage or badge — so it does not become the "syscall that reads a
     * capability" framepeer.c argues against. And it discloses nothing
     * SYS_MAP_FRAME does not already disclose to the same holder: mapping and
     * probing forward tells you the same number, more expensively. */
    check(sys_frame_pages(SLOT_SIZED) == SIZED_PAGES, "frame-pages-sized");
    check(sys_frame_pages(SLOT_FRAME) == 1, "frame-pages-single");
    check(sys_frame_pages(SLOT_REGION) == 1, "frame-pages-region-member");

    /* The authority is the capability the caller NAMES, and it is type-tested.
     * A CAP_TCB's object is a task id — a small integer that would index the
     * frame table perfectly happily — which is C-1's shape exactly. */
    check(sys_frame_pages(CAPSLOT_TCB) < 0, "frame-pages-wrong-type");
    check(sys_frame_pages(CAPSLOT_FRAME) < 0, "frame-pages-legacy-decoy");
    check(sys_frame_pages(60) < 0, "frame-pages-empty-slot");
    check(sys_frame_pages(CNODE_SIZE_PUBLIC) < 0, "frame-pages-slot-out-of-range");

    /* (15) Narrow, then delegate. sys_cap_mint is the only operation ring 3 has
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
