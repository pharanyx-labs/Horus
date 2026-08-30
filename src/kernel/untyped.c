/* untyped.c -- untyped memory and object retyping (roadmap 0.3, audit I-7).
 *
 * WHAT THIS REPLACES
 *
 * Every kernel object in Horus used to be an entry in a fixed `.bss` array:
 * tasks[64], endpoints[128], notifications[64], cspace_pool[64][256]. The
 * problem was never that the numbers were small. It was that the capability
 * graph could not answer "who may create a kernel object?", because the answer
 * was "everyone, and the storage already exists". Object creation was outside
 * the model the whole security argument is stated over.
 *
 * Following seL4: a CAP_UNTYPED capability names a region of physical memory,
 * and SYS_RETYPE carves typed objects out of it. Three properties follow, and
 * they are the reason the roadmap puts this in Track 0:
 *
 *   - Kernel-memory consumption is ATTRIBUTABLE. A task can only create objects
 *     in a region it holds a capability for, so "which authority paid for this
 *     memory" is answerable by inspecting the capability graph.
 *   - Kernel-memory exhaustion is PREVENTABLE. Delegating a small untyped region
 *     to a task is a hard bound on the kernel memory it can ever consume — the
 *     first confinement property the system can state without an asterisk.
 *   - Object lifetime is CAPABILITY-GOVERNED. An object exists exactly as long
 *     as some capability names it (kobj_gc below), instead of forever, because
 *     an array slot is never reclaimed.
 *
 * ALLOCATION DISCIPLINE
 *
 * Within a region, allocation is a bump pointer that never moves backwards.
 * Destroying an object does NOT return its bytes; reclaiming a region means
 * revoking the untyped capability, which destroys every object derived from it
 * and resets the watermark in one step.
 *
 * This is seL4's rule and it is a safety property, not a simplification. With a
 * free list, an object's bytes can be handed straight back out and retyped as a
 * DIFFERENT class while a stale capability still names the old address — the
 * classic type-confusion-through-reuse. A monotonic watermark makes that moment
 * structurally impossible: bytes are only reusable after every capability into
 * the region has been revoked, which is the same event that invalidates the
 * stale reference.
 *
 * WHAT IS AND IS NOT MIGRATED YET
 *
 * Per-task cspaces are allocated here (create_task -> kobj_alloc), which is what
 * removes the 512 KiB static cspace_pool from `.bss`. Endpoints and
 * notifications are retypable from ring 3 into an index range above the static
 * tables, which remain as a compatibility shim for the well-known service
 * objects the boot protocol names by index. Frames (roadmap 2.1) are retypable
 * too and have no static table at all -- they were never a `.bss` array, so
 * every valid frame index is one this file handed out. tasks[] is not migrated:
 * a TCB is reachable from the scheduler's hot path and from every trap frame, so
 * moving it is its own change with its own tests.
 */
#include "kernel.h"
#include "errno.h"

/* Set by paging_init to PHYS_KVA(...) of the reserved arena. */
uint8_t *g_untyped_arena = 0;

struct untyped untypeds[MAX_UNTYPED];

/* Descriptor for one retyped endpoint / notification / frame. These ARE `.bss`, and
 * deliberately so: what they cost is one pointer per addressable object, while
 * the objects themselves — the part that actually scales — live in untyped
 * memory. The array bounds how many retyped objects the kernel can NAME; the
 * untyped region bounds how many a given authority can CREATE, and only the
 * second is a security property. */
struct kobj_slot {
    void    *mem;        /* into the arena; NULL == this index holds no object */
    uint32_t untyped;    /* the region it was carved from (for accounting)     */
    /* FRAMES ONLY: how many contiguous pages this object spans (roadmap 2.1).
     * Endpoints and notifications leave it 0 and never read it; the field is
     * shared rather than given its own parallel array because a parallel array
     * is one more thing that can fall out of step with dyn_frames[] -- and a
     * length that disagrees with the object it describes is a map path walking
     * off the end of an allocation. */
    uint32_t pages;
};
static struct kobj_slot dyn_eps[MAX_DYN_ENDPOINTS];
static struct kobj_slot dyn_notifs[MAX_DYN_NOTIFICATIONS];
/* Frames (roadmap 2.1). Indexed by (object - DYN_FRAME_BASE), same shape as the
 * two above; `mem` points at a PAGE_SIZE-aligned page in the arena. */
static struct kobj_slot dyn_frames[MAX_DYN_FRAMES];

/* ------------------------------------------------------------------------- *
 *  Locking.
 *
 *  The untyped tables are mutated in two very different contexts: at boot
 *  (untyped_init, then create_task(0) from scheduler_init) while the kernel is
 *  still single-threaded with no IDT-driven preemption, and at runtime from
 *  syscall context where two CPUs can race. One plain spinlock covers both.
 *
 *  ---- WHAT USED TO BE HERE, AND WHY IT IS NOT ANY MORE -------------------
 *
 *  Until 2026-08-18 this file carried two workarounds for finding C-3.1 -- the
 *  pre-1.1 spin_unlock() ending in an UNCONDITIONAL `sti` once the global
 *  nesting depth reached zero:
 *
 *    1. locking was DEFERRED past boot behind an `untyped_locking_armed` flag,
 *       because a boot-window lock would have enabled interrupts at a point the
 *       boot code never asked for; and
 *    2. every critical section was wrapped in a pushfq/popfq bracket, so that
 *       `sti` was undone whatever IF state the caller was in.
 *
 *  Roadmap 1.1 landed on 2026-08-11: spin_lock() now begins with `cli` and
 *  records the caller's own RFLAGS.IF per CPU, and spin_unlock() RESTORES that
 *  rather than asserting one. Both workarounds were then conditioned on a
 *  premise that no longer held, and this comment went on asserting the premise
 *  for another week -- a comment naming a closed finding as open is exactly how
 *  [G-2] survived nineteen days.
 *
 *  Re-derived and removed 2026-08-18, both directions checked rather than
 *  assumed:
 *
 *    - The bracket is now a no-op by construction. pushfq -> spin_lock(cli,
 *      saves IF) -> ... -> spin_unlock(restores that IF) -> popfq restores
 *      exactly what the pushfq captured. Deleting it changes no observable
 *      state, and it changes no COUNT either: the IRQ_POLICY_AUDIT counters
 *      increment inside spin_unlock, whose call sites are unchanged, so the
 *      measured legacy-vs-per-CPU comparison in TESTS.md still stands.
 *    - The deferral is safe to remove because spin_lock's only boot-window
 *      hazard was that `sti`, and because this_cpu() -- which spin_lock reads
 *      for its per-CPU depth -- is valid from the first C statement of
 *      kernel_main: setup_tss64 (src/boot/multiboot.S) does `ltr $0x38`
 *      immediately before calling it, so the STR fast path returns 0 rather
 *      than falling back to a LAPIC MMIO read. The boot window is
 *      single-threaded, so the lock it now takes is uncontended, and taking it
 *      is what makes "these tables are always locked" a property with no
 *      window in it rather than a claim with a flag beside it.
 *
 *  Both removals were smoke-tested under IRQ_LEGACY_GLOBAL_LOCK=1 as well as by
 *  default -- 3 boots in 3 to the ring-3 login prompt in each arm -- because a
 *  control arm that no longer boots is a control arm that no longer measures
 *  anything, and the legacy arm is the one this change could plausibly have
 *  broken: with the deferral gone it now takes a lock in the boot window whose
 *  release, in THAT build, still fires an unconditional `sti`.
 * ------------------------------------------------------------------------- */
static spinlock_t untyped_lock;

static inline void ut_lock(void)   { spin_lock(&untyped_lock);   }
static inline void ut_unlock(void) { spin_unlock(&untyped_lock); }

/* ------------------------------------------------------------------------- *
 *  Object sizes and the bump allocator.
 * ------------------------------------------------------------------------- */

/* Every allocation is 64-byte aligned. Alignment is not a performance choice:
 * a capability_t array must be 8-aligned for the Rust FFI's layout assertions to
 * hold over it, and rounding to a cache line additionally guarantees two objects
 * carved from the same region never share a line, so a false-sharing stall
 * cannot turn into a cross-object timing signal under SMP. */
#define KOBJ_ALIGN 64
/* align_up() is a function, so it cannot appear in a _Static_assert. This is the
 * same arithmetic as a constant expression, used only by the asserts below;
 * both are derived from KOBJ_ALIGN so they cannot disagree about the rounding. */
#define align_up_const(v, a)  ((((uint64_t)(v)) + (a) - 1u) & ~((uint64_t)(a) - 1u))

static uint64_t kobj_size(uint32_t kobj_type, uint32_t pages) {
    switch (kobj_type) {
        case KOBJ_CNODE:        return (uint64_t)CNODE_SIZE * sizeof(capability_t);
        case KOBJ_ENDPOINT:     return sizeof(struct endpoint);
        case KOBJ_NOTIFICATION: return sizeof(struct notification);
        /* The only class with a caller-chosen size. Bounded by the caller
         * (untyped_retype) before it gets here, and bounded AGAIN here, because
         * this function is also reachable from kobj_alloc's other caller and a
         * size that is checked in only one of two paths is checked in neither. */
        case KOBJ_FRAME:        return (pages == 0 || pages > MAX_FRAME_PAGES)
                                           ? 0 : (uint64_t)pages * PAGE_SIZE;
        /* The whole task table, allocated once at boot by tasks_init(). Not
         * reachable from SYS_RETYPE -- the type is above KOBJ_TYPE_MAX, which is
         * what untyped_retype bounds against -- so this arm serves kobj_alloc's
         * kernel-internal caller alone. */
        case KOBJ_TASKTABLE:    return (uint64_t)MAX_TASKS * sizeof(tcb_t);
        /* The three per-boot tables that scale with the task count. Sized from
         * MAX_TASKS for the same reason the table above is: they are allocated
         * once, before g_max_tasks is derived from what the reserve holds, so the
         * reserve must be able to satisfy the provisioned maximum. */
        case KOBJ_REVOKE_SPACES:    return ((uint64_t)MAX_TASKS + 1) * sizeof(cspace_desc_t);
        case KOBJ_TASK_RUNNING_CPU: return (uint64_t)MAX_TASKS * sizeof(int);
        case KOBJ_KSTACK_INFLIGHT:  return (uint64_t)((MAX_TASKS + 63) / 64) * sizeof(uint64_t);
        default:                return 0;
    }
}

/* Alignment is per class, not global, because KOBJ_FRAME's is a correctness
 * requirement rather than the cache-line preference the other classes get: a
 * frame is installed in a PTE, and a PTE's address field IS the page number, so
 * a 64-byte-aligned "frame" would either be truncated down onto whatever object
 * shares its page or refused at map time -- and the first of those is a
 * cross-object aliasing bug that would look like data corruption, not like a
 * permission error. Demanding it here means the map path never has to. */
static uint64_t kobj_align(uint32_t kobj_type) {
    return (kobj_type == KOBJ_FRAME) ? (uint64_t)PAGE_SIZE : (uint64_t)KOBJ_ALIGN;
}

static uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) & ~(a - 1); }

static void zero_bytes(uint8_t *p, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) p[i] = 0;
}

/* Bump `count` objects' worth of bytes out of region `u`. Caller holds the lock
 * (or is in the boot window). Returns the arena pointer, or NULL if the region
 * cannot satisfy the request -- which is the whole point: this is where a task's
 * kernel-memory budget is enforced, so it must fail cleanly rather than borrow
 * from anywhere else. */
static void *untyped_bump(struct untyped *u, uint64_t bytes, uint64_t align) {
    if (!u->in_use || !g_untyped_arena) return 0;
    /* The masks below are the power-of-two form. Both callers pass a constant
     * that satisfies it, so this is a guard against a future third one rather
     * than against anything reachable today -- and refusing is the fail-closed
     * answer to "an alignment I cannot honour". */
    if (align == 0 || (align & (align - 1))) return 0;

    /* Align the ABSOLUTE arena address, not the region-relative watermark.
     * Rounding the offset alone is what the 64-byte-only version did, and it was
     * correct only because every region base happened to be a multiple of 64.
     * Nothing requires that, and at PAGE_SIZE it stops being true the moment a
     * region starts anywhere but a page boundary -- so the padding is computed
     * from the address the caller will actually receive. */
    uint64_t abs_base = (uint64_t)(g_untyped_arena + u->base);
    uint64_t start    = u->watermark;

    /* Overflow-safe headroom test throughout: compare what REMAINS against what
     * is needed, never start+bytes against size (which can wrap on a crafted
     * count). The padding is spent out of the same remainder. */
    if (start >= u->size) return 0;
    uint64_t room = u->size - start;
    uint64_t pad  = (align - ((abs_base + start) & (align - 1))) & (align - 1);
    if (pad > room)   return 0;
    start += pad;
    room  -= pad;
    if (bytes > room) return 0;

    u->watermark = start + bytes;
    uint8_t *p = g_untyped_arena + u->base + start;
    zero_bytes(p, bytes);
    return p;
}

/* ------------------------------------------------------------------------- *
 *  Object index tables.
 * ------------------------------------------------------------------------- */

static int dyn_ep_alloc_index(void) {
    for (int i = 0; i < MAX_DYN_ENDPOINTS; i++)
        if (!dyn_eps[i].mem) return i;
    return -1;
}

static int dyn_notif_alloc_index(void) {
    for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++)
        if (!dyn_notifs[i].mem) return i;
    return -1;
}

static int dyn_frame_alloc_index(void) {
    for (int i = 0; i < MAX_DYN_FRAMES; i++)
        if (!dyn_frames[i].mem) return i;
    return -1;
}

struct endpoint *endpoint_by_index(uint32_t idx) {
    if (idx < MAX_ENDPOINTS) return &endpoints[idx];
    if (idx >= EP_INDEX_MAX)  return 0;
    return (struct endpoint *)dyn_eps[idx - DYN_EP_BASE].mem;
}

struct notification *notification_by_index(uint32_t idx) {
    if (idx < MAX_NOTIFICATIONS) return &notifications[idx];
    if (idx >= NOTIF_INDEX_MAX)   return 0;
    return (struct notification *)dyn_notifs[idx - DYN_NOTIF_BASE].mem;
}

/* Unlike endpoints and notifications there is no static frame table to fall back
 * to: frames were never a `.bss` array, so every valid index is a retyped one
 * and BOTH ends of the range are a refusal. That is what the map path leans on
 * to reject the legacy slot-3 CAP_FRAME, whose object is a virtual address that
 * lands nowhere near [DYN_FRAME_BASE, FRAME_INDEX_MAX). */
void *frame_by_index(uint32_t idx) {
    if (idx < DYN_FRAME_BASE || idx >= FRAME_INDEX_MAX) return 0;
    return dyn_frames[idx - DYN_FRAME_BASE].mem;
}

/* The arena is a linear PHYS_KVA window (kernel.h), so the inverse of PHYS_KVA
 * is a subtraction. Returns 0 -- never a frame -- for a dead or out-of-range
 * index, so a caller that skips the NULL check still fails closed. */
/* How many contiguous pages frame `idx` spans. 0 for a dead or out-of-range
 * index, so a caller that skips the check gets a zero-length run rather than a
 * wild one. Deliberately NOT folded into frame_phys_by_index's return: the
 * physical base and the length are two facts, and a caller that wants only the
 * base should not be able to take it while ignoring the length. */
/* Is this physical page inside the untyped arena?
 *
 * The arena is the memory every kernel OBJECT is carved from -- cspaces,
 * endpoints, notifications and frames alike -- and it sits inside
 * [USER_PHYS_BASE, pool ceiling), so it shares the page_refcounts[] table with
 * the anonymous page allocator. That overlap is what makes the question worth
 * asking: the generic page machinery will operate on an arena page perfectly
 * happily, and must not. See the guard at the top of cow_break_pte (paging.c).
 *
 * Deliberately the whole ARENA and not just the frame table. A cnode or an
 * endpoint has even less business being copied out from under its object than a
 * frame does, and a predicate that answered only about frames would be a
 * narrower guarantee than the one the caller needs. */
int phys_in_untyped_arena(uint64_t phys) {
    if (!g_untyped_arena) return 0;
    uint64_t base = (uint64_t)g_untyped_arena - PHYS_KVA_BASE;
    return phys >= base && phys < base + (uint64_t)UNTYPED_ARENA_BYTES;
}

uint32_t frame_pages_by_index(uint32_t idx) {
#ifdef FRAME_INDEX_UNCHECKED
    /* THE ARM HAS TO BE IN BOTH RESOLVERS, and finding that out cost a red CI
     * run. When a frame gained a length there were suddenly TWO functions
     * turning a CAP_FRAME.object into a fact about an object, and the control
     * arm lived in only one of them. frame_phys_by_index returned the object AS
     * an address, exactly as the arm intends -- and then this function applied
     * the bound the arm exists to remove, answered 0 for the legacy slot-3
     * capability, and the map path refused it at the LENGTH check. The arm
     * stopped reproducing: `FRAMETEST: FAIL legacy-cap-mapped` disappeared, and
     * smoke-frame-index-control went red for want of a failure.
     *
     * That is the same hazard the shared validator in syscall_vm.c was written
     * to avoid, met from the other side: not two copies of a GATE drifting, but
     * a defect arm that only mutates half of what it names. A control arm is as
     * split as the thing it injects into.
     *
     * Under the arm this kernel is the pre-length kernel: object is an address,
     * an object is one page. */
    (void)idx;
    return 1;
#else
    if (idx < DYN_FRAME_BASE || idx >= FRAME_INDEX_MAX) return 0;
    int i = (int)(idx - DYN_FRAME_BASE);
    if (!dyn_frames[i].mem) return 0;
    return dyn_frames[i].pages ? dyn_frames[i].pages : 1;
#endif
}

uint64_t frame_phys_by_index(uint32_t idx) {
#ifdef FRAME_INDEX_UNCHECKED
    /* The control arm, and it reproduces the defect in its realistic form rather
     * than by deleting a bounds check. The shortcut a frame-mapping syscall
     * invites is to put the PHYSICAL ADDRESS in capability_t.object and map it:
     * one field, no table, no resolver. This is that kernel.
     *
     * It is reachable on the first boot, because every task is born holding a
     * CAP_FRAME in slot 3 whose object is USER_AREA_BASE. Under this arm,
     * SYS_MAP_FRAME(3, ...) maps physical 0x400000 -- low memory, below the pool
     * -- into ring 3, from a capability the kernel handed out itself.
     *
     * Simply removing the range test from frame_by_index would NOT reproduce it:
     * dyn_frames[0x400000 - 1] is a wild read that faults, so the arm would
     * measure the bounds check crashing rather than the authority being wrong. */
    return (uint64_t)idx;
#else
    void *mem = frame_by_index(idx);
    if (!mem) return 0;
    return (uint64_t)mem - PHYS_KVA_BASE;
#endif
}

uint32_t kobj_live_count(uint32_t kobj_type) {
    uint32_t n = 0;
    if (kobj_type == KOBJ_ENDPOINT) {
        for (int i = 0; i < MAX_DYN_ENDPOINTS; i++) if (dyn_eps[i].mem) n++;
    } else if (kobj_type == KOBJ_NOTIFICATION) {
        for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++) if (dyn_notifs[i].mem) n++;
    } else if (kobj_type == KOBJ_FRAME) {
        for (int i = 0; i < MAX_DYN_FRAMES; i++) if (dyn_frames[i].mem) n++;
    }
    return n;
}

/* ------------------------------------------------------------------------- *
 *  Allocation.
 * ------------------------------------------------------------------------- */

void *kobj_alloc(uint32_t untyped_index, uint32_t kobj_type, uint32_t pages,
                 uint32_t *out_index) {
    if (untyped_index >= MAX_UNTYPED) return 0;
    /* `pages` is meaningful for KOBJ_FRAME alone. Normalising 0 to 1 here is
     * what keeps every existing caller and every existing retype correct without
     * touching them; a NON-zero length on a class that has no length is refused
     * by untyped_retype rather than ignored, because silently dropping an
     * argument the caller passed is how an ABI grows a meaning nobody agreed. */
    if (kobj_type != KOBJ_FRAME) pages = 1;
    else if (pages == 0)         pages = 1;
    uint64_t need = kobj_size(kobj_type, pages);
    if (need == 0) return 0;

    ut_lock();
    struct untyped *u = &untypeds[untyped_index];

    /* Claim the index BEFORE bumping the watermark: an index table that is full
     * must not consume region bytes it can then never hand out. (The watermark
     * never moves backwards, so a failed allocation after a bump would leak.) */
    int idx = -1;
    if (kobj_type == KOBJ_ENDPOINT) {
        idx = dyn_ep_alloc_index();
        if (idx < 0) { ut_unlock(); return 0; }
    } else if (kobj_type == KOBJ_NOTIFICATION) {
        idx = dyn_notif_alloc_index();
        if (idx < 0) { ut_unlock(); return 0; }
    } else if (kobj_type == KOBJ_FRAME) {
        idx = dyn_frame_alloc_index();
        if (idx < 0) { ut_unlock(); return 0; }
    }

    void *mem = untyped_bump(u, need, kobj_align(kobj_type));
    if (!mem) { ut_unlock(); return 0; }

    if (kobj_type == KOBJ_ENDPOINT) {
        struct endpoint *e = (struct endpoint *)mem;
        /* A fresh endpoint must not start life claiming task 0 as its sender or
         * waiter: zeroed memory means index 0, and 0 is a real task. The queue
         * ring needs the same treatment per slot (roadmap 1.3). */
        e->head           = 0;
        e->count          = 0;
        e->last_sender    = -1;
        e->blocked_waiter = -1;
        for (int s = 0; s < EP_QUEUE_SLOTS; s++) {
            e->q[s].len    = 0;
            e->q[s].sender = -1;
        }
        dyn_eps[idx].mem     = mem;
        dyn_eps[idx].untyped = untyped_index;
        if (out_index) *out_index = DYN_EP_BASE + (uint32_t)idx;
    } else if (kobj_type == KOBJ_NOTIFICATION) {
        struct notification *n = (struct notification *)mem;
        n->blocked_waiter = -1;
        dyn_notifs[idx].mem     = mem;
        dyn_notifs[idx].untyped = untyped_index;
        if (out_index) *out_index = DYN_NOTIF_BASE + (uint32_t)idx;
    } else if (kobj_type == KOBJ_FRAME) {
        /* ---- The permanent reference, and why it is not an optimisation ----
         *
         * A frame is arena memory INSIDE [USER_PHYS_BASE, pool ceiling), so it
         * has a slot in the same page_refcounts[] table the anonymous-page
         * allocator uses. That matters because free_user_table (paging.c) walks
         * a dying task's page tables and calls user_leaf_release on every
         * present leaf -- and user_leaf_release pushes a frame onto the FREE
         * PAGE STACK when its count reaches zero. A mapped frame whose count
         * fell to zero would therefore be handed out as an anonymous page while
         * the untyped region still owns those bytes: pool corruption, reachable
         * by mapping a frame and letting the task die.
         *
         * That does not happen today, but only because a never-allocated arena
         * page sits at count 0 and rust_page_ref_dec fails closed on an
         * already-zero frame. That is a value nobody set on purpose holding up a
         * safety property, which is the shape this project treats as a defect
         * rather than a margin.
         *
         * So the region takes a reference of its own, here, once, and never
         * releases it. Every map adds one and every unmap or teardown removes
         * one, so the count is (1 + mappings) and can never reach 0 -- the
         * release path is unreachable for arena frames by arithmetic instead of
         * by accident. It also gives the GC its liveness test for free: a count
         * above 1 means somebody still has this frame mapped.
         *
         * (There is no untyped-region reset in the tree yet. When one lands it
         * must clear these pins as it resets the watermark, or the second carve
         * of the same page would pin it twice; frame_unpin_refcount exists for
         * that caller and is why the pin is a named operation rather than an
         * inline store.) */
        /* EVERY page of the run, not just the first. The pin is what keeps the
         * release path arithmetically unreachable for arena pages, and an
         * unpinned page in the middle of a frame is exactly the page
         * free_user_table would push onto the free stack when the task dies --
         * so a run pinned only at its head is the pool corruption above,
         * relocated to page 1. */
        uint64_t base_phys = (uint64_t)mem - PHYS_KVA_BASE;
        for (uint32_t pg = 0; pg < pages; pg++)
            frame_pin_refcount(base_phys + (uint64_t)pg * PAGE_SIZE);
        dyn_frames[idx].mem     = mem;
        dyn_frames[idx].untyped = untyped_index;
        dyn_frames[idx].pages   = pages;
        if (out_index) *out_index = DYN_FRAME_BASE + (uint32_t)idx;
    } else {
        /* KOBJ_CNODE: no object index -- a cspace is reached through the owning
         * task's tcb, not by index. */
        if (out_index) *out_index = 0;
    }

    u->objects++;
    ut_unlock();
    return mem;
}

/* ------------------------------------------------------------------------- *
 *  Destruction: reachability, not refcounts.
 *
 *  An object dies when no capability names it. That is computed by sweeping the
 *  capability graph rather than by maintaining a refcount, and the choice is
 *  deliberate: a refcount has to be incremented at every mint / transfer / move
 *  / grant and decremented at every revoke / null / task teardown, across BOTH
 *  the C and the safe-Rust halves of the capability implementation. One missed
 *  site is a leak; one double-decrement is a use-after-free reachable from ring
 *  3. Reachability is instead computed from the same graph the security argument
 *  is already stated over, so the two cannot disagree.
 *
 *  The cost is a sweep of every live cspace, which is what a system-wide revoke
 *  already does -- so this adds a constant factor to an operation that was
 *  already O(tasks x cspace), and nothing to any hot path.
 *
 *  IN-FLIGHT POINTERS. An IPC syscall resolves its endpoint to a pointer and
 *  then takes ipc_lock; on another CPU a revoke can destroy that object in
 *  between, so the syscall can be holding a pointer to a just-destroyed object.
 *  This is exactly the case the bump discipline exists for: the bytes are never
 *  handed out again while the region lives, so the write lands in memory nothing
 *  else owns -- a dropped message, not a use-after-free or a type confusion. It
 *  is also why destruction scrubs the object rather than merely dropping the
 *  name: a pointer that outlives the object must not still see live state.
 * ------------------------------------------------------------------------- */

/* Mark one capability, if it names a retyped object.
 *
 * The liveness test is `serial != 0` — the same "this slot holds something"
 * predicate revocation nulls. It does NOT additionally run the serial-keyed
 * generation check, so a capability that is unusable because its lineage was
 * bumped still marks its object. That direction of imprecision is the safe one:
 * it can only delay a destruction (a leak until the next sweep finds the slot
 * actually nulled), never destroy an object something can still name. The
 * opposite bias — treating a slot as empty when a holder could still resolve
 * it — would be a use-after-free reachable from ring 3. */
static void mark_cap(const capability_t *c, uint8_t *ep_marks, uint8_t *nt_marks,
                     uint8_t *fr_marks) {
    if (c->serial == 0) return;   /* empty slot */
    if (c->type == CAP_ENDPOINT) {
        if (c->object >= DYN_EP_BASE && c->object < EP_INDEX_MAX)
            ep_marks[c->object - DYN_EP_BASE] = 1;
    } else if (c->type == CAP_NOTIFICATION) {
        if (c->object >= DYN_NOTIF_BASE && c->object < NOTIF_INDEX_MAX)
            nt_marks[c->object - DYN_NOTIF_BASE] = 1;
    } else if (c->type == CAP_FRAME) {
        /* The legacy slot-3 CAP_FRAME every task is born with lands here on every
         * sweep. Its object is USER_AREA_BASE, far outside the index range, so it
         * marks nothing -- the same bound that stops it mapping anything stops it
         * keeping a frame alive. */
        if (c->object >= DYN_FRAME_BASE && c->object < FRAME_INDEX_MAX)
            fr_marks[c->object - DYN_FRAME_BASE] = 1;
    }
}

/* One pass over every live cspace plus the kernel root cnode, marking each
 * retyped object some capability names. ONE pass, not one per object: the naive
 * "is this object named?" form is O(objects x tasks x cspace), which at a full
 * index table is millions of reads on every revoke and every task exit. */
static void mark_reachable(uint8_t *ep_marks, uint8_t *nt_marks, uint8_t *fr_marks) {
    for (int i = 0; i < MAX_DYN_ENDPOINTS; i++)     ep_marks[i] = 0;
    for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++) nt_marks[i] = 0;
    for (int i = 0; i < MAX_DYN_FRAMES; i++)        fr_marks[i] = 0;

    for (int t = 0; t < g_max_tasks; t++) {
        if (tasks[t].state == 0 || !tasks[t].cspace) continue;
        uint32_t sz = tasks[t].cspace_size ? tasks[t].cspace_size : CNODE_SIZE;
        if (sz > CNODE_SIZE) sz = CNODE_SIZE;
        for (uint32_t s = 0; s < sz; s++)
            mark_cap(&tasks[t].cspace[s], ep_marks, nt_marks, fr_marks);
    }
    /* The kernel root cnode is not any task's cspace; sweep it too, so a
     * kernel-held capability keeps its object alive. */
    const capability_t *root = cap_root_cnode_ref();
    for (uint32_t s = 0; s < CNODE_SIZE; s++)
        mark_cap(&root[s], ep_marks, nt_marks, fr_marks);
}

/* Release an endpoint's storage index. The bytes stay consumed in the untyped
 * region (bump discipline); only the name is reclaimed. */
static void destroy_dyn_endpoint(int i) {
    struct endpoint *e = (struct endpoint *)dyn_eps[i].mem;
    if (!e) return;
    /* A task blocked on an endpoint whose last capability just went away would
     * otherwise wait forever on an object nothing can ever send to. Waking it is
     * the fail-closed choice: it resumes and sees its call did not complete. */
    int w = e->blocked_waiter;
    if (w > 0 && w < g_max_tasks && tasks[w].state != 0) {
        tasks[w].state        = TASK_RUNNABLE;
        tasks[w].runnable_ctx = 1;
        tasks[w].blocked_on   = -1;
    }
    /* Scrub before releasing the name: the bytes are not reused until the whole
     * region is reset, but an in-flight message must not outlive the object that
     * carried it. */
    zero_bytes((uint8_t *)e, sizeof(*e));
    if (dyn_eps[i].untyped < MAX_UNTYPED && untypeds[dyn_eps[i].untyped].objects > 0)
        untypeds[dyn_eps[i].untyped].objects--;
    dyn_eps[i].mem = 0;
}

static void destroy_dyn_notification(int i) {
    struct notification *n = (struct notification *)dyn_notifs[i].mem;
    if (!n) return;
    int w = n->blocked_waiter;
    if (w > 0 && w < g_max_tasks && tasks[w].state != 0) {
        tasks[w].state           = TASK_RUNNABLE;
        tasks[w].runnable_ctx    = 1;
        tasks[w].blocked_on_notif = -1;
    }
    zero_bytes((uint8_t *)n, sizeof(*n));
    if (dyn_notifs[i].untyped < MAX_UNTYPED && untypeds[dyn_notifs[i].untyped].objects > 0)
        untypeds[dyn_notifs[i].untyped].objects--;
    dyn_notifs[i].mem = 0;
}

/* Release a frame's index, if nothing has it mapped.
 *
 * ---- WHY THIS ONE CAN REFUSE, AND THE OTHER TWO CANNOT --------------------
 *
 * For an endpoint, "no capability names it" is the whole liveness question: the
 * only way to reach one is through a capability, so a swept endpoint is
 * genuinely unreachable and the in-flight-pointer case is covered by the bump
 * discipline (a dropped message, never a use-after-free -- see the header).
 *
 * A frame is different in kind, because a PTE is a second, capability-free path
 * to the same bytes. A task that maps a frame and then drops its capability
 * still has the page in its address space and keeps reading and writing it. So
 * "unreachable" is `no capability AND no mapping`, and the mapping half is what
 * frame_map_refcount answers: the region's pin is 1, every mapping is one more,
 * so anything above 1 means a live PTE somewhere.
 *
 * Refusing leaks the index until the last holder unmaps or dies -- teardown
 * walks the page tables and drops the references, so the next sweep collects it.
 * That is the safe direction of imprecision, in the same sense as mark_cap's:
 * the cost of refusing is a name held longer than necessary, and the cost of
 * proceeding would be the region reset handing those bytes to a fresh object
 * while another task's PTE still points at them. */
static void destroy_dyn_frame(int i) {
    uint8_t *pg = (uint8_t *)dyn_frames[i].mem;
    if (!pg) return;
    uint64_t phys  = (uint64_t)pg - PHYS_KVA_BASE;
    uint32_t pages = dyn_frames[i].pages ? dyn_frames[i].pages : 1;

    /* ANY page still mapped keeps the whole run alive. Map and unmap are
     * whole-object operations, so in practice the counts move together and
     * testing the head would give the same answer -- but "in practice" is doing
     * the work in that sentence, and the cost of asking about every page is a
     * loop bounded by 64. Collecting a run because its first page happened to be
     * free would scrub bytes another task is reading. */
    for (uint32_t k = 0; k < pages; k++)
        if (frame_map_refcount(phys + (uint64_t)k * PAGE_SIZE) > 1) return;

    /* A DEVICE mapping is a third capability-free path to these bytes, and until
     * 2026-08-29 nothing removed it. SYS_DMA_ADDR installs an IOMMU translation
     * for the run; frame_map_refcount counts CPU mappings only, so a device
     * mapping neither keeps the frame alive above nor is torn down here. The
     * sequence that follows from that is a device-side use-after-free: a driver
     * maps a frame for its device, drops the capability and its own PTE, this
     * function scrubs the run and returns it to the arena, the arena hands those
     * bytes to a fresh object -- and the device is still bus-mastering into them
     * through a translation whose authorising capability no longer exists. The
     * scrub above is what makes it concrete: it is the point at which the kernel
     * has decided these bytes belong to nobody.
     *
     * Unmapped before the scrub rather than after, so there is no window in which
     * the run is zeroed and reallocatable while a device can still write to it.
     * See iommu_unmap_all for why this tears down where the PTE policy refuses. */
#ifndef IOMMU_NO_FRAME_TEARDOWN
    iommu_unmap_all(phys, pages);
#endif

    /* Scrub before releasing the name, for the reason destroy_dyn_endpoint
     * scrubs: the bytes outlive the object under bump allocation, and a frame's
     * bytes are whatever userspace last put in them. All of them -- a run
     * scrubbed only at its head leaves the rest of a buffer readable by whoever
     * the arena hands those bytes to next. */
    zero_bytes(pg, (uint64_t)pages * PAGE_SIZE);
    for (uint32_t k = 0; k < pages; k++)
        frame_unpin_refcount(phys + (uint64_t)k * PAGE_SIZE);
    if (dyn_frames[i].untyped < MAX_UNTYPED && untypeds[dyn_frames[i].untyped].objects > 0)
        untypeds[dyn_frames[i].untyped].objects--;
    dyn_frames[i].mem   = 0;
    dyn_frames[i].pages = 0;
}

/* Mark bitmaps. Static rather than on the stack: kobj_gc runs from
 * task_teardown, which is reached from the page-fault handler on a kernel stack
 * that has no room for half a KiB of scratch. Safe as statics because every
 * caller holds the untyped lock across the whole mark-and-sweep. */
static uint8_t gc_ep_marks[MAX_DYN_ENDPOINTS];
static uint8_t gc_nt_marks[MAX_DYN_NOTIFICATIONS];
static uint8_t gc_fr_marks[MAX_DYN_FRAMES];

void kobj_gc(void) {
    ut_lock();
    mark_reachable(gc_ep_marks, gc_nt_marks, gc_fr_marks);
    for (int i = 0; i < MAX_DYN_ENDPOINTS; i++)
        if (dyn_eps[i].mem && !gc_ep_marks[i]) destroy_dyn_endpoint(i);
    for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++)
        if (dyn_notifs[i].mem && !gc_nt_marks[i]) destroy_dyn_notification(i);
    for (int i = 0; i < MAX_DYN_FRAMES; i++)
        if (dyn_frames[i].mem && !gc_fr_marks[i]) destroy_dyn_frame(i);
    ut_unlock();
}

/* ------------------------------------------------------------------------- *
 *  Boot.
 * ------------------------------------------------------------------------- */

void untyped_init(void) {
    for (int i = 0; i < MAX_UNTYPED; i++) {
        untypeds[i].base = untypeds[i].size = untypeds[i].watermark = 0;
        untypeds[i].objects = 0;
        untypeds[i].in_use  = 0;
    }
    for (int i = 0; i < MAX_DYN_ENDPOINTS; i++)      { dyn_eps[i].mem = 0;    dyn_eps[i].untyped = 0; }
    for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++)  { dyn_notifs[i].mem = 0; dyn_notifs[i].untyped = 0; }

    /* The arena is split once, at boot, into a kernel half and a user half.
     *
     * The split is the point. UNTYPED_KERNEL backs the per-task cspaces the
     * kernel must be able to allocate to create a task at all; no capability is
     * ever minted for it, so it is unreachable from ring 3 and no userspace
     * allocation pattern can starve task creation. UNTYPED_ROOT is what init
     * holds and delegates onward, so everything ring 3 can ever allocate comes
     * out of a bounded region that the kernel's own bootstrap does not share. A
     * single region for both would make "userspace exhausted kernel memory" and
     * "the system can no longer create a task" the same event. */
    /* UNTYPED_KERNEL_BYTES, not a second copy of the arithmetic.
     *
     * This line recomputed the reserve from CNODE_SIZE directly, which was
     * harmless while the macro said the same thing -- and stopped being harmless
     * the moment the macro grew the TCB table's allowance. The two then described
     * one quantity differently: the reserve was built 2 MiB and everything that
     * reasoned about it thought 2.5 MiB, and the boot provisioned 191 tasks where
     * it should have provisioned 256. That is [H-3]'s shape in the sizing of the
     * region this file exists to manage, and the only durable fix is that there
     * is one expression, in the header, that both the size and the checks read. */
    uint64_t kernel_half = UNTYPED_KERNEL_BYTES;
    /* Round the split to a page so the two regions never share a frame. */
    kernel_half = align_up(kernel_half, PAGE_SIZE);

    untypeds[UNTYPED_KERNEL].base      = 0;
    untypeds[UNTYPED_KERNEL].size      = kernel_half;
    untypeds[UNTYPED_KERNEL].watermark = 0;
    untypeds[UNTYPED_KERNEL].objects   = 0;
    untypeds[UNTYPED_KERNEL].in_use    = 1;

    untypeds[UNTYPED_ROOT].base      = kernel_half;
    untypeds[UNTYPED_ROOT].size      = (uint64_t)UNTYPED_ARENA_BYTES - kernel_half;
    untypeds[UNTYPED_ROOT].watermark = 0;
    untypeds[UNTYPED_ROOT].objects   = 0;
    untypeds[UNTYPED_ROOT].in_use    = 1;
}

/* How many tasks the kernel reserve this boot ACTUALLY built can carry.
 *
 * This is what makes the task count a property of the machine rather than of the
 * image. `untyped_init` sizes the reserve from constants today, but the arena it
 * sits in is pool memory whose extent comes from the E820 map, so a boot on a
 * small machine gets a smaller reserve and therefore fewer tasks -- and every
 * bound in the kernel follows, because tasks_init derives g_max_tasks from this.
 *
 * The divisor is the per-task cost of the FIXED tables: one cspace, plus the TCB
 * table's per-task slice, plus the per-task words of the three tables that scale
 * with the count. Deriving it from the same kobj_size() the allocator uses is
 * what keeps the two from drifting -- a capacity computed from a second copy of
 * the arithmetic is a number that is right until somebody edits one of them.
 *
 * The BYTES ALREADY SPENT are subtracted, because this is asked after the tables
 * are carved: the watermark has moved, and answering from the region's total
 * would promise capacity that is no longer there. */
int untyped_reserve_task_capacity(void)
{
    struct untyped *u = &untypeds[UNTYPED_KERNEL];
    if (!u->in_use || u->size <= u->watermark) return 0;

    /* ONE CSPACE, and nothing else. The first draft added the per-task slices of
     * the TCB table, task_running_cpu and the revocation buffer -- and those
     * bytes are already spent, by the up-front table allocations this function
     * subtracts through the watermark. Counting them again charged every task
     * twice and under-reported the capacity by a third. What is still owed per
     * task, after the tables exist, is the cspace create_task will carve. */
    uint64_t per_task = align_up(kobj_size(KOBJ_CNODE, 1), KOBJ_ALIGN);
    if (per_task == 0) return 0;

    uint64_t avail = u->size - u->watermark;
    uint64_t n = avail / per_task;
    /* The tables above were already carved for the PROVISIONED maximum, so the
     * remaining bytes are what is left for cspaces. Cap at MAX_TASKS: the caller
     * clamps too, and a bound stated in both places is one that cannot be
     * widened by editing one of them. */
    if (n > (uint64_t)MAX_TASKS) n = MAX_TASKS;
    return (int)n;
}

/* The reserve must actually cover MAX_TASKS cspaces, at the alignment this
 * file's allocator uses. Static, because a boot that discovers this at runtime
 * has already committed to a layout it cannot satisfy -- and the failure it
 * prevents is create_task halting the machine on a cspace it cannot allocate.
 *
 * THIS ASSERT CHANGED SHAPE when the arena's halves were decoupled, and the old
 * one is worth recording because it was guarding the wrong thing. It read
 *
 *     UNTYPED_ARENA_BYTES > 2 * MAX_TASKS * CNODE_SIZE * sizeof(capability_t)
 *
 * i.e. "the user half is at least as big as the kernel half" -- a ratio between
 * two quantities that were competing for one fixed total. It was the only thing
 * standing between a routine MAX_TASKS bump and a silently smaller user half,
 * and it would have fired at MAX_TASKS == 256 not because anything was wrong but
 * because 4 MiB had stopped being enough for both. The halves are sized
 * independently now (see UNTYPED_KERNEL_BYTES / UNTYPED_USER_BYTES), so the
 * question worth asking is no longer "is the split fair" but "does the reserve
 * fit what it reserves for". */
_Static_assert(UNTYPED_KERNEL_BYTES >=
                   (uint64_t)MAX_TASKS *
                   align_up_const((uint64_t)CNODE_SIZE * sizeof(capability_t), KOBJ_ALIGN),
               "UNTYPED_KERNEL_BYTES must hold MAX_TASKS cspaces at KOBJ_ALIGN");
/* And the user half must still be able to hold the largest single object any
 * capability can name, or MAX_FRAME_PAGES is a promise the arena cannot keep. */
_Static_assert(UNTYPED_USER_BYTES > (uint64_t)MAX_FRAME_PAGES * PAGE_SIZE,
               "the user half must exceed the largest frame a capability can name");

/* ------------------------------------------------------------------------- *
 *  Syscall bodies.
 *
 *  Both resolve their untyped region from a CSPACE SLOT, never from an index
 *  supplied by userspace -- the same discipline ipc_ep_from_slot enforces for
 *  IPC (finding C-1). The `object` field of the CAP_UNTYPED is what names the
 *  region, and it is consulted at the point of use, which is precisely what C-1
 *  found was NOT happening for endpoints.
 * ------------------------------------------------------------------------- */

/* Resolve an untyped capability slot to the region index it names. */
static int untyped_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out) {
    struct capability *c = cap_lookup(slot, need_rights);
    if (!c || c->type != CAP_UNTYPED) return -1;
    if (c->object >= MAX_UNTYPED)     return -1;
    if (!untypeds[c->object].in_use)  return -1;
    /* UNTYPED_KERNEL is not delegable by construction (no capability is ever
     * minted for it). Refuse it here as well, so a forged or mis-minted cap
     * cannot reach the kernel's cspace reserve even if one ever appeared. */
    if (c->object == UNTYPED_KERNEL)  return -1;
    if (out) *out = (uint32_t)c->object;
    return 0;
}

/* SPLIT A REGION: carve `bytes` off the caller's untyped and mint a CAP_UNTYPED
 * naming the sub-region into `dest_slot`.
 *
 * ---- WHY THIS EXISTS: IT REPAIRS AN OVERCLAIM -----------------------------
 *
 * S57 (2026-08-30) made creating a task cost untyped memory, and stated the
 * property as "a task endowed with none cannot spawn, and a task given a SMALL
 * REGION can spawn a bounded number of times". The first half was true and
 * witnessed. The second half was not implementable: SYS_CAP_GRANT of a
 * CAP_UNTYPED copies a capability naming the SAME region, so init handing the
 * shell untyped handed it init's entire budget. There was no way to give a task
 * a small region, so the sentence described a capability nobody could mint.
 *
 * That is the shape this project keeps finding -- a property asserted in prose
 * that no code makes true -- and it is worse here for having been written by the
 * commit that introduced the gate. This is the missing half.
 *
 * ---- THE BYTES COME OUT OF THE PARENT, WHICH IS THE WHOLE POINT ------------
 *
 * The sub-region is taken from the parent's own unallocated tail and the
 * parent's watermark advances past it, so a split SPENDS budget rather than
 * creating it. Two tasks holding the parent and the child cannot together carve
 * more than the parent could alone, and that holds transitively: a child may
 * split again, and the arithmetic is the same one bump allocator each time.
 *
 * The region is NOT returned when the child dies. That is the same monotonic
 * bump discipline every other allocation here obeys, and for the same reason --
 * reclaiming bytes while a stale capability might still name them is the
 * type-confusion this allocator exists to forbid. A split is a permanent
 * transfer of budget, which is what makes it an honest accounting primitive
 * rather than a loan.
 *
 * ---- THE CAPABILITY IS DERIVED, NOT A NEW ROOT ----------------------------
 *
 * Minted through the same derivation SYS_CAP_MINT uses, so the child's
 * CAP_UNTYPED carries the parent capability's serial as its badge. Revoking the
 * parent's untyped sweeps the child's with it (S3/S4). A fresh root here would
 * be finding 3.3's shape: authority that survives the revocation of the
 * authority it came from.
 *
 * Rights are the parent's, INTERSECTED with what a sub-region can mean -- never
 * widened. A caller holding a READ-only untyped cannot split a WRITE one out of
 * it.
 *
 * `SECURITY.md` **S58**.
 */
int untyped_split(uint32_t src_slot, uint32_t dest_slot, uint64_t bytes)
{
    if (bytes == 0) return SYS_ERR_INVAL;
    if (dest_slot >= CNODE_SIZE) return SYS_ERR_INVAL;
    /* KERNEL_RESERVED_CAPS: the low slots are the kernel's endowment and are not
     * a caller's to overwrite -- the same floor cap_mint enforces. */
    if (dest_slot < KERNEL_RESERVED_CAPS) return SYS_ERR_PERM;

    /* WRITE on the source: splitting consumes the region, exactly as retyping
     * does, so it takes the right that means "may spend this". */
    uint32_t parent = 0;
    if (untyped_from_slot(src_slot, CAP_RIGHT_WRITE, &parent) != 0)
        return SYS_ERR_PERM;

    ut_lock();
    struct untyped *pu = &untypeds[parent];

    /* Page-align the carve. A region whose base is not page-aligned cannot back
     * a KOBJ_FRAME, and a sub-region that silently could not hold the one object
     * class with an alignment requirement would be a capability that means less
     * than it says. */
    uint64_t start = align_up(pu->watermark, PAGE_SIZE);
    uint64_t take  = align_up(bytes, PAGE_SIZE);

    /* Overflow before bounds: `take` is caller-influenced, and start+take must
     * not wrap past the check that follows it. */
    if (take < bytes || start + take < start) { ut_unlock(); return SYS_ERR_INVAL; }
    if (start + take > pu->size)               { ut_unlock(); return SYS_ERR_NOMEM; }

    /* A free descriptor. The table bounds how many regions the kernel can NAME;
     * the arena bounds how much any authority can SPEND, and only the second is
     * a security property -- the same split of concerns dyn_ep_alloc_index makes
     * for endpoints. */
    int child = -1;
    for (int i = 0; i < MAX_UNTYPED; i++) {
        if (!untypeds[i].in_use) { child = i; break; }
    }
    if (child < 0) { ut_unlock(); return SYS_ERR_NOMEM; }

    /* Advance the parent FIRST. If anything below fails, the bytes stay spent
     * rather than being handed out twice -- the safe direction, and the same one
     * untyped_bump takes. */
#ifdef UNTYPED_SPLIT_FREE_BYTES
    /* CONTROL ARM -- never ship. The parent's watermark is NOT advanced, so the
     * sub-region is handed out while the parent still believes those bytes are
     * its own to spend. Two capabilities then name overlapping memory, and the
     * next object either of them carves lands on top of the other's: the
     * type-confusion this allocator's bump discipline exists to forbid, reached
     * through the syscall that is supposed to SPEND budget rather than mint it.
     *
     * It is also S57's accounting made a lie -- "a task given a small region can
     * spawn a bounded number of times" holds only if the giving costs something.
     * See make smoke-captest-split-control. */
    (void)0;
#else
    pu->watermark = start + take;
#endif

    untypeds[child].base      = pu->base + start;
    untypeds[child].size      = take;
    untypeds[child].watermark = 0;
    untypeds[child].objects   = 0;
    untypeds[child].in_use    = 1;
    ut_unlock();

    /* Derive the capability. cap_mint_untyped_child performs the same derivation
     * SYS_CAP_MINT does -- own serial, parent's serial as badge -- so the child
     * region's capability is a subtree of the parent's and a revoke sweeps it. */
    if (cap_mint_untyped_child(src_slot, dest_slot, (uint32_t)child) != 0) {
        /* The descriptor is released; the BYTES are not returned, because the
         * watermark never rewinds. A caller that could not receive the capability
         * has still spent the budget, which is the honest outcome under bump
         * discipline -- the alternative is a rewind that a concurrent carve
         * could interleave with. */
        ut_lock();
        untypeds[child].in_use = 0;
        untypeds[child].base = untypeds[child].size = untypeds[child].watermark = 0;
        ut_unlock();
        return SYS_ERR_PERM;
    }
    return 0;
}

int untyped_retype(uint32_t untyped_slot, uint32_t kobj_type, uint32_t count,
                   uint32_t pages, uint32_t dest_slot) {
    uint32_t u = 0;
    if (untyped_from_slot(untyped_slot, CAP_RIGHT_WRITE, &u) != 0)
        return SYS_ERR_PERM;

    /* Only the object classes a ring-3 task can actually USE are retypable from
     * ring 3. KOBJ_CNODE is allocatable (create_task does it) but has no
     * capability type naming it and no syscall that installs one as a task's
     * cspace, so minting one here would hand out authority with no defined
     * meaning -- refuse until there is something to refuse it FOR. */
    if (kobj_type != KOBJ_ENDPOINT && kobj_type != KOBJ_NOTIFICATION &&
        kobj_type != KOBJ_FRAME)
        return SYS_ERR_INVAL;

    if (count == 0) return SYS_ERR_INVAL;

    /* THE LENGTH, and it is refused rather than ignored on a class that has
     * none. A caller passing pages=8 for an endpoint has a wrong model of what
     * it is asking for, and quietly giving it one endpoint would leave that
     * model uncorrected until it mattered. 0 means "the ordinary case", which is
     * what every retype written before frames had a length passes. */
    if (kobj_type != KOBJ_FRAME) {
        if (pages != 0) return SYS_ERR_INVAL;
    } else {
        if (pages == 0) pages = 1;
        if (pages > MAX_FRAME_PAGES) return SYS_ERR_RANGE;
    }
    /* Bound the loop before touching anything: dest_slot + count must fit the
     * caller's cspace without wrapping, and the whole run must clear the
     * kernel-reserved slots. Checked up front so a partially-satisfiable request
     * is refused outright rather than half-applied. */
    if (dest_slot < KERNEL_RESERVED_CAPS) return SYS_ERR_PERM;
    if (count > CNODE_SIZE)               return SYS_ERR_RANGE;
    if (dest_slot > CNODE_SIZE - count)   return SYS_ERR_RANGE;

    uint32_t cap_type = (kobj_type == KOBJ_ENDPOINT)     ? CAP_ENDPOINT :
                        (kobj_type == KOBJ_NOTIFICATION) ? CAP_NOTIFICATION :
                                                           CAP_FRAME;
    /* A freshly retyped object is the creator's alone: full rights, including
     * REVOKE, because the holder is the only one who can have delegated any copy
     * of it. Narrowing on delegation is the grantee's problem, and cap_mint
     * already refuses to widen. */
    uint32_t rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT |
                      CAP_RIGHT_MINT | CAP_RIGHT_REVOKE;

    int created = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t obj_index = 0;
        void *mem = kobj_alloc(u, kobj_type, pages, &obj_index);
        if (!mem) break;   /* region or name table exhausted: stop, keep what we made */
        if (!cap_install_object(dest_slot + i, cap_type, (uint64_t)obj_index, rights, 0)) {
            /* The capability could not be installed (slot ceiling, authority),
             * so nothing will ever name this object. Drop it now rather than
             * leaking an unreachable object until the next sweep. Under the
             * untyped lock, like every other mutation of the index tables. */
            ut_lock();
            if (kobj_type == KOBJ_ENDPOINT)
                destroy_dyn_endpoint((int)(obj_index - DYN_EP_BASE));
            else if (kobj_type == KOBJ_NOTIFICATION)
                destroy_dyn_notification((int)(obj_index - DYN_NOTIF_BASE));
            else
                destroy_dyn_frame((int)(obj_index - DYN_FRAME_BASE));
            ut_unlock();
            break;
        }
        created++;
    }

    if (created == 0) return SYS_ERR_NOMEM;
    return created;
}

int untyped_info(uint32_t untyped_slot, struct untyped_info *out) {
    uint32_t u = 0;
    if (untyped_from_slot(untyped_slot, CAP_RIGHT_READ, &u) != 0)
        return SYS_ERR_PERM;
    if (!out) return SYS_ERR_FAULT;
    struct untyped *r = &untypeds[u];
    out->size      = r->size;
    out->watermark = r->watermark;
    out->free      = (r->watermark < r->size) ? (r->size - r->watermark) : 0;
    out->objects   = r->objects;
    out->reserved  = 0;
    return 0;
}


#ifdef IOMMU_TEARDOWN_SELFTEST
/* S53: destroying a frame removes every device's translation of it.
 *
 * WHY THIS IS AN IN-KERNEL TEST AND NOT A PACKET. The sibling gates for the
 * IOMMU (NET_IOMMU_NO_MAP and friends) make the DEVICE try, and prove the
 * property by whether a DMA round trip completes. That is the stronger shape and
 * it is the right one when the question is "can the device reach this". It is
 * the wrong one here, because the question is "is the translation gone once the
 * kernel has decided these bytes belong to nobody", and answering it with a DMA
 * means pointing a live device at a page the arena has already reallocated. A
 * test that has to commit the bug to observe the fix is not a test worth having.
 *
 * So this reads the device's second-level table directly through
 * iommu_translates(), which exists for exactly this and has no syscall behind
 * it. What that buys is determinism and no packet; what it costs is that the
 * witness is kernel state rather than device behaviour, and that limit is stated
 * rather than papered over: it shows the entry is removed, not that the device
 * observed its removal. The IOTLB invalidation that makes those the same thing
 * is iommu_flush(), which iommu_unmap() already issues and which this test does
 * not separately witness.
 *
 * The frame is destroyed through destroy_dyn_frame(), the real path, so the arm
 * below reproduces a defect in the shipping code rather than in a copy of it. */
void iommu_frame_teardown_selftest(void) {
    kmsg_begin();

    if (!iommu_active()) {
        print("IOMMUTEST: FAIL no-iommu (this gate boots with SMOKE_IOMMU=1)\n");
        return;
    }

    /* Any present device with a bdf will do: the property is about the domain,
     * not about which hardware owns it. Index 0 is permanently absent. */
    uint64_t dev = 0;
    uint16_t bdf = 0;
    for (uint64_t d = 1; d < IODEV_MAX; d++) {
        const struct io_device *io = iodev_get(d);
        if (io && io->present && io->bdf) { dev = d; bdf = io->bdf; break; }
    }
    if (!dev) {
        print("IOMMUTEST: FAIL no-device (this gate boots with SMOKE_NET)\n");
        return;
    }

    uint32_t idx = 0;
    void *mem = kobj_alloc(UNTYPED_ROOT, KOBJ_FRAME, 1, &idx);
    if (!mem) { print("IOMMUTEST: FAIL frame-alloc\n"); return; }
    uint64_t phys = (uint64_t)mem - PHYS_KVA_BASE;

    if (iommu_translates(dev, phys) != 0) {
        print("IOMMUTEST: FAIL translated-before-map\n");
        return;
    }
    if (iommu_map(dev, bdf, phys, 1, 1) != 0) {
        print("IOMMUTEST: FAIL map\n");
        return;
    }
    /* The positive half. Without it the assertion after the destroy is satisfied
     * by a mapping that was never installed, which is the same mistake as a
     * refusal test whose ungated path would have failed anyway. */
    if (iommu_translates(dev, phys) != 1) {
        print("IOMMUTEST: FAIL not-translated-after-map\n");
        return;
    }

    destroy_dyn_frame((int)(idx - DYN_FRAME_BASE));

    if (iommu_translates(dev, phys) != 0) {
        print("IOMMUTEST: FAIL device-still-translates-destroyed-frame\n");
        return;
    }

    print("IOMMUTEST: PASS\n");
}
#endif /* IOMMU_TEARDOWN_SELFTEST */
