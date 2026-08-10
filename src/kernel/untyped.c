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
 * objects the boot protocol names by index. tasks[] is not migrated: a TCB is
 * reachable from the scheduler's hot path and from every trap frame, so moving
 * it is its own change with its own tests.
 */
#include "kernel.h"
#include "errno.h"

/* Set by paging_init to PHYS_KVA(...) of the reserved arena. */
uint8_t *g_untyped_arena = 0;

struct untyped untypeds[MAX_UNTYPED];

/* Descriptor for one retyped endpoint / notification. These ARE `.bss`, and
 * deliberately so: what they cost is one pointer per addressable object, while
 * the objects themselves — the part that actually scales — live in untyped
 * memory. The array bounds how many retyped objects the kernel can NAME; the
 * untyped region bounds how many a given authority can CREATE, and only the
 * second is a security property. */
struct kobj_slot {
    void    *mem;        /* into the arena; NULL == this index holds no object */
    uint32_t untyped;    /* the region it was carved from (for accounting)     */
};
static struct kobj_slot dyn_eps[MAX_DYN_ENDPOINTS];
static struct kobj_slot dyn_notifs[MAX_DYN_NOTIFICATIONS];

/* ------------------------------------------------------------------------- *
 *  Locking.
 *
 *  The untyped tables are mutated in two very different contexts: at boot
 *  (untyped_init, then create_task(0) from scheduler_init) while the kernel is
 *  still single-threaded with no IDT-driven preemption, and at runtime from
 *  syscall context where two CPUs can race.
 *
 *  Taking a spinlock in the boot window is NOT safe here. spin_unlock() ends
 *  with an UNCONDITIONAL `sti` once the global nesting depth reaches zero --
 *  audit finding C-3.1, the defect roadmap 1.1 has to fix before the per-CPU
 *  lock can land, and which the ring-3 startup handshake currently depends on.
 *  Locking during early boot would therefore enable interrupts at a point the
 *  boot code never asked for, which is exactly the class of accident 1.1 exists
 *  to remove. So locking is ARMED (untyped_arm_locking) at the end of
 *  scheduler_init -- after the last unlocked boot mutation, and before anything
 *  that can run concurrently. Until then the kernel is single-threaded and the
 *  tables need no mutual exclusion.
 *
 *  Do not "simplify" this by locking unconditionally without first landing
 *  roadmap 1.1.
 * ------------------------------------------------------------------------- */
static spinlock_t untyped_lock;
static volatile int untyped_locking_armed = 0;

/* Armed at the END of scheduler_init: after create_task(0), the last unlocked
 * boot mutation, and before anything that can run concurrently. Set exactly
 * once, from single-threaded boot code, at a point where no ut_lock region is in
 * flight -- so lock and unlock always observe the same value and there is no
 * unlock-without-lock. */
void untyped_arm_locking(void) { untyped_locking_armed = 1; }

/* IF-TRANSPARENT critical section. This is the important part, not a flourish.
 *
 * spin_unlock() ends with an UNCONDITIONAL `sti` once the global nesting depth
 * reaches zero (finding C-3.1). kobj_alloc is called from create_task, and
 * kobj_gc from task_teardown -- neither of which took ANY lock before this
 * change, and both of which run on paths that keep interrupts masked
 * deliberately (task_teardown is reached from the page-fault handler; spawn runs
 * inside the ring-3 startup handshake). Letting the raw spin_unlock through made
 * `make smoke-console-smp` flaky: the shell banner sometimes never arrived
 * within the timeout, which is the same signature the reverted per-CPU-lock
 * attempt produced (roadmap 1.1) and for the same underlying reason.
 *
 * Saving and restoring RFLAGS around the region makes the sti a no-op for every
 * caller, whatever IF state it was in. It fixes the hazard once, in the helper,
 * instead of relying on each of the (currently four, later more) call sites to
 * remember a pushfq/popfq bracket.
 *
 * Nesting is correct in both directions: with cap_lock already held (kobj_gc
 * from cap_revoke) the depth goes 1->2->1 so no sti fires and popfq restores the
 * masked state; standalone it goes 0->1->0, the sti fires, and popfq undoes it.
 *
 * This becomes redundant -- not wrong -- once roadmap 1.1 makes spin_unlock
 * IF-preserving. Do not remove it before then. */
static inline uint64_t ut_lock(void) {
    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0" : "=r"(fl) :: "memory");
    if (untyped_locking_armed) spin_lock(&untyped_lock);
    return fl;
}
static inline void ut_unlock(uint64_t fl) {
    if (untyped_locking_armed) spin_unlock(&untyped_lock);
    __asm__ volatile ("push %0; popfq" :: "r"(fl) : "memory", "cc");
}

/* ------------------------------------------------------------------------- *
 *  Object sizes and the bump allocator.
 * ------------------------------------------------------------------------- */

/* Every allocation is 64-byte aligned. Alignment is not a performance choice:
 * a capability_t array must be 8-aligned for the Rust FFI's layout assertions to
 * hold over it, and rounding to a cache line additionally guarantees two objects
 * carved from the same region never share a line, so a false-sharing stall
 * cannot turn into a cross-object timing signal under SMP. */
#define KOBJ_ALIGN 64

static uint64_t kobj_size(uint32_t kobj_type) {
    switch (kobj_type) {
        case KOBJ_CNODE:        return (uint64_t)CNODE_SIZE * sizeof(capability_t);
        case KOBJ_ENDPOINT:     return sizeof(struct endpoint);
        case KOBJ_NOTIFICATION: return sizeof(struct notification);
        default:                return 0;
    }
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
static void *untyped_bump(struct untyped *u, uint64_t bytes) {
    if (!u->in_use || !g_untyped_arena) return 0;
    uint64_t start = align_up(u->watermark, KOBJ_ALIGN);
    /* Overflow-safe headroom test: compare remaining against need, never
     * start+bytes against size (which can wrap on a crafted count). */
    if (start >= u->size)             return 0;
    if (bytes > u->size - start)      return 0;
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

uint32_t kobj_live_count(uint32_t kobj_type) {
    uint32_t n = 0;
    if (kobj_type == KOBJ_ENDPOINT) {
        for (int i = 0; i < MAX_DYN_ENDPOINTS; i++) if (dyn_eps[i].mem) n++;
    } else if (kobj_type == KOBJ_NOTIFICATION) {
        for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++) if (dyn_notifs[i].mem) n++;
    }
    return n;
}

/* ------------------------------------------------------------------------- *
 *  Allocation.
 * ------------------------------------------------------------------------- */

void *kobj_alloc(uint32_t untyped_index, uint32_t kobj_type, uint32_t *out_index) {
    if (untyped_index >= MAX_UNTYPED) return 0;
    uint64_t need = kobj_size(kobj_type);
    if (need == 0) return 0;

    uint64_t fl = ut_lock();
    struct untyped *u = &untypeds[untyped_index];

    /* Claim the index BEFORE bumping the watermark: an index table that is full
     * must not consume region bytes it can then never hand out. (The watermark
     * never moves backwards, so a failed allocation after a bump would leak.) */
    int idx = -1;
    if (kobj_type == KOBJ_ENDPOINT) {
        idx = dyn_ep_alloc_index();
        if (idx < 0) { ut_unlock(fl); return 0; }
    } else if (kobj_type == KOBJ_NOTIFICATION) {
        idx = dyn_notif_alloc_index();
        if (idx < 0) { ut_unlock(fl); return 0; }
    }

    void *mem = untyped_bump(u, need);
    if (!mem) { ut_unlock(fl); return 0; }

    if (kobj_type == KOBJ_ENDPOINT) {
        struct endpoint *e = (struct endpoint *)mem;
        /* A fresh endpoint must not start life claiming task 0 as its sender or
         * waiter: zeroed memory means index 0, and 0 is a real task. The queue
         * ring needs the same treatment per slot (roadmap 1.3). */
        e->head           = 0;
        e->count          = 0;
        e->last_sender    = -1;
        e->blocked_waiter = -1;
        e->recv_waiter    = -1;
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
    } else {
        /* KOBJ_CNODE: no object index -- a cspace is reached through the owning
         * task's tcb, not by index. */
        if (out_index) *out_index = 0;
    }

    u->objects++;
    ut_unlock(fl);
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
static void mark_cap(const capability_t *c, uint8_t *ep_marks, uint8_t *nt_marks) {
    if (c->serial == 0) return;   /* empty slot */
    if (c->type == CAP_ENDPOINT) {
        if (c->object >= DYN_EP_BASE && c->object < EP_INDEX_MAX)
            ep_marks[c->object - DYN_EP_BASE] = 1;
    } else if (c->type == CAP_NOTIFICATION) {
        if (c->object >= DYN_NOTIF_BASE && c->object < NOTIF_INDEX_MAX)
            nt_marks[c->object - DYN_NOTIF_BASE] = 1;
    }
}

/* One pass over every live cspace plus the kernel root cnode, marking each
 * retyped object some capability names. ONE pass, not one per object: the naive
 * "is this object named?" form is O(objects x tasks x cspace), which at a full
 * index table is millions of reads on every revoke and every task exit. */
static void mark_reachable(uint8_t *ep_marks, uint8_t *nt_marks) {
    for (int i = 0; i < MAX_DYN_ENDPOINTS; i++)     ep_marks[i] = 0;
    for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++) nt_marks[i] = 0;

    for (int t = 0; t < MAX_TASKS; t++) {
        if (tasks[t].state == 0 || !tasks[t].cspace) continue;
        uint32_t sz = tasks[t].cspace_size ? tasks[t].cspace_size : CNODE_SIZE;
        if (sz > CNODE_SIZE) sz = CNODE_SIZE;
        for (uint32_t s = 0; s < sz; s++) mark_cap(&tasks[t].cspace[s], ep_marks, nt_marks);
    }
    /* The kernel root cnode is not any task's cspace; sweep it too, so a
     * kernel-held capability keeps its object alive. */
    const capability_t *root = cap_root_cnode_ref();
    for (uint32_t s = 0; s < CNODE_SIZE; s++) mark_cap(&root[s], ep_marks, nt_marks);
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
    if (w > 0 && w < MAX_TASKS && tasks[w].state != 0) {
        tasks[w].state        = TASK_RUNNABLE;
        tasks[w].runnable_ctx = 1;
        tasks[w].blocked_on   = -1;
    }
    /* Same reasoning for a server asleep in SYS_IPC_WAIT_RECV: the object it was
     * waiting for work on has gone, so no send can ever arrive. Leaving it asleep
     * would strand it forever on an endpoint that no longer exists. */
    int rw = e->recv_waiter;
    if (rw > 0 && rw < MAX_TASKS && tasks[rw].state != 0) {
        tasks[rw].state        = TASK_RUNNABLE;
        tasks[rw].runnable_ctx = 1;
        tasks[rw].blocked_on   = -1;
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
    if (w > 0 && w < MAX_TASKS && tasks[w].state != 0) {
        tasks[w].state           = TASK_RUNNABLE;
        tasks[w].runnable_ctx    = 1;
        tasks[w].blocked_on_notif = -1;
    }
    zero_bytes((uint8_t *)n, sizeof(*n));
    if (dyn_notifs[i].untyped < MAX_UNTYPED && untypeds[dyn_notifs[i].untyped].objects > 0)
        untypeds[dyn_notifs[i].untyped].objects--;
    dyn_notifs[i].mem = 0;
}

/* Mark bitmaps. Static rather than on the stack: kobj_gc runs from
 * task_teardown, which is reached from the page-fault handler on a kernel stack
 * that has no room for half a KiB of scratch. Safe as statics because every
 * caller holds the untyped lock across the whole mark-and-sweep. */
static uint8_t gc_ep_marks[MAX_DYN_ENDPOINTS];
static uint8_t gc_nt_marks[MAX_DYN_NOTIFICATIONS];

void kobj_gc(void) {
    uint64_t fl = ut_lock();
    mark_reachable(gc_ep_marks, gc_nt_marks);
    for (int i = 0; i < MAX_DYN_ENDPOINTS; i++)
        if (dyn_eps[i].mem && !gc_ep_marks[i]) destroy_dyn_endpoint(i);
    for (int i = 0; i < MAX_DYN_NOTIFICATIONS; i++)
        if (dyn_notifs[i].mem && !gc_nt_marks[i]) destroy_dyn_notification(i);
    ut_unlock(fl);
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
    uint64_t kernel_half = (uint64_t)MAX_TASKS * align_up((uint64_t)CNODE_SIZE * sizeof(capability_t), KOBJ_ALIGN);
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

/* The arena must be big enough for the kernel half plus a usable user half.
 * Static, because a boot that discovers this at runtime has already committed to
 * a layout it cannot satisfy. */
_Static_assert(UNTYPED_ARENA_BYTES >
                   2u * MAX_TASKS * CNODE_SIZE * sizeof(capability_t),
               "UNTYPED_ARENA_BYTES must leave a user half at least as large as "
               "the kernel cspace reserve");

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

int untyped_retype(uint32_t untyped_slot, uint32_t kobj_type, uint32_t count,
                   uint32_t dest_slot) {
    uint32_t u = 0;
    if (untyped_from_slot(untyped_slot, CAP_RIGHT_WRITE, &u) != 0)
        return SYS_ERR_PERM;

    /* Only the object classes a ring-3 task can actually USE are retypable from
     * ring 3. KOBJ_CNODE is allocatable (create_task does it) but has no
     * capability type naming it and no syscall that installs one as a task's
     * cspace, so minting one here would hand out authority with no defined
     * meaning -- refuse until there is something to refuse it FOR. */
    if (kobj_type != KOBJ_ENDPOINT && kobj_type != KOBJ_NOTIFICATION)
        return SYS_ERR_INVAL;

    if (count == 0) return SYS_ERR_INVAL;
    /* Bound the loop before touching anything: dest_slot + count must fit the
     * caller's cspace without wrapping, and the whole run must clear the
     * kernel-reserved slots. Checked up front so a partially-satisfiable request
     * is refused outright rather than half-applied. */
    if (dest_slot < KERNEL_RESERVED_CAPS) return SYS_ERR_PERM;
    if (count > CNODE_SIZE)               return SYS_ERR_RANGE;
    if (dest_slot > CNODE_SIZE - count)   return SYS_ERR_RANGE;

    uint32_t cap_type = (kobj_type == KOBJ_ENDPOINT) ? CAP_ENDPOINT : CAP_NOTIFICATION;
    /* A freshly retyped object is the creator's alone: full rights, including
     * REVOKE, because the holder is the only one who can have delegated any copy
     * of it. Narrowing on delegation is the grantee's problem, and cap_mint
     * already refuses to widen. */
    uint32_t rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_GRANT |
                      CAP_RIGHT_MINT | CAP_RIGHT_REVOKE;

    int created = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t obj_index = 0;
        void *mem = kobj_alloc(u, kobj_type, &obj_index);
        if (!mem) break;   /* region or name table exhausted: stop, keep what we made */
        if (!cap_install_object(dest_slot + i, cap_type, (uint64_t)obj_index, rights, 0)) {
            /* The capability could not be installed (slot ceiling, authority),
             * so nothing will ever name this object. Drop it now rather than
             * leaking an unreachable object until the next sweep. Under the
             * untyped lock, like every other mutation of the index tables. */
            uint64_t dfl = ut_lock();
            if (kobj_type == KOBJ_ENDPOINT)
                destroy_dyn_endpoint((int)(obj_index - DYN_EP_BASE));
            else
                destroy_dyn_notification((int)(obj_index - DYN_NOTIF_BASE));
            ut_unlock(dfl);
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
