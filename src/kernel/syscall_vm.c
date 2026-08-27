/* syscall_vm.c -- frame capabilities and the virtual-memory syscalls.
 *
 * Roadmap 2.1, audit finding F-2.1. A KOBJ_FRAME is one page carved out of an
 * untyped region by the existing SYS_RETYPE; a CAP_FRAME names it by index; and
 * SYS_MAP_FRAME installs it in the caller's own address space with the rights
 * that capability carries. Two tasks holding capabilities for the same frame
 * index have genuine shared memory, and each one's PTE says only what its own
 * capability permits -- which is what makes the sharing safe between tasks that
 * do not trust each other.
 *
 * ---- WHY THIS IS A SEPARATE FILE FROM syscall_hw.c ------------------------
 *
 * SYS_MAP_PHYS next door looks like the same operation and is the opposite one.
 * There, the frame is named by a PHYSICAL ADDRESS the caller supplies, and the
 * whole security argument is a fixed allowlist of two device ranges plus a
 * CAP_IO_DEVICE that only the console server holds: the capability says "you are
 * a driver", and a table decides which frames a driver may touch. Here the
 * capability names the frame itself, there is no allowlist, and no caller ever
 * supplies a physical address at all. Keeping them in one file would invite a
 * shared helper, and a shared helper would have to take the physical address as
 * a parameter -- which is the property this design exists to remove.
 *
 * ---- WHAT AUTHORISES EACH SYSCALL -----------------------------------------
 *
 * All three are SC_NONE in the dispatch table, with the lookup in the handler,
 * for the reason spelled out at the SYS_RETYPE entry in syscall.c: the
 * authorising capability is the one the CALLER NAMES in an argument, and a fixed
 * table slot here would repeat the C-1 mistake exactly -- gating on a capability
 * every task happens to hold while never consulting the one that names the
 * resource. That mistake is not hypothetical for this file. Every task is born
 * holding a CAP_FRAME in slot 3, and a table entry reading
 * `{ h_map_frame, CAPSLOT_FRAME, CAP_RIGHT_WRITE, CAP_FRAME }` would have
 * type-checked, passed the gate for every task in the system, and authorised
 * nothing.
 */
#include "syscall_internal.h"
#include "errno.h"

/* The user (lower) canonical half. user_pte_slot() independently refuses
 * pml4[256..511], so this is the second of two checks rather than the only one;
 * it is here to turn "the map failed" into a specific SYS_ERR_INVAL the caller
 * can act on. */
#define USER_HALF_LIMIT   0x0000800000000000ULL

/* The authority decision: what rights this mapping may actually carry.
 *
 * `have` is what the capability carries, `want` is what the caller asked for,
 * and the answer is the intersection. It returns RIGHTS rather than PTE bits on
 * purpose: the bits are paging.c's (defined there and nowhere else), and the
 * decision is this file's, because this is where the capability is. Splitting it
 * the other way would put an authority decision inside the page-table code,
 * where the capability that justifies it is no longer in scope.
 *
 * ---- WHY THE INTERSECTION IS NOT THE GATE, AND WHAT IS --------------------
 *
 * The real gate is one line up, at cap_lookup(slot, rights): it refuses unless
 * the capability holds AT LEAST every right requested. Given that, `have & want`
 * is arithmetically equal to `want` at every reachable call -- the intersection
 * cannot subtract a bit the lookup did not already require.
 *
 * That was worth writing down because the first draft of this change shipped a
 * control arm against the intersection (build the flags from `want` alone) and
 * the arm could not fail: under it and without it, the same PTE. A control arm
 * that cannot fail measures nothing, and this file would have carried one with
 * a table row in CLAUDE.md claiming it did. FRAME_RIGHTS_UNCHECKED=1 removes the
 * lookup floor instead -- the thing that actually decides -- so a READ-only
 * capability maps writable and the delegate's write lands.
 *
 * The intersection stays. It is not the gate, but it is what keeps the two from
 * having to be re-derived together if the floor is ever relaxed to admit a
 * caller asking for less than it holds. */
static uint32_t frame_effective_rights(uint32_t have, uint32_t want) {
    return have & want;
}

/* The rights floor. Under FRAME_RIGHTS_UNCHECKED=1 the lookup asks for nothing,
 * so any live CAP_FRAME satisfies it whatever rights it carries -- and since the
 * intersection above then has a `have` that no longer bounds `want`, the mapping
 * is built from the request alone. That is the defect: delegation stops
 * reducing. */
static uint32_t frame_required_rights(uint32_t want) {
#ifdef FRAME_RIGHTS_UNCHECKED
    (void)want;
    return 0;
#else
    return want;
#endif
}

/* ---- A RUN OF PAGES, MAPPED AS A UNIT ------------------------------------
 *
 * `pages` contiguous physical pages from `phys` at `pages` contiguous virtual
 * pages from `vaddr`. All-or-nothing, for the reason SYS_MAP_REGION is
 * all-or-nothing (see its comment): a PTE is authority, so a call that reports
 * failure must not have installed one.
 *
 * The unwind here is O(1) in state and not merely bounded: the run is
 * contiguous, so page k lives at `phys + k * PAGE_SIZE` and needs no record at
 * all. That is the whole reason a frame carries a LENGTH rather than a caller
 * assembling one out of separate capabilities -- the same policy costs nothing
 * to honour, and MAX_FRAME_PAGES is a bound on the arena rather than on what the
 * kernel can remember about the run.
 */
static int map_run(uint32_t cur, uint64_t vaddr, uint64_t phys, uint32_t pages,
                   uint32_t eff) {
    for (uint32_t k = 0; k < pages; k++) {
#ifdef FRAME_PAGES_SAME_PHYS
        /* CONTROL ARM: advance the VIRTUAL address and not the physical one, so
         * every page of the run aliases the frame's first page. It is the
         * plausible slip -- one of two cursors forgotten in a loop that reads
         * correctly -- and it is not a crash: the caller gets `pages` present,
         * writable, correctly-righted pages that silently share one page of
         * storage. A buffer that quietly aliases itself is worse than one that
         * fails to map, because nothing reports it. */
        uint64_t page_phys = phys;
#else
        uint64_t page_phys = phys + (uint64_t)k * PAGE_SIZE;
#endif
        int rc = user_map_frame_page(cur, vaddr + (uint64_t)k * PAGE_SIZE,
                                     page_phys, eff);
        if (rc == 0) continue;

#ifndef FRAME_REGION_NO_ROLLBACK
        /* Withdraw what this call installed, and only that: pages 0..k-1.
         * Page k was never mapped, and whatever occupies it is not ours. */
        for (uint32_t u = k; u-- > 0; ) {
#ifdef FRAME_PAGES_SAME_PHYS
            uint64_t undo_phys = phys;
#else
            uint64_t undo_phys = phys + (uint64_t)u * PAGE_SIZE;
#endif
            (void)user_unmap_frame_page(cur, vaddr + (uint64_t)u * PAGE_SIZE,
                                        undo_phys);
        }
#endif
        return (rc == -2) ? SYS_ERR_EXIST : SYS_ERR_FAULT;
    }
    return 0;
}

/* Withdraw a whole run. Used by SYS_UNMAP_FRAME, which is a whole-object
 * operation: a frame is mapped as a unit and released as a unit, so nothing in
 * this tree ever leaves half a run installed. destroy_dyn_frame relies on that
 * -- it asks every page whether it is still mapped, and the answer is uniform
 * because these two functions are the only things that move it. */
static int unmap_run(uint32_t cur, uint64_t vaddr, uint64_t phys, uint32_t pages) {
    int first_err = 0;
    for (uint32_t k = 0; k < pages; k++) {
        int rc = user_unmap_frame_page(cur, vaddr + (uint64_t)k * PAGE_SIZE,
                                       phys + (uint64_t)k * PAGE_SIZE);
        /* Keep going on a failure rather than stopping. Stopping would leave the
         * REST of the run mapped after an unmap the caller believes happened,
         * which is the fail-open direction; the first error is what it hears. */
        if (rc != 0 && first_err == 0) first_err = SYS_ERR_INVAL;
    }
    return first_err;
}

/* ---- ONE FRAME OF A MAP REQUEST ------------------------------------------
 *
 * The whole per-object decision -- slot bound, rights shape, W^X, capability,
 * type, frame index, length, address span, revalidation, effective rights -- in
 * one place, because SYS_MAP_FRAME and SYS_MAP_REGION must not be able to drift
 * apart.
 *
 * That is not tidiness. A region map that validated one step less than a single
 * map would be a new door of exactly the shape this file exists to close, and
 * two hand-maintained copies of a nine-step check is precisely how a door like
 * that opens: the second copy is written by reading the first, and the next
 * person to add a step adds it to whichever one they were looking at. [H-3] was
 * six copies of one gate, five of which nobody had revisited.
 *
 * Returns 0 or a SYS_ERR_*; on success *out_phys and *out_pages name the run
 * that was mapped, which is what a caller needs in order to withdraw it again.
 *
 * `single_page_only` is set by SYS_MAP_REGION. A run of slots maps each slot at
 * the next page, so a sized frame in the middle of one would make the address of
 * every later slot depend on the length of every earlier capability -- an ABI
 * where you cannot say where slot 5 landed without reading slots 0..4. Refused
 * there, and mapped whole by SYS_MAP_FRAME instead.
 */
static int map_one_frame_object(uint32_t slot, uint64_t vaddr, uint32_t rights,
                                int single_page_only,
                                uint64_t *out_phys, uint32_t *out_pages) {
    if (slot >= CNODE_SIZE) return SYS_ERR_INVAL;

    /* At least one access right must be requested. An empty request would map a
     * present page with no meaning -- x86-64 has no read-disable bit, so "no
     * access" is not a mapping the hardware can express -- and guessing READ on
     * the caller's behalf is the kind of helpfulness that becomes an authority
     * bug. A caller bug, refused, rather than a no-op. */
    if (!(rights & (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC)))
        return SYS_ERR_INVAL;

    /* W^X, for ring 3, at the only place ring 3 can ask for both. The kernel's
     * own W^X is enforced at link and verified by smoke-wx; a frame is the first
     * object userspace can point at an address of its choosing, so it is the
     * first place userspace could have built a writable code page. Refused
     * outright rather than silently dropping one of the two bits: a caller that
     * asked for W|X has a wrong model of what it is doing, and a mapping that
     * quietly differs from the request is worse than an error. */
    if ((rights & CAP_RIGHT_WRITE) && (rights & CAP_RIGHT_EXEC))
        return SYS_ERR_INVAL;

    /* THE GATE. cap_lookup enforces type-agnostic liveness and the rights floor;
     * the type test is what stops a CAP_ENDPOINT or a CAP_TCB standing in for a
     * frame. Both are required -- C-1 was a live capability of the wrong type
     * satisfying a gate that only asked for liveness. */
    capability_t *cap = cap_lookup(slot, frame_required_rights(rights));
    if (!cap || cap->type != CAP_FRAME) return SYS_ERR_PERM;

    cap_snapshot_t snap = cap_snapshot(cap);
    uint32_t have  = cap->rights;
    uint32_t index = (uint32_t)cap->object;

    /* THE BOUND that refuses the legacy slot-3 CAP_FRAME. Its object is
     * USER_AREA_BASE, a virtual address; frame_phys_by_index answers 0 for
     * anything outside [DYN_FRAME_BASE, FRAME_INDEX_MAX) and for any index whose
     * descriptor is dead, so one test covers both. Under
     * FRAME_INDEX_UNCHECKED=1, frame_phys_by_index returns the object AS a
     * physical address without consulting the table at all -- the shortcut this
     * design exists to refuse -- and the legacy capability resolves to
     * 0x400000. That arm is what makes frametest's refusal check a measurement
     * rather than an assertion. */
    uint64_t phys = frame_phys_by_index(index);
    if (phys == 0) return SYS_ERR_INVAL;

    /* THE LENGTH, asked rather than assumed. A map path that took the base and
     * stopped would hand the caller one page of a buffer it believes is whole --
     * and the pages beyond it would stay unmapped while the capability said
     * otherwise, which is a fault at an address the caller has every reason to
     * think it owns. */
    uint32_t pages = frame_pages_by_index(index);
    if (pages == 0 || pages > MAX_FRAME_PAGES) return SYS_ERR_INVAL;
    if (single_page_only && pages != 1) return SYS_ERR_INVAL;

    if ((vaddr & (PAGE_SIZE - 1)) || vaddr == 0) return SYS_ERR_INVAL;

    /* THE SPAN, including its last byte. With a length, "the address is in the
     * user half" is no longer the same question as "the mapping is": a run
     * starting one page below the limit walks past it. Written as
     * `vaddr > LIMIT - span` rather than `vaddr + span > LIMIT` so it cannot
     * wrap past the test instead of failing it.
     *
     * This is the SECOND of two checks, not the only one: user_pte_slot refuses
     * pml4[256..511] independently, so a run that got here would still be
     * refused page by page. It earns its place by turning "the map failed
     * part-way and unwound" into one specific SYS_ERR_INVAL before anything is
     * installed -- and an arm against it would measure the error code, not the
     * outcome, which is why it does not have one. */
    uint64_t span = (uint64_t)pages * PAGE_SIZE;
    if (vaddr > USER_HALF_LIMIT - span) return SYS_ERR_INVAL;

    /* Reconfirm the capability's identity before committing. A concurrent revoke
     * on another CPU between the lookup above and the map below would otherwise
     * install a mapping for authority that no longer exists -- and unlike a
     * dropped IPC message, a stale PTE persists until something unmaps it. */
    if (snap.valid && !cap_revalidate(slot, frame_required_rights(rights), &snap))
        return SYS_ERR_PERM;

    int cur = get_current_task();
#ifdef FRAME_RIGHTS_UNCHECKED
    /* The arm removes the floor, so `have` no longer bounds `rights`; feeding
     * the intersection here would re-impose by accident what the floor used to
     * impose on purpose, and the arm would go back to measuring nothing. */
    uint32_t eff = rights; (void)have;
#else
    uint32_t eff = frame_effective_rights(have, rights);
#endif
    /* SYS_ERR_EXIST comes back from map_run when something is already mapped in
     * the run. A distinct code, because "that address is occupied" and "that
     * address is not allowed" are different problems for the caller and only one
     * of them is fixable by choosing another address. */
    int rc = map_run((uint32_t)cur, vaddr, phys, pages, eff);
    if (rc != 0) return rc;

    audit_log(AUDIT_CAP_OPERATION, index, 0, "frame mapped");
    if (out_phys)  *out_phys  = phys;
    if (out_pages) *out_pages = pages;
    return 0;
}

/* ---- SYS_MAP_FRAME --------------------------------------------------------
 *
 * (frame_slot, vaddr, rights) -> 0. Map the frame named by the CAP_FRAME in
 * `frame_slot` at `vaddr` in the caller's own address space.
 *
 * Fails closed on every irregularity, and the order matters: the capability is
 * resolved first so that a caller holding no authority learns nothing about
 * which addresses are valid. */
void h_map_frame(struct interrupt_frame64 *r) {
    /* Maps the WHOLE frame -- every page of the run the capability names -- and
     * is all-or-nothing across it. The return stays a status rather than
     * becoming a page count, for the reason SYS_MAP_REGION's does: under
     * all-or-nothing there is nothing to count, and a success value that used to
     * be 0 becoming 1 would break every caller that tests `== 0`. A caller that
     * needs the length knows it from the retype that made the frame. */
    int rc = map_one_frame_object((uint32_t)r->rbx, r->rcx, (uint32_t)r->rdx,
                                  0, (uint64_t *)0, (uint32_t *)0);
    r->rax = (uint32_t)rc;
}

/* ---- SYS_UNMAP_FRAME ------------------------------------------------------
 *
 * (frame_slot, vaddr) -> 0. Remove the mapping of the caller's frame at `vaddr`.
 *
 * The capability is required for the unmap as well as the map, and it is not
 * ceremony: it is what confines the operation to memory the caller was entitled
 * to map in the first place. A `SYS_UNMAP_FRAME(vaddr)` taking only an address
 * would let any task unmap its own image, stack or heap -- pages it holds no
 * frame capability for -- turning a memory-sharing syscall into an arbitrary
 * self-corruption primitive. user_unmap_frame_page additionally requires the PTE
 * to name this capability's own frame, so naming a valid frame does not let a
 * caller tear down an unrelated address that happens to be mapped. */
void h_unmap_frame(struct interrupt_frame64 *r) {
    uint32_t slot  = (uint32_t)r->rbx;
    uint64_t vaddr = r->rcx;

    if (slot >= CNODE_SIZE) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    /* No rights floor beyond holding the capability: unmapping withdraws
     * authority from the caller's own address space and can only ever reduce
     * what it can reach, so requiring WRITE would refuse a read-only sharer the
     * ability to let go of a page. */
    capability_t *cap = cap_lookup(slot, 0);
    if (!cap || cap->type != CAP_FRAME) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    uint64_t phys  = frame_phys_by_index((uint32_t)cap->object);
    uint32_t pages = frame_pages_by_index((uint32_t)cap->object);
    if (phys == 0 || pages == 0 || pages > MAX_FRAME_PAGES) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    if ((vaddr & (PAGE_SIZE - 1)) || vaddr == 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    uint64_t span = (uint64_t)pages * PAGE_SIZE;
    if (vaddr > USER_HALF_LIMIT - span) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    /* WITHDRAWS THE WHOLE RUN. A frame is mapped as a unit, so it is released as
     * a unit -- and that symmetry is load-bearing rather than tidy:
     * destroy_dyn_frame decides a run is collectable by asking every page
     * whether it is still mapped, and it can rely on the answer being uniform
     * only because these are the sole operations that move it. A partial unmap
     * syscall would make "is this frame still in use" a question with a
     * different answer per page. */
    int cur = get_current_task();
    int rc = unmap_run((uint32_t)cur, vaddr, phys, pages);
    r->rax = (rc == 0) ? 0 : (uint32_t)SYS_ERR_INVAL;
}

/* ---- SYS_MAP_REGION -------------------------------------------------------
 *
 * (first_slot, count, vaddr, rights) -> 0. Map `count` frames, named by the
 * CAP_FRAMEs in cspace slots first_slot .. first_slot+count-1, at consecutive
 * page-aligned addresses starting at `vaddr`.
 *
 * It is the exact dual of SYS_RETYPE(untyped, KOBJ_FRAME, count, dest), which
 * fills a run of slots: this maps the run that call produced.
 *
 * ---- THE PARTIAL-FAILURE POLICY (roadmap 2.1's open question) -------------
 *
 * ALL OR NOTHING. If any page of the run cannot be mapped, every page this call
 * already mapped is withdrawn and the call returns the failing page's error. A
 * caller that receives an error holds exactly the address space it started with.
 *
 * THIS IS THE OPPOSITE OF WHAT untyped_retype DOES, deliberately, and the
 * asymmetry is in the primitives rather than in taste. Retype stops at the first
 * failure, keeps what it made, and returns the count. That is right there and
 * would be wrong here:
 *
 *   * Retype's partial result is COMPLETE INFORMATION. n objects exist, each
 *     named by a capability at a slot the caller computed; it can enumerate
 *     them, use them, or destroy them. A partial MAP is a hole in an address
 *     range whose entire purpose is to be addressed AS a range -- the caller
 *     does not discover page 3 is absent at the call, it discovers it as a fault
 *     at some arbitrary later instruction, with nothing left to say which call
 *     was responsible.
 *
 *   * FAIL CLOSED means a call that reports failure installs no authority. A PTE
 *     is authority -- it is the thing that lets ring 3 touch the page. Retype's
 *     partial success installs capabilities the caller ASKED for and is told
 *     about in the return value; a partial map after a reported error is
 *     authority the caller was told it did not get.
 *
 *   * ROLLBACK IS EXACTLY BOUNDED HERE AND IS NOT IN RETYPE. This call knows
 *     which PTEs it installed -- pages 0..done-1, at addresses it computed, each
 *     naming a frame it resolved -- so withdrawing them cannot touch a mapping
 *     that was already there. Unwinding a retype would mean DESTROYING objects,
 *     and a destroyed frame's bytes are not reclaimable until its untyped region
 *     is revoked and reset (docs/LIMITATIONS.md), so rollback there would lose
 *     memory to buy nothing.
 *
 * WHY NOT A COUNT. This returns 0 or an error, never "3 of 5". Prefix semantics
 * on a mapping call put the cleanup on a caller that has just been told it
 * failed, and a caller applying the convention every other syscall here uses --
 * treat < 0 as the failure -- would silently keep 3 pages it believes it does
 * not have. The count is redundant under all-or-nothing anyway: it is `count`.
 *
 * WHY NOT "WHICH PAGE". The error says what went wrong, not where. Under
 * all-or-nothing the caller's response is the same whichever page caused it, so
 * an index would be ABI surface bought for nothing. It can still be recovered
 * by walking the run one SYS_MAP_FRAME at a time.
 */

/* The rollback has to remember one physical address per page it installed, and
 * that record lives on the kernel stack -- so the bound on the region is the
 * bound on the record. 64 pages is 256 KiB, and already a quarter of the 256
 * frames MAX_DYN_FRAMES lets the kernel NAME at once, so this is not the limit a
 * real workload meets first. A larger region is the region-OBJECT work (a length
 * carried in the capability, roadmap 2.1), not a bigger array here. */
#define FRAME_REGION_MAX  64

void h_map_region(struct interrupt_frame64 *r) {
    uint32_t first  = (uint32_t)r->rbx;
    uint32_t count  = (uint32_t)r->rcx;
    uint64_t vaddr  = r->rdx;
    uint32_t rights = (uint32_t)r->rsi;

    /* THE SHAPE OF THE RUN IS CHECKED BEFORE ANYTHING IS TOUCHED, in
     * untyped_retype's discipline: a request that cannot be satisfied in
     * principle is refused outright rather than half-applied and unwound.
     * Rollback answers a page that fails on its own merits; it is not a
     * substitute for knowing whether the request was ever coherent. */
    if (count == 0)                 { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (count > FRAME_REGION_MAX)   { r->rax = (uint32_t)SYS_ERR_RANGE; return; }
    if (first >= CNODE_SIZE)        { r->rax = (uint32_t)SYS_ERR_INVAL; return; }
    if (first > CNODE_SIZE - count) { r->rax = (uint32_t)SYS_ERR_RANGE; return; }

    /* The address run must be aligned, non-zero, and entirely inside the user
     * half INCLUDING ITS LAST BYTE. Computing the end up front is what stops a
     * run that starts legally and walks into the kernel half one page at a time;
     * expressing the test as `vaddr > LIMIT - span` rather than
     * `vaddr + span > LIMIT` is what stops it wrapping past the check instead of
     * failing it. (count is bounded above, so span cannot overflow; the form is
     * kept because it stays correct if that bound is ever raised.) */
    if ((vaddr & (PAGE_SIZE - 1)) || vaddr == 0) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }
    uint64_t span = (uint64_t)count * PAGE_SIZE;
    if (vaddr > USER_HALF_LIMIT - span) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    uint64_t mapped_phys[FRAME_REGION_MAX];
    uint32_t done = 0;
    int err = 0;

    for (uint32_t i = 0; i < count; i++) {
        err = map_one_frame_object(first + i, vaddr + (uint64_t)i * PAGE_SIZE,
                                   rights, 1, &mapped_phys[i], (uint32_t *)0);
        if (err != 0) break;
        done = i + 1;
    }

    if (err == 0) { r->rax = 0; return; }

#ifdef FRAME_REGION_NO_ROLLBACK
    /* CONTROL ARM: prefix semantics -- report the failure and keep whatever was
     * mapped before it. This is the policy the paragraph above rejects, and it
     * is what the call would do if the unwind were simply forgotten. frametest's
     * region-rollback checks fail under it. */
    (void)mapped_phys; (void)done;
#else
    /* THE ROLLBACK. Strictly indices below the one that failed: page `done` was
     * never mapped by this call, and whatever occupies it belongs to whoever
     * installed it. An unwind that cleared the whole REQUESTED range would
     * answer a refused request by destroying the mapping that refused it -- a
     * worse outcome than the failure it is cleaning up after, and reachable from
     * ring 3 by asking to map over an address you want gone. frametest checks
     * both directions: the pages this call installed are withdrawn, and the page
     * that was already there survives.
     *
     * Withdrawal names the frame, not just the address: user_unmap_frame_page
     * requires the PTE to hold this exact physical page, which is why the run is
     * recorded rather than re-derived from the capabilities. Re-deriving would
     * read a cspace that a concurrent revoke may have emptied since -- and a
     * rollback that cannot resolve a slot is a rollback that leaves a mapping. */
    int cur = get_current_task();
#ifdef FRAME_REGION_ROLLBACK_WIDE
    /* CONTROL ARM: the OTHER way to get this wrong. Unwind the whole REQUESTED
     * range rather than the pages actually installed, re-deriving each frame
     * from its slot instead of from the record. It is the plausible mistake --
     * the range is right there in the arguments, and re-deriving looks like it
     * saves an array -- and it hands ring 3 a way to destroy a mapping it
     * dislikes by asking to map a region across it. frametest's
     * region-rollback-ate-blocker check fails under it. */
    for (uint32_t i = 0; i < count; i++) {
        capability_t *rc_cap = cap_lookup(first + i, 0);
        uint64_t rc_phys = (rc_cap && rc_cap->type == CAP_FRAME)
                               ? frame_phys_by_index((uint32_t)rc_cap->object) : 0;
        if (rc_phys)
            (void)user_unmap_frame_page((uint32_t)cur,
                                        vaddr + (uint64_t)i * PAGE_SIZE, rc_phys);
    }
    (void)mapped_phys; (void)done;
#else
    for (uint32_t i = done; i-- > 0; ) {
        int rc = user_unmap_frame_page((uint32_t)cur,
                                       vaddr + (uint64_t)i * PAGE_SIZE,
                                       mapped_phys[i]);
        if (rc != 0) {
            /* Unreachable, and fatal if it ever is. These PTEs were installed by
             * this call, in this address space, which no other CPU can be
             * running: nothing between the map and here can have altered them.
             * If one has changed, the page tables disagree with the kernel's
             * model of them, and the alternative to halting is returning an
             * error while leaving ring 3 holding authority it was just told it
             * did not get -- fail-open, in the one path written to prevent it. */
            kfault_begin(0);
            kfault_str("\nPANIC: frame region rollback failed vaddr=");
            kfault_hex(vaddr + (uint64_t)i * PAGE_SIZE);
            kfault_str(" phys=");  kfault_hex(mapped_phys[i]);
            kfault_str(" page=");  kfault_dec(i);
            kfault_str(" of=");    kfault_dec(count);
            kfault_str(" task=");  kfault_task(get_current_task());
            kfault_str("\nKERNEL FATAL REGION ROLLBACK - halting\n");
            kfault_end(0);
            for (;;) __asm__ volatile ("cli; hlt");
        }
    }
#endif
#endif

    r->rax = (uint32_t)err;
}
