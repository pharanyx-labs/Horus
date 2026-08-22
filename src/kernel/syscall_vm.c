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

/* ---- SYS_MAP_FRAME --------------------------------------------------------
 *
 * (frame_slot, vaddr, rights) -> 0. Map the frame named by the CAP_FRAME in
 * `frame_slot` at `vaddr` in the caller's own address space.
 *
 * Fails closed on every irregularity, and the order matters: the capability is
 * resolved first so that a caller holding no authority learns nothing about
 * which addresses are valid. */
void h_map_frame(struct interrupt_frame64 *r) {
    uint32_t slot   = (uint32_t)r->rbx;
    uint64_t vaddr  = r->rcx;
    uint32_t rights = (uint32_t)r->rdx;

    if (slot >= CNODE_SIZE) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    /* At least one access right must be requested. An empty request would map a
     * present page with no meaning -- x86-64 has no read-disable bit, so "no
     * access" is not a mapping the hardware can express -- and guessing READ on
     * the caller's behalf is the kind of helpfulness that becomes an authority
     * bug. A caller bug, refused, rather than a no-op. */
    if (!(rights & (CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC))) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    /* W^X, for ring 3, at the only place ring 3 can ask for both. The kernel's
     * own W^X is enforced at link and verified by smoke-wx; a frame is the first
     * object userspace can point at an address of its choosing, so it is the
     * first place userspace could have built a writable code page. Refused
     * outright rather than silently dropping one of the two bits: a caller that
     * asked for W|X has a wrong model of what it is doing, and a mapping that
     * quietly differs from the request is worse than an error. */
    if ((rights & CAP_RIGHT_WRITE) && (rights & CAP_RIGHT_EXEC)) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    /* THE GATE. cap_lookup enforces type-agnostic liveness and the rights floor;
     * the type test is what stops a CAP_ENDPOINT or a CAP_TCB standing in for a
     * frame. Both are required -- C-1 was a live capability of the wrong type
     * satisfying a gate that only asked for liveness. */
    capability_t *cap = cap_lookup(slot, frame_required_rights(rights));
    if (!cap || cap->type != CAP_FRAME) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
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
    if (phys == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    if ((vaddr & (PAGE_SIZE - 1)) || vaddr == 0 || vaddr >= USER_HALF_LIMIT) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    /* Reconfirm the capability's identity before committing. A concurrent revoke
     * on another CPU between the lookup above and the map below would otherwise
     * install a mapping for authority that no longer exists -- and unlike a
     * dropped IPC message, a stale PTE persists until something unmaps it. */
    if (snap.valid && !cap_revalidate(slot, frame_required_rights(rights), &snap)) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }

    int cur = get_current_task();
#ifdef FRAME_RIGHTS_UNCHECKED
    /* The arm removes the floor, so `have` no longer bounds `rights`; feeding
     * the intersection here would re-impose by accident what the floor used to
     * impose on purpose, and the arm would go back to measuring nothing. */
    uint32_t eff = rights; (void)have;
#else
    uint32_t eff = frame_effective_rights(have, rights);
#endif
    int rc = user_map_frame_page((uint32_t)cur, vaddr, phys, eff);
    if (rc == -2) {
        /* Something is already mapped there. A distinct code, because "that
         * address is occupied" and "that address is not allowed" are different
         * problems for the caller and only one of them is fixable by choosing
         * another address. */
        r->rax = (uint32_t)SYS_ERR_EXIST; return;
    }
    if (rc != 0) { r->rax = (uint32_t)SYS_ERR_FAULT; return; }

    audit_log(AUDIT_CAP_OPERATION, index, 0, "frame mapped");
    r->rax = 0;
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
    uint64_t phys = frame_phys_by_index((uint32_t)cap->object);
    if (phys == 0) { r->rax = (uint32_t)SYS_ERR_INVAL; return; }

    if ((vaddr & (PAGE_SIZE - 1)) || vaddr == 0 || vaddr >= USER_HALF_LIMIT) {
        r->rax = (uint32_t)SYS_ERR_INVAL; return;
    }

    int cur = get_current_task();
    int rc = user_unmap_frame_page((uint32_t)cur, vaddr, phys);
    r->rax = (rc == 0) ? 0 : (uint32_t)SYS_ERR_INVAL;
}
