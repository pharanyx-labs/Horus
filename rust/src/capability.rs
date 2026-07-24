use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub typ: u32,
    pub rights: u32,
    pub object: u64,
    pub badge: u32,
    pub serial: u32,
    pub generation: u32,
}

pub const CAP_NULL: u32 = 0;

// ---------------------------------------------------------------------------
// FFI layout contract.
//
// `Capability` (Rust) and `capability_t` (src/include/kernel.h) MUST have the
// identical layout — the kernel passes raw `*mut Capability` across the FFI and
// both sides index the same memory. These compile-time assertions pin the field
// offsets so reordering or retyping a field in either language fails to build.
// The mirror image of these checks lives in src/kernel/capability.c as
// `_Static_assert`s. Field offsets are identical on the 32- and 64-bit targets;
// only the trailing padding (and thus size_of) differs, so we assert offsets,
// not size.
// ---------------------------------------------------------------------------
const _: () = {
    assert!(core::mem::offset_of!(Capability, typ) == 0);
    assert!(core::mem::offset_of!(Capability, rights) == 4);
    assert!(core::mem::offset_of!(Capability, object) == 8);
    assert!(core::mem::offset_of!(Capability, badge) == 16);
    assert!(core::mem::offset_of!(Capability, serial) == 20);
    assert!(core::mem::offset_of!(Capability, generation) == 24);
    assert!(CAP_NULL == 0);
};

const CNODE_SIZE: u32 = 256;
const KERNEL_RESERVED_CAPS: u32 = 4;


const MIN_DERIVED_SERIAL: u32 = 0x00010000;





// Single source of truth for per-capability lineage generations.
//
// The table is keyed by a capability's globally-unique, monotonic `serial`
// (finding 3.3 / audit A3 follow-up). Every capability gets a fresh serial at
// creation, so serial-keying gives each capability its OWN generation cell.
//
// The previous table was keyed by `object`. Two independent capabilities to the
// same object then shared a cell, so the only way they could stay independent
// under an object-wide revoke bump was to carry the "untracked" generation 0 —
// and 0 was treated as *always valid*. Because every capability in the running
// kernel is created with generation 0 (all primordial roots, every
// `cap_install_*`, and mint/grant which inherit the source's generation), the
// generation backstop was in practice DORMANT: a stale/snapshotted capability
// with generation 0 passed the check unconditionally, so the use-after-revoke /
// TOCTOU-revalidate guard it was meant to provide did nothing (finding 3.3).
//
// Serial-keying + strict-equality checking (below) makes the backstop ACTIVE and
// precise: on revoke the authority bumps the generation of EXACTLY the serials
// the structural sweep (`revoke_subtree`) enumerates — the revoked capability
// and its derivation subtree — so a live sibling, ancestor, or independent
// same-object peer (a *different* serial) is never invalidated, while a detached
// snapshot/copy of a revoked capability (its own, now-bumped serial) fails the
// check even if the structural nulling never reached it. Two independent
// mechanisms (null the slot AND bump its serial-generation) now each invalidate
// a revoked capability.
//
// Each slot is an independent atomic so accesses are sound under preemption/SMP;
// the cspace arrays themselves are mutated only under the C `cap_lock`.
const LINEAGE_SLOTS: usize = 4096;
#[allow(clippy::declare_interior_mutable_const)]
const LINEAGE_ZERO: AtomicU32 = AtomicU32::new(0);
static LINEAGE_GEN: [AtomicU32; LINEAGE_SLOTS] = [LINEAGE_ZERO; LINEAGE_SLOTS];

// Primordial root capabilities (kernel-only, in the reserved slots) carry the
// `0xC0DE****` serial tag and are deliberately non-revocable (see
// `is_primordial_root`). They are exempt from generation tracking: never bumped,
// always valid — so a hash collision with a revoked user serial can never
// invalidate a kernel root capability. This mirrors the tag `is_primordial_root`
// matches, but keyed on the serial alone (no slot index needed).
const PRIMORDIAL_SERIAL_MASK: u32 = 0xFFFF_0000;
const PRIMORDIAL_SERIAL_TAG: u32 = 0xC0DE_0000;

#[inline]
fn serial_is_primordial(serial: u32) -> bool {
    (serial & PRIMORDIAL_SERIAL_MASK) == PRIMORDIAL_SERIAL_TAG
}

/// A serial participates in generation tracking iff it is a real, non-primordial
/// serial. Empty (0) and primordial (`0xC0DE****`) serials are exempt.
#[inline]
fn serial_is_tracked(serial: u32) -> bool {
    serial != 0 && !serial_is_primordial(serial)
}

#[inline]
fn lineage_idx(serial: u32) -> usize {
    let mut x = serial as u64;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x as usize) & (LINEAGE_SLOTS - 1)
}

/// The generation a capability with this `serial` must currently carry to be
/// valid. Read at CREATION time and stored in the capability's `generation`
/// field so that a fresh serial which happens to hash onto a slot a prior,
/// unrelated revoke already bumped is born VALID (matching the slot) rather than
/// born stale. Untracked (empty / primordial) serials always carry 0.
#[inline]
fn lineage_current(serial: u32) -> u32 {
    if !serial_is_tracked(serial) {
        return 0;
    }
    LINEAGE_GEN[lineage_idx(serial)].load(Ordering::SeqCst)
}

/// Bump the generation for `serial`, invalidating every capability (and every
/// detached snapshot) that recorded the previous generation for it. Returns the
/// new generation. Generation 0 means "pristine / never revoked", so we skip it
/// on wrap-around. Exempt serials are never bumped.
#[inline]
fn bump_lineage(serial: u32) -> u32 {
    if !serial_is_tracked(serial) {
        return 0;
    }
    let idx = lineage_idx(serial);
    let prev = LINEAGE_GEN[idx].fetch_add(1, Ordering::SeqCst);
    let g = prev.wrapping_add(1);
    if g == 0 {
        // Wrapped back onto the pristine sentinel; force to 1 so a revoked
        // serial never reads as pristine.
        LINEAGE_GEN[idx].store(1, Ordering::SeqCst);
        1
    } else {
        g
    }
}

/// Authoritative validity check: is a capability that recorded `gen` for its
/// `serial` still live? A tracked capability is valid iff its recorded
/// generation is EXACTLY the serial's current generation — strict equality, so
/// there is no "generation 0 is always valid" escape hatch (finding 3.3). A
/// pristine capability carries gen 0 and matches the pristine slot 0; once its
/// serial is bumped by a revoke, the recorded 0 no longer matches and the
/// capability (or its snapshot) is stale. Empty and primordial serials are
/// exempt (always valid).
#[inline]
fn lineage_check(serial: u32, gen: u32) -> bool {
    if !serial_is_tracked(serial) {
        return true;
    }
    LINEAGE_GEN[lineage_idx(serial)].load(Ordering::SeqCst) == gen
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_lookup(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    required_rights: u32,
) -> *mut Capability {
    if cspace.is_null() {
        return ptr::null_mut();
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return ptr::null_mut();
    }

    let cap = &mut *cspace.add(slot as usize);

    
    
    if cap.typ == CAP_NULL {
        return ptr::null_mut();
    }
    if (cap.rights & required_rights) != required_rights {
        return ptr::null_mut();
    }

    
    
    if cap.serial == 0 {
        return ptr::null_mut();
    }
    // Serial-keyed generation backstop (finding 3.3): a capability whose serial
    // has been bumped by a revoke fails strict-equality here even though its slot
    // is (defensively) also nulled by the structural sweep. `cap.serial != 0` is
    // guaranteed above; primordial serials are exempt inside `lineage_check`.
    if !lineage_check(cap.serial, cap.generation) {
        return ptr::null_mut();
    }
    cap
}

/// Allocate a fresh derived serial, advancing `*next_serial`. This is the SINGLE
/// implementation of the serial wrap logic: serials never collide with the
/// reserved primordial range and never wrap to 0. Both `rust_cap_mint` and the C
/// `cap_alloc_fresh_serial` go through it so the two cannot drift.
#[inline]
unsafe fn assign_fresh_serial(next_serial: *mut u32) -> u32 {
    if next_serial.is_null() {

        return 0xC0DEFFFFu32;
    }
    let cur = *next_serial;


    let base = if cur < MIN_DERIVED_SERIAL { MIN_DERIVED_SERIAL } else { cur };
    let fresh = base.wrapping_add(1);
    let fresh = if fresh < MIN_DERIVED_SERIAL || fresh == 0 { MIN_DERIVED_SERIAL } else { fresh };
    *next_serial = fresh;
    fresh
}

/// FFI: centralized fresh-serial allocation for the C kernel. The caller holds
/// `cap_lock`; `next_serial` points at the kernel's monotonic serial counter.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_alloc_serial(next_serial: *mut u32) -> u32 {
    assign_fresh_serial(next_serial)
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_mint(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    new_rights: u32,
    next_serial: *mut u32,
    _current_task_caps_in_use: u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if dest_slot >= cspace_size || dest_slot >= CNODE_SIZE {
        return false;
    }
    if src_slot >= cspace_size || src_slot >= CNODE_SIZE {
        return false;
    }
    
    if dest_slot < KERNEL_RESERVED_CAPS {
        return false;
    }

    let src = &*cspace.add(src_slot as usize);
    if src.typ == CAP_NULL {
        return false;
    }
    
    if src.serial == 0 {
        return false;
    }

    let dest = &mut *cspace.add(dest_slot as usize);

    
    
    let parent_serial = src.serial;

    let fresh = assign_fresh_serial(next_serial);

    
    let effective_rights = new_rights & src.rights;

    // The child is keyed by its OWN fresh serial (finding 3.3): stamp it with
    // that serial's current generation, so it is born valid even if the serial
    // hashes onto a slot a prior revoke already bumped, and so a later revoke of
    // the child — or of any ancestor, which sweeps the child's serial — makes it
    // fail the strict-equality lineage check.
    *dest = Capability {
        typ: src.typ,
        rights: effective_rights,
        object: src.object,
        badge: parent_serial,
        serial: fresh,
        generation: lineage_current(fresh),
    };
    true
}

#[no_mangle]
pub unsafe extern "C" fn rust_cap_transfer(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    next_serial: *mut u32,
) -> bool {
    rust_cap_mint(cspace, cspace_size, dest_slot, src_slot, !0u32, next_serial, 0)
}

/// FFI: grant (delegate) a capability derived from `src` into ANOTHER task's
/// cspace at `dest_slot`. This is the cross-cspace analogue of `rust_cap_mint`:
/// `src` points at the grantor's own capability (in the grantor's cspace) and
/// `dest_cspace` is the grantee's cspace. It exists so `SYS_CAP_GRANT` writes
/// through the same audited, rights-reducing, lineage-correct logic every other
/// cap write uses, rather than a raw `dest = *src` store in the C kernel.
///
/// Semantics (mirrors mint):
///   - the minted rights are `new_rights & src.rights` (grant can only *reduce*;
///     pass `!0` for the historical "copy full rights" behaviour);
///   - the grantee records the grantor's cap as its parent (`badge = src.serial`)
///     so a later revoke of the grantor's cap sweeps the grantee too, and the
///     derivation tree stays well-formed;
///   - the grantee gets a fresh serial and inherits the source generation, and
///     the object's lineage floor is raised to the source generation.
///
/// Unlike mint there is intentionally NO `dest_slot < KERNEL_RESERVED_CAPS`
/// floor: grant writes into a *child* the caller already dominates (it holds the
/// child's `CAP_TCB`), and endowing a child's low slots — e.g. its IPC gate at
/// slot 3 — is exactly what grant is for. The C caller enforces the CAP_TCB /
/// admin authority and the `caps_in_use` ceiling under `cap_lock`.
///
/// # Safety
/// `src` must be null or a valid pointer to a live `Capability`; `dest_cspace`
/// must be null or point to at least `dest_cspace_size` `Capability` entries;
/// `next_serial` must be null or a valid `*mut u32`. Called under `cap_lock`.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_grant_into(
    src: *const Capability,
    dest_cspace: *mut Capability,
    dest_cspace_size: u32,
    dest_slot: u32,
    new_rights: u32,
    next_serial: *mut u32,
) -> bool {
    if src.is_null() || dest_cspace.is_null() {
        return false;
    }
    if dest_slot >= dest_cspace_size || dest_slot >= CNODE_SIZE {
        return false;
    }
    let s = &*src;
    // Authority cannot be fabricated from an empty or serial-0 (lookup-invalid)
    // source — same guard mint enforces.
    if s.typ == CAP_NULL || s.serial == 0 {
        return false;
    }

    let parent_serial = s.serial;
    let fresh = assign_fresh_serial(next_serial);
    let effective_rights = new_rights & s.rights;

    let dest = &mut *dest_cspace.add(dest_slot as usize);
    // Grantee is keyed by its own fresh serial (finding 3.3), stamped with that
    // serial's current generation — same discipline as mint.
    *dest = Capability {
        typ: s.typ,
        rights: effective_rights,
        object: s.object,
        badge: parent_serial,
        serial: fresh,
        generation: lineage_current(fresh),
    };
    true
}

/// Clear a capability slot to the null capability.
#[inline]
unsafe fn nullify(c: &mut Capability) {
    c.typ = CAP_NULL;
    c.rights = 0;
    c.object = 0;
    c.badge = 0;
    c.serial = 0;
    c.generation = 0;
}

/// Bounded worklist size for a single revocation's descendant closure. A
/// derivation subtree with more than this many members would need hundreds of
/// derived copies of one lineage and does not occur in practice; if it ever
/// happened, `revoke_subtree` falls back to a safe object-match superset rather
/// than truncating the closure (which would leave a descendant live).
const MAX_REVOKE_LINEAGE: usize = 256;

#[inline]
fn set_contains(set: &[u32], v: u32) -> bool {
    let mut i = 0;
    while i < set.len() {
        if set[i] == v {
            return true;
        }
        i += 1;
    }
    false
}

/// Revoke the derivation *subtree* rooted at `root_serial` across every cspace in
/// `spaces`: null the root's transitive descendants — a capability whose `badge`
/// chains back to `root_serial` through the derivation tree (each derived cap
/// records its parent's serial in `badge`) — and NOTHING else. Ancestors,
/// unrelated siblings, and independent capabilities that merely share the same
/// `object` are left intact.
///
/// This is the least-privilege-correct revocation semantics (audit A1). The
/// previous implementation matched an object/badge/serial *equivalence set*,
/// which also revoked the grantor's own capability and every same-`object` peer —
/// far broader than "this capability and everything derived from it".
///
/// The root capability itself is expected to be nulled by the caller already for
/// the `*_global` / `rust_cap_revoke` paths (so it is not double-counted); its
/// serial is still passed here as the closure seed, and any un-nulled cap holding
/// `root_serial` (e.g. the revoke-by-values path) is nulled by the sweep below.
///
/// Descendants are found with a bounded worklist of revoked serials
/// (`MAX_REVOKE_LINEAGE`). If a subtree overflows the worklist, `overflow` is set
/// and the null pass ALSO nulls every cap sharing `root_object`. Because
/// mint/transfer/grant all preserve `object`, that object set is a *superset* of
/// the descendant set, so the fallback can only over-approximate — a descendant
/// can never survive. Revocation is therefore complete (fail-safe) in every case,
/// and exact in every realistic one.
///
/// # Safety
/// `spaces` must be null or point to `space_count` valid `CSpaceDesc`s whose
/// `caps`/`size` describe live arrays. Called under `cap_lock`.
unsafe fn revoke_subtree(
    spaces: *const CSpaceDesc,
    space_count: u32,
    root_serial: u32,
    root_object: u64,
) {
    if spaces.is_null() {
        return;
    }
    let mut revoked = [0u32; MAX_REVOKE_LINEAGE];
    let mut n = 0usize;
    let mut overflow = false;

    if root_serial != 0 {
        revoked[0] = root_serial;
        n = 1;
        // Grow the revoked-serial set one BFS layer per pass until it is closed
        // under "is a child (badge) of an already-revoked serial".
        loop {
            let mut added = false;
            for s in 0..space_count {
                let d = &*spaces.add(s as usize);
                if d.caps.is_null() {
                    continue;
                }
                let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
                for i in 0..limit {
                    let c = &*d.caps.add(i as usize);
                    if c.typ == CAP_NULL || c.serial == 0 || c.badge == 0 {
                        continue;
                    }
                    if set_contains(&revoked[..n], c.badge)
                        && !set_contains(&revoked[..n], c.serial)
                    {
                        if n < MAX_REVOKE_LINEAGE {
                            revoked[n] = c.serial;
                            n += 1;
                            added = true;
                        } else {
                            overflow = true;
                        }
                    }
                }
            }
            if !added {
                break;
            }
        }
    } else {
        // No serial seed (revoke-by-object): fall back to the object sweep, which
        // is complete for a shared-object lineage.
        overflow = true;
    }

    // Null every cap in the revoked set (the root's descendants), plus — only on
    // overflow / no-seed — every cap sharing the root object (a safe superset).
    for s in 0..space_count {
        let d = &*spaces.add(s as usize);
        if d.caps.is_null() {
            continue;
        }
        let limit = if d.size > CNODE_SIZE { CNODE_SIZE } else { d.size };
        for i in 0..limit {
            let c = &mut *d.caps.add(i as usize);
            if c.typ == CAP_NULL {
                continue;
            }
            let hit = set_contains(&revoked[..n], c.serial)
                || (overflow && root_object != 0 && c.object == root_object);
            if hit {
                // Bump this capability's serial generation BEFORE nulling it
                // (nullify clears the serial). This is the active backstop
                // (finding 3.3): a detached snapshot/copy carrying this serial
                // now fails `lineage_check`, independently of the structural
                // null below. Exactly this subtree's serials are bumped, so a
                // sibling/ancestor/independent peer (a different serial) is
                // untouched (audit A1).
                let _ = bump_lineage(c.serial);
                nullify(c);
                if !d.caps_in_use.is_null() && *d.caps_in_use > 0 {
                    *d.caps_in_use -= 1;
                }
            }
        }
    }
}

#[inline]
unsafe fn is_primordial_root(cspace: *mut Capability, slot: u32) -> bool {
    let s = (*cspace.add(slot as usize)).serial;
    slot < KERNEL_RESERVED_CAPS && s != 0 && (s & 0xFFFF0000) == 0xC0DE0000
}

/// Single-cspace revoke. Used for moves and for revoking a CAP_REVOCATION
/// helper slot. For system-wide revocation use `rust_cap_revoke_global`.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke(
    cspace: *mut Capability,
    cspace_size: u32,
    slot: u32,
    _next_serial: *mut u32,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    if slot >= cspace_size || slot >= CNODE_SIZE {
        return false;
    }
    if is_primordial_root(cspace, slot) {
        return false;
    }

    let target = &mut *cspace.add(slot as usize);
    if target.typ == CAP_NULL {
        return true;
    }

    let ts = target.serial;
    let to = target.object;

    nullify(target);

    // Bump the target's own serial generation so a detached snapshot/copy of the
    // revoked capability is invalidated (finding 3.3). The structural sweep below
    // bumps each descendant serial; `to` (the object) is still passed to it only
    // for the overflow object-match fallback, never for generation keying.
    let _ = bump_lineage(ts);

    // Descendant-only sweep of this one cspace (audit A1). The target slot is
    // already nulled, so the closure only reaches capabilities derived from it.
    let desc = CSpaceDesc {
        caps: cspace,
        size: cspace_size,
        caps_in_use: core::ptr::null_mut(),
    };
    revoke_subtree(&desc as *const CSpaceDesc, 1, ts, to);
    true
}

/// Descriptor for one capability space, passed across the FFI so the entire
/// system-wide revocation sweep happens inside one Rust call.
#[repr(C)]
pub struct CSpaceDesc {
    pub caps: *mut Capability,
    pub size: u32,
    /// Optional pointer to the owning task's `caps_in_use` counter; null to skip
    /// accounting (e.g. the kernel root cnode).
    pub caps_in_use: *mut u32,
}

/// SYSTEM-WIDE capability revocation — the authoritative revocation entry point.
///
/// Revokes the capability at `target_slot` of `target_cspace` and then sweeps
/// EVERY cspace in `spaces` (which the caller populates with all live tasks'
/// cspaces plus the kernel root cnode) for the target's derivation *subtree* —
/// the capabilities transitively derived from it (mint/transfer/grant) — nulling
/// them. The lineage generation is bumped exactly once, so any stale copy that
/// somehow escapes the structural sweep still fails the generation check in
/// `rust_cap_lookup`.
///
/// INVARIANT (see ARCHITECTURE.md): after this returns true, no live cspace
/// retains the target capability or any capability derived from it — and, per
/// audit A1, capabilities that are NOT descendants (the grantor/ancestor, unrelated
/// siblings, independent capabilities to the same object) are left intact. This is
/// what makes revocation both complete (no descendant survives its ancestor's
/// revocation) and least-privilege-correct (revoking a delegated capability does
/// not strip the grantor's own authority).
///
/// Must be called by C under `cap_lock` so the `spaces` snapshot is stable.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_global(
    target_cspace: *mut Capability,
    target_cspace_size: u32,
    target_slot: u32,
    target_caps_in_use: *mut u32,
    spaces: *const CSpaceDesc,
    space_count: u32,
    _next_serial: *mut u32,
) -> bool {
    if target_cspace.is_null() {
        return false;
    }
    if target_slot >= target_cspace_size || target_slot >= CNODE_SIZE {
        return false;
    }
    if is_primordial_root(target_cspace, target_slot) {
        return false;
    }

    let target = &mut *target_cspace.add(target_slot as usize);
    if target.typ == CAP_NULL {
        return true;
    }

    let ts = target.serial;
    let to = target.object;

    // Null the target itself and account for it. The system-wide sweep below
    // will skip it (already null), so it is never double-counted.
    nullify(target);
    if !target_caps_in_use.is_null() && *target_caps_in_use > 0 {
        *target_caps_in_use -= 1;
    }

    // Bump the target's own serial generation so a detached snapshot/copy of the
    // revoked capability is invalidated (finding 3.3). The structural sweep below
    // bumps each descendant serial; `to` (the object) is still passed to it only
    // for the overflow object-match fallback, never for generation keying.
    let _ = bump_lineage(ts);

    // Sweep every supplied cspace for the target's derivation subtree only — the
    // target's descendants, not its ancestors, siblings, or same-object peers
    // (audit A1). The target slot is already null, so it cannot re-match.
    revoke_subtree(spaces, space_count, ts, to);
    true
}

/// Single-cspace revoke by explicit values. Retained for compatibility; the
/// system-wide path is `rust_cap_revoke_global`. Revokes the derivation subtree
/// rooted at `target_serial` (audit A1) — `target_badge` is no longer used for
/// matching, since the subtree is defined by the serial→badge derivation links.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_by_values(
    cspace: *mut Capability,
    cspace_size: u32,
    target_serial: u32,
    _target_badge: u32,
    target_obj: u64,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    // Bump the target's own serial generation so a pre-revoke snapshot fails the
    // generation re-check at point of use (the TOCTOU close, finding 3.3); the
    // sweep bumps each descendant serial too. `target_obj` is still passed to the
    // sweep for the overflow object-match fallback, not for generation keying.
    let _ = bump_lineage(target_serial);
    let desc = CSpaceDesc {
        caps: cspace,
        size: cspace_size,
        caps_in_use: core::ptr::null_mut(),
    };
    revoke_subtree(&desc as *const CSpaceDesc, 1, target_serial, target_obj);
    true
}

/// FFI: bump the lineage generation for `serial`. Sole way for C to invalidate a
/// single serial's lineage outside the revoke sweeps.
#[no_mangle]
pub extern "C" fn rust_lineage_bump(serial: u32) -> u32 { bump_lineage(serial) }

/// FFI: check whether a capability recording `gen` for `serial` is still valid.
/// C's `capability_validate_generation` delegates here so both sides agree.
#[no_mangle]
pub extern "C" fn rust_lineage_check(serial: u32, gen: u32) -> bool { lineage_check(serial, gen) }

/// FFI: the generation a freshly-created capability with `serial` must carry to
/// be valid. Every C capability-creation site stamps
/// `cap.generation = rust_lineage_current(cap.serial)` so the serial-keyed
/// backstop (finding 3.3) is active for kernel-created capabilities too, and a
/// serial that collides with a previously-bumped slot is born valid, not stale.
#[no_mangle]
pub extern "C" fn rust_lineage_current(serial: u32) -> u32 { lineage_current(serial) }

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;

    fn cap(typ: u32, rights: u32, object: u64, badge: u32, serial: u32, generation: u32) -> Capability {
        Capability { typ, rights, object, badge, serial, generation }
    }

    // Test isolation for the serial-keyed generation authority (finding 3.3).
    //
    // `LINEAGE_GEN` is a shared `static`, and the strict-equality check now makes
    // a capability's validity depend on that shared state (a pristine gen-0 cap
    // is valid only while its serial's slot is 0). Under `cargo test`'s parallel
    // harness two tests could otherwise hash-collide — one bumping a serial the
    // other asserts survives. This guard serializes every table-touching test and
    // resets the table to pristine on entry, so each runs against a clean, private
    // authority. `core`-only (the crate is `no_std` under test); `cargo test`
    // builds with `panic=unwind`, so `Drop` releases the lock even on a failing
    // assertion.
    static LINEAGE_TEST_LOCK: AtomicU32 = AtomicU32::new(0);
    struct LineageTestGuard;
    impl LineageTestGuard {
        fn new() -> Self {
            while LINEAGE_TEST_LOCK
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }
            for slot in LINEAGE_GEN.iter() {
                slot.store(0, Ordering::SeqCst);
            }
            LineageTestGuard
        }
    }
    impl Drop for LineageTestGuard {
        fn drop(&mut self) {
            LINEAGE_TEST_LOCK.store(0, Ordering::Release);
        }
    }

    /// Regression: a derived capability minted into a *second* task's cspace
    /// must be revoked (and its lineage invalidated) when the parent is revoked
    /// in the first task — the system-wide revocation invariant.
    #[test]
    fn test_global_revoke_reaches_other_task_cspace() {
        let _lin = LineageTestGuard::new();
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];

        // Task A holds the parent CAP_FRAME (object 0x5000, serial 0x4000).
        // Pristine generation 0 matches its pristine serial slot — valid now.
        a[4] = cap(1, 0x3f, 0x5000, 0, 0x4000, 0);
        // Task B holds a derived copy: badge == parent serial, same object,
        // reduced rights, its own fresh serial — exactly what cap_mint produces.
        b[7] = cap(1, 0x03, 0x5000, 0x4000, 0x9001, 0);

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;

        unsafe {
            // Precondition: B's derived cap is currently usable.
            assert!(!rust_cap_lookup(b.as_mut_ptr(), 16, 7, 0x1).is_null());

            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];

            let ok = rust_cap_revoke_global(
                a.as_mut_ptr(),
                16,
                4,
                addr_of_mut!(ciu_a),
                spaces.as_ptr(),
                2,
                core::ptr::null_mut(),
            );
            assert!(ok);

            // Parent revoked in task A.
            assert_eq!(a[4].typ, CAP_NULL);
            assert!(rust_cap_lookup(a.as_mut_ptr(), 16, 4, 0x1).is_null());

            // Derived copy in the OTHER task's cspace is gone — the core fix.
            assert_eq!(b[7].typ, CAP_NULL,
                "derived capability in another task must be revoked system-wide");
            assert!(rust_cap_lookup(b.as_mut_ptr(), 16, 7, 0x1).is_null());

            // Serial generations bumped: a detached copy carrying the parent's
            // OR the derived child's pre-revoke generation now fails the check,
            // even if it had escaped the structural sweep (finding 3.3).
            assert!(!lineage_check(0x4000, 0), "revoked parent serial is now stale");
            assert!(!lineage_check(0x9001, 0), "revoked derived serial is now stale");

            // Accounting: both tasks' caps_in_use were decremented exactly once.
            assert_eq!(ciu_a, 0);
            assert_eq!(ciu_b, 0);
        }
    }

    /// A capability for a *different* object/lineage in another cspace must
    /// survive an unrelated revocation (no over-broad nulling).
    #[test]
    fn test_global_revoke_does_not_touch_unrelated() {
        let _lin = LineageTestGuard::new();
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];
        a[4] = cap(1, 0x3f, 0x7000, 0, 0x7700, 0);
        b[7] = cap(1, 0x3f, 0x8000, 0, 0x8800, 0); // unrelated lineage (distinct serial)

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;
        unsafe {
            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            let ok = rust_cap_revoke_global(
                a.as_mut_ptr(), 16, 4, addr_of_mut!(ciu_a), spaces.as_ptr(), 2, core::ptr::null_mut());
            assert!(ok);
            assert!(!rust_cap_lookup(b.as_mut_ptr(), 16, 7, 0x1).is_null(),
                "unrelated capability must not be revoked");
            assert_eq!(ciu_b, 1);
        }
    }

    #[test]
    fn test_lookup_and_mint_basic() {
        let _lin = LineageTestGuard::new();
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 42, badge: 0, serial: 0x1000, generation: 0 };

        let mut next = 0x1001u32;

        unsafe {
            let ok = rust_cap_mint(
                cspace.as_mut_ptr(),
                16,
                5,
                0,
                0x3,
                &mut next as *mut u32,
                0,
            );
            assert!(ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 5, 0x1);
            assert!(!looked.is_null());
            let c5 = &*looked;
            assert_eq!(c5.typ, 1);
            assert_eq!(c5.rights, 0x3);
            assert_eq!(c5.badge, 0x1000);
            assert!(c5.serial > 0x1000);
            assert_eq!(c5.generation, 0);
        }
    }

    #[test]
    fn test_revoke_clears_and_serial_is_fresh() {
        let _lin = LineageTestGuard::new();
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 99, badge: 0, serial: 0x2000, generation: 0 };

        let mut next = 0x2001u32;
        unsafe {
            let mint_ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 6, 0, 0x7, &mut next, 0);
            assert!(mint_ok);
            let child_before = *cspace.as_ptr().add(6);
            assert_eq!(child_before.badge, 0x2000);
            // The child is keyed by its OWN fresh serial and stamped with that
            // serial's current (pristine) generation — 0 — not the parent's.
            assert_eq!(child_before.generation, 0);

            
            let rev_ok = rust_cap_revoke(cspace.as_mut_ptr(), 16, 0, core::ptr::null_mut());
            assert!(rev_ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 6, 0x1);
            assert!(looked.is_null(), "derived cap must be revoked together with parent (badge lineage)");
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 0, 0).is_null());
        }
    }

    #[test]
    fn test_lineage_no_collision_on_low_bits() {
        let _lin = LineageTestGuard::new();
        // Two capabilities with DISTINCT serials must occupy independent lineage
        // cells: bumping one serial's generation must not invalidate the other.
        // Serial-keying (finding 3.3) is what makes two same-object capabilities
        // independently revocable without the old gen-0 immunity crutch.
        let sa: u32 = 0x0001_0100;
        let sb: u32 = 0x0001_0200;
        let mut cs = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        unsafe {
            // Each stamped with its own serial's current (pristine) generation.
            cs[4] = Capability { typ: 1, rights: 0x3f, object: 0x1001, badge: 0, serial: sa, generation: lineage_current(sa) };
            cs[5] = Capability { typ: 1, rights: 0x3f, object: 0x1101, badge: 0, serial: sb, generation: lineage_current(sb) };

            // Revoke (bump) only serial `sa`.
            let _ = bump_lineage(sa);

            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 4, 0x1).is_null(),
                "serial sa must be stale after its own lineage bump");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null(),
                "serial sb must NOT be invalidated by a bump targeting sa");
        }
    }

    #[test]
    fn test_strict_rights_and_no_escalation() {
        let _lin = LineageTestGuard::new();
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 5, rights: 0b0011, object: 7, badge: 0, serial: 0x3000, generation: 0 };

        let mut next = 0x3001u32;
        unsafe {
            
            let ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 4, 0, 0xFFFF, &mut next, 0);
            assert!(ok);
            let child = &*rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0);
            
            assert_eq!(child.rights, 0b0011);
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 4, 0b0100).is_null());
        }
    }

    /// Serial allocation (the C kernel routes cap_alloc_fresh_serial through this
    /// FFI) must advance monotonically and never hand back a serial in the
    /// reserved primordial range or 0 — including at the u32 wrap boundary. Uses
    /// only a local counter, so it is fully deterministic under parallel tests.
    #[test]
    fn test_alloc_serial_stays_above_reserved_and_nonzero() {
        unsafe {
            // Starting below the floor snaps up to the first derived serial.
            let mut s: u32 = 0;
            let a = rust_cap_alloc_serial(&mut s);
            assert!(a >= MIN_DERIVED_SERIAL);
            assert_eq!(s, a, "counter is advanced in place");
            let b = rust_cap_alloc_serial(&mut s);
            assert!(b > a && b >= MIN_DERIVED_SERIAL);

            // At the wrap boundary it must not yield 0 or dip below the floor.
            let mut w: u32 = u32::MAX;
            let f = rust_cap_alloc_serial(&mut w);
            assert!(f >= MIN_DERIVED_SERIAL && f != 0);

            // A null counter returns the sentinel rather than dereferencing null.
            assert_eq!(rust_cap_alloc_serial(core::ptr::null_mut()), 0xC0DEFFFF);
        }
    }

    /// A primordial root capability (serial prefix `0xC0DE`, sitting in a
    /// kernel-reserved slot) must survive BOTH single-cspace and system-wide
    /// revocation — the check refuses before any mutation, so the cap stays
    /// intact and usable. This is what stops a userspace path from revoking a
    /// system-critical root capability.
    #[test]
    fn test_primordial_root_cannot_be_revoked() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        // slot 2 is within KERNEL_RESERVED_CAPS (4); the serial carries the
        // primordial 0xC0DE prefix. generation 0 == untracked, so lookups do
        // not depend on the shared lineage table (parallel-test safe).
        cs[2] = cap(9 /*CAP_ENCRYPTED_STORAGE*/, 0x3f, 0xA011, 0, 0xC0DE0002, 0);
        unsafe {
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 2, 0x1).is_null(),
                "primordial cap is usable to begin with");

            // Single-cspace revoke refuses and leaves the slot untouched.
            assert!(!rust_cap_revoke(cs.as_mut_ptr(), 16, 2, core::ptr::null_mut()));
            assert_eq!(cs[2].serial, 0xC0DE0002, "primordial cap must be untouched");

            // System-wide revoke refuses too, and performs no sweep.
            let spaces = [CSpaceDesc { caps: cs.as_mut_ptr(), size: 16, caps_in_use: core::ptr::null_mut() }];
            assert!(!rust_cap_revoke_global(
                cs.as_mut_ptr(), 16, 2, core::ptr::null_mut(),
                spaces.as_ptr(), 1, core::ptr::null_mut()));
            assert_eq!(cs[2].typ, 9);
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 2, 0x1).is_null(),
                "primordial cap remains usable after an attempted revocation");
        }
    }

    /// `rust_cap_transfer` copies a capability with the source's full (unmasked)
    /// rights and the parent's serial as its badge, and the copy shares the
    /// parent's lineage: revoking the source clears the transferred copy too.
    #[test]
    fn test_transfer_copies_rights_and_shares_lineage() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        cs[4] = cap(4 /*CAP_FRAME*/, 0x3f, 0xA200, 0, 0xA201, 0);
        let mut next = 0x20000u32;
        unsafe {
            assert!(rust_cap_transfer(cs.as_mut_ptr(), 16, 8, 4, &mut next));
            let d = cs[8];
            assert_eq!(d.typ, 4);
            assert_eq!(d.rights, 0x3f, "transfer preserves the source's full rights");
            assert_eq!(d.object, 0xA200);
            assert_eq!(d.badge, 0xA201, "the copy records the source serial as its badge");
            assert!(d.serial >= MIN_DERIVED_SERIAL && d.serial != 0xA201,
                "the copy gets a fresh serial, distinct from the source");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 8, 0x3f).is_null());

            // Revoking the source lineage clears the transferred copy as well.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut()));
            assert_eq!(cs[4].typ, CAP_NULL);
            assert_eq!(cs[8].typ, CAP_NULL,
                "a transferred copy is revoked together with its source (shared lineage)");
        }
    }

    /// The lineage generation counter reserves 0 to mean "untracked". A bump that
    /// wraps `u32::MAX` back to 0 must skip the reserved value and land on 1, and
    /// a capability that recorded the pre-wrap generation must read as stale — so
    /// use-after-revoke is prevented even across the counter wrap.
    #[test]
    fn test_lineage_generation_wraparound() {
        let _lin = LineageTestGuard::new();
        let serial: u32 = 0xA5A5_0001; // tracked serial -> its own lineage slot
        let idx = lineage_idx(serial);
        // Drive the slot to the wrap boundary directly (a 4-billion-bump loop
        // would be absurd); the store mirrors a counter about to overflow.
        LINEAGE_GEN[idx].store(u32::MAX, core::sync::atomic::Ordering::SeqCst);

        // A capability stamped at the pre-wrap generation is valid right now.
        assert!(lineage_check(serial, u32::MAX));

        // Bump: u32::MAX --(wrap)--> 0 --(skip pristine)--> 1.
        let g = bump_lineage(serial);
        assert_ne!(g, 0, "a wrapped generation must never be the pristine 0");
        assert_eq!(g, 1, "the wrap must land on 1");

        // The pre-wrap capability is now stale (strict equality: MAX != 1).
        assert!(!lineage_check(serial, u32::MAX),
            "a capability recording the pre-wrap generation must be invalid");
        // The current generation (1) is valid; a stale 0 is NOT (strict equality,
        // finding 3.3 — gen 0 is no longer an always-valid escape hatch).
        assert!(lineage_check(serial, 1));
        assert!(!lineage_check(serial, 0),
            "generation 0 is stale once the serial has been bumped away from pristine");
    }

    /// `rust_cap_revoke_by_values` is the explicit-values, single-cspace revoke
    /// behind the IPC snapshot/revalidate guard: it nulls every matching
    /// capability AND bumps the object's lineage, so a snapshot a caller took
    /// before the revoke fails a generation re-check at point of use (the TOCTOU
    /// close).
    #[test]
    fn test_revoke_by_values_invalidates_snapshot() {
        let _lin = LineageTestGuard::new();
        let obj = 0xA300u64;
        let serial: u32 = 0xA301;
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        unsafe {
            // A pristine (generation 0) capability — exactly the gen-0 case that
            // finding 3.3 was about: under the old object-keyed, gen-0-immune
            // check its snapshot passed revalidation forever. Serial-keyed strict
            // equality now invalidates it once the serial is bumped.
            cs[5] = cap(3 /*CAP_ENDPOINT*/, 0x3f, obj, 0, serial, lineage_current(serial));
            // What a caller snapshotted for a later revalidate-at-use.
            let snapshot = cs[5];
            assert!(lineage_check(snapshot.serial, snapshot.generation),
                "snapshot is valid before the revoke");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null());

            assert!(rust_cap_revoke_by_values(cs.as_mut_ptr(), 16, serial, 0, obj));

            // The live slot is nulled structurally...
            assert_eq!(cs[5].typ, CAP_NULL);
            // ...and the pre-revoke snapshot (a gen-0 cap!) now fails the
            // generation re-check — the TOCTOU close that 3.3 restored.
            assert!(!lineage_check(snapshot.serial, snapshot.generation),
                "a pre-revoke snapshot must fail the generation re-check (finding 3.3)");
        }
    }

    /// Minting into a kernel-reserved slot (`0..KERNEL_RESERVED_CAPS`) must be
    /// refused, leaving the slot untouched — this is what stops a userspace mint
    /// from overwriting a primordial root capability by naming its slot.
    #[test]
    fn test_mint_into_reserved_slot_refused() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        // A valid, mint-worthy source in a normal slot. generation 0 => the
        // lookup/mint paths never touch the shared lineage table (parallel-safe).
        cs[5] = cap(1, 0x3f, 0xB100, 0, 0x5100, 0);
        let mut next = 0x10000u32;
        unsafe {
            for dest in 0..KERNEL_RESERVED_CAPS {
                assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, dest, 5, 0x3f, &mut next, 0),
                    "mint into reserved slot {dest} must be refused");
                assert_eq!(cs[dest as usize].typ, CAP_NULL,
                    "reserved slot {dest} must be left untouched");
            }
            // The first non-reserved slot succeeds — proving the guard is the
            // destination slot number, not a broken source or exhausted serial.
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, KERNEL_RESERVED_CAPS, 5, 0x3f, &mut next, 0));
        }
    }

    /// Authority cannot be fabricated from nothing: minting from an empty
    /// (CAP_NULL) source, or from a structurally-present source whose serial is 0
    /// (which lookup also treats as empty), must both be refused with the
    /// destination left untouched.
    #[test]
    fn test_mint_from_invalid_source_refused() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        // slot 6 is empty (CAP_NULL); slot 7 is non-null but carries serial 0.
        cs[7] = cap(1, 0x3f, 0xB101, 0, 0 /* serial */, 0);
        let mut next = 0x10000u32;
        unsafe {
            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 8, 6, 0x3f, &mut next, 0),
                "mint from an empty source slot must be refused");
            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 8, 7, 0x3f, &mut next, 0),
                "mint from a serial-0 source must be refused");
            assert_eq!(cs[8].typ, CAP_NULL, "destination must stay empty when the source is invalid");
        }
    }

    /// Out-of-range slot indices must fail closed on every entry point — null /
    /// false, never an out-of-bounds access or a mutation. Crucially the hard
    /// `CNODE_SIZE` cap holds even when the caller claims an oversized
    /// `cspace_size`, so a bad size argument cannot authorize an OOB read.
    /// Complements the J5 fuzz targets with a fast, explicit regression check.
    #[test]
    fn test_out_of_range_slots_fail_closed() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        cs[5] = cap(1, 0x3f, 0xB102, 0, 0x5102, 0); // a valid in-range cap
        let mut next = 0x10000u32;
        unsafe {
            // slot >= cspace_size
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 16, 0x1).is_null());
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 99, 0x1).is_null());
            // slot >= CNODE_SIZE even when the caller over-claims the size: the
            // hard cap must reject BEFORE indexing the (only 16-long) array.
            assert!(rust_cap_lookup(cs.as_mut_ptr(), u32::MAX, CNODE_SIZE, 0x1).is_null());

            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 16, 5, 0x3f, &mut next, 0),
                "out-of-range dest must be refused");
            assert!(!rust_cap_mint(cs.as_mut_ptr(), 16, 5, 16, 0x3f, &mut next, 0),
                "out-of-range src must be refused");
            assert!(!rust_cap_revoke(cs.as_mut_ptr(), 16, 16, core::ptr::null_mut()),
                "out-of-range revoke must be refused");

            // None of the above disturbed the one valid in-range capability.
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null());
        }
    }

    /// Revocation is transitive across a multi-level derivation chain, not just
    /// parent->child. Minting a grandchild from a child and then revoking the
    /// original parent must null the child AND the grandchild, because every
    /// derived copy shares the parent's `object` and the sweep matches on it.
    #[test]
    fn test_transitive_revoke_across_derivation_chain() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        // Parent in slot 4, generation 0 (lineage-exempt => the pre-revoke
        // lookups never depend on the shared generation table).
        cs[4] = cap(1, 0x3f, 0xB600, 0, 0x5600, 0);
        let mut next = 0x30000u32;
        unsafe {
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 5, 4, 0x3f, &mut next, 0)); // child  <- parent
            assert!(rust_cap_mint(cs.as_mut_ptr(), 16, 6, 5, 0x3f, &mut next, 0)); // grandchild <- child
            for slot in [4u32, 5, 6] {
                assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, slot, 0x1).is_null(),
                    "slot {slot} must be usable before revocation");
            }
            // Revoke the ROOT parent only.
            assert!(rust_cap_revoke(cs.as_mut_ptr(), 16, 4, core::ptr::null_mut()));
            for slot in [4u32, 5, 6] {
                assert_eq!(cs[slot as usize].typ, CAP_NULL,
                    "slot {slot} in the derivation chain must be revoked with its ancestor");
            }
        }
    }

    /// The `caps_in_use` accounting must saturate at zero: if a revocation sweep
    /// nulls capabilities while the counter is already 0 (an accounting
    /// inconsistency), it must stay 0 rather than wrap to `u32::MAX` — an
    /// underflow would permanently defeat the `MAX_CAPS_PER_TASK` ceiling.
    #[test]
    fn test_caps_in_use_never_underflows() {
        let _lin = LineageTestGuard::new();
        let mut cs = [cap(0, 0, 0, 0, 0, 0); 16];
        // A parent and a same-object derived copy (badge == parent serial), both
        // generation 0 for parallel safety.
        cs[4] = cap(1, 0x3f, 0xB700, 0, 0x5700, 0);
        cs[5] = cap(1, 0x03, 0xB700, 0x5700, 0x9700, 0);
        let mut ciu = 0u32; // deliberately understated relative to the two caps present
        unsafe {
            let spaces = [CSpaceDesc { caps: cs.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu) }];
            assert!(rust_cap_revoke_global(
                cs.as_mut_ptr(), 16, 4, addr_of_mut!(ciu), spaces.as_ptr(), 1, core::ptr::null_mut()));
            assert_eq!(cs[4].typ, CAP_NULL);
            assert_eq!(cs[5].typ, CAP_NULL, "the same-object derived copy is swept too");
            assert_eq!(ciu, 0, "caps_in_use must saturate at 0, never wrap to u32::MAX");
        }
    }

    /// `rust_cap_grant_into` delegates a capability across cspaces: the grantee
    /// gets rights reduced to `new_rights & src.rights`, a fresh serial, and the
    /// grantor's cap recorded as its parent (`badge == src.serial`) — so the
    /// derivation tree is well-formed and a later revoke of the grantor sweeps it.
    #[test]
    fn test_grant_into_reduces_rights_and_records_parent() {
        let _lin = LineageTestGuard::new();
        let mut grantor = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut grantee = [cap(0, 0, 0, 0, 0, 0); 16];
        // Grantor holds a full-rights CAP_ENDPOINT (rights 0x3f) at slot 5.
        grantor[5] = cap(3, 0x3f, 0xC100, 0, 0x5100, 0);
        let mut next = 0x40000u32;
        unsafe {
            // Grant with rights reduced to READ|WRITE (0x03), into a low slot 3
            // (allowed: grant endows a dominated child's slots).
            assert!(rust_cap_grant_into(
                &grantor[5] as *const Capability, grantee.as_mut_ptr(), 16, 3, 0x03, &mut next));
            let d = grantee[3];
            assert_eq!(d.typ, 3);
            assert_eq!(d.rights, 0x03, "grant reduces rights to new_rights & src.rights");
            assert_eq!(d.object, 0xC100);
            assert_eq!(d.badge, 0x5100, "grantee records the grantor's cap as its parent");
            assert!(d.serial >= MIN_DERIVED_SERIAL && d.serial != 0x5100,
                "grantee gets a fresh serial distinct from the grantor");
            // A right the source lacks can never be granted, even if requested.
            let mut grantee2 = [cap(0, 0, 0, 0, 0, 0); 16];
            assert!(rust_cap_grant_into(
                &grantor[5] as *const Capability, grantee2.as_mut_ptr(), 16, 4, 0xFFFF, &mut next));
            assert_eq!(grantee2[4].rights, 0x3f, "requested rights are masked by the source's");
        }
    }

    /// Grant refuses an empty / serial-0 source and out-of-range destinations,
    /// leaving the destination untouched — authority cannot be fabricated.
    #[test]
    fn test_grant_into_fails_closed() {
        let _lin = LineageTestGuard::new();
        let mut grantor = [cap(0, 0, 0, 0, 0, 0); 16];
        grantor[7] = cap(3, 0x3f, 0xC200, 0, 0 /* serial 0 => invalid */, 0);
        let mut grantee = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut next = 0x40000u32;
        unsafe {
            // serial-0 source refused.
            assert!(!rust_cap_grant_into(
                &grantor[7] as *const Capability, grantee.as_mut_ptr(), 16, 5, 0x3f, &mut next));
            // null source / null dest refused.
            assert!(!rust_cap_grant_into(
                core::ptr::null(), grantee.as_mut_ptr(), 16, 5, 0x3f, &mut next));
            let valid = cap(3, 0x3f, 0xC201, 0, 0x5201, 0);
            assert!(!rust_cap_grant_into(
                &valid as *const Capability, core::ptr::null_mut(), 16, 5, 0x3f, &mut next));
            // out-of-range dest refused (>= size and >= CNODE_SIZE).
            assert!(!rust_cap_grant_into(
                &valid as *const Capability, grantee.as_mut_ptr(), 16, 16, 0x3f, &mut next));
            assert!(!rust_cap_grant_into(
                &valid as *const Capability, grantee.as_mut_ptr(), u32::MAX, CNODE_SIZE, 0x3f, &mut next));
            assert_eq!(grantee[5].typ, CAP_NULL, "destination untouched on refusal");
        }
    }

    /// A granted capability shares the grantor's lineage: revoking the grantor's
    /// source (system-wide) sweeps the grantee's delegated copy too, because they
    /// share the object and the grantee's badge is the grantor's serial.
    #[test]
    fn test_grant_into_then_revoke_source_sweeps_grantee() {
        let _lin = LineageTestGuard::new();
        let mut grantor = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut grantee = [cap(0, 0, 0, 0, 0, 0); 16];
        grantor[5] = cap(4 /*CAP_FRAME*/, 0x3f, 0xC300, 0, 0x5300, 0);
        let mut next = 0x50000u32;
        let mut ciu_g = 1u32;
        let mut ciu_e = 0u32; // grantee accounting starts at 0; the C caller bumps it
        unsafe {
            assert!(rust_cap_grant_into(
                &grantor[5] as *const Capability, grantee.as_mut_ptr(), 16, 6, !0u32, &mut next));
            ciu_e += 1; // mirror the C caller's was-null increment
            assert!(!rust_cap_lookup(grantee.as_mut_ptr(), 16, 6, 0x1).is_null());

            let spaces = [
                CSpaceDesc { caps: grantor.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_g) },
                CSpaceDesc { caps: grantee.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_e) },
            ];
            assert!(rust_cap_revoke_global(
                grantor.as_mut_ptr(), 16, 5, addr_of_mut!(ciu_g), spaces.as_ptr(), 2, &mut next));
            assert_eq!(grantor[5].typ, CAP_NULL);
            assert_eq!(grantee[6].typ, CAP_NULL, "the delegated copy is revoked with its grantor");
            assert_eq!(ciu_e, 0, "grantee accounting decremented for the swept copy");
        }
    }

    /// AUDIT A1 (core regression): revoking a *delegated child* must NOT disturb
    /// the grantor's original or a sibling child. The old equivalence-set match
    /// nulled the parent (its serial == the child's badge) and same-object peers;
    /// descendant-only revocation touches only what is derived FROM the revoked
    /// capability, not its ancestors or siblings.
    #[test]
    fn test_revoke_child_leaves_parent_and_siblings_intact() {
        let _lin = LineageTestGuard::new();
        let mut grantor = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut child_space = [cap(0, 0, 0, 0, 0, 0); 16];
        // The parent/root of the lineage (generation 0, as every real cap is).
        grantor[4] = cap(3, 0x3f, 0xD100, 0, 0x6100, 0);
        // Two children derived from it (badge == parent serial): a sibling in the
        // grantor's own cspace, and one delegated into another task.
        grantor[5] = cap(3, 0x3f, 0xD100, 0x6100, 0x6101, 0);
        child_space[6] = cap(3, 0x3f, 0xD100, 0x6100, 0x6102, 0);
        let mut ciu_g = 2u32;
        let mut ciu_c = 1u32;
        unsafe {
            let spaces = [
                CSpaceDesc { caps: grantor.as_mut_ptr(),     size: 16, caps_in_use: addr_of_mut!(ciu_g) },
                CSpaceDesc { caps: child_space.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_c) },
            ];
            // Revoke the DELEGATED CHILD (child_space slot 6) — not the parent.
            assert!(rust_cap_revoke_global(
                child_space.as_mut_ptr(), 16, 6, addr_of_mut!(ciu_c),
                spaces.as_ptr(), 2, core::ptr::null_mut()));

            // The child is gone...
            assert_eq!(child_space[6].typ, CAP_NULL);
            assert_eq!(ciu_c, 0);
            // ...but the grantor's original and the sibling child are UNTOUCHED
            // and still usable (the crux of audit A1).
            assert_eq!(grantor[4].typ, 3, "revoking a child must not revoke its parent (A1)");
            assert_eq!(grantor[5].typ, 3, "revoking a child must not revoke a sibling (A1)");
            assert!(!rust_cap_lookup(grantor.as_mut_ptr(), 16, 4, 0x1).is_null(),
                "parent stays usable after a child is revoked");
            assert!(!rust_cap_lookup(grantor.as_mut_ptr(), 16, 5, 0x1).is_null(),
                "sibling stays usable after a child is revoked");
            assert_eq!(ciu_g, 2, "grantor accounting unchanged");
        }
    }

    /// AUDIT A1: two capabilities to the *same object* but with independent
    /// lineages (each installed directly, badge 0, distinct serials — e.g. two
    /// tasks each connected to the fs_server endpoint) must be independent. The
    /// old object-equality match co-revoked them; descendant-only revocation does
    /// not, because neither is derived from the other.
    #[test]
    fn test_revoke_does_not_touch_independent_same_object_cap() {
        let _lin = LineageTestGuard::new();
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];
        // Same object 0xE000, independent lineages (badge 0, distinct serials).
        a[5] = cap(3, 0x3f, 0xE000, 0, 0x7000, 0);
        b[5] = cap(3, 0x3f, 0xE000, 0, 0x7001, 0);
        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;
        unsafe {
            let spaces = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            assert!(rust_cap_revoke_global(
                a.as_mut_ptr(), 16, 5, addr_of_mut!(ciu_a), spaces.as_ptr(), 2, core::ptr::null_mut()));
            assert_eq!(a[5].typ, CAP_NULL, "the revoked cap is gone");
            assert_eq!(b[5].typ, 3, "an independent same-object cap must survive (A1)");
            assert!(!rust_cap_lookup(b.as_mut_ptr(), 16, 5, 0x1).is_null(),
                "the independent same-object cap stays usable");
            assert_eq!(ciu_b, 1, "the other task's accounting is untouched");
        }
    }

    /// The safe overflow fallback: if a derivation subtree is larger than the
    /// bounded worklist (`MAX_REVOKE_LINEAGE`), revocation falls back to nulling
    /// every cap sharing the root object — a complete superset of the descendant
    /// set — so no descendant can ever survive. Over-approximation, never under.
    #[test]
    fn test_revoke_overflow_falls_back_to_complete_object_sweep() {
        let _lin = LineageTestGuard::new();
        const ROOT_SERIAL: u32 = 0x8000_0001;
        const OBJ: u64 = 0xF000;
        // Two full 256-slot cspaces of same-object children of the root (~510
        // descendants) — comfortably past MAX_REVOKE_LINEAGE (256), forcing the
        // overflow path.
        let mut a = [cap(0, 0, 0, 0, 0, 0); 256];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 256];
        // Root in a[0]; the caller (*_global) nulls it before the sweep, and its
        // serial remains the closure seed.
        a[0] = cap(4, 0x3f, OBJ, 0, ROOT_SERIAL, 0);
        let mut serial = 0x9000_0000u32;
        let mut placed = 0usize;
        for c in a.iter_mut().skip(1) {
            serial += 1;
            *c = cap(4, 0x3f, OBJ, ROOT_SERIAL, serial, 0);
            placed += 1;
        }
        for c in b.iter_mut() {
            serial += 1;
            *c = cap(4, 0x3f, OBJ, ROOT_SERIAL, serial, 0);
            placed += 1;
        }
        assert!(placed > MAX_REVOKE_LINEAGE, "test must exceed the worklist to hit overflow");
        let mut ciu_a = 0u32;
        let mut ciu_b = 0u32;
        unsafe {
            let descs = [
                CSpaceDesc { caps: a.as_mut_ptr(), size: 256, caps_in_use: addr_of_mut!(ciu_a) },
                CSpaceDesc { caps: b.as_mut_ptr(), size: 256, caps_in_use: addr_of_mut!(ciu_b) },
            ];
            assert!(rust_cap_revoke_global(
                a.as_mut_ptr(), 256, 0, addr_of_mut!(ciu_a),
                descs.as_ptr(), 2, core::ptr::null_mut()));
            for c in a.iter().chain(b.iter()) {
                assert_eq!(c.typ, CAP_NULL,
                    "overflow fallback must revoke every same-object descendant");
            }
        }
    }

    /// FINDING 3.3 regression. Reproduces the exact production scenario: a parent
    /// and a derived child both carry generation 0 (every capability in the
    /// running kernel is created gen 0, and mint stamps the child from its own
    /// fresh serial, still 0 while pristine). Under the old object-keyed,
    /// gen-0-immune check a detached SNAPSHOT of the child survived the parent's
    /// revocation forever, defeating the use-after-revoke / IPC revalidate guard.
    /// Serial-keyed strict equality must now (a) invalidate the child's snapshot
    /// when the parent is revoked, while (b) leaving an INDEPENDENT same-object
    /// capability (a different serial) valid — so the fix does not regress A1.
    #[test]
    fn test_gen0_snapshot_invalidated_after_revoke_finding_3_3() {
        let _lin = LineageTestGuard::new();
        let mut owner = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut other = [cap(0, 0, 0, 0, 0, 0); 16];
        // Parent, gen 0, real object. An independent capability to the SAME
        // object in another task (badge 0, distinct serial) — e.g. two tasks each
        // independently connected to the fs_server endpoint.
        owner[4] = cap(3 /*CAP_ENDPOINT*/, 0x3f, 0xEE00, 0, 0x4400, 0);
        other[9] = cap(3, 0x3f, 0xEE00, 0, 0x8800, 0);
        let mut ciu_o = 1u32;
        let mut ciu_x = 1u32;
        let mut next = 0x7_0000u32;
        unsafe {
            // Derive a child from the parent (production mint): fresh serial,
            // stamped generation (0 while the serial's slot is pristine).
            assert!(rust_cap_mint(owner.as_mut_ptr(), 16, 5, 4, 0x3, &mut next, 0));
            let child = owner[5];
            assert_eq!(child.generation, 0, "a pristine child is gen 0, as in production");
            // A caller snapshots the child for a later revalidate-at-use.
            let snapshot = child;
            assert!(lineage_check(snapshot.serial, snapshot.generation),
                "the gen-0 child snapshot is valid before the revoke");

            // System-wide revoke of the PARENT (the reachable SYS_CAP_REVOKE path).
            let spaces = [
                CSpaceDesc { caps: owner.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_o) },
                CSpaceDesc { caps: other.as_mut_ptr(), size: 16, caps_in_use: addr_of_mut!(ciu_x) },
            ];
            assert!(rust_cap_revoke_global(
                owner.as_mut_ptr(), 16, 4, addr_of_mut!(ciu_o), spaces.as_ptr(), 2, &mut next));

            // (a) The gen-0 child's detached snapshot now fails revalidation —
            // the hole finding 3.3 identified is closed, even for a gen-0 cap.
            assert!(!lineage_check(snapshot.serial, snapshot.generation),
                "gen-0 child snapshot must be stale after its parent is revoked (finding 3.3)");
            assert_eq!(owner[5].typ, CAP_NULL, "the live child slot is also swept");

            // (b) The independent same-object capability (different serial) is
            // untouched and still usable — the fix does not over-revoke (A1).
            assert_eq!(other[9].typ, 3, "an independent same-object cap must survive");
            assert!(!rust_cap_lookup(other.as_mut_ptr(), 16, 9, 0x1).is_null(),
                "the independent same-object cap stays valid (serial-keyed, not object-keyed)");
            assert_eq!(ciu_x, 1, "the other task's accounting is untouched");
        }
    }
}

// ---------------------------------------------------------------------------
// Formal verification (Kani bounded model checking).
//
// These #[kani::proof] harnesses are compiled ONLY under `cargo kani` (the
// `kani` cfg); they are invisible to the normal build, `cargo test`, clippy,
// and the kernel link. Where a unit test in the module above samples a handful
// of inputs, Kani proves the property over the ENTIRE input space (every u32),
// so it catches a boundary the samples miss. Run with:  cargo kani  (from rust/)
//
// Scope: the pure / self-contained authority invariants. Functions that mutate
// the shared LINEAGE_GEN static are avoided here (global mutable state needs a
// heavier model); the harnesses keep object==0 so the lineage floor update in
// mint is not exercised — the rights logic under proof is identical either way.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// A freshly allocated derived serial is NEVER in the reserved primordial
    /// range and NEVER 0 — for every possible value of the kernel's monotonic
    /// serial counter, not just the boundary values the unit test samples. This
    /// is what guarantees a derived capability's serial can never be mistaken for
    /// a primordial (0xC0DE-prefixed) one or for an empty (serial-0) slot.
    #[kani::proof]
    fn serial_never_reserved_or_zero() {
        let mut counter: u32 = kani::any();
        let s = unsafe { assign_fresh_serial(&mut counter as *mut u32) };
        assert!(s >= MIN_DERIVED_SERIAL, "serial dipped below the derived floor");
        assert!(s != 0, "serial wrapped to the reserved 0");
        assert!(counter == s, "counter must advance to exactly the returned serial");
    }

    /// Minting can only ever REDUCE authority: the minted capability's rights are
    /// a subset of the source's, and exactly the intersection of the requested
    /// and source rights — for EVERY (source rights, requested rights) pair. No
    /// combination of requested rights can escalate beyond what the source holds.
    #[kani::proof]
    fn mint_never_escalates_rights() {
        let src_rights: u32 = kani::any();
        let req_rights: u32 = kani::any();

        // 8-slot cspace: source at slot 0, mint into slot 4 (>= KERNEL_RESERVED_CAPS
        // so the mint is not refused). object==0 keeps the proof free of the
        // shared lineage table.
        let mut cs = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 8];
        cs[0] = Capability { typ: 1, rights: src_rights, object: 0, badge: 0, serial: 0x10000, generation: 0 };
        let mut next: u32 = 0x10000;

        let ok = unsafe {
            rust_cap_mint(cs.as_mut_ptr(), 8, 4, 0, req_rights, &mut next as *mut u32, 0)
        };
        assert!(ok, "mint of a valid source into a non-reserved slot must succeed");

        let minted = cs[4].rights;
        assert!(minted & !src_rights == 0, "minted rights must be a subset of the source's");
        assert!(minted == (req_rights & src_rights), "minted rights must be requested AND source");
    }

    /// Build a 3-capability derivation chain (parent -> child -> grandchild) in
    /// one cspace, with caller-chosen serials. `object` is 0 throughout so the
    /// proofs never touch the shared LINEAGE_GEN static.
    fn chain(p: u32, c: u32, g: u32) -> [Capability; 3] {
        [
            Capability { typ: 1, rights: 0x3f, object: 0, badge: 0, serial: p, generation: 0 },
            Capability { typ: 1, rights: 0x3f, object: 0, badge: p, serial: c, generation: 0 },
            Capability { typ: 1, rights: 0x3f, object: 0, badge: c, serial: g, generation: 0 },
        ]
    }

    /// AUDIT A1, the core invariant, proved over the ENTIRE serial space:
    /// revoking a *derived* capability never nulls its ancestors. For every
    /// distinct (parent, child, grandchild) serial triple, revoking the
    /// grandchild's subtree leaves the parent and the child intact and usable,
    /// and removes exactly the grandchild.
    ///
    /// This is the property the old equivalence-set matcher violated: it matched
    /// the target's `badge` against other caps' `serial`, so revoking a child
    /// also nulled its parent. A unit test samples a few serials; this covers all
    /// of them.
    #[kani::proof]
    #[kani::unwind(6)]
    fn revoke_descendant_never_nulls_ancestors() {
        let p: u32 = kani::any();
        let c: u32 = kani::any();
        let g: u32 = kani::any();
        // Serials are unique and non-zero by construction (assign_fresh_serial).
        kani::assume(p != 0 && c != 0 && g != 0);
        kani::assume(p != c && c != g && p != g);

        let mut cs = chain(p, c, g);
        let desc = CSpaceDesc {
            caps: cs.as_mut_ptr(),
            size: 3,
            caps_in_use: core::ptr::null_mut(),
        };
        // Revoke the LEAF (grandchild) subtree.
        unsafe { revoke_subtree(&desc as *const CSpaceDesc, 1, g, 0) };

        assert!(cs[0].typ != CAP_NULL, "revoking a descendant must not null the parent");
        assert!(cs[0].serial == p, "the parent must be left byte-for-byte intact");
        assert!(cs[1].typ != CAP_NULL, "revoking a descendant must not null its own parent");
        assert!(cs[1].serial == c, "the intermediate cap must be left intact");
        assert!(cs[2].typ == CAP_NULL, "the revoked capability itself must be nulled");
    }

    /// The other half: revocation is COMPLETE downward. Revoking the root of a
    /// derivation chain nulls every descendant — the child and the grandchild —
    /// for every distinct serial triple, so no derived authority can outlive its
    /// ancestor. Together with the proof above this pins revocation to exactly
    /// the target's subtree: no more (no ancestors) and no less (all descendants).
    #[kani::proof]
    #[kani::unwind(6)]
    fn revoke_root_nulls_every_descendant() {
        let p: u32 = kani::any();
        let c: u32 = kani::any();
        let g: u32 = kani::any();
        kani::assume(p != 0 && c != 0 && g != 0);
        kani::assume(p != c && c != g && p != g);

        let mut cs = chain(p, c, g);
        let desc = CSpaceDesc {
            caps: cs.as_mut_ptr(),
            size: 3,
            caps_in_use: core::ptr::null_mut(),
        };
        unsafe { revoke_subtree(&desc as *const CSpaceDesc, 1, p, 0) };

        assert!(cs[0].typ == CAP_NULL, "the revoked root must be nulled");
        assert!(cs[1].typ == CAP_NULL, "a direct child must be revoked with its parent");
        assert!(cs[2].typ == CAP_NULL, "a grandchild must be revoked transitively");
    }

    /// FINDING 3.3, use-after-revoke, proved over the whole serial/generation
    /// space: for any tracked serial and any generation a live capability
    /// recorded (the serial's current cell value), bumping that serial's lineage
    /// makes the recorded generation fail the strict-equality `lineage_check`, and
    /// a bump never yields the pristine 0. This is exactly the guarantee the old
    /// object-keyed, gen-0-immune check could not provide — a gen-0 snapshot then
    /// passed unconditionally. Unlike the pure harnesses above, this one exercises
    /// the shared `LINEAGE_GEN` static on one (symbolic) cell.
    #[kani::proof]
    fn revoke_invalidates_recorded_generation() {
        let serial: u32 = kani::any();
        kani::assume(serial_is_tracked(serial));
        let pre: u32 = kani::any();
        let idx = lineage_idx(serial);
        // Establish an arbitrary current generation and a live cap recording it.
        LINEAGE_GEN[idx].store(pre, core::sync::atomic::Ordering::SeqCst);
        assert!(lineage_check(serial, pre), "a cap recording the current generation is valid");

        // Revoke: bump this serial's lineage generation.
        let new = bump_lineage(serial);
        assert!(new != 0, "a bumped generation is never the pristine 0");
        assert!(!lineage_check(serial, pre),
            "a capability/snapshot recording the pre-revoke generation must be invalid");
    }

    /// FINDING 3.3, precision / no over-revocation (audit A1 at the generation
    /// layer): bumping one serial's lineage cell never invalidates a capability
    /// whose serial maps to a DIFFERENT cell — so a live sibling, ancestor, or
    /// independent same-object peer survives a revoke that is not theirs. The
    /// proof is conditioned on distinct cells: two serials that hash to the same
    /// 4096-slot cell can collide, which is the documented, fail-safe A3 residual.
    #[kani::proof]
    fn revoke_does_not_touch_a_distinct_lineage_cell() {
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        kani::assume(serial_is_tracked(a));
        kani::assume(serial_is_tracked(b));
        kani::assume(lineage_idx(a) != lineage_idx(b));
        let gb: u32 = kani::any();
        LINEAGE_GEN[lineage_idx(b)].store(gb, core::sync::atomic::Ordering::SeqCst);
        assert!(lineage_check(b, gb), "b is valid before the unrelated revoke");

        let _ = bump_lineage(a);
        assert!(lineage_check(b, gb),
            "bumping a serial in a different cell must not invalidate b");
    }
}
