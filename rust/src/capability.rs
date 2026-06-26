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





// Single source of truth for per-object lineage generations.
//
// This table is the *authority* for revocation/use-after-revoke detection.
// The C side no longer keeps its own `lineages[]` table; it delegates every
// generation check and bump through the `rust_lineage_check` / `rust_lineage_bump`
// FFI below. Keeping a single table eliminates the C/Rust desync that allowed a
// stale derived capability to pass one check while the other had been bumped.
//
// Each slot is an independent atomic so accesses are sound under future
// preemption / SMP. On the current single-core cooperative kernel the atomics
// compile down to plain loads/stores plus a `lock`-prefixed add.
const LINEAGE_SLOTS: usize = 4096;
#[allow(clippy::declare_interior_mutable_const)]
const LINEAGE_ZERO: AtomicU32 = AtomicU32::new(0);
static LINEAGE_GEN: [AtomicU32; LINEAGE_SLOTS] = [LINEAGE_ZERO; LINEAGE_SLOTS];



#[inline]
fn lineage_idx(obj: u64) -> usize {
    let mut x = obj;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x as usize) & (LINEAGE_SLOTS - 1)
}

/// Bump the generation for `obj`, invalidating every capability minted against
/// the previous generation. Returns the new generation. Generation 0 is reserved
/// to mean "untracked", so we skip it on wrap-around.
#[inline]
fn bump_lineage(obj: u64) -> u32 {
    if obj == 0 { return 0; }
    let idx = lineage_idx(obj);
    let prev = LINEAGE_GEN[idx].fetch_add(1, Ordering::SeqCst);
    let g = prev.wrapping_add(1);
    if g == 0 {
        // Wrapped back onto the reserved "untracked" value; force to 1.
        LINEAGE_GEN[idx].store(1, Ordering::SeqCst);
        1
    } else {
        g
    }
}

/// Authoritative validity check: is a capability that recorded `gen` for `obj`
/// still live? A cap is stale only when the lineage is tracked (`cg != 0`), the
/// cap carries a concrete generation (`gen != 0`), and they disagree.
#[inline]
fn lineage_check(obj: u64, gen: u32) -> bool {
    if obj == 0 { return true; }
    let cg = LINEAGE_GEN[lineage_idx(obj)].load(Ordering::SeqCst);
    !(cg != 0 && gen != 0 && gen != cg)
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
    if cap.object != 0 && !lineage_check(cap.object, cap.generation) {
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

    *dest = Capability {
        typ: src.typ,
        rights: effective_rights,
        object: src.object,
        badge: parent_serial,
        serial: fresh,
        generation: src.generation,
    };
    if src.object != 0 {
        // Adopt the parent's generation as the floor for this lineage so the
        // authority never lags behind a legitimately-minted capability.
        LINEAGE_GEN[lineage_idx(src.object)].fetch_max(src.generation, Ordering::SeqCst);
    }
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

#[no_mangle]
pub unsafe extern "C" fn rust_cap_move(
    cspace: *mut Capability,
    cspace_size: u32,
    dest_slot: u32,
    src_slot: u32,
    next_serial: *mut u32,
) -> bool {
    if rust_cap_transfer(cspace, cspace_size, dest_slot, src_slot, next_serial) {
        return rust_cap_revoke(cspace, cspace_size, src_slot, next_serial);
    }
    false
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

/// Lineage match predicate: does capability `c` belong to the revoked lineage
/// identified by (serial, badge, object)? A derived capability records its
/// parent's serial in its `badge`, so matching either field on serial/badge —
/// or matching the underlying object — catches every descendant copy.
#[inline]
fn lineage_matches(c: &Capability, ts: u32, tb: u32, to: u64) -> bool {
    (ts != 0 && (c.serial == ts || c.badge == ts))
        || (tb != 0 && (c.serial == tb || c.badge == tb))
        || (to != 0 && c.object == to)
}

/// Null every capability in one cspace that matches the target lineage,
/// skipping `skip_slot` (pass `u32::MAX` to skip none). Decrements
/// `*caps_in_use` once per nulled cap when the pointer is non-null.
///
/// INVARIANT: this is the single mechanism by which a cspace is swept for a
/// revoked lineage; `rust_cap_revoke` and `rust_cap_revoke_global` both go
/// through it so their matching semantics can never drift apart.
unsafe fn revoke_matching_in(
    cspace: *mut Capability,
    size: u32,
    skip_slot: u32,
    ts: u32,
    tb: u32,
    to: u64,
    caps_in_use: *mut u32,
) {
    if cspace.is_null() {
        return;
    }
    let limit = if size > CNODE_SIZE { CNODE_SIZE } else { size };
    for i in 0..limit {
        if i == skip_slot {
            continue;
        }
        let c = &mut *cspace.add(i as usize);
        if c.typ == CAP_NULL {
            continue;
        }
        if lineage_matches(c, ts, tb, to) {
            nullify(c);
            if !caps_in_use.is_null() && *caps_in_use > 0 {
                *caps_in_use -= 1;
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
    let tb = target.badge;
    let to = target.object;

    nullify(target);

    // Single source of truth: bump the object's lineage generation once.
    if to != 0 {
        let _ = bump_lineage(to);
    }

    revoke_matching_in(cspace, cspace_size, slot, ts, tb, to, core::ptr::null_mut());
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
/// cspaces plus the kernel root cnode) for derived copies of the same lineage,
/// nulling them. The lineage generation is bumped exactly once, so any stale
/// copy that somehow escapes the structural sweep still fails the generation
/// check in `rust_cap_lookup`.
///
/// INVARIANT (see ARCHITECTURE.md): after this returns true, no live cspace
/// retains a capability whose serial/badge/object matches the revoked lineage.
/// This is what makes revocation complete rather than caller-local — closing
/// the use-after-revoke / privilege-retention hole where a derived capability
/// in another task's CNode could survive its parent's revocation.
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
    let tb = target.badge;
    let to = target.object;

    // Null the target itself and account for it. The system-wide sweep below
    // will skip it (already null), so it is never double-counted.
    nullify(target);
    if !target_caps_in_use.is_null() && *target_caps_in_use > 0 {
        *target_caps_in_use -= 1;
    }

    // Single source of truth: bump the object's lineage generation once.
    if to != 0 {
        let _ = bump_lineage(to);
    }

    // Sweep every supplied cspace, including the target's own (target slot is
    // already null, so it cannot re-match).
    if !spaces.is_null() {
        for s in 0..space_count {
            let d = &*spaces.add(s as usize);
            revoke_matching_in(d.caps, d.size, u32::MAX, ts, tb, to, d.caps_in_use);
        }
    }
    true
}

/// Single-cspace revoke by explicit values. Retained for compatibility; the
/// system-wide path is `rust_cap_revoke_global`.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_revoke_by_values(
    cspace: *mut Capability,
    cspace_size: u32,
    target_serial: u32,
    target_badge: u32,
    target_obj: u64,
) -> bool {
    if cspace.is_null() {
        return false;
    }
    // Bump lineage once for the object so generation checks also invalidate.
    if target_obj != 0 {
        let _ = bump_lineage(target_obj);
    }
    revoke_matching_in(
        cspace,
        cspace_size,
        u32::MAX,
        target_serial,
        target_badge,
        target_obj,
        core::ptr::null_mut(),
    );
    true
}

/// FFI: bump the lineage generation for `obj`. Sole way for C to invalidate a lineage.
#[no_mangle]
pub extern "C" fn rust_lineage_bump(obj: u64) -> u32 { bump_lineage(obj) }

/// FFI: check whether a capability recording `gen` for `obj` is still valid.
/// C's `capability_validate_generation` delegates here so both sides agree.
#[no_mangle]
pub extern "C" fn rust_lineage_check(obj: u64, gen: u32) -> bool { lineage_check(obj, gen) }

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;

    fn cap(typ: u32, rights: u32, object: u64, badge: u32, serial: u32, generation: u32) -> Capability {
        Capability { typ, rights, object, badge, serial, generation }
    }

    /// Regression: a derived capability minted into a *second* task's cspace
    /// must be revoked (and its lineage invalidated) when the parent is revoked
    /// in the first task — the system-wide revocation invariant.
    #[test]
    fn test_global_revoke_reaches_other_task_cspace() {
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];

        // Task A holds the parent CAP_FRAME (object 0x5000, serial 0x4000, gen 1).
        a[4] = cap(1, 0x3f, 0x5000, 0, 0x4000, 1);
        // Task B holds a derived copy: badge == parent serial, same object,
        // reduced rights, its own fresh serial — exactly what cap_mint produces.
        b[7] = cap(1, 0x03, 0x5000, 0x4000, 0x9001, 1);

        let mut ciu_a = 1u32;
        let mut ciu_b = 1u32;

        unsafe {
            // Mirror reality: minting raises the lineage floor to the parent's
            // generation, so the table holds gen==1 for this object before the
            // revoke (which then bumps it to 2).
            while lineage_check(0x5000, 2) {
                let _ = bump_lineage(0x5000);
            }
            // Now cg == 1, matching the caps' recorded generation.

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

            // Lineage generation bumped: a stale copy carrying the old gen fails
            // the generation check even if it had escaped the structural sweep.
            assert!(!lineage_check(0x5000, 1));

            // Accounting: both tasks' caps_in_use were decremented exactly once.
            assert_eq!(ciu_a, 0);
            assert_eq!(ciu_b, 0);
        }
    }

    /// A capability for a *different* object/lineage in another cspace must
    /// survive an unrelated revocation (no over-broad nulling).
    #[test]
    fn test_global_revoke_does_not_touch_unrelated() {
        let mut a = [cap(0, 0, 0, 0, 0, 0); 16];
        let mut b = [cap(0, 0, 0, 0, 0, 0); 16];
        a[4] = cap(1, 0x3f, 0x7000, 0, 0x7700, 1);
        b[7] = cap(1, 0x3f, 0x8000, 0, 0x8800, 1); // unrelated lineage

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
        let mut cspace = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        cspace[0] = Capability { typ: 1, rights: 0x3f, object: 99, badge: 0, serial: 0x2000, generation: 1 };

        let mut next = 0x2001u32;
        unsafe {
            let mint_ok = rust_cap_mint(cspace.as_mut_ptr(), 16, 6, 0, 0x7, &mut next, 0);
            assert!(mint_ok);
            let child_before = *cspace.as_ptr().add(6);
            assert_eq!(child_before.badge, 0x2000);
            assert_eq!(child_before.generation, 1);

            
            let rev_ok = rust_cap_revoke(cspace.as_mut_ptr(), 16, 0, core::ptr::null_mut());
            assert!(rev_ok);

            let looked = rust_cap_lookup(cspace.as_mut_ptr(), 16, 6, 0x1);
            assert!(looked.is_null(), "derived cap must be revoked together with parent (badge lineage)");
            
            assert!(rust_cap_lookup(cspace.as_mut_ptr(), 16, 0, 0).is_null());
        }
    }

    #[test]
    fn test_lineage_no_collision_on_low_bits() {
        
        
        
        let mut cs = [Capability { typ: 0, rights: 0, object: 0, badge: 0, serial: 0, generation: 0 }; 16];
        unsafe {
            let ga = bump_lineage(0x1001);
            let gb = bump_lineage(0x1101);
            cs[4] = Capability { typ: 1, rights: 0x3f, object: 0x1001, badge: 0, serial: 0x100, generation: ga };
            cs[5] = Capability { typ: 1, rights: 0x3f, object: 0x1101, badge: 0, serial: 0x200, generation: gb };

            
            let _ = bump_lineage(0x1001);

            
            assert!(rust_cap_lookup(cs.as_mut_ptr(), 16, 4, 0x1).is_null(),
                "object 0x1001 should be stale after its lineage bump");
            assert!(!rust_cap_lookup(cs.as_mut_ptr(), 16, 5, 0x1).is_null(),
                "object 0x1101 must NOT be revoked by a bump targeting 0x1001");
        }
    }

    #[test]
    fn test_strict_rights_and_no_escalation() {
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
}
