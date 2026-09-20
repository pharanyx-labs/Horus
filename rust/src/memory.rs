use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// Mirrors USER_PHYS_PAGES in src/include/kernel.h: the *capacity* of the C
// refcount table (page_refcounts) and free_page_stack, i.e. the largest pool the
// metadata can track. The runtime pool is sized from the E820 map and may be
// smaller; this must equal the C constant or rust_page_refcounts_register refuses
// the table and the kernel halts. Keep the two in step.
pub const USER_PHYS_PAGES: u32 = 131072;
pub const USER_PHYS_BASE: u32 = 0x01000000;
pub const PAGE_SIZE: u32 = 4096;

// ---------------------------------------------------------------------------
// Refcount-table trust boundary.
//
// These functions write into a `*mut u16` array supplied by C. Bounds checks
// alone are not enough: a buggy C caller that passes a wrong pointer or a
// `n_pages` larger than the real array would let Rust write out of bounds (UB
// in the combined binary). To close that, C must register the one true table
// once via `rust_page_refcounts_register`; every subsequent inc/dec then
// requires the supplied (pointer, length) to match the registered table
// exactly, and the length to equal the compile-time `USER_PHYS_PAGES`. A
// mismatch is refused rather than trusted.
// ---------------------------------------------------------------------------
static REFC_PTR: AtomicUsize = AtomicUsize::new(0);
static REFC_LEN: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// The index derivation, extracted so it can be PROVED rather than reviewed.
//
// Until 2026-09-20 the "is this address inside the table" arithmetic was
// written out twice, once in rust_page_ref_inc and once in rust_page_ref_dec,
// and it is the only thing standing between a u32 that C chose and a write
// through a raw pointer. Two copies of a bounds check is two places for one to
// drift, and neither copy could be reached by a proof because both were wrapped
// in an `unsafe extern "C"` function that dereferences a pointer Kani has no
// model of. Pulling the arithmetic out gives ONE derivation, used by both, over
// pure integers, which `memory_kani_proofs` below proves in bounds for every
// u32 rather than for the handful the unit test samples.
//
// This is the "by construction beats by remembering" rule pointed at the
// neighbouring C: `free_user_physical_page` in src/kernel/paging.c is safe only
// because its callers keep a refcount protocol (docs/LIMITATIONS.md 2.5a,
// [HORUS-20260919-01]). Nothing here closes that finding. What it does is make
// the Rust half of the same refcount a proved boundary instead of a second
// place discipline is required.
// ---------------------------------------------------------------------------

/// The table index of the page containing `phys`, or `None` when `phys` is
/// below the pool or past the end of a table of `n_pages` entries.
#[inline]
fn refc_index(phys: u32, n_pages: u32) -> Option<usize> {
    if phys < USER_PHYS_BASE {
        return None;
    }
    let idx32 = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if idx32 >= n_pages {
        return None;
    }
    Some(idx32 as usize)
}

/// What an increment writes back. Saturating rather than wrapping: a count that
/// wrapped to 0 would let a page somebody still holds be freed.
#[inline]
fn refc_inc_value(cur: u16) -> u16 {
    cur.saturating_add(1)
}

/// What a decrement writes back, or `None` when the count is already 0.
/// Refusing rather than wrapping: a count that wrapped to 65535 would pin the
/// page for the rest of the boot.
#[inline]
fn refc_dec_value(cur: u16) -> Option<u16> {
    if cur == 0 {
        None
    } else {
        Some(cur - 1)
    }
}

/// Register the authoritative refcount table. Must be called once at paging
/// init before any inc/dec. Rejects anything but the expected fixed-size table.
///
/// # Safety
/// `refcounts` must be null, or point to an array of at least `n_pages` `u16`s
/// that lives for the rest of the boot: it is stored and every later
/// `rust_page_ref_inc`/`_dec` is checked against it. A null pointer, or any
/// `n_pages` other than `USER_PHYS_PAGES`, is refused rather than trusted, so
/// the only obligation the caller cannot be relieved of is that a NON-null
/// pointer really does address that many `u16`s. Call once, from paging init,
/// before any other function in this module; a second call silently re-points
/// the table every later check validates against.
#[no_mangle]
pub unsafe extern "C" fn rust_page_refcounts_register(refcounts: *const u16, n_pages: u32) -> bool {
    if refcounts.is_null() || n_pages != USER_PHYS_PAGES {
        return false;
    }
    REFC_PTR.store(refcounts as usize, Ordering::SeqCst);
    REFC_LEN.store(n_pages, Ordering::SeqCst);
    true
}

/// True iff (refcounts, n_pages) is the exact table that was registered.
#[inline]
fn refc_table_ok(refcounts: *const u16, n_pages: u32) -> bool {
    let p = REFC_PTR.load(Ordering::SeqCst);
    let l = REFC_LEN.load(Ordering::SeqCst);
    p != 0 && p == refcounts as usize && l == n_pages && n_pages == USER_PHYS_PAGES
}

/// Increment the refcount of the page containing `phys`. Returns the new count,
/// or 0 if the arguments do not name a tracked page.
///
/// # Safety
/// `refcounts`/`n_pages` must be the exact pair registered by
/// `rust_page_refcounts_register`; anything else is refused by `refc_table_ok`
/// before a single byte is touched, which is what makes a wrong pointer from C a
/// returned 0 rather than an out-of-bounds write. `phys` is unconstrained: below
/// `USER_PHYS_BASE` or past the end of the table it is refused too. The caller
/// must serialise concurrent calls -- this is a plain read-modify-write through
/// the raw pointer, not an atomic -- which in this kernel means holding
/// `page_lock`.
#[no_mangle]
pub unsafe extern "C" fn rust_page_ref_inc(phys: u32, refcounts: *mut u16, n_pages: u32) -> u16 {
    if !refc_table_ok(refcounts as *const u16, n_pages) {
        return 0;
    }
    let idx = match refc_index(phys, n_pages) {
        Some(i) => i,
        None => return 0,
    };
    let cur = *refcounts.add(idx);
    let next = refc_inc_value(cur);
    *refcounts.add(idx) = next;
    next
}

/// Decrement the refcount of the page containing `phys`. Returns the new count,
/// -1 if the arguments do not name a tracked page, or -2 if it was already 0.
///
/// # Safety
/// As `rust_page_ref_inc`: `refcounts`/`n_pages` must be the registered pair,
/// every other argument is validated, and the caller must hold `page_lock`.
/// Underflow is reported (-2) rather than wrapped, because a refcount that wraps
/// to 65535 would pin a page forever and one that wraps past 0 would free a page
/// somebody still holds.
#[no_mangle]
pub unsafe extern "C" fn rust_page_ref_dec(phys: u32, refcounts: *mut u16, n_pages: u32) -> i32 {
    if !refc_table_ok(refcounts as *const u16, n_pages) {
        return -1;
    }
    let idx = match refc_index(phys, n_pages) {
        Some(i) => i,
        None => return -1,
    };
    let cur = *refcounts.add(idx);
    let next = match refc_dec_value(cur) {
        Some(n) => n,
        None => return -2,
    };
    *refcounts.add(idx) = next;
    next as i32
}

// ---------------------------------------------------------------------------
// Kani proofs for the refcount arithmetic (SECURITY.md S31's method, applied to
// the page pool). Compiled ONLY under `cargo kani` (the `kani` cfg), invisible
// to the normal build, `cargo test`, clippy and the kernel link.
//
// WHAT THESE ADD OVER THE UNIT TEST BELOW. `refcount_trust_boundary` samples a
// handful of addresses: page 0, page 5, page 6, one below the base, one past
// the end. These prove the same properties for EVERY u32 address and EVERY u16
// count, which is the difference between "no boundary we thought of is broken"
// and "no boundary exists". The arithmetic is pure, so the solver cost is
// small: no pointer, no allocation, no global state.
//
// WHAT THEY DO NOT CLAIM. They say nothing about the raw-pointer write itself,
// nor about `refc_table_ok`, which reads process-global atomics that a proof
// harness cannot meaningfully quantify over. The registration boundary stays
// witnessed by the unit test and by Miri. Stated here so a reader does not take
// "memory.rs is proved" from a module that proves its arithmetic.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod memory_kani_proofs {
    use super::*;

    /// **The bound that stands between C's chosen `u32` and a raw write.** For
    /// every address and every table size up to the compile-time capacity, an
    /// accepted index is inside both the caller's table and the fixed-size one
    /// `refc_table_ok` insists on. This is the property `rust_page_ref_inc` and
    /// `rust_page_ref_dec` rely on before `refcounts.add(idx)`.
    #[kani::proof]
    fn refc_index_is_always_inside_the_table() {
        let phys: u32 = kani::any();
        let n_pages: u32 = kani::any();
        kani::assume(n_pages <= USER_PHYS_PAGES);
        if let Some(i) = refc_index(phys, n_pages) {
            assert!(i < n_pages as usize);
            assert!(i < USER_PHYS_PAGES as usize);
        }
    }

    /// The index is not merely in range, it names the page that actually
    /// CONTAINS the address. Stated as containment rather than by recomputing
    /// the division, so the proof characterises the result instead of restating
    /// the implementation; a harness that recomputed it would pass against any
    /// derivation, including a wrong one copied into both places.
    #[kani::proof]
    fn refc_index_names_the_page_that_contains_the_address() {
        let phys: u32 = kani::any();
        let n_pages: u32 = kani::any();
        kani::assume(n_pages <= USER_PHYS_PAGES);
        if let Some(i) = refc_index(phys, n_pages) {
            let page_base = USER_PHYS_BASE + (i as u32) * PAGE_SIZE;
            assert!(phys >= page_base);
            assert!(phys - page_base < PAGE_SIZE);
        }
    }

    /// The completeness half: every page the table can track is reachable, so
    /// the derivation has no gap that would silently stop refcounting a page.
    /// Without this, a derivation that refused everything would satisfy the two
    /// proofs above.
    #[kani::proof]
    fn every_page_in_the_pool_has_an_index() {
        let page: u32 = kani::any();
        let n_pages: u32 = kani::any();
        kani::assume(n_pages <= USER_PHYS_PAGES);
        kani::assume(page < n_pages);
        let phys = USER_PHYS_BASE + page * PAGE_SIZE;
        assert_eq!(refc_index(phys, n_pages), Some(page as usize));
    }

    /// An increment never wraps. A count that wrapped to 0 would let a page
    /// somebody still holds be handed to the free stack, which is the shortest
    /// path to one frame mapped into two address spaces.
    #[kani::proof]
    fn an_increment_never_wraps_a_refcount() {
        let cur: u16 = kani::any();
        let next = refc_inc_value(cur);
        assert!(next >= cur);
        assert!(next != 0);
        if cur == u16::MAX {
            assert_eq!(next, u16::MAX);
        } else {
            assert_eq!(next, cur + 1);
        }
    }

    /// A decrement never underflows, and is refused EXACTLY when the count is
    /// already zero. A count that wrapped to 65535 would pin the page for the
    /// rest of the boot; the equivalence is what stops a refusal that is too
    /// eager from satisfying the property vacuously.
    #[kani::proof]
    fn a_decrement_never_underflows_a_refcount() {
        let cur: u16 = kani::any();
        match refc_dec_value(cur) {
            None => assert_eq!(cur, 0),
            Some(next) => {
                assert!(cur > 0);
                assert!(next < cur);
                assert_eq!(next, cur - 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N: u32 = USER_PHYS_PAGES;
    fn phys_of(page: u32) -> u32 {
        USER_PHYS_BASE + page * PAGE_SIZE
    }

    // The refcount table is guarded by process-global registered (ptr, len).
    // Keep every assertion that depends on that global in ONE test so parallel
    // tests can never clobber the registration between register and use. This
    // is the only test in the crate that calls rust_page_refcounts_register.
    #[test]
    fn refcount_trust_boundary() {
        let mut table = [0u16; USER_PHYS_PAGES as usize];
        let ptr = table.as_mut_ptr();
        let other = [0u16; 4];

        unsafe {
            // Registration accepts only the one true fixed-size table.
            assert!(!rust_page_refcounts_register(core::ptr::null(), N));
            assert!(!rust_page_refcounts_register(ptr, N - 1));
            assert!(!rust_page_refcounts_register(ptr, N + 1));
            assert!(rust_page_refcounts_register(ptr, N));

            // Zero-trust: inc/dec touch memory only when (ptr, len) is the exact
            // registered table — a wrong pointer or length is refused, never
            // dereferenced.
            assert_eq!(rust_page_ref_inc(phys_of(0), other.as_ptr() as *mut u16, N), 0);
            assert_eq!(rust_page_ref_inc(phys_of(0), ptr, N - 1), 0);
            assert_eq!(rust_page_ref_dec(phys_of(0), other.as_ptr() as *mut u16, N), -1);

            // Below the user base and one-past-the-end pages are refused.
            assert_eq!(rust_page_ref_inc(USER_PHYS_BASE - 1, ptr, N), 0);
            assert_eq!(rust_page_ref_inc(phys_of(N), ptr, N), 0);

            // Normal inc/dec round-trips on a valid page.
            assert_eq!(rust_page_ref_inc(phys_of(5), ptr, N), 1);
            assert_eq!(rust_page_ref_inc(phys_of(5), ptr, N), 2);
            assert_eq!(rust_page_ref_dec(phys_of(5), ptr, N), 1);
            assert_eq!(rust_page_ref_dec(phys_of(5), ptr, N), 0);
            // Decrementing a zero refcount is reported (-2), never underflowed.
            assert_eq!(rust_page_ref_dec(phys_of(5), ptr, N), -2);
            assert_eq!(*ptr.add(5), 0);

            // inc saturates at u16::MAX rather than wrapping to a bogus 0.
            //
            // Read and written through `ptr`, not through `table[..]`. Touching
            // the array directly retags it, which invalidates the raw pointer
            // taken earlier -- and the next FFI call then reads through a tag
            // that no longer exists. Miri named that on 2026-08-24; it is a
            // property of THIS HARNESS, not of the code under test, since the C
            // kernel holds one pointer to its refcount table and never reaches
            // the memory another way. Using one provenance throughout models
            // the caller the FFI actually has.
            *ptr.add(6) = u16::MAX;
            assert_eq!(rust_page_ref_inc(phys_of(6), ptr, N), u16::MAX);
            assert_eq!(*ptr.add(6), u16::MAX, "saturated count persists in the table");
        }
    }

    // The extracted helpers, sampled here and PROVED over the whole input space
    // by `memory_kani_proofs`. Both exist on purpose: the proofs run only under
    // `cargo kani`, so without these a refactor of the helpers would go
    // unexercised by an ordinary `cargo test` and by the gating `rust` job.
    #[test]
    fn refc_index_bounds_the_table() {
        assert_eq!(refc_index(USER_PHYS_BASE, N), Some(0));
        assert_eq!(refc_index(USER_PHYS_BASE + PAGE_SIZE - 1, N), Some(0));
        assert_eq!(refc_index(USER_PHYS_BASE + PAGE_SIZE, N), Some(1));
        assert_eq!(refc_index(phys_of(N - 1), N), Some((N - 1) as usize));
        // Below the pool, and the first address past the end, are both refused.
        assert_eq!(refc_index(USER_PHYS_BASE - 1, N), None);
        assert_eq!(refc_index(0, N), None);
        assert_eq!(refc_index(phys_of(N), N), None);
        // A smaller runtime pool bounds the index even though the table is
        // larger: the E820 map may hand the kernel fewer pages than the
        // compile-time capacity.
        assert_eq!(refc_index(phys_of(9), 10), Some(9));
        assert_eq!(refc_index(phys_of(10), 10), None);
    }

    #[test]
    fn refc_inc_saturates_and_dec_refuses_zero() {
        assert_eq!(refc_inc_value(0), 1);
        assert_eq!(refc_inc_value(u16::MAX - 1), u16::MAX);
        assert_eq!(refc_inc_value(u16::MAX), u16::MAX, "saturates, never wraps to 0");

        assert_eq!(refc_dec_value(0), None, "underflow is refused, not wrapped");
        assert_eq!(refc_dec_value(1), Some(0));
        assert_eq!(refc_dec_value(u16::MAX), Some(u16::MAX - 1));
    }
}


