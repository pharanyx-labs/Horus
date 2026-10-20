//! Scheduling-context arithmetic (safe Rust): how CPU share moves between
//! contexts (docs/design/scheduler.md 3.1, step 4a).
//!
//! A scheduling context holds a share of one CPU in parts per million. A split
//! moves share from a parent to a child, and destroying the child moves it back.
//! Nothing else creates share, so the contexts of one CPU never hold more than
//! its root's million: that is the property S152 rests on, and it is stated
//! here, where the Kani proofs below can hold it, rather than in the C that
//! calls it.
//!
//! The C side keeps the contexts and their locking; it passes numbers in and
//! takes numbers out. Nothing it passes is trusted: a parent share above a whole
//! CPU, a zero budget, a budget above its period or a period outside the
//! supported range is refused here whatever the caller checked first.

/// A whole CPU.
pub const PPM_WHOLE: u32 = 1_000_000;
/// The shortest period, one tick. Deadline timers (scheduler design 3.4, steps
/// 3b and 3c) would allow a shorter one; it stays a tick until that is decided.
pub const MIN_PERIOD_US: u32 = 10_000;
/// The longest period, 10 s.
pub const MAX_PERIOD_US: u32 = 10_000_000;

/// The split was made.
pub const SPLIT_OK: i32 = 0;
/// The request is malformed: a zero budget, a budget above its period, a period
/// out of range, a parent share above a whole CPU, or a null out-pointer.
pub const SPLIT_INVAL: i32 = -1;
/// The parent holds less share than the child needs.
pub const SPLIT_NO_SHARE: i32 = -2;

/// The share a child needs to run `budget_us` every `period_us`, rounded UP, so
/// the budget the child is then given (its share of its period, rounded down)
/// is never less than it asked for. `None` if the request is malformed.
fn child_share(budget_us: u32, period_us: u32) -> Option<u32> {
    if !(MIN_PERIOD_US..=MAX_PERIOD_US).contains(&period_us) {
        return None;
    }
    if budget_us == 0 || budget_us > period_us {
        return None;
    }
    // budget <= period <= 1e7, so the product is below 1e13 and fits; the
    // quotient is at most PPM_WHOLE because budget <= period.
    let num = (budget_us as u64) * (PPM_WHOLE as u64);
    let share = num.div_ceil(period_us as u64);
    u32::try_from(share).ok()
}

/// The split itself, given the child's share however it was computed. Every
/// property S152 needs is checked HERE, by multiplication, so a share computed
/// wrongly (by `child_share`, or by any future caller) can only be refused,
/// never create time: the child's share must be some, must buy at least the
/// budget asked for over its period, and must not exceed what the parent holds.
/// This is what the Kani proof covers, for every share whatever, which is why it
/// needs no division and finishes in seconds.
fn split_with_share(
    parent_share: u32,
    budget_us: u32,
    period_us: u32,
    share: u32,
) -> Result<(u32, u32), i32> {
    if parent_share > PPM_WHOLE || !(MIN_PERIOD_US..=MAX_PERIOD_US).contains(&period_us) {
        return Err(SPLIT_INVAL);
    }
    if budget_us == 0 || budget_us > period_us || share == 0 || share > PPM_WHOLE {
        return Err(SPLIT_INVAL);
    }
    // share * period >= budget * 1e6, i.e. the share buys at least the budget.
    // Both products are below 2^44, so neither wraps.
    if (share as u64) * (period_us as u64) < (budget_us as u64) * (PPM_WHOLE as u64) {
        return Err(SPLIT_INVAL);
    }
    if share > parent_share {
        return Err(SPLIT_NO_SHARE);
    }
    Ok((parent_share - share, share))
}

/// Split a child of `budget_us` every `period_us` off a parent holding
/// `parent_share`. On `SPLIT_OK`, writes the parent's share after the split to
/// `*out_parent` and the child's to `*out_child`; on any refusal writes nothing.
///
/// # Safety
/// `out_parent` and `out_child` must each be null or point to a writable `u32`.
/// Null is refused (`SPLIT_INVAL`) rather than dereferenced. The numbers are not
/// trusted: each is range-checked here.
#[no_mangle]
pub unsafe extern "C" fn rust_sc_split(
    parent_share: u32,
    budget_us: u32,
    period_us: u32,
    out_parent: *mut u32,
    out_child: *mut u32,
) -> i32 {
    if out_parent.is_null() || out_child.is_null() {
        return SPLIT_INVAL;
    }
    let share = match child_share(budget_us, period_us) {
        Some(c) => c,
        None => return SPLIT_INVAL,
    };
    match split_with_share(parent_share, budget_us, period_us, share) {
        Ok((p, c)) => {
            *out_parent = p;
            *out_child = c;
            SPLIT_OK
        }
        Err(e) => e,
    }
}

/// Give a destroyed child's share back to its parent. Saturates at a whole CPU,
/// which by S152 a correct caller never reaches: a sum above it would mean share
/// had been created somewhere, and refusing to create more here keeps the bound
/// even then.
#[no_mangle]
pub extern "C" fn rust_sc_reclaim(parent_share: u32, child_share: u32) -> u32 {
    match parent_share.checked_add(child_share) {
        Some(s) if s <= PPM_WHOLE => s,
        _ => PPM_WHOLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(parent: u32, budget: u32, period: u32) -> (i32, u32, u32) {
        let (mut p, mut c) = (u32::MAX, u32::MAX);
        let rc = unsafe { rust_sc_split(parent, budget, period, &mut p, &mut c) };
        (rc, p, c)
    }

    #[test]
    fn a_fifth_of_a_whole_cpu() {
        assert_eq!(split(PPM_WHOLE, 20_000, 100_000), (SPLIT_OK, 800_000, 200_000));
    }

    #[test]
    fn the_child_share_is_rounded_up() {
        // 1 us every 3 s needs 0.333.. ppm: one whole part, never zero.
        let (rc, p, c) = split(10, 1, 3_000_000);
        assert_eq!((rc, p, c), (SPLIT_OK, 9, 1));
    }

    #[test]
    fn a_parent_cannot_give_more_than_it_holds() {
        assert_eq!(split(199_999, 20_000, 100_000), (SPLIT_NO_SHARE, u32::MAX, u32::MAX));
    }

    #[test]
    fn malformed_requests_are_refused_and_write_nothing() {
        for (budget, period) in [(0, 100_000), (100_001, 100_000), (1, 9_999), (1, 10_000_001)] {
            assert_eq!(split(PPM_WHOLE, budget, period), (SPLIT_INVAL, u32::MAX, u32::MAX));
        }
        assert_eq!(split(PPM_WHOLE + 1, 1, 100_000), (SPLIT_INVAL, u32::MAX, u32::MAX));
        let mut c = 0;
        let rc = unsafe { rust_sc_split(PPM_WHOLE, 1, 100_000, core::ptr::null_mut(), &mut c) };
        assert_eq!(rc, SPLIT_INVAL);
    }

    #[test]
    fn a_wrong_share_is_refused_not_believed() {
        // 20 ms every 100 ms needs 200000 ppm; 199999 does not buy it.
        assert_eq!(split_with_share(PPM_WHOLE, 20_000, 100_000, 199_999), Err(SPLIT_INVAL));
        assert_eq!(split_with_share(PPM_WHOLE, 20_000, 100_000, 0), Err(SPLIT_INVAL));
        assert_eq!(split_with_share(PPM_WHOLE, 20_000, 100_000, 200_000), Ok((800_000, 200_000)));
    }

    #[test]
    fn reclaim_restores_the_split() {
        let (_, p, c) = split(PPM_WHOLE, 33_333, 100_000);
        assert_eq!(rust_sc_reclaim(p, c), PPM_WHOLE);
        assert_eq!(rust_sc_reclaim(PPM_WHOLE, 1), PPM_WHOLE);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// A split never creates time (S152): for ANY share the division could have
    /// produced, a split that is made moves share from the parent to the child
    /// and makes none (the two after sum to the parent before), gives the child
    /// some share and no more than it is given, starts from at most a whole CPU,
    /// and gives the child a share that buys at least the budget it asked for.
    /// The share is free here, so the proof holds whatever `child_share` returns.
    #[kani::proof]
    fn a_split_never_creates_time() {
        let parent: u32 = kani::any();
        let budget: u32 = kani::any();
        let period: u32 = kani::any();
        let share: u32 = kani::any();
        if let Ok((p, c)) = split_with_share(parent, budget, period, share) {
            assert!(p as u64 + c as u64 == parent as u64, "a split moves share, never makes it");
            assert!(c == share && c > 0, "the child is given the share, and some");
            assert!(parent <= PPM_WHOLE, "a split only ever starts from at most a whole CPU");
            assert!(
                (c as u64) * (period as u64) >= (budget as u64) * (PPM_WHOLE as u64),
                "the child's share buys at least the budget it asked for"
            );
        }
    }

    /// Reclaiming never takes a parent above a whole CPU, and gives back exactly
    /// what a split took whenever the two could have come from one.
    #[kani::proof]
    fn reclaim_never_exceeds_a_whole_cpu() {
        let parent: u32 = kani::any();
        let child: u32 = kani::any();
        let r = rust_sc_reclaim(parent, child);
        assert!(r <= PPM_WHOLE);
        if parent as u64 + child as u64 <= PPM_WHOLE as u64 {
            assert!(r == parent + child);
        }
    }
}
