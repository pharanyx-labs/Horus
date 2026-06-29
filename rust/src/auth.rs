//! Authentication / sudo throttling and privilege policy (safe Rust).
//!
//! This module is the single source of truth for the kernel's login and `sudo`
//! lockout arithmetic and for the privilege a `sudo`-spawned task is granted.
//! The logic previously lived as hand-inlined constants and counter arithmetic
//! (increment, compare against 5, add an 8000-tick lockout) duplicated across
//! the `SYS_AUTH` and `SYS_SUDO` handlers in `syscall.c`; centralising it here
//! makes the policy auditable and unit-tested, and lets the kernel call one
//! vetted implementation from both paths.
//!
//! Two layers of throttling. Per-account: after `MAX_AUTH_FAILS` failures an
//! account is locked for `LOCKOUT_TICKS` (counters live in the C `user_account`;
//! this module owns only the arithmetic that updates them). Global anti-spray:
//! a single kernel-wide failure counter that slows an attacker cycling through
//! many usernames (which would otherwise never trip any single account's
//! lockout) — more permissive than the per-account limit, but it imposes a
//! short cooldown once tripped.

use core::sync::atomic::{AtomicBool, Ordering};

/// Failed attempts against one account before it is locked.
pub const MAX_AUTH_FAILS: u32 = 5;
/// Per-account lockout duration, in scheduler ticks.
pub const LOCKOUT_TICKS: u64 = 8000;

/// Global failures (across all accounts) before a short kernel-wide cooldown.
pub const GLOBAL_MAX_FAILS: u32 = 12;
/// Global cooldown duration, in scheduler ticks (shorter than per-account so a
/// spray is slowed without locking every legitimate user out for long).
pub const GLOBAL_LOCKOUT_TICKS: u64 = 2000;

// ---------------------------------------------------------------------------
// Capability-right bits (mirror of src/include/kernel.h). Kept in sync by the
// least-privilege test below being explicit about the expected mask.
// ---------------------------------------------------------------------------
const CAP_RIGHT_READ: u32 = 1 << 0;
const CAP_RIGHT_WRITE: u32 = 1 << 1;
const CAP_RIGHT_EXEC: u32 = 1 << 2;

/// Rights a `sudo`-spawned task should receive on its memory **frame**
/// capability (cspace slot 3). The handler previously stamped this slot with
/// `CAP_RIGHT_ALL` (0xFFFFFFFF); a frame only needs read/write/execute, so the
/// mint/revoke/grant/audit bits were ambient authority with no legitimate use
/// on a frame. Returning the minimal mask is defence-in-depth (least
/// privilege) with no loss of function.
#[no_mangle]
pub extern "C" fn rust_sudo_frame_rights() -> u32 {
    CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC
}

/// True if an account whose lockout deadline is `lockout_until` is still locked
/// at tick `now`.
#[no_mangle]
pub extern "C" fn rust_auth_is_locked(lockout_until: u64, now: u64) -> bool {
    lockout_until > now
}

/// Apply one failed attempt to a per-account counter.
///
/// Writes the new failure count through `out_count` and, when the threshold is
/// reached, the new lockout deadline through `out_lockout_until` (and resets the
/// count to 0). A returned lockout of 0 means "leave the account's existing
/// deadline unchanged" — the caller only assigns it when non-zero.
///
/// # Safety
/// `out_count` and `out_lockout_until` must each be null or a valid, aligned,
/// writable pointer for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_auth_on_failure(
    fail_count: u32,
    now: u64,
    out_count: *mut u32,
    out_lockout_until: *mut u64,
) {
    let mut count = fail_count.saturating_add(1);
    let mut lockout: u64 = 0;
    if count >= MAX_AUTH_FAILS {
        lockout = now.saturating_add(LOCKOUT_TICKS);
        count = 0;
    }
    if !out_count.is_null() {
        *out_count = count;
    }
    if !out_lockout_until.is_null() {
        *out_lockout_until = lockout;
    }
}

// ---------------------------------------------------------------------------
// Global anti-spray throttle: a tiny spinlock-guarded counter, same pattern as
// the RNG pool lock. Single-core/cooperative today; sound under future SMP.
// ---------------------------------------------------------------------------
struct GlobalThrottle {
    fails: u32,
    lockout_until: u64,
}

static THROTTLE_LOCK: AtomicBool = AtomicBool::new(false);
static mut THROTTLE: GlobalThrottle = GlobalThrottle {
    fails: 0,
    lockout_until: 0,
};

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        THROTTLE_LOCK.store(false, Ordering::Release);
    }
}
fn lock() -> Guard {
    while THROTTLE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    Guard
}
fn with_throttle<R>(f: impl FnOnce(&mut GlobalThrottle) -> R) -> R {
    let _g = lock();
    // SAFETY: exclusive access is held via THROTTLE_LOCK for the closure.
    let t = unsafe { &mut *core::ptr::addr_of_mut!(THROTTLE) };
    f(t)
}

/// True if the global anti-spray cooldown is active at tick `now`.
#[no_mangle]
pub extern "C" fn rust_auth_global_locked(now: u64) -> bool {
    with_throttle(|t| t.lockout_until > now)
}

/// Record a global failed attempt; opens a kernel-wide cooldown once the
/// threshold is crossed (and resets the counter).
#[no_mangle]
pub extern "C" fn rust_auth_global_on_failure(now: u64) {
    with_throttle(|t| {
        t.fails = t.fails.saturating_add(1);
        if t.fails >= GLOBAL_MAX_FAILS {
            t.lockout_until = now.saturating_add(GLOBAL_LOCKOUT_TICKS);
            t.fails = 0;
        }
    });
}

/// Clear the global failure counter after any successful authentication.
#[no_mangle]
pub extern "C" fn rust_auth_global_on_success() {
    with_throttle(|t| {
        t.fails = 0;
        t.lockout_until = 0;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_rights_are_minimal() {
        // read|write|exec only — no mint/revoke/grant/audit/ALL.
        assert_eq!(rust_sudo_frame_rights(), 0b111);
    }

    #[test]
    fn lock_predicate() {
        assert!(rust_auth_is_locked(100, 50));
        assert!(!rust_auth_is_locked(100, 100));
        assert!(!rust_auth_is_locked(100, 150));
        assert!(!rust_auth_is_locked(0, 0));
    }

    #[test]
    fn failures_below_threshold_do_not_lock() {
        let mut count = 0u32;
        let mut until = 0u64;
        for expected in 1..MAX_AUTH_FAILS {
            unsafe { rust_auth_on_failure(count, 1000, &mut count, &mut until) };
            assert_eq!(count, expected);
            assert_eq!(until, 0, "no lockout before the threshold");
        }
    }

    #[test]
    fn threshold_failure_locks_and_resets() {
        // Arrive at the threshold: count goes 4 -> (5 -> reset 0) with a lockout.
        let mut count = MAX_AUTH_FAILS - 1;
        let mut until = 0u64;
        unsafe { rust_auth_on_failure(count, 1000, &mut count, &mut until) };
        assert_eq!(count, 0, "counter resets when the lockout opens");
        assert_eq!(until, 1000 + LOCKOUT_TICKS);
    }

    #[test]
    fn on_failure_saturates() {
        let mut count = u32::MAX;
        let mut until = 0u64;
        // Must not panic on overflow; u32::MAX+1 saturates, crosses threshold.
        unsafe { rust_auth_on_failure(count, u64::MAX, &mut count, &mut until) };
        assert_eq!(count, 0);
        assert_eq!(until, u64::MAX); // saturating_add
    }

    #[test]
    fn global_throttle_trips_and_clears() {
        rust_auth_global_on_success(); // start clean
        assert!(!rust_auth_global_locked(0));
        for _ in 0..(GLOBAL_MAX_FAILS - 1) {
            rust_auth_global_on_failure(500);
        }
        assert!(!rust_auth_global_locked(500), "not yet at the global threshold");
        rust_auth_global_on_failure(500); // crosses it
        assert!(rust_auth_global_locked(500));
        assert!(rust_auth_global_locked(500 + GLOBAL_LOCKOUT_TICKS - 1));
        assert!(!rust_auth_global_locked(500 + GLOBAL_LOCKOUT_TICKS));
        // A success anywhere clears the cooldown immediately.
        rust_auth_global_on_failure(10_000);
        rust_auth_global_on_success();
        assert!(!rust_auth_global_locked(10_000));
    }
}
