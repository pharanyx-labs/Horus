//! Tamper-evident audit log MACs.
//!
//! The kernel audit log is a fixed circular buffer. To make it tamper-evident
//! the kernel keeps, keyed by the per-boot secret pepper, two things computed
//! here in safe Rust.
//!
//! Per-entry MAC, binding the entry's absolute sequence number:
//! `mac_i = HMAC(key, LE64(seq_i) || event_i)`. Any in-place edit of a retained
//! entry, or moving it to a different ring slot, is detectable by recomputation
//! — the seq binds its position, so a swap or replay does not verify.
//!
//! Running head, chaining *every* entry ever appended (including those already
//! overwritten in the ring): `head_0 = HMAC(key, DOMAIN)`, then
//! `head_i = HMAC(key, head_{i-1} || mac_i)`. The head is a compact commitment
//! to the whole ordered history; a monitor that records it over time can detect
//! dropped/rewritten events and rollbacks of the sequence counter.
//!
//! Scope (documented honestly): this defends against tampering by code that
//! cannot read `key` — stray writes, logic bugs, a confined task reading the
//! log. A full kernel compromise that can read the pepper can recompute a
//! consistent chain; that is the same accepted limit as the user-database
//! integrity tag. It is an integrity *detector* and defence-in-depth, not a
//! guarantee against an attacker who holds the key.

use crate::sha256::{Sha256Hmac, SHA256_OUT};

/// Length of an audit MAC / chain head, in bytes.
pub const AUDIT_MAC_LEN: usize = SHA256_OUT; // 32

/// Domain separator so the chain IV can never collide with a real entry MAC
/// or with the user-database tag (which is keyed the same).
const AUDIT_CHAIN_DOMAIN: &[u8] = b"horus-audit-chain-v1";

/// `mac_i = HMAC(key, LE64(seq) || event)`.
fn entry_mac(key: &[u8], seq: u64, event: &[u8]) -> [u8; SHA256_OUT] {
    let mut h = Sha256Hmac::new(key);
    h.update(&seq.to_le_bytes());
    h.update(event);
    h.finalize()
}

/// `head_0 = HMAC(key, DOMAIN)`.
fn head_init(key: &[u8]) -> [u8; SHA256_OUT] {
    let mut h = Sha256Hmac::new(key);
    h.update(AUDIT_CHAIN_DOMAIN);
    h.finalize()
}

/// `head_i = HMAC(key, head_{i-1} || mac_i)`.
fn head_extend(key: &[u8], prev: &[u8; SHA256_OUT], mac: &[u8; SHA256_OUT]) -> [u8; SHA256_OUT] {
    let mut h = Sha256Hmac::new(key);
    h.update(prev);
    h.update(mac);
    h.finalize()
}

// ---------------------------------------------------------------------------
// FFI surface (the C kernel owns the ring storage and sequence counter; all of
// the keyed-hash logic lives here).
// ---------------------------------------------------------------------------

/// Initialize the chain head: `head_0 = HMAC(key, DOMAIN)`. Writes 32 bytes.
///
/// # Safety
/// `key` must point to `key_len` readable bytes and `out_head32` to 32 writable
/// bytes; both must outlive the call. Null is rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_chain_init(
    key: *const u8,
    key_len: usize,
    out_head32: *mut u8,
) -> i32 {
    if key.is_null() || out_head32.is_null() {
        return -1;
    }
    let k = core::slice::from_raw_parts(key, key_len);
    let h = head_init(k);
    core::ptr::copy_nonoverlapping(h.as_ptr(), out_head32, AUDIT_MAC_LEN);
    0
}

/// Record one event: compute `mac = HMAC(key, LE64(seq) || event)`, then advance
/// the running head to `HMAC(key, head || mac)`. `head32` is read and updated in
/// place; the per-entry MAC is written to `out_mac32`. Writes 32 bytes to each.
///
/// # Safety
/// `key`/`event` must be valid for their lengths (event may be null iff
/// `event_len == 0`); `head32` and `out_mac32` must each point to 32
/// readable+writable bytes. Null (other than the empty-event case) is rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_chain_record(
    key: *const u8,
    key_len: usize,
    seq: u64,
    event: *const u8,
    event_len: usize,
    head32: *mut u8,
    out_mac32: *mut u8,
) -> i32 {
    if key.is_null() || head32.is_null() || out_mac32.is_null() || (event.is_null() && event_len != 0) {
        return -1;
    }
    let k = core::slice::from_raw_parts(key, key_len);
    let ev = if event_len == 0 { &[][..] } else { core::slice::from_raw_parts(event, event_len) };

    let mac = entry_mac(k, seq, ev);

    let mut head = [0u8; AUDIT_MAC_LEN];
    core::ptr::copy_nonoverlapping(head32 as *const u8, head.as_mut_ptr(), AUDIT_MAC_LEN);
    let new_head = head_extend(k, &head, &mac);

    core::ptr::copy_nonoverlapping(new_head.as_ptr(), head32, AUDIT_MAC_LEN);
    core::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac32, AUDIT_MAC_LEN);
    0
}

/// Recompute a single entry's MAC for verification:
/// `mac = HMAC(key, LE64(seq) || event)`. Writes 32 bytes on success.
///
/// # Safety
/// As `rust_audit_chain_record` for `key`/`event`/`out_mac32`.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_entry_mac(
    key: *const u8,
    key_len: usize,
    seq: u64,
    event: *const u8,
    event_len: usize,
    out_mac32: *mut u8,
) -> i32 {
    if key.is_null() || out_mac32.is_null() || (event.is_null() && event_len != 0) {
        return -1;
    }
    let k = core::slice::from_raw_parts(key, key_len);
    let ev = if event_len == 0 { &[][..] } else { core::slice::from_raw_parts(event, event_len) };
    let mac = entry_mac(k, seq, ev);
    core::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac32, AUDIT_MAC_LEN);
    0
}

/// Constant-time comparison of two 32-byte MACs. Returns 1 if equal, else 0.
/// Used by the kernel's audit-verify path so a mismatch search does not leak a
/// timing oracle on where the chain diverged.
///
/// # Safety
/// `a32` and `b32` must each point to 32 readable bytes. Null returns 0.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_mac_eq(a32: *const u8, b32: *const u8) -> i32 {
    if a32.is_null() || b32.is_null() {
        return 0;
    }
    let a = core::slice::from_raw_parts(a32, AUDIT_MAC_LEN);
    let b = core::slice::from_raw_parts(b32, AUDIT_MAC_LEN);
    let mut diff = 0u8;
    for i in 0..AUDIT_MAC_LEN {
        diff |= a[i] ^ b[i];
    }
    (diff == 0) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"per-boot-pepper-16";

    #[test]
    fn entry_mac_is_deterministic() {
        let a = entry_mac(KEY, 7, b"login success");
        let b = entry_mac(KEY, 7, b"login success");
        assert_eq!(a, b);
    }

    #[test]
    fn entry_mac_binds_seq_and_content() {
        let base = entry_mac(KEY, 7, b"login success");
        // Different sequence number -> different MAC (defeats slot swap/replay).
        assert_ne!(base, entry_mac(KEY, 8, b"login success"));
        // Different event bytes -> different MAC (defeats in-place edit).
        assert_ne!(base, entry_mac(KEY, 7, b"login failure"));
        // Different key -> different MAC.
        assert_ne!(base, entry_mac(b"other-key", 7, b"login success"));
    }

    #[test]
    fn head_init_is_key_separated() {
        assert_ne!(head_init(KEY), head_init(b"another-key"));
        // The IV is not just HMAC(key, "") — domain separation is applied.
        let mut h = Sha256Hmac::new(KEY);
        h.update(b"");
        assert_ne!(head_init(KEY), h.finalize());
    }

    #[test]
    fn head_chain_is_order_sensitive() {
        let m1 = entry_mac(KEY, 0, b"a");
        let m2 = entry_mac(KEY, 1, b"b");
        let h0 = head_init(KEY);
        let forward = head_extend(KEY, &head_extend(KEY, &h0, &m1), &m2);
        let swapped = head_extend(KEY, &head_extend(KEY, &h0, &m2), &m1);
        assert_ne!(forward, swapped, "reordering events must change the head");
    }

    #[test]
    fn full_chain_records_and_verifies() {
        // Drive the FFI exactly as the kernel does: init, then record N events,
        // keeping per-entry MACs; then verify each recomputes.
        let events: [&[u8]; 3] = [b"cap mint", b"login success", b"sudo success"];
        let mut head = [0u8; 32];
        unsafe {
            assert_eq!(rust_audit_chain_init(KEY.as_ptr(), KEY.len(), head.as_mut_ptr()), 0);
        }
        let mut macs = [[0u8; 32]; 3];
        for (i, ev) in events.iter().enumerate() {
            let mut mac = [0u8; 32];
            unsafe {
                assert_eq!(
                    rust_audit_chain_record(
                        KEY.as_ptr(), KEY.len(),
                        i as u64,
                        ev.as_ptr(), ev.len(),
                        head.as_mut_ptr(), mac.as_mut_ptr(),
                    ),
                    0
                );
            }
            macs[i] = mac;
        }
        // Every retained entry re-verifies against its stored MAC.
        for (i, ev) in events.iter().enumerate() {
            let mut recomputed = [0u8; 32];
            unsafe {
                rust_audit_entry_mac(KEY.as_ptr(), KEY.len(), i as u64, ev.as_ptr(), ev.len(), recomputed.as_mut_ptr());
                assert_eq!(rust_audit_mac_eq(recomputed.as_ptr(), macs[i].as_ptr()), 1);
            }
        }
        // Tamper with the middle event -> its MAC no longer verifies.
        let mut tampered = [0u8; 32];
        unsafe {
            rust_audit_entry_mac(KEY.as_ptr(), KEY.len(), 1, b"login FAILURE".as_ptr(), 13, tampered.as_mut_ptr());
            assert_eq!(rust_audit_mac_eq(tampered.as_ptr(), macs[1].as_ptr()), 0);
        }
    }

    #[test]
    fn mac_eq_is_correct() {
        let a = entry_mac(KEY, 1, b"x");
        let b = a;
        let mut c = a;
        c[31] ^= 1;
        unsafe {
            assert_eq!(rust_audit_mac_eq(a.as_ptr(), b.as_ptr()), 1);
            assert_eq!(rust_audit_mac_eq(a.as_ptr(), c.as_ptr()), 0);
        }
    }

    #[test]
    fn ffi_rejects_null() {
        let mut out = [0u8; 32];
        unsafe {
            assert_eq!(rust_audit_chain_init(core::ptr::null(), 0, out.as_mut_ptr()), -1);
            assert_eq!(rust_audit_chain_init(KEY.as_ptr(), KEY.len(), core::ptr::null_mut()), -1);
            assert_eq!(rust_audit_mac_eq(core::ptr::null(), out.as_ptr()), 0);
        }
    }
}
