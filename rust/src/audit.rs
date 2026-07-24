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

use crate::sha256::{sha256, Sha256, Sha256Hmac, SHA256_OUT};

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

// ===========================================================================
// Forward-secure (forward-integrity) layer.
//
// The single-key scheme above is tamper-EVIDENT but not tamper-PROOF: an
// attacker who reads the (persistent) key can recompute a self-consistent chain
// and rewrite history. Forward security fixes exactly that, for all history
// *prior to* a compromise:
//
//   K_0                         = SHA256(FS_KEY_DOMAIN || pepper)   (dedicated;
//                                 never the shared pepper, so ratcheting it does
//                                 not disturb the password hash / user-DB tag)
//   mac_i                       = HMAC(K_i, LE64(seq_i) || event_i)
//   head_i                      = HMAC(K_i, head_{i-1} || mac_i)
//   K_{i+1}                     = SHA256(RATCHET_DOMAIN || K_i)   then ERASE K_i
//
// The ratchet is one-way, and each K_i is overwritten in place the instant the
// next entry is recorded. A kernel compromised at time t holds only K_t (and can
// derive K_{t+1}, ...), but CANNOT recover any K_i for i < t, so it cannot forge
// or alter the MAC or the head of any entry committed before t. History before
// the compromise is unforgeable — verified by an external monitor that has been
// recording the head. (Entries logged *after* the compromise, and rollback of
// the whole machine, remain outside any in-domain scheme's reach — that is the
// honest ceiling for a self-hosting kernel; it needs an external append-only
// anchor such as a TPM NV monotonic counter or a remote WORM log.)
// ===========================================================================

/// Domain-separated derivation of the dedicated forward-secure audit key from
/// the shared per-boot pepper. Keeps the audit ratchet off the pepper itself.
const AUDIT_FS_KEY_DOMAIN: &[u8] = b"horus-audit-fs-key-v1";
/// Domain separator for the one-way key ratchet.
const AUDIT_FS_RATCHET_DOMAIN: &[u8] = b"horus-audit-fs-ratchet-v1";
/// Domain separator for the unkeyed public integrity chain (below).
const AUDIT_PUB_DOMAIN: &[u8] = b"horus-audit-pub-v1";

/// Overwrite a key buffer so the old key cannot be recovered. `write_volatile`
/// plus a compiler fence stops the store from being optimized away as dead.
#[inline]
fn erase_key(k: &mut [u8; SHA256_OUT]) {
    for b in k.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0u8) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// One-way key ratchet: `K_{i+1} = SHA256(RATCHET_DOMAIN || K_i)`.
fn ratchet(key: &[u8; SHA256_OUT]) -> [u8; SHA256_OUT] {
    let mut h = Sha256::new();
    h.update(AUDIT_FS_RATCHET_DOMAIN);
    h.update(key);
    h.finalize()
}

/// Derive `K_0 = SHA256(FS_KEY_DOMAIN || pepper)` for the forward-secure chain.
fn fs_genesis_key(pepper: &[u8]) -> [u8; SHA256_OUT] {
    let mut h = Sha256::new();
    h.update(AUDIT_FS_KEY_DOMAIN);
    h.update(pepper);
    h.finalize()
}

/// FFI: initialise the forward-secure chain. Derives the dedicated genesis key
/// `K_0` from the pepper into `out_key32` and the initial head `head_0 =
/// HMAC(K_0, DOMAIN)` into `out_head32`. The C kernel holds the evolving key in
/// `out_key32` from here on and never keeps the pepper-derived `K_0` anywhere
/// else — the first `rust_audit_fs_record` ratchets it away.
///
/// # Safety
/// `pepper` must be readable for `pepper_len`; `out_key32`/`out_head32` must each
/// point to 32 writable bytes. Null is rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_fs_genesis(
    pepper: *const u8,
    pepper_len: usize,
    out_key32: *mut u8,
    out_head32: *mut u8,
) -> i32 {
    if pepper.is_null() || out_key32.is_null() || out_head32.is_null() {
        return -1;
    }
    let p = core::slice::from_raw_parts(pepper, pepper_len);
    let mut k0 = fs_genesis_key(p);
    let head0 = head_init(&k0);
    core::ptr::copy_nonoverlapping(k0.as_ptr(), out_key32, SHA256_OUT);
    core::ptr::copy_nonoverlapping(head0.as_ptr(), out_head32, SHA256_OUT);
    erase_key(&mut k0); // no lingering stack copy of the genesis key
    0
}

/// FFI: record one event under the current key `K_i` (in `key32`), then ratchet
/// the key forward and ERASE `K_i` in place. Computes
/// `mac = HMAC(K_i, LE64(seq) || event)`, advances `head32` to
/// `HMAC(K_i, head || mac)`, writes `mac` to `out_mac32`, and overwrites `key32`
/// with `K_{i+1} = SHA256(RATCHET_DOMAIN || K_i)`. After it returns, `K_i` exists
/// nowhere — the entry it authenticated is forward-secure.
///
/// # Safety
/// `key32`/`head32`/`out_mac32` must each point to 32 readable+writable bytes;
/// `event` must be valid for `event_len` (may be null iff `event_len == 0`).
#[no_mangle]
pub unsafe extern "C" fn rust_audit_fs_record(
    key32: *mut u8,
    seq: u64,
    event: *const u8,
    event_len: usize,
    head32: *mut u8,
    out_mac32: *mut u8,
) -> i32 {
    if key32.is_null() || head32.is_null() || out_mac32.is_null() || (event.is_null() && event_len != 0) {
        return -1;
    }
    let ev = if event_len == 0 { &[][..] } else { core::slice::from_raw_parts(event, event_len) };

    // Copy the current key out so we control its lifetime and erase it.
    let mut k = [0u8; SHA256_OUT];
    core::ptr::copy_nonoverlapping(key32 as *const u8, k.as_mut_ptr(), SHA256_OUT);

    let mac = entry_mac(&k, seq, ev);

    let mut head = [0u8; SHA256_OUT];
    core::ptr::copy_nonoverlapping(head32 as *const u8, head.as_mut_ptr(), SHA256_OUT);
    let new_head = head_extend(&k, &head, &mac);

    // Ratchet, publish the evolved key, and erase every copy of K_i.
    let mut k_next = ratchet(&k);
    core::ptr::copy_nonoverlapping(k_next.as_ptr(), key32, SHA256_OUT);
    erase_key(&mut k);
    erase_key(&mut k_next);

    core::ptr::copy_nonoverlapping(new_head.as_ptr(), head32, SHA256_OUT);
    core::ptr::copy_nonoverlapping(mac.as_ptr(), out_mac32, SHA256_OUT);
    0
}

// --- Unkeyed public integrity chain -----------------------------------------
//
// A running, UNKEYED hash over `(seq, mac)` of every entry:
//   pub_0   = SHA256(PUB_DOMAIN)
//   pub_i   = SHA256(pub_{i-1} || LE64(seq_i) || mac_i)
// It carries no secret and is fully recomputable, so — unlike the keyed chain,
// whose keys are erased — the kernel can still self-check the *retained* window
// against accidental corruption after erasure (a stray write flips a stored
// (seq, mac), and the recomputed window no longer folds to the stored head). It
// is a corruption detector, not an anti-forgery mechanism; the keyed
// forward-secure MACs above are what an attacker cannot forge.

/// FFI: `pub_0 = SHA256(PUB_DOMAIN)`. Writes 32 bytes.
///
/// # Safety
/// `out32` must point to 32 writable bytes. Null is rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_pub_init(out32: *mut u8) -> i32 {
    if out32.is_null() {
        return -1;
    }
    let h = sha256(AUDIT_PUB_DOMAIN);
    core::ptr::copy_nonoverlapping(h.as_ptr(), out32, SHA256_OUT);
    0
}

/// FFI: `out = SHA256(prev || LE64(seq) || mac)`. `prev` and `out` may alias.
/// Writes 32 bytes.
///
/// # Safety
/// `prev32`/`mac32` must be readable for 32 bytes and `out32` writable for 32;
/// null is rejected.
#[no_mangle]
pub unsafe extern "C" fn rust_audit_pub_extend(
    prev32: *const u8,
    seq: u64,
    mac32: *const u8,
    out32: *mut u8,
) -> i32 {
    if prev32.is_null() || mac32.is_null() || out32.is_null() {
        return -1;
    }
    let prev = core::slice::from_raw_parts(prev32, SHA256_OUT);
    let mac = core::slice::from_raw_parts(mac32, SHA256_OUT);
    let mut h = Sha256::new();
    h.update(prev);
    h.update(&seq.to_le_bytes());
    h.update(mac);
    let out = h.finalize();
    core::ptr::copy_nonoverlapping(out.as_ptr(), out32, SHA256_OUT);
    0
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

    const PEPPER: &[u8] = b"per-boot-pepper-16";

    #[test]
    fn fs_genesis_is_dedicated_and_deterministic() {
        let mut k = [0u8; 32];
        let mut h = [0u8; 32];
        unsafe {
            assert_eq!(rust_audit_fs_genesis(PEPPER.as_ptr(), PEPPER.len(), k.as_mut_ptr(), h.as_mut_ptr()), 0);
        }
        // The genesis key is a dedicated derivation, NOT the raw pepper — so
        // ratcheting/erasing it never disturbs the password hash / user-DB tag.
        assert_ne!(&k[..PEPPER.len()], PEPPER);
        assert_eq!(k, fs_genesis_key(PEPPER));
        assert_eq!(h, head_init(&fs_genesis_key(PEPPER)));
    }

    #[test]
    fn fs_record_ratchets_and_uses_a_fresh_key_per_entry() {
        let mut key = [0u8; 32];
        let mut head = [0u8; 32];
        unsafe {
            rust_audit_fs_genesis(PEPPER.as_ptr(), PEPPER.len(), key.as_mut_ptr(), head.as_mut_ptr());
        }
        let k0 = fs_genesis_key(PEPPER);
        assert_eq!(key, k0, "the live key starts at K_0");

        // Record the SAME event twice; because the key ratchets, the two MACs
        // must differ — proof that entry i+1 is authenticated under a fresh key.
        let ev = b"login success";
        let mut mac_a = [0u8; 32];
        let mut mac_b = [0u8; 32];
        unsafe {
            rust_audit_fs_record(key.as_mut_ptr(), 0, ev.as_ptr(), ev.len(), head.as_mut_ptr(), mac_a.as_mut_ptr());
            // After one record the live key must have advanced (K_0 erased).
            assert_eq!(key, ratchet(&k0), "the live key is now K_1");
            assert_ne!(key, k0, "K_0 no longer lives in the key buffer");
            rust_audit_fs_record(key.as_mut_ptr(), 1, ev.as_ptr(), ev.len(), head.as_mut_ptr(), mac_b.as_mut_ptr());
        }
        assert_ne!(mac_a, mac_b, "same event under a ratcheted key yields a distinct MAC");
    }

    /// The property that makes the log forward-secure: an external verifier who
    /// knows only the genesis key K_0 (established out of band at boot) can
    /// re-derive every K_i by ratcheting and confirm each recorded MAC — while
    /// the running kernel, having erased K_0..K_{t-1}, holds only K_t. Thus a
    /// kernel compromised at time t cannot recompute any earlier entry's MAC.
    #[test]
    fn fs_recorded_macs_verify_by_ratcheting_the_genesis_key() {
        let mut key = [0u8; 32];
        let mut head = [0u8; 32];
        unsafe {
            rust_audit_fs_genesis(PEPPER.as_ptr(), PEPPER.len(), key.as_mut_ptr(), head.as_mut_ptr());
        }
        let events: [&[u8]; 4] = [b"cap mint", b"login success", b"sudo success", b"cap revoke"];
        let mut macs = [[0u8; 32]; 4];
        for (i, ev) in events.iter().enumerate() {
            unsafe {
                rust_audit_fs_record(key.as_mut_ptr(), i as u64, ev.as_ptr(), ev.len(), head.as_mut_ptr(), macs[i].as_mut_ptr());
            }
        }

        // External verification: re-derive K_i from K_0 and recompute each MAC.
        let mut k = fs_genesis_key(PEPPER);
        for (i, ev) in events.iter().enumerate() {
            let expect = entry_mac(&k, i as u64, ev);
            assert_eq!(expect, macs[i], "entry {i} must verify under its re-derived key K_i");
            k = ratchet(&k);
        }
        // The live kernel key is exactly K_n (the genesis ratcheted n times).
        assert_eq!(key, k, "the kernel retains only the current key K_n");
        // Altering a past event's bytes fails verification under its K_i.
        let k1 = ratchet(&fs_genesis_key(PEPPER));
        assert_ne!(entry_mac(&k1, 1, b"login FAILURE"), macs[1]);
    }

    #[test]
    fn pub_chain_is_recomputable_and_order_sensitive() {
        let mut p0 = [0u8; 32];
        unsafe { assert_eq!(rust_audit_pub_init(p0.as_mut_ptr()), 0); }
        assert_eq!(p0, sha256(AUDIT_PUB_DOMAIN));

        let m1 = entry_mac(KEY, 0, b"a");
        let m2 = entry_mac(KEY, 1, b"b");
        let mut fwd_a = [0u8; 32];
        let mut fwd = [0u8; 32];
        let mut swp_a = [0u8; 32];
        let mut swp = [0u8; 32];
        unsafe {
            // forward: fold (0,m1) then (1,m2)
            rust_audit_pub_extend(p0.as_ptr(), 0, m1.as_ptr(), fwd_a.as_mut_ptr());
            rust_audit_pub_extend(fwd_a.as_ptr(), 1, m2.as_ptr(), fwd.as_mut_ptr());
            // swapped order
            rust_audit_pub_extend(p0.as_ptr(), 1, m2.as_ptr(), swp_a.as_mut_ptr());
            rust_audit_pub_extend(swp_a.as_ptr(), 0, m1.as_ptr(), swp.as_mut_ptr());
        }
        assert_ne!(fwd, swp, "reordering (seq,mac) pairs must change the public head");
        // Fully recomputable (no key), so the kernel can self-check the window.
        let mut again = [0u8; 32];
        unsafe {
            rust_audit_pub_extend(p0.as_ptr(), 0, m1.as_ptr(), again.as_mut_ptr());
        }
        assert_eq!(again, fwd_a);
    }

    #[test]
    fn fs_ffi_rejects_null() {
        let mut a = [0u8; 32];
        unsafe {
            assert_eq!(rust_audit_fs_genesis(core::ptr::null(), 0, a.as_mut_ptr(), a.as_mut_ptr()), -1);
            assert_eq!(rust_audit_fs_record(core::ptr::null_mut(), 0, core::ptr::null(), 0, a.as_mut_ptr(), a.as_mut_ptr()), -1);
            assert_eq!(rust_audit_pub_init(core::ptr::null_mut()), -1);
            assert_eq!(rust_audit_pub_extend(core::ptr::null(), 0, a.as_ptr(), a.as_mut_ptr()), -1);
        }
    }
}
