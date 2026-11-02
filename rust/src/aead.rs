//! Authenticated encryption for the kernel's encryption-at-rest (storage) layer.
//!
//! Construction: **Encrypt-then-MAC** composing two primitives that already
//! live in this crate and are validated against their RFC known-answer vectors:
//!   * confidentiality — ChaCha20 (RFC 8439), from `crate::rng`,
//!   * integrity       — HMAC-SHA256 (RFC 2104), from `crate::sha256`.
//!
//! This deliberately introduces **no new primitive cryptography**: it is the
//! standard, provably-secure generic composition (Encrypt-then-MAC with
//! independent keys) over building blocks the kernel already trusts. It
//! replaces the previous in-kernel "AES" (a non-AES homebrew permutation with a
//! broken key schedule) and the deterministic-nonce CTR mode that reused
//! keystream across rewrites.
//!
//! Usage contract:
//!   * `enc_key` (32B) and `mac_key` (32B) MUST be independent — derive them
//!     from one secret via HKDF with distinct output ranges, never reuse one as
//!     both.
//!   * `nonce` (12B) MUST be unique per (enc_key) encryption. The storage layer
//!     draws a fresh CSPRNG nonce on every write and stores it beside the tag,
//!     so (key, nonce) never repeats even when a block is overwritten.
//!   * `aad` binds context (e.g. inode/block numbers) into the tag without
//!     encrypting it; the same `aad` must be supplied to `open`.
//!
//! Tag: the 16-byte (128-bit) prefix of HMAC-SHA256 — the same strength class
//! as AES-GCM / ChaCha20-Poly1305 tags.

use crate::rng::chacha20_block;
use crate::sha256::Sha256Hmac;

pub const AEAD_NONCE_LEN: usize = 12;
pub const AEAD_TAG_LEN: usize = 16;

/// XOR `buf` in place with the ChaCha20 keystream for (key, nonce), block
/// counter starting at 0. Encryption and decryption are the same operation.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], buf: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut off = 0usize;
    while off < buf.len() {
        let ks = chacha20_block(key, counter, nonce);
        counter = counter.wrapping_add(1);
        let take = core::cmp::min(64, buf.len() - off);
        for i in 0..take {
            buf[off + i] ^= ks[i];
        }
        off += take;
    }
}

/// Tag = HMAC-SHA256(mac_key, nonce ‖ aad ‖ ciphertext)[..16].
/// Streamed so no contiguous nonce+aad+ct buffer is ever allocated.
fn compute_tag(mac_key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; AEAD_TAG_LEN] {
    let mut mac = Sha256Hmac::new(mac_key);
    mac.update(nonce);
    mac.update(aad);
    mac.update(ct);
    let full = mac.finalize();
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&full[..AEAD_TAG_LEN]);
    tag
}

/// Constant-time tag comparison: no secret-dependent early exit.
fn tags_equal(a: &[u8; AEAD_TAG_LEN], b: &[u8; AEAD_TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..AEAD_TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    // Keep the accumulator opaque so the compiler can't reintroduce a branch.
    core::hint::black_box(diff) == 0
}

/// Encrypt `buf` in place (Encrypt-then-MAC) and produce the tag.
fn seal(enc_key: &[u8; 32], mac_key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; AEAD_TAG_LEN] {
    chacha20_xor(enc_key, nonce, buf);
    compute_tag(mac_key, nonce, aad, buf)
}

/// Verify the tag (constant-time) and, only on success, decrypt `buf` in place.
/// Returns true if authentic. On failure `buf` is zeroed and left undecrypted.
fn open(enc_key: &[u8; 32], mac_key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; AEAD_TAG_LEN]) -> bool {
    let expect = compute_tag(mac_key, nonce, aad, buf);
    if !tags_equal(&expect, tag) {
        for b in buf.iter_mut() {
            *b = 0;
        }
        return false;
    }
    chacha20_xor(enc_key, nonce, buf);
    true
}

// ---------------------------------------------------------------------------
// FFI surface used by the C storage layer.
// ---------------------------------------------------------------------------

/// Seal `buf` (len bytes) in place: ChaCha20 encrypt then HMAC.
/// `enc_key`/`mac_key` are 32 bytes each, `nonce` 12 bytes, `tag_out` 16 bytes.
/// Returns 0 on success, -1 on bad arguments.
///
/// # Safety
/// All pointers must be valid for their stated lengths and non-overlapping with
/// each other (except that `buf` is read and written). `enc_key`/`mac_key` are
/// 32 bytes, `nonce` 12 bytes, `tag_out` 16 bytes, `aad` is `aad_len` bytes
/// (may be null iff `aad_len == 0`), and `buf` is `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_aead_seal(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    buf: *mut u8,
    len: usize,
    tag_out: *mut u8,
) -> i32 {
    if enc_key.is_null() || mac_key.is_null() || nonce.is_null() || tag_out.is_null() {
        return -1;
    }
    if buf.is_null() && len != 0 {
        return -1;
    }
    if aad.is_null() && aad_len != 0 {
        return -1;
    }
    let mut ek = [0u8; 32];
    let mut mk = [0u8; 32];
    let mut nc = [0u8; AEAD_NONCE_LEN];
    ek.copy_from_slice(core::slice::from_raw_parts(enc_key, 32));
    mk.copy_from_slice(core::slice::from_raw_parts(mac_key, 32));
    nc.copy_from_slice(core::slice::from_raw_parts(nonce, AEAD_NONCE_LEN));
    let aad_s = if aad_len == 0 { &[][..] } else { core::slice::from_raw_parts(aad, aad_len) };
    let buf_s = if len == 0 { &mut [][..] } else { core::slice::from_raw_parts_mut(buf, len) };

    let tag = seal(&ek, &mk, &nc, aad_s, buf_s);
    core::ptr::copy_nonoverlapping(tag.as_ptr(), tag_out, AEAD_TAG_LEN);
    0
}

/// Open `buf` (len bytes of ciphertext) in place: verify HMAC (constant-time),
/// then decrypt only if authentic. Returns 0 on success; -1 on auth failure or
/// bad arguments (and on auth failure `buf` is zeroed).
///
/// # Safety
/// Same pointer/length contract as [`rust_aead_seal`]; `tag` is 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_aead_open(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    buf: *mut u8,
    len: usize,
    tag: *const u8,
) -> i32 {
    if enc_key.is_null() || mac_key.is_null() || nonce.is_null() || tag.is_null() {
        return -1;
    }
    if buf.is_null() && len != 0 {
        return -1;
    }
    if aad.is_null() && aad_len != 0 {
        return -1;
    }
    let mut ek = [0u8; 32];
    let mut mk = [0u8; 32];
    let mut nc = [0u8; AEAD_NONCE_LEN];
    let mut tg = [0u8; AEAD_TAG_LEN];
    ek.copy_from_slice(core::slice::from_raw_parts(enc_key, 32));
    mk.copy_from_slice(core::slice::from_raw_parts(mac_key, 32));
    nc.copy_from_slice(core::slice::from_raw_parts(nonce, AEAD_NONCE_LEN));
    tg.copy_from_slice(core::slice::from_raw_parts(tag, AEAD_TAG_LEN));
    let aad_s = if aad_len == 0 { &[][..] } else { core::slice::from_raw_parts(aad, aad_len) };
    let buf_s = if len == 0 { &mut [][..] } else { core::slice::from_raw_parts_mut(buf, len) };

    if open(&ek, &mk, &nc, aad_s, buf_s, &tg) {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic *test* vectors, derived via the crate's SHA-256 from domain
    // labels rather than hard-coded key/nonce bytes. They must be fixed so the
    // round-trip and tamper tests are reproducible, but they never occur in the
    // production path: real enc/mac keys are HKDF-SHA256 subkeys and the nonce is
    // a fresh CSPRNG draw, all supplied by the C storage layer through the
    // rust_aead_seal / rust_aead_open FFI (which take caller-provided key
    // pointers — this crate hard-codes no key material anywhere).
    fn keys() -> ([u8; 32], [u8; 32], [u8; AEAD_NONCE_LEN]) {
        let ek: [u8; 32] = crate::sha256::sha256(b"horus/aead-test/enc-key");
        let mk: [u8; 32] = crate::sha256::sha256(b"horus/aead-test/mac-key");
        let nh = crate::sha256::sha256(b"horus/aead-test/nonce");
        let nc: [u8; AEAD_NONCE_LEN] = core::array::from_fn(|i| nh[i]);
        (ek, mk, nc)
    }

    #[test]
    fn seal_then_open_roundtrip() {
        let (ek, mk, nc) = keys();
        let aad = b"inode=7,block=3";
        let plain = *b"the quick brown fox jumps over the lazy dog!!";
        let mut buf = plain;
        let tag = seal(&ek, &mk, &nc, aad, &mut buf);
        // Ciphertext must differ from plaintext.
        assert_ne!(buf, plain);
        // Authentic open restores the plaintext.
        assert!(open(&ek, &mk, &nc, aad, &mut buf, &tag));
        assert_eq!(buf, plain);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (ek, mk, nc) = keys();
        let aad = b"ctx";
        let mut buf = *b"sensitive block contents here..";
        let tag = seal(&ek, &mk, &nc, aad, &mut buf);
        buf[0] ^= 0x01; // flip one ciphertext bit
        assert!(!open(&ek, &mk, &nc, aad, &mut buf, &tag));
        // Rejected plaintext must not leak: buffer is zeroed on failure.
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let (ek, mk, nc) = keys();
        let aad = b"ctx";
        let mut buf = *b"another block of plaintext bytes";
        let mut tag = seal(&ek, &mk, &nc, aad, &mut buf);
        tag[AEAD_TAG_LEN - 1] ^= 0x80;
        assert!(!open(&ek, &mk, &nc, aad, &mut buf, &tag));
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let (ek, mk, nc) = keys();
        let mut buf = *b"bound-to-context payload bytes!!";
        let tag = seal(&ek, &mk, &nc, b"inode=1", &mut buf);
        // Same key/nonce/ciphertext but different AAD must fail authentication.
        assert!(!open(&ek, &mk, &nc, b"inode=2", &mut buf, &tag));
    }

    #[test]
    fn nonce_separation_changes_keystream() {
        let (ek, mk, mut nc) = keys();
        let plain = *b"0123456789abcdef0123456789abcdef";
        let mut a = plain;
        let _ = seal(&ek, &mk, &nc, b"", &mut a);
        nc[0] ^= 0xFF;
        let mut b = plain;
        let _ = seal(&ek, &mk, &nc, b"", &mut b);
        // Different nonce => different keystream => different ciphertext.
        assert_ne!(a, b);
    }
}

/// Nightly timing of the two compares roadmap 4.20 names.
///
/// `cargo test` does not run an ignored test, so the required `rust` job
/// never measures a clock. The nightly workflow runs this one test. A coarse
/// host timer is not a proof the primitives are constant-time (limitation
/// 5.4 stays open). The run fails closed when the same clock cannot separate
/// a planted early return of the same length: a timer that cannot see the
/// defect is not a witness.
#[cfg(test)]
mod ct_timing {
    extern crate std;

    use super::tags_equal;
    use super::AEAD_TAG_LEN;
    use std::time::Instant;

    /// `PASS_HASH_LEN` in `src/include/kernel.h`. The call-graph check is what
    /// binds `verify_user_password` to that symbol. This times that many bytes.
    const PASS_HASH_LEN: usize = 32;
    const ITERS: u32 = 40_000;
    const ROUNDS: usize = 11;
    /// Early must be under this percent of late, or the planted compare did
    /// not separate and the clock cannot see the defect.
    const PLANT_MAX: u128 = 75;
    /// A real compare must stay within this percent either way. Wider than
    /// the plant on purpose: scheduling noise is not a variable-time compare.
    const SLOP: u128 = 30;

    #[inline(never)]
    fn variable_time(a: &[u8], b: &[u8]) -> i32 {
        let n = a.len();
        let mut i = 0;
        while i < n {
            if core::hint::black_box(a[i]) != core::hint::black_box(b[i]) {
                return 0;
            }
            i += 1;
        }
        1
    }

    #[inline(never)]
    fn password_cmp(a: &[u8], b: &[u8]) -> i32 {
        // The slice is `a.len()` bytes and `b` is the same length. That is
        // the contract `rust_ct_eq` states.
        unsafe {
            crate::rust_ct_eq(
                core::hint::black_box(a.as_ptr()),
                core::hint::black_box(b.as_ptr()),
                core::hint::black_box(a.len()),
            )
        }
    }

    #[inline(never)]
    fn tag_cmp(a: &[u8; AEAD_TAG_LEN], b: &[u8; AEAD_TAG_LEN]) -> i32 {
        i32::from(tags_equal(
            core::hint::black_box(a),
            core::hint::black_box(b),
        ))
    }

    fn time_slice<F>(mut f: F, a: &[u8], b: &[u8]) -> u128
    where
        F: FnMut(&[u8], &[u8]) -> i32,
    {
        let start = Instant::now();
        let mut acc = 0i32;
        let mut i = 0u32;
        while i < ITERS {
            acc |= f(core::hint::black_box(a), core::hint::black_box(b));
            i += 1;
        }
        core::hint::black_box(acc);
        start.elapsed().as_nanos()
    }

    fn median_pair<F>(f: F, a: &[u8], early_b: &[u8], late_b: &[u8]) -> (u128, u128)
    where
        F: Fn(&[u8], &[u8]) -> i32,
    {
        let mut early = [0u128; ROUNDS];
        let mut late = [0u128; ROUNDS];
        let mut r = 0;
        while r < ROUNDS {
            // Alternate which side runs first so a warm cache does not
            // favour one mismatch position.
            let (e, l) = if r % 2 == 0 {
                (time_slice(&f, a, early_b), time_slice(&f, a, late_b))
            } else {
                let l = time_slice(&f, a, late_b);
                let e = time_slice(&f, a, early_b);
                (e, l)
            };
            early[r] = e;
            late[r] = l;
            r += 1;
        }
        early.sort_unstable();
        late.sort_unstable();
        (early[ROUNDS / 2], late[ROUNDS / 2])
    }

    fn separated(early: u128, late: u128) -> bool {
        early > 0 && late > 0 && early.saturating_mul(100) < late.saturating_mul(PLANT_MAX)
    }

    fn held(early: u128, late: u128) -> bool {
        early > 0
            && late > 0
            && early.saturating_mul(100) <= late.saturating_mul(100 + SLOP)
            && late.saturating_mul(100) <= early.saturating_mul(100 + SLOP)
    }

    #[test]
    #[ignore]
    fn ct_timing_password_and_aead() {
        let zero = [0u8; PASS_HASH_LEN];
        let mut early_b = [0u8; PASS_HASH_LEN];
        let mut late_b = [0u8; PASS_HASH_LEN];
        early_b[0] = 1;
        late_b[PASS_HASH_LEN - 1] = 1;
        let _ = variable_time(&zero, &early_b);
        let _ = password_cmp(&zero, &early_b);

        let (pe, pl) = median_pair(variable_time, &zero, &early_b, &late_b);
        std::eprintln!("ct-timing: plant password early {pe} ns late {pl} ns");
        assert!(
            separated(pe, pl),
            "ct-timing: clock cannot separate a planted variable-time compare"
        );

        let (ce, cl) = median_pair(password_cmp, &zero, &early_b, &late_b);
        std::eprintln!("ct-timing: password early {ce} ns late {cl} ns");
        assert!(held(ce, cl), "ct-timing: password compare separated");
        std::eprintln!("ct-timing: password compare held");

        let z16 = [0u8; AEAD_TAG_LEN];
        let mut e16 = [0u8; AEAD_TAG_LEN];
        let mut l16 = [0u8; AEAD_TAG_LEN];
        e16[0] = 1;
        l16[AEAD_TAG_LEN - 1] = 1;
        let (te, tl) = median_pair(variable_time, &z16, &e16, &l16);
        std::eprintln!("ct-timing: plant tag early {te} ns late {tl} ns");
        assert!(
            separated(te, tl),
            "ct-timing: clock cannot separate a planted variable-time compare"
        );
        std::eprintln!("ct-timing: planted variable-time compare separated");

        let mut tag_early = [0u128; ROUNDS];
        let mut tag_late = [0u128; ROUNDS];
        let mut r = 0;
        while r < ROUNDS {
            let (e, l) = if r % 2 == 0 {
                (time_tag(&z16, &e16), time_tag(&z16, &l16))
            } else {
                let l = time_tag(&z16, &l16);
                let e = time_tag(&z16, &e16);
                (e, l)
            };
            tag_early[r] = e;
            tag_late[r] = l;
            r += 1;
        }
        tag_early.sort_unstable();
        tag_late.sort_unstable();
        let ae = tag_early[ROUNDS / 2];
        let al = tag_late[ROUNDS / 2];
        std::eprintln!("ct-timing: aead early {ae} ns late {al} ns");
        assert!(held(ae, al), "ct-timing: aead compare separated");
        std::eprintln!("ct-timing: aead compare held");
    }

    fn time_tag(a: &[u8; AEAD_TAG_LEN], b: &[u8; AEAD_TAG_LEN]) -> u128 {
        let start = Instant::now();
        let mut acc = 0i32;
        let mut i = 0u32;
        while i < ITERS {
            acc |= tag_cmp(core::hint::black_box(a), core::hint::black_box(b));
            i += 1;
        }
        core::hint::black_box(acc);
        start.elapsed().as_nanos()
    }
}
