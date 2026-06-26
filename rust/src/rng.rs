//! Central cryptographically-secure PRNG for the Horus kernel.
//!
//! Construction: ChaCha20 (RFC 8439) run as a fast-key-erasure stream RNG
//! (Bernstein's design): each request emits keystream and then consumes one
//! extra block to overwrite the key, giving forward secrecy. The pool is
//! reseeded from multiple hardware/timing sources at boot and on demand:
//!   * RDRAND (with a simple health check + retry) when the CPU advertises it,
//!   * the timestamp counter (TSC),
//!   * interrupt/jitter samples and a monotonically-increasing call counter.
//!
//! This replaces the kernel's previous ad-hoc `LCG + raw TSC` randomness, which
//! was predictable from userspace (TSC is readable in ring 3) and never used
//! the hardware RNG at all.

use crate::sha256::Sha256;
use core::sync::atomic::{AtomicBool, Ordering};

// ---------------------------------------------------------------------------
// ChaCha20 block function (RFC 8439).
// ---------------------------------------------------------------------------

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Produce one 64-byte ChaCha20 keystream block.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    const CONST: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut state = [0u32; 16];
    state[0..4].copy_from_slice(&CONST);
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3],
        ]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4], nonce[i * 4 + 1], nonce[i * 4 + 2], nonce[i * 4 + 3],
        ]);
    }

    let mut working = state;
    for _ in 0..10 {
        // column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let v = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Reseedable fast-key-erasure RNG state.
// ---------------------------------------------------------------------------

struct RngState {
    key: [u8; 32],
    nonce: [u8; 12],
    seeded: bool,
    reseeds: u64,
}

impl RngState {
    const fn new() -> Self {
        // Non-secret startup constants; the pool MUST be reseeded from
        // hardware entropy before its output is relied upon. `seeded` tracks
        // whether that has happened.
        RngState {
            key: [
                0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed,
                0xc8, 0x34, 0x10, 0x82, 0x27, 0x6b, 0xf3, 0xa2, 0x72, 0x51, 0xf8, 0x6c, 0x6a, 0x11,
                0xd0, 0xc1, 0x8e, 0x95,
            ],
            nonce: [0; 12],
            seeded: false,
            reseeds: 0,
        }
    }

    /// Fold fresh entropy into the key via SHA-256, preserving any existing
    /// state (so adding low-quality entropy can never *reduce* unpredictability).
    fn add_entropy(&mut self, data: &[u8]) {
        let mut h = Sha256::new();
        h.update(b"horus-rng-reseed-v1");
        h.update(&self.key);
        h.update(&self.nonce);
        h.update(&self.reseeds.to_le_bytes());
        h.update(data);
        let d = h.finalize();
        self.key.copy_from_slice(&d);
        // Perturb the nonce from the new key so identical entropy at different
        // reseed counts yields different streams.
        for i in 0..12 {
            self.nonce[i] ^= d[16 + i];
        }
        self.reseeds = self.reseeds.wrapping_add(1);
        self.seeded = true;
    }

    /// Fill `out` with keystream, then rekey (fast key erasure).
    fn fill(&mut self, out: &mut [u8]) {
        let mut counter: u32 = 0;
        let mut produced = 0usize;
        while produced < out.len() {
            let ks = chacha20_block(&self.key, counter, &self.nonce);
            counter = counter.wrapping_add(1);
            let take = core::cmp::min(64, out.len() - produced);
            out[produced..produced + take].copy_from_slice(&ks[..take]);
            produced += take;
        }
        // Rekey: overwrite the key with fresh keystream for forward secrecy.
        let ks = chacha20_block(&self.key, counter, &self.nonce);
        self.key.copy_from_slice(&ks[..32]);
    }
}

// Single global pool guarded by a tiny spinlock so it is sound under future
// SMP / preemption. On the current single-core cooperative kernel the lock is
// uncontended.
static RNG_LOCK: AtomicBool = AtomicBool::new(false);
static mut RNG: RngState = RngState::new();

struct LockGuard;

fn lock() -> LockGuard {
    while RNG_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    LockGuard
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        RNG_LOCK.store(false, Ordering::Release);
    }
}

#[inline]
fn with_rng<R>(f: impl FnOnce(&mut RngState) -> R) -> R {
    let _g = lock();
    // SAFETY: exclusive access is enforced by RNG_LOCK for the duration of the
    // closure; we never hand out a reference that outlives the guard.
    let st = unsafe { &mut *core::ptr::addr_of_mut!(RNG) };
    f(st)
}

// ---------------------------------------------------------------------------
// Hardware RNG (RDRAND) with health check.
// ---------------------------------------------------------------------------

/// Read one 64-bit value from RDRAND. Returns false if the CPU does not signal
/// success after retries, or if the value fails a trivial health check.
///
/// SAFETY / preconditions: the caller MUST only invoke this when CPUID has
/// confirmed RDRAND support; otherwise the instruction faults (#UD).
#[no_mangle]
pub unsafe extern "C" fn rust_rdrand_u64(out: *mut u64) -> bool {
    if out.is_null() {
        return false;
    }
    match rdrand_u64_inner() {
        Some(v) => {
            *out = v;
            true
        }
        None => false,
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_step_64() -> Option<u64> {
    let mut val: u64 = 0;
    // _rdrand64_step returns 1 on success, 0 on failure.
    if core::arch::x86_64::_rdrand64_step(&mut val) == 1 {
        Some(val)
    } else {
        None
    }
}

#[cfg(target_arch = "x86")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand_step_32() -> Option<u32> {
    let mut val: u32 = 0;
    if core::arch::x86::_rdrand32_step(&mut val) == 1 {
        Some(val)
    } else {
        None
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn rdrand_raw() -> Option<u64> {
    rdrand_step_64()
}

#[cfg(target_arch = "x86")]
unsafe fn rdrand_raw() -> Option<u64> {
    let lo = rdrand_step_32()?;
    let hi = rdrand_step_32()?;
    Some(((hi as u64) << 32) | lo as u64)
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
unsafe fn rdrand_raw() -> Option<u64> {
    None
}

unsafe fn rdrand_u64_inner() -> Option<u64> {
    // Up to 10 retries per Intel's guidance.
    for _ in 0..10 {
        if let Some(v) = rdrand_raw() {
            // Trivial health check: reject the degenerate all-zero / all-one
            // outputs that a stuck RNG would produce.
            if v != 0 && v != u64::MAX {
                return Some(v);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// FFI surface used by the C kernel.
// ---------------------------------------------------------------------------

/// Mix `len` bytes of caller-supplied entropy into the pool.
#[no_mangle]
pub unsafe extern "C" fn rust_rng_add_entropy(data: *const u8, len: usize) {
    if data.is_null() || len == 0 {
        return;
    }
    let s = core::slice::from_raw_parts(data, len);
    with_rng(|r| r.add_entropy(s));
}

/// Fill `len` bytes of `out` with CSPRNG output.
#[no_mangle]
pub unsafe extern "C" fn rust_rng_fill(out: *mut u8, len: usize) {
    if out.is_null() || len == 0 {
        return;
    }
    let s = core::slice::from_raw_parts_mut(out, len);
    with_rng(|r| r.fill(s));
}

/// Return one random u64 from the CSPRNG.
#[no_mangle]
pub unsafe extern "C" fn rust_rng_u64() -> u64 {
    let mut b = [0u8; 8];
    with_rng(|r| r.fill(&mut b));
    u64::from_le_bytes(b)
}

/// Report whether the pool has been reseeded from real entropy at least once.
#[no_mangle]
pub extern "C" fn rust_rng_is_seeded() -> bool {
    with_rng(|r| r.seeded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nyb(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    }
    fn assert_hex(actual: &[u8], expected_hex: &str) {
        let h = expected_hex.as_bytes();
        assert_eq!(actual.len() * 2, h.len());
        for i in 0..actual.len() {
            let want = (nyb(h[2 * i]) << 4) | nyb(h[2 * i + 1]);
            assert_eq!(actual[i], want);
        }
    }

    #[test]
    fn chacha20_rfc8439_block() {
        // RFC 8439 Section 2.3.2 test vector.
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce = [0u8, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = chacha20_block(&key, 1, &nonce);
        assert_hex(
            &block,
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c0680304\
22aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cb\
d083e8a2503c4e",
        );
    }

    #[test]
    fn rng_changes_and_reseed_effective() {
        // Two consecutive fills must differ (rekeying advances state).
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::with_rng(|r| r.fill(&mut a));
        super::with_rng(|r| r.fill(&mut b));
        assert_ne!(a, b);

        // Adding entropy must change subsequent output.
        super::with_rng(|r| r.add_entropy(b"some entropy bytes"));
        let mut c = [0u8; 32];
        super::with_rng(|r| r.fill(&mut c));
        assert_ne!(b, c);
        assert!(super::with_rng(|r| r.seeded));
    }
}
