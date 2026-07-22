//! Audited-standard hashing primitives for the Horus kernel.
//!
//! Pure-`no_std`, constant-time-ish (data-independent control flow on secret
//! length only where unavoidable) implementations of:
//!   * SHA-256                 (FIPS 180-4)
//!   * HMAC-SHA256             (RFC 2104)
//!   * PBKDF2-HMAC-SHA256      (RFC 8018) — password hashing
//!   * HKDF-SHA256             (RFC 5869) — key derivation
//!
//! These replace the kernel's previous custom ARX / XOR-rotate constructions,
//! which were unaudited and had no security proof. The FFI wrappers at the
//! bottom are the only entry points the C kernel uses.

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const SHA256_BLOCK: usize = 64;
pub const SHA256_OUT: usize = 32;

/// Streaming SHA-256 state.
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; SHA256_BLOCK],
    buf_len: usize,
    total: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { h: H0, buf: [0u8; SHA256_BLOCK], buf_len: 0, total: 0 }
    }

    fn compress(h: &mut [u32; 8], block: &[u8; SHA256_BLOCK]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = SHA256_BLOCK - self.buf_len;
            let take = if data.len() < need { data.len() } else { need };
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == SHA256_BLOCK {
                let block = self.buf;
                Self::compress(&mut self.h, &block);
                self.buf_len = 0;
            }
        }
        while data.len() >= SHA256_BLOCK {
            let mut block = [0u8; SHA256_BLOCK];
            block.copy_from_slice(&data[..SHA256_BLOCK]);
            Self::compress(&mut self.h, &block);
            data = &data[SHA256_BLOCK..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; SHA256_OUT] {
        let bit_len = self.total.wrapping_mul(8);
        // Append 0x80 then pad with zeros, then 64-bit big-endian length.
        let mut pad = [0u8; SHA256_BLOCK + 8];
        pad[0] = 0x80;
        let rem = self.buf_len % SHA256_BLOCK;
        // pad_len chosen so (buf_len + pad_len + 8) % 64 == 0
        let pad_len = if rem < 56 { 56 - rem } else { 120 - rem };
        self.update(&pad[..pad_len]);
        let len_be = bit_len.to_be_bytes();
        self.update(&len_be);

        let mut out = [0u8; SHA256_OUT];
        for i in 0..8 {
            out[i * 4..i * 4 + 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

/// One-shot SHA-256.
pub fn sha256(data: &[u8]) -> [u8; SHA256_OUT] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_OUT] {
    let mut k0 = [0u8; SHA256_BLOCK];
    if key.len() > SHA256_BLOCK {
        let kh = sha256(key);
        k0[..SHA256_OUT].copy_from_slice(&kh);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK];
    let mut opad = [0x5cu8; SHA256_BLOCK];
    for i in 0..SHA256_BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018). Writes `out.len()` derived bytes.
/// `iterations` must be >= 1 (we clamp to 1).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let iters = if iterations == 0 { 1 } else { iterations };
    let mut block_index: u32 = 1;
    let mut offset = 0usize;

    while offset < out.len() {
        // U1 = PRF(password, salt || INT_32_BE(block_index))
        let mut salt_ctr = Sha256Hmac::new(password);
        salt_ctr.update(salt);
        salt_ctr.update(&block_index.to_be_bytes());
        let mut u = salt_ctr.finalize();
        let mut t = u;

        for _ in 1..iters {
            u = hmac_sha256(password, &u);
            for j in 0..SHA256_OUT {
                t[j] ^= u[j];
            }
        }

        let take = core::cmp::min(SHA256_OUT, out.len() - offset);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        block_index = block_index.wrapping_add(1);
    }
}

/// HKDF-SHA256 (RFC 5869): extract-then-expand. Writes `out.len()` bytes
/// (capped at 255*32). `salt` empty => zero salt per spec.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    // Extract
    let zero_salt = [0u8; SHA256_OUT];
    let salt_ref: &[u8] = if salt.is_empty() { &zero_salt } else { salt };
    let prk = hmac_sha256(salt_ref, ikm);

    // Expand
    let mut t: [u8; SHA256_OUT] = [0u8; SHA256_OUT];
    let mut t_len = 0usize;
    let mut offset = 0usize;
    let mut counter: u8 = 1;
    while offset < out.len() {
        let mut mac = Sha256Hmac::new(&prk);
        mac.update(&t[..t_len]);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize();
        t_len = SHA256_OUT;

        let take = core::cmp::min(SHA256_OUT, out.len() - offset);
        out[offset..offset + take].copy_from_slice(&t[..take]);
        offset += take;
        // 255-block limit per RFC 5869; out is small in practice.
        if counter == 255 {
            break;
        }
        counter += 1;
    }
}

/// Streaming HMAC, used internally by PBKDF2/HKDF to avoid reconstructing the
/// keyed pads on every call, and by `crate::aead` to MAC a multi-part message
/// (nonce ‖ aad ‖ ciphertext) without allocating a contiguous buffer.
pub(crate) struct Sha256Hmac {
    inner: Sha256,
    opad: [u8; SHA256_BLOCK],
}

impl Sha256Hmac {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut k0 = [0u8; SHA256_BLOCK];
        if key.len() > SHA256_BLOCK {
            let kh = sha256(key);
            k0[..SHA256_OUT].copy_from_slice(&kh);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; SHA256_BLOCK];
        let mut opad = [0x5cu8; SHA256_BLOCK];
        for i in 0..SHA256_BLOCK {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        Sha256Hmac { inner, opad }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub(crate) fn finalize(self) -> [u8; SHA256_OUT] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner_hash);
        outer.finalize()
    }
}

// ---------------------------------------------------------------------------
// FFI surface used by the C kernel.
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC-SHA256 password hash. Returns 0 on success, -1 on bad args.
#[no_mangle]
pub unsafe extern "C" fn rust_password_hash(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if password.is_null() || salt.is_null() || out.is_null() || out_len == 0 {
        return -1;
    }
    let pw = core::slice::from_raw_parts(password, password_len);
    let st = core::slice::from_raw_parts(salt, salt_len);
    let o = core::slice::from_raw_parts_mut(out, out_len);
    pbkdf2_hmac_sha256(pw, st, iterations, o);
    0
}

/// Plain SHA-256 digest of `data`, writing 32 bytes to `out32`.
///
/// Used to verify boot-module payloads against the hash manifest embedded in the
/// kernel image (see `boot_module_verify_all`). A keyed MAC would add nothing
/// here: the manifest ships *inside* the reproducible kernel image, so the image
/// itself is the root of trust and any key in it would be equally readable.
///
/// # Safety
/// `data` must be valid for `data_len` bytes (or `data_len` may be 0), and
/// `out32` must point to at least 32 writable bytes. Null is handled.
#[no_mangle]
pub unsafe extern "C" fn rust_sha256(data: *const u8, data_len: usize, out32: *mut u8) -> i32 {
    if out32.is_null() || (data.is_null() && data_len != 0) {
        return -1;
    }
    let d = if data_len == 0 { &[][..] } else { core::slice::from_raw_parts(data, data_len) };
    let digest = sha256(d);
    core::ptr::copy_nonoverlapping(digest.as_ptr(), out32, SHA256_OUT);
    0
}

/// HMAC-SHA256 over `data` with `key`, writing 32 bytes to `out32`.
#[no_mangle]
pub unsafe extern "C" fn rust_hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    out32: *mut u8,
) -> i32 {
    if key.is_null() || out32.is_null() || (data.is_null() && data_len != 0) {
        return -1;
    }
    let k = core::slice::from_raw_parts(key, key_len);
    let d = if data_len == 0 { &[][..] } else { core::slice::from_raw_parts(data, data_len) };
    let tag = hmac_sha256(k, d);
    core::ptr::copy_nonoverlapping(tag.as_ptr(), out32, SHA256_OUT);
    0
}

/// HKDF-SHA256 (extract+expand). Returns 0 on success, -1 on bad args.
#[no_mangle]
pub unsafe extern "C" fn rust_hkdf_sha256(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if ikm.is_null() || out.is_null() || out_len == 0 {
        return -1;
    }
    let ikm_s = core::slice::from_raw_parts(ikm, ikm_len);
    let salt_s = if salt.is_null() || salt_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(salt, salt_len)
    };
    let info_s = if info.is_null() || info_len == 0 {
        &[][..]
    } else {
        core::slice::from_raw_parts(info, info_len)
    };
    let o = core::slice::from_raw_parts_mut(out, out_len);
    hkdf_sha256(ikm_s, salt_s, info_s, o);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // core-only hex comparison (the crate is no_std even under test).
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
    fn sha256_known_vectors() {
        // "" and "abc" from FIPS 180-4.
        assert_hex(
            &sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_hex(
            &sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn sha256_multiblock() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_hex(
            &sha256(msg),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
    }

    /// The `rust_sha256` FFI the kernel uses to verify boot modules against its
    /// embedded manifest: it must agree with the internal digest on the FIPS
    /// vectors, handle the empty input, and fail closed (never write) on a null
    /// output pointer or a null/non-zero-length input.
    #[test]
    fn rust_sha256_ffi_matches_and_fails_closed() {
        unsafe {
            let mut out = [0u8; 32];
            assert_eq!(rust_sha256(b"abc".as_ptr(), 3, out.as_mut_ptr()), 0);
            assert_hex(&out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

            // Empty input is valid: a null data pointer with len 0 is accepted.
            let mut empty = [0u8; 32];
            assert_eq!(rust_sha256(core::ptr::null(), 0, empty.as_mut_ptr()), 0);
            assert_hex(&empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

            // Fail closed: null output, or null input with a non-zero length.
            assert_eq!(rust_sha256(b"abc".as_ptr(), 3, core::ptr::null_mut()), -1);
            let mut untouched = [0xAAu8; 32];
            assert_eq!(rust_sha256(core::ptr::null(), 3, untouched.as_mut_ptr()), -1);
            assert!(untouched.iter().all(|&b| b == 0xAA), "output must not be written on refusal");
        }
    }

    #[test]
    fn hmac_rfc4231_case2() {
        // key = "Jefe", data = "what do ya want for nothing?"
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_hex(
            &tag,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
    }

    #[test]
    fn pbkdf2_rfc_like_vector() {
        // RFC 7914 PBKDF2-HMAC-SHA256: P="passwd", S="salt", c=1, dkLen=64
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut out);
        assert_hex(&out[..16], "55ac046e56e3089fec1691c22544b605");
    }

    #[test]
    fn pbkdf2_two_iterations() {
        // P="password", S="salt", c=2, dkLen=32 (known answer)
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha256(b"password", b"salt", 2, &mut out);
        assert_hex(
            &out,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        );
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 Test Case 1
        let ikm = [0x0bu8; 22];
        let salt = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256(&ikm, &salt, &info, &mut okm);
        assert_hex(
            &okm,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
    }
}
