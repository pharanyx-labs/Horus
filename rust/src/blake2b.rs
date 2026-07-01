//! BLAKE2b (RFC 7693) — the hash primitive underlying Argon2id (`argon2.rs`).
//!
//! Safe `no_std` Rust, incremental, keyless, arbitrary output length 1..=64.
//! Validated against the RFC 7693 Appendix A known-answer vector in the tests.
//! Not exposed over FFI on its own; used only by the Argon2 core.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// The BLAKE2b mixing function G.
#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Incremental BLAKE2b hasher (keyless).
pub struct Blake2b {
    h: [u64; 8],
    t: [u64; 2], // 128-bit byte counter (t[0] low, t[1] high)
    buf: [u8; 128],
    buflen: usize,
    outlen: usize,
}

impl Blake2b {
    /// New hasher producing `outlen` bytes (1..=64), no key.
    pub fn new(outlen: usize) -> Self {
        debug_assert!(outlen >= 1 && outlen <= 64);
        let mut h = IV;
        // Parameter block: digest length, key length 0, fanout 1, depth 1.
        h[0] ^= 0x0101_0000 ^ (outlen as u64);
        Blake2b { h, t: [0, 0], buf: [0u8; 128], buflen: 0, outlen }
    }

    #[inline]
    fn inc_counter(&mut self, n: u64) {
        let (lo, carry) = self.t[0].overflowing_add(n);
        self.t[0] = lo;
        if carry {
            self.t[1] = self.t[1].wrapping_add(1);
        }
    }

    fn compress(&mut self, last: bool) {
        let mut m = [0u64; 16];
        for (i, mi) in m.iter_mut().enumerate() {
            *mi = u64::from_le_bytes(self.buf[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last {
            v[14] ^= !0u64;
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // A full 128-byte block is only compressed once we know more bytes
        // follow it (the final block is compressed in finalize with the last
        // flag set), so never compress the trailing buffer here.
        let fill = 128 - self.buflen;
        if data.len() > fill {
            self.buf[self.buflen..].copy_from_slice(&data[..fill]);
            self.inc_counter(128);
            self.compress(false);
            self.buflen = 0;
            data = &data[fill..];
            while data.len() > 128 {
                self.buf.copy_from_slice(&data[..128]);
                self.inc_counter(128);
                self.compress(false);
                data = &data[128..];
            }
        }
        self.buf[self.buflen..self.buflen + data.len()].copy_from_slice(data);
        self.buflen += data.len();
    }

    pub fn finalize(mut self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.outlen);
        self.inc_counter(self.buflen as u64);
        for i in self.buflen..128 {
            self.buf[i] = 0;
        }
        self.compress(true);
        let mut bytes = [0u8; 64];
        for i in 0..8 {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&self.h[i].to_le_bytes());
        }
        out.copy_from_slice(&bytes[..self.outlen]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(outlen: usize, data: &[u8]) -> [u8; 64] {
        let mut h = Blake2b::new(outlen);
        h.update(data);
        let mut out = [0u8; 64];
        h.finalize(&mut out[..outlen]);
        out
    }

    #[test]
    fn rfc7693_blake2b512_abc() {
        // RFC 7693 Appendix A: BLAKE2b-512("abc").
        let expect: [u8; 64] = [
            0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d, 0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12,
            0xf6, 0xe9, 0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7, 0x4b, 0x12, 0xbb, 0x6f,
            0xdb, 0xff, 0xa2, 0xd1, 0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d, 0xc2, 0x52,
            0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95, 0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
            0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23,
        ];
        assert_eq!(hash(64, b"abc"), expect);
    }

    #[test]
    fn empty_and_multiblock() {
        // BLAKE2b-512("") known answer.
        let empty = hash(64, b"");
        assert_eq!(empty[0], 0x78);
        assert_eq!(empty[1], 0x6a);
        // A >128-byte input exercises the multi-block path without panicking and
        // is deterministic.
        let big = [0x61u8; 200];
        assert_eq!(hash(64, &big), hash(64, &big));
    }
}
