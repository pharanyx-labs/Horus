//! Argon2id (RFC 9106) — memory-hard password hashing, safe `no_std` Rust.
//!
//! Single lane (`p = 1`, which is what the kernel's auth path uses), no secret
//! key or associated data (the per-boot pepper is folded into the salt by the
//! caller). Built on the crate's own BLAKE2b (`blake2b.rs`); introduces no
//! external dependency. The kernel supplies the memory-fill scratch buffer (no
//! allocator in the kernel), so `rust_argon2id_hash` takes it as a parameter.
//!
//! Validated in the tests against reference tags produced by the `argon2-cffi`
//! reference implementation for the exact same parameters (type=Argon2id,
//! version=0x13, p=1, no secret/AD).
//!
//! Replaces the previous PBKDF2-HMAC-SHA256 password hashing: unlike PBKDF2,
//! Argon2id is memory-hard, so it resists the GPU/ASIC parallel brute force
//! that PBKDF2 is cheap to mount.

use crate::blake2b::Blake2b;

const QWORDS: usize = 128; // u64 per 1 KiB block
const VERSION: u32 = 0x13; // 19
const TYPE_ID: u32 = 2; // Argon2id
const SYNC_POINTS: usize = 4;
const ADDRESSES_PER_BLOCK: usize = 128;

type Block = [u64; QWORDS];

/// Argon2's modified BLAKE2b mixing function (adds the `2*lo32(a)*lo32(b)` term).
#[inline(always)]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    fn m(x: u64, y: u64) -> u64 {
        // 2 * (x & 0xffffffff) * (y & 0xffffffff), all in wrapping u64.
        let lo = (x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff);
        lo.wrapping_mul(2)
    }
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(m(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(m(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One BLAKE2 round (no message) over 16 words: 4 columns then 4 diagonals.
#[inline(always)]
fn round(x: &mut [u64; 16]) {
    gb(x, 0, 4, 8, 12);
    gb(x, 1, 5, 9, 13);
    gb(x, 2, 6, 10, 14);
    gb(x, 3, 7, 11, 15);
    gb(x, 0, 5, 10, 15);
    gb(x, 1, 6, 11, 12);
    gb(x, 2, 7, 8, 13);
    gb(x, 3, 4, 9, 14);
}

/// The Argon2 compression G: `out = t ^ P(prev ^ ref)` where P is the row-wise
/// then column-wise BLAKE2 permutation, and `t` is `prev ^ ref` (plus the old
/// `out` block when `with_xor`, i.e. on passes after the first).
fn fill_block(prev: &Block, reff: &Block, out: &mut Block, with_xor: bool) {
    let mut r = [0u64; QWORDS];
    for i in 0..QWORDS {
        r[i] = prev[i] ^ reff[i];
    }
    let mut t = r;
    if with_xor {
        for i in 0..QWORDS {
            t[i] ^= out[i];
        }
    }
    // Rows: 8 rows of 16 words.
    let mut tmp = [0u64; 16];
    for i in 0..8 {
        tmp.copy_from_slice(&r[16 * i..16 * i + 16]);
        round(&mut tmp);
        r[16 * i..16 * i + 16].copy_from_slice(&tmp);
    }
    // Columns: word indices 2*i + {0,1,16,17,...,112,113}.
    for i in 0..8 {
        for k in 0..8 {
            tmp[2 * k] = r[2 * i + 16 * k];
            tmp[2 * k + 1] = r[2 * i + 16 * k + 1];
        }
        round(&mut tmp);
        for k in 0..8 {
            r[2 * i + 16 * k] = tmp[2 * k];
            r[2 * i + 16 * k + 1] = tmp[2 * k + 1];
        }
    }
    for i in 0..QWORDS {
        out[i] = t[i] ^ r[i];
    }
}

/// Variable-length hash H' (RFC 9106 §3.2): BLAKE2b for `out.len() <= 64`,
/// otherwise the 32-byte-chunked extension.
fn blake2b_long(out: &mut [u8], inputs: &[&[u8]]) {
    let outlen = out.len();
    let lenle = (outlen as u32).to_le_bytes();
    if outlen <= 64 {
        let mut h = Blake2b::new(outlen);
        h.update(&lenle);
        for chunk in inputs {
            h.update(chunk);
        }
        h.finalize(out);
        return;
    }
    let mut v = [0u8; 64];
    let mut h = Blake2b::new(64);
    h.update(&lenle);
    for chunk in inputs {
        h.update(chunk);
    }
    h.finalize(&mut v);
    out[..32].copy_from_slice(&v[..32]);
    let mut pos = 32;
    while outlen - pos > 64 {
        let mut h = Blake2b::new(64);
        h.update(&v);
        h.finalize(&mut v);
        out[pos..pos + 32].copy_from_slice(&v[..32]);
        pos += 32;
    }
    let remaining = outlen - pos;
    let mut last = [0u8; 64];
    let mut h = Blake2b::new(remaining);
    h.update(&v);
    h.finalize(&mut last[..remaining]);
    out[pos..].copy_from_slice(&last[..remaining]);
}

fn load_block(bytes: &[u8; 1024]) -> Block {
    let mut b = [0u64; QWORDS];
    for i in 0..QWORDS {
        b[i] = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    b
}

fn get(mem: &[u64], i: usize) -> Block {
    let mut b = [0u64; QWORDS];
    b.copy_from_slice(&mem[i * QWORDS..i * QWORDS + QWORDS]);
    b
}
fn put(mem: &mut [u64], i: usize, b: &Block) {
    mem[i * QWORDS..i * QWORDS + QWORDS].copy_from_slice(b);
}

/// Map a 32-bit pseudo-random value to a reference *column* within the chosen
/// lane (RFC 9106 §3.4). `same_lane` is whether the reference lane is the lane
/// being filled: a different lane cannot expose the segment currently being
/// filled, so its reference area is one smaller when `index == 0`.
fn index_alpha(
    pass: u32,
    slice: usize,
    index: usize,
    pseudo_rand: u32,
    same_lane: bool,
    seg_len: usize,
    lane_len: usize,
) -> usize {
    let ref_area_size: u64 = if pass == 0 {
        if slice == 0 {
            (index - 1) as u64
        } else if same_lane {
            (slice * seg_len + index - 1) as u64
        } else {
            (slice * seg_len - if index == 0 { 1 } else { 0 }) as u64
        }
    } else if same_lane {
        (lane_len - seg_len + index - 1) as u64
    } else {
        (lane_len - seg_len - if index == 0 { 1 } else { 0 }) as u64
    };
    // Non-uniform mapping into [0, ref_area_size).
    let mut rel = pseudo_rand as u64;
    rel = (rel * rel) >> 32;
    rel = ref_area_size - 1 - ((ref_area_size * rel) >> 32);
    let start: u64 = if pass == 0 || slice == SYNC_POINTS - 1 {
        0
    } else {
        ((slice + 1) * seg_len) as u64
    };
    ((start + rel) % (lane_len as u64)) as usize
}

/// Core Argon2id over `lanes` lanes. `mem` must hold exactly `m_blocks * 128`
/// u64 words, and `m_blocks` must be a multiple of `4 * lanes`. Writes the
/// 32-byte tag into `out`.
fn argon2id(pwd: &[u8], salt: &[u8], t_cost: u32, lanes: usize, m_blocks: usize, mem: &mut [u64], out: &mut [u8]) {
    // H0 (64 bytes).
    let mut h0 = [0u8; 72]; // 64-byte H0 followed by two LE32 slots
    {
        let mut h = Blake2b::new(64);
        h.update(&(lanes as u32).to_le_bytes()); // p (lanes)
        h.update(&(out.len() as u32).to_le_bytes()); // T (tag length)
        h.update(&(m_blocks as u32).to_le_bytes()); // m
        h.update(&t_cost.to_le_bytes()); // t
        h.update(&VERSION.to_le_bytes());
        h.update(&TYPE_ID.to_le_bytes());
        h.update(&(pwd.len() as u32).to_le_bytes());
        h.update(pwd);
        h.update(&(salt.len() as u32).to_le_bytes());
        h.update(salt);
        h.update(&0u32.to_le_bytes()); // secret length
        h.update(&0u32.to_le_bytes()); // associated-data length
        h.finalize(&mut h0[..64]);
    }

    let lane_len = m_blocks / lanes; // q: blocks per lane
    let seg_len = lane_len / SYNC_POINTS;
    let zero: Block = [0u64; QWORDS];

    // First two blocks of every lane: B[l][0] = H'(H0 || LE32(0) || LE32(l)),
    // B[l][1] = H'(H0 || LE32(1) || LE32(l)).
    let mut blockbytes = [0u8; 1024];
    for lane in 0..lanes {
        for col in 0..2usize {
            blake2b_long(
                &mut blockbytes,
                &[&h0[..64], &(col as u32).to_le_bytes(), &(lane as u32).to_le_bytes()],
            );
            let b = load_block(&blockbytes);
            put(mem, lane * lane_len + col, &b);
        }
    }

    for pass in 0..t_cost {
        for slice in 0..SYNC_POINTS {
            // Fill this slice for every lane before advancing (cross-lane
            // references may only reach already-finished slices).
            for lane in 0..lanes {
                let data_independent = pass == 0 && slice < 2; // Argon2id hybrid
                let mut input_block: Block = [0u64; QWORDS];
                let mut address_block: Block = [0u64; QWORDS];
                if data_independent {
                    input_block[0] = pass as u64;
                    input_block[1] = lane as u64;
                    input_block[2] = slice as u64;
                    input_block[3] = m_blocks as u64;
                    input_block[4] = t_cost as u64;
                    input_block[5] = TYPE_ID as u64;
                }
                let start = if pass == 0 && slice == 0 { 2 } else { 0 };
                if data_independent && pass == 0 && slice == 0 {
                    input_block[6] += 1;
                    fill_block(&zero, &input_block, &mut address_block, false);
                    let tmp = address_block;
                    fill_block(&zero, &tmp, &mut address_block, false);
                }

                for index in start..seg_len {
                    let col = slice * seg_len + index;
                    let cur = lane * lane_len + col;
                    let prev = if col == 0 { lane * lane_len + lane_len - 1 } else { cur - 1 };

                    let pseudo_rand: u64 = if data_independent {
                        if index % ADDRESSES_PER_BLOCK == 0 && !(pass == 0 && slice == 0 && index == 0) {
                            input_block[6] += 1;
                            fill_block(&zero, &input_block, &mut address_block, false);
                            let tmp = address_block;
                            fill_block(&zero, &tmp, &mut address_block, false);
                        }
                        address_block[index % ADDRESSES_PER_BLOCK]
                    } else {
                        get(mem, prev)[0]
                    };
                    let j1 = (pseudo_rand & 0xffff_ffff) as u32;
                    let j2 = (pseudo_rand >> 32) as u32;
                    // Reference lane: current lane on the very first slice,
                    // otherwise selected by J2.
                    let ref_lane = if pass == 0 && slice == 0 { lane } else { (j2 as usize) % lanes };
                    let same_lane = ref_lane == lane;
                    let ref_col = index_alpha(pass, slice, index, j1, same_lane, seg_len, lane_len);
                    let ref_index = ref_lane * lane_len + ref_col;

                    let prev_b = get(mem, prev);
                    let ref_b = get(mem, ref_index);
                    let mut cur_b = get(mem, cur);
                    fill_block(&prev_b, &ref_b, &mut cur_b, pass > 0);
                    put(mem, cur, &cur_b);
                }
            }
        }
    }

    // Final: XOR the last block of every lane, then tag = H'(that).
    let mut c = get(mem, lane_len - 1); // lane 0's last block
    for lane in 1..lanes {
        let lb = get(mem, lane * lane_len + lane_len - 1);
        for i in 0..QWORDS {
            c[i] ^= lb[i];
        }
    }
    let mut lastbytes = [0u8; 1024];
    for i in 0..QWORDS {
        lastbytes[i * 8..i * 8 + 8].copy_from_slice(&c[i].to_le_bytes());
    }
    blake2b_long(out, &[&lastbytes]);
}

/// Compute `m'`: the actual number of 1 KiB blocks, rounded down to a multiple
/// of `4 * lanes` and clamped to the Argon2 minimum of `8 * lanes`.
fn effective_blocks(m_cost_kib: u32, lanes: usize) -> usize {
    let unit = 4 * lanes;
    let min = 8 * lanes;
    let mut m = m_cost_kib as usize;
    if m < min {
        m = min;
    }
    (m / unit) * unit
}

// ---------------------------------------------------------------------------
// FFI surface. The kernel owns the scratch buffer (no allocator in-kernel);
// all key/secret material stays in caller memory.
// ---------------------------------------------------------------------------

/// Argon2id password hash. `m_cost` is in KiB (== 1 KiB blocks), `t_cost` is
/// the pass count, `p_cost` is the number of lanes (parallelism). `mem`/
/// `mem_words` is a scratch buffer the caller provides; it must hold at least
/// `128 * effective_blocks(m_cost, p_cost)` u64 words. Writes `out_len` (== 32)
/// bytes to `out`. Returns 0 on success, -1 on bad arguments (incl. a too-small
/// scratch buffer).
///
/// # Safety
/// `pwd`/`salt`/`mem`/`out` must be valid for their stated lengths and
/// non-overlapping; `mem` must be 8-byte aligned (it is reinterpreted as u64).
/// `pwd`/`salt` may be null iff their length is 0.
#[no_mangle]
pub unsafe extern "C" fn rust_argon2id_hash(
    pwd: *const u8,
    pwd_len: usize,
    salt: *const u8,
    salt_len: usize,
    t_cost: u32,
    m_cost: u32,
    p_cost: u32,
    mem: *mut u64,
    mem_words: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    if mem.is_null() || out.is_null() || out_len == 0 {
        return -1;
    }
    if (pwd.is_null() && pwd_len != 0) || (salt.is_null() && salt_len != 0) {
        return -1;
    }
    if t_cost == 0 || p_cost == 0 {
        return -1;
    }
    let lanes = p_cost as usize;
    let m_blocks = effective_blocks(m_cost, lanes);
    if mem_words < m_blocks * QWORDS {
        return -1;
    }
    let pwd_s = if pwd_len == 0 { &[][..] } else { core::slice::from_raw_parts(pwd, pwd_len) };
    let salt_s = if salt_len == 0 { &[][..] } else { core::slice::from_raw_parts(salt, salt_len) };
    let mem_s = core::slice::from_raw_parts_mut(mem, m_blocks * QWORDS);
    let out_s = core::slice::from_raw_parts_mut(out, out_len);
    argon2id(pwd_s, salt_s, t_cost, lanes, m_blocks, mem_s, out_s);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference tags from argon2-cffi (type=Argon2id, version=0x13, no
    // secret/AD) for the exact same parameters. See the generation command in
    // the commit that introduced this file.
    fn run(pwd: &[u8], salt: &[u8], m: u32, t: u32, p: usize) -> [u8; 32] {
        let m_blocks = effective_blocks(m, p);
        let mut mem = alloc::vec![0u64; m_blocks * QWORDS];
        let mut out = [0u8; 32];
        argon2id(pwd, salt, t, p, m_blocks, &mut mem, &mut out);
        out
    }

    fn hex(b: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for x in b {
            let _ = write!(s, "{:02x}", x);
        }
        s
    }

    #[test]
    fn argon2id_vectors_p1() {
        assert_eq!(
            hex(&run(b"password", b"0123456789abcdef", 8, 1, 1)),
            "771338d819573c67116b39e1788ae8e04b0eb0cf9dfbbfe2e6d746cf3e464fc7"
        );
        assert_eq!(
            hex(&run(b"password", b"0123456789abcdef", 32, 3, 1)),
            "72c63dd5c2ebcb402af0e0372451ceae01bef4a22aafdd8f22b0a234cbc5c818"
        );
        assert_eq!(
            hex(&run(b"hello world", b"saltsaltsaltsalt", 16, 2, 1)),
            "ce2e7a14d89b31e8e6eb1e4510dd97209279dc93f0acb815c5f35521d20adb24"
        );
    }

    #[test]
    fn argon2id_vectors_multilane() {
        // p=2 and p=4 against argon2-cffi reference tags: exercises cross-lane
        // references, per-lane seeding, and the final-block XOR.
        assert_eq!(
            hex(&run(b"password", b"0123456789abcdef", 32, 3, 2)),
            "af98a308561e6660735bcee5a939a242d8024a37cd82d0243c1a9916194a1a8c"
        );
        assert_eq!(
            hex(&run(b"password", b"0123456789abcdef", 64, 3, 4)),
            "82199d30c09d8a58300e9bd251d5ddf239576e537d5b09718279b23569d2a6e7"
        );
        assert_eq!(
            hex(&run(b"hello world", b"saltsaltsaltsalt", 16, 2, 2)),
            "1f27f07017e02a85ea9f1eff62a0e1384d88db2531f25d59e579c258059f22e0"
        );
    }

    #[test]
    fn argon2id_kernel_profile() {
        // The exact profile the kernel uses: m=4096 KiB, t=3, p=1.
        assert_eq!(
            hex(&run(b"rootpass", b"0123456789abcdef", 4096, 3, 1)),
            "92c114d55d765663717a7a704475aa4f1c2ad530642308ace8311a062bd569dd"
        );
    }
}
