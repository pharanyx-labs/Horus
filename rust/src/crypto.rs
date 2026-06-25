extern "C" {
    fn crypto_aes128_ctr_encrypt(buf: *mut u8, len: usize, key: *const u8, nonce: *const u8);
    fn secure_zero(p: *mut u8, n: usize);
}

#[inline]
pub unsafe fn safe_secure_zero(p: *mut u8, n: usize) {
    if !p.is_null() && n > 0 {
        secure_zero(p, n);
    }
}

#[inline]
unsafe fn build_nonce(
    ino: u64,
    block: u64,
    gen: u32,
    tsc_low32: u32,
    volume_salt: *const u8,
    out: &mut [u8; 16],
) {
    for i in 0..8 {
        out[i] = ((ino >> (i * 8)) & 0xff) as u8;
        out[8 + i] = ((block >> (i * 8)) & 0xff) as u8;
    }
    let diff = gen ^ tsc_low32;
    for i in 0..4 {
        out[12 + i] ^= ((diff >> (i * 8)) & 0xff) as u8;
    }
    if !volume_salt.is_null() {
        for i in 0..4 {
            out[i] ^= *volume_salt.add(i);
            out[8 + i] ^= *volume_salt.add(8 + (i & 3));
        }
    }
}

unsafe fn arx_derive_1024_rounds(
    volume_key: *const u8,
    ino: u64,
    block: u64,
    gen: u32,
    pepper: *const u8, 
    enc_key_out: *mut u8, 
    mac_key_out: *mut u8,
) -> i32 {
    if volume_key.is_null() || enc_key_out.is_null() || mac_key_out.is_null() {
        return -1;
    }

    let mut state = [0u8; 32];

    for i in 0..16 {
        state[i] = *volume_key.add(i);
    }
    for i in 0..8 {
        let v = ((ino >> (i * 8)) ^ (block >> (i * 8))) & 0xff;
        state[16 + i] = v as u8;
    }
    state[24] = (gen & 0xff) as u8;
    state[25] = ((gen >> 8) & 0xff) as u8;
    state[26] = ((gen >> 16) & 0xff) as u8;
    state[27] = ((gen >> 24) & 0xff) as u8;

    if !pepper.is_null() {
        for i in 0..4 {
            state[28 + i] = *pepper.add(i);
        }
    }

    for r in 0..1024u32 {
        let w = state.as_mut_ptr() as *mut u32;
        for q in (0..8).step_by(2) {
            let sum = (*w.add(q)).wrapping_add(*w.add(q + 1)).wrapping_add(r);
            *w.add(q) = sum;
            let rot = ((r & 7) + 3) as u32;
            let rotw = (*w.add(q + 1) << rot) | (*w.add(q + 1) >> (32 - rot));
            *w.add(q + 1) = rotw ^ *w.add(q);
        }
        if (r & 63) == 0 && !pepper.is_null() {
            for i in 0..16 {
                state[i] ^= *pepper.add(i & 15);
            }
        }
        let t = *w.add(0);
        for i in 0..7 {
            *w.add(i) = *w.add(i + 1);
        }
        *w.add(7) = t;
    }

    for i in 0..16 {
        *enc_key_out.add(i) = state[i];
        *mac_key_out.add(i) = state[16 + i];
    }

    safe_secure_zero(state.as_mut_ptr(), 32);
    0
}

unsafe fn arx_compute_mac(
    nonce: *const u8,
    data: *const u8,
    data_len: usize,
    mac_key: *const u8,
    tag_out: *mut u8,
) -> i32 {
    if nonce.is_null() || data.is_null() || mac_key.is_null() || tag_out.is_null() {
        return -1;
    }

    let mut state = [0u8; 32];
    for i in 0..16 {
        state[i] = *nonce.add(i);
        state[16 + i] = *mac_key.add(i);
    }

    for pos in 0..data_len {
        state[pos & 31] ^= *data.add(pos);
        if (pos & 31) == 31 {
            let w = state.as_mut_ptr() as *mut u32;
            for q in (0..8).step_by(2) {
                *w.add(q) = (*w.add(q)).wrapping_add(*w.add(q + 1));
                let rotw = (*w.add(q + 1) << 11) | (*w.add(q + 1) >> 21);
                *w.add(q + 1) = rotw ^ *w.add(q);
            }
        }
    }

    for r in 0..8u32 {
        let w = state.as_mut_ptr() as *mut u32;
        for q in (0..8).step_by(2) {
            *w.add(q) = (*w.add(q)).wrapping_add(*w.add(q + 1)).wrapping_add(r);
            let rotw = (*w.add(q + 1) << 13) | (*w.add(q + 1) >> 19);
            *w.add(q + 1) = rotw ^ *w.add(q);
        }
        let t = *w.add(0);
        for j in 0..7 {
            *w.add(j) = *w.add(j + 1);
        }
        *w.add(7) = t;
    }

    for i in 0..16 {
        *tag_out.add(i) = state[i] ^ state[16 + i];
    }

    safe_secure_zero(state.as_mut_ptr(), 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn rust_storage_derive_block_keys(
    ino: u64,
    block: u64,
    gen: u32,
    volume_key: *const u8,
    pepper: *const u8,
    enc_key_out: *mut u8,
    mac_key_out: *mut u8,
) -> i32 {
    arx_derive_1024_rounds(volume_key, ino, block, gen, pepper, enc_key_out, mac_key_out)
}

#[no_mangle]
pub unsafe extern "C" fn rust_storage_compute_mac(
    nonce: *const u8,
    data: *const u8,
    data_len: usize,
    mac_key: *const u8,
    tag_out: *mut u8,
) -> i32 {
    arx_compute_mac(nonce, data, data_len, mac_key, tag_out)
}

#[no_mangle]
pub unsafe extern "C" fn rust_storage_encrypt_block(
    ino: u64,
    block: u64,
    buf: *mut u8,
    gen: u32,
    tsc_low32: u32,
    volume_key: *const u8,
    volume_salt: *const u8,
    pepper: *const u8,
) -> i32 {
    if buf.is_null() {
        return -1;
    }

    let mut nonce = [0u8; 16];
    build_nonce(ino, block, gen, tsc_low32, volume_salt, &mut nonce);

    let mut enc_key = [0u8; 16];
    let mut mac_key = [0u8; 16];

    let rc = arx_derive_1024_rounds(
        volume_key,
        ino,
        block,
        gen,
        pepper,
        enc_key.as_mut_ptr(),
        mac_key.as_mut_ptr(),
    );
    if rc != 0 {
        safe_secure_zero(nonce.as_mut_ptr(), 16);
        return rc;
    }

    crypto_aes128_ctr_encrypt(buf, 4080, enc_key.as_ptr(), nonce.as_ptr());

    let mut tag = [0u8; 16];
    let _ = arx_compute_mac(
        nonce.as_ptr(),
        buf,
        4080,
        mac_key.as_ptr(),
        tag.as_mut_ptr(),
    );

    for i in 0..16 {
        *buf.add(4080 + i) = tag[i];
    }

    safe_secure_zero(enc_key.as_mut_ptr(), 16);
    safe_secure_zero(mac_key.as_mut_ptr(), 16);
    safe_secure_zero(nonce.as_mut_ptr(), 16);
    0
}

#[no_mangle]
pub unsafe extern "C" fn rust_storage_decrypt_block(
    ino: u64,
    block: u64,
    buf: *mut u8,
    gen: u32,
    tsc_low32: u32,
    volume_key: *const u8,
    volume_salt: *const u8,
    pepper: *const u8,
) -> i32 {
    if buf.is_null() {
        return -1;
    }

    let mut nonce = [0u8; 16];
    build_nonce(ino, block, gen, tsc_low32, volume_salt, &mut nonce);

    let mut want = [0u8; 16];
    for i in 0..16 {
        want[i] = *buf.add(4080 + i);
    }

    let mut enc_key = [0u8; 16];
    let mut mac_key = [0u8; 16];

    let rc = arx_derive_1024_rounds(
        volume_key,
        ino,
        block,
        gen,
        pepper,
        enc_key.as_mut_ptr(),
        mac_key.as_mut_ptr(),
    );
    if rc != 0 {
        safe_secure_zero(buf, 4096);
        safe_secure_zero(nonce.as_mut_ptr(), 16);
        return rc;
    }

    let mut tag = [0u8; 16];
    let _ = arx_compute_mac(nonce.as_ptr(), buf, 4080, mac_key.as_ptr(), tag.as_mut_ptr());

    let mut bad = 0i32;
    for i in 0..16 {
        if tag[i] != want[i] {
            bad = 1;
        }
    }

    if bad != 0 {
        safe_secure_zero(buf, 4096);
        safe_secure_zero(enc_key.as_mut_ptr(), 16);
        safe_secure_zero(mac_key.as_mut_ptr(), 16);
        safe_secure_zero(nonce.as_mut_ptr(), 16);
        return -1;
    }

    crypto_aes128_ctr_encrypt(buf, 4080, enc_key.as_ptr(), nonce.as_ptr());

    safe_secure_zero(enc_key.as_mut_ptr(), 16);
    safe_secure_zero(mac_key.as_mut_ptr(), 16);
    safe_secure_zero(nonce.as_mut_ptr(), 16);
    0
}

