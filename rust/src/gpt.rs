//! Find the one Horus volume on a GPT disk.
//!
//! WHY THIS IS IN RING 0 AT ALL. The kernel mounts the volume at boot, before
//! any ring-3 server runs, so whatever tells it where the volume starts is read
//! by the kernel. Until 2026-10-08 nothing did: a volume was a whole device,
//! starting at block 0. A disk that boots on its own needs an EFI system
//! partition in front of the volume, so the volume moves into a partition and
//! the kernel has to read the partition table to find it.
//!
//! WHY IT IS RUST. The table is bytes off a disk, and a disk is hostile
//! (CLAUDE.md section 1): anyone who had the machine's storage in their hands
//! wrote them. Every field below is an offset, a length or a count an attacker
//! chose, and the C side does arithmetic on the result to address the device.
//! Here every sum is checked, every slice is bounded, and the one function that
//! turns the table's answer into blocks the kernel will touch
//! (`volume_blocks`) is proved by Kani to return only a non-empty, block-aligned
//! range that lies inside the device and outside the table.
//!
//! WHAT IS ACCEPTED, deliberately narrow, failing closed on anything else:
//!   * the primary header at LBA 1, its CRC32 correct, `my_lba` = 1;
//!   * 128-byte entries (the only size any partitioning tool writes) starting
//!     at LBA 2 or later and lying wholly inside the bytes the caller read;
//!   * the entry array's CRC32 correct;
//!   * EXACTLY ONE entry of the Horus volume type. Two is refused rather than
//!     "the first", since which one is first is the attacker's choice;
//!   * that entry inside the header's usable range, after the entry array, and
//!     4 KiB aligned at both ends, since the volume is addressed in 4 KiB blocks.
//!
//! WHAT IS NOT CHECKED, and why that is safe: the backup header at the end of
//! the disk, and the protective MBR. Neither is consulted to find the volume,
//! so neither can mislead it. Nor is anything here a reason to TRUST the
//! volume: a forged table can only point the kernel at blocks, and the volume's
//! own superblock, Merkle root and AEAD decide whether those blocks are a
//! volume. What this module guarantees is that the kernel never addresses a
//! block outside the device because a table said so.

/// The Horus volume's partition type, 7b1c4a3e-5f2d-4e8a-9c61-0d2f3a4b5c6d, in
/// the on-disk byte order GPT uses (the first three fields little-endian).
/// Our own type rather than a generic "Linux data" one, so no other system's
/// tooling claims it, and so the swap partition's type below cannot be mistaken
/// for it.
pub const HORUS_VOLUME_TYPE: [u8; 16] = [
    0x3e, 0x4a, 0x1c, 0x7b, 0x2d, 0x5f, 0x8a, 0x4e, 0x9c, 0x61, 0x0d, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d,
];

/// The Horus swap partition's type, 7b1c4a3e-5f2d-4e8a-9c61-0d2f3a4b5c6e, on
/// disk. Reserved by the installer and used by nothing yet, so the kernel has no
/// use for it; it is here, beside the volume's, so the two are seen to differ.
/// NOT the Linux swap type: a Linux system booted on this machine activates any
/// partition of that type on its own, and would write its memory, unencrypted,
/// over ours.
#[cfg(test)]
pub const HORUS_SWAP_TYPE: [u8; 16] = [
    0x3e, 0x4a, 0x1c, 0x7b, 0x2d, 0x5f, 0x8a, 0x4e, 0x9c, 0x61, 0x0d, 0x2f, 0x3a, 0x4b, 0x5c, 0x6e,
];

/// GPT addresses 512-byte sectors; the volume is addressed in 4 KiB blocks.
pub const SECTOR: u64 = 512;
pub const SECTORS_PER_BLOCK: u64 = 8;
const ENTRY_SIZE: usize = 128;

/// No GPT on this device: the caller may treat it as a whole-device volume, as
/// before. The ONLY error after which that is allowed; every other one means a
/// table is there and is wrong, and the device is refused.
pub const GPT_NONE: i32 = -1;
pub const GPT_BAD_HEADER: i32 = -2;
pub const GPT_BAD_ENTRIES: i32 = -3;
pub const GPT_BAD_ENTRIES_CRC: i32 = -4;
pub const GPT_NO_VOLUME: i32 = -5;
pub const GPT_TWO_VOLUMES: i32 = -6;
pub const GPT_BAD_RANGE: i32 = -7;

/// CRC-32 (IEEE 802.3, reflected, as GPT uses), continued from `crc`. Start a
/// fresh one with `!0` and finish with `!`. Bitwise rather than table-driven:
/// a few hundred bytes are checked once per boot, and a table is 1 KiB of
/// constants nobody can review at a glance.
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc
}

pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// Turn a partition's inclusive sector range into the 4 KiB blocks the kernel
/// will address: `(first block, block count)`, or `None`.
///
/// THIS IS THE FUNCTION THE KERNEL'S SAFETY RESTS ON, and the one Kani proves
/// (`gpt_volume_is_inside_the_device`): any `Some` it returns is non-empty and
/// lies wholly inside `[0, device_blocks)`, after the end of the entry array
/// (`table_end`, in sectors) and inside the header's usable range. Every input
/// is a number off the disk except `device_blocks`.
pub fn volume_blocks(
    first: u64,
    last: u64,
    first_usable: u64,
    last_usable: u64,
    table_end: u64,
    device_blocks: u64,
) -> Option<(u64, u64)> {
    if first > last || first < first_usable || last > last_usable || first < table_end {
        return None;
    }
    // 4 KiB aligned at both ends, so the range is a whole number of blocks.
    if !first.is_multiple_of(SECTORS_PER_BLOCK) {
        return None;
    }
    let end = last.checked_add(1)?; // exclusive, in sectors
    if !end.is_multiple_of(SECTORS_PER_BLOCK) {
        return None;
    }
    let base = first / SECTORS_PER_BLOCK;
    let count = (end - first) / SECTORS_PER_BLOCK;
    // Inside the device the kernel can address, which may be smaller than the
    // disk the table describes (BLOCKS_PER_DISK caps it).
    if count == 0 || base.checked_add(count)? > device_blocks {
        return None;
    }
    Some((base, count))
}

/// Find the Horus volume in the first `buf.len()` bytes of a device holding
/// `device_blocks` 4 KiB blocks. Returns `(first block, block count)` or one
/// of the `GPT_*` codes.
pub fn find_volume(buf: &[u8], device_blocks: u64) -> Result<(u64, u64), i32> {
    let hdr = buf.get(SECTOR as usize..2 * SECTOR as usize).ok_or(GPT_NONE)?;
    if &hdr[0..8] != b"EFI PART" {
        return Err(GPT_NONE);
    }

    // The header. Its CRC covers `header_size` bytes with the CRC field itself
    // taken as zero.
    let header_size = rd_u32(hdr, 12).ok_or(GPT_BAD_HEADER)? as usize;
    if !(92..=SECTOR as usize).contains(&header_size) {
        return Err(GPT_BAD_HEADER);
    }
    let stored = rd_u32(hdr, 16).ok_or(GPT_BAD_HEADER)?;
    let mut c = crc32_update(!0, &hdr[0..16]);
    c = crc32_update(c, &[0u8; 4]);
    c = crc32_update(c, &hdr[20..header_size]);
    if !c != stored {
        return Err(GPT_BAD_HEADER);
    }
    if rd_u64(hdr, 24) != Some(1) {
        return Err(GPT_BAD_HEADER); // not the primary header, or not where it says
    }
    let first_usable = rd_u64(hdr, 40).ok_or(GPT_BAD_HEADER)?;
    let last_usable = rd_u64(hdr, 48).ok_or(GPT_BAD_HEADER)?;
    let entries_lba = rd_u64(hdr, 72).ok_or(GPT_BAD_HEADER)?;
    let num = rd_u32(hdr, 80).ok_or(GPT_BAD_HEADER)? as usize;
    let size = rd_u32(hdr, 84).ok_or(GPT_BAD_HEADER)? as usize;
    let entries_crc = rd_u32(hdr, 88).ok_or(GPT_BAD_HEADER)?;

    // The entry array, wholly inside what the caller read.
    if size != ENTRY_SIZE || num == 0 || entries_lba < 2 {
        return Err(GPT_BAD_ENTRIES);
    }
    let start = usize::try_from(entries_lba.checked_mul(SECTOR).ok_or(GPT_BAD_ENTRIES)?)
        .map_err(|_| GPT_BAD_ENTRIES)?;
    let span = num.checked_mul(size).ok_or(GPT_BAD_ENTRIES)?;
    let end = start.checked_add(span).ok_or(GPT_BAD_ENTRIES)?;
    let entries = buf.get(start..end).ok_or(GPT_BAD_ENTRIES)?;
    // GPT_ENTRIES_CRC_UNCHECKED=1 (the `gpt_entries_crc_unchecked` feature)
    // removes this check: the control arm for make smoke-gpt-volume. The
    // header's CRC covers only the array's CRC FIELD, not the entries, so this
    // is the one check that catches an entry edited on the disk.
    if !cfg!(feature = "gpt_entries_crc_unchecked") && crc32(entries) != entries_crc {
        return Err(GPT_BAD_ENTRIES_CRC);
    }
    // The first sector after the array: no partition may start before it.
    let table_end = (end as u64).div_ceil(SECTOR);

    let mut found: Option<(u64, u64)> = None;
    let (rows, _) = entries.as_chunks::<ENTRY_SIZE>(); // span is a multiple of the size
    for e in rows {
        if e[0..16] != HORUS_VOLUME_TYPE {
            continue;
        }
        if found.is_some() {
            return Err(GPT_TWO_VOLUMES);
        }
        let first = rd_u64(e, 32).ok_or(GPT_BAD_RANGE)?;
        let last = rd_u64(e, 40).ok_or(GPT_BAD_RANGE)?;
        found = Some(
            volume_blocks(first, last, first_usable, last_usable, table_end, device_blocks)
                .ok_or(GPT_BAD_RANGE)?,
        );
    }
    found.ok_or(GPT_NO_VOLUME)
}

/// FFI entry: find the Horus volume on a device. `buf` holds the device's
/// first `buf_len` bytes (block 0 onwards); `device_blocks` is how many 4 KiB
/// blocks the kernel can address on it. On success writes the volume's first
/// block and block count and returns 0; otherwise returns a `GPT_*` code and
/// writes nothing. `GPT_NONE` (-1) alone means "no table": every other code
/// means a table that is present and refused.
///
/// # Safety
/// `buf` must point to `buf_len` readable bytes, and `out_base` and
/// `out_count` must each be a writable, aligned `u64`. Null pointers are
/// checked here and refused with `GPT_BAD_HEADER`; nothing else about the
/// buffer's contents is assumed, since they are read off the disk.
#[no_mangle]
pub unsafe extern "C" fn rust_gpt_find_volume(
    buf: *const u8,
    buf_len: usize,
    device_blocks: u64,
    out_base: *mut u64,
    out_count: *mut u64,
) -> i32 {
    if buf.is_null() || out_base.is_null() || out_count.is_null() {
        return GPT_BAD_HEADER;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    match find_volume(s, device_blocks) {
        Ok((base, count)) => {
            *out_base = base;
            *out_count = count;
            0
        }
        Err(code) => code,
    }
}

#[cfg(kani)]
mod gpt_kani_proofs {
    use super::*;

    /// Whatever the disk says, an accepted volume is a non-empty run of whole
    /// blocks inside the device, starting after the partition table and inside
    /// the header's usable range: for every u64 the table can hold, overflow
    /// included. Stated in sectors as well as blocks, so a version that
    /// converted wrongly could not satisfy it.
    #[kani::proof]
    fn gpt_volume_is_inside_the_device() {
        let (first, last, fu, lu, te, dev): (u64, u64, u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        if let Some((base, count)) = volume_blocks(first, last, fu, lu, te, dev) {
            assert!(count > 0, "an empty volume was accepted");
            assert!(base.checked_add(count).is_some_and(|e| e <= dev), "the volume runs past the device");
            assert!(base * SECTORS_PER_BLOCK == first, "the first block is not the first sector");
            assert!(base * SECTORS_PER_BLOCK >= te, "the volume overlaps the partition table");
            assert!(first >= fu && last <= lu, "the volume is outside the usable range");
            assert!((base + count) * SECTORS_PER_BLOCK == last + 1, "the block count is not the sector range");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    const DEV_BLOCKS: u64 = 1 << 20; // 4 GiB

    /// A disk image's first 32 KiB with a valid GPT: entries at LBA 2, usable
    /// from sector 2048, and the given partitions (type, first, last).
    fn disk(parts: &[([u8; 16], u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 32768];
        let num = 128usize;
        for (i, (t, f, l)) in parts.iter().enumerate() {
            let e = 1024 + i * ENTRY_SIZE;
            b[e..e + 16].copy_from_slice(t);
            b[e + 16] = i as u8 + 1; // a nonzero unique GUID
            b[e + 32..e + 40].copy_from_slice(&f.to_le_bytes());
            b[e + 40..e + 48].copy_from_slice(&l.to_le_bytes());
        }
        let ecrc = crc32(&b[1024..1024 + num * ENTRY_SIZE]);
        let h = 512;
        b[h..h + 8].copy_from_slice(b"EFI PART");
        b[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        b[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes());
        b[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes());
        b[h + 32..h + 40].copy_from_slice(&(DEV_BLOCKS * 8 - 1).to_le_bytes());
        b[h + 40..h + 48].copy_from_slice(&2048u64.to_le_bytes());
        b[h + 48..h + 56].copy_from_slice(&(DEV_BLOCKS * 8 - 34).to_le_bytes());
        b[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
        b[h + 80..h + 84].copy_from_slice(&(num as u32).to_le_bytes());
        b[h + 84..h + 88].copy_from_slice(&(ENTRY_SIZE as u32).to_le_bytes());
        b[h + 88..h + 92].copy_from_slice(&ecrc.to_le_bytes());
        reseal(&mut b);
        b
    }

    fn reseal(b: &mut [u8]) {
        b[512 + 16..512 + 20].copy_from_slice(&[0; 4]);
        let c = crc32(&b[512..512 + 92]);
        b[512 + 16..512 + 20].copy_from_slice(&c.to_le_bytes());
    }

    const ESP: [u8; 16] = [0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b];

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn the_installer_layout_is_found() {
        // ESP 1 MiB..65 MiB, swap, then the volume.
        let d = disk(&[(ESP, 2048, 133119), (HORUS_SWAP_TYPE, 133120, 1181695), (HORUS_VOLUME_TYPE, 1181696, 2097151)]);
        assert_eq!(find_volume(&d, DEV_BLOCKS), Ok((1181696 / 8, (2097152 - 1181696) / 8)));
    }

    #[test]
    fn no_signature_is_the_only_soft_answer() {
        assert_eq!(find_volume(&[0u8; 32768], DEV_BLOCKS), Err(GPT_NONE));
        assert_eq!(find_volume(&[0u8; 100], DEV_BLOCKS), Err(GPT_NONE));
    }

    #[test]
    fn a_corrupt_header_is_refused_not_ignored() {
        let mut d = disk(&[(HORUS_VOLUME_TYPE, 2048, 4095)]);
        d[512 + 40] ^= 1; // first_usable, without resealing
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_BAD_HEADER));
    }

    #[test]
    fn a_corrupt_entry_array_is_refused() {
        let mut d = disk(&[(HORUS_VOLUME_TYPE, 2048, 4095)]);
        d[1024 + 32] = 0x08; // move the start, header untouched
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_BAD_ENTRIES_CRC));
    }

    #[test]
    fn two_volumes_are_refused_not_chosen_between() {
        let d = disk(&[(HORUS_VOLUME_TYPE, 2048, 4095), (HORUS_VOLUME_TYPE, 4096, 8191)]);
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_TWO_VOLUMES));
    }

    #[test]
    fn a_disk_without_a_volume_is_refused() {
        let d = disk(&[(ESP, 2048, 4095)]);
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_NO_VOLUME));
    }

    #[test]
    fn a_volume_past_the_device_is_refused() {
        // Inside the header's usable range, but beyond what the kernel addresses.
        let d = disk(&[(HORUS_VOLUME_TYPE, 2048, DEV_BLOCKS * 8 + 8191)]);
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_BAD_RANGE));
    }

    #[test]
    fn a_misaligned_volume_is_refused() {
        assert_eq!(find_volume(&disk(&[(HORUS_VOLUME_TYPE, 2049, 4096)]), DEV_BLOCKS), Err(GPT_BAD_RANGE));
        assert_eq!(find_volume(&disk(&[(HORUS_VOLUME_TYPE, 2048, 4094)]), DEV_BLOCKS), Err(GPT_BAD_RANGE));
    }

    #[test]
    fn a_volume_over_the_table_is_refused() {
        // first_usable lowered to 0 and resealed, so only table_end stands in the way.
        let mut d = disk(&[(HORUS_VOLUME_TYPE, 0, 4095)]);
        d[512 + 40..512 + 48].copy_from_slice(&0u64.to_le_bytes());
        reseal(&mut d);
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_BAD_RANGE));
    }

    #[test]
    fn an_entry_array_past_the_buffer_is_refused() {
        let mut d = disk(&[(HORUS_VOLUME_TYPE, 2048, 4095)]);
        d[512 + 80..512 + 84].copy_from_slice(&1024u32.to_le_bytes()); // 128 KiB of entries
        reseal(&mut d);
        assert_eq!(find_volume(&d, DEV_BLOCKS), Err(GPT_BAD_ENTRIES));
    }

    #[test]
    fn the_ffi_refuses_null_pointers() {
        let mut o = 0u64;
        let r = unsafe { rust_gpt_find_volume(core::ptr::null(), 0, 1, &mut o, &mut o) };
        assert_eq!(r, GPT_BAD_HEADER);
    }
}
