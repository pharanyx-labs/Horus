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
/// disk. Reserved by the installer and used by nothing yet. NOT the Linux swap
/// type: a Linux system booted on this machine activates any partition of that
/// type on its own, and would write its memory, unencrypted, over ours.
pub const HORUS_SWAP_TYPE: [u8; 16] = [
    0x3e, 0x4a, 0x1c, 0x7b, 0x2d, 0x5f, 0x8a, 0x4e, 0x9c, 0x61, 0x0d, 0x2f, 0x3a, 0x4b, 0x5c, 0x6e,
];

/// The EFI system partition's type, c12a7328-f81f-11d2-ba4b-00a0c93ec93b, on
/// disk: the one type every UEFI firmware looks for.
pub const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
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
/// The swap partition's own refusals (find_swap). A table that is refused for
/// the volume is refused for swap with the same code first.
pub const GPT_NO_SWAP: i32 = -8;
pub const GPT_TWO_SWAPS: i32 = -9;
pub const GPT_SWAP_OVERLAPS: i32 = -10;

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
    find_part(buf, device_blocks, &HORUS_VOLUME_TYPE, GPT_TWO_VOLUMES)?.ok_or(GPT_NO_VOLUME)
}

/// Find the Horus swap partition on the same table, which must also carry the
/// volume (swap is only ever used beside an unlocked volume, on its disk), and
/// must not share a block with it: a table edited to lay swap over the volume
/// would otherwise have the kernel write sealed pages over the filesystem.
pub fn find_swap(buf: &[u8], device_blocks: u64) -> Result<(u64, u64), i32> {
    let vol = find_volume(buf, device_blocks)?;
    let swap = find_part(buf, device_blocks, &HORUS_SWAP_TYPE, GPT_TWO_SWAPS)?.ok_or(GPT_NO_SWAP)?;
    if !ranges_disjoint(vol.0, vol.1, swap.0, swap.1) {
        return Err(GPT_SWAP_OVERLAPS);
    }
    Ok(swap)
}

/// Do `[a, a + na)` and `[b, b + nb)` share no block? An end that overflows is
/// taken as overlapping everything, so a range that wraps can never pass.
pub fn ranges_disjoint(a: u64, na: u64, b: u64, nb: u64) -> bool {
    match (a.checked_add(na), b.checked_add(nb)) {
        (Some(ea), Some(eb)) => ea <= b || eb <= a,
        _ => false,
    }
}

/// The one partition of type `ty` in a verified table, `None` if there is none,
/// and `two` if there are more than one.
fn find_part(buf: &[u8], device_blocks: u64, ty: &[u8; 16], two: i32) -> Result<Option<(u64, u64)>, i32> {
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
        if e[0..16] != ty[..] {
            continue;
        }
        if found.is_some() {
            return Err(two);
        }
        let first = rd_u64(e, 32).ok_or(GPT_BAD_RANGE)?;
        let last = rd_u64(e, 40).ok_or(GPT_BAD_RANGE)?;
        found = Some(
            volume_blocks(first, last, first_usable, last_usable, table_end, device_blocks)
                .ok_or(GPT_BAD_RANGE)?,
        );
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// Writing a table: the installer's layout (docs/design/installed-system.md
// section 6). The kernel writes it, from the operator's sizes, when the
// installer asks for a disk that boots itself.

/// Where the layout starts: 1 MiB in, past the protective MBR and the primary
/// table, and aligned for any flash erase block.
pub const LEAD_BLOCKS: u64 = 256;
/// The 1 MiB kept free at the end for the backup table (the last 33 sectors).
pub const TAIL_BLOCKS: u64 = 256;
/// The EFI system partition: 64 MiB, room for GRUB, the kernel and its modules
/// in a FAT32 filesystem (whose own minimum is about 33 MiB).
pub const ESP_BLOCKS: u64 = 16384;
/// The table's bytes at each end of the disk: five blocks, the least that holds
/// the MBR, a header and 128 entries (primary) or 128 entries and a header
/// (backup, in the last 33 sectors).
pub const TABLE_BLOCKS: usize = 5;
pub const TABLE_BYTES: usize = TABLE_BLOCKS * 4096;

/// A planned layout, in 4 KiB blocks: (first block, block count) for each
/// partition. `swap.1` is 0 when no swap partition is laid out.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GptLayout {
    pub esp_base: u64,
    pub esp_count: u64,
    pub swap_base: u64,
    pub swap_count: u64,
    pub volume_base: u64,
    pub volume_count: u64,
}

/// Lay out ESP, swap and volume on a device of `device_blocks` blocks, from the
/// operator's sizes: `swap_blocks` (0 for none) and `volume_blocks` (0 for the
/// rest of the device). `None` if they do not fit with a volume of at least
/// `min_volume` blocks.
///
/// Proved by Kani (`gpt_plan_is_inside_the_device`): any layout it returns has
/// the three partitions in order, without overlap, after the primary table and
/// before the backup, and a volume no smaller than asked for.
pub fn plan(device_blocks: u64, swap_blocks: u64, volume_blocks: u64, min_volume: u64) -> Option<GptLayout> {
    let esp_base = LEAD_BLOCKS;
    let swap_base = esp_base.checked_add(ESP_BLOCKS)?;
    let volume_base = swap_base.checked_add(swap_blocks)?;
    let limit = device_blocks.checked_sub(TAIL_BLOCKS)?; // first block of the tail
    let room = limit.checked_sub(volume_base)?;
    let volume_count = if volume_blocks == 0 { room } else { volume_blocks };
    if volume_count < min_volume || volume_count == 0 || volume_count > room {
        return None;
    }
    Some(GptLayout {
        esp_base,
        esp_count: ESP_BLOCKS,
        swap_base,
        swap_count: swap_blocks,
        volume_base,
        volume_count,
    })
}

fn put(b: &mut [u8], off: usize, v: &[u8]) {
    b[off..off + v.len()].copy_from_slice(v);
}

fn entry_bytes(e: &mut [u8], ty: &[u8; 16], unique: &[u8; 16], base: u64, count: u64, name: &str) {
    put(e, 0, ty);
    put(e, 16, unique);
    put(e, 32, &(base * SECTORS_PER_BLOCK).to_le_bytes());
    put(e, 40, &((base + count) * SECTORS_PER_BLOCK - 1).to_le_bytes());
    for (i, c) in name.encode_utf16().take(36).enumerate() {
        put(e, 56 + 2 * i, &c.to_le_bytes());
    }
}

/// What the primary and backup headers share.
struct HeaderCommon<'a> {
    first_usable: u64,
    last_usable: u64,
    disk: &'a [u8; 16],
    entries_crc: u32,
}

fn header_bytes(h: &mut [u8], my: u64, alt: u64, entries_lba: u64, c: &HeaderCommon) {
    let (fu, lu, disk, ecrc) = (c.first_usable, c.last_usable, c.disk, c.entries_crc);
    put(h, 0, b"EFI PART");
    put(h, 8, &0x0001_0000u32.to_le_bytes());
    put(h, 12, &92u32.to_le_bytes());
    put(h, 24, &my.to_le_bytes());
    put(h, 32, &alt.to_le_bytes());
    put(h, 40, &fu.to_le_bytes());
    put(h, 48, &lu.to_le_bytes());
    put(h, 56, disk);
    put(h, 72, &entries_lba.to_le_bytes());
    put(h, 80, &128u32.to_le_bytes());
    put(h, 84, &(ENTRY_SIZE as u32).to_le_bytes());
    put(h, 88, &ecrc.to_le_bytes());
    let c = crc32(&h[0..92]);
    put(h, 16, &c.to_le_bytes());
}

/// Which end of the disk a table write is for.
pub const SIDE_HEAD: u32 = 0;
pub const SIDE_TAIL: u32 = 1;

/// Write one end of the table for `l` on a device of `device_blocks` blocks
/// into `buf`: SIDE_HEAD is the device's first TABLE_BYTES (protective MBR,
/// primary header, entries), SIDE_TAIL its last TABLE_BYTES (backup entries,
/// backup header in the last sector). `guids` are the disk's and the three
/// partitions' unique GUIDs. `buf` is written whole, zeros included.
///
/// ONE END AT A TIME, IN PLACE: the entries are written straight into `buf`
/// and their CRC taken from there, so nothing large lives on the stack. This
/// runs in the kernel, whose stacks have no room for two 20 KiB tables. Both
/// ends write the same entries, so they carry the same CRC.
pub fn build_side(l: &GptLayout, device_blocks: u64, guids: &[[u8; 16]; 4], side: u32, buf: &mut [u8; TABLE_BYTES]) {
    buf.fill(0);
    let sectors = device_blocks * SECTORS_PER_BLOCK;
    let last = sectors - 1;
    let table_sectors = (128 * ENTRY_SIZE) as u64 / SECTOR; // 32
    let tail_first = sectors - (TABLE_BYTES as u64 / SECTOR);
    let backup_entries_lba = last - table_sectors;
    let (eoff, hoff, entries_lba, my, alt) = if side == SIDE_HEAD {
        (1024usize, 512usize, 2u64, 1u64, last)
    } else {
        (((backup_entries_lba - tail_first) * SECTOR) as usize, ((last - tail_first) * SECTOR) as usize, backup_entries_lba, last, 1u64)
    };

    {
        let entries = &mut buf[eoff..eoff + 128 * ENTRY_SIZE];
        let mut n = 0;
        entry_bytes(&mut entries[0..ENTRY_SIZE], &ESP_TYPE, &guids[1], l.esp_base, l.esp_count, "EFI system");
        n += 1;
        if l.swap_count > 0 {
            entry_bytes(&mut entries[n * ENTRY_SIZE..(n + 1) * ENTRY_SIZE], &HORUS_SWAP_TYPE, &guids[2], l.swap_base, l.swap_count, "Horus swap");
            n += 1;
        }
        entry_bytes(&mut entries[n * ENTRY_SIZE..(n + 1) * ENTRY_SIZE], &HORUS_VOLUME_TYPE, &guids[3], l.volume_base, l.volume_count, "Horus volume");
    }
    let ecrc = crc32(&buf[eoff..eoff + 128 * ENTRY_SIZE]);
    let common = HeaderCommon {
        first_usable: 2 + table_sectors,
        last_usable: last - 1 - table_sectors,
        disk: &guids[0],
        entries_crc: ecrc,
    };
    header_bytes(&mut buf[hoff..hoff + 512], my, alt, entries_lba, &common);

    if side == SIDE_HEAD {
        // Protective MBR: one partition of type 0xEE covering the disk, so a
        // tool that knows only MBR sees the disk as in use rather than empty.
        let mbr_len = core::cmp::min(last, 0xFFFF_FFFF) as u32;
        put(buf, 446, &[0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF]);
        put(buf, 454, &1u32.to_le_bytes());
        put(buf, 458, &mbr_len.to_le_bytes());
        put(buf, 510, &[0x55, 0xAA]);
    }
}

/// FFI entry: plan the installer's layout without writing anything. 0 and
/// `*out`, or -1 if the sizes do not fit, or `GPT_BAD_HEADER` for a null `out`.
///
/// # Safety
/// `out` must be a writable, aligned `GptLayout`; it is checked for null and
/// written only on success. The sizes are numbers from ring 3 and are bounded
/// by `plan`, not assumed.
#[no_mangle]
pub unsafe extern "C" fn rust_gpt_plan(
    device_blocks: u64,
    swap_blocks: u64,
    volume_blocks: u64,
    min_volume: u64,
    out: *mut GptLayout,
) -> i32 {
    if out.is_null() {
        return GPT_BAD_HEADER;
    }
    match plan(device_blocks, swap_blocks, volume_blocks, min_volume) {
        Some(l) => {
            *out = l;
            0
        }
        None => -1,
    }
}

/// FFI entry: write one end (`side`, SIDE_HEAD or SIDE_TAIL) of the table for
/// the layout `rust_gpt_plan` returns for the same sizes. Re-plans rather than
/// trusting a layout handed back from C, so the table written can only ever be
/// one `plan` accepted. 0, or -1 if the sizes do not fit, or `GPT_BAD_HEADER`
/// for a null, short or unknown argument; `buf` is untouched on any error.
///
/// # Safety
/// `guids` must point to 64 readable bytes, `buf` to `buf_len` writable bytes
/// (checked: anything under TABLE_BYTES is refused), and the two must not
/// overlap. The sizes are bounded by `plan`, not assumed.
#[no_mangle]
pub unsafe extern "C" fn rust_gpt_build_side(
    device_blocks: u64,
    swap_blocks: u64,
    volume_blocks: u64,
    min_volume: u64,
    guids: *const u8,
    side: u32,
    buf: *mut u8,
    buf_len: usize,
) -> i32 {
    if guids.is_null() || buf.is_null() || buf_len < TABLE_BYTES || side > SIDE_TAIL {
        return GPT_BAD_HEADER;
    }
    let Some(l) = plan(device_blocks, swap_blocks, volume_blocks, min_volume) else {
        return -1;
    };
    let g = core::slice::from_raw_parts(guids, 64);
    let mut gs = [[0u8; 16]; 4];
    let (rows, _) = g.as_chunks::<16>();
    for (i, c) in rows.iter().enumerate() {
        gs[i] = *c;
    }
    let b = &mut *(buf as *mut [u8; TABLE_BYTES]);
    build_side(&l, device_blocks, &gs, side, b);
    0
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

/// Find the swap partition beside the volume: `rust_gpt_find_volume`'s contract,
/// with `find_swap`'s codes. Returns 0 and writes the range, or a `GPT_*` code
/// and writes nothing.
///
/// # Safety
/// `buf` must point to `buf_len` readable bytes, and `out_base` and
/// `out_count` must each be a writable, aligned `u64`. Null pointers are
/// checked here and refused with `GPT_BAD_HEADER`; the buffer's contents are
/// read off the disk and assumed nothing about.
#[no_mangle]
pub unsafe extern "C" fn rust_gpt_find_swap(
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
    match find_swap(s, device_blocks) {
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

    /// Whatever sizes the operator types, a planned layout keeps the ESP, swap
    /// and volume in that order without overlap, after the primary table and
    /// before the backup, and gives the volume at least `min_volume` blocks
    /// and exactly what was asked for when a size was given.
    #[kani::proof]
    fn gpt_plan_is_inside_the_device() {
        let (dev, swap, vol, min): (u64, u64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
        if let Some(l) = plan(dev, swap, vol, min) {
            assert!(l.esp_base >= LEAD_BLOCKS, "the ESP overlaps the primary table");
            assert!(l.esp_base + l.esp_count <= l.swap_base, "the ESP overlaps swap");
            assert!(l.swap_base + l.swap_count <= l.volume_base, "swap overlaps the volume");
            assert!(l.volume_count > 0 && l.volume_count >= min, "the volume is smaller than asked");
            assert!(vol == 0 || l.volume_count == vol, "the volume is not the size asked for");
            assert!(
                l.volume_base.checked_add(l.volume_count).is_some_and(|e| e <= dev - TAIL_BLOCKS),
                "the volume overlaps the backup table or runs past the device"
            );
        }
    }

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

    /// Whatever the table says, swap that is accepted shares no block with the
    /// volume: for every pair of ranges a u64 can describe, overflow included,
    /// no block lies in both. Stated per block, so a check that compared the
    /// wrong ends could not satisfy it.
    #[kani::proof]
    fn gpt_swap_never_overlaps_the_volume() {
        let (a, na, b, nb, x): (u64, u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        if ranges_disjoint(a, na, b, nb) {
            let in_a = x >= a && x - a < na;
            let in_b = x >= b && x - b < nb;
            assert!(!(in_a && in_b), "a block lies in both the volume and swap");
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
    fn swap_is_found_beside_the_volume() {
        let d = disk(&[(ESP, 2048, 133119), (HORUS_SWAP_TYPE, 133120, 1181695), (HORUS_VOLUME_TYPE, 1181696, 2097151)]);
        assert_eq!(find_swap(&d, DEV_BLOCKS), Ok((133120 / 8, (1181696 - 133120) / 8)));
    }

    #[test]
    fn swap_is_refused_when_it_is_missing_doubled_alone_or_over_the_volume() {
        let none = disk(&[(HORUS_VOLUME_TYPE, 2048, 4095)]);
        assert_eq!(find_swap(&none, DEV_BLOCKS), Err(GPT_NO_SWAP));
        let two = disk(&[(HORUS_SWAP_TYPE, 2048, 4095), (HORUS_SWAP_TYPE, 4096, 8191), (HORUS_VOLUME_TYPE, 8192, 16383)]);
        assert_eq!(find_swap(&two, DEV_BLOCKS), Err(GPT_TWO_SWAPS));
        let alone = disk(&[(HORUS_SWAP_TYPE, 2048, 4095)]);
        assert_eq!(find_swap(&alone, DEV_BLOCKS), Err(GPT_NO_VOLUME));
        let over = disk(&[(HORUS_SWAP_TYPE, 2048, 8191), (HORUS_VOLUME_TYPE, 4096, 16383)]);
        assert_eq!(find_swap(&over, DEV_BLOCKS), Err(GPT_SWAP_OVERLAPS));
        // The volume itself is still found on a table whose swap overlaps it:
        // the refusal is swap's alone.
        assert!(find_volume(&over, DEV_BLOCKS).is_ok());
    }

    #[test]
    fn disjoint_means_no_shared_block_and_a_wrapping_range_never_is() {
        assert!(ranges_disjoint(0, 10, 10, 5));
        assert!(ranges_disjoint(10, 5, 0, 10));
        assert!(!ranges_disjoint(0, 11, 10, 5));
        assert!(!ranges_disjoint(u64::MAX - 1, 5, 0, 1));
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

    fn written(dev: u64, swap: u64, vol: u64) -> (GptLayout, [u8; TABLE_BYTES], [u8; TABLE_BYTES]) {
        let l = plan(dev, swap, vol, 512).expect("fits");
        let g = [[1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16]];
        let (mut h, mut t) = ([0u8; TABLE_BYTES], [0u8; TABLE_BYTES]);
        build_side(&l, dev, &g, SIDE_HEAD, &mut h);
        build_side(&l, dev, &g, SIDE_TAIL, &mut t);
        (l, h, t)
    }

    #[test]
    fn a_written_table_is_read_back_by_the_parser() {
        for (swap, vol) in [(0, 0), (262144, 0), (262144, 1 << 19), (0, 4096)] {
            let (l, h, _) = written(DEV_BLOCKS, swap, vol);
            assert_eq!(find_volume(&h, DEV_BLOCKS), Ok((l.volume_base, l.volume_count)), "swap {swap} vol {vol}");
        }
    }

    #[test]
    fn the_written_table_is_what_fdisk_expects() {
        let (_, h, t) = written(DEV_BLOCKS, 262144, 0);
        assert_eq!(&h[510..512], &[0x55, 0xAA]);
        assert_eq!(h[446 + 4], 0xEE);
        // The backup header is in the device's last sector, names itself, and
        // points back at the primary.
        let bh = &t[TABLE_BYTES - 512..];
        assert_eq!(&bh[0..8], b"EFI PART");
        assert_eq!(rd_u64(bh, 24), Some(DEV_BLOCKS * 8 - 1));
        assert_eq!(rd_u64(bh, 32), Some(1));
        // Both entry arrays are the same bytes.
        assert_eq!(&h[1024..1024 + 16384], &t[TABLE_BYTES - 512 - 16384..TABLE_BYTES - 512]);
    }

    #[test]
    fn sizes_that_do_not_fit_are_refused() {
        assert_eq!(plan(DEV_BLOCKS, DEV_BLOCKS, 0, 512), None);           // swap the size of the disk
        assert_eq!(plan(DEV_BLOCKS, 0, DEV_BLOCKS, 512), None);           // volume the size of the disk
        assert_eq!(plan(LEAD_BLOCKS + ESP_BLOCKS + TAIL_BLOCKS + 100, 0, 0, 512), None); // too small
        assert_eq!(plan(100, 0, 0, 512), None);                           // smaller than the tail
        assert_eq!(plan(DEV_BLOCKS, u64::MAX, 0, 512), None);             // overflow
    }

    #[test]
    fn the_ffi_refuses_null_pointers() {
        let mut o = 0u64;
        let r = unsafe { rust_gpt_find_volume(core::ptr::null(), 0, 1, &mut o, &mut o) };
        assert_eq!(r, GPT_BAD_HEADER);
        let r = unsafe { rust_gpt_find_swap(core::ptr::null(), 0, 1, &mut o, &mut o) };
        assert_eq!(r, GPT_BAD_HEADER);
    }
}
