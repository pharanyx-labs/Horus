// no_std for the kernel staticlib. Two environments need std instead: the
// `fuzzing` feature (an rlib inside a std libFuzzer harness) and `cargo kani`
// (Kani links its own std, and its verification harnesses run there). In both,
// std also provides the panic handler, so ours below is gated off.
#![cfg_attr(not(any(feature = "fuzzing", kani)), no_std)]
// The page-fault / protection / demand-paging policy below is written as
// explicit `addr >= LO && addr < HI` window comparisons on purpose: the bounds
// are security-sensitive and read more auditably side-by-side than as range
// `.contains()` calls. Allow the lint crate-wide so a `-D warnings` CI gate
// stays meaningful (catches new issues) without mechanically rewriting them.
#![allow(clippy::manual_range_contains)]

// `alloc` is only pulled in for host tests (the Argon2 memory buffer is large);
// the kernel build stays strictly `no_std`, no allocator.
#[cfg(test)]
extern crate alloc;

mod aead;
mod argon2;
mod blake2b;
mod audit;
mod auth;
mod capability;
mod crypto;
mod memory;
mod ps;
mod rng;
mod sha256;

// Present only when this crate is the final artifact (the kernel staticlib).
// Under `test`, the `fuzzing` feature, or `cargo kani`, the crate is compiled
// into a std binary that already provides a panic handler; defining a second one
// is a duplicate `panic_impl` lang item and will not link.
#[cfg(all(not(test), not(feature = "fuzzing"), not(kani)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[repr(C)]
pub struct SafeCap {
    pub raw: u32,
}

impl SafeCap {
    pub fn has_rights(&self, required: u32) -> bool {
        (self.raw & required) == required
    }
}

/// Low user stack window that `create_user_pagedir` premaps (32 pages below
/// `0x7ff000`). Fixed, so it is a constant here rather than a per-task bound.
const LOW_STACK_BASE: u64 = 0x7df000;
const LOW_STACK_TOP: u64 = 0x7ff000;

/// Is `fault_addr` a legitimate part of THIS task's user address space?
///
/// Region-aware: the caller passes the task's actual image and heap bounds
/// (`tasks[tid]`), and the fixed low-stack window is checked directly. Only these
/// regions are user memory; a fault anywhere else — the null page, the `[4, 16)`
/// MiB range that is the kernel's own `.bss` reached through supervisor mappings,
/// the gaps between regions, kernel space — is a real access violation, so it
/// returns `false` and the fault handler routes it to the task's SIGSEGV handler
/// (or a kill), never a blessed-but-unmappable page the pager silently declines.
///
/// This is the single source of truth for "valid user address": the demand pager
/// gates a demand-zero mapping on it (so it never maps an arbitrary address), and
/// the fault handler uses it for the SIGSEGV-vs-diagnostic decision.
#[no_mangle]
pub extern "C" fn rust_validate_page_fault(
    fault_addr: u64,
    _error_code: u32,
    image_base: u64,
    image_end: u64,
    heap_start: u64,
    heap_end: u64,
) -> bool {
    // Image: code, rodata, data, bss. image_base is 0 only for an unbuilt task.
    if image_base != 0 && fault_addr >= image_base && fault_addr < image_end {
        return true;
    }
    // Demand-paged heap: [heap_start, heap_end), the sbrk-authorized ceiling.
    if heap_start != 0 && fault_addr >= heap_start && fault_addr < heap_end {
        return true;
    }
    // Low user stack (premapped, so it does not demand-fault; included so a
    // protection fault on a present stack page is still classed as in-region).
    if fault_addr >= LOW_STACK_BASE && fault_addr < LOW_STACK_TOP {
        return true;
    }
    false
}

#[repr(C)]
pub struct SafeCapability {
    pub raw: u32,
}

/// # Safety
/// `cap` must be null or a valid, aligned pointer to a `SafeCapability` that
/// stays live for the call. Null is handled; any other invalid pointer is UB.
#[no_mangle]
pub unsafe extern "C" fn rust_cap_has_rights(cap: *const SafeCapability, required: u32) -> bool {
    if cap.is_null() {
        return false;
    }
    ((*cap).raw & required) == required
}

#[no_mangle]
pub extern "C" fn rust_get_user_page_protection(_task_id: u32, vaddr: u64) -> u32 {
    // [0xA00000, 0xB00000) is deliberately absent. It used to be excluded because
    // the kernel was linked low and `argon2_scratch` occupied that virtual
    // address; the kernel now runs at KERNEL_VMA, so the reason is different but
    // the answer is the same — nothing maps it, and no task's image, heap or
    // stack lives there. rust_validate_page_fault is the per-task authority on
    // that; this is a coarse window check for the premap's protection bits.
    if (vaddr >= 0x400000 && vaddr < 0x800000) ||
       (vaddr >= 0x1000000 && vaddr < 0x5000000) ||   // demand-paged heap
       (vaddr >= 0x7FC000 && vaddr < 0x800000) ||
       (vaddr >= 0xff000000 && vaddr < 0xfff00000) {
        return 0x7;
    }
    0
}

/// W^X policy: is the user page at `vaddr` non-executable?
///
/// User stacks must never be executable -- mapping them no-execute (the PTE NX
/// bit, honoured because EFER.NXE is enabled) defeats classic shellcode on the
/// stack. The kernel ORs `PAGE_NX` into a stack page's PTE when this returns
/// true. The image/heap region (from `USER_AREA_BASE` upward) stays executable:
/// the flat-binary loader cannot distinguish code from data within it, so it
/// must remain runnable. Takes a full 64-bit vaddr so the high ASLR stack is
/// expressible (unlike `rust_get_user_page_protection`, which is u32).
#[no_mangle]
pub extern "C" fn rust_user_page_is_noexec(vaddr: u64) -> bool {
    // Low user stack: top of the 4-8 MB user area. The loaded image starts at
    // 0x400000 and is at most 1 MB tall, and the heap tops out well under
    // 0x520000, so nothing executable lives at or above 0x7d0000.
    if (0x0000_0000_007d_0000..0x0000_0000_0080_0000).contains(&vaddr) {
        return true;
    }
    // High ASLR stack window around 0x7ff0_0000_0000.
    const HIGH_STACK_BASE: u64 = 0x0000_7ff0_0000_0000;
    if (HIGH_STACK_BASE - 0x10_0000..HIGH_STACK_BASE + 0x10_0000).contains(&vaddr) {
        return true;
    }
    false
}

/// # Safety
/// `cmd` must be null or point to at least `len` initialized bytes that stay
/// live for the call. Null is handled; any other invalid (pointer, len) is UB.
#[no_mangle]
pub unsafe extern "C" fn rust_handle_command(cmd: *const u8, len: usize) -> i32 {
    if cmd.is_null() {
        return 0;
    }

    let cmd_slice = core::slice::from_raw_parts(cmd, len);
    let cmd_str = match core::str::from_utf8(cmd_slice) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };

    if cmd_str == "help" { return 42; }
    if cmd_str == "version" { return 43; }
    if cmd_str.starts_with("echo ") { return 44; }
    if cmd_str == "exit" { return 1; }
    if cmd_str == "uptime" { return 45; }
    if cmd_str == "ps" || cmd_str == "tasks" { return 46; }
    if cmd_str == "caps" { return 47; }
    if cmd_str == "clear" { return 48; }
    if cmd_str.starts_with("kill ") { return 49; }
    if cmd_str.starts_with("mint ") { return 50; }
    if cmd_str == "rotate_keys" { return 36; }
    if cmd_str.starts_with("fs ") || cmd_str.starts_with("cap_") { return 52; }

    -1
}

#[no_mangle]
pub extern "C" fn rust_cow_copy_required(is_cow: bool, is_write: bool, ref_count: u16) -> bool {
    is_cow && is_write && ref_count > 1
}

#[no_mangle]
pub extern "C" fn rust_should_demand_zero(err_code: u32) -> bool {
    (err_code & 1) == 0 && (err_code & 4) != 0
}

/// Validate a would-be ring-3 signal-handler entry address against *this task's*
/// image. On a fault the kernel iretq's ring 3 to this address, so it must be a
/// plausible user *code* location; anything else (the stack, the heap, the
/// kernel image, an unmapped address, or 0) is rejected so a task cannot
/// register a handler that redirects control flow somewhere it should not run.
/// Pure value predicate — no pointer deref.
///
/// The bound is the caller's own `[image_base, image_end)` rather than a fixed
/// window. It used to be a hardcoded `[0x400000, 0x800000)`, which was both too
/// loose and too tight: too loose because a task could name any address in that
/// 4 MiB whether or not its image reached there — image-base ASLR randomises the
/// load address, so most of the window was *not* the task's code — and too tight
/// because the window was `u32`, so an image loaded above 4 GiB could not
/// express a legal handler at all. Per-task bounds are strictly stronger: the
/// handler must be inside the code the task actually loaded.
#[no_mangle]
pub extern "C" fn rust_signal_handler_addr_ok(vaddr: u64, image_base: u64, image_end: u64) -> bool {
    // A task with no image recorded has no code to point at. Fail closed rather
    // than fall back to a default window.
    if image_base == 0 || image_end <= image_base {
        return false;
    }
    vaddr >= image_base && vaddr < image_end
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FsOp {
    Lookup = 0,
    Create = 1,
    Delete = 2,
    Read   = 3,
    Write  = 4,
    Mint   = 5,
}

#[no_mangle]
pub extern "C" fn rust_validate_fs_operation(
    task_id: u32,
    _op: u32,
    rights_held: u32,
    name_ptr: *const u8,
    name_len: usize,
) -> i32 {
    if !name_ptr.is_null() && name_len > 0 && name_len < 32 {
        let _ = (task_id,);
    }

    if rights_held == 0 {
        return -1;
    }

    0
}

/// Constant-time equality of two `len`-byte buffers. Returns 1 if equal, else 0;
/// the running time depends only on `len`, never on where or how many bytes
/// differ, so a mismatch leaks no timing oracle. Single Rust source of truth for
/// comparing secret material (password hashes, the user-database integrity tag),
/// replacing the hand-rolled C `constant_time_compare` in kusers.c. Same 1=equal
/// convention as `rust_audit_mac_eq`, but length-generic.
///
/// # Safety
/// `a` and `b` must each point to `len` readable bytes. A null pointer or an
/// empty comparison (`len == 0`) returns 0 (fail closed) rather than vacuously
/// "equal" — no caller compares zero-length secrets, and equal-by-default on an
/// empty buffer is a footgun for an equality-of-secrets primitive.
#[no_mangle]
pub unsafe extern "C" fn rust_ct_eq(a: *const u8, b: *const u8, len: usize) -> i32 {
    if a.is_null() || b.is_null() || len == 0 {
        return 0;
    }
    let sa = core::slice::from_raw_parts(a, len);
    let sb = core::slice::from_raw_parts(b, len);
    let mut diff = 0u8;
    for i in 0..len {
        diff |= sa[i] ^ sb[i];
    }
    (diff == 0) as i32
}

// ---------------------------------------------------------------------------
// ELF image header validation (J10.1).
//
// The ELF loader (src/kernel/loader.c: try_elf_load) parses a fully
// attacker-controlled program image. Moving the header parse — the part that
// reads untrusted offsets and lengths — into safe Rust means a malformed header
// can never cause an out-of-bounds read in the parser: every field access is a
// bounds-checked slice read. This is behaviour-preserving: the validator accepts
// exactly the images the C loader accepted and returns the SAME negative codes
// for each rejection, so smoke-elf / smoke-elf64 are unchanged. Only the parser's
// memory safety improves. The PT_LOAD segment walk still parses in C (a later
// change, J10.2, moves that too).
// ---------------------------------------------------------------------------

/// Validated ELF header fields — the identity plus the program-header locator.
/// Mirrors `struct elf_header_info` in src/include/kernel.h (identical field
/// order and repr(C) layout). Rust fills it; the C loader reads it only after
/// `rust_elf_validate_header` returns 0.
#[repr(C)]
#[derive(Clone, Copy)]
// Debug/PartialEq are only used by the unit tests' assert_eq!, so keep them out
// of the kernel staticlib (which is linked --whole-archive, pulling in even
// unused impls) rather than shipping code the kernel never runs.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ElfHeaderInfo {
    pub e_entry: u64,   // entry vaddr, zero-extended from the 32- or 64-bit field
    pub e_phoff: u32,   // program-header table offset (loader plumbing is 32-bit)
    pub e_type: u16,    // 2 = ET_EXEC, 3 = ET_DYN
    pub e_machine: u16, // 3 = EM_386, 62 = EM_X86_64
    pub e_phnum: u16,   // number of program headers, validated to 1..=8
    pub ei_class: u8,   // 1 = ELFCLASS32, 2 = ELFCLASS64
}

#[inline]
fn elf_rd_u16(s: &[u8], off: usize) -> Option<u16> {
    let b = s.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
#[inline]
fn elf_rd_u32(s: &[u8], off: usize) -> Option<u32> {
    let b = s.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
#[inline]
fn elf_rd_u64(s: &[u8], off: usize) -> Option<u64> {
    let b = s.get(off..off + 8)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}
/// Read an ELF64 8-byte field into the loader's 32-bit plumbing, refusing any
/// value that does not fit (the -17 case). Mirrors elf64_narrow in loader.c:
/// reading only the low half would defeat the downstream bounds checks. `Err(-2)`
/// on an out-of-bounds read (a truncated header; cannot happen for the real
/// MAX_PROGRAM_SIZE-sized staging buffer, but fails closed rather than reading
/// past the slice).
#[inline]
fn elf_narrow(s: &[u8], off: usize) -> Result<u32, i32> {
    let v = elf_rd_u64(s, off).ok_or(-2)?;
    if v > u32::MAX as u64 { return Err(-17); }
    Ok(v as u32)
}

/// Pure, panic-free ELF-header validator over a byte slice — the core exercised
/// by the unit tests, the fuzz target, and the Kani proof. `buf` is the staged
/// image; `buf.len()` is the size of the staging buffer (MAX_PROGRAM_SIZE in the
/// kernel). Returns the validated fields, or the loader's negative error code.
///
/// The check order mirrors try_elf_load exactly, so a header failing more than
/// one check yields the same code the C loader would have (e.g. an ELF64 header
/// with a narrowed e_phoff returns -17 before the e_type check).
fn validate_elf_header(buf: &[u8]) -> Result<ElfHeaderInfo, i32> {
    // ELF magic: 0x7f 'E' 'L' 'F'.
    if buf.get(0..4) != Some(&[0x7f, b'E', b'L', b'F'][..]) {
        return Err(-2);
    }
    let ei_class = *buf.get(4).ok_or(-2)?;
    let ei_data = *buf.get(5).ok_or(-2)?;
    if ei_data != 1 { return Err(-3); } // ELFDATA2LSB (little-endian) only

    let e_type = elf_rd_u16(buf, 16).ok_or(-2)?;
    let e_machine = elf_rd_u16(buf, 18).ok_or(-2)?;

    let (e_entry, e_phoff, e_phnum) = match ei_class {
        1 => {
            // ELFCLASS32: e_machine EM_386, 32-bit e_entry/e_phoff, e_phnum @44.
            if e_machine != 3 { return Err(-4); }
            let entry = elf_rd_u32(buf, 24).ok_or(-2)? as u64;
            let phoff = elf_rd_u32(buf, 28).ok_or(-2)?;
            let phnum = elf_rd_u16(buf, 44).ok_or(-2)?;
            (entry, phoff, phnum)
        }
        2 => {
            // ELFCLASS64: e_machine EM_X86_64, 64-bit e_entry, narrowed e_phoff,
            // e_phnum @56.
            if e_machine != 62 { return Err(-4); }
            let entry = elf_rd_u64(buf, 24).ok_or(-2)?;
            let phoff = elf_narrow(buf, 32)?;
            let phnum = elf_rd_u16(buf, 56).ok_or(-2)?;
            (entry, phoff, phnum)
        }
        _ => return Err(-5),
    };

    if e_type != 2 && e_type != 3 { return Err(-6); } // ET_EXEC | ET_DYN
    if e_phnum == 0 || e_phnum > 8 { return Err(-7); }
    // e_phoff in [1, buf.len() - 64]. buf.len() == MAX_PROGRAM_SIZE at the call
    // site, so this is the same bound the C loader used, now also guaranteeing the
    // program-header table start is inside the buffer.
    let max_phoff = (buf.len() as u64).saturating_sub(64);
    if e_phoff == 0 || e_phoff as u64 > max_phoff { return Err(-8); }

    Ok(ElfHeaderInfo { e_entry, e_phoff, e_type, e_machine, e_phnum, ei_class })
}

/// FFI entry: validate the header of the staged ELF image. On success fills
/// `*out` and returns 0; otherwise returns the loader's negative error code
/// (-2 bad magic, -3 not LE, -4 machine/class mismatch, -5 bad class, -6 bad
/// e_type, -7 bad e_phnum, -8 bad e_phoff, -17 an ELF64 field exceeds 32 bits).
///
/// # Safety
/// `buf` must point to `buf_len` readable bytes; `out` must be a writable,
/// aligned `ElfHeaderInfo`. Null pointers are handled (returns -2).
#[no_mangle]
pub unsafe extern "C" fn rust_elf_validate_header(
    buf: *const u8,
    buf_len: usize,
    out: *mut ElfHeaderInfo,
) -> i32 {
    if buf.is_null() || out.is_null() {
        return -2;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    match validate_elf_header(s) {
        Ok(info) => {
            *out = info;
            0
        }
        Err(code) => code,
    }
}

#[cfg(kani)]
mod elf_kani_proofs {
    use super::*;

    /// Soundness of the ELF header validator, over EVERY possible 128-byte input
    /// (buffer size chosen so acceptance is reachable: e_phoff can fall within
    /// [1, len-64]). Two things are proved together:
    ///   - the parse never panics — no overflow, no out-of-bounds slice read;
    ///   - if it ACCEPTS a header, every field the C loader then trusts is within
    ///     the range the loader assumes (class, e_type, e_phnum, e_phoff bound,
    ///     and the machine/class pairing). A malformed image can never slip an
    ///     out-of-range field past the validator.
    #[kani::proof]
    fn elf_header_validation_is_sound() {
        let buf: [u8; 128] = kani::any();
        if let Ok(info) = validate_elf_header(&buf) {
            assert!(info.ei_class == 1 || info.ei_class == 2);
            assert!(info.e_type == 2 || info.e_type == 3);
            assert!(info.e_phnum >= 1 && info.e_phnum <= 8);
            assert!(info.e_phoff >= 1);
            assert!(info.e_phoff as usize <= buf.len() - 64);
            assert!(
                (info.ei_class == 1 && info.e_machine == 3)
                    || (info.ei_class == 2 && info.e_machine == 62)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ELF header validation (J10.1) -----------------------------------
    // Minimal little-endian ELF header builders (512-byte buffer; only the
    // fields the validator reads are set, the rest stay 0).
    fn elf32(e_machine: u16, e_type: u16, e_phoff: u32, e_phnum: u16) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 1; // ELFCLASS32
        b[5] = 1; // ELFDATA2LSB
        b[16..18].copy_from_slice(&e_type.to_le_bytes());
        b[18..20].copy_from_slice(&e_machine.to_le_bytes());
        b[24..28].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // e_entry
        b[28..32].copy_from_slice(&e_phoff.to_le_bytes());
        b[44..46].copy_from_slice(&e_phnum.to_le_bytes());
        b
    }
    fn elf64(e_machine: u16, e_type: u16, phoff_lo: u32, phoff_hi: u32, e_phnum: u16) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // ELFDATA2LSB
        b[16..18].copy_from_slice(&e_type.to_le_bytes());
        b[18..20].copy_from_slice(&e_machine.to_le_bytes());
        b[24..32].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // e_entry (8 bytes)
        b[32..36].copy_from_slice(&phoff_lo.to_le_bytes());       // e_phoff low dword
        b[36..40].copy_from_slice(&phoff_hi.to_le_bytes());       // e_phoff high dword
        b[56..58].copy_from_slice(&e_phnum.to_le_bytes());
        b
    }

    #[test]
    fn elf_header_accepts_valid_elf32_and_elf64() {
        let info = validate_elf_header(&elf32(3, 2, 64, 1)).expect("valid ELF32");
        assert_eq!(
            info,
            ElfHeaderInfo { e_entry: 0x0040_0000, e_phoff: 64, e_type: 2, e_machine: 3, e_phnum: 1, ei_class: 1 }
        );
        let info = validate_elf_header(&elf64(62, 3, 64, 0, 2)).expect("valid ELF64");
        assert_eq!(
            info,
            ElfHeaderInfo { e_entry: 0x0040_0000, e_phoff: 64, e_type: 3, e_machine: 62, e_phnum: 2, ei_class: 2 }
        );
    }

    #[test]
    fn elf_header_rejects_with_the_loaders_exact_codes() {
        let mut bad_magic = elf32(3, 2, 64, 1);
        bad_magic[1] = b'X';
        assert_eq!(validate_elf_header(&bad_magic), Err(-2)); // bad magic
        let mut be = elf32(3, 2, 64, 1);
        be[5] = 2;
        assert_eq!(validate_elf_header(&be), Err(-3)); // not little-endian
        assert_eq!(validate_elf_header(&elf32(62, 2, 64, 1)), Err(-4)); // ELF32 wrong machine
        assert_eq!(validate_elf_header(&elf64(3, 2, 64, 0, 1)), Err(-4)); // ELF64 wrong machine
        let mut badclass = elf32(3, 2, 64, 1);
        badclass[4] = 3;
        assert_eq!(validate_elf_header(&badclass), Err(-5)); // bad ELFCLASS
        assert_eq!(validate_elf_header(&elf32(3, 1, 64, 1)), Err(-6)); // ET_REL not loadable
        assert_eq!(validate_elf_header(&elf32(3, 2, 64, 0)), Err(-7)); // e_phnum 0
        assert_eq!(validate_elf_header(&elf32(3, 2, 64, 9)), Err(-7)); // e_phnum > 8
        assert_eq!(validate_elf_header(&elf32(3, 2, 0, 1)), Err(-8)); // e_phoff 0
        assert_eq!(validate_elf_header(&elf32(3, 2, 500, 1)), Err(-8)); // e_phoff > len-64 (448)
        assert_eq!(validate_elf_header(&elf64(62, 2, 64, 1, 1)), Err(-17)); // e_phoff exceeds 32 bits
        // The narrow (-17) is checked inside the class branch, before e_type
        // (-6), so a header that fails both yields -17 — same as the C loader.
        assert_eq!(validate_elf_header(&elf64(62, 1, 64, 1, 1)), Err(-17));
    }

    #[test]
    fn elf_header_never_panics_on_short_buffers() {
        // A truncated header must fail closed with a negative code, never panic
        // or read past the slice — the memory-safety win of the Rust parse.
        let full = elf64(62, 3, 64, 0, 1);
        for n in 0..=80usize {
            assert!(validate_elf_header(&full[..n]).is_err() || n >= 58);
        }
    }

    // err_code bit layout used throughout: present=1, write=2, user=4.
    const PRESENT: u32 = 1;
    const USER: u32 = 4;

    #[test]
    fn ct_eq_matches_only_on_equal_buffers() {
        let a = [0x11u8, 0x22, 0x33, 0x44];
        let equal = a;
        let diff_last = [0x11u8, 0x22, 0x33, 0x45];
        let diff_first = [0x10u8, 0x22, 0x33, 0x44];
        unsafe {
            assert_eq!(rust_ct_eq(a.as_ptr(), equal.as_ptr(), a.len()), 1);
            assert_eq!(rust_ct_eq(a.as_ptr(), diff_last.as_ptr(), a.len()), 0);
            assert_eq!(rust_ct_eq(a.as_ptr(), diff_first.as_ptr(), a.len()), 0);
            // Fail closed: null pointer and zero-length both return not-equal.
            assert_eq!(rust_ct_eq(core::ptr::null(), a.as_ptr(), a.len()), 0);
            assert_eq!(rust_ct_eq(a.as_ptr(), core::ptr::null(), a.len()), 0);
            assert_eq!(rust_ct_eq(a.as_ptr(), equal.as_ptr(), 0), 0);
        }
    }

    #[test]
    fn page_fault_validation_is_region_scoped() {
        // A representative task: image at an ASLR'd base [0x4a0000, 0x4b6000),
        // heap [0x1000000, 0x1040000). Bounds come from tasks[tid] at the call site.
        let ib = 0x4a0000; let ie = 0x4b6000;
        let hs = 0x1000000; let he = 0x1040000;
        let v = |a: u64| rust_validate_page_fault(a, 0, ib, ie, hs, he);

        // In-region: image, heap, low stack.
        assert!(v(0x4a0000));            // image base
        assert!(v(0x4b5fff));            // image end - 1
        assert!(v(0x1000000));           // heap start
        assert!(v(0x103ffff));           // heap end - 1
        assert!(v(0x7df000));            // low stack base
        assert!(v(0x7fefff));            // low stack top - 1

        // Out of region: below the image, the gap between image and stack, past
        // the heap ceiling, the null page, kernel space. (These addresses were
        // once the kernel's own .bss, back when it was linked low; they are just
        // unmapped user-half addresses now. Either way: not this task's memory.)
        assert!(!v(0x49ffff));           // just below the image base
        assert!(!v(0x4b6000));           // just past the image end
        assert!(!v(0x570000));           // was kernel_page_dir: blessed-but-unmappable
        assert!(!v(0x800000));           // was the [8,16) MiB kernel .bss window
        assert!(!v(0xA00000));           // was argon2_scratch
        assert!(!v(0xffffff));           // just below the heap base
        assert!(!v(0x1040000));          // just past the heap ceiling
        assert!(!v(0x0));                // null page
        assert!(!v(0x100000));           // kernel image low
        assert!(!v(0xC0000000));         // kernel space

        // A zero image_base (unbuilt task) never validates the image window.
        assert!(!rust_validate_page_fault(0x400000, 0, 0, 0, hs, he));
    }

    #[test]
    fn cap_rights_are_subset_checked() {
        let held = SafeCapability { raw: 0b1011 };
        unsafe {
            // A null capability grants nothing.
            assert!(!rust_cap_has_rights(core::ptr::null(), 0b0001));
            // Holding a superset of the required bits passes.
            assert!(rust_cap_has_rights(&held, 0b0001));
            assert!(rust_cap_has_rights(&held, 0b1010));
            assert!(rust_cap_has_rights(&held, 0b1011));
            // Requiring any bit not held fails — no rights escalation.
            assert!(!rust_cap_has_rights(&held, 0b0100));
            assert!(!rust_cap_has_rights(&held, 0b1111));
        }
        assert!(SafeCap { raw: 0b110 }.has_rights(0b100));
        assert!(!SafeCap { raw: 0b110 }.has_rights(0b001));
    }

    #[test]
    fn user_page_protection_windows() {
        assert_eq!(rust_get_user_page_protection(0, 0x400000), 0x7);
        assert_eq!(rust_get_user_page_protection(0, 0x1000000), 0x7);  // heap base
        assert_eq!(rust_get_user_page_protection(0, 0xff000000), 0x7);
        assert_eq!(rust_get_user_page_protection(0, 0), 0);
        assert_eq!(rust_get_user_page_protection(0, 0x300000), 0);
        // Not user memory. (Once because kernel .bss sat at these VAs behind
        // supervisor huge pages; now because nothing maps them at all. This used
        // to return 0x7 and had a test asserting it did.)
        assert_eq!(rust_get_user_page_protection(0, 0xA00000), 0);
        assert_eq!(rust_get_user_page_protection(0, 0x800000), 0);
    }

    #[test]
    fn wx_stack_noexec_image_executable() {
        // Image / code region must stay executable (flat binaries run here).
        assert!(!rust_user_page_is_noexec(0x400000)); // load base
        assert!(!rust_user_page_is_noexec(0x500000)); // top of a max-size image
        assert!(!rust_user_page_is_noexec(0x519000)); // top of the heap window
        assert!(!rust_user_page_is_noexec(0x7cf000)); // just below the stack floor
        // Low user stack must be non-executable.
        assert!(rust_user_page_is_noexec(0x7d0000));  // window floor (inclusive)
        assert!(rust_user_page_is_noexec(0x7df000));  // low-stack base
        assert!(rust_user_page_is_noexec(0x7ff000 - 0x1000)); // near stack top
        // 0x800000 is one past the user area -> not stack.
        assert!(!rust_user_page_is_noexec(0x800000));
        // High ASLR stack window is non-executable.
        assert!(rust_user_page_is_noexec(0x0000_7ff0_0000_0000 - 0x1000));
        // Other mapped windows and the null page stay executable.
        assert!(!rust_user_page_is_noexec(0xA00000));
        assert!(!rust_user_page_is_noexec(0));
    }

    #[test]
    fn signal_handler_addr_window() {
        // A task whose image is the classic low one.
        const LO: u64 = 0x400000;
        const HI: u64 = 0x480000;
        assert!(rust_signal_handler_addr_ok(LO, LO, HI)); // base (inclusive)
        assert!(rust_signal_handler_addr_ok(0x401234, LO, HI)); // a real handler entry
        assert!(rust_signal_handler_addr_ok(HI - 1, LO, HI)); // last byte in-image
        // Outside this task's image -> rejected (fail closed).
        assert!(!rust_signal_handler_addr_ok(0, LO, HI)); // null
        assert!(!rust_signal_handler_addr_ok(LO - 1, LO, HI)); // just below the base
        assert!(!rust_signal_handler_addr_ok(HI, LO, HI)); // one past the top
        assert!(!rust_signal_handler_addr_ok(0x100000, LO, HI)); // kernel image
        // The stack and heap are outside the image by construction.
        assert!(!rust_signal_handler_addr_ok(0x7f0000, LO, HI)); // low stack
        assert!(!rust_signal_handler_addr_ok(0x1000000, LO, HI)); // heap
    }

    #[test]
    fn signal_handler_addr_is_per_task_not_a_fixed_window() {
        // The point of taking the image bounds: an address inside the OLD fixed
        // [0x400000, 0x800000) window but outside *this* task's image must be
        // refused. Image-base ASLR means most of that window was never the
        // task's code, and the fixed check accepted all of it.
        const LO: u64 = 0x400000;
        const HI: u64 = 0x480000;
        assert!(!rust_signal_handler_addr_ok(0x7fffff, LO, HI));

        // And an image above 4 GiB can express a legal handler at all, which a
        // u32 window could not represent.
        const HIGH_LO: u64 = 0x0000_0004_0000_0000;
        const HIGH_HI: u64 = HIGH_LO + 0x80000;
        assert!(rust_signal_handler_addr_ok(HIGH_LO + 0x1234, HIGH_LO, HIGH_HI));
        assert!(!rust_signal_handler_addr_ok(0x401234, HIGH_LO, HIGH_HI));
    }

    #[test]
    fn signal_handler_addr_fails_closed_on_a_degenerate_image() {
        // No image recorded, or an inverted/empty range: there is no code to
        // point at, so nothing is acceptable — including addresses that would
        // pass under the old fixed window.
        assert!(!rust_signal_handler_addr_ok(0x401234, 0, 0));
        assert!(!rust_signal_handler_addr_ok(0x401234, 0, 0x800000));
        assert!(!rust_signal_handler_addr_ok(0x401234, 0x400000, 0x400000));
        assert!(!rust_signal_handler_addr_ok(0x401234, 0x480000, 0x400000));
    }

    #[test]
    fn cow_required_truth_table() {
        assert!(rust_cow_copy_required(true, true, 2));
        assert!(!rust_cow_copy_required(true, true, 1)); // sole owner -> no copy
        assert!(!rust_cow_copy_required(false, true, 2)); // not a COW page
        assert!(!rust_cow_copy_required(true, false, 2)); // not a write
    }

    #[test]
    fn should_demand_zero_bits() {
        assert!(rust_should_demand_zero(USER)); // not-present + user
        assert!(!rust_should_demand_zero(USER | PRESENT)); // already present
        assert!(!rust_should_demand_zero(0)); // not a user fault
    }

    #[test]
    fn fs_operation_requires_some_right() {
        let name = b"file";
        // No rights held -> denied.
        assert_eq!(rust_validate_fs_operation(1, FsOp::Read as u32, 0, name.as_ptr(), name.len()), -1);
        // Any right held -> allowed (per-op masking is enforced in C capfs).
        assert_eq!(rust_validate_fs_operation(1, FsOp::Read as u32, 0x1, name.as_ptr(), name.len()), 0);
    }

    #[test]
    fn handle_command_dispatch() {
        unsafe {
            // A null command is a no-op, not a crash.
            assert_eq!(rust_handle_command(core::ptr::null(), 0), 0);
            let help = b"help";
            assert_eq!(rust_handle_command(help.as_ptr(), help.len()), 42);
            let echo = b"echo hi";
            assert_eq!(rust_handle_command(echo.as_ptr(), echo.len()), 44);
            let unknown = b"frobnicate";
            assert_eq!(rust_handle_command(unknown.as_ptr(), unknown.len()), -1);
            // Invalid UTF-8 is rejected rather than mis-parsed.
            let bad = [0xffu8, 0xfe];
            assert_eq!(rust_handle_command(bad.as_ptr(), bad.len()), -1);
        }
    }
}


