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

// ---------------------------------------------------------------------------
// ELF program-header (PT_LOAD) validation -> load plan (J10.2).
//
// The second attacker-controlled parser in try_elf_load: it walks the program
// header table, reads each PT_LOAD's offset/vaddr/filesz/memsz/flags, validates
// them, and computes where each segment maps. Moving it into safe Rust removes
// the memory-safety blast radius the hand-rolled C carried:
//   * `p_offset + p_filesz` was u32 arithmetic — a crafted header could overflow
//     it below MAX_PROGRAM_SIZE, pass the bound, then copy from `st + p_offset`
//     far out of bounds (a kernel-memory read into the new image). Here the sum
//     is computed in u64 and cannot wrap.
//   * the program-header table read `ph + i*phentsize` could run past the
//     staging buffer for a large e_phoff with e_phnum up to 8; every read here
//     is a bounds-checked slice access instead.
// Legitimate images (small e_phoff, no overflow) are unaffected, so behaviour is
// unchanged for them; only malformed images that previously triggered an OOB
// read are now cleanly rejected. Rust returns a validated plan; the C loader
// executes only the privileged copy_to_user from it. The relocation pass stays
// in C (J10.3 moves that).
// ---------------------------------------------------------------------------

/// One validated PT_LOAD segment of the load plan. Mirrors `struct
/// elf_load_segment` in kernel.h.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ElfLoadSegment {
    pub dest_va: u64,  // where it maps: validated in [user_area_base, user_max_vaddr)
    pub file_off: u32, // offset of the file bytes in the staging buffer
    pub file_sz: u32,  // bytes to copy from the file (file_off + file_sz <= buf_len)
    pub mem_sz: u32,   // total mapped size; the [file_sz, mem_sz) tail is zero-filled
    pub flags: u32,    // ELF p_flags: PF_X=1, PF_W=2, PF_R=4
}

/// The validated plan the C loader executes. Mirrors `struct elf_load_plan` in
/// kernel.h. Holds up to 8 segments (e_phnum is capped at 8 by the header check).
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ElfLoadPlan {
    pub slide: u64,      // load bias applied to every p_vaddr (load_base - min_vaddr page)
    pub max_va_end: u64, // highest dest_va + mem_sz across segments (the image end)
    pub segs: [ElfLoadSegment; 8],
    pub nseg: u32,       // number of PT_LOAD segments, 1..=8
}

const PT_LOAD: u32 = 1;

/// Pure, panic-free program-header validator. Two passes mirroring try_elf_load:
/// find the minimum PT_LOAD vaddr (to compute the load slide), then validate each
/// segment and record it. Returns the loader's negative code on rejection
/// (-9 no PT_LOAD / malformed table, -10 memsz<filesz, -11 file range out of the
/// buffer, -12 dest vaddr outside the user window, -13 dest range overflow,
/// -17 an ELF64 field exceeds 32 bits).
fn build_load_plan(
    buf: &[u8],
    ei_class: u8,
    e_phoff: u32,
    e_phnum: u16,
    load_base: u64,
    user_area_base: u64,
    user_max_vaddr: u64,
) -> Result<ElfLoadPlan, i32> {
    let phentsize: usize = if ei_class == 1 { 32 } else { 56 };
    let ph = e_phoff as usize;

    // A PT_LOAD's p_vaddr: 32-bit direct for ELFCLASS32, narrowed for ELFCLASS64.
    // An out-of-bounds phdr read is a malformed table (-9); a value that does not
    // fit the 32-bit plumbing is -17.
    let read_vaddr = |p: usize| -> Result<u32, i32> {
        if ei_class == 1 {
            elf_rd_u32(buf, p + 8).ok_or(-9)
        } else {
            match elf_rd_u64(buf, p + 16) {
                None => Err(-9),
                Some(v) if v > u32::MAX as u64 => Err(-17),
                Some(v) => Ok(v as u32),
            }
        }
    };

    // Pass 1: minimum PT_LOAD vaddr -> slide.
    let mut min_vaddr = u32::MAX;
    let mut have_load = false;
    for i in 0..e_phnum as usize {
        let p = ph + i * phentsize;
        let p_type = elf_rd_u32(buf, p).ok_or(-9)?;
        if p_type != PT_LOAD {
            continue;
        }
        let p_vaddr = read_vaddr(p)?;
        if p_vaddr < min_vaddr {
            min_vaddr = p_vaddr;
        }
        have_load = true;
    }
    if !have_load {
        return Err(-9);
    }
    let slide = load_base.wrapping_sub((min_vaddr & !0xFFFu32) as u64);

    // Pass 2: validate and record each PT_LOAD segment.
    let mut plan = ElfLoadPlan {
        slide,
        max_va_end: 0,
        segs: [ElfLoadSegment { dest_va: 0, file_off: 0, file_sz: 0, mem_sz: 0, flags: 0 }; 8],
        nseg: 0,
    };
    for i in 0..e_phnum as usize {
        let p = ph + i * phentsize;
        let p_type = elf_rd_u32(buf, p).ok_or(-9)?;
        if p_type != PT_LOAD {
            continue;
        }

        let (p_offset, p_vaddr, p_filesz, p_memsz, p_flags) = if ei_class == 1 {
            (
                elf_rd_u32(buf, p + 4).ok_or(-9)?,
                elf_rd_u32(buf, p + 8).ok_or(-9)?,
                elf_rd_u32(buf, p + 16).ok_or(-9)?,
                elf_rd_u32(buf, p + 20).ok_or(-9)?,
                elf_rd_u32(buf, p + 24).ok_or(-9)?,
            )
        } else {
            (
                elf_narrow(buf, p + 8)?,
                elf_narrow(buf, p + 16)?,
                elf_narrow(buf, p + 32)?,
                elf_narrow(buf, p + 40)?,
                // p_flags is a genuine 4-byte field at offset 4 in ELF64.
                elf_rd_u32(buf, p + 4).ok_or(-9)?,
            )
        };

        if p_memsz < p_filesz {
            return Err(-10);
        }
        // Checked in u64 so a crafted p_offset/p_filesz cannot wrap past the
        // buffer bound the way the old u32 addition could (both are <= u32::MAX,
        // so the u64 sum itself never overflows).
        if p_offset as u64 + p_filesz as u64 > buf.len() as u64 {
            return Err(-11);
        }
        // dest_va / va_end use wrapping adds (matching the C's u64 arithmetic);
        // load_base is caller-supplied so slide is unconstrained here. The range
        // check (-12) and the wrap detection (-13, == the C's `va_end < dest_va`)
        // are what make the result sound, not the absence of a wrap.
        let dest_va = (p_vaddr as u64).wrapping_add(slide);
        let va_end = dest_va.wrapping_add(p_memsz as u64);
        if dest_va < user_area_base || dest_va >= user_max_vaddr {
            return Err(-12);
        }
        if va_end < dest_va {
            return Err(-13);
        }
        if va_end > plan.max_va_end {
            plan.max_va_end = va_end;
        }

        // e_phnum <= 8 (header check) bounds the PT_LOAD count to 8.
        let n = plan.nseg as usize;
        if n < 8 {
            plan.segs[n] = ElfLoadSegment {
                dest_va,
                file_off: p_offset,
                file_sz: p_filesz,
                mem_sz: p_memsz,
                flags: p_flags,
            };
            plan.nseg += 1;
        }
    }

    Ok(plan)
}

/// FFI entry: parse+validate the PT_LOAD program headers of the staged image and
/// build the load plan the C loader executes. Returns 0 and fills `*out` on
/// success, else the loader's negative error code (see build_load_plan).
///
/// # Safety
/// `buf` must point to `buf_len` readable bytes; `out` must be a writable,
/// aligned `ElfLoadPlan`. Null pointers are handled (returns -9).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn rust_elf_build_load_plan(
    buf: *const u8,
    buf_len: usize,
    ei_class: u8,
    e_phoff: u32,
    e_phnum: u16,
    load_base: u64,
    user_area_base: u64,
    user_max_vaddr: u64,
    out: *mut ElfLoadPlan,
) -> i32 {
    if buf.is_null() || out.is_null() {
        return -9;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    match build_load_plan(s, ei_class, e_phoff, e_phnum, load_base, user_area_base, user_max_vaddr) {
        Ok(plan) => {
            *out = plan;
            0
        }
        Err(code) => code,
    }
}

// ---------------------------------------------------------------------------
// i386 dynamic relocation parsing (J10.3a).
//
// The third attacker-controlled parser in the ELF loader: for a static-PIE
// (ET_DYN) ELFCLASS32 image it walks PT_DYNAMIC to find the REL table, maps the
// table's link-time vaddr to a file offset, and validates each entry. Moving the
// PARSE into safe Rust means the untrusted-offset reads are bounds-checked slice
// accesses; the C loader keeps the privileged apply (a read-modify-write of the
// user address space — `*(u32*)target += slide`), which needs ring 0.
//
// Behaviour-preserving: only R_386_RELATIVE (type 8) is applied, R_386_NONE is
// skipped, and everything else — a DT_RELA table (i386 uses REL), a bad entsize,
// an unmapped/out-of-bounds table, an unknown type, a target outside every
// loaded segment — fails closed with -16, exactly as the C did.
// ---------------------------------------------------------------------------

/// The located i386 REL table. Mirrors `struct elf_i386_reloc_table` in kernel.h.
/// `nrel == 0` means the image has no dynamic relocations (a success, not an
/// error).
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ElfI386RelocTable {
    pub rel_file_off: u32, // file offset of the REL table in the staging buffer
    pub nrel: u32,         // number of 8-byte Elf32_Rel entries, capped at 8192
}

const I386_PHENTSIZE: usize = 32;

/// Map a link-time (base-0) vaddr to its offset in the staging file image via the
/// PT_LOAD segment that contains it. None if no segment contains it or the file
/// offset would not fit u32 (fail closed).
fn i386_map_vaddr_to_file_off(buf: &[u8], e_phoff: u32, e_phnum: u16, vaddr: u32) -> Option<u32> {
    let ph = e_phoff as usize;
    for i in 0..e_phnum as usize {
        let p = ph + i * I386_PHENTSIZE;
        if elf_rd_u32(buf, p)? != PT_LOAD {
            continue;
        }
        let p_offset = elf_rd_u32(buf, p + 4)?;
        let p_vaddr = elf_rd_u32(buf, p + 8)?;
        let p_filesz = elf_rd_u32(buf, p + 16)?;
        if vaddr >= p_vaddr && (vaddr as u64) < p_vaddr as u64 + p_filesz as u64 {
            let off = p_offset as u64 + (vaddr - p_vaddr) as u64;
            return u32::try_from(off).ok();
        }
    }
    None
}

/// Locate + validate the i386 dynamic REL table. Mirrors the parse in
/// elf_apply_relocations_i386. `Ok(nrel==0)` for no dynamic relocations.
fn i386_reloc_locate(buf: &[u8], e_phoff: u32, e_phnum: u16) -> Result<ElfI386RelocTable, i32> {
    let none = ElfI386RelocTable { rel_file_off: 0, nrel: 0 };
    let ph = e_phoff as usize;

    // Locate PT_DYNAMIC (p_type == 2). Elf32_Phdr: p_type@0 p_offset@4 p_filesz@16.
    let (mut dyn_off, mut dyn_sz) = (0u32, 0u32);
    for i in 0..e_phnum as usize {
        let p = ph + i * I386_PHENTSIZE;
        if elf_rd_u32(buf, p).ok_or(-16)? == 2 {
            dyn_off = elf_rd_u32(buf, p + 4).ok_or(-16)?;
            dyn_sz = elf_rd_u32(buf, p + 16).ok_or(-16)?;
            break;
        }
    }
    if dyn_off == 0 || dyn_sz == 0 {
        return Ok(none);
    }
    let len = buf.len() as u64;
    if dyn_off as u64 > len || dyn_sz as u64 > len || dyn_off as u64 + dyn_sz as u64 > len {
        return Err(-16);
    }

    // Walk Elf32_Dyn { i32 d_tag; u32 d_val } (8 bytes) for the REL table.
    let (mut rel_vaddr, mut rel_sz, mut rel_ent) = (0u32, 0u32, 8u32);
    let mut o = 0u32;
    while o as u64 + 8 <= dyn_sz as u64 {
        let base = (dyn_off + o) as usize;
        let tag = elf_rd_u32(buf, base).ok_or(-16)? as i32;
        let val = elf_rd_u32(buf, base + 4).ok_or(-16)?;
        match tag {
            0 => break,             // DT_NULL
            17 => rel_vaddr = val,  // DT_REL
            18 => rel_sz = val,     // DT_RELSZ
            19 => rel_ent = val,    // DT_RELENT
            7 => return Err(-16),   // DT_RELA: unsupported on i386
            _ => {}
        }
        o += 8;
    }
    if rel_vaddr == 0 || rel_sz == 0 {
        return Ok(none);
    }
    if rel_ent != 8 {
        return Err(-16);
    }

    let rel_file_off = i386_map_vaddr_to_file_off(buf, e_phoff, e_phnum, rel_vaddr).ok_or(-16)?;
    if rel_file_off as u64 > len || rel_sz as u64 > len || rel_file_off as u64 + rel_sz as u64 > len
    {
        return Err(-16);
    }

    let nrel = rel_sz / 8;
    if nrel > 8192 {
        return Err(-16);
    }
    Ok(ElfI386RelocTable { rel_file_off, nrel })
}

/// Validate entry `k` of the located REL table and return its patch target
/// (`r_offset + slide`, which the caller read-modify-writes). `Ok(Some(t))` =
/// apply, `Ok(None)` = skip (R_386_NONE), `Err(-16)` = reject.
fn i386_reloc_target(
    buf: &[u8],
    rel_file_off: u32,
    k: u32,
    slide: u64,
    seg_va: &[u64],
    seg_memsz: &[u64],
) -> Result<Option<u64>, i32> {
    let r = rel_file_off as usize + k as usize * 8;
    let r_offset = elf_rd_u32(buf, r).ok_or(-16)?;
    let r_info = elf_rd_u32(buf, r + 4).ok_or(-16)?;
    let r_type = r_info & 0xFF;
    if r_type == 0 {
        return Ok(None); // R_386_NONE
    }
    if r_type != 8 {
        return Err(-16); // only R_386_RELATIVE
    }

    let target = (r_offset as u64).wrapping_add(slide);
    let n = seg_va.len().min(seg_memsz.len());
    for s in 0..n {
        if let (Some(t4), Some(end)) = (target.checked_add(4), seg_va[s].checked_add(seg_memsz[s])) {
            if target >= seg_va[s] && t4 <= end {
                return Ok(Some(target));
            }
        }
    }
    Err(-16)
}

/// FFI: locate the i386 dynamic REL table. 0 + `*out` on success (out.nrel == 0
/// = no relocations), else -16.
///
/// # Safety
/// `buf` points to `buf_len` readable bytes; `out` is a writable
/// `ElfI386RelocTable`.
#[no_mangle]
pub unsafe extern "C" fn rust_elf_i386_reloc_locate(
    buf: *const u8,
    buf_len: usize,
    e_phoff: u32,
    e_phnum: u16,
    out: *mut ElfI386RelocTable,
) -> i32 {
    if buf.is_null() || out.is_null() {
        return -16;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    match i386_reloc_locate(s, e_phoff, e_phnum) {
        Ok(rt) => {
            *out = rt;
            0
        }
        Err(code) => code,
    }
}

/// FFI: resolve reloc entry `k`. Returns 0 (apply `*out_target`), 1 (skip /
/// R_386_NONE), or -16 (reject).
///
/// # Safety
/// `buf`/`buf_len` bound the staging image; `seg_va`/`seg_memsz` each point to
/// `nseg` readable u64s; `out_target` is writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn rust_elf_i386_reloc_target(
    buf: *const u8,
    buf_len: usize,
    rel_file_off: u32,
    k: u32,
    slide: u64,
    seg_va: *const u64,
    seg_memsz: *const u64,
    nseg: u32,
    out_target: *mut u64,
) -> i32 {
    if buf.is_null() || out_target.is_null() || seg_va.is_null() || seg_memsz.is_null() {
        return -16;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    let va = core::slice::from_raw_parts(seg_va, nseg as usize);
    let mz = core::slice::from_raw_parts(seg_memsz, nseg as usize);
    match i386_reloc_target(s, rel_file_off, k, slide, va, mz) {
        Ok(Some(t)) => {
            *out_target = t;
            0
        }
        Ok(None) => 1,
        Err(code) => code,
    }
}

// ---------------------------------------------------------------------------
// x86-64 dynamic relocation parsing (J10.3b).
//
// The x86-64 counterpart of the i386 parser above and the last hand-rolled
// untrusted-input parser in the ELF loader. It differs from i386 in three ways
// that each matter for correctness: RELA (24-byte entries with an explicit
// addend, so the patch is a *write* of slide+addend, not a read-modify-write);
// the type is the low 32 bits of r_info; and R_X86_64_GLOB_DAT (6) resolves a
// symbol from the dynamic symbol table (undefined-weak -> NULL, defined ->
// st_value+slide+addend, undefined-strong -> reject).
//
// The whole parse — dynamic walk, RELA/symtab location, per-entry validation AND
// the symbol lookup — is memory-safe Rust (bounds-checked slice reads). Because
// x86-64 relocations are a pure write of a computed value, Rust computes the
// value too; the C loader keeps only the privileged copy_to_user. Behaviour is
// preserved: R_X86_64_RELATIVE (8) and GLOB_DAT (6) are applied, R_X86_64_NONE
// skipped, everything else (a DT_REL table, bad entsizes, out-of-bounds tables,
// unknown types, out-of-segment targets, unresolved strong symbols) fails closed
// with -16.
// ---------------------------------------------------------------------------

/// The located x86-64 RELA + symbol tables. Mirrors `struct
/// elf_x86_64_reloc_table` in kernel.h. `nrela == 0` = no dynamic relocations;
/// `sym_file_off == 0` = no symbol table (any GLOB_DAT then fails closed).
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct ElfX8664RelocTable {
    pub rela_file_off: u64, // file offset of the RELA table in the staging buffer
    pub sym_file_off: u64,  // file offset of the dynamic symbol table (0 = none)
    pub nrela: u64,         // number of 24-byte Elf64_Rela entries (<= 8192)
}

const X86_64_PHENTSIZE: usize = 56;

/// Map a link-time (base-0) vaddr to its offset in the staging file image via the
/// PT_LOAD segment that contains it. None if unmapped. Elf64_Phdr: p_type@0
/// p_offset@8 p_vaddr@16 p_filesz@32.
fn x86_64_map_vaddr_to_file_off(buf: &[u8], e_phoff: u32, e_phnum: u16, vaddr: u64) -> Option<u64> {
    let ph = e_phoff as usize;
    for i in 0..e_phnum as usize {
        let p = ph + i * X86_64_PHENTSIZE;
        if elf_rd_u32(buf, p)? != PT_LOAD {
            continue;
        }
        let p_offset = elf_rd_u64(buf, p + 8)?;
        let p_vaddr = elf_rd_u64(buf, p + 16)?;
        let p_filesz = elf_rd_u64(buf, p + 32)?;
        if vaddr >= p_vaddr && vaddr < p_vaddr.checked_add(p_filesz)? {
            return p_offset.checked_add(vaddr - p_vaddr);
        }
    }
    None
}

/// Locate + validate the x86-64 RELA table and dynamic symbol table. Mirrors the
/// parse in elf_apply_relocations_x86_64. `Ok(nrela==0)` for no relocations.
fn x86_64_reloc_locate(buf: &[u8], e_phoff: u32, e_phnum: u16) -> Result<ElfX8664RelocTable, i32> {
    let none = ElfX8664RelocTable { rela_file_off: 0, sym_file_off: 0, nrela: 0 };
    let ph = e_phoff as usize;
    let len = buf.len() as u64;

    // Locate PT_DYNAMIC (p_type == 2). Elf64_Phdr: p_offset@8 p_filesz@32.
    let (mut dyn_off, mut dyn_sz) = (0u64, 0u64);
    for i in 0..e_phnum as usize {
        let p = ph + i * X86_64_PHENTSIZE;
        if elf_rd_u32(buf, p).ok_or(-16)? == 2 {
            dyn_off = elf_rd_u64(buf, p + 8).ok_or(-16)?;
            dyn_sz = elf_rd_u64(buf, p + 32).ok_or(-16)?;
            break;
        }
    }
    if dyn_off == 0 || dyn_sz == 0 {
        return Ok(none);
    }
    if dyn_off > len || dyn_sz > len || dyn_off + dyn_sz > len {
        return Err(-16);
    }

    // Walk Elf64_Dyn { i64 d_tag; u64 d_val } (16 bytes) for the RELA + symtab.
    let (mut rela_vaddr, mut rela_sz, mut rela_ent) = (0u64, 0u64, 24u64);
    let (mut sym_vaddr, mut sym_ent) = (0u64, 24u64);
    let mut o = 0u64;
    while o + 16 <= dyn_sz {
        let base = (dyn_off + o) as usize;
        let tag = elf_rd_u64(buf, base).ok_or(-16)? as i64;
        let val = elf_rd_u64(buf, base + 8).ok_or(-16)?;
        match tag {
            0 => break,             // DT_NULL
            7 => rela_vaddr = val,  // DT_RELA
            8 => rela_sz = val,     // DT_RELASZ
            9 => rela_ent = val,    // DT_RELAENT
            6 => sym_vaddr = val,   // DT_SYMTAB
            11 => sym_ent = val,    // DT_SYMENT
            17 => return Err(-16),  // DT_REL: x86-64 must use RELA
            _ => {}
        }
        o += 16;
    }
    if sym_vaddr != 0 && sym_ent != 24 {
        return Err(-16); // Elf64_Sym is 24 bytes
    }
    if rela_vaddr == 0 || rela_sz == 0 {
        return Ok(none);
    }
    if rela_ent != 24 {
        return Err(-16);
    }

    let rela_file_off = x86_64_map_vaddr_to_file_off(buf, e_phoff, e_phnum, rela_vaddr).ok_or(-16)?;
    if rela_file_off > len || rela_sz > len || rela_file_off + rela_sz > len {
        return Err(-16);
    }

    // The symbol table has no length in the dynamic section; only its base is
    // resolved (each entry is bounds-checked at use). sym_file_off == 0 (no
    // symtab, or a symtab that maps to file offset 0) makes any GLOB_DAT below
    // fail closed rather than read from offset 0 — matching the C.
    let mut sym_file_off = 0u64;
    if sym_vaddr != 0 {
        sym_file_off = x86_64_map_vaddr_to_file_off(buf, e_phoff, e_phnum, sym_vaddr).unwrap_or(0);
        if sym_file_off == 0 || sym_file_off > len {
            return Err(-16);
        }
    }

    let nrela = rela_sz / 24;
    if nrela > 8192 {
        return Err(-16);
    }
    Ok(ElfX8664RelocTable { rela_file_off, sym_file_off, nrela })
}

/// Validate RELA entry `k` and compute the (target, value) to write.
/// `Ok(Some((target, value)))` = write `value` at `target`, `Ok(None)` = skip
/// (R_X86_64_NONE), `Err(-16)` = reject.
#[allow(clippy::too_many_arguments)]
fn x86_64_reloc_resolve(
    buf: &[u8],
    rela_file_off: u64,
    sym_file_off: u64,
    k: u64,
    slide: u64,
    user_max_vaddr: u64,
    seg_va: &[u64],
    seg_memsz: &[u64],
) -> Result<Option<(u64, u64)>, i32> {
    let r = (rela_file_off as usize)
        .checked_add((k as usize).checked_mul(24).ok_or(-16)?)
        .ok_or(-16)?;
    let r_offset = elf_rd_u64(buf, r).ok_or(-16)?;
    let r_info = elf_rd_u64(buf, r + 8).ok_or(-16)?;
    let r_addend = elf_rd_u64(buf, r + 16).ok_or(-16)? as i64;
    let r_type = (r_info & 0xFFFF_FFFF) as u32;
    if r_type == 0 {
        return Ok(None); // R_X86_64_NONE
    }
    if r_type != 8 && r_type != 6 {
        return Err(-16);
    }

    if r_offset > user_max_vaddr {
        return Err(-16);
    }
    let target = r_offset.wrapping_add(slide);
    let mut in_seg = false;
    let n = seg_va.len().min(seg_memsz.len());
    for s in 0..n {
        if let (Some(t8), Some(end)) = (target.checked_add(8), seg_va[s].checked_add(seg_memsz[s])) {
            if target >= seg_va[s] && t8 <= end {
                in_seg = true;
                break;
            }
        }
    }
    if !in_seg {
        return Err(-16);
    }

    // RELA default: write slide + addend outright (the linker recorded the addend).
    let mut w = (slide as i64).wrapping_add(r_addend) as u64;

    if r_type == 6 {
        // R_X86_64_GLOB_DAT: resolve a symbol from the dynamic symbol table.
        let sym_idx = r_info >> 32;
        if sym_file_off == 0 {
            return Err(-16); // GLOB_DAT with no symbol table
        }
        if sym_idx > buf.len() as u64 / 24 {
            return Err(-16); // index overflow
        }
        let sym_off = sym_idx
            .checked_mul(24)
            .and_then(|m| sym_file_off.checked_add(m))
            .ok_or(-16)?;
        if sym_off.checked_add(24).is_none_or(|e| e > buf.len() as u64) {
            return Err(-16); // entry out of the staged image
        }
        let base = sym_off as usize;
        // Elf64_Sym: st_name@0 st_info@4 st_other@5 st_shndx@6(u16) st_value@8(u64).
        let st_info = *buf.get(base + 4).ok_or(-16)?;
        let st_shndx = elf_rd_u16(buf, base + 6).ok_or(-16)?;
        let st_value = elf_rd_u64(buf, base + 8).ok_or(-16)?;

        if st_shndx == 0 {
            // SHN_UNDEF: only an undefined *weak* symbol (STB_WEAK == 2) resolves
            // to NULL; an undefined strong symbol is genuinely unresolved.
            if (st_info >> 4) != 2 {
                return Err(-16);
            }
            w = 0;
        } else {
            if st_value > user_max_vaddr {
                return Err(-16);
            }
            w = (st_value as i64)
                .wrapping_add(slide as i64)
                .wrapping_add(r_addend) as u64;
        }
    }

    Ok(Some((target, w)))
}

/// FFI: locate the x86-64 RELA + symbol tables. 0 + `*out` on success
/// (out.nrela == 0 = no relocations), else -16.
///
/// # Safety
/// `buf` points to `buf_len` readable bytes; `out` is a writable
/// `ElfX8664RelocTable`.
#[no_mangle]
pub unsafe extern "C" fn rust_elf_x86_64_reloc_locate(
    buf: *const u8,
    buf_len: usize,
    e_phoff: u32,
    e_phnum: u16,
    out: *mut ElfX8664RelocTable,
) -> i32 {
    if buf.is_null() || out.is_null() {
        return -16;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    match x86_64_reloc_locate(s, e_phoff, e_phnum) {
        Ok(rt) => {
            *out = rt;
            0
        }
        Err(code) => code,
    }
}

/// FFI: resolve RELA entry `k`. Returns 0 (write `*out_value` at `*out_target`),
/// 1 (skip / R_X86_64_NONE), or -16 (reject).
///
/// # Safety
/// `buf`/`buf_len` bound the staging image; `seg_va`/`seg_memsz` each point to
/// `nseg` readable u64s; `out_target`/`out_value` are writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn rust_elf_x86_64_reloc_resolve(
    buf: *const u8,
    buf_len: usize,
    rela_file_off: u64,
    sym_file_off: u64,
    k: u64,
    slide: u64,
    user_max_vaddr: u64,
    seg_va: *const u64,
    seg_memsz: *const u64,
    nseg: u32,
    out_target: *mut u64,
    out_value: *mut u64,
) -> i32 {
    if buf.is_null() || out_target.is_null() || out_value.is_null() || seg_va.is_null() || seg_memsz.is_null() {
        return -16;
    }
    let s = core::slice::from_raw_parts(buf, buf_len);
    let va = core::slice::from_raw_parts(seg_va, nseg as usize);
    let mz = core::slice::from_raw_parts(seg_memsz, nseg as usize);
    match x86_64_reloc_resolve(s, rela_file_off, sym_file_off, k, slide, user_max_vaddr, va, mz) {
        Ok(Some((t, v))) => {
            *out_target = t;
            *out_value = v;
            0
        }
        Ok(None) => 1,
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

    /// Soundness of the PT_LOAD load-plan builder, over a symbolic staging buffer
    /// and an ARBITRARY load_base (which drives the wrapping dest_va arithmetic).
    /// Proves the builder never panics/overflows, and that every segment in an
    /// accepted plan is safe for the C loader to execute: its file source range
    /// is inside the buffer, its map target is inside the user window, and its
    /// zero-fill tail is non-negative (mem_sz >= file_sz).
    #[kani::proof]
    fn elf_load_plan_is_sound() {
        const UAB: u64 = 0x0040_0000;
        const UMV: u64 = 0x0000_8000_0000_0000;
        let buf: [u8; 128] = kani::any();
        let load_base: u64 = kani::any();
        // ELFCLASS64, one program header at offset 0.
        if let Ok(plan) = build_load_plan(&buf, 2, 0, 1, load_base, UAB, UMV) {
            assert!(plan.nseg <= 8);
            // Iterate the fixed-size segs array with a CONSTANT bound and guard on
            // the count, so CBMC unwinds a fixed 8 times rather than treating the
            // u32 nseg as a symbolic loop bound (which does not terminate).
            for i in 0..8usize {
                if (i as u32) < plan.nseg {
                    let s = plan.segs[i];
                    assert!(s.dest_va >= UAB && s.dest_va < UMV);
                    assert!(s.file_off as u64 + s.file_sz as u64 <= buf.len() as u64);
                    assert!(s.mem_sz >= s.file_sz);
                }
            }
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

    // --- ELF program-header load plan (J10.2) ----------------------------
    const UAB: u64 = 0x0040_0000; // USER_AREA_BASE
    const UMV: u64 = 0x0000_8000_0000_0000; // USER_MAX_VADDR

    fn buf_with_phdrs(phoff: usize, phdrs: &[u8]) -> [u8; 4096] {
        let mut b = [0u8; 4096];
        b[phoff..phoff + phdrs.len()].copy_from_slice(phdrs);
        b
    }
    // One ELFCLASS64 program header (56 bytes): p_type@0 p_flags@4 p_offset@8
    // p_vaddr@16 p_filesz@32 p_memsz@40.
    fn ph64(p_type: u32, p_flags: u32, p_offset: u64, p_vaddr: u64, p_filesz: u64, p_memsz: u64) -> [u8; 56] {
        let mut p = [0u8; 56];
        p[0..4].copy_from_slice(&p_type.to_le_bytes());
        p[4..8].copy_from_slice(&p_flags.to_le_bytes());
        p[8..16].copy_from_slice(&p_offset.to_le_bytes());
        p[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
        p[32..40].copy_from_slice(&p_filesz.to_le_bytes());
        p[40..48].copy_from_slice(&p_memsz.to_le_bytes());
        p
    }
    // One ELFCLASS32 program header (32 bytes): p_type@0 p_offset@4 p_vaddr@8
    // p_filesz@16 p_memsz@20 p_flags@24.
    fn ph32(p_type: u32, p_flags: u32, p_offset: u32, p_vaddr: u32, p_filesz: u32, p_memsz: u32) -> [u8; 32] {
        let mut p = [0u8; 32];
        p[0..4].copy_from_slice(&p_type.to_le_bytes());
        p[4..8].copy_from_slice(&p_offset.to_le_bytes());
        p[8..12].copy_from_slice(&p_vaddr.to_le_bytes());
        p[16..20].copy_from_slice(&p_filesz.to_le_bytes());
        p[20..24].copy_from_slice(&p_memsz.to_le_bytes());
        p[24..28].copy_from_slice(&p_flags.to_le_bytes());
        p
    }

    #[test]
    fn load_plan_accepts_valid_pt_load() {
        // ELF64: one R+X PT_LOAD at vaddr 0x400000 (== load_base, so slide 0).
        let buf = buf_with_phdrs(64, &ph64(PT_LOAD, 5, 0, 0x40_0000, 0x100, 0x200));
        let plan = build_load_plan(&buf, 2, 64, 1, 0x40_0000, UAB, UMV).expect("valid ELF64 plan");
        assert_eq!(plan.nseg, 1);
        assert_eq!(plan.slide, 0);
        assert_eq!(plan.max_va_end, 0x40_0000 + 0x200);
        assert_eq!(
            plan.segs[0],
            ElfLoadSegment { dest_va: 0x40_0000, file_off: 0, file_sz: 0x100, mem_sz: 0x200, flags: 5 }
        );

        // ELF32: same shape via the 32-bit program header.
        let buf = buf_with_phdrs(52, &ph32(PT_LOAD, 6, 0, 0x40_0000, 0x80, 0x80));
        let plan = build_load_plan(&buf, 1, 52, 1, 0x40_0000, UAB, UMV).expect("valid ELF32 plan");
        assert_eq!(plan.nseg, 1);
        assert_eq!(plan.segs[0].flags, 6);
        assert_eq!(plan.segs[0].mem_sz, 0x80);
    }

    #[test]
    fn load_plan_rejects_with_the_loaders_exact_codes() {
        let mk = |ph: [u8; 56]| buf_with_phdrs(64, &ph);
        // -9: no PT_LOAD segment (a lone PT_NOTE).
        assert_eq!(build_load_plan(&mk(ph64(4, 4, 0, 0x40_0000, 0, 0)), 2, 64, 1, 0x40_0000, UAB, UMV), Err(-9));
        // -10: p_memsz < p_filesz.
        assert_eq!(build_load_plan(&mk(ph64(PT_LOAD, 6, 0, 0x40_0000, 0x200, 0x100)), 2, 64, 1, 0x40_0000, UAB, UMV), Err(-10));
        // -11: file range past the 4096-byte buffer.
        assert_eq!(build_load_plan(&mk(ph64(PT_LOAD, 6, 0, 0x40_0000, 0x2000, 0x2000)), 2, 64, 1, 0x40_0000, UAB, UMV), Err(-11));
        // -12: dest vaddr below the user window.
        assert_eq!(build_load_plan(&mk(ph64(PT_LOAD, 6, 0, 0x1000, 0x10, 0x10)), 2, 64, 1, 0x1000, UAB, UMV), Err(-12));
        // -17: an ELF64 field (p_offset) exceeds 32 bits.
        assert_eq!(build_load_plan(&mk(ph64(PT_LOAD, 6, 0x1_0000_0000, 0x40_0000, 0x10, 0x10)), 2, 64, 1, 0x40_0000, UAB, UMV), Err(-17));
    }

    #[test]
    fn load_plan_rejects_the_u32_overflow_that_the_c_missed() {
        // p_offset=0xFFFF_F000, p_filesz=0x2000: the old C did `p_offset+p_filesz`
        // in u32, which wraps to 0x1000 (< buffer) and PASSED the bound — then
        // copied from `st + 0xFFFF_F000`, a large out-of-bounds read. The u64 sum
        // is 0x1_0000_1000 > buffer, so it is correctly rejected with -11.
        let buf = buf_with_phdrs(64, &ph64(PT_LOAD, 6, 0xFFFF_F000, 0x40_0000, 0x2000, 0x2000));
        assert_eq!(build_load_plan(&buf, 2, 64, 1, 0x40_0000, UAB, UMV), Err(-11));
    }

    #[test]
    fn load_plan_never_panics_on_adversarial_inputs() {
        // An arbitrary load_base (which would overflow a naive dest_va add) over
        // junk program-header bytes must never panic — just return a plan or an
        // error. Exercises the wrapping arithmetic and the bounds-checked reads.
        let mut buf = [0xFFu8; 256];
        buf[64..68].copy_from_slice(&PT_LOAD.to_le_bytes());
        for lb in [0u64, u64::MAX, 0x7fff_ffff_ffff_f000, UAB] {
            let _ = build_load_plan(&buf, 2, 64, 1, lb, UAB, UMV);
            let _ = build_load_plan(&buf, 1, 52, 8, lb, UAB, UMV);
        }
    }

    // --- i386 dynamic relocations (J10.3a) --------------------------------
    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    // Build a minimal ELFCLASS32 static-PIE image with two program headers
    // (PT_LOAD covering everything, PT_DYNAMIC), a dynamic section naming the REL
    // (or, if `rela`, RELA) table, and the REL entries. e_phoff = 64.
    fn build_i386_reloc_image(rels: &[(u32, u32)], rela: bool) -> [u8; 1024] {
        let mut b = [0u8; 1024];
        // phdr0 PT_LOAD @64: type=1, offset=0, vaddr=0, filesz=1024.
        put_u32(&mut b, 64, 1);
        put_u32(&mut b, 64 + 16, 1024);
        // phdr1 PT_DYNAMIC @96: type=2, offset=dyn_off, filesz set below.
        let dyn_off = 128u32;
        put_u32(&mut b, 96, 2);
        put_u32(&mut b, 96 + 4, dyn_off);
        // dynamic section @128: Elf32_Dyn { tag, val } (8 bytes).
        let rel_vaddr = 256u32;
        let rel_sz = rels.len() as u32 * 8;
        let mut d = dyn_off as usize;
        let tag = if rela { 7u32 } else { 17u32 }; // DT_RELA vs DT_REL
        put_u32(&mut b, d, tag);
        put_u32(&mut b, d + 4, rel_vaddr);
        d += 8;
        put_u32(&mut b, d, 18); // DT_RELSZ
        put_u32(&mut b, d + 4, rel_sz);
        d += 8;
        put_u32(&mut b, d, 19); // DT_RELENT
        put_u32(&mut b, d + 4, 8);
        d += 8;
        put_u32(&mut b, d, 0); // DT_NULL
        d += 8;
        put_u32(&mut b, 96 + 16, d as u32 - dyn_off); // PT_DYNAMIC p_filesz
        // REL table @ file offset 256 (== rel_vaddr, since p_offset=p_vaddr=0).
        let mut r = rel_vaddr as usize;
        for (r_offset, r_info) in rels {
            put_u32(&mut b, r, *r_offset);
            put_u32(&mut b, r + 4, *r_info);
            r += 8;
        }
        b
    }

    #[test]
    fn i386_reloc_locate_and_target() {
        // Two R_386_RELATIVE (type 8) + one R_386_NONE (type 0).
        let img = build_i386_reloc_image(&[(0x10, 8), (0x20, 8), (0x30, 0)], false);
        let rt = i386_reloc_locate(&img, 64, 2).expect("locate ok");
        assert_eq!(rt, ElfI386RelocTable { rel_file_off: 256, nrel: 3 });
        let (va, mz) = ([0u64], [1024u64]);
        assert_eq!(i386_reloc_target(&img, 256, 0, 0, &va, &mz), Ok(Some(0x10)));
        assert_eq!(i386_reloc_target(&img, 256, 2, 0, &va, &mz), Ok(None)); // R_386_NONE
        // slide applied and target re-validated against the slid segment.
        assert_eq!(i386_reloc_target(&img, 256, 1, 0x40_0000, &[0x40_0000], &[1024]), Ok(Some(0x40_0020)));
    }

    #[test]
    fn i386_reloc_rejects_malformed() {
        // DT_RELA on i386 is rejected outright.
        assert_eq!(i386_reloc_locate(&build_i386_reloc_image(&[(0x10, 8)], true), 64, 2), Err(-16));
        // An unknown relocation type fails closed.
        let img = build_i386_reloc_image(&[(0x10, 5)], false);
        assert_eq!(i386_reloc_target(&img, 256, 0, 0, &[0u64], &[1024u64]), Err(-16));
        // A target outside every loaded segment fails closed.
        let img = build_i386_reloc_image(&[(0x900, 8)], false);
        assert_eq!(i386_reloc_target(&img, 256, 0, 0, &[0u64], &[0x100u64]), Err(-16));
        // No PT_DYNAMIC -> no relocations (success, nrel 0).
        let mut bare = [0u8; 256];
        put_u32(&mut bare, 64, 1); // one PT_LOAD phdr
        assert_eq!(i386_reloc_locate(&bare, 64, 1), Ok(ElfI386RelocTable { rel_file_off: 0, nrel: 0 }));
    }

    #[test]
    fn i386_reloc_never_panics_on_junk() {
        let junk = [0xABu8; 300];
        for phoff in [0u32, 64, 296, 0xFFFF_FFF0] {
            let _ = i386_reloc_locate(&junk, phoff, 8);
        }
        for k in [0u32, 1, 100, u32::MAX] {
            let _ = i386_reloc_target(&junk, 0, k, u64::MAX, &[0u64, 1], &[1u64, 2]);
        }
    }

    // --- x86-64 dynamic relocations (J10.3b) ------------------------------
    fn put_u64(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    // Build a minimal ELFCLASS64 static-PIE image with a PT_LOAD + PT_DYNAMIC,
    // a dynamic section naming the RELA (or, if `use_rel`, DT_REL) table and the
    // dynamic symbol table, plus the RELA entries and the symbols. e_phoff = 64;
    // PT_LOAD maps p_offset=p_vaddr=0 so file offset == vaddr. RELA @512, symtab
    // @1024. Each sym: (st_info, st_shndx, st_value).
    fn build_x86_64_reloc_image(
        relas: &[(u64, u64, i64)],
        syms: &[(u8, u16, u64)],
        use_rel: bool,
    ) -> [u8; 2048] {
        let mut b = [0u8; 2048];
        // phdr0 PT_LOAD @64 (56-byte Elf64_Phdr): p_type@0 p_offset@8 p_vaddr@16 p_filesz@32.
        put_u32(&mut b, 64, 1);
        put_u64(&mut b, 64 + 32, 2048);
        // phdr1 PT_DYNAMIC @120: p_type@0 p_offset@8 p_filesz@32.
        let dyn_off = 256u64;
        put_u32(&mut b, 120, 2);
        put_u64(&mut b, 120 + 8, dyn_off);
        // dynamic section @256: Elf64_Dyn { tag, val } (16 bytes).
        let rela_vaddr = 512u64;
        let rela_sz = relas.len() as u64 * 24;
        let sym_vaddr = 1024u64;
        let mut d = dyn_off as usize;
        put_u64(&mut b, d, if use_rel { 17 } else { 7 }); // DT_REL / DT_RELA
        put_u64(&mut b, d + 8, rela_vaddr);
        d += 16;
        put_u64(&mut b, d, 8); // DT_RELASZ
        put_u64(&mut b, d + 8, rela_sz);
        d += 16;
        put_u64(&mut b, d, 9); // DT_RELAENT
        put_u64(&mut b, d + 8, 24);
        d += 16;
        put_u64(&mut b, d, 6); // DT_SYMTAB
        put_u64(&mut b, d + 8, sym_vaddr);
        d += 16;
        put_u64(&mut b, d, 11); // DT_SYMENT
        put_u64(&mut b, d + 8, 24);
        d += 16;
        put_u64(&mut b, d, 0); // DT_NULL
        d += 16;
        put_u64(&mut b, 120 + 32, d as u64 - dyn_off); // PT_DYNAMIC p_filesz
        // RELA table @512: Elf64_Rela { r_offset(8), r_info(8), r_addend(8) }.
        let mut r = 512usize;
        for (off, info, add) in relas {
            put_u64(&mut b, r, *off);
            put_u64(&mut b, r + 8, *info);
            put_u64(&mut b, r + 16, *add as u64);
            r += 24;
        }
        // symtab @1024: Elf64_Sym { st_name(4) st_info@4 st_other@5 st_shndx@6(u16) st_value@8(u64) ... }.
        let mut sy = 1024usize;
        for (info, shndx, value) in syms {
            b[sy + 4] = *info;
            put_u16(&mut b, sy + 6, *shndx);
            put_u64(&mut b, sy + 8, *value);
            sy += 24;
        }
        b
    }

    const UMV64: u64 = 0x0000_8000_0000_0000;

    #[test]
    fn x86_64_reloc_relative_glob_dat_and_none() {
        let slide = 0x40_0000u64;
        let relas = [
            (0x10u64, 8u64, 0x100i64),         // R_X86_64_RELATIVE
            (0x20u64, (1u64 << 32) | 6, 0i64), // R_X86_64_GLOB_DAT, sym index 1
            (0x30u64, 0u64, 0i64),             // R_X86_64_NONE
        ];
        // sym 0 = reserved null; sym 1 = defined (shndx != 0), st_value 0x2000.
        let syms = [(0u8, 0u16, 0u64), (0x10u8, 1u16, 0x2000u64)];
        let img = build_x86_64_reloc_image(&relas, &syms, false);
        let rt = x86_64_reloc_locate(&img, 64, 2).expect("locate ok");
        assert_eq!(rt.nrela, 3);
        let seg = ([slide], [0x2000u64]);
        // RELATIVE: value = slide + addend.
        assert_eq!(
            x86_64_reloc_resolve(&img, rt.rela_file_off, rt.sym_file_off, 0, slide, UMV64, &seg.0, &seg.1),
            Ok(Some((slide + 0x10, slide + 0x100)))
        );
        // GLOB_DAT defined: value = st_value + slide + addend.
        assert_eq!(
            x86_64_reloc_resolve(&img, rt.rela_file_off, rt.sym_file_off, 1, slide, UMV64, &seg.0, &seg.1),
            Ok(Some((slide + 0x20, 0x2000 + slide)))
        );
        // NONE: skip.
        assert_eq!(
            x86_64_reloc_resolve(&img, rt.rela_file_off, rt.sym_file_off, 2, slide, UMV64, &seg.0, &seg.1),
            Ok(None)
        );
    }

    #[test]
    fn x86_64_reloc_glob_dat_weak_and_rejections() {
        let slide = 0x40_0000u64;
        let relas = [(0x10u64, (1u64 << 32) | 6, 0i64)]; // GLOB_DAT, sym index 1
        let seg = ([slide], [0x2000u64]);

        // Undefined *weak* (shndx 0, STB_WEAK bind => st_info>>4 == 2) resolves to 0.
        let img = build_x86_64_reloc_image(&relas, &[(0u8, 0u16, 0u64), (0x20u8, 0u16, 0u64)], false);
        let rt = x86_64_reloc_locate(&img, 64, 2).unwrap();
        assert_eq!(
            x86_64_reloc_resolve(&img, rt.rela_file_off, rt.sym_file_off, 0, slide, UMV64, &seg.0, &seg.1),
            Ok(Some((slide + 0x10, 0)))
        );

        // Undefined *strong* (STB_GLOBAL) is genuinely unresolved -> reject.
        let img = build_x86_64_reloc_image(&relas, &[(0u8, 0u16, 0u64), (0x10u8, 0u16, 0u64)], false);
        let rt = x86_64_reloc_locate(&img, 64, 2).unwrap();
        assert_eq!(
            x86_64_reloc_resolve(&img, rt.rela_file_off, rt.sym_file_off, 0, slide, UMV64, &seg.0, &seg.1),
            Err(-16)
        );

        // DT_REL on x86-64 is rejected outright.
        assert_eq!(x86_64_reloc_locate(&build_x86_64_reloc_image(&[(0, 8, 0)], &[(0, 0, 0)], true), 64, 2), Err(-16));

        // An unknown relocation type fails closed.
        let img = build_x86_64_reloc_image(&[(0x10, 99, 0)], &[(0, 0, 0)], false);
        let rt = x86_64_reloc_locate(&img, 64, 2).unwrap();
        assert_eq!(
            x86_64_reloc_resolve(&img, rt.rela_file_off, rt.sym_file_off, 0, slide, UMV64, &seg.0, &seg.1),
            Err(-16)
        );
    }

    #[test]
    fn x86_64_reloc_never_panics_on_junk() {
        let junk = [0xCDu8; 400];
        for phoff in [0u32, 64, 396, 0xFFFF_FFF0] {
            let _ = x86_64_reloc_locate(&junk, phoff, 8);
        }
        for k in [0u64, 1, 1000, u64::MAX] {
            let _ = x86_64_reloc_resolve(&junk, 0, 0, k, u64::MAX, u64::MAX, &[0u64, 1], &[1u64, 2]);
            let _ = x86_64_reloc_resolve(&junk, 100, 200, k, u64::MAX, 0, &[u64::MAX], &[u64::MAX]);
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


