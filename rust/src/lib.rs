#![no_std]
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

#[cfg(not(test))]
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

/// Validate a would-be ring-3 signal-handler entry address. On a fault the
/// kernel iretq's ring 3 to this address, so it must be a plausible user *code*
/// location: inside the loader's user image window `[0x400000, 0x800000)`.
/// Anything else (the stack, the heap, the kernel image, an unmapped address, or
/// 0) is rejected so a task cannot register a handler that redirects control
/// flow somewhere it should not run. Pure value predicate — no pointer deref.
#[no_mangle]
pub extern "C" fn rust_signal_handler_addr_ok(vaddr: u32) -> bool {
    const USER_CODE_LO: u32 = 0x0040_0000;
    const USER_CODE_HI: u32 = 0x0080_0000;
    vaddr >= USER_CODE_LO && vaddr < USER_CODE_HI
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

#[cfg(test)]
mod tests {
    use super::*;

    // err_code bit layout used throughout: present=1, write=2, user=4.
    const PRESENT: u32 = 1;
    const USER: u32 = 4;

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
        // Inside the user code window [0x400000, 0x800000) -> accepted.
        assert!(rust_signal_handler_addr_ok(0x400000)); // window base (inclusive)
        assert!(rust_signal_handler_addr_ok(0x401234)); // a real handler entry
        assert!(rust_signal_handler_addr_ok(0x7fffff)); // last byte in-window
        // Outside the window -> rejected (fail closed).
        assert!(!rust_signal_handler_addr_ok(0));        // null
        assert!(!rust_signal_handler_addr_ok(0x3fffff)); // just below the base
        assert!(!rust_signal_handler_addr_ok(0x800000)); // one past the top
        assert!(!rust_signal_handler_addr_ok(0x7d0000 + 0x400000)); // ~stack, mapped high
        assert!(!rust_signal_handler_addr_ok(0x100000)); // kernel image
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


