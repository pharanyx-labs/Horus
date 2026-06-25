#![no_std]

mod capability;
mod crypto;
mod memory;

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

#[no_mangle]
pub extern "C" fn rust_validate_page_fault(task_id: u32, fault_addr: u32, error_code: u32) -> bool {
    let _ = (task_id, error_code);
    if fault_addr >= 0x7FB000 && fault_addr < 0x7FC000 { return false; }
    if fault_addr >= 0x400000 && fault_addr < 0x800000 { return true; }
    if fault_addr >= 0xA00000 && fault_addr < 0xB00000 { return true; }
    false
}

#[repr(C)]
pub struct SafeCapability {
    pub raw: u32,
}

#[no_mangle]
pub extern "C" fn rust_cap_has_rights(cap: *const SafeCapability, required: u32) -> bool {
    if cap.is_null() {
        return false;
    }
    unsafe { ((*cap).raw & required) == required }
}

#[no_mangle]
pub extern "C" fn rust_get_user_page_protection(_task_id: u32, vaddr: u32) -> u32 {
    if (vaddr >= 0x400000 && vaddr < 0x800000) ||
       (vaddr >= 0xA00000 && vaddr < 0xB00000) ||
       (vaddr >= 0x7FC000 && vaddr < 0x800000) ||
       (vaddr >= 0xff000000 && vaddr < 0xfff00000) {
        return 0x7;
    }
    0
}

#[no_mangle]
pub extern "C" fn rust_handle_command(cmd: *const u8, len: usize) -> i32 {
    if cmd.is_null() {
        return 0;
    }

    let cmd_slice = unsafe { core::slice::from_raw_parts(cmd, len) };
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

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DemandAction {
    Invalid = -1,
    DemandZero = 0,
    CowCopyNeeded = 1,
    NoAction = 2,
}

#[no_mangle]
pub extern "C" fn rust_handle_demand_page_fault(
    fault_addr: u32,
    err_code: u32,
    is_cow: bool,
    ref_count: u16,
) -> DemandAction {
    if fault_addr >= 0x7FB000 && fault_addr < 0x7FC000 {
        return DemandAction::Invalid;
    }

    let in_user_window =
        (fault_addr >= 0x400000 && fault_addr < 0x800000) ||
        (fault_addr >= 0xA00000 && fault_addr < 0xB00000);

    if !in_user_window {
        return DemandAction::Invalid;
    }

    if fault_addr >= 0xFFC00000 {
        return DemandAction::Invalid;
    }

    let is_write = (err_code & 2) != 0;
    let is_user = (err_code & 4) != 0;

    if is_cow && is_write && is_user {
        if ref_count > 1 {
            return DemandAction::CowCopyNeeded;
        } else {
            return DemandAction::NoAction;
        }
    }

    if (err_code & 1) == 0 && is_user {
        return DemandAction::DemandZero;
    }

    DemandAction::Invalid
}

#[no_mangle]
pub extern "C" fn rust_cow_copy_required(is_cow: bool, is_write: bool, ref_count: u16) -> bool {
    is_cow && is_write && ref_count > 1
}

#[no_mangle]
pub extern "C" fn rust_should_demand_zero(err_code: u32) -> bool {
    (err_code & 1) == 0 && (err_code & 4) != 0
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


