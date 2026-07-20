#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the ELF header validator (the memory-safe front door to the kernel's ELF
// loader) over arbitrary bytes. Two invariants:
//   - it must never panic or read out of bounds for ANY input — the whole point
//     of moving the attacker-controlled header parse into safe Rust;
//   - any header it ACCEPTS must carry only in-range fields, so the C loader can
//     trust them.
fuzz_target!(|data: &[u8]| {
    let mut info = core::mem::MaybeUninit::<horus_shell::ElfHeaderInfo>::zeroed();
    let rc = unsafe {
        horus_shell::rust_elf_validate_header(data.as_ptr(), data.len(), info.as_mut_ptr())
    };
    if rc == 0 {
        let info = unsafe { info.assume_init() };
        assert!(info.ei_class == 1 || info.ei_class == 2);
        assert!(info.e_type == 2 || info.e_type == 3);
        assert!(info.e_phnum >= 1 && info.e_phnum <= 8);
        assert!(info.e_phoff >= 1);
        assert!(info.e_phoff as usize <= data.len().saturating_sub(64));
    }
});
