#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the PT_LOAD load-plan builder. For any program-header bytes, class,
// phoff/phnum, and load_base it must never panic or read out of bounds; and any
// segment it accepts must be safe for the C loader to execute — file source
// range inside the buffer, map target inside the user window, non-negative
// zero-fill tail.
fuzz_target!(|data: &[u8]| {
    if data.len() < 15 {
        return;
    }
    let ei_class = data[0];
    let e_phoff = u32::from_le_bytes(data[1..5].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(data[5..7].try_into().unwrap());
    let load_base = u64::from_le_bytes(data[7..15].try_into().unwrap());
    let buf = &data[15..];

    const UAB: u64 = 0x0040_0000;
    const UMV: u64 = 0x0000_8000_0000_0000;

    let mut plan = core::mem::MaybeUninit::<horus_shell::ElfLoadPlan>::zeroed();
    let rc = unsafe {
        horus_shell::rust_elf_build_load_plan(
            buf.as_ptr(),
            buf.len(),
            ei_class,
            e_phoff,
            e_phnum,
            load_base,
            UAB,
            UMV,
            plan.as_mut_ptr(),
        )
    };
    if rc == 0 {
        let plan = unsafe { plan.assume_init() };
        assert!(plan.nseg <= 8);
        for i in 0..plan.nseg as usize {
            let s = plan.segs[i];
            assert!(s.dest_va >= UAB && s.dest_va < UMV);
            assert!(s.file_off as u64 + s.file_sz as u64 <= buf.len() as u64);
            assert!(s.mem_sz >= s.file_sz);
        }
    }
});
