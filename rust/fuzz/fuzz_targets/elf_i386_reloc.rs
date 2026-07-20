#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the i386 dynamic-relocation parser over arbitrary bytes. For any image,
// e_phoff/e_phnum, slide, and segment table it must never panic or read out of
// bounds — the point of moving the attacker-controlled reloc parse into safe
// Rust. If the table locates, resolving each entry must also never panic.
fuzz_target!(|data: &[u8]| {
    if data.len() < 14 {
        return;
    }
    let e_phoff = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(data[4..6].try_into().unwrap());
    let slide = u64::from_le_bytes(data[6..14].try_into().unwrap());
    let buf = &data[14..];

    let seg_va = [0u64, 0x40_0000];
    let seg_memsz = [0x1000u64, 0x1000];

    let mut rt = horus_shell::ElfI386RelocTable { rel_file_off: 0, nrel: 0 };
    let rc = unsafe {
        horus_shell::rust_elf_i386_reloc_locate(buf.as_ptr(), buf.len(), e_phoff, e_phnum, &mut rt)
    };
    if rc == 0 {
        assert!(rt.nrel <= 8192);
        // Resolve a bounded slice of entries (cap iterations to keep it fast).
        for k in 0..rt.nrel.min(64) {
            let mut target = 0u64;
            let _ = unsafe {
                horus_shell::rust_elf_i386_reloc_target(
                    buf.as_ptr(),
                    buf.len(),
                    rt.rel_file_off,
                    k,
                    slide,
                    seg_va.as_ptr(),
                    seg_memsz.as_ptr(),
                    seg_va.len() as u32,
                    &mut target,
                )
            };
        }
    }
});
