#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the x86-64 dynamic-relocation parser (incl. the R_X86_64_GLOB_DAT symbol
// lookup) over arbitrary bytes. For any image, e_phoff/e_phnum, slide, and
// segment table it must never panic or read out of bounds; if the table
// locates, resolving each entry must also never panic.
fuzz_target!(|data: &[u8]| {
    if data.len() < 14 {
        return;
    }
    let e_phoff = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let e_phnum = u16::from_le_bytes(data[4..6].try_into().unwrap());
    let slide = u64::from_le_bytes(data[6..14].try_into().unwrap());
    let buf = &data[14..];

    let seg_va = [0u64, 0x40_0000];
    let seg_memsz = [0x2000u64, 0x2000];
    const UMV: u64 = 0x0000_8000_0000_0000;

    let mut rt =
        horus_shell::ElfX8664RelocTable { rela_file_off: 0, sym_file_off: 0, nrela: 0 };
    let rc = unsafe {
        horus_shell::rust_elf_x86_64_reloc_locate(buf.as_ptr(), buf.len(), e_phoff, e_phnum, &mut rt)
    };
    if rc == 0 {
        assert!(rt.nrela <= 8192);
        for k in 0..rt.nrela.min(64) {
            let (mut t, mut v) = (0u64, 0u64);
            let _ = unsafe {
                horus_shell::rust_elf_x86_64_reloc_resolve(
                    buf.as_ptr(),
                    buf.len(),
                    rt.rela_file_off,
                    rt.sym_file_off,
                    k,
                    slide,
                    UMV,
                    seg_va.as_ptr(),
                    seg_memsz.as_ptr(),
                    seg_va.len() as u32,
                    &mut t,
                    &mut v,
                )
            };
        }
    }
});
