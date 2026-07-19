#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz rust_signal_handler_addr_ok. Besides never panicking, a positive result
// must imply the handler address lies strictly inside the task's recorded image
// window [image_base, image_end) with a well-formed (non-empty) window.
fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    let g = |i: usize| u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
    let vaddr = g(0);
    let image_base = g(8);
    let image_end = g(16);
    if horus_shell::rust_signal_handler_addr_ok(vaddr, image_base, image_end) {
        assert!(
            image_base != 0 && image_end > image_base && vaddr >= image_base && vaddr < image_end,
            "handler address accepted outside the recorded image window"
        );
    }
});
