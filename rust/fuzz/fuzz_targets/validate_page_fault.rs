#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz rust_validate_page_fault over arbitrary scalar inputs. It is a pure
// region-membership predicate (is the faulting address a legal user address for
// this task's image/heap?) and must never panic — no overflow, no UB — for any
// combination of fault address, error code, and image/heap bounds.
fuzz_target!(|data: &[u8]| {
    if data.len() < 41 {
        return;
    }
    let g = |i: usize| u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
    let fault_addr = g(0);
    let image_base = g(8);
    let image_end = g(16);
    let heap_start = g(24);
    let heap_end = g(32);
    let error_code = data[40] as u32;
    let _ = horus_shell::rust_validate_page_fault(
        fault_addr, error_code, image_base, image_end, heap_start, heap_end,
    );
});
