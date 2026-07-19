#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the constant-time equality primitive rust_ct_eq. Split the input into two
// halves and compare equal-length prefixes, asserting the invariants a
// constant-time compare must uphold: symmetry, agreement with a plain byte
// comparison, and reflexivity on a non-empty buffer. A panic or a violated
// invariant is a real bug.
fuzz_target!(|data: &[u8]| {
    let mid = data.len() / 2;
    let (a, b) = data.split_at(mid);
    let len = core::cmp::min(a.len(), b.len());
    unsafe {
        let r_ab = horus_shell::rust_ct_eq(a.as_ptr(), b.as_ptr(), len);
        let r_ba = horus_shell::rust_ct_eq(b.as_ptr(), a.as_ptr(), len);
        assert_eq!(r_ab, r_ba, "rust_ct_eq must be symmetric");

        // len == 0 is fail-closed (0), matching rust_ct_eq's contract.
        let expect = if len == 0 { 0 } else { (a[..len] == b[..len]) as i32 };
        assert_eq!(r_ab, expect, "rust_ct_eq must agree with a plain comparison");

        if !a.is_empty() {
            assert_eq!(
                horus_shell::rust_ct_eq(a.as_ptr(), a.as_ptr(), a.len()),
                1,
                "rust_ct_eq must be reflexive on a non-empty buffer"
            );
        }
    }
});
