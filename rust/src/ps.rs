//! Task-listing (`ps`) presentation helpers (safe Rust).
//!
//! The kernel stores a task's run state as a bare integer; this module is the
//! single, unit-tested source of truth for turning that into a human-readable
//! name for the `ps` command. Keeping it here (rather than as scattered magic
//! numbers in the shell renderers) means the mapping is tested and the in-kernel
//! shell renders the same labels the policy intends.
//!
//! Task state values (see scheduler.c): 0 = dead/free slot, 1 = runnable,
//! 2 = blocked. Anything else is reported as unknown rather than mislabelled.

/// Single source of truth: a NUL-terminated static label per task state.
const fn state_cstr(state: u32) -> &'static [u8] {
    match state {
        0 => b"dead\0",
        1 => b"run\0",
        2 => b"blkd\0",
        _ => b"?\0",
    }
}

/// C-callable: return a NUL-terminated static label for a task state. The
/// returned pointer is to a `'static` byte string and is always valid.
#[no_mangle]
pub extern "C" fn rust_task_state_name(state: u32) -> *const u8 {
    state_cstr(state).as_ptr()
}

/// Rust-side label (without the trailing NUL); test/consumer helper.
#[cfg(test)]
pub fn state_name(state: u32) -> &'static str {
    let b = state_cstr(state);
    core::str::from_utf8(&b[..b.len() - 1]).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_states() {
        assert_eq!(state_name(0), "dead");
        assert_eq!(state_name(1), "run");
        assert_eq!(state_name(2), "blkd");
    }

    #[test]
    fn unknown_state_is_marked() {
        assert_eq!(state_name(3), "?");
        assert_eq!(state_name(u32::MAX), "?");
    }

    #[test]
    fn ffi_strings_are_nul_terminated() {
        // Every returned pointer must reference a NUL-terminated static buffer.
        for st in [0u32, 1, 2, 99] {
            let p = rust_task_state_name(st);
            let mut len = 0usize;
            // SAFETY: the FFI fn only ever returns 'static b"...\0" literals.
            unsafe {
                while *p.add(len) != 0 {
                    len += 1;
                    assert!(len < 8, "missing NUL terminator");
                }
            }
            assert!(len >= 1);
        }
    }
}
