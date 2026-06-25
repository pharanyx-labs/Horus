# Testing Horus

## Current state

Testing coverage is minimal. There is one Rust unit test in the crate and no automated integration tests. Expanding the test suite is one of the highest-priority contributions the project needs.

---

## Running the existing tests

### Rust unit tests

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

This runs the single test in `rust/src/capability.rs` which exercises basic capability slot operations.

### Full build test

```bash
make test
```

This runs the Rust tests, then does a clean full build to verify that all C and assembly sources compile without errors or new warnings.

### Manual testing under QEMU

The most useful test is booting Horus and exercising it interactively:

```bash
make run
```

In the QEMU window (or via `nc localhost 4445` on the serial port):

```
login root
<enter password>
whoami
uname
ps
help
```

---

## What needs tests

### Rust unit tests (`rust/src/`)

The capability module has one test. It needs coverage for:

- Minting a capability with a subset of rights and verifying the rights are restricted
- Revoking a capability and verifying derived capabilities are invalidated
- Verifying that a capability with a stale generation is rejected
- Verifying that primordial capabilities (`0xC0DE` prefix) cannot be revoked
- Cross-task revocation: capability in task A is derived from one in task B; revoking in task B invalidates task A's copy

### Integration tests

An integration test should:

1. Boot Horus under QEMU with `-nographic`
2. Send input to the serial port
3. Read and assert on the serial output

A minimal harness could use `expect` or a Python `pexpect` script. Suggested test cases:

- Boot completes and shell prompt appears
- `whoami` returns `root` after login as root
- `login` with a wrong password is rejected
- Accessing a resource without a capability returns an error
- A task that page-faults does not crash the kernel

### Build matrix tests

CI should verify that both `BITS=32` and `BITS=64` build without errors, and that the `DEBUG_SHELL=1` and `MINIMAL_SECURE=1` variants also compile cleanly.

---

## Test directory

`tests/test_capability.c` contains a C-language capability test skeleton. It is not yet compiled into a runnable test binary — it exists as a reference for the intended syscall sequences.

---

## Fuzzing

The syscall interface is an obvious fuzzing target. A useful harness would:

1. Boot a minimal Horus kernel under QEMU with KVM
2. Drive a privileged task that calls each syscall with mutated arguments
3. Check for kernel panics, hangs, or unexpected memory accesses

`syzkaller` with a custom syscall description file is a natural fit for this. Contributions here are very welcome.
