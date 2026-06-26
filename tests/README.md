# Tests

This directory contains test code for Horus.

## Contents

| File | Description |
|---|---|
| `test_capability.c` | Standalone host illustration. It reimplements a simplified `cap_lookup` and is **not** linked against the kernel's `capability.c`, nor built by the Makefile — treat it as a reference, not coverage. |

## Running

The Rust unit tests live in the `rust/` crate and are run with:

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

`test_capability.c` is a reference for intended syscall sequences and is not yet compiled into a standalone test binary.

See [TESTS.md](../TESTS.md) at the project root for the full picture of current coverage and what is needed.
