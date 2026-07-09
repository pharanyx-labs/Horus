# Tests

This directory contains host-side test code for Horus. The primary test suites live elsewhere:

- **Rust unit tests** (54) in the `rust/` crate — the security core.
- **Headless QEMU self-tests** driven by the Makefile (`make smoke`, `smoke-elf`, `smoke-preempt`, `smoke-signal`, `smoke-proc`, `smoke-smp`, `smoke-fs`, `smoke-newlib`) via `tools/smoke_test.sh`.

## Contents

| File | Description |
|---|---|
| `test_capability.c` | Standalone host illustration. It reimplements a simplified `cap_lookup` and is **not** linked against the kernel's `capability.c`, nor built by the Makefile — treat it as a reference for intended syscall sequences, not coverage. |

## Running

The Rust unit tests:

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

A wiring-up opportunity: a host harness that links the real `src/kernel/capability.c` against mocked `tasks[]` / `get_current_task()` would give the C-side capability guards genuine regression coverage. `test_capability.c` is a starting point.

See [TESTS.md](../TESTS.md) at the project root for the full picture of current coverage and what is needed.
