# Tests

This directory holds host-side test code for Horus. The primary suites live elsewhere:

- **Rust unit tests** (**91**) in the `rust/` crate — the security core — plus advisory Kani proofs.
- **Headless QEMU self-tests** driven by the Makefile via `tools/smoke_test.sh` — ~45 `smoke-*` targets, all run in CI (covering boot, W^X leaf sweep single- and multi-core, CR4/TSD protections, stack guards, ELF loader for both classes, ASLR, preemption, signals, process control, COW + non-zero COW, notifications, pipes, flush-on-switch, SMT parking, SMP, capability conformance, the filesystem/libc suite, the console-server / device-delegation suite, coreutils-from-modules incl. tamper rejection, and TPM measured boot + sealing). See [BUILDING.md](../docs/BUILDING.md) for the full list.
- **Scripted integration session** — `make smoke-session` (`tools/session_test.py`) drives the real ring-3 shell over serial (login, identity, least-privilege enforcement) and asserts on the responses; `smoke-session-smp` runs it under `-smp 4`.

## Contents

| File | Description |
|---|---|
| `test_capability.c` | Standalone host illustration. It reimplements a simplified `cap_lookup` and is **not** linked against the kernel's `capability.c`, nor built by the Makefile — treat it as a reference for intended syscall sequences, not coverage. |

## Running

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

A wiring-up opportunity: a host harness linking the real `src/kernel/capability.c` against mocked `tasks[]` / `get_current_task()` would give the C-side capability guards genuine regression coverage. `test_capability.c` is a starting point.

See [TESTS.md](../TESTS.md) at the project root for the full picture of current coverage and what is needed.
