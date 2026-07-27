# Host-side tests

This directory holds test code compiled and run **on the build host**, outside QEMU, for fast
iteration on logic that does not need a booted kernel.

| File | Covers |
|---|---|
| `test_capability.c` | Capability lookup, mint, and revocation logic against the C structures |

## Running

```bash
make test     # runs these along with the full self-test sweep
```

## Where the real coverage lives

Host-side C tests are a convenience, not the authority. The binding tests for Horus's
security properties are elsewhere:

| Suite | Location | Run with |
|---|---|---|
| Capability algebra unit tests | `rust/src/capability.rs` | `cargo test --manifest-path rust/Cargo.toml` |
| Kani proofs (revocation subtree) | `rust/src/` | `cargo kani` |
| FFI boundary fuzzing | `rust/fuzz/` | `cargo +nightly fuzz run <target>` |
| Kernel integration self-tests | `src/kernel/selftest.c`, `userspace/` | `make smoke-<name>` |
| Capability conformance (29 checks) | `userspace/captest.c` | `make smoke-captest` |
| Scripted shell sessions | `tools/*_session.py` | `make smoke-session` |

See [`../TESTS.md`](../TESTS.md) for the full catalogue and what each test proves.

## Adding a test here

Only add a host-side test when the logic genuinely does not depend on a running kernel — no
page tables, no scheduler, no real cspaces. Anything that touches kernel state belongs in a
QEMU self-test, and anything algebraic belongs in the Rust crate where it can also carry a
Kani proof.
