# Testing Horus

## Current state

The Rust security core has **31 unit tests**, and a CI pipeline gates every push and pull request (`.github/workflows/ci.yml`). There is still **no booted-kernel integration test or fuzz harness** — that is the highest-value remaining contribution.

---

## Running the tests

### Rust unit tests

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

This runs the unit tests across the security core:

- `capability.rs` — mint with a subset of rights (no escalation), system-wide / cross-task revocation, stale-generation rejection, lineage low-bit collision safety, fresh-serial allocation across the u32 wrap boundary
- `memory.rs` — the refcount-table trust boundary (a wrong pointer or length is refused, not dereferenced), saturation, decrement-at-zero, valid-user-phys bounds, and the page alloc/free LIFO + exhaustion guards
- `lib.rs` — page-fault validation, capability-rights subset checks, demand-paging (COW / demand-zero) policy, FS-operation right enforcement, and command dispatch
- `rng.rs` — ChaCha20 against the RFC 8439 vector, reseed behaviour
- `sha256.rs` — SHA-256 / HMAC / HKDF / PBKDF2 against published known-answer vectors
- `aead.rs` — the ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD: seal/open round-trip, tampered-ciphertext and tampered-tag rejection (fail-closed), wrong-AAD rejection, and nonce separation

### Full build test

```bash
make test          # cargo tests, then a clean full build (warnings are errors-adjacent)
```

### Manual testing under QEMU

The most useful end-to-end check is still booting and exercising Horus interactively:

```bash
make run            # then interact in the QEMU window or via the serial port
```

```
login root
<enter password>
whoami
uname
help
```

---

## Continuous integration

`.github/workflows/ci.yml` runs three jobs, all hard gates, using only first-party actions:

1. **rust** — `cargo test --release` and `cargo clippy --all-targets -- -D warnings`
2. **kernel** — builds `kernel.elf` and a bootable ISO (x86_64) and uploads them as artifacts
3. **reproducible** — builds `kernel.elf` twice and fails if the two are not byte-for-byte identical

---

## What still needs tests

Already covered by the unit tests above: rights-subset minting, cross-task / system-wide revocation, stale-generation rejection, the refcount trust boundary, and the demand-paging policy. The gaps that remain:

### Booted-kernel integration tests

A harness that boots Horus under QEMU `-nographic`, drives the serial port, and asserts on output. A Python `pexpect` script is a natural fit. Suggested cases:

- Boot completes and the shell prompt appears
- `whoami` returns `root` after a successful root login; a wrong password is rejected
- Accessing a resource without the required capability returns an error
- A userspace page fault does not take down the kernel

### Build-matrix coverage

CI currently builds the default 64-bit configuration. It should also cover `BITS=32` (needs the `i686-unknown-linux-gnu` Rust target), `DEBUG_SHELL=1`, and `MINIMAL_SECURE=1`.

### TLA+ specs

`docs/cap_algebra.tla` and `docs/paging_isolation.tla` model the capability and paging invariants but are not model-checked in CI. Wiring TLC/Apalache into the pipeline would close the loop between the specs and the implementation.

### A real C-side test harness

`tests/test_capability.c` is a standalone illustration that reimplements a simplified `cap_lookup`; it is **not** linked against the kernel's `capability.c` and is not built by the Makefile. A host harness that links the real `capability.c` with mocked `tasks[]` / `get_current_task()` would give the C guards (e.g. the no-ambient-authority check) genuine regression coverage.

---

## Fuzzing

The syscall interface and the Rust FFI boundary are the obvious targets. Useful directions:

- A `cargo-fuzz` target over the pointer-taking FFI entry points (`rust_handle_command`, the refcount and capability functions) — cheap to stand up and runs on the host.
- `syzkaller` with a custom syscall description driving a privileged task under QEMU/KVM, watching for panics, hangs, or unexpected memory accesses.

Contributions to any of the above are very welcome.
