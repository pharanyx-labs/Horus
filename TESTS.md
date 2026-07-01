# Testing Horus

## Current state

The Rust security core has **48 unit tests**, and a CI pipeline gates every push and pull request (`.github/workflows/ci.yml`). Three **headless QEMU boot tests** run in CI: `make smoke` boots the kernel and asserts it reaches userspace with no fault, `make smoke-elf` boots a real multi-segment ELF and asserts the loader enforced W^X, and `make smoke-preempt` spawns two non-yielding ring-3 tasks and asserts the timer preempts and time-slices them. There is still no deeper booted-kernel integration test (driving the shell through scripted sessions) or fuzz harness; those are the highest-value remaining contributions.

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
- `audit.rs` — the tamper-evident audit MACs: per-entry MAC determinism, sequence/content/key binding (defeats slot swap, replay, in-place edit), domain-separated chain IV, order-sensitivity of the chain head, a full record-then-verify cycle with tamper detection, the constant-time MAC compare, and FFI null rejection
- `lib.rs` (W^X) — `rust_user_page_is_noexec`: stack windows are non-executable, image/heap/code stay executable
- `ps.rs` — task state-name labels

### Headless smoke-boot test

```bash
make smoke          # SMOKE_TIMEOUT=<seconds> to override the default 40
```

Boots the kernel under QEMU with no display (`tools/smoke_test.sh`, software TCG so it needs no host KVM), captures the serial port, and asserts the ring-3 shell banner appears with no `PAGE FAULT` / CPU exception / `PANIC` and no triple-fault. Reaching the banner proves the whole boot path end to end: kernel init, the loader, per-task paging including the W^X stack, dropping to ring 3 and executing there, the syscall dispatch table servicing `SYS_WRITE`, and console output.

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

`.github/workflows/ci.yml` runs eight jobs, all hard gates:

1. **rust** — `cargo test --release` and `cargo clippy --all-targets -- -D warnings`
2. **kernel** — builds `kernel.elf` and a bootable ISO (x86-64) and uploads them as artifacts
3. **altconfigs** — a build matrix over `DEBUG_SHELL=1` and `MINIMAL_SECURE=1` (the `#ifdef`-toggled configurations, which have broken silently before)
4. **smoke** — installs QEMU and runs `make smoke` (headless boot to the shell banner, no fault)
5. **smoke-elf** — runs `make smoke-elf`: boots a real multi-segment ELF and requires `ELF_SELFTEST: PASS` (the loader mapped each `PT_LOAD` under the correct W^X permissions)
6. **smoke-preempt** — runs `make smoke-preempt`: spawns two non-yielding ring-3 tracers and requires `PREEMPT_SELFTEST: PASS` (the timer time-sliced them, proven by interleaved traces)
7. **reproducible** — builds `kernel.elf` twice and fails if the two are not byte-for-byte identical
8. **security** — Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`, and a CycloneDX SBOM

All but the security job use only first-party / pinned actions; the security job additionally installs third-party scanners and is advisory (non-blocking).

---

## What still needs tests

Already covered by the unit tests above: rights-subset minting, cross-task / system-wide revocation, stale-generation rejection, the refcount trust boundary, and the demand-paging policy. The gaps that remain:

### Deeper booted-kernel integration tests

The `make smoke` test already covers "boot completes and userspace runs with no fault." The remaining gap is a harness that *drives* the serial port through scripted sessions and asserts on the responses (a Python `pexpect` script is a natural fit). Suggested cases:

- `whoami` returns `root` after a successful root login; a wrong password is rejected
- Accessing a resource without the required capability returns an error
- An ELF loaded through `SYS_RECEIVE_PROGRAM` runs under W^X (code executes; a write to a code page faults)

### Build-matrix coverage

CI builds the default configuration plus a matrix over `DEBUG_SHELL=1` and `MINIMAL_SECURE=1` (the `altconfigs` job) and the `ELF_SELFTEST=1` configuration (the `smoke-elf` job). Horus is x86-64 only, so there is no longer a 32-bit build variant to cover.

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
