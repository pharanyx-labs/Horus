# Contributing to Horus

Thank you for your interest. Horus is an early-stage research microkernel and there is meaningful work available at every level — from fixing shell command stubs to designing the SMP scheduler. Contributions of all sizes are welcome.

---

## Before you start

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) to understand the design. Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) to understand what is and is not working. This will save you time and help you choose work that fits the project's direction.

If you are planning something non-trivial, open an issue first to discuss the approach. This avoids parallel effort and conflicting designs.

---

## Setting up

```bash
git clone https://github.com/yossicohenmcr-ctrl/Horus
cd Horus

# Install build tools (Debian/Ubuntu)
sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin qemu-system-x86

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-none

# Build and run
make
make run
```

See [docs/BUILDING.md](docs/BUILDING.md) for a full explanation of build targets and flags.

---

## Where help is needed

The [ROADMAP](docs/ROADMAP.md) lists planned work in priority order. Here are specific areas by skill set:

### C kernel work

- **Crash-recovery replay for the intent log** (`src/kernel/storage.c`): The intent log records in-flight operations (alloc/free/create) but currently has no replay pass on mount. Replaying it after an unclean shutdown would make the filesystem consistent after a power loss.
- **Scheduler priorities / fairness** (`src/kernel/scheduler.c`): The round-robin timer preemption works; adding weights or priority queues would make it more suitable as a base for real workloads.
- **Concurrent IPC / multi-client fs_server** (`userspace/fs_server.c`): The fs_server currently handles one client at a time (single endpoint); a proper select/multiplex loop would allow multiple tasks to use the filesystem concurrently.

### Rust work

- **Argon2 tuning** *(multi-lane + configurable cost done)*: `rust/src/argon2.rs` now supports `p ≥ 1` lanes and the `m`/`t`/`p` cost is set by three `kernel.h` defines. Remaining nice-to-haves: a true intra-request threaded fill (the lanes are currently filled sequentially, so `p > 1` changes the hash but not wall-clock time on one core), and exposing the cost profile to an admin at runtime.
- **Property-based tests for the capability core**: add a `proptest`/`quickcheck`-style harness (or hand-rolled generators, since the crate is `no_std`) over mint/transfer/revoke to fuzz the lineage and revocation invariants beyond the current example-based tests.
- **Kani / Verus verification**: Apply a Rust verification tool to `capability.rs` to formally verify the revocation properties.

### Testing

- **Integration test suite**: A headless smoke-boot test (`make smoke`) already runs in CI and asserts the kernel boots to userspace with no fault. Extend it into a harness that drives scripted shell sessions (login, capability denials, ELF-under-W^X) and checks the output.
- **Syscall fuzzer**: Apply coverage-guided fuzzing to the syscall interface. The kernel runs in QEMU under a controlled environment; `syzkaller` or a custom harness could work.
- **More Rust unit tests**: the crate has 54 tests today (capability revocation/lineage/mint-subsetting, the refcount trust boundary, the crypto vectors, the AEAD, the tamper-evident audit MAC/chain, BLAKE2b + Argon2id against reference vectors, the W^X policy, the signal-handler-address window). Gaps worth filling: serial-wrap edge cases and lineage-generation wraparound.

### Documentation

- Any clarification to [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or [docs/BUILDING.md](docs/BUILDING.md)
- Annotated examples showing how to use the capability API from userspace
- TLA+ extensions to the existing specifications

---

## Code style

### C

- `snake_case` for functions and variables
- `UPPER_CASE` for constants and macros
- Types end in `_t` (`tcb_t`, `capability_t`)
- No comments explaining what the code does — only why, for non-obvious invariants
- No dynamic allocation in the kernel (no `malloc` — everything is statically allocated or stack-allocated)
- All kernel code is freestanding — no libc headers except via the kernel header

### Rust

- Follow standard `rustfmt` formatting
- All kernel-side Rust must be `no_std`, `no_alloc`
- FFI functions exposed to C must be `extern "C"` with `#[no_mangle]`
- No `unsafe` in `capability.rs`, `memory.rs`, or `lib.rs` — unsafe belongs exclusively in the C-side FFI shims

---

## Submitting a pull request

1. Fork the repository and create a branch from `main`
2. Make your changes. Keep commits focused — one logical change per commit
3. Ensure `make` succeeds with no new warnings
4. Ensure `make test` passes
5. If your change affects the architecture, update `docs/ARCHITECTURE.md`
6. Open a pull request with a clear description of what changed and why

Pull requests that break the build, introduce new warnings without justification, or touch security-critical paths without explanation will be held for discussion before merging.

---

## A note on security changes

The capability system, authentication, and audit log are security-critical paths. Changes to these areas receive closer review. If you are proposing a change that affects security properties — even positively — describe the invariant you are preserving or introducing, and explain why the change does not break existing guarantees.

If you find a security issue, please follow the disclosure process in [SECURITY.md](SECURITY.md).
