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

- **Preemptive scheduler** (`src/kernel/scheduler.c`): Hook the timer ISR to force a task switch. The round-robin logic already exists; it just needs to be called from the interrupt path.
- **IPC call/reply** (`src/kernel/syscall.c`): Complete `SYS_IPC_CALL` so a caller blocks until a server replies atomically (it is currently a thin wrapper over send).
- **Blocking IPC endpoints** (`src/kernel/syscall.c`): replace the busy-spin-with-`yield()` rendezvous with real blocking/queueing semantics.
- **ATA + storage integration** (`src/kernel/ata.c`, `src/kernel/storage.c`): Wire the working ATA driver to the on-disk inode format sketched in `storage.c`.
- **Shell command stubs** (`userspace/shell.c`): Fill in `ls`, `cat`, `mkdir`, `rm`, and `spawn` to call the correct syscalls.

### Rust work

- **Argon2id**: Port or write a `no_std`-compatible Argon2id implementation to replace the current PBKDF2-HMAC-SHA256 password hashing (a stronger memory-hard KDF).
- **Property-based tests for the capability core**: add a `proptest`/`quickcheck`-style harness (or hand-rolled generators, since the crate is `no_std`) over mint/transfer/revoke to fuzz the lineage and revocation invariants beyond the current example-based tests.
- **Kani / Verus verification**: Apply a Rust verification tool to `capability.rs` to formally verify the revocation properties.

### Testing

- **Integration test suite**: A headless smoke-boot test (`make smoke`) already runs in CI and asserts the kernel boots to userspace with no fault. Extend it into a harness that drives scripted shell sessions (login, capability denials, ELF-under-W^X) and checks the output.
- **Syscall fuzzer**: Apply coverage-guided fuzzing to the syscall interface. The kernel runs in QEMU under a controlled environment; `syzkaller` or a custom harness could work.
- **More Rust unit tests**: the crate has 48 tests today (capability revocation/lineage/mint-subsetting, the refcount trust boundary, the crypto vectors, the AEAD, the tamper-evident audit MAC/chain, the W^X policy). Gaps worth filling: serial-wrap edge cases and lineage-generation wraparound.

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
