# Contributing to Horus

Thank you for your interest. Horus is an early-stage research microkernel and there is meaningful work available at every level — from fixing shell command stubs to hardening the SMP scheduler. Contributions of all sizes are welcome.

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
sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin mtools qemu-system-x86

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-none

# Build and run
make
make run            # console on serial: nc localhost 4445
```

See [docs/BUILDING.md](docs/BUILDING.md) for a full explanation of build targets and flags.

---

## Where help is needed

The [ROADMAP](docs/ROADMAP.md) lists planned work in priority order. Here are specific areas by skill set:

### C kernel work

- **SMP maturity** (`src/kernel/scheduler.c`): multi-core works behind `SMP=1` over a shared runnable pool. Per-CPU run queues, scheduling priorities/fairness, and making it default-on are the next steps.
- **Notifications** (`src/kernel/syscall_ipc.c`): `SYS_NOTIFY` / `SYS_WAIT_NOTIFY` still return `SYS_ERR_NOSYS` after the capability check — this is the main unimplemented IPC primitive.
- **Richer IPC** (`src/kernel/syscall_ipc.c`): endpoints are single-slot mailboxes serving one in-flight request; multiple-client service is layered on top via `SYS_IPC_REPLY_TO`. A multi-slot mailbox or a worker-pool `fs_server` would allow genuine parallel request processing.
- **Larger volumes** (`src/kernel/storage.c`): the single 512-byte bitmap block caps a volume at 4096 blocks (2 MiB). Multi-block allocation bitmaps would lift the cap — currently a deliberate non-goal, so discuss in an issue first if you want to take it on.

### Rust work

- **Argon2 intra-request threading** (`rust/src/argon2.rs`): multi-lane + configurable cost is done, but lanes are filled sequentially, so `p > 1` changes the hash without reducing wall-clock time on one core.
- **Property-based tests for the capability core**: add hand-rolled generators (the crate is `no_std`) over mint/transfer/grant/revoke to fuzz the lineage and revocation invariants beyond the current example-based tests.
- **Kani / Verus verification**: apply a Rust verification tool to `capability.rs` to formally verify the revocation properties.

### Testing

- **Integration test suite**: `make smoke` boots to userspace with no fault; extend it into a harness that drives scripted shell sessions (login, capability denials, ELF-under-W^X) and checks the output. Gating the existing `smoke-fs` and `smoke-newlib` targets in CI is low-hanging fruit.
- **Syscall fuzzer**: coverage-guided fuzzing of the syscall interface / FFI boundary (`cargo-fuzz` on the host, or `syzkaller` under QEMU/KVM).
- **More Rust unit tests**: the crate has 54 tests today. Gaps worth filling: serial-wrap edge cases and lineage-generation wraparound.

### Documentation

- Clarifications to [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or [docs/BUILDING.md](docs/BUILDING.md)
- Annotated examples showing how to use the capability API from userspace
- TLA+ extensions to the existing specifications

---

## Code style

### C

- `snake_case` for functions and variables; `UPPER_CASE` for constants and macros; types end in `_t`
- Comments explain *why* (non-obvious invariants), not *what*
- No dynamic allocation in the kernel — everything is statically or stack-allocated
- Freestanding — no libc headers except via the kernel header

### Rust

- Standard `rustfmt` formatting
- All kernel-side Rust must be `no_std`, `no_alloc`
- FFI functions exposed to C are `unsafe extern "C"` with `#[no_mangle]`, carry a `# Safety` contract, and validate their arguments (fail closed)
- No `unsafe` in the logic of `capability.rs`, `memory.rs`, or `lib.rs` — unsafe belongs exclusively in the C-facing FFI shims

---

## Submitting a pull request

1. Fork the repository and create a branch from `main`
2. Make your changes. Keep commits focused — one logical change per commit
3. Ensure `make` succeeds with no new warnings, and `make test` passes
4. Run the self-test relevant to your change (`make smoke`, `smoke-proc`, `smoke-fs`, …)
5. If your change affects the architecture, update `docs/ARCHITECTURE.md` (and `docs/SYSCALLS.md` for a new syscall)
6. Open a pull request with a clear description of what changed and why (see the PR template)

Pull requests that break the build, introduce new warnings without justification, or touch security-critical paths without explanation will be held for discussion before merging.

---

## A note on security changes

The capability system, authentication, audit log, and the process-control authority model (`SYS_KILL`/`SYS_SIGNAL`/`SYS_CAP_GRANT` gating) are security-critical paths and receive closer review. If you are proposing a change that affects security properties — even positively — describe the invariant you are preserving or introducing, and explain why the change does not break existing guarantees.

If you find a security issue, please follow the disclosure process in [SECURITY.md](SECURITY.md).
