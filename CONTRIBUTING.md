# Contributing to Horus

Horus is an early-stage research microkernel with meaningful work at every level — from filling in shell command stubs to maturing the SMP scheduler. Contributions of all sizes are welcome.

---

## Before you start

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for what is and is not working — it will help you pick work that fits the project's direction. For anything non-trivial, open an issue first to discuss the approach.

---

## Setting up

```bash
git clone https://github.com/pharanyx-labs/Horus
cd Horus

sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin mtools qemu-system-x86 swtpm

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-none

make
make run            # console on serial: nc localhost 4445
```

See [docs/BUILDING.md](docs/BUILDING.md) for the full target/flag reference.

---

## Where help is needed

The [ROADMAP](docs/ROADMAP.md) lists work in priority order. The July 2026 audit's ([docs/AUDIT-2026-07.md](docs/AUDIT-2026-07.md)) **code** findings (A1–A4) are now fixed; the highest-value remaining work is:

- **Track 0 — Assurance & governance** (mostly repository config + CI): the open items are **P2** (add a second reviewer so required CODEOWNERS review can be turned on — it is deliberately off today because with one maintainer it would deadlock every merge) and **P4** (a hermetic, pinned, signed build with SLSA provenance). Branch protection, CodeQL, and Dependabot are already in place.

Specific areas by skill set:

### C kernel work

- **SMP performance maturity** (`src/kernel/scheduler.c`): the security-relevant items (flush-on-switch, SMT parking) are done; multi-core still runs over a *single shared runnable pool*. Per-CPU run queues with load-balancing, then priorities/fairness/affinity, and cache partitioning are the next steps (Roadmap Track 3).
- **Richer IPC** (`src/kernel/syscall_ipc.c`): endpoints are single-slot mailboxes serving one in-flight request; multi-client service is layered on via `SYS_IPC_REPLY_TO`, and notifications and bounded pipes work. A multi-slot mailbox or a worker-pool `fs_server` would allow genuine parallel request processing; IPC send/recv timeouts are also wanted.
- **Larger volumes** (`src/kernel/storage.c`): the 16 MiB volume uses a multi-block data bitmap; scaling to multi-GiB wants the *inode* allocator made multi-block too and the crypto-metadata array bootstrapped from the pool rather than sized in `.bss`.
- **Driver separation** (Roadmap Track 6): move PS/2 keyboard input into the console server, and carve the block/ATA driver into a ring-3 server.

### Rust work

- **Exact per-serial lineage generations** (`rust/src/capability.rs`): the use-after-revoke backstop is active and serial-keyed (finding 3.3) but still a lossy 4096-slot hash; a collision-free per-serial map removes the last (fail-safe, availability-only) imprecision (Roadmap Track 1 residual / Track 5).
- **Argon2 intra-request threading** (`rust/src/argon2.rs`): multi-lane + configurable cost is done, but lanes fill sequentially, so `p > 1` changes the hash without reducing wall-clock time on one core.
- **Extend the proofs**: grow the Kani harness set (revocation subtree + lineage are proved; a multi-cspace + overflow-fallback model and the TLA+ specs are the next targets), and add hand-rolled property generators over mint/transfer/grant/revoke.

### Testing

- **Broaden the scripted session** (`tools/session_test.py`): add W^X-violation and IPC/FS round-trip scenarios, and a negative test proving a granted-then-revoked capability does not disturb the grantor.
- **Syscall fuzzer**: coverage-guided fuzzing of the syscall / FFI boundary (`cargo-fuzz` on the host, or `syzkaller` under QEMU).
- **More Rust unit tests**: the crate has **91** tests today; property-based generators and serial-wrap fuzzing beyond the current boundary example are worthwhile gaps.

### Documentation

- Clarifications to any doc; annotated examples of using the capability API from userspace; TLA+ extensions to `docs/cap_algebra.tla` / `docs/paging_isolation.tla`.

---

## Code style

**C** — `snake_case` functions/variables, `UPPER_CASE` constants/macros, types end in `_t`; comments explain *why*, not *what*; no dynamic allocation in the kernel; freestanding (no libc headers except via the kernel header).

**Rust** — standard `rustfmt`; all kernel-side Rust is `no_std`, `no_alloc`; FFI functions are `unsafe extern "C"` with `#[no_mangle]`, a `# Safety` contract, and fail-closed argument validation; **no `unsafe` in the logic of `capability.rs`, `memory.rs`, or `lib.rs`** — unsafe belongs exclusively in the C-facing FFI shims.

---

## Submitting a pull request

1. Fork and branch from `main`.
2. Keep commits focused — one logical change each.
3. Ensure `make` succeeds with no new warnings and `make test` passes.
4. Run the self-test relevant to your change (`make smoke`, `smoke-proc`, `smoke-fs`, …).
5. Update `docs/ARCHITECTURE.md` (and `docs/SYSCALLS.md` for a new syscall) if the change affects the design.
6. Open a PR with a clear description (see the PR template).

> **Enforcement.** `main` is branch-protected: the four hard-gate checks (Rust+clippy, kernel+ISO build, QEMU smoke-boot, reproducible build) are **required** and enforced for administrators, and force-push/deletion are blocked. Required CODEOWNERS review is intentionally deferred until a second reviewer exists (Roadmap Track 0 / audit P2), so independent review is currently a contributor convention rather than a technical guarantee. Do not merge a PR with a red pipeline.

---

## A note on security changes

The capability system, authentication, audit log, and the process-control authority model (`SYS_KILL`/`SYS_SIGNAL`/`SYS_CAP_GRANT` gating) are security-critical and receive closer review. If your change affects security properties — even positively — describe the invariant you preserve or introduce and why existing guarantees still hold. To report a security issue, follow the disclosure process in [SECURITY.md](SECURITY.md).
