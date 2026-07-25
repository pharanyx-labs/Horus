<div align="center">

# Horus

**A capability-based x86-64 microkernel with a safe-Rust security core.**

[![CI](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/pharanyx-labs/Horus)](LICENSE)
[![Platform: x86-64](https://img.shields.io/badge/platform-x86--64-blue.svg)](docs/ARCHITECTURE.md)
[![Language: C + Rust](https://img.shields.io/badge/language-C%20%2B%20Rust-orange.svg)](docs/ARCHITECTURE.md)
[![Reproducible build](https://img.shields.io/badge/build-reproducible-success.svg)](docs/BUILDING.md)

[Architecture](docs/ARCHITECTURE.md) ·
[Security](SECURITY.md) ·
[Syscalls](docs/SYSCALLS.md) ·
[Building](docs/BUILDING.md) ·
[Limitations](docs/LIMITATIONS.md) ·
[Roadmap](docs/ROADMAP.md)

</div>

---

## Overview

Horus is an x86-64 microkernel whose single, foundational security primitive is the **capability token**. Every privileged operation — file access, IPC, task creation, signalling, device I/O — requires an explicit, unforgeable capability. Capabilities are minted with reduced rights, delegated between tasks one slot at a time, and revoked instantly and transitively across the whole system. There is no ambient authority: a task that holds no capability for an object cannot even name it.

The kernel is written in C, but its **security-critical core runs in safe, `no_std` Rust** — the capability engine, physical-memory reference counting, the cryptographic primitives (SHA-2, BLAKE2b, Argon2id, HKDF, ChaCha20+HMAC AEAD, CSPRNG), the W^X page policy, the ELF-loader parse, the tamper-evident audit MAC, and every FFI validation boundary. There the type system statically rules out whole classes of memory-safety defects; the crate contains no `unsafe` in its logic, only at the documented, contract-checked FFI shims.

Horus is engineered *as if* it were headed for production — while being explicit that it is not. Every change is gated by CI: 91 Rust unit tests, a clippy pass with all warnings denied, a byte-for-byte **reproducible-build** check, and ~45 headless QEMU self-tests, plus an advisory supply-chain scan with an SBOM.

> ### Project status — research / early development
> Horus boots into 64-bit long mode, runs a ring-3 `init` (PID 1) that supervises a ring-3 shell, and enforces capability-based access control end to end. It has preemptive multi-core scheduling; a userspace filesystem server over an encrypted, persistent object store (per-file POSIX ownership/permissions against a kernel-attested identity, multi-client, crash-atomic via a write-ahead journal); a newlib libc port; ring-3 process control (spawn/exec/kill/signal/wait, masks, alternate stacks); shell pipelines over bounded in-kernel pipes; a ring-3 console driver; measured boot with a TPM-sealed disk key; and a forward-secure audit log. Some subsystems (multi-slot IPC, per-CPU run queues) are deliberately scaffolded rather than finished. This is a research and learning kernel, not a shipping OS.
>
> A July 2026 security & engineering audit ([docs/AUDIT-2026-07.md](docs/AUDIT-2026-07.md)) found the kernel to be disciplined research-grade work but the surrounding **engineering process** (independent review, supply-chain provenance) not yet at a high-assurance bar. Its code findings (A1–A4) are now fixed; the process findings set the current [roadmap](docs/ROADMAP.md). [docs/LIMITATIONS.md](docs/LIMITATIONS.md) is a candid, subsystem-by-subsystem account of exactly where the line sits.

---

## Why Horus

| Principle | How Horus applies it |
|---|---|
| **No ambient authority** | Access derives solely from held capabilities — never from UID, task identity, or global state. |
| **Least privilege by construction** | Capabilities are minted with a *subset* of rights; a spawned task receives only the TCB, frames, and endpoints it needs. A parent delegates one slot at a time (`SYS_CAP_GRANT`) into a child it supervises. |
| **Verifiable core** | Security-sensitive logic lives in safe Rust with unit tests, RFC known-answer vectors, and machine-checked proofs (Kani); the C/Rust ABI is pinned by mirrored compile-time assertions. |
| **Defence in depth** | Hardware isolation (SMEP/SMAP/UMIP, W^X/NX), a single centralized syscall-authorization choke point, transitive revocation, side-channel flushing, and a forward-secure audit log reinforce one another. |
| **Provenance you can trust** | Byte-for-byte reproducible builds; measured boot records the boot hash chain into a TPM, and the disk key is sealed to a measured-good boot state. |

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                   Userspace  (Ring 3)                     │
 │  init → shell   fs_server   console_server   hello  ...   │
 └──────────────────────┬───────────────────────────────────┘
                        │  syscalls 0–88 (int 0x80, table-dispatched)
 ┌──────────────────────▼───────────────────────────────────┐
 │                  Horus Kernel  (Ring 0)                   │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐      │
 │  │ Capability │  │  Paging /  │  │  Scheduler /    │      │
 │  │  Engine    │  │  COW / W^X │  │  Task + Signals │      │
 │  └────────────┘  └────────────┘  └─────────────────┘      │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐      │
 │  │  Syscall   │  │  IPC / EPs │  │  Auth / Audit   │      │
 │  │  Dispatch  │  │  + Pipes   │  │ (forward-secure)│      │
 │  └────────────┘  └────────────┘  └─────────────────┘      │
 │  ┌────────────────────────────────────────────────────┐  │
 │  │        Rust Security Core  (no_std, safe Rust)     │  │
 │  │  capability.rs  memory.rs  lib.rs (W^X, ELF parse) │  │
 │  │  sha256  blake2b  argon2  rng  aead  audit  auth   │  │
 │  └────────────────────────────────────────────────────┘  │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐      │
 │  │ GDT/IDT/TSS│  │  SMP/APIC  │  │ ATA / RAM store │      │
 │  │  serial    │  │  TPM (TIS) │  │ (encrypted)     │      │
 │  └────────────┘  └────────────┘  └─────────────────┘      │
 └──────────────────────┬───────────────────────────────────┘
 ┌──────────────────────▼───────────────────────────────────┐
 │            Hardware  (x86-64, 1..N cores)                 │
 └──────────────────────────────────────────────────────────┘
```

The kernel runs in 64-bit long mode and so does userspace: ring-3 tasks execute as static-PIE `EM_X86_64` images, relocated at load. The kernel lives in the higher half at `0xFFFFFFFF80000000`, so no user mapping can share an address with kernel state *by construction*. The only 32-bit code left is the boot on-ramp that must be — the multiboot entry stage and the AP startup trampoline. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

---

## Capabilities & security at a glance

- **Transitive, descendant-only revocation.** Revoking a capability nulls it and its exact **derivation subtree** across every task's cspace *and* the kernel root cnode in one atomic Rust sweep, then bumps a per-serial lineage generation — so a stale bit pattern that escaped the structural sweep still fails at point of use. It does *not* touch ancestors, siblings, or independent same-object peers ([audit A1](docs/AUDIT-2026-07.md), fixed; Kani-proved). Task slots are zeroed on reuse.
- **Centralized authorization.** Syscall dispatch is a descriptor table that enforces each call's required capability at one choke point; an unlisted number fails closed, and a `_Static_assert` forbids adding a syscall without a table slot.
- **Hardware isolation.** Ring 0/3 separation with per-task page tables; **SMEP/SMAP/UMIP** engaged when advertised; **W^X** via `EFER.NXE` + the PTE NX bit — for user memory *and* the kernel's own image (`.text` r-x, `.rodata` r--, `.data`/`.bss` rw-NX, `CR0.WP` set). Every task kernel stack, boot stack, and IST fault stack sits above an unmapped guard page.
- **Register-file isolation.** A task's x87/SSE registers are saved/restored around every ring-3 kernel entry; the kernel is built `-mno-sse` and holds no FPU state of its own to leak.
- **Side-channel hardening.** `CR4.TSD` disables ring-3 `RDTSC`; **flush-on-switch** evicts IBPB / L1D / MDS state between distrusting tasks; **SMT is disabled in software** (sibling threads parked) so no untrusted work co-resides on a core.
- **Modern cryptography, safe Rust.** Argon2id (RFC 9106) password hashing on an in-house BLAKE2b, HKDF-SHA256 key derivation, a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD for storage, and a ChaCha20 fast-key-erasure CSPRNG — all validated against reference vectors.
- **Forward-secure audit log.** Per-entry MAC keys are ratcheted one-way and erased, so history *before* a compromise is cryptographically unforgeable even if the current key is read; a hash-chain head commits to the whole ordered history and `SYS_AUDIT_DIGEST` exposes it for an external monitor.
- **Measured boot + TPM-sealed storage.** A TPM 2.0 TIS driver extends the reproducible boot hash chain (kernel identity → `PCR[8]`, each verified boot module → `PCR[9]`); on a TPM-formatted volume the disk KEK is sealed under `PolicyPCR` and released only by a measured-good boot.

Full posture and threat model: **[SECURITY.md](SECURITY.md)**.

---

## Status at a glance

| Subsystem | State |
|---|---|
| Multiboot2 boot into x86-64 long mode, kernel in the higher half | ✅ Working |
| 64-bit ring-3 ABI (`EM_X86_64` static-PIE, RELA relocation at load) | ✅ Working |
| Console (VGA text + serial) driven by a **ring-3 server** (`console_server`) over IPC | ✅ Working |
| Linux-style timestamped boot log + root-only `dmesg` (`SYS_DMESG`) | ✅ Working |
| GDT/IDT/TSS, hardware user/kernel isolation; kernel + IST + task stack guard pages | ✅ Working |
| Paging, per-task address spaces, higher-half kernel | ✅ Working |
| Capability mint / transfer / move / grant / revoke | ✅ Working |
| Transitive, **descendant-only** revocation + per-serial lineage (audit A1, Kani-proved) | ✅ Working |
| SMEP / SMAP / UMIP hardening (when advertised, CI-gated in CR4) | ✅ Working |
| W^X for user memory **and** the kernel's own image (`CR0.WP` + NX, full leaf sweep) | ✅ Working |
| Per-task x87/SSE context (FXSAVE/FXRSTOR on the ring-3 boundary) | ✅ Working |
| ASLR — per-spawn stack, heap, and PIE image base (30 bits, 4 TiB window above 16 GiB) | ✅ Working |
| Table-driven syscall dispatch (central capability gate, 0–88) | ✅ Working |
| User authentication + lockout (Argon2id memory-hard hashing) | ✅ Working |
| **Forward-secure** audit log (ratcheted per-entry MAC + chain head + `SYS_AUDIT_DIGEST`) | ✅ Working |
| Encryption-at-rest AEAD (ChaCha20 + HMAC-SHA256, per-block HKDF keys) | ✅ Working |
| **Measured boot** (TPM 2.0 TIS, PCR 8/9) + **TPM-sealed** vdisk KEK | ✅ Working |
| PS/2 keyboard input | ✅ Working |
| Preemptive round-robin scheduling (timer-driven, ring-3) | ✅ Working |
| **Flush-on-switch** between distrusting tasks (IBPB / L1D / MDS) | ✅ Working |
| **SMT disabled in software** (sibling threads parked; close co-residency) | ✅ Working |
| `CR4.TSD` — ring-3 `RDTSC` disabled | ✅ Working |
| Fault signals + async task-to-task signals (`CAP_TCB`-gated, mask, altstack) | ✅ Working |
| Ring-3 process control — spawn/exec/kill/exit/wait/grant + image exec | ✅ Working |
| Ring-3 `init` (PID 1) supervising the shell | ✅ Working |
| Userspace filesystem server over the encrypted object store (single filesystem) | ✅ Working |
| Per-file POSIX ownership & permissions (zero-trust, kernel-attested identity) | ✅ Working |
| Multi-client `fs_server` concurrency (identity-routed replies via `SYS_IPC_REPLY_TO`) | ✅ Working |
| Crash-atomic filesystem (write-ahead redo journal + mount-time `fsck`) | ✅ Working |
| Large files (direct + single- + double-indirect blocks, 16 MiB volume) | ✅ Working |
| Disk-backed persistent storage (ATA probe at boot; RAM vdisk fallback) | ✅ Working |
| newlib libc port over a per-process POSIX fd layer | ✅ Working |
| **Shell pipelines** over bounded in-kernel pipes (`SYS_PIPE*`, stdio wired at spawn) | ✅ Working |
| ELF loader parse (header, phdrs, i386 + x86-64 relocations) in memory-safe Rust | ✅ Working |
| Boot-module integrity: SHA-256 manifest embedded in the kernel (audit A4) | ✅ Working |
| Driver privilege separation — console runs as a ring-3 server (`CAP_IO_DEVICE`) | ✅ Working |
| Symmetric multiprocessing (AP bringup, per-CPU preemption, TLB-shootdown IPIs) | ✅ Working *(default-on; `SMP=0` compiles it out)* |
| Reproducible builds | ✅ Working |
| Async notifications (`SYS_NOTIFY` / `SYS_WAIT_NOTIFY`, badge-carrying) | ✅ Working |
| Copy-on-write paging (shared zero page + generic non-zero break) | ✅ Working |
| Userspace shell breadth (many commands; coverage uneven) | 🟡 Partial |
| Endpoint IPC (single-slot mailbox; multi-client replies routed by identity) | 🟡 Partial |
| SMP scheduler *performance* maturity (per-CPU run queues, priorities, affinity) | ⬜ Not yet |

> The two **security**-relevant SMP items — flush-on-switch and SMT co-residency — are done; what remains is *performance* scheduler maturity (a single shared runnable pool, no per-CPU queues or priorities). See [ROADMAP.md](docs/ROADMAP.md) Track 3.

---

## Quick start

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin mtools qemu-system-x86

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-none
```

### Build and run

```bash
make          # produces kernel.elf
make run      # builds boot.iso and launches QEMU (console on serial; nc localhost 4445)
```

Default login: `user` / `password` (or `root` / `rootpass`).

### Verify it

```bash
make test               # Rust unit tests (91) + a clean full build
make smoke              # headless QEMU boot to the ring-3 login prompt, no fault
make smoke-proc         # ring-3 process control: exit/kill/spawn/exec/grant/signal/wait
make reproducible-build # byte-for-byte deterministic kernel.elf
```

### Build flags

| Flag | Default | Effect |
|---|---|---|
| `DEBUG_SHELL` | `0` | Enable the in-kernel debug shell |
| `MINIMAL_SECURE` | `0` | Strip non-essential kernel features (smaller attack surface) |
| `RUST_ENABLED` | `1` | Link the Rust security core (`0` uses C stub shims) |
| `SMP` | `1` | Bring up the application processors; default-on. `SMP=0` boots single-core |
| `STORAGE_ATA` | `0` | Prefer the ATA path in smoke builds; runtime always probes and falls back to the RAM vdisk |
| `COREUTILS_MODULES` | `0` | Ship the ported GNU coreutils + man pages as GRUB boot modules |
| `*_SELFTEST` | `0` | Boot-time self-tests (`ELF_`, `ASLR_`, `PREEMPT_`, `SIGNAL_`, `PROC_`, `COW_`, `FS_`, `SMP_`, `WX_`, …) |

Horus is x86-64 only. See [docs/BUILDING.md](docs/BUILDING.md) for the full toolchain reference, all targets, and troubleshooting.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design decisions, subsystem internals, capability model, memory layout |
| [docs/SYSCALLS.md](docs/SYSCALLS.md) | Per-syscall reference (0–88): numbers, capability requirements, notes |
| [docs/BUILDING.md](docs/BUILDING.md) | Toolchain setup, build targets, build flags, QEMU configuration |
| [SECURITY.md](SECURITY.md) | Security posture, hardening in place, threat model, disclosure |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Honest breakdown of what works and what does not |
| [docs/AUDIT-2026-07.md](docs/AUDIT-2026-07.md) | July 2026 security & engineering audit findings + status |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Audit-driven remediation tracks and open contribution areas |
| [TESTS.md](TESTS.md) | Test coverage today and what is still needed |
| [CHANGES.md](CHANGES.md) | Changelog (state of the `main` branch) |

---

## Contributing

Horus is at an early stage, with meaningful work across kernel C, safe Rust, and tooling. Contributions of all sizes are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Security

Please report vulnerabilities responsibly via a GitHub Security Advisory rather than a public issue. Details and scope are in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) — Copyright © 2026 The Horus Project.
