# Horus

[![CI](https://github.com/yossicohenmcr-ctrl/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/yossicohenmcr-ctrl/Horus/actions/workflows/ci.yml)

A capability-based microkernel for x86 and x86-64, written in C and Rust.

---

Horus is a research microkernel that treats **capability tokens** as the single foundational security primitive. Every operation — file access, IPC, task creation, device I/O — requires an explicit capability. Capabilities can be minted with reduced rights, transferred between tasks, and revoked instantly across the entire system. The kernel is written in C; the capability engine, memory reference counting, and security-sensitive validation are implemented in safe, no_std Rust.

**Current status: early development.**
Horus boots, runs userspace, and enforces capability-based access control. A number of subsystems — disk I/O, the filesystem server, SMP — are scaffolded but not yet complete. This is a research and learning project, not a production kernel. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for an honest account of where things stand.

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                   Userspace  (Ring 3)                    │
 │     shell          hello       fs_server      captest    │
 └──────────────────────┬───────────────────────────────────┘
                        │  syscalls (~51 defined)
 ┌──────────────────────▼───────────────────────────────────┐
 │                  Horus Kernel  (Ring 0)                  │
 │                                                          │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐     │
 │  │ Capability │  │  Paging /  │  │  Scheduler /    │     │
 │  │  System    │  │  Memory    │  │  Task Mgmt      │     │
 │  └────────────┘  └────────────┘  └─────────────────┘     │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐     │
 │  │  Syscall   │  │  IPC /     │  │  Auth / Audit   │     │
 │  │  Handler   │  │  Notifs    │  │  Logging        │     │
 │  └────────────┘  └────────────┘  └─────────────────┘     │
 │                                                          │
 │  ┌────────────────────────────────────────────────────┐  │
 │  │        Rust Security Core  (no_std, safe Rust)     │  │
 │  │    capability.rs     memory.rs     crypto.rs       │  │
 │  └────────────────────────────────────────────────────┘  │
 │                                                          │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐     │
 │  │  Terminal  │  │  GDT / IDT │  │  ATA / RAM      │     │
 │  │  / VGA     │  │  / TSS     │  │  Filesystem     │     │
 │  └────────────┘  └────────────┘  └─────────────────┘     │
 └──────────────────────┬───────────────────────────────────┘
                        │
 ┌──────────────────────▼───────────────────────────────────┐
 │              Hardware  (x86 / x86-64)                    │
 └──────────────────────────────────────────────────────────┘
```

---

## Status at a glance

| Subsystem | State |
|---|---|
| Multiboot boot (32-bit and 64-bit) | Working |
| VGA terminal and serial output | Working |
| GDT / IDT / TSS | Working |
| Hardware-enforced user/kernel isolation | Working |
| Paging, memory isolation, per-task address spaces | Working |
| Capability mint, transfer, and revoke | Working |
| Cross-task capability revocation | Working |
| Lineage tracking (use-after-revoke prevention) | Working |
| User authentication and lockout | Working |
| Audit logging | Working |
| Keyboard input (PS/2) | Working |
| Round-robin task scheduling | Working |
| Reproducible builds | Working |
| Userspace shell and commands | Partial |
| Endpoint-based IPC | Partial |
| RAM-backed filesystem | Partial |
| Copy-on-write paging | Partial |
| ATA disk driver | Stub |
| Userspace filesystem server | Stub |
| Disk-backed persistent storage | Not yet |
| Symmetric multiprocessing | Not yet |
| Preemptive scheduling | Not yet |

---

## Quick start

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin qemu-system-x86

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-none
```

### Build and run (64-bit, default)

```bash
make          # produces kernel.elf
make run      # builds boot.iso, launches QEMU
```

### Build (32-bit)

```bash
make BITS=32
rustup target add i686-unknown-linux-gnu
make BITS=32
```

### Reproducible build

```bash
make reproducible-build
```

The kernel binary is built with a fixed `SOURCE_DATE_EPOCH` and a seeded compiler random, producing a byte-for-byte identical binary across clean builds on the same toolchain version.

### Build flags

| Flag | Default | Effect |
|---|---|---|
| `BITS` | `64` | Target architecture (`32` or `64`) |
| `DEBUG_SHELL` | `0` | Enable in-kernel debug shell |
| `MINIMAL_SECURE` | `0` | Strip non-essential kernel features |
| `RUST_ENABLED` | `1` | Link the Rust security core |

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design decisions, subsystem internals, capability model |
| [docs/BUILDING.md](docs/BUILDING.md) | Toolchain setup, build targets, QEMU configuration |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Honest breakdown of what works and what does not |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Planned milestones and open contribution areas |

---

## Contributing

Horus is at an early stage and there is meaningful work available across kernel C, safe Rust, and tooling. Contributions of all sizes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.

## License

[MIT](LICENSE) — Copyright (c) 2026 Horus Project
