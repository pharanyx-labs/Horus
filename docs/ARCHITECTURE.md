# Horus Architecture

This document describes the design and internals of the Horus microkernel. It is intended for contributors wanting to understand the system before working on it, and for anyone evaluating the design.

---

## Design philosophy

Horus is built around one principle: **no ambient authority**. A task cannot access any resource — files, other tasks, devices, memory — unless it holds an explicit capability token granting that access. The kernel enforces this at every system call boundary.

The secondary goal is **verifiability**: the most security-sensitive operations (capability manipulation, memory reference counting) are implemented in safe Rust, where the type system statically rules out whole classes of memory safety bugs.

Horus is a microkernel. The kernel handles only what must run in Ring 0: memory management, capability enforcement, task scheduling, and interrupt handling. Filesystems and device drivers above the hardware abstraction layer are intended to live in userspace, communicating via IPC.

---

## Target hardware

Horus targets **x86 and x86-64** exclusively.

- Default build: `x86-64` (64-bit long mode, PML4 paging, 48-bit virtual addresses)
- Secondary build: `IA-32` (32-bit protected mode, two-level paging)
- Bootloader: **Multiboot2** compatible (GRUB2)
- CPU features detected at runtime: SMAP, AES-NI, SSE2/SSE4.2, TSC, RDRAND

Both targets are supported in the same codebase via `BITS=32` / `BITS=64` build flags and `#if defined(__x86_64__)` guards.

---

## Memory layout

### 64-bit virtual address space

| Region | Virtual address | Notes |
|---|---|---|
| Recursive PML4 | `0xFFFFFFFFFFFFF000` | Page table self-map slot 510 |
| Recursive PDPT | `0xFFFFFFFFFFE00000` | |
| Recursive PD | `0xFFFFFFFFC0000000` | |
| Recursive PT | `0xFFFFFF8000000000` | |
| User text | `0x0000000000400000` | 4 MB initial window |
| User heap | `0x0000000001000000` | Grows upward via `sbrk` |

### Physical memory

| Region | Physical address | Purpose |
|---|---|---|
| User page pool | `0x01000000` | 16,384 × 4 KB pages (64 MB) |
| Kernel stacks | allocated at init | 256 × 8 KB, one per task slot |

### Paging

The kernel uses **recursive page table mapping**: PML4 entry 510 (64-bit) or PDE entry 1023 (32-bit) points back at the page table root. This gives the kernel a fixed virtual window to read and write any page table entry without a separate mapping.

**Copy-on-write** is implemented at the page level. Pages shared after a fork are marked `PAGE_COW`. On the first write fault, `rust_handle_demand_page_fault()` allocates a fresh physical page, copies the content, and remaps the faulting address. Physical pages carry reference counts maintained in Rust (`rust_page_ref_inc`, `rust_page_ref_dec`).

**ASLR**: load address randomisation is seeded from TSC entropy at boot. The infrastructure is in place; full enforcement is an open work item.

---

## Capability system

The capability system is the core security mechanism. All other security properties derive from it.

### What a capability is

A capability is an unforgeable token residing in a task's **capability node (CNode)**. Each CNode has 256 slots. Slots 0–3 are reserved for kernel-assigned capabilities; slots 4–255 are available to userspace.

```c
typedef struct capability {
    uint32_t type;     /* CAP_TCB, CAP_FRAME, CAP_FILE, CAP_ENDPOINT, ... */
    uint32_t rights;   /* bitmask: READ | WRITE | EXEC | GRANT | MINT | REVOKE | ... */
    uint64_t object;   /* identifies the governed object */
    uint32_t badge;    /* parent serial, used for revocation tracking */
    uint32_t serial;   /* unique per capability instance */
} capability_t;
```

### Rights bitmask

| Right | Bit | Meaning |
|---|---|---|
| `CAP_RIGHT_READ` | `0x001` | Read the object |
| `CAP_RIGHT_WRITE` | `0x002` | Write to the object |
| `CAP_RIGHT_EXEC` | `0x004` | Execute or invoke |
| `CAP_RIGHT_GRANT` | `0x008` | Transfer a copy to another task |
| `CAP_RIGHT_MINT` | `0x010` | Derive a new capability with a subset of rights |
| `CAP_RIGHT_REVOKE` | `0x020` | Revoke this and all derived capabilities |
| `CAP_RIGHT_AUDIT_WRITE` | `0x040` | Append to the audit log |
| `CAP_RIGHT_FS_*` | `0x100+` | Filesystem-specific rights |

### Capability operations

All capability operations live in `rust/src/capability.rs` (safe Rust) and are called from the C kernel over FFI.

| Operation | Effect |
|---|---|
| **Mint** | Creates a derived capability with a subset of the parent's rights. The new capability records the parent's serial as its badge. |
| **Transfer** | Copies a capability into another task's CNode with the same rights. |
| **Move** | Transfer, then immediately nullify the source slot. |
| **Revoke** | Nullifies the target capability, scans every task's CNode for capabilities whose badge matches the revoked serial, nullifies those too, and bumps the lineage generation counter. |

### Revocation and lineage

The system prevents use-after-revoke via a **lineage table** with 1,024 entries. Each entry is a generation counter. When a capability is minted, it records the current generation number for its lineage slot. At use time the kernel checks whether the stored generation still matches; a revocation bumps the counter, making all previously minted copies invalid immediately.

**Primordial capabilities** — root capabilities assigned at boot, identified by the `0xC0DE` serial prefix — cannot be revoked. A serial-range check in the Rust revocation path enforces this.

---

## Task model

Horus supports up to 64 concurrent tasks. Each task has:

- A **Task Control Block (TCB)** with saved register state (`eip`/`rip`, `esp`/`rsp`, `cr3`)
- A **capability node** (256 slots)
- A dedicated **kernel stack** (8 KB) used during syscall and interrupt handling
- A **user heap** tracked by `heap_start`, `heap_current`, `heap_end`
- A **UID and GID** establishing its authentication context
- A per-user **file master key** slot (infrastructure present, not yet active)

The scheduler is round-robin. Tasks can be runnable, blocked on IPC or a notification, or dead. There is no preemption in the current implementation — tasks yield cooperatively or on syscall return.

---

## IPC

IPC is endpoint-based. The kernel maintains 64 endpoints. A sending task writes a message to an endpoint; a task waiting on that endpoint receives it. Messages carry a small payload (up to the register set) and a sender badge.

**Notifications** complement endpoints: a task can post a signal to a notification object and another task can block waiting for it, without exchanging a full message.

The basic send/receive/call/reply cycle is implemented. The call/reply path (`SYS_IPC_CALL`) is partially complete.

---

## Syscall interface

Syscalls use `int 0x80`. The syscall number is in `eax`; arguments follow the C calling convention on the stack or in registers. There are approximately 51 defined syscall numbers.

Selected syscalls by category:

**Core**
- `SYS_PRINT` (1), `SYS_EXIT` (2), `SYS_YIELD` (3), `SYS_SBRK` (4), `SYS_GETPID` (5)

**IPC**
- `SYS_IPC_SEND` (10), `SYS_IPC_RECV` (11), `SYS_IPC_CALL` (12), `SYS_IPC_REPLY` (13)
- `SYS_NOTIFY` (14), `SYS_WAIT_NOTIFY` (15)

**Task management**
- `SYS_SPAWN` (20) — stub

**Authentication**
- `SYS_AUTH` (30), `SYS_SUDO` (31), `SYS_USERADD` (32), `SYS_USERDEL` (33), `SYS_PASSWD` (34)
- `SYS_GETUID` (35), `SYS_READ_AUDIT` (36)

**Capabilities**
- `SYS_CAP_REVOKE` (40)

**Filesystem**
- `SYS_FS_LOOKUP` (50), `SYS_FS_READ` (51), `SYS_FS_WRITE` (52), `SYS_FS_CREATE` (53)
- `SYS_FS_DELETE` (54), `SYS_FS_READDIR` (55), `SYS_FS_GET_ROOT` (56), `SYS_FS_MINT_FILE` (57)

**Block devices / storage (stubs)**
- `SYS_BLOCK_READ` (60), `SYS_BLOCK_WRITE` (61)
- `SYS_REGISTER_STORAGE_BACKEND` (62), `SYS_REGISTER_FS_SERVER` (70), `SYS_CONNECT_FS_SERVER` (71)

---

## User authentication and audit

### User database

Up to 32 users are stored in a kernel-managed table, serialised to the RAM filesystem as a `passwd` file. Each entry holds: username, UID, GID, home directory path, shell path, a random per-user salt, a password hash, and an authentication failure counter.

Password hashing uses a custom 4,096-round XOR-rotate mixing function over the password concatenated with the salt and a kernel pepper. This is not a standard algorithm. See [LIMITATIONS.md](LIMITATIONS.md) for the security implications.

### Audit log

The kernel maintains a 256-entry circular buffer. Each event records: event type, TSC timestamp, subject UID, object identifier, and result code. Types include authentication, sudo, user management, capability operations, file access, IPC, and filesystem events. The log is readable via `SYS_READ_AUDIT`.

---

## Rust integration

The Rust crate at `rust/` compiles to a static library (`libhorus_shell.a`) that is linked into the kernel. It is a `no_std` crate — no allocator, no OS dependencies. Data crosses the C/Rust boundary as raw pointers and integers via the FFI shims in `src/kernel/rust_memory_stubs.c`.

| Module | Role |
|---|---|
| `capability.rs` | Capability mint, transfer, move, revoke, and lineage management |
| `memory.rs` | Physical page reference counting and validation |
| `lib.rs` | Page fault validation, demand-paging decisions, command token parsing |
| `crypto.rs` | Placeholder for future cryptographic primitives |

The Rust code is safe Rust throughout. The FFI boundary is the only place `unsafe` appears, and it is confined to the C-side shim files.

---

## Reproducible builds

The build system sets `SOURCE_DATE_EPOCH=1609459200` (2021-01-01 UTC) and passes `-frandom-seed=horus` to GCC. The linker is invoked with `--build-id=none`. The Rust build uses `--locked`, `opt-level=z`, `lto=true`, and `codegen-units=1`. The result is a byte-for-byte identical `kernel.elf` across clean builds on the same toolchain version.

Reference checksums of a known-good build are stored in `.build1.sha` and `.build2.sha` at the repository root.

---

## Security properties

### What the design provides

- **No ambient authority** — a task cannot access a resource it does not hold a capability for, regardless of UID or any other factor
- **Transitive revocation** — revoking a capability immediately invalidates all capabilities derived from it, across all tasks
- **Use-after-revoke prevention** — lineage generations make a revoked capability slot invalid even if its bit pattern is retained
- **Primordial capability protection** — system-critical root capabilities cannot be revoked by any userspace path
- **Hardware user/kernel isolation** — Ring 0 / Ring 3 boundary enforced by the CPU

### What the design does not yet provide

See [LIMITATIONS.md](LIMITATIONS.md) for detail. Key gaps: cryptography is custom and not to production standard, SMP is non-functional, preemption is absent, and the filesystem has no persistent backing.
