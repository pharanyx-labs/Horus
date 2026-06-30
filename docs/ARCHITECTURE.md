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

**Copy-on-write** is implemented at the page level. Shared pages are marked `PAGE_COW`. On the first write fault, `rust_handle_demand_page_fault()` allocates a fresh physical page, copies the content, and remaps the faulting address (preserving the page's NX bit). Physical pages carry reference counts maintained in Rust (`rust_page_ref_inc`, `rust_page_ref_dec`). The COW-copy-vs-demand-zero decision logic is unit-tested.

**W^X**: `EFER.NXE` is enabled at boot and the kernel uses the PTE NX bit (63) to keep writable pages non-executable. User stacks (low and high ASLR) are mapped no-execute. The ELF loader honours each `PT_LOAD` segment's `p_flags`, mapping code read+execute and data/rodata read[+write]+NX; the policy decision (`rust_user_page_is_noexec`) lives in Rust and is unit-tested. The flat-binary fallback path (used by the shipped userspace binaries, which are not ELF) keeps its image executable.

**ASLR**: per-spawn stack top and heap gap are randomised from the CSPRNG. Load-base randomisation (PIE userspace) is still an open work item.

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
| **Revoke** | System-wide. A single Rust entry point (`rust_cap_revoke_global`) nullifies the target capability and then sweeps **every live task's CNode plus the kernel root cnode**, nullifying any capability whose serial, badge, or object matches the revoked lineage, and bumps the lineage generation counter exactly once. |

### Revocation and lineage

Revocation is **complete, not caller-local**: the C wrapper `cap_revoke` (under `cap_lock`) builds the list of all live cspaces and passes it to `rust_cap_revoke_global`, which performs the entire sweep inside one Rust call. A derived capability copied into another task's CNode is therefore revoked together with its parent — there is no window in which another task retains access after revocation.

The system additionally prevents use-after-revoke via a **lineage table** (`LINEAGE_SLOTS` = 4,096 entries, mirrored by `MAX_LINEAGES` in the C header). Each entry is a generation counter, and the Rust table is the single source of truth. When a capability is minted it records the current generation for its lineage slot; at use time `rust_cap_lookup` checks whether the stored generation still matches. A revocation bumps the counter, so even a stale bit pattern that somehow escaped the structural sweep fails the generation check immediately. The structural sweep and the generation bump are defence-in-depth for the same invariant.

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

Dispatch is **table-driven**: `syscall_handler` indexes a `syscall_table[]` of descriptors `{ handler, slot, rights, type }`, validates the number, and — for syscalls whose authority is a single fixed capability — enforces that capability in one central place before calling the handler. A number with no entry (including the reserved/gap numbers below) fails closed. A `_Static_assert` pins the table size to the highest syscall number, so a syscall cannot be added without a table slot. Syscalls with dynamic or self-authorising policy (the capability ops, the FS ops, auth/sudo, user management) carry no fixed slot and authorise inside their handler or the helper they call.

Selected syscalls by category:

Numbers are the authoritative values from `include/syscall.h`. (Numbers 1/`SYS_PRINT`, 2/`SYS_EXIT`, 20/`SYS_GETPID` are defined but not dispatched by the current handler.)

**Core / process**
- `SYS_YIELD` (0), `SYS_GET_LINE` (3), `SYS_SBRK` (10), `SYS_WRITE` (11), `SYS_READ` (12), `SYS_OPEN` (13)
- `SYS_WAIT` (17), `SYS_GET_TASK_INFO` (18), `SYS_EXEC` (19)

**IPC**
- `SYS_IPC_SEND` (21), `SYS_IPC_RECV` (22), `SYS_IPC_CALL` (23), `SYS_IPC_REPLY` (24)
- `SYS_NOTIFY` (25), `SYS_WAIT_NOTIFY` (26) — both return `SYS_ERR_NOSYS` (not implemented)

**Task / program loading**
- `SYS_RECEIVE_PROGRAM` (27), `SYS_SPAWN` (28)

**Authentication**
- `SYS_GETUID` (29), `SYS_AUTH` (30), `SYS_SUDO` (31), `SYS_GET_PASS` (32)
- `SYS_USERADD` (33), `SYS_USERDEL` (34), `SYS_PASSWD` (35), `SYS_ROTATE_KEYS` (36), `SYS_READ_AUDIT` (37)

**Capabilities**
- mint (4), transfer (8), move (9) — raw-numbered, no public macro; `SYS_CAP_REVOKE` (51)

**Filesystem**
- `SYS_FS_MINT_FILE` (38), `SYS_FS_LOOKUP` (39), `SYS_FS_CREATE` (40), `SYS_FS_DELETE` (41)
- `SYS_FS_READDIR` (42), `SYS_FS_GET_ROOT` (43), `SYS_FS_READ` (44), `SYS_FS_WRITE` (45)

**Block devices / storage**
- `SYS_REGISTER_STORAGE_BACKEND` (46 — removed, fails closed; see SECURITY.md)
- `SYS_BLOCK_READ` (47), `SYS_BLOCK_WRITE` (48), `SYS_REGISTER_FS_SERVER` (49), `SYS_CONNECT_FS_SERVER` (50)

---

## User authentication and audit

### User database

Up to 32 users are stored in a kernel-managed table, serialised to the RAM filesystem as a `passwd` file. Each entry holds: username, UID, GID, home directory path, shell path, a random per-user salt, a password hash, and an authentication failure counter. The serialised table is authenticated with an HMAC-SHA256 tag keyed by the per-boot pepper.

Password hashing is **PBKDF2-HMAC-SHA256** (RFC 8018, 120,000 iterations), implemented in safe Rust (`rust/src/sha256.rs`), over the password with the per-user random salt and a per-boot secret pepper folded in; the raw 32-byte derived key is stored. Verification runs in constant time and is equalised so a missing username cannot be distinguished by timing. (This replaced an earlier custom XOR-rotate scheme.) Lockout arithmetic and a global anti-spray throttle live in `rust/src/auth.rs`.

### Audit log

The kernel maintains a 256-entry circular buffer. Each event records: event type, TSC timestamp, subject UID, object identifier, and result code. Types include authentication, sudo, user management, capability operations, file access, IPC, and filesystem events. The log is readable via `SYS_READ_AUDIT`.

---

## Rust integration

The Rust crate at `rust/` compiles to a static library (`libhorus_shell.a`) that is linked into the kernel. It is a `no_std` crate — no allocator, no OS dependencies. Data crosses the C/Rust boundary as raw pointers and integers via the FFI shims in `src/kernel/rust_memory_stubs.c`.

| Module | Role |
|---|---|
| `capability.rs` | Capability mint, transfer, move, revoke, and lineage management |
| `memory.rs` | Physical page reference counting and validation |
| `lib.rs` | Page-fault validation, demand-paging decisions, W^X page policy (`rust_user_page_is_noexec`), command token parsing |
| `sha256.rs` | SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA256 |
| `rng.rs` | ChaCha20 fast-key-erasure CSPRNG; RDRAND + timing-jitter seeding |
| `aead.rs` | ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (encryption-at-rest) |
| `auth.rs` | Auth/sudo lockout + anti-spray throttle; least-privilege sudo frame rights |
| `ps.rs` | Task state-name labels for the `ps` renderers |
| `crypto.rs` | Intentionally empty — the primitives live in the modules above |

The Rust code is safe Rust throughout, with one deliberate exception: two FFI entry points that dereference C-supplied raw pointers (`rust_cap_has_rights`, `rust_handle_command`) are marked `unsafe extern "C"` with documented `# Safety` contracts. All other `unsafe` is confined to the C-side shim files.

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
- **Hardware user/kernel isolation** — Ring 0 / Ring 3 boundary enforced by the CPU; SMEP/SMAP enabled when advertised
- **W^X for user memory** — stacks are non-executable and ELF segments honour their `p_flags`, so a writable page is never executable
- **Centralised syscall authorisation** — one table-driven choke point enforces the required capability; an unlisted syscall number fails closed

### What the design does not yet provide

See [LIMITATIONS.md](LIMITATIONS.md) for detail. Key gaps: cryptography is custom and not to production standard, SMP is non-functional, preemption is absent, and the filesystem has no persistent backing.
