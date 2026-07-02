# Horus Syscall Reference

**Document Status**: Early development (as of July 2026)  
**Interface**: Syscall number in `eax`/`rax`; arguments in `ebx, ecx, edx, esi, edi`. The kernel services syscalls through its `int 0x80` handler (`syscall_handler`), which dispatches via a descriptor table: for syscalls with a single fixed authorising capability it is enforced centrally before the handler runs, and any syscall number with no table entry fails closed.  
**Security Model**: All operations are capability-gated. No ambient authority.

---

## Introduction

Horus treats **capabilities** as the fundamental security primitive. Every syscall that interacts with a resource (tasks, memory, IPC endpoints, files, devices) requires an appropriate capability with the necessary rights.

This document provides a comprehensive reference for all implemented and planned syscalls. Numbers are considered stable for implemented calls but subject to change during early development.

For full details on the capability system, revocation semantics, and memory model, see [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md).

---

## Syscall Categories

Numbers below are the authoritative values from [`include/syscall.h`](../include/syscall.h); capability requirements reflect the current handler in `src/kernel/syscall.c`. "Required capability" refers to a typed capability the caller must hold in the named cspace slot.

### Core / process

| Number | Name              | Description                                                  | Required Capability                          | Notes |
|--------|-------------------|--------------------------------------------------------------|----------------------------------------------|-------|
| 0      | `SYS_YIELD`       | Yield the CPU to the scheduler                               | None                                         | — |
| 3      | `SYS_GET_LINE`    | Read a line from the console                                 | `CAP_CONSOLE` (slot 8) or endpoint READ (slot 3) | Returns length read |
| 10     | `SYS_SBRK`        | Move the user heap break                                     | None (caller's own heap, within fixed bounds)| Returns previous break, or 0 on failure |
| 11     | `SYS_WRITE`       | Write to a descriptor (fd 1 → console)                       | None for console; ramfs paths need slot-3 caps | Bytes written |
| 12     | `SYS_READ`        | Read from a descriptor (fd 0 → console, fd ≥ 3 → ramfs)      | endpoint READ (slot 3) for ramfs             | Bytes read |
| 13     | `SYS_OPEN`        | Open a ramfs file by name                                    | endpoint READ (slot 3)                       | Returns fd |
| 17     | `SYS_WAIT`        | Block until another task exits                               | None                                         | — |
| 18     | `SYS_GET_TASK_INFO` | Read task metadata                                         | Self always; other tasks need `CAP_USER` (slot 6) or `CAP_AUDIT` (slot 7) | — |
| 19     | `SYS_EXEC`        | Enter ring 3 at load-base + entry                            | endpoint WRITE\|EXEC (slot 3)                | — |

> Numbers **1** (`SYS_PRINT`), **2** (`SYS_EXIT`) and **20** (`SYS_GETPID`) are defined in `syscall.h` but **not dispatched** by the current handler — console output goes through `SYS_WRITE` (fd 1) and the current UID through `SYS_GETUID`.

### IPC

| Number | Name              | Description                                  | Required Capability        | Notes |
|--------|-------------------|----------------------------------------------|----------------------------|-------|
| 21     | `SYS_IPC_SEND`    | Send a message to an endpoint                | endpoint WRITE (slot 3)    | **Non-blocking**: returns -2 if the single-slot mailbox is full (caller polls from ring 3) |
| 22     | `SYS_IPC_RECV`    | Receive a message from an endpoint           | endpoint READ (slot 3)     | **Non-blocking**: returns -2 if no message; else returns length |
| 23     | `SYS_IPC_CALL`    | RPC-style send (thin wrapper over send)      | endpoint WRITE (slot 3)    | No atomic reply-block yet |
| 24     | `SYS_IPC_REPLY`   | Reply (thin wrapper over send)               | endpoint WRITE (slot 3)    | — |
| 25     | `SYS_NOTIFY`      | Post a notification                          | endpoint WRITE (slot 3)    | **Not implemented** — returns `SYS_ERR_NOSYS` (-38) after the cap check |
| 26     | `SYS_WAIT_NOTIFY` | Wait for a notification                      | endpoint READ (slot 3)     | **Not implemented** — returns `SYS_ERR_NOSYS` (-38) |

### Task / program loading

| Number | Name                  | Description                                  | Required Capability          | Notes |
|--------|-----------------------|----------------------------------------------|------------------------------|-------|
| 27     | `SYS_RECEIVE_PROGRAM` | Receive a program image via the loader       | endpoint WRITE\|EXEC (slot 3)| Arms the staged image |
| 28     | `SYS_SPAWN`           | Spawn the armed program as a new task        | endpoint WRITE\|EXEC (slot 3)| Implemented: ELF load + paging/heap/ASLR setup |

### Authentication & audit

| Number | Name               | Description                                  | Required Capability                 | Notes |
|--------|--------------------|----------------------------------------------|-------------------------------------|-------|
| 29     | `SYS_GETUID`       | Get the current UID                          | None                                | — |
| 30     | `SYS_AUTH`         | Authenticate as a user                       | None (verifies a password)          | Lockout after repeated failures; updates audit log |
| 31     | `SYS_SUDO`         | Re-authenticate and spawn the armed program as root | None (verifies the caller's password) | Returns new pid |
| 32     | `SYS_GET_PASS`     | Read a password from the console (masked)    | None                                | Returns length |
| 33     | `SYS_USERADD`      | Add a user account                           | Admin: `CAP_USER` (slot 6) or uid 0 | — |
| 34     | `SYS_USERDEL`      | Remove a user account                        | Admin: `CAP_USER` (slot 6) or uid 0 | — |
| 35     | `SYS_PASSWD`       | Change a password                            | Self, or admin for another user     | — |
| 36     | `SYS_ROTATE_KEYS`  | Rotate stored-block keys                     | `CAP_CONSOLE` (slot 8)              | Returns blocks rotated |
| 37     | `SYS_READ_AUDIT`   | Read the kernel audit log                    | `CAP_AUDIT` READ (slot 7)           | Circular buffer |
| 52     | `SYS_AUDIT_DIGEST` | Read the audit-log integrity digest          | `CAP_AUDIT` READ (slot 7)           | Writes 40 bytes (8-byte event count + 32-byte chain-head MAC); returns verify status (0 = intact, >0 = first tampered index + 1, -1 = uninitialised) |
| 54     | `SYS_SIGACTION`    | Register/clear this task's own fault handler | None (self only)                    | Handler vaddr validated to the user code window (safe Rust); 0 clears. On a ring-3 fault the kernel enters the handler (signal # in `ebx`, fault addr in `ecx`) instead of killing the task |
| 55     | `SYS_SIGRETURN`    | Resume the pre-signal context from a handler | None (self only)                    | Restores the exact interrupted trap frame; serviced in `interrupt_handler64`. Fails if called outside a handler |

### Capabilities

| Number | Name             | Description                                          | Required Capability               | Notes |
|--------|------------------|------------------------------------------------------|-----------------------------------|-------|
| 4      | *(mint)*         | Mint a capability into a slot with reduced rights    | `CAP_RIGHT_MINT` on the source    | No public `SYS_` macro (raw number) |
| 8      | *(transfer)*     | Copy a capability to another slot                    | `CAP_RIGHT_MINT` on the source    | No public macro |
| 9      | *(move)*         | Move a capability (transfer, then revoke the source) | `CAP_RIGHT_MINT` on the source    | No public macro |
| 51     | `SYS_CAP_REVOKE` | Revoke a capability and **all** derived copies       | `CAP_RIGHT_REVOKE` on the target  | System-wide sweep + lineage generation bump |

### Filesystem (capability-addressed)

| Number | Name               | Description                               | Required Capability            | Notes |
|--------|--------------------|-------------------------------------------|--------------------------------|-------|
| 38     | `SYS_FS_MINT_FILE` | Mint a reduced-rights file/dir capability | dir cap `FS_LOOKUP`\|`MINT`     | — |
| 39     | `SYS_FS_LOOKUP`    | Resolve a name in a directory capability  | dir cap `FS_LOOKUP`            | — |
| 40     | `SYS_FS_CREATE`    | Create a file or directory                | dir cap `FS_CREATE`            | — |
| 41     | `SYS_FS_DELETE`    | Delete a name                             | dir cap `FS_DELETE`            | — |
| 42     | `SYS_FS_READDIR`   | List a directory                          | dir cap `FS_LOOKUP`            | Bounced through a kernel buffer + `copy_to_user` |
| 43     | `SYS_FS_GET_ROOT`  | Obtain the root directory capability      | `CAP_USER` admin (slot 6) or uid 0 | — |
| 44     | `SYS_FS_READ`      | Read from a file capability               | file cap `FS_READ`            | Returns bytes |
| 45     | `SYS_FS_WRITE`     | Write to a file capability                | file cap `FS_WRITE`           | Returns bytes |

### Block storage & server registration

| Number | Name                            | Description                                  | Required Capability              | Notes |
|--------|---------------------------------|----------------------------------------------|----------------------------------|-------|
| 46     | `SYS_REGISTER_STORAGE_BACKEND`  | *(Removed)*                                  | —                                | **Fails closed** (`SYS_ERR_NOSYS`). Formerly registered a ring-3 callback the kernel invoked from ring 0 (SMEP violation / TCB escape); a userspace provider must be an IPC server |
| 47     | `SYS_BLOCK_READ`                | Read a 512-byte block                        | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Over the in-kernel virtual disk |
| 48     | `SYS_BLOCK_WRITE`               | Write a 512-byte block                       | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Over the in-kernel virtual disk |
| 49     | `SYS_REGISTER_FS_SERVER`        | Register the caller as the FS server         | `CAP_USER` admin + endpoint cap  | — |
| 50     | `SYS_CONNECT_FS_SERVER`         | Obtain an endpoint capability to the FS server | dest slot in 4..255            | Now mints a valid (fresh-serial) cap |

### Encrypted object store (used by the userspace FS server)

The kernel exposes its persistent, encrypted inode/block store to a ring-3 filesystem server. AEAD keys never leave the kernel; the server addresses storage by (inode, logical block) and builds all filesystem semantics on top. All are gated on `CAP_BLOCK_DEV` (slot 7) + uid 0, like the raw block syscalls.

| Number | Name                 | Description                                        | Required Capability            | Notes |
|--------|----------------------|----------------------------------------------------|--------------------------------|-------|
| 56     | `SYS_FS_INODE_ALLOC` | Allocate a fresh inode of a type                   | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Returns inode number |
| 57     | `SYS_FS_INODE_FREE`  | Free an inode and its data blocks                  | `CAP_BLOCK_DEV` (slot 7) + uid 0 | — |
| 58     | `SYS_FBLOCK_READ`    | Read+decrypt logical block of an inode             | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Returns `BLOCK_SIZE` (512) |
| 59     | `SYS_FBLOCK_WRITE`   | Encrypt+write logical block of an inode            | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Fresh per-write nonce |
| 60     | `SYS_FS_STAT`        | Read inode metadata (`struct fs_stat`)             | `CAP_BLOCK_DEV` (slot 7) + uid 0 | — |
| 61     | `SYS_FS_SET_SIZE`    | Set an inode's logical size                        | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Server owns file size |

> Number **53** (`SYS_PREEMPT_TRACE`) is a **test-only** hook, present in the dispatch table and wired to a trace handler *only* in `PREEMPT_SELFTEST=1` builds; in the default/ship kernel its table slot is absent and the number fails closed.

> The handler also services a few **raw-numbered** operations that have no public macro: **5** (clear screen, slot-3 WRITE), **6** (kernel version string), **14** (legacy in-place task create, slot-3 WRITE\|EXEC), **15** (ramfs create, slot-3 WRITE), **16** (ramfs list, slot-3 READ), and **7** (`DEBUG_SHELL` builds only: run an in-kernel shell command).

---

## Common Conventions

- **Error Codes**: Errors are negative; success is 0 (or a non-negative result). They come from a shared, descriptive, errno-aligned set in [`include/errno.h`](../include/errno.h) — `SYS_ERR_PERM` (−1, missing capability), `SYS_ERR_NOENT` (−2), `SYS_ERR_AUTH` (−13, bad password/lockout), `SYS_ERR_FAULT` (−14, bad user pointer), `SYS_ERR_INVAL` (−22), `SYS_ERR_NOSYS` (−38, unknown/unimplemented syscall), `SYS_ERR_REVOKED`/`SYS_ERR_NORIGHT` (capability-specific), and more. `sys_strerror(code)` renders a human-readable reason. The header is shared verbatim by the kernel and userspace, so the same condition yields the same code everywhere.
- **Capability Rights**: See full bitmask in `ARCHITECTURE.md`. Common rights include `READ`, `WRITE`, `EXEC`, `GRANT`, `MINT`, `REVOKE`.
- **Revocation Semantics**: `SYS_CAP_REVOKE` performs a complete system-wide sweep. Lineage tracking prevents use-after-revoke even if a stale capability bit pattern remains.
- **Message Format (IPC)**: Small fixed-size payload + sender badge.

---

## Future Work

- Expanded task management (`SYS_SPAWN` full implementation)
- More complete filesystem and storage APIs
- Preemptive scheduling support
- Additional device classes

For the most up-to-date status, consult [`TESTS.md`](../TESTS.md), [`CHANGES.md`](../CHANGES.md), and [`ROADMAP.md`](../ROADMAP.md).

---

**Contribution Note**: This reference should be kept in sync with `include/syscall.h` and the syscall handler table in the kernel.

*Last updated: 2026-07-02 — added the encrypted object-store API (56-61) for the userspace filesystem server and made IPC send/recv non-blocking; numbers and capability requirements synced against `include/syscall.h` and the table-driven `syscall_handler` dispatch.*