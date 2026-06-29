# Horus Syscall Reference

**Document Status**: Early development (as of June 2026)  
**Interface**: Software interrupt `int 0x80`. Syscall number passed in `eax`; arguments follow the C calling convention (primarily on stack).  
**Security Model**: All operations are capability-gated. No ambient authority.

---

## Introduction

Horus treats **capabilities** as the fundamental security primitive. Every syscall that interacts with a resource (tasks, memory, IPC endpoints, files, devices) requires an appropriate capability with the necessary rights.

This document provides a comprehensive reference for all implemented and planned syscalls. Numbers are considered stable for implemented calls but subject to change during early development.

For full details on the capability system, revocation semantics, and memory model, see [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md).

---

## Syscall Categories

### Core Syscalls

| Number | Name              | Description                          | Required Capabilities          | Return Value / Notes |
|--------|-------------------|--------------------------------------|--------------------------------|----------------------|
| 1      | `SYS_PRINT`       | Write string to kernel console (VGA + serial) | None (debug)                  | Length written |
| 2      | `SYS_EXIT`        | Terminate the current task           | None                           | Does not return |
| 3      | `SYS_YIELD`       | Voluntarily yield the CPU            | None                           | - |
| 4      | `SYS_SBRK`        | Change user heap break point         | Implicit via task memory cap   | New break address |
| 5      | `SYS_GETPID`      | Get current task ID                  | None                           | PID |

### IPC Syscalls

| Number | Name              | Description                                      | Required Capabilities              | Notes |
|--------|-------------------|--------------------------------------------------|------------------------------------|-------|
| 10     | `SYS_IPC_SEND`    | Send message to an endpoint                      | `CAP_ENDPOINT` (WRITE)             | Non-blocking option available |
| 11     | `SYS_IPC_RECV`    | Receive message from an endpoint                 | `CAP_ENDPOINT` (READ)              | Blocking |
| 12     | `SYS_IPC_CALL`    | RPC-style send + block for reply                 | `CAP_ENDPOINT` (CALL)              | Partially implemented |
| 13     | `SYS_IPC_REPLY`   | Send reply to pending call                       | `CAP_ENDPOINT` (REPLY)             | - |
| 14     | `SYS_NOTIFY`      | Post a notification to a notifier object         | `CAP_NOTIFY` (WRITE)               | Lightweight signal |
| 15     | `SYS_WAIT_NOTIFY` | Block waiting for notification                   | `CAP_NOTIFY` (READ)                | - |

### Task Management

| Number | Name           | Description               | Required Capabilities     | Notes |
|--------|----------------|---------------------------|---------------------------|-------|
| 20     | `SYS_SPAWN`    | Create and start new task | `CAP_TCB` (MINT/GRANT)    | Currently stubbed |

### Authentication and Audit

| Number | Name               | Description                        | Required Capabilities          | Notes |
|--------|--------------------|------------------------------------|--------------------------------|-------|
| 30     | `SYS_AUTH`         | Authenticate as a user             | None (kernel password check)   | Updates audit log |
| 31     | `SYS_SUDO`         | Temporary privilege escalation     | Special primordial capability  | Restricted use |
| 32     | `SYS_USERADD`      | Add new user account               | Administrative capability      | - |
| 33     | `SYS_USERDEL`      | Remove user account                | Administrative capability      | - |
| 34     | `SYS_PASSWD`       | Change user password               | User self-capability           | - |
| 35     | `SYS_GETUID`       | Retrieve current UID/GID           | None                           | - |
| 36     | `SYS_READ_AUDIT`   | Read from kernel audit log         | `CAP_AUDIT_READ`               | Circular buffer (256 entries) |

### Capability Management

| Number | Name                | Description                                      | Required Capabilities     | Notes |
|--------|---------------------|--------------------------------------------------|---------------------------|-------|
| 40     | `SYS_CAP_REVOKE`    | Revoke a capability and **all** derived copies   | `CAP_REVOKE`              | Global sweep + lineage generation counter |

### Filesystem Syscalls

| Number | Name                  | Description                          | Required Capabilities              | Notes |
|--------|-----------------------|--------------------------------------|------------------------------------|-------|
| 50     | `SYS_FS_LOOKUP`       | Resolve path to file capability      | `CAP_FS_LOOKUP` on parent          | - |
| 51     | `SYS_FS_READ`         | Read data from file                  | `CAP_FILE` (READ)                  | - |
| 52     | `SYS_FS_WRITE`        | Write data to file                   | `CAP_FILE` (WRITE)                 | - |
| 53     | `SYS_FS_CREATE`       | Create file or directory             | `CAP_FILE` (GRANT/MINT) on parent | - |
| 54     | `SYS_FS_DELETE`       | Remove file or directory             | `CAP_FILE` (WRITE) on parent       | - |
| 55     | `SYS_FS_READDIR`      | Read directory contents              | `CAP_FILE` (READ)                  | - |
| 56     | `SYS_FS_GET_ROOT`     | Obtain root filesystem capability    | Appropriate root cap               | - |
| 57     | `SYS_FS_MINT_FILE`    | Create reduced-rights file capability| `CAP_FILE` (MINT)                  | - |

### Block Storage & Server Registration (Stubs)

| Number | Name                            | Description                              | Required Capabilities       | Notes |
|--------|---------------------------------|------------------------------------------|-----------------------------|-------|
| 60     | `SYS_BLOCK_READ`                | Read sectors from block device           | `CAP_BLOCK` (READ)          | Stub |
| 61     | `SYS_BLOCK_WRITE`               | Write sectors to block device            | `CAP_BLOCK` (WRITE)         | Stub |
| 62     | `SYS_REGISTER_STORAGE_BACKEND`  | (Removed) formerly registered a block storage provider | —                | **Removed** — fails closed (`SYS_ERR_NOSYS`). Used to register a ring-3 callback the kernel invoked from ring 0 (SMEP violation / TCB escape); a userspace provider must be an IPC server. |
| 70     | `SYS_REGISTER_FS_SERVER`        | Register userspace filesystem server     | Privileged                  | Stub |
| 71     | `SYS_CONNECT_FS_SERVER`         | Connect to registered FS server          | Appropriate caps            | Stub |

---

## Common Conventions

- **Error Codes**: Negative values follow a standard convention (e.g. `-EINVAL`, `-ENOMEM`, `-EPERM`).
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

*Generated with Horus Doc Generator skill*  
*Last updated: June 27, 2026*