# Horus Syscall Reference

**Document Status**: Early development (as of July 2026)
**Interface**: Syscall number in `eax`/`rax`; arguments in `ebx, ecx, edx, esi, edi`. The kernel services syscalls through its `int 0x80` handler (`interrupt_handler64` → `syscall_handler`), which dispatches via a descriptor table: for syscalls with a single fixed authorising capability it is enforced centrally before the handler runs, and any syscall number with no table entry fails closed.
**Security Model**: All operations are capability-gated. No ambient authority.

---

## Introduction

Horus treats **capabilities** as the fundamental security primitive. Every syscall that interacts with a resource (tasks, memory, IPC endpoints, files, devices) requires an appropriate capability with the necessary rights.

Numbers below are the authoritative values from [`include/syscall.h`](../include/syscall.h); capability requirements reflect the current handler in `src/kernel/syscall.c`. "Required capability" refers to a typed capability the caller must hold in the named cspace slot. Syscalls with dynamic or self-authorising policy carry no fixed table slot and authorise inside their handler.

For the capability system, revocation semantics, and memory model, see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Syscall Categories

### Core / process

| Number | Name              | Description                                                  | Required Capability                          | Notes |
|--------|-------------------|--------------------------------------------------------------|----------------------------------------------|-------|
| 0      | `SYS_YIELD`       | Yield the CPU to the scheduler                               | None                                         | — |
| 2      | `SYS_EXIT`        | Terminate the calling task                                   | None (self)                                  | Tears the task down, wakes any `SYS_WAIT` waiter, and switches to the next runnable task; does not return |
| 3      | `SYS_GET_LINE`    | Read a line from the console                                 | `CAP_CONSOLE` (slot 8) or endpoint READ (slot 3) | Returns length read |
| 10     | `SYS_SBRK`        | Move the user heap break by a delta                         | None (caller's own heap, within fixed bounds)| Returns previous break, or 0 on failure |
| 11     | `SYS_WRITE`       | Write to a descriptor (fd 1 → console)                       | None for console; ramfs paths need slot-3 caps | Bytes written |
| 12     | `SYS_READ`        | Read from a descriptor (fd 0 → console, fd ≥ 3 → ramfs)      | endpoint READ (slot 3) for ramfs             | Bytes read |
| 13     | `SYS_OPEN`        | Open a ramfs file by name                                    | endpoint READ (slot 3)                       | Returns fd |
| 17     | `SYS_WAIT`        | Block until another task exits                              | None                                          | Suspends the caller on the preemptive block/switch path (`TASK_BLOCKED_WAIT`); the target's teardown wakes it. Returns 0 (incl. if already dead), -1 on a bad tid, or `SYS_ERR_INTR` if a signal interrupts the wait |
| 18     | `SYS_GET_TASK_INFO` | Read task metadata (name, state, uid, …)                  | Self always; other tasks need `CAP_USER` (slot 6) or `CAP_AUDIT` (slot 7) | Never exposes `cr3` |
| 19     | `SYS_EXEC`        | Enter ring 3 at load-base + entry                            | endpoint WRITE\|EXEC (slot 3)                | Rejects `load_base + entry_offset ≥ USER_MAX_VADDR` (overflow guard) |
| 62     | `SYS_BRK`         | Set the absolute heap break (`addr=0` queries current)      | None (own heap, demand-paged)                | Bounded by `[heap_start, heap_start + USER_HEAP_MAX_SIZE)` |

> Numbers **1** (`SYS_PRINT`) and **20** (`SYS_GETPID`) are defined in `syscall.h` but **not dispatched** — console output goes through `SYS_WRITE` (fd 1) and the current UID through `SYS_GETUID`.

### Process control (ring-3, Phase 1)

| Number | Name              | Description                                                  | Required Capability                          | Notes |
|--------|-------------------|--------------------------------------------------------------|----------------------------------------------|-------|
| 28     | `SYS_SPAWN`       | Spawn a named embedded binary as a new task                 | endpoint WRITE\|EXEC (slot 3)                | Runs the ELF load in the kernel address space; hands the caller a `CAP_TCB` to the child. `edx` = one-word arg; `esi`/`edi` = argv/argc (marshalled onto the child's stack). `sys_spawn_named[_arg\|_argv](…)` |
| 68     | `SYS_SPAWN_ARG`   | Read the one-word argument this task was spawned with       | None (self only)                             | Fast path alongside the full argv below |
| 69     | `SYS_GET_ARGV`    | Read this task's argument vector                            | None (self only)                             | Returns `argc`; writes the argv[] base (a vaddr into the task's own stack, NULL-terminated) to the user `char***`. `sys_get_argv(&argv)`. Up to 16 args / 512 bytes |
| 63     | `SYS_KILL`        | Terminate task `tid`                                        | `CAP_TCB` to the target (or `CAP_USER` admin)| Enforced in the handler since the target is dynamic |
| 64     | `SYS_EXEC_NAMED`  | Replace the caller's own image with a named embedded binary | endpoint WRITE\|EXEC (slot 3)                | Same task id and cspace (capabilities survive, POSIX-style); `esi`/`edi` = argv/argc marshalled onto the fresh stack. Does not return on success. `sys_exec_named[_argv](…)` |
| 70     | `SYS_SPAWN_IMAGE` | Spawn a child from a program image supplied in the caller's own memory (execve-from-fd) | endpoint WRITE\|EXEC (slot 3) | `ebx`/`ecx` = image/len; the caller reads the image from a file via the `fs_server`, the kernel validates it with the same loader a named binary uses (Horus `.bin` header or bare ELF; `arm_image_from_user` → `try_elf_load`). `edx` = one-word arg; `esi`/`edi` = argv/argc. Returns the child pid. `sys_spawn_image(…)` |
| 71     | `SYS_EXEC_IMAGE`  | Replace the caller's own image with a program image supplied in its own memory (execve-from-fd, in place) | endpoint WRITE\|EXEC (slot 3) | Same task id and cspace (capabilities survive); shares the image-replace tail with `SYS_EXEC_NAMED`. A bad image fails cleanly with the caller intact; does not return on success. `sys_exec_image(…)` |
| 65     | `SYS_CAP_GRANT`   | Copy the caller's cap from `src_slot` into a supervised child's `dest_slot` | `CAP_TCB` to the target (or `CAP_USER` admin) | Least-privilege delegation from a parent that spawned the child |
| 66     | `SYS_SIGNAL`      | Send an async signal to another task                        | `CAP_TCB` to the target (or `CAP_USER` admin)| Same authority as `SYS_KILL`. Queues `signum` (1..31); redirected into the target's `SYS_SIGACTION` handler on its next return to ring 3 (signal # in `ebx`). Unhandled — or the uncatchable `SIG_KILL` (9) — takes the default terminate action |

### IPC

| Number | Name              | Description                                  | Required Capability        | Notes |
|--------|-------------------|----------------------------------------------|----------------------------|-------|
| 21     | `SYS_IPC_SEND`    | Send a message to an endpoint                | endpoint WRITE (slot 3)    | **Non-blocking**: returns -2 if the single-slot mailbox is full (caller polls from ring 3) |
| 22     | `SYS_IPC_RECV`    | Receive a message from an endpoint           | endpoint READ (slot 3)     | **Non-blocking**: returns -2 if no message; else returns length |
| 23     | `SYS_IPC_CALL`    | RPC-style send that may block for a reply    | endpoint WRITE (slot 3)    | Can block the caller (`TASK_BLOCKED_IPC`), resumed via the block/switch path |
| 24     | `SYS_IPC_REPLY`   | Reply (thin wrapper over send)               | endpoint WRITE (slot 3)    | — |
| 73     | `SYS_IPC_SENDER`  | Kernel-attested identity of an endpoint's last sender | endpoint READ (slot 3) | Returns the sender's uid and (via `*ecx`) gid, taken from `tasks[last_sender]` — set at login, not from the message — so a server (e.g. the `fs_server`) learns who a client is without trusting the client. Returns `(uint32_t)-1` if there is no valid sender |
| 75     | `SYS_IPC_REPLY_TO`| Reply to the sender of the last request on an endpoint | endpoint WRITE (slot 3) | Delivers the reply directly into the request sender's blocked `SYS_IPC_CALL` buffer, routed by kernel-recorded identity (`last_sender`), not a shared reply endpoint — so one server serves concurrent clients without their replies colliding. Returns 0 on delivery (or if the client has gone); a negative return means "retry" (the sender raced and hasn't finished blocking) |
| 25     | `SYS_NOTIFY`      | Post a notification badge                    | endpoint WRITE (slot 3)    | ORs the badge into the slot; wakes a task blocked on it (accumulates if none) |
| 26     | `SYS_WAIT_NOTIFY` | Wait for a notification badge                | endpoint READ (slot 3)     | Returns a pending badge, else blocks; badge delivered in `ebx`. Proven by `make smoke-notify` |

### Task / program loading

| Number | Name                  | Description                                  | Required Capability          | Notes |
|--------|-----------------------|----------------------------------------------|------------------------------|-------|
| 27     | `SYS_RECEIVE_PROGRAM` | Receive a program image via the loader       | endpoint WRITE\|EXEC (slot 3)| Arms the staged image for `SYS_SPAWN`/`SYS_EXEC` |

### Authentication & audit

| Number | Name               | Description                                  | Required Capability                 | Notes |
|--------|--------------------|----------------------------------------------|-------------------------------------|-------|
| 29     | `SYS_GETUID`       | Get the current UID                          | None                                | — |
| 30     | `SYS_AUTH`         | Authenticate as a user                       | None (verifies a password)          | Argon2id hash + constant-time compare; lockout + anti-spray throttle; scrubs the cleartext buffer; updates the audit log |
| 31     | `SYS_SUDO`         | Re-authenticate and spawn the armed program as root | None (verifies the caller's password) | Returns new pid; least-privilege sudo frame |
| 32     | `SYS_GET_PASS`     | Read a password from the console (masked)    | None                                | Returns length |
| 33     | `SYS_USERADD`      | Add a user account                           | Admin: `CAP_USER` (slot 6) or uid 0 | No initial password → CSPRNG-random hash (account locked until `SYS_PASSWD`) |
| 34     | `SYS_USERDEL`      | Remove a user account                        | Admin: `CAP_USER` (slot 6) or uid 0 | — |
| 35     | `SYS_PASSWD`       | Change a password                            | Self, or admin for another user     | Persists across reboots; scrubs the cleartext buffer |
| 36     | `SYS_ROTATE_KEYS`  | Rotate stored-block keys                     | `CAP_CONSOLE` (slot 8)              | Returns blocks rotated |
| 37     | `SYS_READ_AUDIT`   | Read the kernel audit log                    | `CAP_AUDIT` READ (slot 7)           | Circular buffer |
| 52     | `SYS_AUDIT_DIGEST` | Read the audit-log integrity digest          | `CAP_AUDIT` READ (slot 7)           | Writes 40 bytes (8-byte event count + 32-byte chain-head MAC); returns verify status (0 = intact, >0 = first tampered index + 1, -1 = uninitialised) |

### Signals

| Number | Name               | Description                                  | Required Capability                 | Notes |
|--------|--------------------|----------------------------------------------|-------------------------------------|-------|
| 54     | `SYS_SIGACTION`    | Register/clear this task's own fault/signal handler | None (self only)             | Handler vaddr validated to the user code window (safe Rust); 0 clears. On a ring-3 fault the kernel enters the handler (signal # in `ebx`, fault addr in `ecx`) instead of killing the task |
| 55     | `SYS_SIGRETURN`    | Resume the pre-signal context from a handler | None (self only)                    | Restores the exact interrupted trap frame; serviced in `interrupt_handler64`. Fails if called outside a handler |
| 66     | `SYS_SIGNAL`       | *(see Process control)* async task-to-task signal | `CAP_TCB` to the target          | Queued in a pending bitmask; the lowest unmasked one is delivered into the target's handler. Interrupts a `SYS_WAIT`-blocked target. Default-terminates if unhandled or `SIG_KILL` |
| 67     | `SYS_SIGMASK`      | Block/unblock this task's own signals        | None (self only)                    | `how` = `SIG_SETMASK`/`SIG_BLOCK`/`SIG_UNBLOCK`, `mask` = bitmask; returns the old mask. A blocked signal stays pending until unblocked. `SIG_KILL` can never be blocked |
| 72     | `SYS_SIGALTSTACK`  | Register this task's own alternate signal stack | None (self only)                 | `ebx`/`ecx` = `ss_sp`/`ss_size` (0 disables). A signal delivered while not already on it enters the handler on `[ss_sp, ss_sp+ss_size)` (SS_ONSTACK), so a corrupt/overflowed primary stack cannot stop the handler running; cleared on `SYS_SIGRETURN`. Range must lie in user space and be ≥ `SIGSTKSZ_MIN`; refused while a handler is running on it |

Signal numbers: `SIG_ILL` (4, `#UD`), `SIG_KILL` (9, uncatchable/unmaskable), `SIG_USR1` (10), `SIG_SEGV` (11, page fault / `#GP`), `SIG_USR2` (12), `SIG_TERM` (15, default terminate). The pending set and mask are full 1..31 (`SIG_MAX`) bitmasks.

### Capabilities

| Number | Name             | Description                                          | Required Capability               | Notes |
|--------|------------------|------------------------------------------------------|-----------------------------------|-------|
| 4      | *(mint)*         | Mint a capability into a slot with reduced rights    | `CAP_RIGHT_MINT` on the source    | No public `SYS_` macro (raw number) |
| 8      | *(transfer)*     | Copy a capability to another slot                    | `CAP_RIGHT_MINT` on the source    | No public macro |
| 9      | *(move)*         | Move a capability (transfer, then revoke the source) | `CAP_RIGHT_MINT` on the source    | No public macro |
| 51     | `SYS_CAP_REVOKE` | Revoke a capability and **all** derived copies       | `CAP_RIGHT_REVOKE` on the target  | System-wide sweep + lineage generation bump |

### Filesystem — legacy in-memory capfs (removed)

Numbers **38–45** were the legacy in-memory capability-addressed filesystem (`SYS_FS_MINT_FILE`, `_LOOKUP`, `_CREATE`, `_DELETE`, `_READDIR`, `_GET_ROOT`, `_READ`, `_WRITE`). That parallel filesystem — with its own permission model, its own at-rest AEAD, and no persistence — was **removed**: the `capfs_*` engine and `fs_objects[]` are gone, the dispatch-table entries are deleted (so the numbers **fail closed** with `SYS_ERR_NOSYS`), and the numbers are reserved so a later syscall cannot silently inherit an old capfs caller. The encrypted `fs_server` (below) is the system's single filesystem. The `CAP_DIR` / `CAP_FILE` types and the `CAP_RIGHT_FS_*` rights are likewise reserved but no longer govern any live object.

### Encrypted object store (userspace filesystem-server backend)

The kernel exposes only an encrypted inode/block API; the ring-3 `fs_server` builds directories, paths, and file sizes on top. AEAD keys never leave the kernel TCB.

| Number | Name                | Description                                   | Required Capability            | Notes |
|--------|---------------------|-----------------------------------------------|--------------------------------|-------|
| 56     | `SYS_FS_INODE_ALLOC`| Allocate an inode of a given type             | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Returns ino |
| 57     | `SYS_FS_INODE_FREE` | Free an inode                                 | `CAP_BLOCK_DEV` + uid 0        | — |
| 58     | `SYS_FBLOCK_READ`   | Read (decrypt + verify) an (inode, block)     | `CAP_BLOCK_DEV` + uid 0        | Returns `BLOCK_SIZE`; fail-closed on a bad tag |
| 59     | `SYS_FBLOCK_WRITE`  | Write (encrypt, fresh nonce) an (inode, block)| `CAP_BLOCK_DEV` + uid 0        | Per-(ino,block) AEAD |
| 60     | `SYS_FS_STAT`       | Read inode metadata                           | `CAP_BLOCK_DEV` + uid 0        | Writes a `struct fs_stat` (size, type, mode, uid, gid, links) |
| 61     | `SYS_FS_SET_SIZE`   | Set an inode's logical size                   | `CAP_BLOCK_DEV` + uid 0        | Server owns logical file size |
| 74     | `SYS_FS_SET_META`   | Persist an inode's owner (uid/gid) + mode     | `CAP_BLOCK_DEV` + uid 0        | Only the low 12 permission bits are settable (file-type bits preserved); the `fs_server` uses it to stamp the creator as owner and to apply chmod/chown after authorising the caller |

### Block storage & server registration

| Number | Name                          | Description                              | Required Capability      | Notes |
|--------|-------------------------------|------------------------------------------|--------------------------|-------|
| 46     | `SYS_REGISTER_STORAGE_BACKEND`| *(removed)*                              | —                        | **Fails closed** (`SYS_ERR_NOSYS`); ABI slot reserved. Used to register ring-3 function pointers the kernel called from ring 0 — a TCB escape. See [SECURITY.md](../SECURITY.md) |
| 47     | `SYS_BLOCK_READ`              | Read a raw storage block                  | `CAP_BLOCK_DEV`          | — |
| 48     | `SYS_BLOCK_WRITE`            | Write a raw storage block                 | `CAP_BLOCK_DEV`          | — |
| 49     | `SYS_REGISTER_FS_SERVER`     | Register the ring-3 filesystem server     | admin                    | — |
| 50     | `SYS_CONNECT_FS_SERVER`      | Obtain endpoints to the filesystem server | None                     | Mints fresh-serial endpoint caps |

### Test-only

| Number | Name               | Description                                  | Notes |
|--------|--------------------|----------------------------------------------|-------|
| 53     | `SYS_PREEMPT_TRACE`| Append to the preemption trace ring          | Present only in `PREEMPT_SELFTEST` builds; `SYS_ERR_NOSYS` otherwise |

---

## Dispatch and error model

Dispatch is table-driven: `syscall_handler` indexes `syscall_table[]` of descriptors `{ handler, slot, rights, type }`, validates the number, and — for syscalls whose authority is a single fixed capability — enforces that capability in one central place before calling the handler. A number with no entry fails closed. A `_Static_assert` pins the table size to the highest syscall number + 1, so a syscall cannot be added without a table slot.

Error codes come from the shared, errno-aligned `SYS_ERR_*` vocabulary in [`include/errno.h`](../include/errno.h) (included by both kernel and userspace): `SYS_ERR_PERM` (missing capability), `SYS_ERR_NOSYS` (unknown/removed syscall), `SYS_ERR_AUTH`, `SYS_ERR_FAULT`, `SYS_ERR_INVAL`, `SYS_ERR_NOENT`, `SYS_ERR_REVOKED`, `SYS_ERR_NORIGHT`, … `sys_strerror()` renders them; the shell prints it.
