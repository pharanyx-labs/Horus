# Horus Syscall Reference

**Interface:** syscall number in `rax`; arguments in `rbx, rcx, rdx, rsi, rdi` (a sixth in `r8`). Arguments and the return value are 64-bit — they carry user pointers, and `SYS_BRK`/`SYS_SBRK` return an address. The kernel services syscalls through its `int 0x80` handler (`interrupt_handler64` → `syscall_handler`), which dispatches via a descriptor table: for a syscall whose authority is a single fixed capability it is enforced centrally before the handler runs; any number with no table entry fails closed.

**Security model:** every operation is capability-gated. No ambient authority.

Numbers below are the authoritative values from [`include/syscall.h`](../include/syscall.h); capability requirements reflect the current handlers in `src/kernel/`. "Required capability" names a typed capability the caller must hold in the given cspace **slot** — in the fixed endowment a cap conventionally lives at the slot equal to its type value (e.g. `CAP_ENDPOINT`→3, `CAP_USER`→6, `CAP_CONSOLE`→8, `CAP_IO_DEVICE`→12), though a single-purpose server may hold its one cap at a lower slot (the object store expects `CAP_BLOCK_DEV` at slot 7). Syscalls with dynamic or self-authorising policy carry no fixed table slot and authorise inside their handler.

The full range is **0 (`SYS_YIELD`) – 88 (`SYS_DMESG`)**. For the capability system, revocation semantics, and memory model, see [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Core / process

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 0 | `SYS_YIELD` | Yield the CPU to the scheduler | None | Full-context switch via `sched_yield_switch` |
| 2 | `SYS_EXIT` | Terminate the calling task | None (self) | Tears down, wakes any `SYS_WAIT` waiter, switches away; does not return |
| 3 | `SYS_GET_LINE` | Read a line from the console | `CAP_CONSOLE` (slot 8) or endpoint READ (slot 3) | Returns length read |
| 10 | `SYS_SBRK` | Move the user heap break by a delta | None (own heap, within bounds) | Returns previous break, or 0 on failure |
| 11 | `SYS_WRITE` | Write to a descriptor (fd 1 → console/pipe) | None for console; pipe end / fs paths need their cap | Bytes written |
| 12 | `SYS_READ` | Read from a descriptor (fd 0 → console/pipe, fd ≥ 3 → fs) | endpoint / pipe cap as applicable | Bytes read |
| 13 | `SYS_OPEN` | Open a file by name | endpoint READ (slot 3) | Returns fd |
| 17 | `SYS_WAIT` | Block until another task exits | None | `TASK_BLOCKED_WAIT`; woken by the target's teardown. Returns 0 (incl. already dead), −1 on bad tid, `SYS_ERR_INTR` if a signal interrupts |
| 18 | `SYS_GET_TASK_INFO` | Read task metadata (name, state, uid, …) | Self always; other tasks need `CAP_USER` (slot 6) or `CAP_AUDIT` (slot 7) | Never exposes `cr3` |
| 19 | `SYS_EXEC` | Enter ring 3 at load-base + entry | endpoint WRITE\|EXEC (slot 3) | Rejects `load_base + entry ≥ USER_MAX_VADDR` (overflow guard) |
| 62 | `SYS_BRK` | Set the absolute heap break (`addr=0` queries) | None (own heap, demand-paged) | Bounded by `[heap_start, heap_start + USER_HEAP_MAX_SIZE)` |

> Numbers **1** (`SYS_PRINT`) and **20** (`SYS_GETPID`) are defined in `syscall.h` but **not dispatched** — output goes through `SYS_WRITE` (fd 1), the current UID through `SYS_GETUID`.

## Process control (ring-3)

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 28 | `SYS_SPAWN` | Spawn a named embedded binary as a new task | endpoint WRITE\|EXEC (slot 3) | Loads in the kernel address space; hands the caller a `CAP_TCB` to the child. `rdx`=one-word arg; `rsi`/`rdi`=argv/argc |
| 68 | `SYS_SPAWN_ARG` | Read the one-word argument this task was spawned with | None (self) | Fast path alongside the full argv |
| 69 | `SYS_GET_ARGV` | Read this task's argument vector | None (self) | Returns `argc`; writes the argv[] base to the user `char***`. Up to 16 args / 512 bytes |
| 63 | `SYS_KILL` | Terminate task `tid` | `CAP_TCB` to the target (or `CAP_USER` admin) | Enforced in the handler (dynamic target) |
| 64 | `SYS_EXEC_NAMED` | Replace the caller's own image with a named embedded binary | endpoint WRITE\|EXEC (slot 3) | Same pid and cspace (caps survive); `rsi`/`rdi`=argv/argc. No return on success |
| 70 | `SYS_SPAWN_IMAGE` | Spawn a child from a program image in the caller's memory (execve-from-fd) | endpoint WRITE\|EXEC (slot 3) | `rbx`/`rcx`=image/len (read from a file via `fs_server`); validated by the same loader (`arm_image_from_user`→`try_elf_load`). `rdx`=arg; `rsi`/`rdi`=argv/argc. Returns the child pid |
| 71 | `SYS_EXEC_IMAGE` | Replace the caller's own image with a caller-supplied image | endpoint WRITE\|EXEC (slot 3) | Same pid and cspace; shares the replace tail with `SYS_EXEC_NAMED`. Bad image fails cleanly; no return on success |
| 65 | `SYS_CAP_GRANT` | Copy the caller's cap from `src_slot` into a supervised child's `dest_slot` | `CAP_TCB` to the target (or `CAP_USER`) | Least-privilege delegation; routed through the locked, accounted, rights-masked `cap_grant_into` (audit A2) |
| 66 | `SYS_SIGNAL` | Send an async signal to another task | `CAP_TCB` to the target (or `CAP_USER`) | Same authority as `SYS_KILL`. Queues `signum` (1..31); default-terminates if unhandled or `SIG_KILL` (9). *(see Signals)* |

## IPC, notifications, and pipes

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 21 | `SYS_IPC_SEND` | Send a message to an endpoint | endpoint WRITE (slot 3) | **Non-blocking**: returns −2 if the single-slot mailbox is full |
| 22 | `SYS_IPC_RECV` | Receive a message from an endpoint | endpoint READ (slot 3) | **Non-blocking**: −2 if empty; else length |
| 23 | `SYS_IPC_CALL` | RPC-style send that may block for a reply | endpoint WRITE (slot 3) | May block (`TASK_BLOCKED_IPC`); resumed via the block/switch path |
| 24 | `SYS_IPC_REPLY` | Reply (thin wrapper over send) | endpoint WRITE (slot 3) | — |
| 73 | `SYS_IPC_SENDER` | Kernel-attested identity of an endpoint's last sender | endpoint READ (slot 3) | Returns the sender's uid, gid via `*rcx`, from `tasks[last_sender]` (set at login). `(uint32_t)-1` if none |
| 75 | `SYS_IPC_REPLY_TO` | Reply to the last request's sender on an endpoint | endpoint WRITE (slot 3) | Delivers straight into the sender's blocked `SYS_IPC_CALL`, routed by recorded identity — concurrent-client safe. 0 on delivery (or client gone); negative = retry |
| 25 | `SYS_NOTIFY` | Post a notification badge | endpoint WRITE (slot 3) | ORs the badge into the slot; wakes a blocked waiter (accumulates otherwise) |
| 26 | `SYS_WAIT_NOTIFY` | Wait for a notification badge | endpoint READ (slot 3) | Returns a pending badge, else blocks; badge in `rbx`. `make smoke-notify` |
| 83 | `SYS_PIPE` | Create a bounded in-kernel pipe | None (self) | Installs a read + write `CAP_PIPE` in the caller's cspace; returns `(read_slot<<16)\|write_slot` |
| 84 | `SYS_PIPE_READ` | Read from a pipe end | the read `CAP_PIPE` | Bytes; 0 = EOF (all writers closed); `SYS_ERR_AGAIN` = empty but a writer is open |
| 85 | `SYS_PIPE_WRITE` | Write to a pipe end | the write `CAP_PIPE` | Bytes; `SYS_ERR_AGAIN` = full but a reader is open; `SYS_ERR_PIPE` = no reader remains |
| 86 | `SYS_PIPE_CLOSE` | Drop a pipe-end cap and unref that end | the `CAP_PIPE` | Returns 0 |
| 87 | `SYS_STDIO_INFO` | Query which of fd 0/1 the spawner wired to a pipe | None (self) | bit0 = stdin-is-pipe, bit1 = stdout-is-pipe; read by `posix_init` |

## Task / program loading

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 27 | `SYS_RECEIVE_PROGRAM` | Receive a program image via the loader | endpoint WRITE\|EXEC (slot 3) | Arms the staged image for `SYS_SPAWN`/`SYS_EXEC` |

## Authentication & audit

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 29 | `SYS_GETUID` | Get the current UID | None | — |
| 30 | `SYS_AUTH` | Authenticate as a user | None (verifies a password) | Argon2id + constant-time compare; lockout + anti-spray throttle; scrubs cleartext; audits |
| 31 | `SYS_SUDO` | Re-authenticate and spawn the armed program as root | None (verifies the caller's password) | Returns new pid; least-privilege sudo frame |
| 32 | `SYS_GET_PASS` | Read a password from the console (masked) | None | Returns length |
| 33 | `SYS_USERADD` | Add a user account | `CAP_USER` (slot 6) or uid 0 | No initial password → CSPRNG-random hash (locked until `SYS_PASSWD`) |
| 34 | `SYS_USERDEL` | Remove a user account | `CAP_USER` (slot 6) or uid 0 | — |
| 35 | `SYS_PASSWD` | Change a password | Self, or admin for another user | Persists across reboots; scrubs cleartext |
| 36 | `SYS_ROTATE_KEYS` | Rotate stored-block keys | `CAP_CONSOLE` (slot 8) | Returns blocks rotated |
| 37 | `SYS_READ_AUDIT` | Read the kernel audit log | `CAP_AUDIT` READ (slot 7) | Circular buffer |
| 52 | `SYS_AUDIT_DIGEST` | Read the forward-secure audit digest | `CAP_AUDIT` READ (slot 7) | Writes 40 bytes (8-byte event count + 32-byte chain-head MAC); returns retained-window verify status (0 = intact, >0 = first tampered index + 1, −1 = uninitialised) |
| 88 | `SYS_DMESG` | Copy a chunk of the kernel message ring | **root only** (uid 0) | `(buf, offset, max)` → bytes copied at `offset`; `SYS_ERR_PERM` for non-root. Backs the `dmesg` command |

## Signals

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 54 | `SYS_SIGACTION` | Register/clear this task's fault/signal handler | None (self) | Handler vaddr validated to the task's own `[image_base, image_end)` (safe Rust); 0 clears |
| 55 | `SYS_SIGRETURN` | Resume the pre-signal context from a handler | None (self) | Restores the exact interrupted frame; serviced in `interrupt_handler64`. Fails outside a handler |
| 66 | `SYS_SIGNAL` | *(see Process control)* async task-to-task signal | `CAP_TCB` to the target | Lowest unmasked pending delivered into the target's handler; interrupts a `SYS_WAIT`-blocked target |
| 67 | `SYS_SIGMASK` | Block/unblock this task's own signals | None (self) | `how`=`SIG_SETMASK`/`SIG_BLOCK`/`SIG_UNBLOCK`; returns the old mask. `SIG_KILL` never maskable |
| 72 | `SYS_SIGALTSTACK` | Register this task's alternate signal stack | None (self) | `rbx`/`rcx`=`ss_sp`/`ss_size` (0 disables). SS_ONSTACK; must lie in user space and be ≥ `SIGSTKSZ_MIN`; refused while a handler runs on it |

Signal numbers: `SIG_ILL` (4, `#UD`), `SIG_KILL` (9, uncatchable/unmaskable), `SIG_USR1` (10), `SIG_SEGV` (11, page fault / `#GP`), `SIG_USR2` (12), `SIG_TERM` (15). The pending set and mask are full 1..31 (`SIG_MAX`) bitmasks.

## Capabilities

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 4 | *(mint)* | Mint a capability into a slot with reduced rights | `CAP_RIGHT_MINT` on the source | Raw number, no `SYS_` macro |
| 8 | *(transfer)* | Copy a capability to another slot | `CAP_RIGHT_MINT` on the source | Raw number |
| 9 | *(move)* | Move a capability (transfer, then revoke the source) | `CAP_RIGHT_MINT` on the source | Raw number |
| 51 | `SYS_CAP_REVOKE` | Revoke a capability and its derivation subtree | `CAP_RIGHT_REVOKE` on the target | System-wide descendant-only sweep + per-serial lineage bump |

## Filesystem — legacy in-memory capfs (removed)

Numbers **38–45** were the legacy in-memory capability-addressed filesystem (`SYS_FS_MINT_FILE`, `_LOOKUP`, `_CREATE`, `_DELETE`, `_READDIR`, `_GET_ROOT`, `_READ`, `_WRITE`). That parallel filesystem was **removed**: the `capfs_*` engine and `fs_objects[]` are gone, the dispatch entries deleted (the numbers **fail closed** with `SYS_ERR_NOSYS`), and the numbers reserved. The encrypted `fs_server` (below) is the single filesystem.

## Encrypted object store (fs_server backend)

The kernel exposes only an encrypted inode/block API; the ring-3 `fs_server` builds directories, paths, and file sizes on top. AEAD keys never leave the kernel TCB.

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 56 | `SYS_FS_INODE_ALLOC` | Allocate an inode of a given type | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Returns ino |
| 57 | `SYS_FS_INODE_FREE` | Free an inode | `CAP_BLOCK_DEV` + uid 0 | — |
| 58 | `SYS_FBLOCK_READ` | Read (decrypt + verify) an (inode, block) | `CAP_BLOCK_DEV` + uid 0 | Returns `BLOCK_SIZE`; fail-closed on a bad tag |
| 59 | `SYS_FBLOCK_WRITE` | Write (encrypt, fresh nonce) an (inode, block) | `CAP_BLOCK_DEV` + uid 0 | Per-(ino,block) AEAD |
| 60 | `SYS_FS_STAT` | Read inode metadata | `CAP_BLOCK_DEV` + uid 0 | Writes a `struct fs_stat` (size, type, mode, uid, gid, links) |
| 61 | `SYS_FS_SET_SIZE` | Set an inode's logical size | `CAP_BLOCK_DEV` + uid 0 | Server owns logical file size |
| 74 | `SYS_FS_SET_META` | Persist an inode's owner (uid/gid) + mode | `CAP_BLOCK_DEV` + uid 0 | Only the low 12 permission bits are settable (type bits preserved); backs chmod/chown after authorising the caller |
| 76 | `SYS_FS_INODE_LINK` | Increment an inode's hard-link count | `CAP_BLOCK_DEV` + uid 0 | Backs `link()`; `unlink` frees the inode only when the last name goes |

## Boot modules

Program images GRUB loaded as multiboot2 modules — read-only, same trust tier as the block store (both TCB-supplied), so same authority. The `fs_server` copies each into `/bin` (or `/usr/share/man`) at boot; nothing executes a module in place. Verified against the embedded SHA-256 manifest before exposure (audit A4).

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 77 | `SYS_BOOT_MODULE_INFO` | Count modules; read one's size + name | `CAP_BLOCK_DEV` (slot 7) + uid 0 | Returns the module count; fills a `struct boot_module_info` for a valid, verified index (empty slot if unverified) |
| 78 | `SYS_BOOT_MODULE_READ` | Copy a byte range out of a module's payload | `CAP_BLOCK_DEV` + uid 0 | Offset/length bounded to the module extent; source reached through `PHYS_KVA`; `SYS_ERR_PERM` for an unverified module |

## Device delegation (ring-3 drivers)

These let a ring-3 driver server own device hardware directly. All are gated on `CAP_IO_DEVICE` (slot 12) with WRITE — only `console_server` is endowed with it, by `init`. See [`proposals/console-server.md`](proposals/console-server.md).

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 79 | `SYS_MAP_PHYS` | Map an allowlisted device frame into the caller's address space | `CAP_IO_DEVICE` (slot 12) + WRITE | Frame must be on a fixed allowlist (VGA framebuffer / graphics-plane); mapped present + user + NX, one 4 KiB page per call. Fails closed off-list or on a kernel-half target |
| 80 | `SYS_IOPORT_GRANT` | Grant native ring-3 `in`/`out` on the console ports | `CAP_IO_DEVICE` (slot 12) + WRITE | Per-task TSS I/O-permission bitmap allowing only serial UART, PS/2 keyboard, VGA register ports; every other port still `#GP`s. Dropped on a switch away |
| 81 | `SYS_IRQ_REGISTER` | Route a hardware IRQ to an async notification | `CAP_IO_DEVICE` (slot 12) + WRITE | `irq` 0 (timer) / 1 (keyboard); each firing calls `sys_notify(slot, badge)`. Dropped when the task exits |
| 82 | `SYS_CONSOLE_OWNED` | Report whether a ring-3 console server owns the console | None (self, read-only) | Returns 1 if fd-1 output must route through the server, else 0 |

## Block storage & server registration

| # | Name | Description | Required capability | Notes |
|---|---|---|---|---|
| 46 | `SYS_REGISTER_STORAGE_BACKEND` | *(removed)* | — | **Fails closed** (`SYS_ERR_NOSYS`); slot reserved. Used to register ring-3 function pointers the kernel called from ring 0 — a TCB escape. See [SECURITY.md](../SECURITY.md) |
| 47 | `SYS_BLOCK_READ` | Read a raw storage block | `CAP_BLOCK_DEV` | — |
| 48 | `SYS_BLOCK_WRITE` | Write a raw storage block | `CAP_BLOCK_DEV` | — |
| 49 | `SYS_REGISTER_FS_SERVER` | Register the ring-3 filesystem server | admin | — |
| 50 | `SYS_CONNECT_FS_SERVER` | Obtain endpoints to the filesystem server | None | Mints fresh-serial endpoint caps |

## Test-only

| # | Name | Description | Notes |
|---|---|---|---|
| 53 | `SYS_PREEMPT_TRACE` | Append to the preemption trace ring | Present only in `PREEMPT_SELFTEST` builds; `SYS_ERR_NOSYS` otherwise |

---

## Dispatch and error model

Dispatch is table-driven: `syscall_handler` indexes `syscall_table[]` of descriptors `{ handler, slot, rights, type }`, validates the number, and — for a syscall whose authority is a single fixed capability — enforces it centrally before calling the handler. A number with no entry fails closed. A `_Static_assert` pins the table size to the highest syscall number + 1.

Error codes come from the shared, errno-aligned `SYS_ERR_*` vocabulary in [`include/errno.h`](../include/errno.h) (used by both kernel and userspace): `SYS_ERR_PERM` (missing capability), `SYS_ERR_NOSYS` (unknown/removed), `SYS_ERR_AGAIN` (pipe/IPC would block), `SYS_ERR_PIPE` (no reader), `SYS_ERR_AUTH`, `SYS_ERR_FAULT`, `SYS_ERR_INVAL`, `SYS_ERR_NOENT`, `SYS_ERR_REVOKED`, `SYS_ERR_NORIGHT`, `SYS_ERR_INTR`, … `sys_strerror()` renders them; the shell prints it.
