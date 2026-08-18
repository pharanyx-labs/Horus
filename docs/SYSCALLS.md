# Horus Syscall Reference

## Calling convention

Syscall number in `rax`; arguments in `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, with a sixth in
`r8`. Arguments and the return value are 64-bit — they carry user pointers, and `SYS_BRK` /
`SYS_SBRK` return addresses.

Entry is `int 0x80` → `interrupt_handler64` → `syscall_handler`.

Userspace wrappers for every call live in [`include/syscall.h`](../include/syscall.h).

## Dispatch and authorisation

Every syscall has exactly one entry in a descriptor table:

```c
typedef struct {
    void   (*fn)(struct interrupt_frame64 *r);
    uint16_t slot;     /* authorizing cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;
```

Where a syscall's authority is a single fixed capability, `syscall_handler` enforces it
**centrally, before the handler runs** — so the syscall physically cannot execute without it.
`SC_NONE` means the authority is argument-dependent (the target is dynamic) and the handler
performs its own check; the reason is noted per entry in `src/kernel/syscall.c`.

**Fail-closed properties.**

- A number with no table entry, or a `NULL` handler, returns `SYS_ERR_NOSYS`.
- Numbers **38–45** are permanently reserved. They were the legacy in-memory capfs; the
  entries were removed rather than reused, so no future syscall silently inherits an old
  ring-3 caller.
- A compile-time assertion ties the table size to the highest syscall number, so adding a
  syscall without its entry is a build failure.

> ### IPC arguments are cspace slots, not object indices
>
> Every IPC syscall's first argument is a **cspace slot**. The kernel resolves it through
> `ipc_ep_from_slot` / `ipc_notif_from_slot`, checking the capability's type, the right for
> the direction (`READ` to receive, `WRITE` to send), and its lineage generation before
> trusting `object`. A task therefore reaches a service only via a capability naming that
> service's endpoint.
>
> `READ` is the receive right, so it is what separates a server from its clients:
> `SYS_IPC_RECV`, `SYS_IPC_RECV_BLOCK`, `SYS_IPC_REPLY_TO`, and `SYS_IPC_SENDER` all require it, and clients are
> minted `WRITE`-only. Replies land on the caller's private per-task reply endpoint, which no
> other task can name. Fixed 2026-07-27 — see **[C-1]** in
> [`AUDIT-2026-07-27.md`](AUDIT-2026-07-27.md).

## Return values

Errors are negative `SYS_ERR_*` codes (`include/errno.h`); success is `0`, a length, or an
identifier depending on the call.

| Code | Meaning |
|---|---|
| `SYS_OK` | Success |
| `SYS_ERR_PERM` | Authorisation failed |
| `SYS_ERR_INVAL` | Invalid argument |
| `SYS_ERR_NOENT` | No such object |
| `SYS_ERR_FAULT` | A user pointer could not be resolved |
| `SYS_ERR_NOSYS` | Unknown, reserved, or unimplemented |
| `SYS_ERR_AGAIN` | Would block — retry (pipes). The IPC calls use `IPC_AGAIN` (`-2`) instead; see [IPC](#ipc) |
| `SYS_ERR_INTR` | Interrupted by a signal |
| `SYS_ERR_IO` | Storage failure |
| `SYS_ERR_PIPE` | No reader on the pipe |

`SYS_SBRK` is the exception: its failure sentinel is `(uint64_t)-1`, the all-ones pointer,
because it returns an *address* and newlib's `_sbrk` compares against `(void *)(intptr_t)-1`.

---

## Process and task control

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 0 | `SYS_YIELD` | — | none (self) |
| 2 | `SYS_EXIT` | — | none (self) |
| 17 | `SYS_WAIT` | `tid` | none (self) |
| 18 | `SYS_GET_TASK_INFO` | `tid`, `struct task_info *` | self; or `CAP_USER` / `CAP_AUDIT` |
| 19 | `SYS_EXEC` | `load_base`, `entry` | slot 3: WRITE\|EXEC |
| 20 | `SYS_GETPID` | — | none (self-authorising) |
| 28 | `SYS_SPAWN` | — | slot 3: WRITE\|EXEC |
| 63 | `SYS_KILL` | `tid` | `CAP_TCB` for target, or `CAP_USER` |
| 64 | `SYS_EXEC_NAMED` | `name` | slot 3: WRITE\|EXEC |
| 68 | `SYS_SPAWN_ARG` | — | none (self) |
| 69 | `SYS_GET_ARGV` | `char ***out` | none (self) |
| 70 | `SYS_SPAWN_IMAGE` | `image`, `len`, `arg`, `argv`, `argc` | slot 3: WRITE\|EXEC |
| 71 | `SYS_EXEC_IMAGE` | `image`, `len`, `0`, `argv`, `argc` | slot 3: WRITE\|EXEC |
| 27 | `SYS_RECEIVE_PROGRAM` | `struct program_header *` | slot 3: WRITE\|EXEC |

`SYS_GET_TASK_INFO` reports `cr3` as 0 deliberately — disclosing the page-table physical base
would reveal the physical memory layout — and since **[I-4]** reports `eip` only for the
calling task, zeroed for any other, so it cannot be used to defeat another task's ASLR. Being
uid 0 is no longer sufficient for cross-task introspection; a `CAP_USER` or `CAP_AUDIT` is
required (**[I-1]**).

`SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE` are the `execve`-from-memory path. The image is validated
by the Rust ELF loader exactly like a named binary.

**Every one of these consumes the same process-wide staging, and since 2026-08-18 it has an
owner.** Arming an image records the arming task, and a spawn or exec refuses to consume an
image armed by any other — fail closed, including on an image with no recorded owner. This is
invisible to a caller that arms and spawns in the usual way (both halves are the same task) and
matters to the two paths where they can differ: `SYS_SPAWN` with a null name, which spawns
whatever is already armed, and `SYS_SUDO`. Finding **[G-11]**, property **S21**; the arm →
consume window is also serialised, so two CPUs cannot interleave through the staging buffer.

## Signals

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 54 | `SYS_SIGACTION` | `handler` | self only |
| 55 | `SYS_SIGRETURN` | — | inside a handler only |
| 66 | `SYS_SIGNAL` | `tid`, `signum` | `CAP_TCB` for target, or `CAP_USER` |
| 67 | `SYS_SIGMASK` | `how`, `mask` | self only |
| 72 | `SYS_SIGALTSTACK` | `ss_sp`, `ss_size` | self only |

`SYS_SIGACTION` validates the handler address against the caller's own image window in safe
Rust, so a fault can only ever redirect ring-3 control flow into plausible user code.
`SIG_KILL` is uncatchable and unblockable. Registering an altstack while executing on one
fails closed.

## Memory

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 10 | `SYS_SBRK` | `increment` | none (own heap, bounds-checked) |
| 62 | `SYS_BRK` | `addr` (0 queries) | none (own heap) |

Both grow the authorised ceiling on demand; physical pages arrive lazily via the demand pager.
Both currently perform 32-bit arithmetic on 64-bit heap bounds — finding **[I-2]**.

## Console and basic I/O

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 3 | `SYS_GET_LINE` | `buf` | slot 8 READ, else slot 3 READ |
| 5 | *clear screen* | — | slot 3: WRITE |
| 6 | *sysinfo* | `buf` (64 bytes) | none (ambient version string) |
| 7 | *debug exec* | `cmd` | `DEBUG_SHELL` builds only |
| 11 | `SYS_WRITE` | `fd`, `buf`, `len` | none (fd 1 = ambient console) |
| 12 | `SYS_READ` | `fd`, `buf`, `len` | fd 0 ambient; fd ≥ 3 needs slot 3 READ |
| 13 | `SYS_OPEN` | `name`, `flags` | slot 3: READ |
| 82 | `SYS_CONSOLE_OWNED` | — | none (read-only status) |
| 88 | `SYS_DMESG` | `buf`, `offset`, `max` | `CAP_KERNEL_LOG` at `CAPSLOT_KERNEL_LOG` |

`SYS_GET_LINE` and the fd-0 path of `SYS_READ` **fail closed while a ring-3 console server
owns the UART** (`console_hw_owned()`). A kernel-side read would race the owner and steal
bytes from a typed line, so clients must route input through the server. The in-kernel path
exists only for before handoff and after the owner dies.

`SYS_DMESG` requires a `CAP_KERNEL_LOG` capability, which `init` delegates to the shell
(finding **[I-1]**; it was previously an ambient `uid == 0` check). The kernel log discloses
addresses and boot detail, so the shell additionally restricts the `dmesg` *command* to root
— capabilities are per-task and the shell serves successive logins, so only the session
manager can express a per-user policy. It is read in small chunks (offset + max), so no
shared kernel buffer is exposed.

## Capabilities

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 4 | *cap mint* | `dest_slot`, `src_slot`, `rights` | `CAP_RIGHT_MINT` on source |
| 8 | *cap transfer* | `dest_slot`, `src_slot` | `CAP_RIGHT_MINT` on source |
| 9 | *cap move* | `dest_slot`, `src_slot` | transfer + revoke |
| 51 | `SYS_CAP_REVOKE` | `slot` | `CAP_RIGHT_REVOKE` on target |
| 65 | `SYS_CAP_GRANT` | `target_tid`, `src_slot`, `dest_slot` | `CAP_TCB` for target, or `CAP_USER` |

Mint and grant mask rights to `new_rights & src->rights` — **delegation can only ever reduce
authority**. Grant pushes into a child the caller supervises; there is deliberately no
reserved-slot floor, because endowing a child's low slots is exactly what grant is for.

`SYS_CAP_REVOKE` is **system-wide and subtree-scoped**: it nulls the target and every
capability transitively derived from it across every task's cspace, while leaving ancestors,
siblings, and independent capabilities to the same object intact.

Kernel-reserved slots 0–3 cannot be minted into. Primordial root capabilities (serial prefix
`0xC0DE`) cannot be revoked.

## Untyped memory

| # | Name | Arguments | Authorisation *(as checked)* |
|---|---|---|---|
| 90 | `SYS_RETYPE` | `untyped_slot`, `kobj_type`, `count`, `dest_slot` | `CAP_UNTYPED` at `untyped_slot`: WRITE |
| 91 | `SYS_UNTYPED_INFO` | `untyped_slot`, `struct untyped_info *` | `CAP_UNTYPED` at `untyped_slot`: READ |

Both are capability-**addressed** like the IPC calls: the slot argument *is* the gate, and
both are `SC_NONE` in the dispatch table. A fixed table slot would repeat finding **[C-1]** —
gating on a capability every task happens to hold while never consulting the one that names
the resource.

`kobj_type` is `KOBJ_ENDPOINT` (2) or `KOBJ_NOTIFICATION` (3). `KOBJ_CNODE` (1) is allocatable
by the kernel but **refused to ring 3**: no capability type names a CNode and no syscall
installs one as a task's cspace, so minting one would be authority with no defined meaning.

`SYS_RETYPE` returns the number of objects created — which may be fewer than `count` if the
region runs out — or a negative error. It refuses outright, without consuming any of the
region, on: a destination below `KERNEL_RESERVED_CAPS` (`SYS_ERR_PERM`), a run that would
overrun the cspace (`SYS_ERR_RANGE`), and an unknown type or zero count (`SYS_ERR_INVAL`). A
refusal that spent budget would be a denial-of-service primitive against the caller's own
region, so `captest` asserts the watermark is unchanged after every refused call.

Each new object's capability carries READ|WRITE|GRANT|MINT|REVOKE — the creator is its only
holder, so nothing can be surprised by a later revoke, and revoking the last capability to an
object **destroys it**.

Allocation is a monotonic bump pointer: destroying an object does not return its bytes. See
[`ARCHITECTURE.md` §4](ARCHITECTURE.md) for why that is a safety property rather than a
simplification.

## IPC

| # | Name | Arguments | Authorisation *(as checked)* |
|---|---|---|---|
| 21 | `SYS_IPC_SEND` | `ep_slot`, `msg`, `len` | `CAP_ENDPOINT` at `ep_slot`: WRITE |
| 22 | `SYS_IPC_RECV` | `ep_slot`, `buf`, `max` | `CAP_ENDPOINT` at `ep_slot`: **READ** |
| 94 | `SYS_IPC_RECV_BLOCK` | `ep_slot`, `buf`, `max` | `CAP_ENDPOINT` at `ep_slot`: **READ** |
| 23 | `SYS_IPC_CALL` | `send_slot`, *(ignored)*, `msg`, `len`, `reply_buf` | `CAP_ENDPOINT` at `send_slot`: WRITE |
| 24 | `SYS_IPC_REPLY` | `ep_slot`, `msg`, `len` | `CAP_ENDPOINT` at `ep_slot`: WRITE |
| 25 | `SYS_NOTIFY` | `notif_slot`, `badge` | `CAP_NOTIFICATION` at `notif_slot`: WRITE |
| 26 | `SYS_WAIT_NOTIFY` | `notif_slot` | `CAP_NOTIFICATION` at `notif_slot`: READ |
| 73 | `SYS_IPC_SENDER` | `ep_slot`, `uint32_t *out_gid` | `CAP_ENDPOINT` at `ep_slot`: **READ** |
| 75 | `SYS_IPC_REPLY_TO` | `req_slot`, `msg`, `len` | `CAP_ENDPOINT` at `req_slot`: **READ**, *plus* the one-shot `CAP_REPLY` at `CAPSLOT_REPLY` (21), which it consumes |

`SYS_IPC_REPLY_TO` requires **READ**, not WRITE: it writes directly into the recorded
sender's blocked reply buffer, so only the task that legitimately *receives* requests on the
endpoint may answer them. Requiring WRITE would let any client — every client holds WRITE in
order to send — impersonate the server to another client.

`SYS_IPC_CALL`'s second argument is vestigial and ignored; the reply always lands on the
caller's own private reply endpoint. Pass 0.

`SEND` and `RECV` are **non-blocking**: they return `-2` when the endpoint's bounded FIFO is
genuinely full (`SEND`, `count == EP_QUEUE_SLOTS`) or empty (`RECV`, `count == 0`), and the
caller polls from ring 3 where timer preemption guarantees progress. Spinning in-kernel would
not, since the kernel is not preemptible.

`SYS_IPC_RECV_BLOCK` is the **blocking** receive, and it is what a server should use. Same
capability and same right as `SYS_IPC_RECV` — `CAP_ENDPOINT` with **READ** — and the same
completion, including minting the one-shot `CAP_REPLY` for the message it hands back; the only
difference is that an empty queue sleeps the caller instead of answering `-2`. It therefore
**never returns `IPC_AGAIN`**, so a negative return from it is permanent and must not be
retried in a loop (see the retry contract below).

Two things about it are worth stating because they are where a blocking receive usually goes
wrong. The wait is published only *after* the trap frame is saved — the same ordering
`SYS_IPC_CALL` uses, so a sender on another CPU cannot patch a stale frame. And the wake is
performed by the *sender's* syscall, in the sender's address space and cspace, so the reply
right has to be minted into a cspace that is not the current one; getting that wrong would
hand a woken server a request it holds no authority to answer. `make smoke-recvblock` asserts
exactly that, and fails if the mint is removed.

A task blocked in `SYS_IPC_RECV_BLOCK` is waiting for a **request**, not a reply, so
`SYS_IPC_REPLY_TO` refuses to deliver into it: a reply capability naming a task that has moved
on to receiving is stale by construction, and delivering would inject a message past the
endpoint queue.

**`-2` is the only retryable IPC code.** It is `IPC_AGAIN` in
[`include/syscall.h`](../include/syscall.h), tested by `ipc_transient(rc)`, and it is a raw
literal — *not* `SYS_ERR_AGAIN` (`-11`), which the IPC syscalls never return. Every other
negative is **permanent**, `SYS_ERR_PERM` (`-1`) above all: it means "you hold no capability
for this endpoint", which will be just as true on the millionth attempt as on the first. A
`while (sys_ipc_call(...) < 0) spin_delay();` loop therefore retries an authorisation failure
forever, which is a security bug and not merely a robustness one — fail-closed has to mean
stop, loudly, at the point authority was refused, or the one event the capability system
exists to make visible becomes indistinguishable from a hang. Retry on `ipc_transient()`
only, and bound even that.

`SYS_IPC_CALL` blocks. It deposits the message and records a *pending* block; the waiter is
published only after the trap frame is saved, so a cross-CPU reply can never patch a stale
frame.

`SYS_IPC_SENDER` is the **zero-trust identity anchor**: it returns `tasks[last_sender].uid` —
established only by a successful `SYS_AUTH` and recorded by the kernel when the message was
sent, *not* anything the client placed in the message. `fs_server` authorises every request
against it.

`SYS_IPC_REPLY_TO` routes the reply to the client named by the one-shot `CAP_REPLY` that
`SYS_IPC_RECV` minted for the dequeued message — not through a shared reply endpoint, and no
longer through the endpoint's mutable `last_sender`, which the next receive overwrites. The
capability names one blocked caller, cannot be retargeted, and is consumed by the reply, so a
server cannot reply twice to one request or reply to a client it never received from: both
are unrepresentable rather than merely refused. That is what makes one server safe for
concurrent clients. It may return `-2` under SMP if the sender has deposited its request but
not yet published its block — the server retries, and the reply right is deliberately *not*
consumed on that path.

## Pipes

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 83 | `SYS_PIPE` | — → `(read_slot<<16)\|write_slot` | none (own cspace) |
| 84 | `SYS_PIPE_READ` | `slot`, `buf`, `len` | `CAP_PIPE` READ at `slot` |
| 85 | `SYS_PIPE_WRITE` | `slot`, `buf`, `len` | `CAP_PIPE` WRITE at `slot` |
| 86 | `SYS_PIPE_CLOSE` | `slot` | `CAP_PIPE` at `slot` |
| 87 | `SYS_STDIO_INFO` | — | none (own tcb) |

Pipes *are* properly capability-addressed: the slot argument is a cspace slot resolved through
`cap_lookup` with the direction's right. They are the model the IPC syscalls should follow.

`SYS_PIPE_READ` returns 0 at EOF and `SYS_ERR_AGAIN` when empty with writers still open;
`SYS_PIPE_WRITE` returns `SYS_ERR_AGAIN` when full and `SYS_ERR_PIPE` when there is no reader.
`task_teardown` releases a dying task's ends so a pipeline stage cannot wedge its peer.

## Users and authentication

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 29 | `SYS_GETUID` | — | none (self) |
| 30 | `SYS_AUTH` | `user`, `pass` | none (self-authorising) |
| 31 | `SYS_SUDO` | `pass` | re-authentication in handler **and** the armed image must be one this task armed (**S21**) |
| 32 | `SYS_GET_PASS` | `buf` | none |
| 33 | `SYS_USERADD` | `user`, `pass` | `CAP_USER` at `CAPSLOT_USER` |
| 34 | `SYS_USERDEL` | `user` | `CAP_USER` at `CAPSLOT_USER` |
| 35 | `SYS_PASSWD` | `user`, `pass` | `CAP_USER`, or the target is the caller's own uid |

These three are `SC_NONE` in the dispatch table, so `current_user_is_admin()` in
`src/kernel/kusers.c` *is* the gate. Until 2026-08-15 it accepted `uid == 0` as an
alternative to holding the capability — the last surviving ambient gate from **[I-1]**, which
roadmap 0.2's sweep of `syscall.c` never reached (finding **[H-1]**). "Admin" here now means
possession of `CAP_USER`, and nothing else; a task at uid 0 with an empty cspace is refused.
Witnessed by `make smoke-captest` (which runs as uid 0 and holds no `CAP_USER`) and by
`make smoke-session`, which asserts both directions through the real ring-3 shell.

`SYS_SUDO` spawns the currently-armed program image as uid 0, and the arm is a *different
syscall* from the consume. Until 2026-08-18 nothing tied the two together, so a task that
authenticated correctly could elevate a program **another** task had armed — a confused deputy
in which neither party fails a rights check and the authority comes from the pairing (finding
**[G-11]**, adversary **A1c**). The handler now refuses unless the armed image belongs to the
caller, and audits that refusal rather than logging a failure: a correct password that was about
to elevate somebody else's program is the event worth recording.

Passwords are Argon2-hashed. Failed authentication is rate-limited per task
(`auth_fail_count`, `auth_lockout_until`).

## Object store — `fs_server` only

Gated on a `CAP_ENCRYPTED_STORAGE` capability at `CAPSLOT_AUDIT`, required **by type**. The
ambient `uid == 0` check that used to accompany it is gone (**[I-1]**), and the type is now
actually enforced — these entries previously passed the type constant in the *rights* field
with `ctype = SC_ANYTYPE`, so any capability with `READ|WRITE|GRANT` passed (**[I-1a]**). The
AEAD stays entirely in the kernel; the server addresses storage as `(inode, logical block)`
and never sees key material.

| # | Name | Arguments |
|---|---|---|
| 46 | `SYS_REGISTER_STORAGE_BACKEND` | — |
| 47 / 48 | `SYS_BLOCK_READ` / `SYS_BLOCK_WRITE` | raw block I/O |
| 56 / 57 | `SYS_FS_INODE_ALLOC` / `_FREE` | `type` → `ino` / `ino` |
| 76 | `SYS_FS_INODE_LINK` | `ino` (increment link count) |
| 58 / 59 | `SYS_FBLOCK_READ` / `_WRITE` | `(ino, block, buf[, len])` — decrypt+verify / encrypt with fresh nonce |
| 60 | `SYS_FS_STAT` | `ino`, `struct fs_stat *` |
| 61 | `SYS_FS_SET_SIZE` | `ino`, `size` |
| 74 | `SYS_FS_SET_META` | `ino`, `mode`, `uid`, `gid` |
| 77 | `SYS_BOOT_MODULE_INFO` | `index`, `struct boot_module_info *` → count *(needs `CAP_BOOT_MODULE`)* |
| 78 | `SYS_BOOT_MODULE_READ` | `index`, `offset`, `buf`, `len` *(needs `CAP_BOOT_MODULE`)* |

`SYS_BOOT_MODULE_READ` **refuses any module that failed its manifest hash check**. Since
provisioning into `/bin` goes through this path, an unverified module can never become a
root-owned executable. `SYS_BOOT_MODULE_INFO` reports such a module as an empty slot, keeping
module numbering stable.

## Filesystem server registration

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 49 | `SYS_REGISTER_FS_SERVER` | `ep_slot` | slot 6: `CAP_USER` (ALL) |
| 50 | `SYS_CONNECT_FS_SERVER` | `dest_slot`, `rights` | none — any task may connect |

Connecting grants no file access on its own: the server is a reference monitor that authorises
every request by kernel-attested identity. `SYS_CONNECT_FS_SERVER` mints the endpoint
capability through the locked, accounted `cap_install_endpoint` path (rights masked to
READ\|WRITE\|GRANT), not a raw cspace store.

These two are the only places `CAP_ENDPOINT->object` is currently consulted.

## Device delegation — `console_server` only

Gated on `CAP_IO_DEVICE` with WRITE in slot 10. Only `init` holds the primordial copy and it
grants it to exactly one task.

| # | Name | Arguments |
|---|---|---|
| 79 | `SYS_MAP_PHYS` | `paddr`, `vaddr`, `len`, `flags` — map an **allowlisted** device frame |
| 80 | `SYS_IOPORT_GRANT` | — grant native ring-3 `in`/`out` on the console ports via the TSS I/O bitmap |
| 81 | `SYS_IRQ_REGISTER` | `irq`, `notif_slot`, `badge` — route a hardware IRQ to the notification named by the `CAP_NOTIFICATION` at `notif_slot` (needs WRITE) |

`SYS_MAP_PHYS` additionally checks the requested frame against a fixed allowlist in the
handler, so the capability grants access to *device* memory, not to arbitrary physical
memory.

The port-I/O grant is revoked in `task_teardown` (`io_allowed = 0`), because task slots are
reused — otherwise a fresh task could inherit a dead driver's grant. `tss_set_io_allowed` is
driven from the single `set_current_task` chokepoint, so every other task gets an
`iomap_base` past the TSS limit and a ring-3 `in`/`out` faults.

## Audit

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 36 | `SYS_ROTATE_KEYS` | — | slot 8: `CAP_CONSOLE` READ |
| 37 | `SYS_READ_AUDIT` | `buf`, `max` | slot 7: `CAP_AUDIT` READ |
| 52 | `SYS_AUDIT_DIGEST` | `buf` | slot 7: `CAP_AUDIT` READ |

The audit log is **forward-secure**: the chaining key is ratcheted after each record, so an
attacker who compromises the system cannot forge or alter history written before the
compromise.

## Test-only

| # | Name | Present in |
|---|---|---|
| 53 | `SYS_PREEMPT_TRACE` | `PREEMPT_SELFTEST` builds only — `SYS_ERR_NOSYS` otherwise |

## Reserved

| # | Former name |
|---|---|
| 1 | `SYS_PRINT` (never dispatched) |
| 38–45 | The removed in-memory capfs — permanently reserved, never to be reused |

---

## Adding a syscall

1. Define the number in **both** `include/syscall.h` and `src/include/kernel.h` — they are
   duplicated, and drift between them is a real hazard.
2. Write `h_yourcall(struct interrupt_frame64 *r)` in the appropriate `syscall*.c`.
3. Add the table entry with its authorising slot, rights, and type — or `SC_NONE` plus a
   comment stating where the handler performs its own check.
4. Grow `SYSCALL_TABLE_SIZE`. The `_Static_assert` will tell you if you forgot.
5. Add a userspace wrapper in `include/syscall.h`.
6. **Add a negative test to `userspace/captest.c`** proving the call is refused without its
   capability. This is not optional — see `CONTRIBUTING.md`. Assert the **exact** error code,
   not merely a negative return: `sys_ipc_recv` returns `-2` for an empty queue, so a
   `< 0` check cannot tell a refusal from an empty object and will pass on a broken kernel.
