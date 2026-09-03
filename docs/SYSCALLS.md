# Horus Syscall Reference

## Calling convention

Syscall number in `rax`; arguments in `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, with a sixth in `r8`.
Arguments and the return value are 64-bit; they carry user pointers, and `SYS_BRK` / `SYS_SBRK`
return addresses.

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
**centrally, before the handler runs**, so the syscall physically cannot execute without it.
`SC_NONE` means the authority is argument-dependent (the target is dynamic) and the handler
performs its own check; the reason is noted per entry in `src/kernel/syscall.c`.

**Fail-closed properties.**

- A number with no table entry, or a `NULL` handler, returns `SYS_ERR_NOSYS`.
- Numbers **38–45** are permanently reserved. They were the legacy in-memory capfs; the
  entries were removed rather than reused, so no future syscall silently inherits an old
  ring-3 caller.
- A compile-time assertion ties the table size to the highest syscall number, so adding a
  syscall without its entry is a build failure.

> ### Retired: four syscalls with no caller anywhere in the tree
>
> `SYS_CLEAR` (5), `SYS_SYSINFO` (6), `SYS_DEBUG_EXEC` (7) and `SYS_EXEC_LEGACY` (14) were
> **removed on 2026-08-23** and now fail closed at `SYS_ERR_NOSYS`, their numbers reserved the
> way 38–45 are. None had a wrapper in `include/syscall.h` or a caller in any program under
> `userspace/`: they were reachable only by issuing the raw number, which any ring-3 task can do.
>
> **`SYS_EXEC_LEGACY` is why this is a security change and not a tidy-up.** It read
> `{ h_exec, 3, CAP_RIGHT_WRITE|CAP_RIGHT_EXEC, SC_ANYTYPE }`, cspace slot 3, the legacy
> `CAP_FRAME` `create_task` installs in every task, any type, and it **creates a task**. That is
> exactly the shape **[H-3]** closed on four other doors, and it sat directly beneath the comment
> explaining that shape for the whole of that finding. Measured before removal: `passwdprobe`,
> running as uid 1000 and holding no delegated capability, called syscall 14 and was handed task
> id 2.
>
> The task it made had no identity of its own, `create_task` assigns `state` and never `uid` or
> `gid`, so a new task carried whatever the slot held: 0 on a never-used slot, the previous
> occupant's uid on a reused one. Since **S18** uid 0 confers no *kernel* authority, but
> `fs_server` enforces file permissions against the kernel-attested uid (**S13**/**S14**).
>
> `SYS_DEBUG_EXEC` survives in a `DEBUG_SHELL=1` build, which is documented development-only
> surface. Before this change its *entry* was unconditional and only the handler body was
> guarded, so the ship kernel dispatched it, copied 127 bytes from the caller, and returned −1.
>
> Witness `make smoke-passwd-probe` (8 checks), falsified by
> `make smoke-passwd-probe-legacy-control` (`LEGACY_SYSCALLS_PRESENT=1`).

> ### Retired: the in-kernel ramfs surface

`SYS_OPEN` (13), `SYS_RAMFS_CREATE` (15), `SYS_RAMFS_LIST` (16) and `SYS_READ` for
`fd >= 3` were **removed on 2026-08-22** (finding **[H-3]**) and now fail closed at
`SYS_ERR_NOSYS`, exactly as syscalls 38–45 do.

All four authorised on cspace slot 3 with `SC_ANYTYPE`. Slot 3 holds the legacy `CAP_FRAME` that
`create_task` installs in every task, so the gate was satisfied by a capability nobody asked for
and everybody has; **[C-1]**'s shape, on the last four gates still wearing it. The in-kernel
ramfs itself remains, used internally by `src/kernel/kusers.c`; what was removed is the ring-3
door, not the store. Filesystem access from ring 3 is the `fs_server` IPC protocol
(`include/fs_proto.h`) and nothing else.

## Frame capabilities and shared memory

**Seven entries were named on 2026-08-23**, `SYS_YIELD` (0, which had a name the table did not
use), `SYS_CLEAR` (5), `SYS_SYSINFO` (6), `SYS_DEBUG_EXEC` (7), `SYS_EXEC_LEGACY` (14),
`SYS_RAMFS_CREATE` (15) and `SYS_RAMFS_LIST` (16). The numbers are unchanged; what changed is
that `tools/check_syscall_coverage.py` can now see them, so each one has to be classified and
carry evidence. As bare `[5]`-style indices they were invisible to it, which is how five live
handlers in the ship build came to have no coverage rule, no measurement and, for four of them:
no userspace wrapper anywhere in this tree. A bare numeric index is now refused by the checker.

| # | Name | Arguments | Authorisation *(as checked)* |
|---|---|---|---|
| 4 | `SYS_CAP_MINT` | `dest_slot`, `src_slot`, `rights` | holding the source; `cap_mint` masks to `rights & src->rights` |
| 95 | `SYS_MAP_FRAME` | `frame_slot`, `vaddr`, `rights` | `CAP_FRAME` at `frame_slot`, holding at least `rights`; maps the **whole run** the frame names |
| 96 | `SYS_UNMAP_FRAME` | `frame_slot`, `vaddr` | `CAP_FRAME` at `frame_slot`, any rights; withdraws the **whole run** |
| 99 | `SYS_MAP_REGION` | `first_slot`, `count`, `vaddr`, `rights` | a `CAP_FRAME` at each of `first_slot .. first_slot+count-1`, each holding at least `rights` |
| 100 | `SYS_FRAME_PAGES` | `frame_slot` | `CAP_FRAME` at `frame_slot`, any rights |
| 109 | `SYS_UNTYPED_SPLIT` | `src_slot`, `dest_slot`, `bytes` | `CAP_UNTYPED` + WRITE at `src_slot`. Carves `bytes` off that region and mints a **derived** `CAP_UNTYPED` over the sub-region into `dest_slot`. The parent's watermark advances past the carve, so a split **spends** budget rather than creating it (**S58**), and it is what makes **S57**'s "a task given a small region can spawn a bounded number of times" mintable — granting a `CAP_UNTYPED` names the *same* region and shares the whole budget |
| 101 | `SYS_FORK` |, | `CAP_UNTYPED` at `CAPSLOT_UNTYPED` (`CAP_RIGHT_WRITE`) — the same authority `SYS_SPAWN` requires, because both create a task and a task's cspace is carved from it (**S57**) |

Both frame calls are `SC_NONE` in the dispatch table for the same reason `SYS_RETYPE` is, and
here the alternative is not hypothetical: **every task is born holding a `CAP_FRAME` in slot
3**, so a table entry reading `{ h_map_frame, CAPSLOT_FRAME, CAP_RIGHT_WRITE, CAP_FRAME }`
would have type-checked, passed for every task in the system, and authorised nothing.

**A `CAP_FRAME` names an index, not an address.** `capability_t.object` is an index into the
frame table `SYS_RETYPE` populates, checked against `[DYN_FRAME_BASE, FRAME_INDEX_MAX)`. The
shortcut (put the physical address in `object` and map it) would have been reachable on the
first boot through that slot-3 capability, whose object is `USER_AREA_BASE`: it would ask the
kernel to map physical `0x400000` into ring 3. The index makes that refusal a bound rather than
an allowlist somebody remembered to write. See `SECURITY.md` **S26**.

`SYS_MAP_FRAME` builds the PTE from `cap->rights & rights`, so a mapping can never carry
authority the capability does not (**S27**). It refuses, without mapping anything: a capability
of the wrong type or a dead frame index (`SYS_ERR_PERM` / `SYS_ERR_INVAL`), an address that is
zero, misaligned, or in the kernel half (`SYS_ERR_INVAL`), an empty rights request
(`SYS_ERR_INVAL`: x86-64 has no read-disable bit, so it names no mapping the hardware can
express), `WRITE` and `EXEC` together (`SYS_ERR_INVAL`, W^X), and an address that is already
mapped (`SYS_ERR_EXIST`, silently replacing a live PTE would drop that page's reference with
nobody releasing it).

`SYS_UNMAP_FRAME` requires the capability as well as the address, and the PTE at `vaddr` must
name *that* capability's frame. Without it, an address-only unmap would let any task punch a
hole in its own image, stack, or heap, pages it holds no frame capability for.

**`SYS_MAP_REGION` is all-or-nothing, and that is the ABI, not an implementation detail**
(**S35**). It maps `count` frames from consecutive cspace slots at `count` consecutive pages
from `vaddr`; the dual of `SYS_RETYPE(untyped, KOBJ_FRAME, count, dest)`, which fills the run of
slots it maps. Every per-page refusal listed for `SYS_MAP_FRAME` applies unchanged, because both
calls share one validation function; the run itself additionally refuses `count == 0`
(`SYS_ERR_INVAL`), `count` above 64 (`SYS_ERR_RANGE`), a slot run that leaves the cspace
(`SYS_ERR_RANGE`), and an address run whose *last byte* is not in the user half
(`SYS_ERR_INVAL`).

**It returns 0 or an error, never a count of pages mapped.** If any page of the run fails, every
page the call already mapped is withdrawn before it returns, so a caller holding an error holds
the address space it started with. That is deliberately the opposite of `SYS_RETYPE`, which
stops at the first failure, keeps what it made, and returns how many: retype's partial result is
complete information (n objects, each named by a capability at a slot the caller computed) while
a partial *map* is a hole in a range whose whole purpose is to be addressed as a range, found
later as a fault with nothing left to say which call left it. A PTE is authority, so a partial
map after a reported error hands ring 3 authority it was just told it did not get.

The unwind withdraws **only the pages this call installed**. The pre-existing mapping that
caused the refusal is not one of them and survives: an unwind that cleared the whole *requested*
range would answer a refused request by destroying the mapping that refused it, which any task
could invoke against a mapping it disliked by asking to map a region across it. Both directions
are gated: `smoke-frame-region-control` and `smoke-frame-region-wide-control`.

**A frame carries a LENGTH** (**S36**, roadmap 2.1's region object). `SYS_RETYPE(untyped_slot,
KOBJ_FRAME, count, dest_slot, pages)` (`pages` is the **fifth** argument, in `rdi`, and
`sys_retype_sized()` is the wrapper for it) carves `pages` contiguous pages as **one object**.
`pages == 0` means one page, which is what every retype written before frames had a length
passes, so no existing call site changed. A non-zero length on a class that has no length
(`KOBJ_ENDPOINT`, `KOBJ_NOTIFICATION`, `KOBJ_CNODE`) is **refused**, not ignored: a caller
asking for an 8-page endpoint has a wrong model, and quietly handing it one endpoint leaves that
model uncorrected until it matters. `MAX_FRAME_PAGES` is 64.

`SYS_MAP_FRAME` and `SYS_UNMAP_FRAME` act on the **whole run**, and the symmetry is
load-bearing rather than tidy: the frame collector decides a run is dead by asking every page
whether it is still mapped, and it can rely on the answer being uniform only because these two
are the only operations that move it.

`SYS_MAP_REGION` **refuses a sized frame** (`SYS_ERR_INVAL`). A run of slots maps each slot at
the next page, so a sized frame in the middle would make the address of every later slot depend
on the length of every earlier capability: an ABI where you cannot say where slot 5 landed
without reading slots 0..4. Map a sized frame whole with `SYS_MAP_FRAME`; use `SYS_MAP_REGION`
for a run of one-page capabilities.

Both calls bound the **span** including its last byte. With a length, "the address is in the
user half" stops being the same question as "the mapping is": a run starting one page below the
limit walks past it. `user_pte_slot` refuses `pml4[256..511]` independently, so this is the
second of two checks; it earns its place by turning a part-way failure into one refusal before
anything is installed.

The 64-page ceiling is the **arena's**, not the record's. The unwind needs no per-page state for
a sized frame (the run is contiguous, so page *k* is `base + k`) and `UNTYPED_ARENA_BYTES` is 4
MiB *total*, shared with every cspace, endpoint and notification. A frame that could span the
arena would be a denial-of-service against every other object class dressed as a feature.

**`SYS_FRAME_PAGES` is how a holder learns that length** (**S37**). It takes a **cspace slot**,
resolves it through `cap_lookup`, type-tests it, and returns the count as a scalar: no buffer,
so no pointer to truncate. It takes no rights floor: the size is not the contents, and requiring
`READ` would refuse a `WRITE`-only sharer the ability to learn how much it may write.

**It takes a slot and never a frame index**, and that is the security property rather than a
calling convention. An index argument would be **[C-1]**'s shape (authority read from somewhere
other than the capability naming the resource) and would additionally turn the call into an
**object-existence oracle**: a task holding no frame capability at all could walk indices and
learn which frames are live, and how large, across every task in the system.
`FRAME_INFO_BY_INDEX=1` is that kernel, and `framepeer` catches it by asking about slots it
holds nothing in.

It is **not** "a syscall that reads a capability", which `userspace/framepeer.c` argues against
and is right to. It reports the *object's* extent and says nothing about the capability (not its
rights, not its lineage, not its badge) so a holder still cannot discover what authority it has
without exercising it. And it discloses nothing `SYS_MAP_FRAME` already withholds from the same
holder: mapping and probing forward yields the same number, more expensively.

**`SYS_CAP_MINT` is the only rights-reducing operation ring 3 has.** `SYS_CAP_GRANT` copies the
source's rights whole (it passes `CAP_RIGHT_ALL` and `cap_grant_into` masks to the source), so
sharing a page read-only is mint-then-grant: narrow a copy in your own cspace, then delegate the
narrowed slot. Syscall 4 is not new (it has been in the dispatch table since the beginning as an
unnamed numeric entry) but roadmap 2.1 is the first time anything in ring 3 could call it, so it
was unnameable from `include/syscall.h` until then.

 ### `SYS_FORK` (101), roadmap 2.3

`SYS_FORK()` duplicates the caller into a new task and returns the child's tid to the parent
and **0 to the child**, from the same instruction. The child's address space is a
**copy-on-write clone** of the caller's (**S39**), and the call is **refused** while the caller
has a `CAP_FRAME` mapped (**S40**).

**It is gated on the same capability as `SYS_SPAWN`, and that is the ABI decision worth
stating.** The tempting reading is that fork needs no capability: it names no object, and a task
copying *itself* reaches nothing it could not already reach. Both halves are true and the
conclusion is still wrong, because an ungated `SYS_FORK` would be a **second way to bring a task
into existence** standing beside a gated one. Revoke a task's authority to create tasks and it
would stop spawning but not stop forking, so "this task can create no more tasks" would quietly
stop being true. A new path to an existing capability's effect inherits that capability's gate.

**Since 2026-08-30 that shared capability is `CAP_UNTYPED`, and the gate is real for the first
time** (**S57**, `docs/LIMITATIONS.md` §1.6b). It was cspace **slot 3** with `SC_ANYTYPE` — which
`create_task` fills in every task with `READ|WRITE|EXEC`, so the check could not fail and the
paragraph above described a revocation nobody could perform. A task's cspace is a `KOBJ_CNODE`
and is now carved from the region the caller's `CAP_UNTYPED` names, so the authority to create a
task is the authority to spend kernel memory — which is delegable, revocable, and bounded.

**The child inherits the caller's capabilities as derived copies** (**S41**), in the same slots
and with the same rights. Each copy has its **own serial** and names the caller's capability as
its `badge` (the derivation edge) so the child's authority is a *subtree* of the caller's and
fork adds no new root to the capability graph: revoking a capability here sweeps the child's
copy with it. The caller is also handed a `CAP_TCB` naming the child, so it can `SYS_WAIT` /
`SYS_KILL` it.

**Rights are not narrowed**, unlike the console capability `SYS_SPAWN` masks down to `WRITE`.
The two are handing authority to different things: spawn's child is a *different program* and
the caller is choosing what to give a stranger, while fork's child is the same program at the
same instruction. A silently reduced copy would break `if (fork() == 0) serve();` with nothing
to report it, and the program would have the parent grant the rights back, achieving nothing
except a less legible graph. `rust_cap_grant_into` still intersects with the source's rights, so
a copy can never carry more than the parent held.

**Four things are not inherited, and each would be impersonation rather than delegation.** Slots
0–3 and slot 4 are the child's *own* identity: the caller's slot 0 names the **caller**, so
copying it would mint a `CAP_TCB` over the parent that the parent never held in a delegatable
form; slot 4 is the private reply endpoint `SYS_IPC_CALL` parks on, whose entire value is that
nobody else has it (finding **C-1**). `CAP_REPLY` is skipped **by type** wherever it sits,
because it is one-shot and names a specific in-flight sender: two holders is reply forgery. A
revoked or lookup-invalid source is skipped rather than copied.

**Inherited:** the memory (copy-on-write), uid/gid, the heap bounds, the image window, the
registered signal handler and mask, the FPU register file, and the argument vector. **Not
inherited:** the cspace *object*; the child gets its own `KOBJ_CNODE`, populated with derived
copies as above, never a share of the parent's: the port-I/O grant (`io_allowed`; the TSS I/O
bitmap is per-task by construction), the file master key (it mirrors uid, which *is* inherited,
so leaving it behind fails closed), and every in-flight kernel rendezvous, a blocked endpoint, a
pending reply buffer, a one-shot `CAP_REPLY`, queued signals. A fork mid-IPC would otherwise
produce two tasks waiting on one reply.

**The child is born runnable**, unlike a spawned one. `SYS_SPAWN` suspends its child because a
supervisor's only way to endow one is `spawn → grant → resume`, and publishing it earlier let
it run with a half-populated cspace; fork performs the child's entire endowment inside the
syscall, before the frame is published, so there is no window for a supervisor to lose.

**Errors.** `SYS_ERR_INVAL`: this task cannot be cloned as it stands (today: a mapped
`CAP_FRAME`, or a huge user page, which nothing builds). `SYS_ERR_NOMEM`: no free task slot, or
no physical page for the child's tables.

### `SYS_EXEC_NAMED` (64) / `SYS_EXEC_IMAGE` (71): what an exec does to authority

Both replace the caller's image **in place**, keeping its task id, and on success neither
returns. What they do to the caller's capabilities is **nothing at all**, and that is a stated
property rather than an implementation detail (**S42**).

The execed task holds the same capabilities it held going in, with the same `serial` and the
same `badge`; the same *position in the derivation graph*, not merely the same authority. So a
revocation aimed at whatever those capabilities were derived from still reaches them, and **a
task cannot launder delegated authority into a root of its own by execing**. Combined with
`SYS_FORK`'s derived inheritance (**S41**), `fork(); exec();`; the sequence every shell
performs; yields a task whose authority is still a subtree of its parent's.

The address space, by contrast, is entirely rebuilt: a fresh page directory, a fresh stack,
signal dispositions reset, `spawn_arg`/`argc`/`argv` cleared and any new argv marshalled onto
the new stack. The **previous** address space is reclaimed, which matters when the caller was
itself a fork: it is the only path in the tree that frees a copy-on-write clone while its parent
is still running.

**Neither is capability-gated, and since 2026-08-30 that is a decision rather than an accident.**
They used to carry the same slot-3 `WRITE|EXEC` entry as `SYS_SPAWN`, on the reasoning that
"replacing a task's image is a way of putting a program on a CPU, and a new path to a gated
effect inherits the gate". That reasoning is right about `SYS_FORK`, which *creates* a task, and
wrong here: an exec replaces the **caller's own** image, creates no task, and touches no
capability (**S42** — the execed task keeps its serial, its badge and its place in the derivation
graph). There is nothing to charge and no authority to confer, so the untyped gate that
`SYS_SPAWN` and `SYS_FORK` now carry (**S57**) would be a second vacuous check standing where the
first one stood. They are `SC_NONE` and self-only: `h_exec_named` operates on
`get_current_task()` and can reach no other task.

An image supplied by the caller (`SYS_EXEC_IMAGE`) is validated by the same loader as a named one
(W^X, bounds, fail-closed relocations) because the bytes are untrusted in both cases.

**Errors** (the image is left intact, and the call returns): `SYS_ERR_NOENT` (no embedded binary
by that name. `SYS_ERR_INVAL`) the supplied image failed validation. Past the point of no return
there is no error path: the caller's image is gone.

## IPC arguments are cspace slots, not object indices
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
> other task can name. Fixed 2026-07-27, see **[C-1]** in
> [`history/AUDIT-2026-07.md`](history/AUDIT-2026-07.md).

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
| `SYS_ERR_AGAIN` | Would block: retry (pipes). The IPC calls use `IPC_AGAIN` (`-2`) instead; see [IPC](#ipc) |
| `SYS_ERR_INTR` | Interrupted by a signal |
| `SYS_ERR_IO` | Storage failure |
| `SYS_ERR_PIPE` | No reader on the pipe |

`SYS_SBRK` is the exception: its failure sentinel is `(uint64_t)-1`, the all-ones pointer,
because it returns an *address* and newlib's `_sbrk` compares against `(void *)(intptr_t)-1`.

---

## Process and task control

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 0 | `SYS_YIELD` |, | none (self) |
| 2 | `SYS_EXIT` |, | none (self) |
| 17 | `SYS_WAIT` | `tid` | none (self) |
| 18 | `SYS_GET_TASK_INFO` | `tid`, `struct task_info *` | self; or `CAP_USER` / `CAP_AUDIT` |
| 19 | `SYS_EXEC` | `load_base`, `entry` | **retired 2026-09-03** (**S79**); compiles only under `LEGACY_SYSCALLS_PRESENT=1` |
| 20 | `SYS_GETPID` |, | none (self-authorising) |
| 28 | `SYS_SPAWN` |, | `CAP_UNTYPED` at `CAPSLOT_UNTYPED`: WRITE (**S57**) |
| 63 | `SYS_KILL` | `tid` | `CAP_TCB` for target, or `CAP_USER` |
| 64 | `SYS_EXEC_NAMED` | `name` | none (self): replaces the caller's own image, creates no task |
| 68 | `SYS_SPAWN_ARG` |, | none (self) |
| 69 | `SYS_GET_ARGV` | `char ***out` | none (self) |
| 70 | `SYS_SPAWN_IMAGE` | `image`, `len`, `arg`, `argv`, `argc` | `CAP_UNTYPED` at `CAPSLOT_UNTYPED`: WRITE (**S57**) |
| 71 | `SYS_EXEC_IMAGE` | `image`, `len`, `0`, `argv`, `argc` | none (self), as `SYS_EXEC_NAMED` |
| 27 | `SYS_RECEIVE_PROGRAM` | `struct program_header *` | **retired 2026-09-03** (**S79**); compiles only under `LEGACY_SYSCALLS_PRESENT=1` |

**19 and 27 are retired, and the numbers are reserved** (**S79**,
`docs/LIMITATIONS.md` §1.6c). Both read `{ handler, 3, WRITE|EXEC, SC_ANYTYPE }` in the ship
table -- cspace slot 3 being the `CAP_FRAME` `create_task` installs in every task, so the row
authorised every ring-3 caller. Neither had a caller: `SYS_EXEC` dropped the caller to ring 3 at
`load_base + entry` with nothing validated and is superseded by `SYS_EXEC_NAMED` /
`SYS_EXEC_IMAGE`, and `SYS_RECEIVE_PROGRAM`'s transport was a second serial port no target in
this tree attaches. Their wrappers (`sys_exec`, `sys_receive_program`) are removed too, because
a wrapper is the ring-3-facing half of a syscall. Absent rows fail closed at `SYS_ERR_NOSYS`,
which `make smoke-passwd-probe` requires from an ordinary uid-1000 task, and
`tools/check_dispatch_gates.py` fails the build if a slot-3 row returns.

`SYS_GET_TASK_INFO` reports `cr3` as 0 deliberately (disclosing the page-table physical base
would reveal the physical memory layout) and since **[I-4]** reports `eip` only for the calling
task, zeroed for any other, so it cannot be used to defeat another task's ASLR. Being uid 0 is
no longer sufficient for cross-task introspection; a `CAP_USER` or `CAP_AUDIT` is required
(**[I-1]**).

`SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE` are the `execve`-from-memory path. The image is validated
by the Rust ELF loader exactly like a named binary.

**Every one of these consumes the same process-wide staging, and since 2026-08-18 it has an
owner.** Arming an image records the arming task, and a spawn or exec refuses to consume an
image armed by any other, fail closed, including on an image with no recorded owner. This is
invisible to a caller that arms and spawns in the usual way (both halves are the same task) and
matters to the two paths where they can differ: `SYS_SPAWN` with a null name, which spawns
whatever is already armed, and `SYS_SUDO`. Finding **[G-11]**, property **S21**; the arm →
consume window is also serialised, so two CPUs cannot interleave through the staging buffer.

## Signals

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 54 | `SYS_SIGACTION` | `handler` | self only |
| 55 | `SYS_SIGRETURN` |, | inside a handler only |
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
Both currently perform 32-bit arithmetic on 64-bit heap bounds, finding **[I-2]**.

## Pointer arguments

**Every pointer argument is passed full-width.** The argument registers are 64-bit (`syscall()`
in `include/syscall.h` takes `uint64_t`), so narrowing a pointer on the way in is pure loss, and
silent, because the low 32 bits of a valid address are usually themselves a valid-looking
address.

`sys_dmesg()` and `sys_audit_digest()` narrowed theirs to `uint32_t` until 2026-08-20 (issue
#176), so the kernel was handed the low 32 bits of a buffer the caller never named and resolved
*that* in the caller's own address space. It was invisible because `USER_IMAGE_ASLR_BASE` is 16
GiB: every static and global in a PIE image is above 4 GiB and was always truncated, while a
stack buffer sits near 8 MiB and never was, and every caller in the tree passed a stack buffer.

Wrappers now pass pointers through `SYSCALL_UPTR()`, and `tools/check_syscall_abi.py` (the
required `syscall-abi` job) fails the build if any wrapper narrows one. Property **S24**.

## Time (roadmap 2.2)

| # | Name | Arguments | Authorisation *(as checked)* |
|---|---|---|---|
| 98 | `SYS_CLOCK_GETTIME` | `clock_id`, `struct horus_timespec *` | none (ambient) |

Monotonic time since boot. `HORUS_CLOCK_MONOTONIC` (1) is the only accepted id; anything else is
`SYS_ERR_INVAL`. There is no wall clock in this system (nothing reads an RTC and nothing attests
one) so `CLOCK_REALTIME` is refused rather than answered with uptime.

**Resolution is 10 ms, and that is the security-relevant part.** `CR4.TSD` denies ring 3 RDTSC
to remove the cycle-accurate timer cache and covert-channel attacks lean on
(`src/kernel/crypto.c`); a nanosecond clock behind a syscall hands it back. So the value comes
from the PIT tick counter at `PIT_TICK_HZ`, and `nsec` is always a multiple of 10,000,000. Not a
claim of side-channel safety (a counting loop still builds a finer timer) only a refusal to
supply one.

**Ambient on purpose.** A coarse count of time since boot is not authority over an object, and
every task can already approximate it by counting yields; gating it would buy nothing and push
callers toward a worse clock of their own. Same class as `SYS_GETPID`.

Monotonic **by construction**: the source is a counter the timer interrupt only increments,
64-bit since 2026-08-24 because a `uint32_t` at 100 Hz wraps after ~497 days, and a clock that
goes backwards makes every timeout built on it fire early or never.

## Observation (roadmap 3.6)

| # | Name | Arguments | Authorisation *(as checked)* |
|---|---|---|---|
| 97 | `SYS_CAP_ENUMERATE` | `tid`, `slot`, `struct cap_info *` | `CAP_DEBUG` at `CAPSLOT_DEBUG` (19), READ |

Reads one slot of one task's cspace: type, rights, serial, badge, generation, and whether the
slot is occupied. The shell's `capview` walks it and prints the capability graph.

**`object` is deliberately not reported.** For most types it is an index into a kernel table (a
frame-table index since **[F-2.1]**, an endpoint index, a task id) but "most" is not a security
argument, and the legacy `CAP_FRAME` in slot 3 still carries `USER_AREA_BASE`, an address.
Withholding it costs the graph nothing that matters: `serial` and `badge` **are** the edges, so
derivation is fully visible without naming what each node points at. Same reasoning suppresses
`cr3` and another task's `eip` (finding **[I-4]**).

**A dead task reports every slot empty rather than an error**, so a caller cannot use this as a
task-existence oracle it was not otherwise granted.

`CAP_DEBUG` is minted **READ-only** in the root cnode. Rights only ever narrow, so no delegate
can hold a `CAP_DEBUG` that writes, observation is not control.

## Console and basic I/O

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 3 | `SYS_GET_LINE` | `buf` | `CAP_CONSOLE` at `CAPSLOT_CONSOLE` + READ, **type-tested in the handler**; no fallback |
| 7 | `SYS_DEBUG_EXEC` | `cmd` | none (`SC_NONE`); **`DEBUG_SHELL` builds only**; absent from the ship kernel since 2026-08-23 |
| 11 | `SYS_WRITE` | `fd`, `buf`, `len` | console: none (fd 1 = ambient). `klog`: `CAP_KERNEL_LOG` + WRITE |
| 12 | `SYS_READ` | `fd`, `buf`, `len` | fd 0 ambient; **fd ≥ 3 retired 2026-08-22** (**[H-3]**); that branch compiles only under `RAMFS_SLOT3_GATE=1` |
| 13 | `SYS_OPEN` | `name`, `flags` | slot 3: READ; **absent from the ship kernel since 2026-08-22** (**[H-3]**); the dispatch entry compiles only under `RAMFS_SLOT3_GATE=1` |
| 82 | `SYS_CONSOLE_OWNED` |, | none (read-only status) |
| 88 | `SYS_DMESG` | `buf`, `offset`, `max` | `CAP_KERNEL_LOG` at `CAPSLOT_KERNEL_LOG` |

`SYS_GET_LINE` and the fd-0 path of `SYS_READ` **fail closed while a ring-3 console server
owns the UART** (`console_hw_owned()`). A kernel-side read would race the owner and steal
bytes from a typed line, so clients must route input through the server. The in-kernel path
exists only for before handoff and after the owner dies.

**That guard is not the authority check, and until 2026-08-24 nothing else was** (finding
**[H-3]**'s sixth door, property **S28**). `SYS_GET_LINE`'s dispatch entry declares `SC_NONE`,
so its handler is the only gate: and that gate read `cap_lookup(8, READ)` with a fallback to
`cap_lookup(3, READ)`, **neither of them type-tested**. Slot 3 holds the legacy `CAP_FRAME`
every task is born with, so the fallback was satisfied by a capability that confers no console
authority at all, on the syscall that returns *what the user is typing*, including at a login
prompt. It survived because `console_hw_owned()` refuses first in any live boot, which is a
circumstance (the server happens to be alive), not a gate. The row above is now the whole
answer: `CAP_CONSOLE`, type-tested, no fallback. `console_hw_owned()` is unchanged and stays
where it is, "do not race the owner" was never an answer to "may I read the console".

**`SYS_WRITE` fd 1 has two destinations and they are gated differently** (finding **[H-2]**,
fixed 2026-08-20). The bytes always reach the console: a terminal write is not an authority this
system rations, and that entry stays ambient on purpose. They reach the kernel message ring only
if the calling task holds `CAP_KERNEL_LOG` with `CAP_RIGHT_WRITE`, checked by `cap_lookup` in
`h_write` and passed to `print_from_user`. Until that split existed, the *read* side of the ring
required a capability (`SYS_DMESG`, below) while the *write* side required nothing, so any task
could forge `dmesg` lines and flood the 16 KiB ring to evict real ones. No task holds that write
right today (`root_cnode[15]` mints the capability READ-only and delegation may only narrow) so
the append is currently unreachable from ring 3 by construction rather than by policy.

`SYS_DMESG` requires a `CAP_KERNEL_LOG` capability, which `init` delegates to the shell (finding
**[I-1]**; it was previously an ambient `uid == 0` check). The kernel log discloses addresses
and boot detail, so the shell additionally restricts the `dmesg` *command* to root, capabilities
are per-task and the shell serves successive logins, so only the session manager can express a
per-user policy. It is read in small chunks (offset + max), so no shared kernel buffer is
exposed.

## Capabilities

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 4 | *cap mint* | `dest_slot`, `src_slot`, `rights` | `CAP_RIGHT_MINT` on source |
| 8 | *cap transfer* | `dest_slot`, `src_slot` | `CAP_RIGHT_MINT` on source |
| 9 | *cap move* | `dest_slot`, `src_slot` | transfer + revoke |
| 51 | `SYS_CAP_REVOKE` | `slot` | `CAP_RIGHT_REVOKE` on target |
| 65 | `SYS_CAP_GRANT` | `target_tid`, `src_slot`, `dest_slot` | `CAP_TCB` for target, or `CAP_USER` |

Mint and grant mask rights to `new_rights & src->rights`; **delegation can only ever reduce
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

Both are capability-**addressed** like the IPC calls: the slot argument *is* the gate, and both
are `SC_NONE` in the dispatch table. A fixed table slot would repeat finding **[C-1]**, gating
on a capability every task happens to hold while never consulting the one that names the
resource.

`kobj_type` is `KOBJ_ENDPOINT` (2), `KOBJ_NOTIFICATION` (3) or `KOBJ_FRAME` (4). `KOBJ_CNODE`
(1) is allocatable by the kernel but **refused to ring 3**: no capability type names a CNode
and no syscall installs one as a task's cspace, so minting one would be authority with no
defined meaning.

`KOBJ_FRAME` is one `PAGE_SIZE` page, aligned to a page rather than to `KOBJ_ALIGN` because it
is installed in a PTE. Its capability is a `CAP_FRAME`, and see "Frame capabilities" below for
what one names and why it is not a physical address.

`SYS_RETYPE` returns the number of objects created (which may be fewer than `count` if the
region runs out) or a negative error. It refuses outright, without consuming any of the region,
on: a destination below `KERNEL_RESERVED_CAPS` (`SYS_ERR_PERM`), a run that would overrun the
cspace (`SYS_ERR_RANGE`), and an unknown type or zero count (`SYS_ERR_INVAL`). A refusal that
spent budget would be a denial-of-service primitive against the caller's own region, so
`captest` asserts the watermark is unchanged after every refused call.

Each new object's capability carries READ|WRITE|GRANT|MINT|REVOKE; the creator is its only
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

`SYS_IPC_REPLY_TO` requires **READ**, not WRITE: it writes directly into the recorded sender's
blocked reply buffer, so only the task that legitimately *receives* requests on the endpoint may
answer them. Requiring WRITE would let any client (every client holds WRITE in order to send)
impersonate the server to another client.

`SYS_IPC_CALL`'s second argument is vestigial and ignored; the reply always lands on the
caller's own private reply endpoint. Pass 0.

`SEND` and `RECV` are **non-blocking**: they return `-2` when the endpoint's bounded FIFO is
genuinely full (`SEND`, `count == EP_QUEUE_SLOTS`) or empty (`RECV`, `count == 0`), and the
caller polls from ring 3 where timer preemption guarantees progress. Spinning in-kernel would
not, since the kernel is not preemptible.

`SYS_IPC_RECV_BLOCK` is the **blocking** receive, and it is what a server should use. Same
capability and same right as `SYS_IPC_RECV` (`CAP_ENDPOINT` with **READ**) and the same
completion, including minting the one-shot `CAP_REPLY` for the message it hands back; the only
difference is that an empty queue sleeps the caller instead of answering `-2`. It therefore
**never returns `IPC_AGAIN`**, so a negative return from it is permanent and must not be retried
in a loop (see the retry contract below).

Two things about it are worth stating because they are where a blocking receive usually goes
wrong. The wait is published only *after* the trap frame is saved; the same ordering
`SYS_IPC_CALL` uses, so a sender on another CPU cannot patch a stale frame. And the wake is
performed by the *sender's* syscall, in the sender's address space and cspace, so the reply
right has to be minted into a cspace that is not the current one; getting that wrong would hand
a woken server a request it holds no authority to answer. `make smoke-recvblock` asserts exactly
that, and fails if the mint is removed.

A task blocked in `SYS_IPC_RECV_BLOCK` is waiting for a **request**, not a reply, so
`SYS_IPC_REPLY_TO` refuses to deliver into it: a reply capability naming a task that has moved
on to receiving is stale by construction, and delivering would inject a message past the
endpoint queue.

**`-2` is the only retryable IPC code.** It is `IPC_AGAIN` in
[`include/syscall.h`](../include/syscall.h), tested by `ipc_transient(rc)`, and it is a raw
literal, *not* `SYS_ERR_AGAIN` (`-11`), which the IPC syscalls never return. Every other
negative is **permanent**, `SYS_ERR_PERM` (`-1`) above all: it means "you hold no capability for
this endpoint", which will be just as true on the millionth attempt as on the first. A `while
(sys_ipc_call(...) < 0) spin_delay();` loop therefore retries an authorisation failure forever,
which is a security bug and not merely a robustness one: fail-closed has to mean stop, loudly,
at the point authority was refused, or the one event the capability system exists to make
visible becomes indistinguishable from a hang. Retry on `ipc_transient()` only, and bound even
that.

`SYS_IPC_CALL` blocks. It deposits the message and records a *pending* block; the waiter is
published only after the trap frame is saved, so a cross-CPU reply can never patch a stale
frame.

`SYS_IPC_SENDER` is the **zero-trust identity anchor**: it returns `tasks[last_sender].uid`:
established only by a successful `SYS_AUTH` and recorded by the kernel when the message was
sent, *not* anything the client placed in the message. `fs_server` authorises every request
against it.

`SYS_IPC_REPLY_TO` routes the reply to the client named by the one-shot `CAP_REPLY` that
`SYS_IPC_RECV` minted for the dequeued message: not through a shared reply endpoint, and no
longer through the endpoint's mutable `last_sender`, which the next receive overwrites. The
capability names one blocked caller, cannot be retargeted, and is consumed by the reply, so a
server cannot reply twice to one request or reply to a client it never received from: both are
unrepresentable rather than merely refused. That is what makes one server safe for concurrent
clients. It may return `-2` under SMP if the sender has deposited its request but not yet
published its block; the server retries, and the reply right is deliberately *not* consumed on
that path.

## Pipes

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 83 | `SYS_PIPE` |: → `(read_slot<<16)\|write_slot` | none (own cspace) |
| 84 | `SYS_PIPE_READ` | `slot`, `buf`, `len` | `CAP_PIPE` READ at `slot` |
| 85 | `SYS_PIPE_WRITE` | `slot`, `buf`, `len` | `CAP_PIPE` WRITE at `slot` |
| 86 | `SYS_PIPE_CLOSE` | `slot` | `CAP_PIPE` at `slot` |
| 87 | `SYS_STDIO_INFO` |, | none (own tcb) |

Pipes *are* properly capability-addressed: the slot argument is a cspace slot resolved through
`cap_lookup` with the direction's right. They are the model the IPC syscalls should follow.

`SYS_PIPE_READ` returns 0 at EOF and `SYS_ERR_AGAIN` when empty with writers still open;
`SYS_PIPE_WRITE` returns `SYS_ERR_AGAIN` when full and `SYS_ERR_PIPE` when there is no reader.
`task_teardown` releases a dying task's ends so a pipeline stage cannot wedge its peer.

## Users and authentication

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 29 | `SYS_GETUID` |, | none (self) |
| 30 | `SYS_AUTH` | `user`, `pass` | none (self-authorising) |
| 31 | `SYS_SUDO` | `pass` | re-authentication in handler **and** the armed image must be one this task armed (**S21**) |
| 32 | `SYS_GET_PASS` | `buf` | none |
| 33 | `SYS_USERADD` | `user`, `pass` | `CAP_USER` at `CAPSLOT_USER` |
| 34 | `SYS_USERDEL` | `user` | `CAP_USER` at `CAPSLOT_USER` |
| 35 | `SYS_PASSWD` | `user`, `pass` | `CAP_USER`, or the target is the caller's own uid |
| 112 | `SYS_USERLIST` | `index`, `struct user_entry *` | `CAP_USER` at `CAPSLOT_USER` |

`SYS_PASSWD` **also grants the target a volume key slot** when an administrator sets *another*
account's password, and records its index in that account's record (**S76**). Without one the
password opens the account and not the volume, and the account cannot be the first login after a
power cycle -- see `SECURITY.md` **S61** for what a key slot is and `docs/LIMITATIONS.md` 2.6b for
what its absence cost. It **fails closed**: the slot is taken before the hash changes, so a volume
with no free slot leaves the old password working and returns an error rather than setting a
password that cannot open the machine. Changing your **own** password re-seals the slot you
already hold instead, and a machine with no persistent volume grants nothing.

`SYS_USERLIST` reads one account's **public metadata** -- name, uid, gid, home -- and nothing
else: no hash, no salt, no key slot, no lockout state. It returns 1 when the buffer was filled,
**0 when `index` is past the last account**, and `SYS_ERR_PERM` without the capability; the
buffer is written only on 1, so a refusal and an empty index are not distinguishable by
inspecting it. The index is **dense over valid accounts** rather than an array position, because
the table is sparse -- `SYS_USERDEL` clears a slot and leaves it -- so array positions would
export `MAX_USERS` across the boundary and make a hole in the middle read as the end. A caller
loops from 0 until it gets 0. The one caller today is `fs_server`, which uses it to give every
account a home directory it owns (**S78**); it already holds `CAP_USER` as the
`SYS_REGISTER_FS_SERVER` gate, so nothing was granted to make this work.

These four are `SC_NONE` in the dispatch table, so `current_user_is_admin()` in
`src/kernel/kusers.c` *is* the gate. Until 2026-08-15 it accepted `uid == 0` as an alternative
to holding the capability: the last surviving ambient gate from **[I-1]**, which roadmap 0.2's
sweep of `syscall.c` never reached (finding **[H-1]**). "Admin" here now means possession of
`CAP_USER`, and nothing else; a task at uid 0 with an empty cspace is refused. Witnessed by
`make smoke-captest` (which runs as uid 0 and holds no `CAP_USER`) and by `make smoke-session`,
which asserts both directions through the real ring-3 shell.

`SYS_SUDO` spawns the currently-armed program image as uid 0, and the arm is a *different
syscall* from the consume. Until 2026-08-18 nothing tied the two together, so a task that
authenticated correctly could elevate a program **another** task had armed: a confused deputy in
which neither party fails a rights check and the authority comes from the pairing (finding
**[G-11]**, adversary **A1c**). The handler now refuses unless the armed image belongs to the
caller, and audits that refusal rather than logging a failure: a correct password that was about
to elevate somebody else's program is the event worth recording.

Passwords are Argon2-hashed. Failed authentication is rate-limited per task
(`auth_fail_count`, `auth_lockout_until`).

## Object store: `fs_server` only

Gated on a `CAP_ENCRYPTED_STORAGE` capability at `CAPSLOT_AUDIT`, required **by type**. The
ambient `uid == 0` check that used to accompany it is gone (**[I-1]**), and the type is now
actually enforced: these entries previously passed the type constant in the *rights* field with
`ctype = SC_ANYTYPE`, so any capability with `READ|WRITE|GRANT` passed (**[I-1a]**). The AEAD
stays entirely in the kernel; the server addresses storage as `(inode, logical block)` and never
sees key material.

| # | Name | Arguments |
|---|---|---|
| 46 | `SYS_REGISTER_STORAGE_BACKEND` |, |
| 47 / 48 | `SYS_BLOCK_READ` / `SYS_BLOCK_WRITE` | raw block I/O |
| 56 / 57 | `SYS_FS_INODE_ALLOC` / `_FREE` | `type` → `ino` / `ino` |
| 76 | `SYS_FS_INODE_LINK` | `ino` (increment link count) |
| 58 / 59 | `SYS_FBLOCK_READ` / `_WRITE` | `(ino, block, buf[, len])`, decrypt+verify / encrypt with fresh nonce |
| 60 | `SYS_FS_STAT` | `ino`, `struct fs_stat *` |
| 61 | `SYS_FS_SET_SIZE` | `ino`, `size` |
| 74 | `SYS_FS_SET_META` | `ino`, `mode`, `uid`, `gid` |
| 77 | `SYS_BOOT_MODULE_INFO` | `index`, `struct boot_module_info *` → count *(needs `CAP_BOOT_MODULE`)* |
| 78 | `SYS_BOOT_MODULE_READ` | `index`, `offset`, `buf`, `len` *(needs `CAP_BOOT_MODULE`)* |

**Every one of the eight object-store calls above requires the volume to be UNLOCKED, not
merely mounted** (**S74**). A sealed ATA volume is mounted and locked from power-on until a
login opens a key slot, and in that window all eight return `SYS_ERR_INVAL` -- the same code as
an unmounted store, because both mean "there is no open store to act on", a statement about the
volume rather than about the caller whose authority the dispatch table has already settled.
Until 2026-09-01 they tested `mounted` alone: the AEAD enforced the rule for `SYS_FBLOCK_READ` /
`_WRITE` as a side effect of needing the key, and the inode table is plaintext on disk, so the
six metadata calls enforced nothing and a sealed volume served real inode records and accepted
edits to its own inode table. The check is now in one place, `store_open()` in
`src/kernel/syscall_fs.c`. **`SYS_BLOCK_READ` / `SYS_BLOCK_WRITE` are deliberately outside this
rule**: they sit below the volume abstraction and move ciphertext, which is what the journal and
crash gates need of them.

`SYS_BOOT_MODULE_READ` **refuses any module that failed its manifest hash check**. Since
provisioning into `/bin` goes through this path, an unverified module can never become a
root-owned executable. `SYS_BOOT_MODULE_INFO` reports such a module as an empty slot, keeping
module numbering stable.

## Installing: destroying a volume and laying a new one down (roadmap 2.9)

Gated on `CAP_STORAGE_FORMAT` at `CAPSLOT_STORAGE_FORMAT` (23), required **by type**
(`SECURITY.md` **S72**). That is a capability of its own and **not** the
`CAP_ENCRYPTED_STORAGE` the section above describes: `fs_server` and the shell both hold that
one, and gating a format on it would mean the filesystem server may erase the filesystem and a
login shell may erase the volume it just opened. `init` is endowed with `CAP_STORAGE_FORMAT`
from the primordial root cnode and grants it to the installer alone.

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 110 | `SYS_STORAGE_INFO` | `struct storage_info *` | `CAP_STORAGE_FORMAT` at `CAPSLOT_STORAGE_FORMAT`: READ |
| 111 | `SYS_STORAGE_FORMAT` | `password`, `plen` | `CAP_STORAGE_FORMAT` at `CAPSLOT_STORAGE_FORMAT`: WRITE |

The rights differ on purpose. READ is the survey an installer shows before it asks; WRITE is
the destruction. A build that wanted a read-only survey tool can be handed a `READ`-only mint,
and the primordial carries `READ|WRITE` and **not** `CAP_RIGHT_ALL` -- rights only narrow on
delegation, so no descendant of it can grant or mint.

`struct storage_info` reports whether a **persistent** block device is attached, its size in
blocks, whether a Horus volume was recognised on it, whether that volume is unlocked, and
whether **this kernel would format an unrecognised volume at the login prompt**
(`format_on_login`, 1 only under the `STORAGE_AUTOFORMAT` control arm). That last field exists
because `init` uses this survey to decide whether to launch an installer, and a kernel that
formats at login by itself is a machine with nothing for an installer to do — without it, the
dozen test targets that boot a deliberately blank image would each launch an installer that
waits forever for a keystroke nobody is there to type. It
deliberately reports nothing about the volume's contents: it exists so an installer can tell an
operator what is about to be destroyed, and every field is a disclosure made under this
capability. The ephemeral RAM vdisk answers `present = 0` -- it is a block device by every
internal measure, and reporting it would have an installer offering to format memory.

`SYS_STORAGE_FORMAT` is the **one** caller of `storage_authorize_format()`, the function
**S63** introduced with the comment "which an installer calls and a login never does" and which
had no caller at all until 2026-09-01. A login (`SYS_AUTH` -> `storage_unlock`) still meets an
unformatted volume and still refuses it.

`plen` is bounded at `STORAGE_FORMAT_PASSWORD_MAX` (31) and an over-long password is
**refused, not truncated**. That bound is a round-trip property rather than a buffer size: a
login copies 31 bytes of what was typed and offers exactly those to `storage_unlock`, so a
volume sealed to more could never be opened by the operator who chose the password, and an
installer that silently shortened one would seal the volume to a string nobody picked. An empty
password is refused for the same reason it would be at a login prompt.

## Filesystem server registration

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 49 | `SYS_REGISTER_FS_SERVER` | `ep_slot` | slot 6: `CAP_USER` (ALL) |
| 50 | `SYS_CONNECT_FS_SERVER` | `dest_slot`, `rights` | none, any task may connect |

Connecting grants no file access on its own: the server is a reference monitor that authorises
every request by kernel-attested identity. `SYS_CONNECT_FS_SERVER` mints the endpoint
capability through the locked, accounted `cap_install_endpoint` path (rights masked to
READ\|WRITE\|GRANT), not a raw cspace store.

These two are the only places `CAP_ENDPOINT->object` is currently consulted.

## Device delegation

Each of these takes a **cspace slot** holding a `CAP_IO_DEVICE` as its first argument, and the
authority is that capability's `object`: an index into the kernel's I/O-device table
(`src/kernel/pci.c`), built once at boot from a PCI bus scan plus one non-enumerable
**platform** entry for the legacy console hardware. The resource the caller asks for is
checked against what **that** device declares. `SECURITY.md` **S43**.

| # | Name | Arguments |
|---|---|---|
| 79 | `SYS_MAP_PHYS` | `dev_slot`, `paddr`, `vaddr`, `len`, `flags`, map one 4 KiB frame **the named device declares** (needs WRITE) |
| 80 | `SYS_IOPORT_GRANT` | `dev_slot`, grant native ring-3 `in`/`out` on **the named device's** port ranges via the TSS I/O bitmap (needs WRITE) |
| 81 | `SYS_IRQ_REGISTER` | `dev_slot`, `irq`, `notif_slot`, `badge`, route an IRQ **the named device declares** to the notification named by the `CAP_NOTIFICATION` at `notif_slot` (both need WRITE) |
| 102 | `SYS_DEVICE_INFO` | `dev_slot`, `struct dev_info *`, report the named device's ids, MMIO ranges, port ranges and IRQ lines (needs READ) |
| 103 | `SYS_DEVICE_ENABLE` | `dev_slot`, `flags`, set the named device's three PCI decode bits (I/O, memory, **bus master**) to exactly `flags`, and nothing else in configuration space (needs WRITE) |
| 107 | `SYS_MSI_REGISTER` | `dev_slot`, `notif_slot`, `badge`, route the named device's message-signalled interrupt to a notification. **No vector argument**, deliberately (WRITE on both) |
| 108 | `SYS_SHLIB_INFO` | `frame_slot`, `struct shlib_info *`: where the shared library is loaded **this boot**. The base is drawn from the ASLR source, not compiled in, so a program cannot assume it. Requires a `CAP_FRAME` + READ naming one of the library's own **text** frames: the base is the address of code every task executes, and a task's private copy of the library's data page does not qualify |
| 106 | `SYS_POLL_NOTIFY` | `notif_slot`, `uint32_t *`, consume a pending badge, or report `IPC_AGAIN` if none. `sys_wait_notify`'s non-blocking twin; same `CAP_NOTIFICATION` + READ gate |
| 104 | `SYS_DMA_ADDR` | `dev_slot`, `frame_slot`, `uint64_t *`, `flags`: map that frame into that device's address space and report the address it reaches it at (needs **both**: CAP_IO_DEVICE WRITE and CAP_FRAME READ) |

None of the four has a dispatch-table slot: they are `SC_NONE`, and **that is the gate**, in
exactly the sense the IPC syscalls are. Until 2026-08-28 each had a fixed slot-10
`CAP_IO_DEVICE` entry and the resources came from constants, a compiled-in VGA allowlist, one
compiled-in console port set prefilled into the TSS bitmap at boot, a hardcoded pair of IRQ
numbers. The capability's `object` was never read, so holding the *type* was holding the
console: finding **[C-1]**'s shape one layer down, and it takes [C-1]'s fix.

`SYS_DEVICE_INFO` is READ where the other three are WRITE, and reports only the device the
capability names. A driver needs it because firmware assigns BARs and a hardcoded address is
how a driver ends up mapping whatever happens to sit there; there is deliberately no bus walk,
because holding one device should not be a way to enumerate the machine.

`SYS_DEVICE_ENABLE` is the only write to configuration space reachable from ring 3, and it
reaches exactly three bits of one register. The narrowness is load-bearing: the BARs live in the
same 256 bytes, and a driver that could move its own BAR could point it at another device's
registers and make the frame check above a lie. Unknown bits are **refused**, not masked (a
caller must not be told yes and given something else) and a platform device, which has no
configuration space, is refused outright rather than reported as configured.

`SYS_DMA_ADDR` **installs the mapping** as well as reporting the address, where there is an
IOMMU (**S45**): a device's address space starts empty, so this call is what grants the reach
rather than merely describing it, and the mapping carries the frame capability's own write
right. It takes an optional flags word; `DMA_ADDR_NO_MAP` reports without mapping and exists for
the control arm.

`SYS_DMA_ADDR` requires **two** capabilities, which is the interesting part of its design. The
answer is a physical address, disclosed nowhere else in this ABI; gating it on the frame alone
would hand the kernel's memory layout to every task that ever retyped a page, for no purpose any
of them could act on. Requiring a device capability is what makes the disclosure land only on a
caller who has a use for it.

The original argument was stronger and is now **wrong**: it read that the disclosure adds nothing
because a holder of a bus-mastering device can already read and write all of physical memory
through it, IOMMU-less. That stopped being true on 2026-08-28, when VT-d gave every device an
address space of its own that starts empty (**S45**), and it is recorded here rather than quietly
replaced because it was a security rationale and it should be visible that it was retired rather
than forgotten. On a machine with no DMAR the old sentence still describes the situation, and
`iommu_active()` is what distinguishes the two.

The name is `dma_addr` rather than `paddr` deliberately: what a device needs is the address *it*
uses. That is the physical address here because the IOVA is chosen equal to it, which is a choice
and not an identity map: one mapping is installed per frame a driver asks for, so the device
reaches those frames and faults on every other address. The signature is already the right shape
for an IOVA that differs. Since 2026-08-29 the mapping this call installs is also removed when the
frame is destroyed (**S53**). `SECURITY.md` **S44**, **S45**, **S53**.

**`SYS_SHLIB_INFO` exists because the library's base is not a constant, and it is gated because
the base is worth protecting.** The shared library is loaded at an address drawn once per boot
from the same CSPRNG-seeded source the image loader uses (S51), so a program cannot hardcode it,
and must not, since the object's relocations were applied against that base and it is only
correct when mapped there.

The answer is not ambient. A caller presents a `CAP_FRAME` over one of the library's own
**text** frames, and the kernel replies only if that capability names a frame the library
actually owns. **`data_first`/`data_pages` are a RANGE, and were a single index until the real
libc was loaded through this call.** newlib's writable segment is two pages; a caller built on
the single-index version asked for EXEC on the second and failed to map it. The demo object
could not have shown that; its whole data segment was one `int`. The range is contiguous because
the loader accepts exactly one writable `PT_LOAD`, which `tools/check_shared_object.py` enforces
at build time.

Two things follow, and both are asserted by `make smoke-shlib`: a capability of the wrong *type*
is refused, and so is a `CAP_FRAME` of the wrong *object*, including the task's own private copy
of the library's writable page, which it legitimately holds and which says nothing about holding
the code. Without that gate an attacker with execution in any task could simply ask where the
shared gadgets are, and randomising the base would protect nothing.

Shared text must be at the same address in every address space (that is what makes it shared) so
per-boot is the strongest randomisation this mechanism admits. One information leak reveals the
library for every task rather than for one; that is weaker than per-process ASLR and far
stronger than an address printed in the binary.

**`SYS_MSI_REGISTER` takes no vector, and that absence is the property.** An MSI is a memory
write whose data word carries the interrupt vector, so a driver able to choose one could point
its device at the timer, at another driver's interrupt, or at an exception gate. The kernel
allocates from a range it owns (48–63) and programs the capability itself; `SYS_DEVICE_INFO`
reports *whether* a device has MSI and never *where* the capability lives, because that offset
names the register carrying the vector. `SECURITY.md` **S47**.

**One page of a device's own MMIO is never mappable: its MSI-X vector table** (**S48**). A table
entry carries the interrupt vector, and unlike MSI's it sits in a BAR rather than in
configuration space, so a driver holding a valid `CAP_IO_DEVICE` is still refused that page,
read-only as well as writable. `SYS_DEVICE_INFO` reports which page it is, because knowing the
address buys nothing against a refusal.

Device index **0 is reserved** and names nothing. Two things default to zero, a task slot's
`io_device` and a capability's `object`, which `cap_install_from_root`'s fourth argument
overrides, and both must fail closed rather than resolve to the console.

The port-I/O grant is revoked in `task_teardown` (`io_device = IODEV_NONE`), because task slots
are reused: otherwise a fresh task could inherit a dead driver's grant. `tss_set_io_device` is
driven from the single `set_current_task` chokepoint and reloads the bitmap from the incoming
task's device, so every other task gets an `iomap_base` past the TSS limit and a ring-3
`in`/`out` faults. A grant is to **one** device: regranting replaces it rather than
accumulating, because the union of two devices' ports is an authority neither capability names.
PCI configuration space (`0xCF8`/`0xCFC`) is declared by no device and reachable by nobody, a
driver that could write it could move any device's BARs and defeat the frame check as well.

## Audit

| # | Name | Arguments | Authorisation |
|---|---|---|---|
| 36 | `SYS_ROTATE_KEYS` |: | slot 8: `CAP_CONSOLE` READ |
| 37 | `SYS_READ_AUDIT` | `buf`, `max` | slot 7: `CAP_AUDIT` READ |
| 52 | `SYS_AUDIT_DIGEST` | `buf` | slot 7: `CAP_AUDIT` READ |

`SYS_READ_AUDIT` writes up to `max` records into `buf`, **oldest first**, and returns how many
it wrote. A record is `struct audit_record` — **160 bytes**, declared in `include/audit_abi.h`,
which the kernel and ring 3 both include and both `_Static_assert` the size of. Nothing else
declares it: the layout is the ABI, so `buf` must be an array of that type and the stride the
kernel writes at is that type's. Until 2026-09-01 it was declared twice under one name, 256
bytes in the kernel and 72 in `include/syscall.h`, and the copy used the kernel's — see
`SECURITY.md` **S71** for what that cost and `include/audit_abi.h` for why the record is a
projection of the kernel's internal event rather than the event itself.

`SYS_AUDIT_DIGEST` writes a fixed **40 bytes** — an 8-byte little-endian total event count then
the 32-byte chain-head MAC — and returns the verify status of the retained window: `0` intact,
a positive value for the first tampered index plus one, `-1` for a chain never initialised.

The audit log is **forward-secure**: the chaining key is ratcheted after each record, so an
attacker who compromises the system cannot forge or alter history written before the
compromise.

## Test-only

| # | Name | Present in |
|---|---|---|
| 53 | `SYS_PREEMPT_TRACE` | `PREEMPT_SELFTEST` builds only: `SYS_ERR_NOSYS` otherwise |

## Reserved

| # | Former name |
|---|---|
| 1 | `SYS_PRINT` (never dispatched) |
| 38–45 | The removed in-memory capfs, permanently reserved, never to be reused |

---

## Adding a syscall

1. Define the number in **both** `include/syscall.h` and `src/include/kernel.h`; they are
   duplicated, and drift between them is a real hazard.
2. Write `h_yourcall(struct interrupt_frame64 *r)` in the appropriate `syscall*.c`.
3. Add the table entry with its authorising slot, rights, and type, or `SC_NONE` plus a
   comment stating where the handler performs its own check.
4. Grow `SYSCALL_TABLE_SIZE`. The `_Static_assert` will tell you if you forgot.
5. Add a userspace wrapper in `include/syscall.h`.
6. **Add a negative test to `userspace/captest.c`** proving the call is refused without its
   capability. This is not optional, see `CONTRIBUTING.md`. Assert the **exact** error code,
   not merely a negative return: `sys_ipc_recv` returns `-2` for an empty queue, so a
   `< 0` check cannot tell a refusal from an empty object and will pass on a broken kernel.
