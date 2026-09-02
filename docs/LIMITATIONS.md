# Horus: Current Limitations

An honest account of what Horus does not do, does not enforce, or does badly, so that nobody
draws an incorrect conclusion about its readiness. This document is deliberately unflattering.

**Where this document and the code disagree, the code is the source of truth: please open an
issue.**

Findings referenced as **[C-n]** / **[I-n]** / **[M-n]** are from
[`AUDIT.md`](AUDIT.md). **[G-n]** are the known architectural gaps in
[`ARCHITECTURE.md`](ARCHITECTURE.md) §14. **[H-n]** are from the independent external audit of
2026-08-15, which supersedes the 2026-07-27 status for several findings; that document is not
in the tree, so the findings it raised are recorded here and in `CHANGES.md`.

---

## 1. Security properties that are claimed elsewhere but not enforced

### 1.1 ~~IPC is not capability-mediated~~ (**FIXED 2026-07-27**) **[C-1]**

**Resolved.** IPC is now capability-addressed: every IPC syscall takes a cspace slot and the
kernel derives the endpoint or notification from the capability there, checking type, right,
and lineage. A task is born with only its own private reply endpoint; everything else arrives
by delegation. Clients receive WRITE-only capabilities, so they can send to a service but
never intercept its traffic or forge its replies. `captest` grew from 29 to 41 checks, twelve
of them asserting these refusals, and the suite was falsified against the pre-fix kernel to
confirm it detects the bug. The original description follows for the record.

Endpoints (`MAX_ENDPOINTS = 64`) and notifications (`MAX_NOTIFICATIONS = 64`) are flat global
arrays addressed by an integer taken directly from a userspace register. The index is
bounds-checked against the array size and nothing else.

The `object` field of `CAP_ENDPOINT` (the field that names *which* endpoint) is read only by
`SYS_REGISTER_FS_SERVER` and `SYS_CONNECT_FS_SERVER`. It is never consulted on an IPC operation.
The dispatch table authorises IPC on cspace slot 3 with `SC_ANYTYPE`, and `create_task` gives
every task a `CAP_FRAME` in slot 3. *(That capability still exists. Since roadmap 2.1 gave
`CAP_FRAME` a meaning it is a live decoy rather than an inert one, and `smoke-frame` asserts on
every boot that it maps nothing, see §2.5 and `SECURITY.md` S26.)*

**Therefore any unprivileged ring-3 program can:**

- `SYS_IPC_RECV(FS_EP_REQ)`, dequeue another user's filesystem request, disclosing paths and
  data being written, and removing the request so the real server never sees it;
- `SYS_IPC_REPLY_TO(FS_EP_REQ, forged)`, have the kernel write a forged reply directly into
  the victim's blocked `SYS_IPC_CALL` buffer and wake it, indistinguishable from a genuine
  server reply. This forges file contents, `stat` results, and permission outcomes, and
  since the shell loads `/bin` binaries through the FS server, it can serve arbitrary bytes
  as the contents of a program another user is about to run;
- the same against `CON_EP_REQ`, intercepting or injecting console traffic including the
  masked-password path;
- `SYS_NOTIFY(any slot)`, forge hardware interrupt delivery to a ring-3 driver (**[C-2]**).

The endpoint indices are compile-time constants in public headers (`FS_EP_REQ = 4`,
`FS_EP_REP = 5`, `CON_EP_REQ = 6`).

**Consequence.** The isolation between userspace servers and their clients is not enforced.
`fs_server`'s POSIX permission model and the `SYS_IPC_SENDER` zero-trust identity anchor are
both correctly implemented and both bypassable, because an attacker impersonates the server
rather than lying to it.

Fixing this is the top roadmap item. Until it lands, **treat Horus as offering no isolation
between mutually distrusting ring-3 programs.**

### 1.2 ~~Root is an ambient authority parallel to capabilities~~ (**FIXED 2026-07-27, completed
2026-08-15**) **[I-1]**, **[H-1]**

**Resolved.** Every `tasks[current].uid != 0` gate is gone, replaced by a held capability:
`CAP_KERNEL_LOG` for `SYS_DMESG`, `CAP_BOOT_MODULE` for the boot-module surface, and
`CAP_ENCRYPTED_STORAGE` (enforced **by type**) for the object-store API. `SYS_GET_TASK_INFO` no
longer promotes uid 0. **The capability graph is now a complete description of kernel
authority**, the precondition for any confinement or MAC story later.

**One gate outlived the fix by nineteen days, and this section asserted otherwise the whole time
(**[H-1]**, fixed 2026-08-15).** Roadmap 0.2 swept `syscall.c` and `syscall_fs.c` for `uid != 0`
gates. It did not reach `src/kernel/kusers.c`, where `current_user_is_admin()` ended `return
tasks[get_current_task()].uid == 0;`: and since `SYS_USERADD`, `SYS_USERDEL` and `SYS_PASSWD`
are `SC_NONE` in the dispatch table, that function *was* the gate. A ring-3 task at uid 0
holding **no capability at all** could create an account with any uid/gid it chose and reset any
other user's password. Because uid is the identity `fs_server` authorises every file operation
against, authority over the account table is authority over the filesystem's entire subject
namespace.

**It was load-bearing, and the gate is what proved it.** The intended reading was that nothing
legitimate depended on the fallback, because `CAP_USER` would already have reached the shell.
It had not: `launch_shell` (`userspace/init.c`) delegated console, storage, the console client
endpoint, `CAP_KERNEL_LOG` and `CAP_AUDIT`, and **not** `CAP_USER`. So the shell's `useradd`
had been working on the ambient gate alone, and deleting it turned `smoke-session` red at
`[ok] useradd allowed for root`. That is the finding's own proof: an authority nothing held a
capability for was being exercised daily.

The fix is therefore two-sided, and copies the split `CAP_KERNEL_LOG` already uses. `init`
delegates `CAP_USER` to the shell, and the **shell** refuses `useradd`/`userdel` to a non-root
session itself. The kernel asks whether the task holds the authority; the session manager asks
whether this user may exercise it. Granting without the second half would hand account creation
to every logged-in user, strictly weaker than the `uid == 0` gate being removed, which is the
exact mistake `smoke-session` caught the first time round. `passwd` needs neither: the shell
always targets the caller's own uid, and `do_passwd` permits that without admin.

*Two notes on the process, both worth more than the defect.*

First, `captest` could not have caught this. Its checks probe refusals for capabilities it does
not hold, and there was no `useradd` probe at all; the suite tested the properties that had been
enumerated, and this one had not been. Four refusals now cover it. (A hypothesis worth recording
as **withdrawn**: that captest had been silently holding `CAP_USER` via `do_spawn_inner`'s
propagation. It does not, and the refusals pass identically with and without the slot explicitly
cleared. The propagation reads `cap_lookup(6, …)` *after* `load_staged_image_into` has made the
child current, so it inspects the child's own empty cspace and never fires: `kspawn.c`,
`do_spawn_inner`. Dead, and dead in the fail-closed direction; "fixing" it would silently widen
authority to every spawned child and must not be done as a tidy-up.)

Second, this section, `SECURITY.md` S18 and `ARCHITECTURE.md` §G-2 all recorded the finding as
closed for nineteen days while it was open; the exact failure mode §3 of `CLAUDE.md` now gates
against.

Two things fell out of the fix. The gates were additionally *type-confused*; the dispatch table
passed a type constant in the rights field with `ctype = SC_ANYTYPE`, so they never checked the
type at all (**[I-1a]**). And delegating the kernel log to the shell would have handed it to
every logged-in user, since capabilities are per-task and the shell serves successive logins;
the shell now enforces the per-user policy itself, with the kernel enforcing possession.
`smoke-session` caught that.

Note that `uid` still exists and still matters; it is the *identity* `fs_server` authorises file
access against (`SYS_IPC_SENDER`). What is gone is uid as a source of **kernel** authority.

### 1.3 ~~`SYS_GET_TASK_INFO` discloses another task's instruction pointer~~ (**FIXED**)
**[I-4]**

`info.cr3` is correctly zeroed with an explicit comment about not leaking physical layout,
but `info.eip` is returned verbatim, defeating userspace ASLR for any task a privileged
caller can observe.

### 1.4 ~~User copies truncate silently~~ (**FIXED 2026-08-13**) **[C-4]**

`copy_from_user` and `copy_to_user` clamped `n` to `USER_MEM_MAX_COPY` and returned success. A
caller requesting more got a partial copy it believed succeeded, leaving stale kernel-stack
bytes in the tail of the destination. No current caller was known to be exploitable, but this
was a latent kernel-memory disclosure that would bite the first time a larger struct was added.

Both helpers now **refuse** a request above the ceiling (`paging.c:1441-1462`). The ceiling was
never the defect, reporting a short copy as a complete one was.

Auditing all ~89 call sites found none that can reach it: each either bounds `n` by the kernel
scratch buffer it stages through (`h_write` 255, `h_dmesg` 1024, `pipe_read`/`pipe_write`
`PIPE_IO_CHUNK`, the block syscalls `BLOCK_SIZE`, the rest a `sizeof`), or chunks explicitly to
`USER_MEM_MAX_COPY` first (`arm_image_from_user`, `try_elf_load`, `load_staged_image_into`). So
refusing is behaviour-preserving, which an 11-target sweep confirms.

One handler *was* live rather than latent: `h_boot_module_read` copies straight out of the
`PHYS_KVA` window with no kernel staging buffer, and returned the **unclamped** `len`, so a
request above 64 KiB reported bytes it had not written. It now clamps to the ceiling itself and
returns the count it actually copied: a short read, which is what its ABI already promises and
what `fs_server`'s provisioning loop already handles by advancing on the returned value.

*Caveat on the witness.* Because every syscall clamps to its own buffer before calling the
helpers, the refusal itself is **not reachable from ring 3**, there is no userspace test that
can trigger it, and this section should not imply otherwise. The reachable behaviour, and the
one worth a falsification test, is the boot-module short read.

### 1.5 ~~Broad revocation can be forced by an unprivileged task~~ (**FIXED 2026-08-16**)
**[I-3]**

**Was:** the descendant-closure worklist in `revoke_subtree` was bounded at 256 entries, and on
overflow the sweep over-approximated by nulling every capability sharing the root `object`. It
failed safe in the direction that matters (no descendant ever survived) but a task could
deliberately build a derivation subtree larger than 256 members, force the fallback, and destroy
an *unrelated* task's independent capability to the same object. A denial of service against a
peer, and an over-broad revocation the capability graph does not describe.

**Now:** the closure marks in place and iterates to a fixpoint, so it is exact at any subtree
size and the object-wide fallback is gone from the seeded path. The mark lives in the
capability's own `typ` field in two states (`CAP_MARK_NEW`, children not yet expanded;
`CAP_MARK_DONE`, expanded) while `serial` and `badge` stay readable, so no side array and no
allocation are needed: which is what forced the old bound in a `no_std` kernel with nowhere to
grow one. Each capability is marked at most once and promoted at most once, so the loop
terminates without a depth bound or a cycle check, at a cost proportional to the subtree the
revoker actually derived rather than to the whole system.

Revoke-*by-object* (`root_serial == 0`) still sweeps by object. That is not a fallback: with no
lineage seed it is the only complete answer, and it is exact for a shared-object lineage.

Witnesses: `test_revoke_large_subtree_is_exact_and_spares_independent_peers` (breadth, 3 levels
deep, past the old bound) and `test_revoke_deep_chain_is_fully_closed` (a 300-link chain). Both
falsified against `--features=revoke_legacy_bounded`, which restores the bounded closure; CI
runs that control arm and fails if the tests pass against it.

### 1.6 ~~Three syscalls are still ungated by any capability~~: **[H-2] FIXED 2026-08-20**

**[I-1]** and **[H-1]** removed authority derived from *identity*. They did not remove authority
derived from *nothing*, and README and the website have both stated the stronger claim. The
residual paths, so that nobody has to take the absolute phrasing on trust: and note what this
list is derived from, because that is what it got wrong: it enumerates gates that are
**absent**, and a gate can also be **present and vacuous**. See §1.6a:

| Path | Gate | Assessment |
|---|---|---|
| `SYS_WRITE` fd 1 → the console | none | Correct and deliberate: every task has a stdout, and writing to a terminal is not an authority this system rations. Marked ambient in `SYSCALLS.md` |
| `SYS_WRITE` fd 1 → `klog` | `CAP_KERNEL_LOG` + `CAP_RIGHT_WRITE` | **Fixed 2026-08-20**: **[H-2]**, below |
| `SYS_READ` fd 0 / `SYS_GET_LINE` | none, but both refuse once `console_hw_owned()` | Correctly mitigated; the guard is present and deliberate |
| `SYS_SYSINFO` | none | A version string. Acceptable, and marked ambient in `SYSCALLS.md` |
| `SYS_OPEN`, `15` (ramfs create), `16` (ramfs list), `SYS_READ` fd ≥ 3 | cspace slot 3, `SC_ANYTYPE` | **Missing from this table until 2026-08-22, and the omission is the point**: see **[H-3]** below. Slot 3 holds the legacy `CAP_FRAME` every task is born with, so all four were gated on nothing. **Fixed 2026-08-22**: retired |

> *This table was headed "the complete residual list" from 2026-08-20 and was not complete: it
> named the four paths gated on **nothing** and missed the four gated on a capability that is
> **equivalent to nothing**, which is a harder thing to see and the reason the audit that
> produced this section looked for the first shape only. The lesson generalises past the four
> rows: **"ungated" and "gated on something every task holds" are the same security property
> and were being counted differently.***

**[H-2]** was the one with teeth, and it was an asymmetry rather than an oversight in isolation:
the *read* side of the kernel log was converted to require `CAP_KERNEL_LOG` under **[I-1]**
(`SYS_DMESG`), and the write side was never considered. `h_write` clamped to 255 bytes and
called `print()`, which appended to `klog` unconditionally: `terminal.c`'s `klog_append` ran
before the `drive_hw` test, so the append survived the handoff to `console_server`. `klog_buf`
is 16 KiB. Any unprivileged ring-3 task could therefore forge lines that appear in `dmesg`
indistinguishable from kernel diagnostics, and could flood 16 KiB to evict genuine ones, an
anti-forensics primitive against the log a maintainer reads after an incident.

**What it did not reach**, and this is the part of the design that was right: the
tamper-evident audit chain in `src/kernel/kaudit.c` is a separate buffer under a ratcheted,
erased-after-use MAC key (property S19). Forging or evicting `klog` never touched it.

#### The fix, and why it closes rather than narrows the finding

`print()` is split. Kernel-origin output goes through `print()` and always records;
ring-3-origin output goes through `print_from_user(str, may_klog)`, and `h_write` computes
`may_klog` by asking the capability graph: `cap_lookup(CAPSLOT_KERNEL_LOG, CAP_RIGHT_WRITE)`,
with the object type checked too. No uid, no task id, no slot convention: an ambient gate here
would have re-created **[I-1]** inside the fix for **[H-2]**.

The console still takes the bytes either way, which is the distinction the old code did not
draw. Writing to the *terminal* is ungated on purpose; writing to the *kernel's log* is an
authority.

**It closes the finding completely, and the reason is a property of the root cnode rather than
of `h_write`:** `root_cnode[15]` mints `CAP_KERNEL_LOG` with `CAP_RIGHT_READ` and nothing else,
and delegation may only ever reduce rights, so **no task in this system can hold the WRITE right
the gate asks for**. The authority is expressible (mint it with WRITE the day a userspace logger
has a reason to exist) without being granted to anyone. Deleting the append outright would have
been fewer lines and would have made that future case unexpressible.

Witness `make smoke-klog-forge`: a ring-3 probe endowed with `CAP_KERNEL_LOG` (READ: so it can
read the ring back and check its own work, and is still refused the direction it was not given)
pushes 28800 bytes through fd 1, more than the ring holds, and requires both that none of it
appears in `klog` and that a marker seeded before ring-3 entry is still there. Falsified by
`KLOG_WRITE_UNGATED=1` (`make smoke-klog-forge-control`), which restores the unconditional
append: `KLOGTEST: FAIL forged+evicted`, 3 boots in 3, and `smoke-klog-forge` goes red under the
same flag.

Both halves are asserted and both are evaluated before either is reported, so the control arm
exercises both branches on every boot. Asserting only one would pass a half-fix: rate-limiting
ring-3 appends would keep the marker and still leak the forgery, and dropping the bytes while
still advancing the ring would lose the marker.

> *An earlier revision of this section said the cheap remediation was to tag `klog` entries
> with their originating task and rate-limit ring-3 appends, and the thorough one a write-side
> capability. The capability turned out to be the cheap one too; the gate is four lines; 
> because the rights that make it fail closed were already minted correctly in 2026-07-27's
> root cnode and nobody had asked what they implied.*

### 1.6a ~~Four paths into the in-kernel ramfs were gated on the [C-1] decoy~~: **[H-3] FIXED
2026-08-22**

*Found 2026-08-22 while orienting on roadmap 2.4, not by an audit.*

Four paths authorised on cspace **slot 3** with `SC_ANYTYPE`:

```c
[SYS_OPEN] = { h_open,         3, CAP_RIGHT_READ,  SC_ANYTYPE }
[15]       = { h_ramfs_create, 3, CAP_RIGHT_WRITE, SC_ANYTYPE }
[16]       = { h_fs_list,      3, CAP_RIGHT_READ,  SC_ANYTYPE }
h_read, fd >= 3:  cap_lookup(3, CAP_RIGHT_READ)   /* inline, same decoy */
```

Slot 3 holds the `CAP_FRAME` that `create_task` installs in **every** task (`READ|WRITE|EXEC`,
naming a fixed window, asked for by nobody) and `SC_ANYTYPE` accepts any type. So all four were
satisfied by a capability nobody requested and everybody has. This is **[C-1]**'s shape exactly:
the pre-C-1 dispatch table gated IPC on slot 3 for the same reason, and these were the last four
gates still wearing it. They survived **[I-1]** and **[H-1]** because both of those swept for
authority derived from *identity*, and survived §1.6's own sweep because that looked for gates
that were *absent*. A gate that is present and vacuous matches neither search.

**Demonstrated, not inferred.** A ring-3 task running as the ordinary uid-1000 account, holding
no capability anyone delegated to it, opened the file `kusers.c` writes the user database into,
read bytes out of three separate ramfs files, created a file of its own, and listed the store:

```
PASSWDPROBE: sys_open("passwd") -> 5
PASSWDPROBE: sys_read(fd=3) returned 24 bytes
PASSWDPROBE: sys_read(fd=4) returned 64 bytes
PASSWDPROBE: sys_read(fd=5) returned 32 bytes
PASSWDPROBE: ramfs_create -> 6
PASSWDPROBE: fs_list -> 38 ... store contains: hello.txt
PASSWDPROBE: FAIL 4 of 4 doors open
```

> *Corrected 2026-08-22: the user database is no longer behind these gates at all. The
> save/load pair that put it there was deleted as code that had never run (§2.6), so what the
> control arm now reaches is an ordinary seeded demo file. **[H-3]** and **S28** are unchanged; 
> the property was never about what happened to be stored there, and a gate satisfied by a
> capability every task already holds is not a gate whatever sits behind it. The probe's first
> check was retargeted accordingly; against `"passwd"` it would now pass trivially in both arms,
> which is a required gate measuring nothing.*

**What it did NOT disclose, and why that is luck rather than design.** `users_save_to_ramfs`
writes the database as `"passwd"`, and every record carries `salt[16]` and `pass_hash[32]`; the
complete input to an offline dictionary attack against every account including root. Those 32
bytes the probe read are **not** the hashes: they are the trailing HMAC tag, because
`ramfs_write` (§2.6 below) takes no offset and rewrites from byte 0 on every call, so only the
last of the four writes survives. **The password hashes were one bug-fix away from being
world-readable**, repair the write path and this open gate hands them out. That is the whole
argument for closing the gate rather than treating the ramfs as harmless.

#### The fix

The three dispatch entries and the `fd >= 3` branch are **retired**, not re-gated, following
syscalls 38–45: the in-kernel ramfs is a toy superseded by `fs_server`, no ring-3 program in
this tree calls any of them, and an ABI kept alive for nobody is surface with no owner. An
absent table entry fails closed at `SYS_ERR_NOSYS` by dispatch. The ramfs itself stays
(`kusers.c` uses it internally) so what closed is the door, not the room.

This is the opposite choice from **[H-2]**, where the authority was kept *expressible* and
granted to nobody. The difference is that `CAP_KERNEL_LOG` names something a future userspace
logger will want; nothing will ever want a second in-kernel filesystem while `fs_server` exists.

Witness `make smoke-passwd-probe`; the probe above, asserting all four doors shut, 4 checks.
Falsified by `RAMFS_SLOT3_GATE=1` (`make smoke-passwd-probe-control`), which restores the four
gates verbatim and reproduces all four openings on every boot.

### 1.6b ~~The task-creating syscalls are gated on the same slot-3 decoy~~: CLOSED 2026-08-30

*Found 2026-08-30 by audit, and it is **[H-3]**'s shape rather than **[H-3]** itself.*

Seven dispatch entries authorise on cspace **slot 3** with `SC_ANYTYPE`:

```c
[SYS_SPAWN]       = { h_spawn,       3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE }
[SYS_SPAWN_IMAGE] = { h_spawn_image, 3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE }
[SYS_EXEC_NAMED]  = { h_exec_named,  3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE }
[SYS_EXEC_IMAGE]  = { h_exec_image,  3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE }
[SYS_FORK]        = { h_fork,        3, CAP_RIGHT_WRITE | CAP_RIGHT_EXEC, SC_ANYTYPE }
```

`create_task` installs a `CAP_FRAME` in slot 3 of **every** task with exactly
`READ|WRITE|EXEC` (`src/kernel/scheduler.c`), so `WRITE|EXEC` on slot 3 is satisfied by a
capability nobody asked for and everybody has. By **S28** that is not a gate.

**Why this is a documentation defect and not an escalation.** Unlike **[H-3]**, where the decoy
bought reach into the in-kernel ramfs, these syscalls confer nothing the caller did not already
have: a fork copies the caller's own address space and cspace, and a spawn endows a child from
what the spawner holds and never more (**S41**, **S42**). A vacuous gate in front of an
operation that grants no new authority is dead weight, not a hole. The harm is in the
description: `src/kernel/syscall.c` says fork "answers to the capability that gates the first",
which reads as a restriction that does not exist, and `src/include/kernel.h` said the opposite
("No capability of its own") until 2026-08-30: two comments, in disagreement, both describing a
check that admits everyone.

**Closed on 2026-08-30, and the premise recorded here was wrong.** This section said the fix
needed *"a `CAP_TCB`-shaped authority to create tasks"* and that it was blocked because *"the
capability would have to name something, and the thing it would name does not yet exist as a
kernel object"*. Two things were wrong with that. A task **is** already named by a capability —
`CAP_TCB` carries a task id, and a spawner gets one for each child — so the object existed all
along. And a capability naming the task cannot gate its *creation* anyway: you cannot hold a
capability to a task that does not exist yet.

**What the authority actually is, is the resource.** A task's cspace is a `KOBJ_CNODE`, and
every other kernel object in this system is carved from an untyped region by an authority that
holds one. That is roadmap 0.3's premise — *"creating a kernel object is an exercise of authority
the capability graph describes"* — and tasks were the one exception to it. They are not now:
`SYS_SPAWN`, `SYS_SPAWN_IMAGE` and `SYS_FORK` resolve the caller's `CAP_UNTYPED` and carve the
child's cspace **out of that region**, so a task endowed with none cannot create one, and a task
given a small region can spawn a bounded number of times. That is precisely the property this
section asked for — *"a task could be spawned without the right to spawn further tasks"* — and
it needed no new object class.

**The charge is the allocation, deliberately.** Debiting a counter while still carving from the
kernel reserve would have been easier and would have been two descriptions of one quantity: the
**[H-3]** shape. The bytes the child's cspace occupies are the bytes the parent paid.

**Two of the five are not untyped-gated, and the split is the point.** `SYS_EXEC_NAMED` and
`SYS_EXEC_IMAGE` replace the **caller's own** image and create no task, so there is nothing to
charge and no new authority to confer (**S42**: an exec touches no capability). Gating them on a
region they do not consume would be a second vacuous check in place of the first. They are
`SC_NONE` and self-only, and say so.

**Why a fixed slot is legitimate here and was not for slot 3.** The defect in the old gate is not
that the slot number is fixed — `CAPSLOT_CONSOLE`, `CAPSLOT_DEBUG` and `CAPSLOT_USER` are all
fixed. It is that slot 3 is **always occupied**, by a capability the kernel installs itself, so
the test could not fail. `CAPSLOT_UNTYPED` is empty unless somebody delegated into it, and the
type is checked.

**What it changed about the running system**, stated because it is a real behaviour change and not
only a check: `init` now delegates `CAP_UNTYPED` to the shell, because `spawn` is a shell command
and a task with no untyped cannot spawn. That grant is the point rather than a workaround — "may
this task create tasks?" is now a question with an answer that is written down and revocable. The
kernel's own task creation (task 0, `init`, the boot shell, `SYS_SUDO`'s relaunch) is charged to
`UNTYPED_KERNEL`, which is not delegable and is sized at exactly `MAX_TASKS` cspaces, so no ring-3
allocation pattern can starve it.

Witness `make smoke-proc`: `grantee` is spawned by `proctest` and deliberately **not** given
untyped — it is exactly "a task spawned without the right to spawn further tasks" — and asserts
that spawn, fork and spawn-image all return `SYS_ERR_PERM`. `SYS_ERR_PERM` specifically, because
a spawn can fail for want of a slot or a bad name and neither says anything about authority.
Falsified by `SPAWN_SLOT3_DECOY_GATE=1` (`make smoke-proc-spawn-decoy-control`), which restores
the slot-3 check: `grantee` can then spawn, and reports `FAIL spawn-without-untyped`.

**What this does not do.** There is no region splitting, so a delegate shares its grantor's budget
rather than receiving a sub-budget; per-delegate accounting is what a `SYS_UNTYPED_SPLIT` would
buy. And a task is still not retyped from untyped as a `KOBJ_TASK` in the seL4 sense — the TCB
storage is still `tasks[]`. What is now true is that creating one costs authority somebody holds.

 ### 1.7 ~~Two syscall wrappers truncated their buffer pointer to 32 bits~~ (**FIXED
2026-08-20**) issue #176

`sys_dmesg()` and `sys_audit_digest()` passed their buffer as
`(uint32_t)(unsigned long)ptr`. The argument registers are 64-bit, so the cast was pure loss:
the kernel received the low 32 bits of the pointer and resolved *that* address in the caller's
own page tables.

**Why a 100-check conformance suite could not see it.** `USER_IMAGE_ASLR_BASE` is 16 GiB with 4
TiB of randomisation, so every static and global in a PIE image is above 4 GiB *by construction*
and was always truncated: while a stack buffer sits near 8 MiB and never was. Every caller in
the tree passed a stack buffer. The two `captest` checks that name these syscalls both assert a
**capability refusal**, and the dispatch gate returns before the handler ever reads the pointer.
The one success-path caller, the shell's `dmesg`, used `char buf[512]` on the stack. So the
defect was 100% reproducible for an entire class of buffer and reachable by no test in the tree.

**It was not fail-closed.** The `SYS_ERR_FAULT` that surfaced it is what happens when nothing is
mapped at the truncated address. Low user addresses *are* populated (the stack at ~8 MiB, the
heap at 16 MiB in a non-high-heap build) and when the truncated address hits one, `copy_to_user`
writes kernel-supplied bytes into a page the caller never nominated. Confined to the caller
(`user_copy` walks `tasks[cur].cr3`, never another task's), so this is corruption rather than a
privilege boundary, but it invalidates any argument of the form "we validated the pointer the
caller gave us", because the pointer the kernel validated is not the one the caller passed.

Both wrappers now use `SYSCALL_UPTR()`. Property **S24**. The gate is
`tools/check_syscall_abi.py` (required job `syscall-abi`), which decides the property for all 46
pointer arguments at build time rather than for whichever syscalls a probe happens to call; the
runtime arm is `make smoke-klog-forge`, whose probe reads the log into a `static` (hence
above-4-GiB) buffer, falsified by `SYSCALL_PTR_TRUNC32=1` (`make smoke-klog-forge-abi-control`),
3 boots in 3.

`user_copy()` still **refuses** an absent page rather than resolving it through
`handle_demand_page_fault()`, and the comment there now says why: that refusal is what kept
this bug fail-closed in the case that was observed, and driving the pager would have allocated
a page at the bogus address and reported success.

> *Issue #176's original analysis was wrong and is corrected on the issue. It reported that
> `pt_walk(tasks[cur].cr3, v)` disagreed with the hardware walk. The two agreed exactly; 
> measured, `ucr3 == livecr3`, and the kernel was faithfully walking a different address. The
> observations were right; the inference was not, and it pointed at `paging.c` for a defect
> that lived in `include/syscall.h`.*

### 1.8 Part of the syscall table has no test that runs its handler, and one of those gaps hid a defect

**Measured since 2026-08-20**, and re-derived on every merge rather than restated: as of
2026-09-01, and gated since: **83 of 95** implemented syscalls have their handler
body entered by the three tracked workloads (the scripted ring-3 session, the conformance suite, and the
boot-modules session). The other 12 are listed in `.github/syscall-coverage.yml`, each with a written reason.
2026-08-30, and gated since: **83 of 95** implemented syscalls have their handler
body entered by the three tracked workloads (the scripted ring-3 session, the conformance suite, and the
boot-modules session). The other 12 are listed in `.github/syscall-coverage.yml`, each with a written reason.

This was stated as a limitation rather than a finding, on the grounds that nothing here was
known to be broken. **That is no longer the honest framing, and it has now been wrong twice.**

On 2026-08-29 three of the syscalls on the uncovered list, `SYS_CAP_MINT`, `SYS_CAP_TRANSFER`
and `SYS_CAP_MOVE`, turned out to reach a helper that spun forever on a NULL capability lookup
while holding `cap_lock` with interrupts masked, which any unprivileged ring-3 task could
trigger in one syscall (**S52**). The three had carried the reason "not entered by any tracked
workload, and by no build known in this tree" since 2026-08-22. Nothing ran them, so nothing
found it. They are on the `covered` list now because the fix is not finished until something
enters the handler.

On 2026-09-01 it happened again, to the syscall this whole file was written about. **The two
wrappers issue #176 truncated were `SYS_DMESG` and `SYS_AUDIT_DIGEST`; only the first had ever
been covered.** Writing the probe that entered the second — `userspace/auditprobe.c`, a task
holding one `CAP_AUDIT` and nothing else — found a defect on its first boot, in the neighbour
it also entered. `struct audit_event` was declared twice under one name: 256 bytes and twelve
fields in the kernel, 72 bytes and seven in `include/syscall.h`. `h_read_audit` copied the
kernel's size at the kernel's stride into an array ring 3 had sized with the other, so every
field was read from the wrong offset **and** the copy ran 184 bytes past the array per record —
into `userspace/grantee.c`'s 144-byte stack array, on every `PROC_SELFTEST` boot since that
caller was written. Fixed by `include/audit_abi.h`, one declaration both rings compile, with a
`_Static_assert` on the size in each (**S71**).

Three things are worth taking from the repeat rather than from either defect. The prescription
was **already written down**: the `uncovered` entry for `SYS_AUDIT_DIGEST` said in as many
words that "a probe task holding one `CAP_AUDIT` is worth writing", and it sat there for nine
days. A gap with a costed fix beside it is not a gap anyone is working on. Second, both defects
were in the *neighbours* of what was being covered — S52's trio and this one's `SYS_READ_AUDIT`
were entered incidentally, which is an argument for covering a capability's whole family at
once rather than the one syscall that motivated it. And third, **neither would have been caught
by a wider `captest`**: both syscalls are gated on a real capability, so the only way in is a
task that holds one, which is why the answer was a new task rather than a bigger suite.

So the standing risk is not hypothetical: a defect in any of those 12 handlers is invisible in
the same way issue #176 was, and in the way S52 and S71 just were. `captest` is a **refusal** suite by
So the standing risk is not hypothetical: a defect in any of those 12 handlers is invisible in
the same way issue #176 was, and in the way S52 just was. `captest` is a **refusal** suite by
construction: its checks for `SYS_DMESG` and `SYS_AUDIT_DIGEST` both assert `SYS_ERR_PERM`, and
the capability gate returns before the handler runs. Both syscalls were named by the suite;
neither handler had ever executed. What S52 adds to that lesson is that a refusal test does not
even establish the refusal comes back.

`tools/check_syscall_coverage.py` (required job `syscall-coverage`) fails on drift in either
direction, so the number cannot quietly fall. It deliberately does not require all of them; that
would be a large body of test-writing disguised as a gate. Property **S25**.

**Thirteen were promoted on 2026-08-30, and what made them promotable was one structural fact
nobody had asked the list about.** Twelve of the 26 carried `SC_NONE` dispatch rows. An
`SC_NONE` row means the central check in `syscall_handler` admits every caller and whatever
authority the call needs is tested *inside* the handler, so the handler body is reachable from
ring 3 by a task holding nothing at all: a `captest` probe that proves the call says no is a
probe that ran the body. That argument is not new here. It is the one that promoted
`SYS_GET_LINE` on 2026-08-24, the device family on 2026-08-28, and S52's capability trio on
2026-08-29, each written into the manifest as "the same structural reason". What had not
happened was asking it of the whole list.

**The manifest had drifted in its reasons while enforcing itself perfectly on its numbers**, and
that is the part worth keeping. Its `uncovered` entries described why each call's *success* path
was not reached — no `CAP_UNTYPED` to retype a frame from, no pipeline in the session, login
reads its password elsewhere. Every one of those sentences was true, and none of them is about
whether the body runs, which is the distinction the file's own header says it exists to
preserve. Two were also false: `captest` holds a `CAP_UNTYPED` and retypes from it, and
`SYS_FRAME_PAGES`' entry claimed the legacy slot-3 capability was "refused before the handler
body would report anything" when its row admits every caller. The count those sentences
surrounded was gated and correct throughout; the reasoning was not gated and was wrong.

**The thirteenth was a gap in the workload rather than in the kernel**, which is the shape this
paragraph used to claim for the pipe family — accurately when it was written, and stale from the
day #179 closed it. `SYS_FS_INODE_FREE` is gated on `CAP_ENCRYPTED_STORAGE`, which `fs_server`
holds and calls on its unlink path, so the handler was one shell command away from running on
every session boot and nothing had issued it: the scenario created files and never destroyed
one. `tools/session_test.py` now runs `rm` and asserts with `stat` that the name stops
resolving.

**Two SC_NONE handlers were deliberately not promoted, and they are the boundary of the
technique.** `SYS_GET_PASS` blocks — its only early return is `console_hw_owned()`, no ring-3
server owns the UART in the `captest` image, and the first draft of its probe hung the gate for
the full timeout. It looks identical to `SYS_GET_LINE` from the dispatch table; the difference
is that `h_get_line` tests `CAP_CONSOLE` inside the handler and refuses outright, where this one
tests no authority at all. `SYS_SHLIB_INFO` would enter a body that returns at its first line,
because `shlib_active()` is false in every tracked image, so covering it would raise this
number without ever running the gate the syscall is interesting for. **"The body was entered"
stops being coverage when the body is one branch of a feature that is compiled out.**

**Falsified by `SYSCOV_PROBES_ABSENT=1`**, which compiles the probes out; `make
smoke-syscall-coverage` must then go red naming *exactly* the twelve, and
`make smoke-syscall-coverage-control` asserts that set rather than merely asserting a failure.
The arm rebuilds and reboots all three workloads even though the flag changes only `captest`,
because running the one arm would leave the other two transcripts missing and redden the gate
without the defect contributing anything. Without the arm, a promotion the probes earned would
be indistinguishable from one that was free all along.

**What is left is twelve, in three groups, and the grouping is the useful part** because it
says what each would cost. **Five** have a real capability in their dispatch row, so the table
refuses before the handler runs and `captest` holds none of `CAP_ENCRYPTED_STORAGE` or
`CAP_STORAGE_FORMAT` — covering one needs a probe task that holds exactly one of them, not a
wider `captest`. That prescription was followed for `CAP_AUDIT` on 2026-09-01 and it worked, so
the cost is now known rather than estimated: one small task, and the first entry into either
handler found a defect.

**`SYS_STORAGE_FORMAT` is the one member of that group a probe task cannot rescue**, and it is
worth naming because it is the boundary of the technique rather than a gap in it: entering its
body **formats the attached disk**, so no tracked workload can enter it without destroying the
volume the run is using. Its sibling `SYS_STORAGE_INFO` is `covered` instead — by `init` calling
it at boot from the same capability (roadmap 2.9), which is the same capability and the opposite
consequence.

Five carry the slot-3 `[C-1]` decoy (§1.6b), which is not a gate, so `captest` passes the table
check and is stopped by the opposite problem — the call would *succeed*, replacing or
duplicating the caller. Two are the SC_NONE pair above.

### 1.9 ~~S16 had no witness at all~~: CLOSED 2026-08-28

`SECURITY.md` S16 (*"a task cannot read another's XMM register file"*) carried a literal em-dash
in its witness column for the life of the project. The property was real and the code enforcing
it was real: `fpu_save` / `fpu_restore` (`src/kernel/scheduler.c`) capture and reinstate the
whole 512-byte FXSAVE image on every ring transition, called from `interrupt_handler64`.
**Nothing exercised them.**

That is the **[C-1]** shape precisely (a documented property with no test binding it to the
code) and it is the shape this whole section exists to record. It survived every prior sweep
because those sweeps looked for gates that were *absent* or *vacuous*, and this gate was
neither: it was present, correct, and untested. Nobody had asked the different question, *which
claims have no witness at all*, because nothing asked it mechanically.

**Closed by `make smoke-fpu`**, falsified one arm per half (`FPU_NO_RESTORE=1` discloses without
losing, `FPU_NO_SAVE=1` loses without disclosing). Writing the arm found a defect in the *test*
first: released together, the peer could exhaust its sampling window before the sentinel
existed, and the arm reproduced 2 boots in 3. It is ordered rather than retried: see `TESTS.md`.
**Found while surveying `SECURITY.md` for roadmap 4.12's invariant registry**, which is the
mechanical version of that question and is what stops the next one lasting as long. Until 4.12
lands, "does every S-number have a witness" is still a thing a person has to remember to ask.

---

### 1.10 ~~A gate is classified as a control arm by its NAME~~ , CLOSED 2026-08-30

*Found 2026-08-30 by audit, fixed the same day.*

`tools/check_gate_pairs.py` decided whether a `smoke-*` target was a control arm by testing
whether the string `control` appeared in its name. Four falsification arms are named otherwise
(`smoke-kfault-legacy`, and `smoke-resume-guard-{legacy,nofloor,preclaim}`) and were counted as
base gates. Nothing was unprotected by that: all four are invoked by CI and assert their markers
exactly as a `-control` arm does. What was wrong was the **count**, and both figures it produced
are published and gated by `doc-claims`, so a documented number rested on a string match. They
read 69 arms and 97 gates against a true **73 and 93**, and the gate caught both the moment the
classification became honest.

**Three derivations were tried, and each is wrong in a different direction.** By NAME, 69,
missing the four above. By BUILD (does the recipe set a member of `DEFECT_FLAGS`?), 87, because
that list holds instruments and policy opt-ins as well as defects: `KSTACK_RACE_WIDEN`,
`RNG_UNSEEDED_PROBE`, `SYSCALL_COVERAGE` and `KSTACK0_PARK_TRACE` are each called *"not a
defect"* in `CLAUDE.md`, two are deliberately set in **both** arms of a pair, and `smoke-heap64`
and `smoke-rng-seed` are base gates that boot a defect-exposing configuration on purpose. By
ASSERTION (does it require a `FAIL` marker?), 17 disagreements, because many arms drive a
bespoke script rather than `tools/smoke_test.sh` and have no marker to read.

**So it is declared.** `.github/gate-pairs.yml` names every one of the 166 targets: each control
arm with the base gate it extends, and each base gate. The distinction is a statement about
*intent*, which is not recoverable from the Makefile, and this is the same bargain
`.github/ci-gating.yml` makes for jobs. A new target that appears in neither list fails the
build rather than inheriting a classification by being named like an old one.

Falsified seven ways by `tools/test_check_gate_pairs.sh`, which the required `gate-pairs` job
runs: each of the five rules against a tree mutated to break it, a manifest entry whose target
has been deleted, and an unmutated tree that must pass, because six "is it caught" arms are
satisfied by a checker that rejects everything.

### 1.11 ~~The `enforced by` column of the property table is parsed and discarded~~ , CLOSED 2026-08-30

*Found 2026-08-30 by audit, fixed the same day.*

`tools/check_invariants.py` read each row of `SECURITY.md`'s table as
`(statement, enforced_by, witness)` and bound only the third:

```python
_stmt, _enf, wit = sec[sid]
```

`_enf` was never used again, so the column that says *which code makes this true* could name a
function that had been renamed or deleted and all six rules still passed. The witness half was
checked thoroughly; the mechanism half was prose. That is the wrong way round: a witness that
runs against code which no longer does what the row claims is the shape of **[H-1]**.

**Two rules now, and both directions are covered.**

**R7** validates the column: every backticked path must exist and every backticked identifier
must appear in the shipping tree. 236 tokens are checked, and all 236 resolved when the rule was
added, which is the right moment to gate a property rather than the wrong one. Prose in
backticks is skipped deliberately, since the point is to catch a named function that has gone,
not to police the writing.

**R8** covers the reverse, which is the half a reader needs when they are about to *change*
something rather than audit it: **20 of the 56 S-numbers appeared nowhere outside prose**, so
somebody editing `rust_cap_revoke_global` could not see from the code that S3 and S4 depended on
it. All 56 are now cited at the site that carries them, and R8 keeps it that way.

**There is no exemption list, and that is a finding in itself.** Five properties looked as
though they had no site to be cited from, being about the build rather than the kernel:
reproducible images, documented numbers, the Kani proofs, Miri, and `unsafe` documentation. Each
turned out to have one, the tool that enforces it. A property with nowhere to be cited from is a
property nothing enforces, which is worth discovering rather than excusing.

Falsified by `tools/test_check_invariants.sh`, which the required `invariants` job runs: ten
arms now, one per rule, including R7 against a row naming a renamed function and R8 against a
tree with every mention of a property stripped out.

### 1.12 ~~The rollback tree does not make the volume monotonic~~ (**ANCHORED 2026-09-01**, `SECURITY.md` S70)

**S66**'s tree catches *partial* rollback: a subtree of the metadata region rewound while the rest
of the volume moves on. It could not catch the whole volume being replaced with a consistent
earlier snapshot, because every internal relationship holds and the root lives in the superblock
it is meant to protect — nothing inside the disk can tell "this volume" from "this volume, last
week".

There is an anchor outside it now: a **TPM NV monotonic counter**. `sb.rollback_gen` records the
counter value the volume was last written at, bound into the Merkle root's preimage so it cannot
be edited, and unlock refuses a volume whose generation is behind the counter. `make
smoke-rollback` restores an entire earlier disk image between boots and requires the refusal;
`ROLLBACK_ANCHOR_IGNORE=1` is the arm.

**What is still true, and it is a real limit, not a formality:**

- **Only volumes formatted on a machine with a TPM are anchored.** `sb.rollback_anchored` records
  which kind a volume is, so a reader is never guessing — but an unanchored volume has exactly the
  protection it had before, which is the tree and no more. `ROLLBACK_ANCHOR_REQUIRED` does not
  exist yet; a policy that refuses to mount an unanchored volume is the obvious next step and is
  not built.
- **The granularity is one boot.** The counter advances once per unlock, so a rollback to any
  state from a *previous* boot is refused and a rollback to an earlier point *within the current
  boot session* is not. Closing that would mean a TPM NV write per filesystem transaction — NV
  writes are milliseconds and the endurance is finite, so it would cost more than it buys.
- **An attacker who can talk to the TPM can deny service.** Advancing the counter, or undefining
  the index, leaves the volume refusing to mount. Neither lets them roll it back: making an old
  volume look current needs a root MAC they cannot forge, and a re-created counter index starts
  above every value any counter on that TPM has held.
- **It is bound to the machine, not to the disk.** Moving an anchored volume to another machine
  presents a generation that machine's counter has never issued, and it is refused. That is the
  correct behaviour for the threat being defended against and it is also, straightforwardly, an
  obstacle to legitimate disk migration. There is no export path.

---

## 2. Correctness limitations

### 2.0 ~~Spinlock interrupt state is global, and the bug is load-bearing~~ (**FIXED
2026-08-11**) **[C-3]**, **[C-3.1]**

**What it was.** `irq_lock_depth` was a single **global** counter shared by every CPU,
incremented and decremented non-atomically, and `spin_unlock` did an **unconditional** `sti`
when it reached zero. Under SMP one CPU's release could re-enable interrupts while another
still held a lock, and racing read-modify-writes lost counts outright. The unconditional `sti`
separately re-enabled interrupts inside a caller's own `cli` region, including `user_copy`'s
CR3 window, where a preemption leaves a stale CR3 to restore.

Worse, it was **load-bearing**: because that `sti` fired for any lock taken while interrupts
were masked (and `int 0x80` masks them on every syscall entry) interrupts came on earlier and
more often than any stated policy asked for, and the startup handshake had come to depend on it.
A correct per-CPU, IF-preserving lock written on 2026-07-27 passed every local gate and broke
the ring-3 handshake in CI; it was reverted.

**What fixed it.** The depth and the saved `RFLAGS.IF` are now per-CPU, and the outermost
release *restores the caller's own* `IF` instead of asserting one.

The July patch was not wrong; the tree was. Three subsystems were subsequently changed to route
around **[C-3.1]**, above all `preempt_on_tick`'s ring-0 guard, widened from `cpu == 0` to every
CPU precisely because a ring-0 tick could land mid-syscall. With that guard a ring-0 tick is
never a switch point, so the accidental `sti` no longer produces the preemption anything
depended on.

Interrupt policy is now **stated** (see [`ARCHITECTURE.md` §6, "Interrupt policy"]) and gated:
`smoke-irq-policy` records `IF` at six milestones, the sixth being `IF` immediately after the
first outermost `spin_unlock`, which is the one observation separating the two locks.
`IRQ_LEGACY_GLOBAL_LOCK=1` rebuilds the defect exactly, as the control arm.

Measured on the same 14-command workload, the two builds count the same predicate (a release
whose caller had `IF` clear): legacy **1439 accidental + 720 benign = 2159**; per-CPU **2159
suppressed + 0 benign = 2159**. Identical totals, 1439 unwanted enablements removed. Interleaved
pinned session rates: `-smp 1` 0/20 both arms; `-smp 4` 3/40 legacy vs 1/40 per-CPU: a
difference well inside noise, and every failure in both arms was **G-8 signature A** (the ring-3
shell faults and `init` relaunches it), not an interrupt-policy fault.
`smoke-console-smp-stress` and `smoke-sched-invariants-stress` both 30/30 on the new lock.

**An open question, recorded rather than rounded off.** Those session rates are one harness. A
separate boot-only harness (`-smp 4` squeezed onto a single host core against three CPU hogs,
arms interleaved) found a kernel page fault in the interrupt-return path at **3 boots in 125 on
the per-CPU arm, against 0/125 legacy and 0/105 on `main`**. p ≈ 0.045: marginal, and not
conclusive at that sample size. It is recorded here because the correct bar for a fault on that
path is *shown not to be mine*, not *not yet shown to be mine*, and because the alternative
reading: that the new lock changes when interrupts are masked and therefore merely **exposes** a
latent teardown-vs-selection race, puts the fix somewhere else entirely. The capture is a
corrupted trap frame being `iretq`'d (`err=0x11`, `rip` and `rsp` 0x80 apart in the same kernel
stack: the kernel executing from a stack), not a wild pointer, so a range check on the resume
`%rsp` cannot catch it and did not when it was armed for exactly this.

**Still open, and now visible.** The three workarounds written for C-3.1 are still in place and
were not removed here, `preempt_on_tick`'s ring-0 guard, `untyped.c`'s IF-transparent critical
section, and the deferred lock arming past boot. They are no longer load-bearing for interrupt
policy, but each was justified by this defect, and each now deserves its own re-examination
rather than a bulk revert on the strength of one green run.

### 2.1 ~~64-bit arithmetic is truncated in the heap syscalls~~ (**FIXED 2026-08-13**) **[I-2]**

`SYS_SBRK` and `SYS_BRK` computed the new break in `uint32_t` while `heap_start` and
`heap_max` are 64-bit. Correct only while every heap lived below 4 GiB. Both are now 64-bit
end to end, with the overflow check before the range test (roadmap 1.5).

**The finding was wider than this section described, and the extra part was not latent.** The
same truncation appeared a third time, in the *pager* rather than the syscalls,
`handle_demand_page_fault`'s region gate cast the task's heap bounds to `uint32_t` when calling
`rust_validate_page_fault`, which declares them `u64`:

```c
!rust_validate_page_fault(fault_addr, err_code, image_base, image_end,
                          (uint32_t)tasks[tid_g].heap_start,   /* truncated */
                          (uint32_t)tasks[tid_g].heap_end)
```

So for a heap above 4 GiB the effect was not a wrong break value but **no demand paging at
all**: the gate compared a 64-bit fault address against a truncated window, found it outside,
and refused to map a page the task was entitled to. A heap outside the premapped low window
could never be paged. **Silently**, a ring-3 fault prints nothing (`idt.c` says so in its own
comment), so the system simply wedged.

The tell was that the two gates disagreed: `page_fault_handler` passes the same values to the
same validator *untruncated* and admitted the fault, and then the pager rejected it. One
validator, two call sites, one of them narrowing.

Witnessed, in both directions, by `make smoke-heap64`: `USER_HEAP_HIGH_BASE=1` places every
heap at 8 GiB, which makes the truncation reachable, and `captest` exercises `sbrk`/`brk` and
then writes to the page it was given. Built without the fix the same target reports
`CAPTEST: FAIL (sbrk-grow-failed)`. That control arm is why this one is not filed as
"latent, believed fixed" the way **[C-4]** had to be.

### 2.2 ~~Endpoints are single-slot mailboxes~~ (**QUEUED + REPLY-CAP 2026-08-10**) **[I-5]**

**Mostly resolved.** Each endpoint now owns a bounded FIFO of `EP_QUEUE_SLOTS` (4) messages, so
concurrent senders enqueue instead of colliding and `-2` means the ring is genuinely *full*
rather than merely occupied. Measured on the 4-client concurrency test under single-core
starvation, 12 boots each:

| Depth | Mean | Spread |
|---|---|---|
| 1 (the old single slot) | 7042 ms | 6648–7694 ms, in **three discrete clusters ~520 ms apart** |
| 4 (the queue) | **5162 ms** | 11 of 12 runs within **15 ms** |

The clustering is the evidence, more than the 27%: single-slot completion times quantised into
steps, and each step is one more collision-and-retry round. The queue removes the quantisation.
`EP_QUEUE_SLOTS=1` rebuilds the old behaviour exactly, which is how this was measured rather
than asserted.

**The reply path is now a one-shot capability.** `SYS_IPC_RECV` mints a `CAP_REPLY` naming the
sender of the message it dequeued; `SYS_IPC_REPLY_TO` requires it and consumes it. Replying to a
client you never received from, replying twice to one request, and replying to the wrong client
are no longer *refused*: they are **unrepresentable**, because the right names one blocked
caller and dies on use. That retires the convention a server previously had to honour: the old
routing read the endpoint's mutable `last_sender`, and the bounded queue above made that sharper
by letting a server hold several dequeued requests while only the newest was nameable.

**The receive side no longer has to poll.** `SYS_IPC_RECV_BLOCK` sleeps on an empty queue
instead of returning `-2`, and `fs_server` and `console_server` both use it. A server with no
work is now genuinely off the run queue rather than merely yielding between polls.

Measured on `tools/session_test.py`, interleaved (adjacent alternating boots, so host drift
cannot produce the trend) and pinned to two host cores:

| Build | `-smp 1` mean | `-smp 4` mean | Failures |
|---|---|---|---|
| polling servers | **15.18 s** | 4.69 s | 0/10, 0/12 |
| blocking servers | **6.25 s** | 3.88 s | 0/10, 0/12 |

Both arms complete the same 26 checks (12 under `-smp 4`), so the difference is not a shorter
test. The single-core ranges do not overlap, slowest blocking boot 6.63 s, fastest polling boot
14.63 s. The gain is smaller with four cores because spare cores absorb the wasted turns, which
is the expected shape if the cause is a runnable server competing for turns it cannot use.

**A caution for anyone extending this path.** The interesting hazard is not the sleep, it is
that a blocked receiver is completed by the *sender's* syscall, on the sender's CPU, with the
sender's cspace current. The first version of this minted the receiver's one-shot reply right
after marking it runnable, so under `-smp 4` the woken server could reply before it held the
right, get `SYS_ERR_PERM`, and correctly drop the reply, hanging the client. It hung 8 of 25
loaded sessions (0 of 25 after the fix) while passing every single-CPU gate. The rule now is **a
receiver holds its reply right before it is schedulable**, and `TESTS.md` carries the loaded
reproduction, since an idle host will not show it.

**Still open.** Priority inheritance still cannot be expressed: the kernel now records that a
task is waiting on an endpoint, which is the prerequisite, but nothing propagates priority along
that edge, and there are no task priorities to propagate yet. `fs_server` also still polls in
one place by design, re-stating the root inode while a sealed ATA volume is locked; it blocks
only once provisioning has succeeded.

*(An earlier revision of this section claimed finding **[G-8]** signature C was a livelock
caused by this contention. **That was wrong.** It was a startup race, clients that lost the race
against `fs_server`'s registration held no endpoint capability, and every IPC then returned
`SYS_ERR_PERM` into a userspace loop that retried it forever. Evidence: not one byte of traffic
ever crossed any endpoint in a hung boot, which contention cannot produce. Fixed in userspace;
see `TESTS.md`. The queue above is a real improvement, but it did **not** fix that hang and was
never what caused it.)*

*(The shared global reply endpoint that used to compound this is gone: every task now has a
private one, so **[I-5]** is closed. The missing queue is not.)*

The block/wake protocol around these mailboxes is the delicate part, and it has now produced two
defects of the same shape. A caller becomes wake-visible in stages (`pending_block` set,
`saved_ksp` written, then `state` published) and any interval in which it is committed to
blocking without advertising it is a window where a wake can be lost. The publish-after-save
ordering covers `saved_ksp`; a reply arriving before `pending_block` was set, or between it
being cleared and `state` being written, used to be **dropped and reported as delivered** (see
CHANGES.md). Both are closed, and the declaration now spans the whole interval, but the staged
design means the next primitive added here has to reason about the same thing. A proper reply
capability consumed on reply (roadmap 1.3) would retire the class rather than patch instances of
it.

### 2.25 ~~The write-ahead journal is not durable on real hardware~~ (**FIXED 2026-08-16**)
**[I-10]**

**Was:** `src/kernel/ata.c` issued exactly three ATA commands (`READ SECTORS` (0x20), `WRITE
SECTORS` (0x30), `IDENTIFY` (0xEC)) with **no `FLUSH CACHE` (0xE7)** anywhere in the kernel.
`WRITE SECTORS` completes once the data reaches the drive's volatile write cache, which is
enabled by default on essentially every ATA/SATA device, so a power failure between the
journal's commit record and the platter lost the record and left recovery in the state the WAL
exists to prevent.

**Now:** the driver implements `FLUSH CACHE`, and `journal_commit()` places three barriers,
not the two the roadmap originally specified:

| Barrier | Position | What it prevents |
|---|---|---|
| **A** | after the journal data, **before** the commit header | The write-ahead rule itself. Without it the header can land first and recovery redoes a valid, correctly-HMAC'd transaction from data sectors that never reached the medium. |
| **B** | after the commit header, before applying home | A crash mid-apply with no durable record to replay. |
| **C** | after applying home, before clearing the header | Retiring the only copy that could replay the update. |

`journal_recover()` carries the same barrier before it clears a replayed header. A failed
barrier is not advisory: A and B abort the transaction with home untouched; C deliberately
leaves the header in place so the next mount replays it, and returns success because the
transaction genuinely is committed.

**Why the obvious test would not have worked.** Switching `smoke-fs-wal` to `cache=writeback`
(the original plan) does **not** distinguish a flushing kernel from a non-flushing one: guest
writes land in the host *page cache*, which outlives the QEMU process, so killing QEMU loses
nothing either way. There is no QEMU cache mode in which a two-boot test's outcome depends on
whether the guest flushed. The gates instead make the flush **fail** (`blkdebug`, `inject-error`
on `flush_to_disk`) and assert the kernel's reaction, and trace the IDE command register to
assert the barriers sit in the right *place*. See `TESTS.md`.

Witnesses: `make smoke-fs-wal-flush` (issued and checked) and `make smoke-fs-wal-order`
(ordering). Both falsified against `WAL_NO_FLUSH=1`.

### 2.3 Kernel object lifecycle covers retyped objects only

*Restated 2026-08-15. This section previously read "Endpoints and notifications are never
reference-counted or destroyed", which stopped being true when **[I-7]** landed and was never
revised.*

A **retyped** endpoint, notification or frame: one carved from untyped memory, at an index at or
above `DYN_EP_BASE` / `DYN_NOTIF_BASE` / `DYN_FRAME_BASE`, is destroyed when no capability names
it any more. That is computed by mark-and-sweep over the capability graph
(`src/kernel/untyped.c:306-400`) rather than by reference counting, on the reasoning that
reachability derived from the same graph the security argument is stated over cannot disagree
with it. The sweep's imprecision is deliberately biased toward leaking: a capability whose
lineage generation was bumped still marks its object, because the opposite bias, treating a slot
as empty while a holder can still resolve it, is a use-after-free reachable from ring 3.

A **frame** carries one extra condition, because a PTE is a second, capability-free path to the
same bytes: a task that maps a frame and then drops its capability still reads and writes the
page. So a frame is collectable only when no capability names it *and* nothing has it mapped,
which the refcount answers directly; the untyped region holds one permanent reference, every
mapping adds one, so a count above 1 means a live PTE somewhere. Refusing leaks the index until
the last holder unmaps or dies; teardown walks the page tables and drops the references, so the
next sweep collects it. Same direction of imprecision as above.

That permanent reference is also what keeps a frame out of the free page stack. An arena page
sits inside `[USER_PHYS_BASE, pool ceiling)` and therefore has a refcount slot, and
`free_user_table` releases every present leaf of a dying task's page tables: so without a
reference of its own, a mapped frame's bytes would be handed out as an anonymous page while the
untyped region still owned them. Before roadmap 2.1 that was avoided only because a
never-allocated arena page sits at count 0 and `rust_page_ref_dec` fails closed on an
already-zero frame: a value nobody set on purpose holding up a safety property.

What has no lifecycle is the **static shim** below those bases: the well-known service endpoints
and the per-task reply endpoints are named by the boot protocol rather than by any single
capability, so nothing can decide they are dead. They are immortal by construction and will stop
being so as they migrate to retyped objects. Destruction also does not return the bytes: the
arena is a monotonic bump allocator, so only the *name* is reclaimed.

### 2.4 ~~Copy-on-write is implemented but narrow~~: LARGELY CLOSED 2026-08-28

*This section said "there is no `fork`: the only COW producer is the demand pager" for a day
after `fork` landed (#220), which is the drift §3 of `CLAUDE.md` exists to catch. Recorded here
rather than silently rewritten.*

COW works for the shared zero page and for the generic non-zero case, and `SYS_FORK` is now a
second producer: `clone_user_aspace` downgrades **both** trees' leaves and `cow_break_pte` hands
out the private copy to whichever side writes first (**S39**, `make smoke-fork`).

The question this section left open (*what a COW break means for a page two tasks hold
capabilities for*) has been **answered rather than implemented**, and the answer is that it does
not happen. `cow_break_pte` refuses any page inside the untyped arena (**S38**), because a break
would allocate the private copy from the *anonymous* pool, resource authority no untyped region
paid for, and would repoint the PTE at a page no capability names. `SYS_FORK` refuses one layer
earlier still, rejecting the clone outright while a `CAP_FRAME` is mapped (**S40**), so the
refusal reaches the caller at a point it can act on rather than killing whichever side writes
first. A task wanting a private copy of a frame retypes its own and copies the bytes: explicit,
budgeted, and visible in the capability graph.

What remains narrow is *sharing*: there is still no way for two tasks to hold one frame
copy-on-write. That becomes expressible now that a fork duplicates a cspace (§2.11), and it is
deliberately not written yet.

### 2.5 A frame's bytes are not reclaimable until its untyped region is reset

*Added 2026-08-22 with roadmap 2.1.*

A `KOBJ_FRAME` is bump-allocated out of an untyped region like every other kernel object, so
destroying it reclaims the **name** and not the page. The bytes come back only when the untyped
capability is revoked and the region's watermark resets, and that reset is not written yet, so
in the tree as it stands a frame's page is consumed for the life of the boot.

This is the seL4 trade taken deliberately rather than an oversight, and the alternative was
considered and rejected: a free list lets an object's bytes be handed straight back out and
retyped as a *different* class while a stale capability still names the old address, which is
type-confusion-through-reuse. A monotonic watermark makes that moment structurally impossible.
The cost is that a long-running workload that creates and destroys many frames exhausts its
region rather than recycling it, and `SYS_UNTYPED_INFO` is how a task observes that coming.

A second, smaller ceiling sits above it: `MAX_DYN_FRAMES` (256) bounds how many frames the
kernel can **name** at once. The untyped region bounds how many a given authority can
**create**, and only the second is a security property, but the first is what a real workload
meets first.

A third, smaller still: **a frame spans at most `MAX_FRAME_PAGES` (64) pages**, and
`SYS_MAP_REGION` maps at most 64 slots in one call. Since 2026-08-27 a `KOBJ_FRAME` carries a
length (**S36**), so 64 pages is 256 KiB in one object under one capability.

That bound is the **arena's**, not the unwind's. `UNTYPED_ARENA_BYTES` is 4 MiB *total*, shared
with every cspace, endpoint and notification in the system, so a frame that could span the arena
would be a denial-of-service against every other object class dressed up as a feature. The
all-or-nothing unwind costs no per-page state for a sized frame (the run is contiguous, so page
*k* is `base + k`) which is exactly why the length belongs in the object rather than in the
caller's bookkeeping.

~~**A delegate cannot ask how large a frame is.**~~ **Closed 2026-08-27** by `SYS_FRAME_PAGES`
(**S37**). The alternative (a field in `struct cap_info`, reported by `SYS_CAP_ENUMERATE`) was
rejected on authority grounds rather than taste: that call is gated on `CAP_DEBUG`, so a task
would have needed a cross-task *observability* capability to learn about its **own** object, and
`CAP_DEBUG` would have started revealing other tasks' object extents at the same time. Holding a
capability that names the object is the entitlement to know how big it is, so the authority is
that capability.

### 2.6 ~~User accounts do not survive a reboot~~ (**FIXED 2026-08-31**, `SECURITY.md` S62)

*Restated 2026-08-22; closed 2026-08-31. This section previously read "`ramfs_write` ignores
position, so the user database has never persisted", which was true and was only one of three
reasons.*

**Closed as designed.** The table is sealed under a key derived from `disk_key` and written
through the write-ahead log, so a crash leaves it wholly before or wholly after; the pepper is
gone from account hashes, which is what reason 3 below said had to happen before storage could
matter at all; and the ordering inverted to unlock-then-identify, with the identity supplied by
the key slot that opened (S61) rather than worked around. A table that is present and does not
authenticate refuses every login rather than being reseeded — reseeding would restore the
compiled-in `root` password, which is a downgrade rather than a recovery. The account below is
kept because it is the reasoning the fix was derived from, and because reason 3 is the part a
reader will otherwise rediscover the hard way.

`users_init` seeds `root` and `user` from compile-time constants on every boot. `useradd`,
`userdel` and `passwd` take effect immediately and are gone at the next power cycle. The audit
log is the only durable record that an account ever existed.

The mechanism that was supposed to prevent this (`users_save_to_ramfs` /
`users_load_from_ramfs`) was **deleted on 2026-08-22 as code that had never run**. Three
independent reasons, any one of which was fatal:

1. `ramfs_write` took no offset: it wrote to `data[0]` and set `size = len` on every call, so
   of the four writes the save made only the last survived. `ramfs_read` had no position
   either, so the load's sequential reads were equally broken.
2. Nothing persisted the ramfs (`ramfs_files[]` is `.bss`) and `users_load_from_ramfs` was
   called exactly once, from `users_init`, at boot, when that table is still zeroed. It opened
   nothing and returned immediately, every boot, since it was written.
3. **Password hashes are boot-local by construction.** `kernel_pepper` is fresh random bytes
   every boot and feeds `strong_password_hash` both when a password is set and when it is
   verified, so a hash from one boot cannot verify in the next *whatever it is stored in*. The
   integrity tag was MAC'd under the same pepper, so even a correctly written file could never
   have validated across a reboot.

**Reason 3 is the one that shapes the fix**, and it is a property of the hash rather than of
the storage: persisting the database is not sufficient, or even meaningful, while the pepper is
per-boot.

**The agreed design puts the table inside the AEAD object store.** The hashes are then protected
at rest by the volume key that is already sealed under `PolicyPCR(8,9)`, so a stolen disk yields
nothing to attack offline: and **the pepper stops needing to survive the reboot at all**,
because encryption is doing the job the pepper was being asked to do. That is smaller and
stronger than sealing a second secret, and it works on a machine with no TPM, which the
alternative did not.

*An earlier revision of this section proposed TPM-sealing the pepper under the same policy. That
was superseded on 2026-08-22: it added a parallel protection mechanism where the existing sealed
KEK already covered the data, and it delivered nothing without a TPM; the common case. The
observation that prompted it still stands, and is why the pepper cannot simply be persisted in
the clear: `fs_superblock.kek_salt` already excludes the pepper, commented "must be reproducible
across reboots from the same pwd"; the same conclusion, reached earlier, one field away.*

The cost of the chosen design is an ordering change: `verify_password` currently runs **before**
`storage_unlock`, and hashes inside the store invert that to unlock-then-identify. That is sound
(`storage_unlock` authenticates, since the AEAD unwrap of `disk_key` fails on a wrong password)
but it interacts with the single-password limitation immediately below.

**~~A related limitation, orthogonal and pre-existing: only one password can unlock the
volume.~~ FIXED 2026-08-31 (`SECURITY.md` S61).** The volume key is now wrapped once per key
slot — up to `HORUS_KEYSLOTS` (8) independent wraps of `disk_key[32] \|\| uid[4]`, each under a
KEK derived from its own password and its own salt — so several passwords open one volume and
revoking one revokes exactly that one. The uid is sealed *inside* the slot, so a slot that opens
says who opened it; that is what supplies the identity the ordering change above needs, rather
than it having to be worked around. Two consequences are forced rather than chosen: revocation is
by slot index, because finding a slot by uid would require that user's password; and the last
active slot cannot be removed, because a volume with no slots is unreachable rather than deleted.
Witness `make smoke-keyslots` (two boots on one image), falsified by `KEYSLOT_REMOVE_NOOP=1`.

### 2.6a Self-test markers emitted in two writes, on a shared console (swept 2026-08-31, **gated 2026-09-01** after the sweep was found incomplete)

*Added 2026-08-31.*

Several self-tests print a marker as a prefix and then a detail — `report("X: FAIL ")` followed by
`report(name)` — while the serial console is shared with every other ring-3 task. Another task's
output can land between the two writes and split the exact string a gate asserts on. It is not
hypothetical: `smoke-init-provision-control` failed on 2026-08-31 with
`INIT_PROVISION: FAIL provisioning stopped at step [fs_server] userspace FS server starting`,
and the gate timed out looking for a contiguous `stopped at step 1` that had been emitted in two
pieces. The arm had passed since it was written, on timing luck.

Ten instances were fixed on 2026-08-31. Six of the seven userspace cases share one
`kput_marker()` in `libhorus`, because the hazard is a property of the console rather than of any
individual self-test; the kernel's aspace test and `proctest` join locally, having no access to
that helper.

**That was recorded as closed, and it was not. Two more instances were missed, and one of them
reddened CI on 2026-09-01.**

`userspace/captest.c`'s `fail()` emitted `CAPTEST: FAIL `, the detail, and the newline as **three
writes**. Ten `smoke-captest-*-control` arms assert a contiguous `CAPTEST: FAIL <detail>`, so
every one of them was one unlucky interleave away from a spurious red. The sweep missed it for a
specific and repeatable reason: it searched for the shape it had just fixed —
`report(prefix); report(detail);` over `libhorus`'s helpers — and `captest` has a private `out()`
and does not include `libhorus.h` at all. `src/kernel/main.c`'s `DEFECT FLAGS: ` line was the
second, asserted by six gates and emitted in three writes.

**A latent defect and a second writer are the same defect; only one of them is observable.** The
captest instance was harmless while that image had exactly one ring-3 writer. `auditprobe` joined
it on 2026-09-01 (**S71**) and CI reddened on the very next PR:

```
AUDITPROBE: rotate_keys -> -1CAPTEST: FAIL
clock-resolution-finer-than-a-pit-tick
SMOKE FAIL: timed out after 40s without required marker
              'CAPTEST: FAIL clock-resolution-finer-than-a-pit-tick'
```

The marker **was** printed. The defect the arm exists to reproduce **did** reproduce. The gate
reported a timeout — which is what a broken runner looks like, so the natural response is to
re-run it and move on. That is the worst way for a check to be wrong, and it is why this is now
enforced rather than swept.

**The enforcement is `tools/check_split_markers.py`** (required job step, beside
`check_capslots.py` and `check_abi_structs.py` — the same "written down twice, nothing compares
them" class). For every consecutive run of single-write console calls, if the first call's
literal is a strict prefix of a marker some gate asserts contiguously, the build fails. It
deliberately does **not** flag ungated informational output: 91 multi-write runs exist and
rewriting them would be churn with no property behind it. The rule is not "never write twice", it
is "never emit a gated marker in pieces". Falsified four ways by
`tools/test_check_split_markers.sh` — a split userspace marker, a split kernel marker, an
*ungated* split that must **not** be flagged, and the unmutated tree, since three
"is it caught" arms are all satisfied by a checker that rejects everything.

**No runtime gate reproduces this, and that is now a decision rather than a gap.** Reproducing it
needs another task's output to land between two writes on demand; the interleave is timing, and it
did not reproduce in **0 of 12** local boots of the exact failing configuration even though CI
hits it. A control arm built on that rate would be a coin toss asserting a property. The property
is structural — a marker is one write — so it is checked statically, where it is decidable.

**And "a marker is one write" is not sufficient for a KERNEL marker.** `panic_str` writes one
byte at a time to a UART a ring-3 server owns, so a single call is splittable and the static check
cannot tell. See 2.6c, which is that hazard observed reddening CI on 2026-09-02.

### 2.6b ~~An account created after the install cannot be the first login after a power cycle~~ (**CLOSED 2026-09-02**, `SECURITY.md` **S76**)

The volume is sealed to **key slots** (**S61**) and `h_auth` calls
`users_unlock_and_restore(typed_password)` *before* it consults the account table, because on a
sealed volume the table it would otherwise read is the compiled-in one `users_init` seeded. An
account with no slot therefore opened nothing, the persisted table was never loaded, the account
was not found, and the login was refused -- **while working perfectly on a machine somebody else
had already opened**. That asymmetry is why it lasted: every test and every operator logs in as
root first.

`do_passwd` now grants a key slot when an administrator sets another account's password, and
records its index in `user_account.keyslot`. **Both halves already existed with no live caller** --
`storage_keyslot_add` had only a selftest, and the field's one assignment was also in a selftest --
which is the shape **S63**'s `storage_authorize_format` had before **S72** gave it one.

The installer asks for two passwords and lays down two accounts, so a machine comes up with an
administrator and an everyday login, either of which can open the disk. It also **deletes the
compiled-in `user` account**: a fresh volume's table is seeded from `users_init`'s RAM image, so
until 2026-09-02 every installed machine shipped a working login whose password is printed in this
repository.

Witnessed by `make smoke-installer-accounts`, which logs in as the **unprivileged** account first
on a machine nobody has opened; falsified by `PASSWD_NO_KEYSLOT=1`.

**What is still true** is narrower and worth keeping: a slot is granted only when an *administrator
sets a password*. `useradd` alone leaves the account locked and slotless by design, a user changing
their own password re-seals the slot they already hold rather than taking another, and a volume has
`HORUS_KEYSLOTS` (8) of them -- so a machine with more than eight password-holding accounts cannot
give them all one. Nothing warns at the eighth; `storage_keyslot_add` returns "full" and
`do_passwd` fails closed, which is the right direction but a poor message.

### 2.6c A KERNEL marker is splittable even when it is one write, and 2.6a's rule does not reach it

**Open.** *Added 2026-09-02.*

2.6a's model is "a gated marker emitted as two writes can be split by another task's output",
and its repair is "emit it as one write", enforced statically by `tools/check_split_markers.py`.
**For a marker printed by the KERNEL while ring 3 is running, one write is not enough**, and the
checker cannot see the difference.

`panic_str` is `while (*s) panic_ch(*s++)` — one byte to the UART at a time. `console_server`
owns that UART from a ring-3 task on another CPU (a deliberate second-writer arrangement, finding
**#126**, recorded in the comment above `kfault_begin`). A ring-3 write can therefore land between
any two **characters** of a single `panic_str` call. The claim `kfault_begin` takes serialises
kernel reporters against each other and against nothing else; `kfault_begin(1)`/`panic_begin`
halts other CPUs that try to *report*, which is also not ring 3. There is no lock the kernel can
take here, because the party it needs to exclude is a task it does not schedule out.

**Observed 2026-09-02**, CI run `33553525177`, job `smoke-kstack-park-control` on PR #289 — a PR
touching `userspace/shell.c`, documentation and a userspace-only build flag this gate never sets.
`src/kernel/scheduler.c:1660` emits

```c
kfault_str("\nPANIC: two CPUs parking on one kernel stack rsp=");
```

as a single call. It reached the wire as:

```
Us parking on one kernel stack rsp=0xffffffffc0010ff0 this-cpu=3 already-cpu=0 task=1 'hello'
KERNEL FATAL SHARED PARK STACK - halting
```

`\nPANIC: two CP` is gone — the line begins mid-word, ring-3 `PROC_SELFTEST` output having landed
inside the call. The gate's `KSTACK_PARK_RE = PANIC: two CPUs parking on one kernel stack` did not
match, and it reported:

```
boot 1/8: 5 park(s), none shared   ...   boot 8/8: 5 park(s), none shared
KSTACK PARK CONTROL: FAIL - the shared park did NOT reproduce in
  8 boots that ran to completion (0 more died and were not counted).
```

**Its own evidence dump, four lines below that sentence, contains the panic.** The defect
reproduced; the arm scored it a clean sweep of misses.

**Both of that gate's detectors failed at once, each for a reason already written down.** The
duplicate-`PARKTRACE` test needs two trace lines, and `sched_note_park` halts on seeing the second
CPU, so on the boot that reproduces hardest the second line is never printed — the #193 lesson,
which is *why* the panic fallback was added. The panic fallback then needs contiguity the console
cannot provide. Each detector covers the other's blind spot in principle and neither covers this
boot. Every `PARKTRACE` in that run was `cpu=0` while the panic reported `this-cpu=3
already-cpu=0`, which is exactly that shape.

Measured both ways on the same day: CI **FAIL** with the panic present in its own dump, and the
same arm on `origin/main` locally **PASS on boot 1 of 8**, caught by the duplicate-trace path
(`distinct CPUs parking: 2`) because there both CPUs printed before the halt. The arm is not
flaky about whether the defect occurs — it occurred in both — it is flaky about **which detector
sees it**, and one of the two is unreliable by construction.

**Why `check_split_markers.py` passes this.** The checker's rule is "a gated marker is one write",
and this marker *is* one write. The invariant is correct for userspace, where `sys_write` delivers
a buffer, and insufficient for the kernel, where the write is a character loop. A static check
cannot distinguish the two without knowing that `panic_str` is not atomic — so the hazard is
outside what the 2026-09-01 gating closed, rather than a regression of it.

**What the repair is not.** "Make the emission atomic" was the first proposal and is not
available, for the reason above. A shorter grep is a smaller probability, not a property, and
`0.4^N` reasoning about a detector is the framing CLAUDE.md's own park worked-example rejects.

**What it probably is.** A channel the kernel controls end to end. `isa-debug-exit` at port
`0x604` is already wired into every harness invocation and already written by
`src/kernel/kshell.c:99`; `tools/smoke_test.sh:146` says outright that it is "present for parity
with `make run`; not relied on here". A distinct exit code for the shared-park collision cannot be
split by any amount of console noise, and would make this arm's assertion exact rather than
probabilistic. That is a kernel change plus a harness change plus its own witness, and it should
be designed against the other kernel-marker gates rather than bolted onto this one.

**Scope is reasoned, not enumerated.** The mechanism applies to any gate matching a kernel-emitted
string while ring 3 is running — CLAUDE.md already records `DEFECT FLAGS: ` as asserted by six
gates and emitted from the kernel. Which gates are actually exposed has **not** been measured, and
this entry does not claim a count.

### 2.7 The VFS namespace is a name, not an enforcement boundary

*Added 2026-08-22 with roadmap 2.4.*

`userspace/hvfs.c` is a per-task mount table: a path prefix maps to a cspace slot holding that
filesystem server's endpoint capability, and crossing a mount point means sending on a different
slot. There is no VFS server, deliberately: one would have to hold a capability to every backing
filesystem, which is the monolithic trust 2.4 exists to avoid.

**What that enforces:** a task holding no capability for a mount cannot reach that subtree,
whatever path it writes. `hvfs_mount` refuses a slot holding no usable capability, and an empty
or wrong-type slot fails the kernel's IPC gate. That is `SECURITY.md` **S29**.

**What it does not:** a task that *does* hold a server's capability reaches **all** of that
server, regardless of where (or whether) it is mounted. Mounting `dev_server` at `/dev` does not
confine it to `/dev`; it only decides which server a `/dev/...` path is addressed to.
Confinement is the server's job (`fs_server` is a reference monitor over the kernel-attested
uid). A caller that reads a mount table and concludes a path is unreachable has concluded the
wrong thing.

Three smaller consequences of the same design:

- The table is per-task `.bss`, so no task can install a mount into another's namespace, and
  equally, a child inherits nothing. Namespace inheritance across `spawn` is roadmap 2.3.
- `HVFS_MAX_MOUNTS` is 4. It bounds how many mounts a task can NAME, which is not a security
  property; the capabilities it holds are.
- ~~**`hvfs` has no users in the ship build yet.**~~ **Migrated 2026-08-23.** `posix.c` and
  `shell.c` resolve paths through `hvfs_walk` / `hvfs_walk_parent`, so the shell, the libc and
  every coreutil share one walker. `libhorus.a` is linked into the newlib programs to make that
  possible; the collision the Makefile note feared does not arise, since nothing in `libhorus.o`
  is named `memcpy`.

  **This entry was wrong about `fsclient.c`**, which never had a walker: it does flat
  single-name lookups in the root, over a private `rpc()` with bounded retry and its own
  selftest markers that `hvfs_rpc` deliberately does not provide. It is left alone.

  **What the migration found** is recorded in `docs/ROADMAP.md` §2.4: `..` did not work below a
  mount root in any client, because `hvfs` asked the server for a `..` *entry* and `fs_server`
  creates none. Dead from #195 until 2026-08-23, and invisible because the only test for `..`
  used the pinned case, which returns before the lookup.

### 2.8 ~~The CSPRNG is safe by boot ordering, not by construction~~: CLOSED 2026-08-23

*Added 2026-08-22 from an external audit (its F-5), after checking the claim against the tree.
Closed 2026-08-23; the section is kept because what was recorded here was right and the shape
recurs.*

`RngState::fill()` (`rust/src/rng.rs`) did not test `self.seeded`. It would produce keystream
from whatever key was present, and the initial key is, in the file's own words, *"non-secret
startup constants"*, with a comment that the pool *"MUST be reseeded from hardware entropy
before its output is relied upon"*. That MUST was not enforced where the output is produced.

**It was never reachable, and the audit overstated it.** The finding claimed weak ASLR, canaries
and nonces from early use, and recommended *"panic or refuse output until `seeded=true`"*, a fix
that already existed one layer up. `entropy_init()` (`src/kernel/crypto.c`) gathers entropy,
then tests `rust_rng_is_seeded()` and **halts the machine** if it is false. It runs in
`kernel_main` before the first consumer, `aslr_init_seed()`.

What remained was narrower: a safety property held up by **the order of two calls in
`kernel_main`** instead of by the function that could enforce it; the same shape as the
frame-refcount hazard in #192, where a mapped frame was kept out of the free page stack only by
a refcount nobody had set on purpose.

**Closed.** `fill()` now returns false and zeroes the caller's buffer while unseeded (S30), and
the two C wrappers halt on a refusal. `rust_rng_u64()` went with it: returning a `uint64_t`, it
had nowhere to put a refusal, so it is `rust_rng_u64_checked(uint64_t *)` behind
`secure_random_u64()`. Witness `make smoke-rng-seed`, falsified by `smoke-rng-seed-control`
(`RNG_UNSEEDED_LEGACY=1`) and by `cargo test --features rng_unseeded_legacy`. The audit's own
recommendation is the one thing not taken: a panic inside `no_std` Rust reaches a
`#[panic_handler]` that is `loop {}`, so it would have hung the machine silently where the C
side halts with a `PANIC:` line the smoke harness already treats as fatal.

### 2.9 Measured boot degrades silently in the kernel when no TPM is present: *policy added
2026-08-23*

*Added 2026-08-22 from the same audit (its F-9), and partly overtaken by #197.*

`tpm_present()` returns false and boot proceeds: PCRs are not extended, and the volume key is
never sealed. Nothing fails, so on hardware without a TPM (or under QEMU without swtpm, which is
the default) **the measured-boot properties (S11, S12) simply do not apply** rather than failing
closed. The boot log says `tpm: no TPM present, measured boot skipped`, which is honest but easy
to read past.

**The CI half of this is closed.** Until 2026-08-22 the four TPM gates *also* degraded quietly:
they printed `SKIP` and exited 0 when swtpm was absent, so `smoke-tpm-seal` (a required
merge-gating job carrying S11 and S12) could report success while measuring nothing.
`SWTPM_REQUIRED=1` now makes that an error and CI sets it (#197). `make run` also boots with a
TPM when swtpm is installed, so the configuration the security properties are stated over is the
one you get by default.

**The kernel half is now an opt-in policy: `MEASURED_BOOT_REQUIRED=1`, 2026-08-23.** It was
recorded here as a design question rather than a defect, and the answer taken is the one this
section argued for: the default still boots on a TPM-less machine, because that is what a
research prototype needs, and a deployment that requires measurement builds with the flag. Under
it, an unavailable measured boot halts (no TPM, locality, transport, or PCR readback), and a
**persistent** volume that was never sealed is refused rather than unlocked on its password.

**The ephemeral vdisk is exempt, and that is the policy's one hole.** It is RAM-only, formatted
fresh each boot with a full-entropy key that is discarded at power-off, and never written where
a later boot could read it; there is nothing for a measurement to protect. Because the default
boot runs on exactly that volume, the refusal branch is unreachable in an ordinary run, which is
why `MEASURED_VOLUME_EXEMPT_NONE=1` exists: it removes the exemption so the branch executes and
can be falsified. **What is still not gated is a persistent disk under the policy**, the arm
proves the refusal fires, not that a real on-disk volume reaches it. That remains open.

**Default behaviour is unchanged**, which is deliberate: this is a flag, not a new default, and
S11/S12 still do not apply to a boot without a TPM. What changed is that a deployment can now
make them apply or refuse to run.

### 2.10 ~~Four live syscalls have no caller anywhere in this tree~~: CLOSED 2026-08-23

*Found 2026-08-23, while teaching the coverage deriver to evaluate the preprocessor.*

`SYS_CLEAR` (5), `SYS_SYSINFO` (6), `SYS_DEBUG_EXEC` (7) and `SYS_EXEC_LEGACY` (14) are dispatch
entries with real handlers in the ship build, and **no userspace wrapper exists for any of
them**, not in `include/syscall.h`, not in any program under `userspace/`. They are reachable
only by issuing the raw number, which any ring-3 task can do.

They were invisible for as long as they were: written as bare `[5]`-style indices, they did not
match the `[SYS_NAME]` pattern every coverage rule is built on, so nothing classified them,
nothing measured them, and nothing could fail on them. All four are now named, declared
`uncovered` with what was measured, and a bare numeric index is refused by
`tools/check_syscall_coverage.py`.

**What they are.** `SYS_CLEAR` clears the kernel VGA text buffer, which `console_server` has
owned since it took the framebuffer. `SYS_SYSINFO` returns a version string. `SYS_EXEC_LEGACY`
is the pre-ELF `(load_base, entry_offset)` exec, superseded by `SYS_EXEC` / `SYS_EXEC_NAMED` and
the Rust load planner. `SYS_DEBUG_EXEC` copies 127 bytes from ring 3 and, **under `DEBUG_SHELL`
only**, hands them to `process_user_command` with `SC_NONE`: no capability at all. That is the
"extra syscall surface" a `DEBUG_SHELL=1` build is already documented to carry (`CLAUDE.md` §6);
in the ship build it copies the string and returns −1.

**Deleted the next day, once the decision had been taken deliberately rather than inherited.**
All four dispatch entries are gone; the numbers are reserved as 38–45 are, and `SYS_DEBUG_EXEC`
survives only in a `DEBUG_SHELL=1` build.

**What tipped it from tidy-up to security fix** was reading `SYS_EXEC_LEGACY`'s table row. `{
h_exec, 3, CAP_RIGHT_WRITE|CAP_RIGHT_EXEC, SC_ANYTYPE }` (cspace slot 3, the legacy `CAP_FRAME`
every task is born holding) on a syscall that **creates a task**. That is exactly the shape
**[H-3]** closed on four other doors, and it sat directly beneath the comment explaining that
shape. Measured before removal: `passwdprobe`, uid 1000 with no delegated capability, called
syscall 14 and was handed task id 2.

The task it made had no identity: `create_task` assigns `state` and never `uid`/`gid`, so it
carried whatever the slot held, 0 on a fresh slot, the previous occupant's uid on a reused one.
Since **S18** uid 0 confers no kernel authority, but `fs_server` enforces file permissions
against the kernel-attested uid (**S13**/**S14**).

Witness `make smoke-passwd-probe` (8 checks), falsified by
`make smoke-passwd-probe-legacy-control`.

---

### 2.11 ~~A forked child does not inherit its parent's cspace~~: CLOSED 2026-08-28

*Open for one day, from the fork memory clone (#220) to the cspace clone.*

`SYS_FORK` now gives the child a **derived** copy of every capability the parent holds, in the
same slot (`cap_clone_cspace`, **S41**). The entry below is kept because the reason it was a
separate change is the reason the change is correct, and because it names the two defects the
control arms now reproduce on demand.

**Why it was not simply part of the memory clone.** A cspace is an array of `capability_t`, so
duplicating one looks like a `memcpy`, and that is wrong in two independent directions:

- **Identical serials.** `rust_cap_revoke_global`'s sweep nulls every capability whose `serial`
  matches the revoked root's, in **every** cspace, because a serial is supposed to name exactly
  one capability. Duplicate one and the child revoking its *own* slot destroys the parent's; 
  a cross-task revocation primitive available to any task that can fork, which is every task.
  Revocation is meant to flow *down* the derivation tree; this makes it flow sideways.
  Reproduced by `FORK_CSPACE_FLAT_COPY=1`.
- **No parent edge.** A fresh serial with `badge` left alone is not derived from anything, a
  second **root** of the capability graph holding the parent's authority. `mark_children_of`
  never marks it and its serial matches no revocation root, so revoking the parent's capability
  leaves the child's working. This is finding **3.3**'s shape, a capability keyed to a serial
  no sweep reaches, applied to a whole cspace at once. Reproduced by
  `FORK_CSPACE_ORPHAN_COPY=1`.

Both are avoided by not writing the copy at all: `cap_clone_cspace` calls
`rust_cap_grant_into` per slot, so a forked capability and a delegated one are the same object
by construction. **[H-3]** is what happens when two implementations of one idea drift.

**What is still not inherited**, and each is deliberate rather than pending: slots 0–3 and slot
4 (the child's own `CAP_TCB`, image frame and private reply endpoint: copying the parent's would
be impersonation, not delegation), `CAP_REPLY` by type (one-shot; two holders is reply forgery),
the port-I/O grant, the file master key, and every in-flight kernel rendezvous. A task with a
`CAP_FRAME` **mapped** still cannot fork at all (**S40**): that is now the only remaining
refusal, and it stands until a frame can be shared with the capability that names it rather than
without one.

**And the exec on the other side of it is closed too** (2026-08-28, **S42**). A cspace a child
inherits is only worth as much as what happens to it next, and the sequence a shell performs is
`fork(); exec();`: so `exec` was asked what it does to the capability graph, and the answer is
**nothing**: same capabilities, same serials, same badges, same position in the derivation
graph. Without that stated, an exec that re-minted what it kept would turn every inherited
capability into a **root**, undoing this section's closure one syscall later with no visible
symptom until somebody tried to revoke. `EXEC_ROOT_CSPACE=1` is that kernel; `make
smoke-forkexec` is the gate.

**What a shell still cannot do is narrow the child before it execs.** The child carries
everything the parent held, and the only subtraction available is the child revoking its own
slots before calling `exec`. A `SYS_CAP_DELETE`, or an exec that takes a keep-set, is the
natural next step and is not written.

**Namespace (mount-table) inheritance across `spawn` and `fork` is separately open**; see
roadmap 2.4. So are process groups, job control and `/proc`, roadmap 2.3.

---

### 2.12 What a device capability does not cover

**S43** landed 2026-08-28: a `CAP_IO_DEVICE` names one entry in the kernel's I/O-device table
and reaches only that device's frames, ports and interrupt lines. The things that property
deliberately does **not** say are listed below, because a device model that looked like it
enforced a boundary it does not is worse than one that never claimed to. Several have since
closed and are struck through rather than deleted, so the shape of what the capability covers
stays legible.

- ~~**DMA is outside it entirely.**~~ **Closed 2026-08-28 by VT-d** (**S45**). A device now has
  an address space of its own that starts **empty**, so it reaches exactly the frames its driver
  mapped with `SYS_DMA_ADDR` and faults on everything else. What remains true is narrower and
  worth stating precisely: the confinement is of **memory**, and only on a machine that *has* an
  IOMMU. `iommu_active()` is 0 where there is no DMAR; the kernel says so on the wire rather
  than pretending, and on such a machine this bullet still reads as it did.
- **PCI-to-PCI bridges are not walked.** The scan covers bus 0, which is every device on the
  machines this kernel targets. A device behind a bridge is *absent* from the table, so no
  capability can name it; the failure is un-delegatable hardware, not unmediated hardware.
- ~~**MSI/MSI-X are not routed.**~~ **Closed 2026-08-29** (**S47**, **S48**). `SYS_MSI_REGISTER`
  programs the device's MSI capability, and the vector is chosen by the kernel: there is no field
  in the ABI for a driver to name one, which is why a driver cannot aim an interrupt at a vector
  it does not own. The MSI-X vector table lives in a BAR rather than in configuration space, so
  `SYS_MAP_PHYS` refuses the page it occupies; otherwise a driver would write its own vector with
  no syscall involved.
- ~~**Bus mastering is not enabled by anything.**~~ **Closed 2026-08-28** by `SYS_DEVICE_ENABLE`
  (**S44**), which sets the three decode bits of the device a capability names and nothing else
  in configuration space. The DMA question above was answered rather than inherited: the
  capability decides **who** may turn bus mastering on and **for which device**, and the first
  bullet is what it still cannot decide. Note one measured caveat; QEMU does not enforce the
  bus-master bit for virtio-net, so on this emulator the bit is not what permits the DMA; `netd`
  sets it because real hardware requires it, and no gate can witness that half here.
- **A driver cannot learn a bus address without a device capability**, and that is deliberate
  rather than missing: `SYS_DMA_ADDR` requires the frame capability *and* a device capability. A
  physical address is a disclosure, and the two-capability rule makes it a disclosure to somebody
  who has no use for it. The original argument for that was "a bus-mastering device holder can
  already reach all of memory anyway", and **since VT-d landed that argument is no longer true**:
  the device reaches only what its driver mapped. The rule stands on the narrower ground that a
  device capability is what makes a bus address meaningful at all, rather than on a reach the
  IOMMU has since removed. A task that only retyped a page is refused (`make
  smoke-frame-dma-control`).
- ~~**A device translation outlives the frame that authorised it.**~~ **Closed 2026-08-29**
  (**S53**). `SYS_DMA_ADDR` installed an IOMMU entry and nothing removed it: `frame_map_refcount`
  counts CPU mappings only, so a device mapping neither kept the frame alive nor was torn down
  when it died, and `destroy_dyn_frame` scrubbed the run and returned it to the arena with the
  device still able to read and write it. `destroy_dyn_frame` now unmaps from every device domain
  before the scrub, and `task_teardown` resets a dying driver's domain. What is still **not**
  witnessed is the task-death half: reproducing it needs a driver holding a device capability to
  die under `SMOKE_IOMMU` while a peer still holds the frame, and no workload here does that yet.
- **The table is not enumerable.** `SYS_DEVICE_INFO` reports the device the caller's capability
  names and nothing else; there is no "list the devices" call, so holding one device is not a
  way to learn the shape of the machine. That is a deliberate omission, and it means a driver
  cannot discover a *second* device it might legitimately want, `init` delegates, or nothing
  does.

### 2.13 ~~A PCI interrupt line cannot be delivered to ring 3~~: CLOSED 2026-08-28

*This heading and the paragraph below it said the opposite until 2026-08-29, two days after the
entry was closed: the edit that struck them through was in a script that aborted before writing,
while a second edit appended the closure text successfully. The section therefore contradicted
itself on `main`; the exact drift `tools/check_doc_claims.py` gates numbers against and cannot
gate prose against. Recorded rather than quietly fixed.*

The IRQ → notification bridge was capability-gated and refused a line the caller's device did
not declare (**S43**), but could not **deliver** one: `pic_init` programmed the 8259 master with
`0xFC`, so IRQ 0 (the PIT) and IRQ 1 (the PS/2 keyboard) were the only unmasked lines, and bit
2, the cascade to the slave PIC, was masked too, so no line above 7 could arrive at all.

*Closed by **S46**. The entry is kept because the second question it raised is the one the fix
had to answer, and because what was found on the way is worth not rediscovering.*

A line is now unmasked when `SYS_IRQ_REGISTER` accepts a capability for it, which makes
unmasking the capability taking effect in hardware rather than a boot-time constant.

**The second question was the real work.** Legacy PCI interrupts are level-triggered: an
unserviced device holds its line asserted, so an EOI alone means immediate re-delivery, forever.
The kernel therefore masks a registered line when it fires and leaves it masked until
`SYS_IRQ_ACK`, see **S46** for why that is a security property and not a scheduling detail.

**What was found on the way:** the IDT had no gates for vectors 34–47. The stubs `isr34`–`isr47`
had existed in `lowlevel64.S` since the IDT was written and nothing ever installed a gate,
because the PIC masked every line above 1 so none could arrive. Unmasking without them is not
"the interrupt is ignored": a vector with no gate raises **#GP**, attributed to whatever was
interrupted, so the first PCI interrupt kills an innocent ring-3 task at a random instruction.
That is how it was found: `netd` died with `ring-3 trap vector 13` on the store immediately
after enabling its device's interrupt, and the store was not the problem.

**Routing moved to the I/O APIC on 2026-08-28**, which is what VT-d interrupt remapping needs,
remapping applies to messages from an I/O APIC or MSI, never to the 8259's direct delivery. The
8259 remains the fallback for a machine with no MADT entry and stays buildable
(`IRQ_FORCE_PIC=1`) so that path is exercised.

**MSI landed 2026-08-29** (**S47**): the kernel walks the capability list, allocates a vector
from a range it owns, and programs the device: a driver names a device and a notification and
never a vector. **MSI-X** is still absent, and **interrupt remapping** still is not on; both are
in §2.15. The teardown mask (a dead driver's line going down with it) is correct by construction
but has no arm of its own yet.

### 2.15 What MSI does not yet cover

**S47** puts vector choice in the kernel's hands. Three things about it are worth stating.

- **MSI-X is PROTECTED but not ENABLED, and the order is deliberate.** Its table lives in a BAR
  rather than in configuration space, so a driver could reach it with an ordinary `SYS_MAP_PHYS`
  of its own device's memory; the vector-choice argument had to be made again against a
  mechanism inside the driver's own reach, and *"the kernel writes it"* was not an available
  answer. **S48** is that answer: the page carrying the table is refused to the driver, for every
  device that has one, whether or not the kernel ever enables MSI-X.

  Enabling is deferred, and the reason is worth being blunt about. Bringing MSI-X up end to end
  needs per-device work that could not be **verified** here: on the one MSI-X-capable device in
  this tree (an 82574L) the cause-to-entry mapping lives in a register whose layout was not
  confirmed, an attempt at it produced no interrupt, and an interrupt that never arrives is
  indistinguishable from a driver that is simply wrong. Shipping a path that appears to work by
  guesswork is how a device ends up never interrupting on real hardware. So the protection ships
  and the enabling does not, which also means the door is shut *before* it is opened rather than
  afterwards.

  While MSI-X Enable stays clear the table is inert; that bit is in configuration space, which
  ring 3 cannot reach, so **S48 is defence in depth today rather than load-bearing**. A device
  offering only MSI-X is refused a message-signalled interrupt and falls back to its INTx line,
  rather than being handed a mechanism the kernel cannot drive.
- **A vector is never reclaimed.** `msi_clear_task` stops delivering to a dead driver's route but
  leaves the device enabled and the vector allocated. Freeing it means the next device allocated
  that vector inherits any message this one already put in flight; disabling the capability means
  writing configuration space of a device that may be mid-transaction. Sixteen vectors and
  sixteen delegatable devices, so exhaustion needs a machine larger than the table; the leak is
  the safe direction, and reclaiming needs a quiesce step this tree does not have.
- **Interrupt remapping still is not on**, and with MSI that finally matters in the way the I/O
  APIC work anticipated: an MSI is a memory write, so a device that could DMA anywhere could in
  principle compose a message itself rather than being programmed to. What stops that today is
  **S45**, the device's address space contains only the frames its driver mapped, and the
  LAPIC's message window is not one of them.

**One arm got weaker and has since been repaired, and the repair is the interesting part.**
`IRQ_NO_MASK_ON_FIRE` reproduces a livelock on the 8259 and **not** on the I/O APIC (QEMU does
not storm on that path) so the mask-on-fire property briefly had no emulator-observable
catastrophic consequence on the routing the ship build uses. The direct test that would have
fixed it, *"no notification arrives while the line is masked"*, was blocked by a real ABI gap:
there was no way to observe that a notification did **not** arrive, because `sys_wait_notify`
either returns (the property is broken) or blocks forever (the property held, and the test hangs
indistinguishably from a crash).

`SYS_POLL_NOTIFY` closed that gap, and S46 is now falsified **directly** on the I/O APIC path
(`make smoke-net-mask-control`) as well as through the livelock on the PIC path (`make
smoke-net-irq-storm-control`). The general lesson is worth keeping: a property of the form "no
event arrives while X" needs a non-blocking way to observe absence, or it can only ever be
witnessed through whatever catastrophe its violation happens to cause, and catastrophes are
environment-dependent in a way the property is not.

### 2.14 `netd` transmits but does not receive

`netd` completes the DMA round trip its gate asserts (the device reads its descriptor ring,
reads the packet buffer, and writes completion status back) and the ARP request it builds
appears on the wire byte-correct, verified with a QEMU `filter-dump` capture. The **reply does
not reach its receive ring**, and the cause is not yet known.

**Updated 2026-08-29: it is a property of ONE DEVICE MODEL, not of the driver.** The same
`netd`, the same code path, against QEMU's **82574L** (`e1000e`) receives the ARP reply on **5
boots out of 5**: reliably enough that `make smoke-net` gates on it. Against the **82540EM**
(`e1000`) a reply has been seen exactly once in many attempts. Two device models, one driver,
opposite outcomes, which localises the problem to the model, or to this driver's interaction
with it, rather than to the receive path in general. `make smoke-net-intx` keeps the 82540EM
exercised for its INTx and masking behaviour and does not assert reception.

*The paragraph below is kept as written, because its measurements are still the record of what
was ruled out.*

**Updated 2026-08-28, and the update sharpens it rather than closing it.** A reply *has* been
received once, into `netd`'s own ring, correctly parsed: so the receive path is **not
categorically broken**, which is what this entry previously implied. It was observed on a boot
where a second ARP request was sent while the driver was already listening. Adding a proper
retry loop (which the driver now has, because one request is not a protocol) did **not** make it
reproduce: 0 of 3 boots with retries, 0 of 5 before that. So the honest state is *intermittent
and not understood*, not *absent*, and one observation is not a property, which is why nothing
gates on it.

Recorded rather than hidden, with what was measured, because the next person to look should not
repeat it. Ruled out: the address filter (promiscuous mode changes nothing), the ring address
(`RDBAL` reads back exactly the value written), the descriptor layout (`RDLEN` correct,
descriptors zeroed and re-armed), the device reset (skipping it changes nothing), bus mastering
(`PCI_COMMAND` reads back `0x0106`: MEM, MASTER, SERR), and the IOMMU (it fails identically on a
machine with no DMAR at all). QEMU's `e1000x_rx_can_recv_disabled` trace fires exactly once,
early, before the driver has configured anything.

It is **not** a gap in **S45**: the property is about what a device may reach, and both
directions of DMA (device-reads-memory and device-writes-memory) are exercised and falsified by
the transmit path alone. It is a gap in `netd` as a *network driver*, and it is why roadmap 2.6
still has no IP layer above it.

### 2.17 hello_newlib is 1.2 MB of real code

Unlike the coreutils, `hello_newlib` is **not** mostly debug info: stripped, its text alone is
1,220,900 bytes. It is linked without `--gc-sections`, which the coreutils rule does pass, so it
retains every newlib object the archive offers rather than only what it calls. It is a gated
selftest binary rather than something the default image ships, so it costs nothing today, but
the same one-word difference is why `coreutils_echo` is 94 KiB and this is twelve times larger,
and it is worth fixing before anything else links the same way.

### 2.16 What the shared-library mechanism does not yet do

**S49** makes shared library text executable by many tasks and writable by none, and **S50**
makes a shared library's writable data private to each task; the half a libc needs, since of the
59 newlib symbols the shipped coreutils reference, three (`_impure_ptr`, `optarg`, `optind`) are
writable. Together they are the mechanism roadmap 2.5's remainder needs, and they are not yet
dynamic linking. Four things it does not do, stated because a mechanism that looked like a
linker would be worse than one that says what it is.

**One property is asserted more narrowly than it may read.** S50 gives each task a private copy
of the library's writable segment; it does **not** give the library per-task storage in any
richer sense. There is no TLS (`R_X86_64_TPOFF*` is refused with every other non-RELATIVE
relocation), and a task's copy is instantiated once when the library is endowed to it; nothing
re-initialises it, so a `fork` would need the copy-on-write path that ordinary user pages
already take rather than a second instantiation. Neither is exercised by a test today, so
neither is claimed.

- **It resolves nothing by name.** A caller indexes a fixed export table whose address the
  loader takes from the object's `e_entry`. Symbol resolution, walking `.dynsym`, matching
  `DT_NEEDED`, patching a GOT, is what makes a dynamic linker, and an index into a table is what
  this supports until one exists.
- **newlib is still statically linked.** The saving from SHARING it has not been taken yet.
  The mechanism can now carry it (S50 closed the writable-data blocker on 2026-08-29) and the
  shared object itself now builds and is gated (`userspace/libc.so`, the required
  `shared-objects` job): 135 KiB of shared text, 342 `R_X86_64_RELATIVE` relocations and nothing
  else, no undefined symbols.

**The stub archive landed 2026-08-29** and a program links against it: `hello_shared`, ordinary
C calling `printf` by name, carrying no libc: 106,392 bytes static against 13,088 shared. What
remains is migrating the **shipped** programs, which needs the kernel to endow ordinary tasks
with the library's capabilities.

  **One part of it still needs a GOT, and the limit is now exact.** A tail-jump thunk forwards a
  *call*; a reference to a **variable** is an address the compiler emits directly, and redirecting
  it needs a GOT. So `tools/gen_libc_stubs.sh` emits stubs for the 55 exported **functions** and
  none for the four data symbols, and the consequences differ per symbol:

  - `_impure_ptr` works anyway. It is a pointer *to* per-task state, so `crt0_shared` gives the
    program its own copy initialised from the library's, and both reach the one `struct _reent` in
    the library's private data (S50).
  - `environ` works the same way, and `crt0_shared` defines an empty one: the library's is empty
    too, so there is nothing for the two copies to disagree about.
  - `optarg`/`optind` **do not** and cannot. They *are* the state, and a program-local copy would
    diverge from the library's `getopt` that writes it. No stub is emitted, so a program needing
    them **fails to link**, the fail-closed outcome, and far better than one whose `optind`
    silently stops advancing.
  - `_ctype_` is const, so a local copy would be correct, but it is data all the same and gets no
    stub for the same reason.

  Measured: of the eleven shipped coreutils, `echo`, `true` and `false` need only `_impure_ptr`
  among data symbols and can move as they are; the rest use `getopt`.
  Note the figure that used to sit here was misleading: `coreutils_echo` was 404,572 bytes, but
  **77% of that was DWARF debug info**, not libc. Stripping what ships (2026-08-29) took it to
  94,172 and the eleven coreutils from 4,847,020 to 1,210,436 bytes in total. What sharing libc
  would still save is its ~70 KiB of text per program, real, and no longer the headline.
  Migrating newlib onto this mechanism is a build-system job, rebuilding it `-shared -fPIC`,
  relinking every program against it, and it gets its own commit rather than riding on the one
  that adds the mechanism.
- **The library's ASLR is per BOOT, not per task.** Shared text must be identical in every address
  space, so it is relocated once and mapped at that address everywhere; text needing per-task
  relocation would not be shared text. Since 2026-08-29 that address is **drawn at boot** from the
  same CSPRNG-seeded source the image loader uses rather than compiled in (**S51**), so it is not
  an address an attacker reads off the binary. The residual cost is real and stated: one
  information leak reveals the library for *every* task rather than for one, which is weaker than
  the per-process ASLR an ordinary PIE image gets. Per-task randomisation needs PC-relative code
  with a per-task GOT, which is where full dynamic linking goes.
- **Only `R_X86_64_RELATIVE`.** A shared object with an undefined symbol, a `JUMP_SLOT` or a TLS
  entry is refused at load rather than partially applied, because a half-relocated library is one
  whose calls go somewhere nobody chose. That is also why the demo object is built
  `-fvisibility=hidden`: an exported symbol can be interposed, so the linker emits
  `R_X86_64_64` against the dynamic symbol for it.

### 2.18 `SYS_RECEIVE_PROGRAM` cannot succeed, and the reason is a struct with two definitions

`struct program_header` is declared in both headers and they describe different things. The
kernel's (`src/include/kernel.h`) is an **ELF** program header — `type`, `offset`, `vaddr`,
`paddr`, `filesz`, `memsz`, `flags`, `align` — with four Horus staging fields appended
(`name[32]`, `size`, `magic`, `entry`): **104 bytes**. Ring 3's (`include/syscall.h`) is the
staging header alone, `{magic, entry, size, name[32]}`: **44 bytes**. One name, no compiler that
sees both.

It breaks the transfer in two independent places, and the second is why the first has never
been reached.

- **`h_receive_program` copies the kernel's size.** `copy_to_user(user_hdr, &k_hdr,
  sizeof(k_hdr))` writes 104 bytes into an object ring 3 sized at 44. The shell's `receive` and
  `load` commands declare `struct program_header h;` **on the stack**, so a successful transfer
  would write 60 bytes past it — and then read `h.name` at offset 12, where the kernel wrote the
  low half of `vaddr`.
- **The wire format disagrees too, and fails closed.** `loader_receive_to_staging` reads
  `sizeof(hdr)` = 104 bytes off serial port 2, but the uploader sends the 44-byte header
  `tools/mkheadered` writes, followed by the payload. So `magic` is tested at offset 96 against
  payload bytes, essentially never matches `0x55524F48`, and the command answers **"Bad magic"**
  every time. The overrun above is therefore unreachable, and the feature is simply broken.

**This is `SECURITY.md` S71's defect in a second struct**, found by the same question on the
same day, and it is filed rather than fixed because the two are not the same size of job:
S71's was a struct rename and a projection, this one needs a decision about what the loader's
**transport** format is before anything can be made to agree with anything. Fixing the export
without fixing the wire read would produce a transfer that still cannot succeed.

It is also **`§1.8`'s pattern for the third time**: `SYS_RECEIVE_PROGRAM` is on the `uncovered`
list, nothing enters the handler, and a feature that cannot work has sat in the shell's command
table unnoticed. Nothing found it by reading; it fell out of enumerating what crosses the ring
boundary.

**Gated, so it cannot be forgotten and cannot quietly change shape.**
`tools/check_abi_structs.py` now *discovers* every struct defined in both headers rather than
comparing a hand-written list — the rule that would have caught S71 — and `program_header` is
its one `UNRESOLVED` entry, carrying this section's number. The checker fails if it is removed,
if another unenrolled struct appears, **and if `program_header` starts agreeing**, at which
point the exemption has outlived its reason and this section should close.

## 3. Scale and performance limitations

### 3.1 Hard compile-time ceilings: **[I-7]**

| Resource | Limit | Where |
|---|---|---|
| Tasks | 256 **provisioned**, derived at boot | `g_max_tasks` (from the reserve; `MAX_TASKS` provisions it) |
| Capabilities per task | 128 in use, 256 slots | `MAX_CAPS_PER_TASK`, `CNODE_SIZE` |
| CPUs | 4 | `MAX_CPUS` |
| Static endpoints (well-known + per-task reply) | 128 | `MAX_ENDPOINTS` |
| Retyped endpoint descriptors | 256 | `MAX_DYN_ENDPOINTS`, indices from `DYN_EP_BASE` |
| Static notifications | 64 | `MAX_NOTIFICATIONS` |
| Retyped notification descriptors | 256 | `MAX_DYN_NOTIFICATIONS`, indices from `DYN_NOTIF_BASE` |
| Untyped arena, user half | 3.5 MiB | `UNTYPED_USER_BYTES` |
| Untyped regions namable at once | 64 | `MAX_UNTYPED` |
| Untyped arena, kernel reserve | 2.5 MiB (`MAX_TASKS` x (8 KiB cspace + 2 KiB TCB)) | `UNTYPED_KERNEL_BYTES` |
| IPC message | 256 bytes | `IPC_MSG_MAX` |
| Boot modules | 48 | `MAX_BOOT_MODULES` |
| Volume | 16 GiB **ceiling**; the actual size comes from the disk | `BLOCKS_PER_DISK` x `HORUS_BLOCK_SIZE`, clamped against IDENTIFY |
| File | 512 GiB, so the **volume** is the bound in practice | 12 direct + single + double + triple indirect, at 4 KiB blocks |
| Inodes | one per 32 blocks (128 KiB of volume) | `storage_format_sealed`; the inode bitmap spans blocks |
| Disk the ATA driver can address | 128 GiB | LBA28; `_Static_assert` in `storage.c` |
| Staged program image | 8 MiB | `LOADER_STAGING_BYTES` |

*This table said "Endpoints 64 / Notifications 64 … These are `.bss` arrays, not dynamically
allocated objects. There is no retyping discipline and no per-task kernel-memory accounting"
until 2026-08-15. Both halves had been false since **[I-7]** landed on 2026-07-27, in the same
document whose §1.2 records the fix.*

There **is** a retyping discipline. `CAP_UNTYPED` + `SYS_RETYPE` carve cspaces, endpoints and
notifications out of the arena (`src/kernel/untyped.c`), so creating a kernel object is an
exercise of authority the capability graph describes and the memory is attributable to the task
that holds the untyped capability. The static tables survive as a **shim** below `DYN_EP_BASE`
/ `DYN_NOTIF_BASE` for the well-known service objects and the per-task reply endpoints, which
the boot protocol names positionally; `endpoint_by_index()` is the single resolver and nothing
indexes `endpoints[]` directly any more. The dynamic ceilings above bound only the descriptor
arrays, not the objects.

**The task ceiling moved from 64 to 256 on 2026-08-30, and what was actually holding it down was
not what this section said.** It named `tasks[]` — the TCB table — as the thing to migrate. That
table is **72 KiB** at 64 tasks. `per_task_kstacks`, a static `.bss` array of one 64 KiB slot per
task, was **4 MiB**: fifty-six times larger, and 98% of the constraint. Migrating the TCB table
would have moved the ceiling by nothing at all.

The chain, since none of its links is visible from the array's declaration:

- `linker64.ld` asserts `__bss_end - KERNEL_VMA <= 16 MiB`, because the physical page pool starts
  at `USER_PHYS_BASE` and nothing else stops the image growing into it. `.bss` was 12.36 MiB, so
  a 4 MiB array left 3.64 MiB of headroom — `MAX_TASKS` could not even be **doubled**.
- That 16 MiB is not a policy number. It is `KERN_SPLIT_PDES` (8) × 2 MiB: the window where the
  kernel's own mapping uses 4 KiB pages rather than 2 MiB ones, and therefore the only window in
  which a guard page can be expressed at all.
- The headroom was not free either. GRUB stages the boot modules in the gap between `__bss_end`
  and the pool base, and nothing checks that. Growing `.bss` toward the assert eats the staging
  area silently.

So the stacks left `.bss` for a region of their own under `high_pdpt[511]` — one previously
unused PDPT entry, 1 GiB of kernel-half VA, inside the `pml4[256..511]` range every address
space shares, so a slot is visible everywhere with nothing to install per address space. Slots
are bound on first use and kept for the life of the boot (the lifetime the array had), the guard
page is **never mapped** rather than mapped and then unmapped — which removes the
before-`smp_bringup` ordering requirement instead of satisfying it — and a slot maps 8 of its 16
pages, making the unused tail a second guard against an overflow of the slot below. `.bss` fell
to **8.57 MiB even with `MAX_TASKS` at 256**, so the image is 3.8 MiB *smaller* than it was at 64.

**Three things scaled with the ceiling, and all three fail silently rather than loudly**, which
is why `make smoke-task-ceiling` exists: a boot uses about six tasks, all below 64, so every
defect this change could introduce lives in the range no boot visits. The witness asserts on the
alias pair (255, 191) — the pair each defect makes identical — and is falsified in two
directions (`KSTACK_INFLIGHT_LEGACY_WORD`, `KSTACK_SLOT_INDEX_TRUNC`).

The sharpest was `g_kstack_inflight`, the standing witness for **S20**: one `uint64_t`, bit *t*
per task, with `src/include/kernel.h` explaining in one line that *"MAX_TASKS is 64, so one word
covers every task exactly"*. A correctness argument about a witness in one file, resting on a
constant in another. At 256, `1ULL << t` is undefined for *t* ≥ 64 and x86 masks the shift to 6
bits, so the detector does not stop working — **it starts answering about the wrong task**, with
no report for a genuine collision above 63 and a spurious one below it. It is an array sized from
`MAX_TASKS` now, with the width asserted at compile time.

**[I-7] closed on 2026-08-30, and the three things that closed it are worth separating** because
each was blamed on the wrong thing at some point.

**The TCB table left `.bss`.** `tcb_t tasks[MAX_TASKS]` was the last kernel object class outside
the retyping discipline — every other one (cspaces, endpoints, notifications, frames) had moved
years of commits earlier, and this table was described in four documents as "its own change with
its own tests" for a month. It is `tcb_t *tasks`, one contiguous block carved from the kernel's
untyped reserve by `tasks_init()`. All 785 `tasks[id].field` sites compile unchanged, because
array indexing on a pointer is identical syntax — the change is tractable precisely because it is
a pointer rather than an array of pointers, which would have been `tasks[id]->field` at every one
of them and an extra indirection on the scheduler's hot path.

**The count became a property of the machine.** `g_max_tasks` is derived at boot from the reserve
`untyped_init` actually built, and 127 bounds across fourteen files read it. `MAX_TASKS` survives
only as the compile-time input that PROVISIONS the reserve; nothing branches on it. The boot
reports the number it arrived at (`tasks: 256 provisioned from the kernel untyped reserve`), so
the derivation is observable rather than asserted.

**And the thing that would actually have capped it was not `tasks[]` at all.** The revocation
sweep declared `cspace_desc_t spaces[MAX_TASKS + 1]` **on the kernel stack**, which nobody had
measured:

| `MAX_TASKS` | sweep's stack use | of a 32 KiB kernel stack |
|---|---|---|
| 256 | 6,168 B | 19% |
| 512 | 12,312 B | 38% |
| 1024 | 24,600 B | 75% |
| 2048 | 49,176 B | **150% — overflow** |

So the 64 → 256 raise had already spent a fifth of a kernel stack in the revoke path, and the
guard page below it was what stood between the next raise and silent corruption of the adjacent
slot. It is one allocated buffer now, shared under the `cap_lock` the sweep already holds
throughout. `task_running_cpu` and the S20 inflight witness moved with it.

**What remains is a provisioning constant, not a ceiling anything asserts.** `MAX_TASKS` sizes
the reserve; raising it costs pool frames rather than image budget, and no linker assert
constrains it. That is a scale parameter of the same kind as `BLOCKS_PER_DISK`, and it is listed
in the table above rather than tracked as a finding.

**The prerequisite named here for a month closed on 2026-08-30, and it was two defects rather
than one.** `cap_lookup` — the function every capability gate in this kernel resolves through —
ended in an unconditional fallback:

```c
if (cspace && slot < cspace_sz) { ...the caller's own cspace... }
else                            { ...root_cnode...              }
```

The half this document described is the first: a task with **no cspace** resolved every slot
against the primordial root cnode, which is why freeing a dead task's cspace would have been an
authority escalation rather than a crash. The half nobody had written down is the second: a task
asking for a slot **past the end of its own cspace** was handed `root_cnode[slot]` — the identical
escalation, reached by arithmetic instead of by a null pointer, and needing no missing cspace at
all.

**Both were unreachable, and both by circumstance rather than by property.** The first needs
`create_task` to keep halting rather than run a task whose cspace allocation failed; the second
needs it to keep setting `cspace_size = CNODE_SIZE` for every task — one assignment, in another
file, whose being a constant is the whole of the argument. Neither is a statement about
`cap_lookup`.

**The rule that replaced it was already in the file.** `caller_has_authority()` encodes
`cur == 0 || tasks[cur].cspace != NULL` for the *mutating* operations, precisely so the
`cspace == root_cnode` rights exemption in `cap_mint`/`cap_transfer` provably means "kernel
only". Task 0 is the kernel boot/idle/reaper task and legitimately has no cspace of its own;
every other task without one is now refused, and a slot past the caller's own cspace is out of
range rather than a reason to consult somebody else's.

Witness `make smoke-cap-lookup`, which **manufactures** both conditions — a refusal test whose
ungated path could not have succeeded witnesses nothing — and checks the third direction too,
that task 0 still resolves, since a `cap_lookup` returning NULL for everything would satisfy
both refusals while breaking every gate in the kernel. Falsified one arm per rule
(`CAP_LOOKUP_ROOT_FALLBACK`, `CAP_LOOKUP_RANGE_FALLBACK`); two arms because the witness returns
at its first failure, so an arm restoring both halves never reaches the second rule.

**Reclaiming a dead task's cspace landed on 2026-08-30, and the literal reading of that phrase
would have broken the system.** Every document here, this one included, said "free the cspace".
Two independent facts forbid returning its bytes:

- **The arena is a monotonic bump allocator, and that is a safety property.** `untyped.c`'s own
  header says so: *"With a free list, an object's bytes can be handed straight back out and
  retyped as a DIFFERENT class while a stale capability still names the old address — the classic
  type-confusion-through-reuse."* Returning a cspace's bytes reintroduces exactly that.
- **The kernel reserve holds exactly `MAX_TASKS` cspaces.** The watermark never rewinds, so a
  free-then-reallocate consumes a second cspace's worth for the same slot; after `MAX_TASKS` task
  deaths the reserve is exhausted and `create_task` halts the machine, because a task with no
  cspace must not run.

The codebase already had the right word, in `destroy_dyn_endpoint`: *"The bytes stay consumed in
the untyped region (bump discipline); only the **name** is reclaimed."* A cspace's bytes belong to
its task slot for the life of the boot, exactly as `cspace_pool[id]` did; what is reclaimed is its
**contents**.

**And that was the real gap, which no document had described.** `task_teardown` released every
device resource a task held — its IRQ route, its MSI route, its IOMMU domain, its port grant, the
console, its pipe ends — and left the **capabilities** in place. They sat in memory from the
task's death until its slot was next used, which may be never. Nothing could reach them, but only
because three separate readers each test `state == 0`: `mark_reachable` when deciding which
retyped objects are still named, `h_cap_enumerate` when reporting, and `create_task` when
overwriting. **The property "a task's authority ends when the task does" was held by three readers
agreeing about a flag, not by the data** — and a fourth reader that forgot the flag would have
found a full cspace. That is the same shape as the `cap_lookup` fallback above, and as **S38**'s
arena guard.

`cap_release_cspace` empties it at teardown, **before** `kobj_gc`, so the sweep sees an object
genuinely unnamed rather than one it is skipping on the strength of a flag; the two now agree by
construction. `create_task`'s zeroing stays, defending the first use of a slot rather than a dead
task's leftovers. Witness `make smoke-cspace-release`, which goes through `task_teardown` rather
than calling the function — a witness that calls the function under test proves the function works
and says nothing about whether anything invokes it — and checks the slot is still **reusable**
afterwards, since a teardown that destroyed the cspace outright would pass the emptiness check
while breaking task creation. Falsified by `CSPACE_KEEP_ON_TEARDOWN=1`, under which the dead task
still holds slot 0: its own `CAP_TCB`.

**And the next ceiling is now the arena's, which is why its halves were separated.** The arena is
split into a kernel half (the per-task cspaces, which no capability names and ring 3 cannot
reach) and a user half (`UNTYPED_ROOT`, what `init` delegates onward) — and the sizing did not
honour that split. The **total** was a fixed 4 MiB and the kernel half was carved out of it, so
raising `MAX_TASKS` silently **shrank what userspace could ever allocate**. That matters because
the user half is the number the documented denial-of-service reasoning rests on: `MAX_FRAME_PAGES`
is 64 pages precisely because a frame that could span the arena would starve every other object
class. A bound that moves when an unrelated constant moves is not a bound. The user half is the
fixed quantity now — 3.5 MiB, exactly what it was at `MAX_TASKS` 64, so no documented ratio
changes — and the kernel reserve is derived from `MAX_TASKS` and added on top.

### 3.2 ~~`this_cpu()` reads LAPIC MMIO on every call~~: **[I-6]**, fixed

`this_cpu()` now derives the CPU id from the TSS selector in `TR` (`cpu = (str() - 0x38) /
0x10`, a register read) instead of the uncached LAPIC MMIO read it used to do on every
`get_current_task()`. Every CPU already `ltr`s a distinct TSS (RSP0 and the IST stacks are
loaded from the running CPU's TSS), and the selectors are linear: `0x38` for the BSP,
`0x48/0x58/0x68` for the APs. In the non-SMP build it compiles to `return 0`.

`percpu_id_verify_self()` cross-checks the derivation against the LAPIC on each core as its
TSS is loaded and panics on disagreement; `make smoke-percpu` asserts that check ran on every
online CPU (and requires ≥2 cores, since on one CPU the mapping is right by accident).

**What remains.** This took the MMIO read off the syscall path, which is what made **[I-6]**
a performance/DoS finding. It did *not* introduce the `%gs`-based per-CPU block itself. That
was roadmap 1.2's other half, and **[C-3]** no longer waits on it: the per-CPU lock landed on
2026-08-11 holding its state in `MAX_CPUS`-indexed arrays (`irq_depth_pc[]`,
`irq_saved_if_pc[]`, `src/kernel/scheduler.c`), which `this_cpu()` indexes for the cost of a
`str` plus arithmetic. A real `%gs` block is still wanted for a current-TCB pointer and to stop
paying `MAX_CPUS` of cache line per datum, but nothing is blocked on it. See the note on
`this_cpu()` in `src/kernel/scheduler.c` for why `%gs` was not the right first step: the ring-3
return paths load a user selector into `%gs`, which zeroes the GS base, so a per-CPU base only
survives with `swapgs` in every ISR entry and exit.

### 3.3 SMP scheduling is naive

A shared runnable pool with a linear scan and no affinity, no load balancing beyond
"whoever asks first", no priorities beyond a stored-but-unused field, and no real-time
guarantees. Under TCG emulation four cores are measurably *slower* than one; the
multi-core benefit needs KVM or real hardware to appear.

### 3.4 No timers or clock

There is no `clock_gettime`, no per-task timers, and no timeouts on IPC. A blocked task
blocks until woken or killed.

---

### 3.5 ~~The block allocator rescans the bitmap from the start on every allocation~~ (**FIXED 2026-09-01**)

`storage_alloc_block` read data-bitmap block 0, then 1, then 2, until it found a clear bit. On a
nearly-full 16 GiB volume the bitmap spans 128 blocks, so an allocation near the end of a fill
read all of them — and a sequential write allocating N blocks did that N times.

It is a **rotating start hint** now: the scan begins where the last allocation succeeded and
wraps. The hint is a starting point and never a bound, which is what makes it safe to be wrong —
a stale value costs one wasted read, not a block the allocator fails to find. `ALLOC_NO_HINT=1`
restores the old behaviour.

**Measured, on a 2 GiB volume with 15 of its 16 bitmap blocks full** (`make smoke-alloc-hint`):

| | bitmap reads for 32 allocations |
|---|---|
| scan from block 0 | **512** — exactly 32 × 16 |
| rotating hint | **47** — 16 for the first, one each thereafter |

The gate asserts both halves, and the second is the one that matters: after the measurement it
fills the volume completely, frees a single block in bitmap block 0 — *behind* the hint — and
requires the next allocation to return exactly that block. It can only do so by wrapping. A gate
that measured the cost alone would pass a "fix" that made the allocator fast by giving up early.

It also refuses to conclude on a volume whose bitmap is one block, which is every volume below
about a gigabyte: `ALLOCHINT: FAIL the bitmap is too small for a scan to exist`. That is the same
reason the cost went unnoticed for so long — at 128 MiB there is no second block to scan, so the
old allocator and the new one read the same single block and no workload could tell them apart.

---

## 4. Functionality that does not exist

- **Networking.** No drivers, no stack, no sockets.
- **Graphics.** VGA text mode only; no framebuffer graphics, no windowing.
- **USB, sound, or any modern bus.** ATA PIO and PS/2 only.
- **Process groups, job control, and `/proc`.** `SYS_SPAWN`, `SYS_EXEC_*` and `SYS_FORK` all
  exist, and `fork` + `exec` is gated as a pairing (**S42**, `make smoke-forkexec`); what a
  shell still cannot do is group its children, put one in the background, or read `/proc`.
  *This bullet read "`fork` does not [exist]" for a day after it landed.*
- **Dynamic linking.** Every binary statically links newlib (~70 KiB of libc text each once
  stripped; the file used to look far larger because 77% of it was debug info, §2.16).
- **Multiple filesystems or mount points.** One `fs_server`, one volume.
- **Threads within a task.** One thread per address space.
- **Swap or memory pressure handling.** Pool exhaustion is a hard failure.
- **KASLR.** Userspace has 30-bit ASLR; the kernel is loaded at a fixed address.
- **IOMMU.** A DMA-capable device can read all of physical memory.
- **Signals beyond the basics.** No `SIGCHLD`, no job control, no process groups.
- **ARM or RISC-V.** x86-64 only, and the boot path is Multiboot2/BIOS (no UEFI).

---

## 5. Process and assurance limitations

### 5.1 No independent review: **[C-5]**

Horus is maintained by one person. The branch ruleset requires a pull request but sets
`required_approving_review_count: 0`, and every recent PR merged with zero reviews.

Automated verification is extensive; human verification is absent. **[C-1]** is the
demonstration of what that combination produces: a defect that passes every automated gate (it
builds, boots, and satisfies a 29-check capability conformance suite) because the suite tests
the property the author had in mind rather than the property the documentation claims.

The assurance Horus can honestly claim today is *"thoroughly automatically verified"*, not
*"independently reviewed"*.

### 5.2 Which tests gate a merge is reconciled by hand: **[C-6]**

`.github/workflows/ci.yml` defines **105** jobs, `codeql.yml` one more and `ruleset-audit.yml`
one more: **107** across the three, producing **110** status-check contexts. Ruleset `21815299`
requires all **107** today. Its predecessor `19007209` required **22** of them before
2026-08-16, and until 2026-08-15 exactly **zero** of those 22 were security gates: capability
conformance, kernel W^X, measured boot, boot-module tamper rejection, SMEP/SMAP presence,
flush-on-switch and stack-guard reseed could all fail while a PR merged green. The required set
was inverted, functional tests blocked merges, security tests did not.

**One of them is now fixed, and it is the one that mattered most.** `smoke-captest` is a
required check as of 2026-08-15. `SECURITY.md` names it as the witness for **eight** of its
S-numbered properties (S1, S5, S6, S7, S13, S13a, S13b and S18) so until that change the suite
establishing most of the security argument could not block a merge, and the exact defect class
**[C-1]** was would have merged green. That is no longer true.

(An earlier revision of this section, and the audit that prompted it, both said *nine*. Counted
off the witness column: eight. Recorded because "re-derive every number you cite" is a rule this
document is subject to, not merely one it states.)

**The mechanism behind it was closed on 2026-08-16; the gap itself narrows in two steps, and
only the first has landed.** When this finding was filed there were roughly 30 jobs and 21
required. There were 66 and 22 immediately before this change, because every gate added after
the ruleset was written landed in the advisory set *by default* and nothing forced the question,
twice at the cost of a security gate, `smoke-captest` until 2026-08-15 and the two [I-10]
durability gates on 2026-08-16, the latter advisory in the very commit that fixed the defect
they witness.

`.github/ci-gating.yml` is now the checked-in decision record: every job in `ci.yml` and
`codeql.yml` must appear under `required:` or under `advisory:` **with a written reason**, and
the `ci-gating` job fails the build if any job is in neither, in both, or names a job that no
longer exists. There is deliberately no default, because defaulting is the defect. It caught
CodeQL sitting unclassified on its first run.

**Since 2026-08-22 it also refuses a `required:` job that carries job-level `continue-on-error:
true`**: a gate that cannot fail. GitHub publishes such a job's check run as SUCCESS however its
steps exited, so the ruleset's requirement is satisfied by a job that failed outright, and the
classification this file exists to make explicit is undone one directory away.
`smoke-kstack-park` was in exactly that state for the whole window between its promotion and
this rule: #190 promoted it by editing `.github/ci-gating.yml` and the ruleset and touched no
workflow, and #191 then rewrote the job *name* one line above the mask to delete the word
ADVISORY from the published context: while leaving the mask. It was not idle. The job **failed
on `main` at 9476799**, and on `a59667ab` before that, inside runs GitHub reported green.
Nothing could have noticed: `ruleset-audit` compares context *names*, and a masked job publishes
the right name with the wrong verdict. Step-level `continue-on-error` is untouched and still
allowed; it lets one step be advisory while the job's own status still reports the truth, which
is how the `security` job keeps its scanners advisory without becoming unfailable itself.

That intended set is **107 required contexts and 3 reasoned exemptions**: `fuzz` (a 30-second
time-boxed search is evidence of effort, not absence), `kani` (manual-only, so it has no
conclusion to gate on), `ruleset-audit` (schedule-only, so it never runs on a pull request) and
`smoke-kstack-park` was a fifth until **[G-9]** closed on 2026-08-21; it was promoted on
2026-08-22 and **no exemption now stands for an open defect**. `smoke-fs-wal` was a third until
[I-11] was fixed on 2026-08-16 and it was promoted back, and `smoke-session-smp-soak` a fourth
until [G-8] was closed on 2026-08-17 and it was promoted with it: the last exemption in this
repo that stood for an open defect rather than for a property of the test itself. The promotion
list is justified by measurement rather than optimism: across 18 CI runs sampled on 2026-08-16,
64 of 66 jobs had **zero** failures over 1152 job-executions, and the only two that failed are
both on the exemption list or were deliberate.

**The ruleset was synced toward that set on 2026-08-16**, from 22 required contexts, with
`strict_required_status_checks_policy` true and no bypass actors. **Syncing it is a separate,
manual, lagging step: and getting that wrong froze the repository.** The first `--sync-ruleset`
was run from a feature branch, so it wrote the *intended* list, including three contexts `main`
could not yet produce: the `ci-gating` job itself and the two [I-10] journal gates. A required
context no workflow on the base branch produces **never reports**, so every pull request was
blocked on it indefinitely, and it looks like an ordinary red check, not a misconfiguration.
`tools/prune_unsatisfiable_checks.py` dropped the three (67 → 64) and now encodes the rule:
**never require a context the base branch cannot produce.** Promotion must lag the job landing
by one merge, never lead it. Every security gate the finding named, kernel W^X, SMEP/SMAP,
measured boot, boot-module and newlib tamper rejection, flush-on-switch, stack-guard reseed, the
64-bit heap, interrupt policy, per-CPU identity, the resume-`%rsp` guard, CodeQL, and the two
journal durability gates, now blocks a merge.

**What kept this finding open was that CI could not verify it stays that way**, and the
mechanism for that landed on 2026-08-17. Reading a ruleset needs the `Administration`
permission, which is not among the scopes a workflow `GITHUB_TOKEN` can be granted at all, so
the `ci-gating` job proves the classification is *complete* but not that the ruleset *matches*
it: the two could diverge through a change in the GitHub UI with nothing in CI noticing.
`.github/workflows/ruleset-audit.yml` now runs `--check-ruleset` daily as a **GitHub App scoped
to this repository with `Administration: read` and nothing else**: the token is minted per run,
expires within the hour, and cannot modify the ruleset it reads. Its log states the comparison
outcome explicitly (`live ruleset <id> : <n> required contexts, matches`, or `DIVERGED`, or `NOT
READ`), so a green run is self-evidencing rather than merely silent; the first live run could
only be shown to have read anything by falsifying it afterwards with a bad token.

That is a trade and it is written into the workflow header rather than left implicit, a
credential able to read repository administration now sits in Actions secrets, in order to
detect drift that requires administration access to cause. It is read-only, single-repository,
and revocable by uninstalling the App; the alternative was a check nobody runs, which is what
left the required set at 22 of 66 with no security gate among them.

**The App went live on 2026-08-19, and the audit is now a real check.** The scheduled run at
07:56Z that morning reported

```
jobs across 3 workflows      : 74
live ruleset 19007209        : 73 required contexts, matches
PASS: every CI job is classified, merge-gating, or exempted with a reason
```

and the run 24 hours before it had failed at the secret-presence step with
`RULESET_AUDIT_APP_ID` missing. The workflow itself has not changed since it merged, so the
difference is the App and its two secrets. That the comparison line printed at all is the
evidence: reading a ruleset needs `Administration: read`, which no workflow token can hold.

It failed loudly rather than skipping for every day it was unconfigured, which is why the
transition is legible at all, an audit that skips when unconfigured is a check that cannot fail,
and this repository has been bitten by that three times now (`make test`'s `|| true`, the
scanner-presence step before #154, and `smoke-kstack-park`'s job-level `continue-on-error`
above, which is the first of the three to have been *required* while it was unfailable).

**What keeps [C-6] open is now only the second half.** `--sync-ruleset` writes the ruleset and
needs an admin token, so a PR that adds a gating job leaves the ruleset one context behind until
someone runs it afterwards. This very commit demonstrates it: adding the `doc-claims` job took
the checked-in set to 74 while the live ruleset stayed at 73, and `--check-ruleset` reports
`DIVERGED (1 missing, 0 unexpected)` until the sync is run. Promotion lags a merge by construction; the audit is what makes the
lag visible the next morning instead of indefinitely. Read the count from the API or from that
job's log, never from this paragraph.

**Measured 2026-09-02, and the number to keep is not the lag but what fits inside it.** The
`installer` job -- the S73 witness, "a disk is erased only after the word that means erase this
disk" -- entered `required:` in `c0a9f2e` on 2026-09-01 and the ruleset was not synced. When it
finally was, the sync reported `103 -> 106` and named three additions: `installer`, plus
`store-locked` and `passwd-target` from the two merges that had each added a gating job in the
meantime. **Five merges landed in that window** (#287 through #291) with a job classified
merge-gating and not enforced -- and `smoke-installer` went red on `main` twice inside it,
where it could not have blocked anything.

**The audit is not what failed, and saying so is the point.** Its last scheduled run before the
change was 2026-09-01 12:35Z, five hours earlier; it passed correctly on the state it saw and had
not yet had a chance to fire. The lag is therefore bounded by the schedule rather than by
attention -- one day, at worst -- which is the guarantee this design actually offers. What the
`doc-claims` example above does not convey, and this one does, is that a day is not small when it
is measured in merges: the same person adds the job and holds the token, at different times, and
nothing in between refuses.

Two counts moved in the right direction since. `strict_required_status_checks_policy` is now
**true**, so a stale-base merge is no longer permitted. And the `security` job is a required
check whose scanner-presence step no longer carries `continue-on-error` (#154), so the job goes
red if the scanners are absent: a job that structurally could not fail now can. **`gitleaks` and `cargo-audit` findings now fail the build** (roadmap 4.3, 2026-08-30). Both are
reproducible — gitleaks matches fixed patterns against this repository and its history, and
cargo-audit resolves a lockfile against a dated advisory database — so a finding from either is a
fact about this tree rather than an artifact of a ruleset that moved. They run in their own step
above the advisory one, so `continue-on-error` cannot hide them.

The remaining four scanners' **findings** stay advisory, deliberately: `trivy` exits 0 on
findings, `cppcheck` and `flawfinder` pipe into `head` which discards the status, and
`semgrep --config=auto` fetches rules from a registry that changes with no commit here. Gating on
their content is what pinning those rulesets would unlock. Note that `cargo-audit` still depends
on an external advisory feed, so it can redden without a change here — that is accepted
deliberately: a newly disclosed advisory against a dependency *is* news about this tree.

### 5.2b ~~One required check is nondeterministic by construction~~ (**FIXED 2026-08-16**)
**[I-11]**

**Was:** `smoke-fs-wal` killed QEMU the instant a marker appeared on the serial console, then
rebooted on the same disk image. The marker proved the guest *reached* that point, not that its
journal writes had completed, so on a loaded runner boot 2 failed with `WAL_CRASHTEST: FAIL
read` against an unmodified kernel. The worse consequence was not the spurious failure but that
**a real WAL regression was indistinguishable from the race**, both produced the same output.

**The finding had two halves, and the [I-10] work closed one of them without saying so.** The
physical race is gone: barrier B is a real `FLUSH CACHE` and it runs *before*
`WAL_CRASHTEST: crashed-after-commit` is printed (`src/kernel/storage.c`), so by the time the
marker reaches the console the journal write the test cares about is already on stable media.
That could not have been said when this was filed, because the barrier did not exist.

**What remained was the diagnostic half**, and that is what the fix addresses. Boot 1 now ends
by asking QEMU to leave over its QMP monitor (`tools/qmp_quit.py`) and *waiting for the process
to exit*, rather than by signalling on a string match. The end of a run is a process exit; a
guest that reaches the marker and then fails to leave is a timeout, not a pass.

Roadmap 1.55 had prescribed `isa-debug-exit` for this. It does not work, and the measurements
are kept so nobody repeats them: on QEMU 10.0.11 a byte write to port `0x604` does **not**
terminate the process, with or without `-no-shutdown`, and the `lidt 0x0; int $0x0`
triple-fault fallback that `src/kernel/kshell.c:99` pairs with it faults while *reading* the
descriptor at address 0, so the kernel's own handler catches it and prints a `PAGE FAULT` the
harness correctly fails on. QMP `quit` shuts the block backends down cleanly and exits 0.

The harness fails **closed** rather than reverting to signalling: without `python3`, without an
executable `tools/qmp_quit.py`, or when the quit cannot be delivered, the run fails. A silent
fallback would be this finding again, wearing the fix's name.

Also fixed here: an exit the harness *asked for* was being reported as `SMOKE FAIL: QEMU exited
before the banner (triple fault?)`, because QEMU could die between the inner and outer liveness
checks, a window of microseconds, hit reliably in practice.

Witness: `make smoke-fs-wal`. **20/20 two-boot runs passed** on 2026-08-16 (`tools/`-driven
soak, one fresh 32768-block image per run). Falsified four ways, see `TESTS.md`; the decisive
one is that a serial log containing `WAL_CRASHTEST: crashed-after-commit` now **fails** when the
quit cannot be delivered, where the old harness scored that identical log a pass.

*Note on what the rate does and does not show.* 20/20 is the post-fix rate on this machine. The
pre-fix flakiness was load-dependent and did not reproduce here, so this is not a before/after
comparison; the substantive argument is structural (the marker alone can no longer pass, and
barrier B orders the write before the marker), and the rate is corroboration, not proof.

### 5.2c The SMP session soak: **[G-8]**, diagnosed and closed 2026-08-17

**Closed.** A task was published as claimable by another CPU while the CPU making the switch
was still executing ISR C frames on that task's kernel stack. `smoke-session-smp-soak` is
restored to **gating**.

*The mechanism.* Every switch path in `scheduler.c` (`preempt_on_tick`, `ipc_block_switch`,
`sched_yield_switch`) is called from `interrupt_handler64`, which runs on the outgoing task's
kernel stack: its C frames sit immediately below the trap frame the CPU pushed on entry.
Releasing `task_running_cpu[cur]` and dropping the scheduler lock there left this CPU with ~30
instructions still to execute on that stack: six callee-saved pops, a `ret` through a return
address on it, the floor guard, `fpu_restore`, a stack-protector canary read, four more pops and
a second `ret`, before `isr_common_stub64` reached `movq %rax,%rsp`. A CPU that claimed the task
inside that window resumed it to ring 3, and its next trap re-entered the ISR **on the same
stack, at the same depth, running the same functions**, rewriting exactly the words the first
CPU had not finished reading.

*Why it was invisible.* The overlap is exact, so the return addresses and the canary land back
at their own slots holding their own values: every frame validates, every `ret` goes where it
should, and only the data differs. The first datum out is the resume `%rsp`. That accounts for
the whole recorded signature, a plausible word from the wrong context (a `.text` return address
in one capture, `4` in another), a canary that passed, and a claim invariant that read
consistent.

*The correction this section owes.* The 2026-08-13 update below said the shared-stack hypothesis
had "nothing observed supporting it" because the one `t > 0` capture showed `task_running_cpu[4]
== 0` and `percpu_current_task[0] == 4`. **That is withdrawn.** A deliberately reproduced
collision prints `claim: task 4 running_cpu=3 percpu_current=[0,0,0,4]`; the invariant holds
*while two CPUs are on one kernel stack*, because it is true: the task is running on exactly one
CPU, and the other is merely still leaving. The instrument could not see this and never could.
The capture was never evidence against the hypothesis; it was evidence the invariant was scoped
to the wrong question.

*The fix.* The claim is held until the CPU has physically left the stack. `isr_common_stub64`
calls `sched_release_deferred()` immediately after `movq %rax,%rsp` (the first instruction at
which this CPU is provably reading a different stack) and the hand-over completes there. And the
property is checked rather than asserted (`SECURITY.md` **S20**): `g_kstack_inflight` carries
bit *t* for the duration of that window on task *t*'s stack, and `interrupt_handler64` tests it
on entry, halting if two CPUs are ever on one stack.

*The rate.* Paired, adjacent-boot alternating on one host, `-smp 4`, 1600 boots:

| Arm | Failures | Rate |
|---|---|---|
| `KSTACK_RELEASE_EARLY=1` (pre-fix release site) | 31 / 800 | 3.9% |
| shipped (deferred release) | **0 / 800** | 0% (95% upper bound 0.38%) |

Fisher exact, two-sided: **p = 6.9 × 10⁻¹⁰**. The 3.9% decomposes onto what this section already
documented: 13 of the 31 were caught at the collision by the new detector, and the other 18
(**2.25%**) ran on into a downstream failure, which is the 2–3% per boot this section has
carried since 2026-08-09, reproduced. An earlier run of the same design, on binaries predating
the detector's report deduplication, gave 44/800 against 0/800: a different total, an identical
**18/800** downstream subset.

`make smoke-kstack-race` and `smoke-kstack-race-control` settle it in seconds instead of at
~1 boot in 150: `KSTACK_RACE_WIDEN=1` stretches the window so it is entered on essentially
every switch, and is set in **both** arms, so the same widened window must be harmless with
the fix and fatal without it.

**The second path, closed the same day.** The `#PF`/exit fallbacks in `idt.c` resumed a CPU with
`frame->rsp = tasks[0].kernel_stack_top` when nothing else was runnable, and every CPU taking
one landed on that one stack. This was recorded here as an unwitnessed lead: one soak capture,
all four CPUs idle on task 0, `PANIC: dispatcher returned a bogus resume rsp=0xfee000b0`, the
LAPIC EOI register address and therefore a word out of another CPU's `lapic_eoi` frame. It has a
witness now.

*Why it read as latent.* On a healthy session the path is **never entered**, 0 parks in 3 boots,
measured with `KSTACK0_PARK_TRACE=1`. Tasks do not die, and when one does something else is
usually runnable. On a workload that kills tasks on purpose (`PROC_SELFTEST`, `-smp 4`) it is
entered **5–8 times per boot**, every park on the same `rsp`, and two CPUs were parked on that
one stack **2–3 times per boot, 3 boots of 3**. That is the difference between "unreachable" and
"unexercised", and only choosing the right workload distinguished them.

*The fix.* Each CPU parks on its own ring-0 stack (the one `enter_cpu_idle()` already uses) so
the fault path joins the kernel's single park mechanism instead of keeping a worse second one.
`sched_note_park()` records the choice and halts if two CPUs ever pick the same stack, so the
property is checked rather than intended. `make smoke-kstack-park` and its control arm gate it,
both asserting the same deterministic property: whether any one park stack was used by more than
one CPU.

*And it exposed a second gap.* The per-CPU idle stacks had **no guard page**, so `SECURITY.md`
S9 ("an unmapped guard page below every kernel stack") was false, independently of this finding,
since `enter_cpu_idle()` has always parked CPUs there. The guard is now the first page of each
slot, which leaves the stack *top* where `ap_trampoline.S` computes it and so needs no change to
the trampoline or its duplicated stride constant. `smoke-wx` / `smoke-wx-smp` enumerate the
family; falsified by disabling the arming, which reports `WX_SELFTEST: FAIL armed 0 AP
idle-stack guards, expected 4`.

The history below is the standing reminder of what a lead recorded rather than acted on costs,
in this case one day, and only because the next session went looking for it.

---

The record of how this was read wrongly, kept because the wrong readings are the point:

`smoke-session-smp-soak` failed at roughly **2–3% per boot**: 1 hang in 45 pinned to two host
cores, and 1 in 45 on a CI runner. Two distinct signatures were captured: one where the session
completes 9 of 12 checks and then stalls mid-output, and one where **boot never reaches the
login prompt at all** and the serial log ends at `[console_server] ready`. That second signature
is the `smoke-console-smp` deadlock's signature verbatim, and the open question was read for
weeks as whether that fix was incomplete. It was neither. It is **not** the IPC lost-reply race
(`#116` is in every tree measured).

**2026-08-13: the proximate mechanism.** A 150-boot soak at `-smp 4` on `ba84e90`, the first run
after #140 made kernel fault reports audible during a live session, caught it once. The fault is
a `#GP` **at the `iretq`** in `isr_common_stub64`: `interrupt_handler64` returned a resume
`%rsp` pointing into `.text`, the stub's 15 `pop`s loaded registers from instruction bytes, and
`iretq` took `CS` from those bytes. Proved rather than inferred: the reported `rbp` is
bit-for-bit the code bytes at `resume_rsp + 64`. `TESTS.md` has the disassembly. `#123`'s floor
guard did not cover that value: it is higher-half, so `rsp < 0xFFFF800000000000` passed it.
*(Superseded 2026-08-18: the guard is now bounded at both ends against `[__bss_start,
__bss_end)`, and a `.text` pointer is outside that range, so this capture's value would be
rejected and reported today. Detection only, see the ~7% note below.)*

**2026-08-13: a second capture, and two corrections.** A dual-arm run caught the fault again on
`main` at `e9aebdd`, in a boot carrying **two** corrupted resume values on two CPUs: a `.text`
return address, and **`4`**. It is not one bad write: no `saved_ksp` assignment produces `4`,
which correctly retired "find the line that stores the wrong value". The same run was the
control for **PR #135** (per-CPU IRQ lock): `main` 1/150, #135 rebased 0/150, not a significant
difference (Fisher p = 1.0) and no improvement claimed, but it established the fault as `main`'s
and unblocked that PR.

**2026-08-13: the guard was mute, and that was fixed and gated.** The guard's report was
bracketed `kfault_begin(1)`, and `kfault_begin(1)` is `panic_begin()`, whose claim is
**permanent**: a CPU that asks for it after another CPU's fatal exception halts *inside*
`panic_begin` without emitting a byte. In the two-event capture the fatal `#GP` on cpu 3 printed
first and kept the claim, so the guard **could not have been heard on that boot whether or not
it fired**. #140 made this report reach the UART but left it behind a claim the failure itself
takes away. Every "the guard did not catch it" statement about that capture was withdrawn then,
and `make smoke-resume-guard` / `-preclaim` / `-legacy` / `-nofloor` settle it in seconds.

**2026-08-13: a narrowing that was right about the window and wrong about the register.** The
guard-less arm showed a resume `%rsp` of `4` still present at `out->cs` faults at `0x94`, while
the capture faulted at `0x4` in the stub's first `pop`, so the value became `4` *after* the
guard. With the canary passing, that was read as "a register that did not survive". The window
was identified correctly and is the one closed above; the register reading was the wrong half,
because a callee-saved register restored from a slot a second CPU rewrote is both.

### 5.2d Claims leak and kernel stacks collide on the spawn/reap path under SMP: **[G-9]**

**Open, found 2026-08-17, pre-existing, and narrowed the same day**, one component fixed and
falsified, the rest still open; see the sub-section below. The original report follows as
written, because the leads it got wrong are part of the record.

Running `PROC_SELFTEST` at `-smp 4` violates the
claim invariant on roughly **40% of boots**. Nothing had ever run that workload at more than one
CPU: `smoke-proc` boots it uniprocessor, where it is clean.

Under `SCHED_INVARIANTS=1` the checker names it, always on the same task, task 3, the self-test
driver that spawns and reaps children:

```
PANIC: stale scheduler claim at preempt_on_tick: task 3 claimed by cpu 2
       but that cpu was running 0 (persisted across two audits; observed by cpu 1)
```

*"Persisted across two audits"* is the two-strike checker's own guard against crying wolf on a
mid-flight update, so this is a genuine leak rather than a transient.

**Both directions of the invariant break.** As well as the leaked claim above, a boot showed
`claim: task 1 running_cpu=-1  percpu_current=[0,0,1,0]`, a task **running with no claim**,
which `ARCHITECTURE.md` §7 names as the dangerous direction because an unclaimed running task is
selectable by a second CPU. The observed consequence is exactly that: two CPUs on one kernel
stack, reported by the stack canary in `h_write` (`stack smashing detected in function at
0xffffffff8010ebbc`, always `task=1`).

| Configuration | Boots | Failed | Stale-claim reported |
|---|---|---|---|
| `-smp 1` | 20 | **0** | 0 |
| `-smp 4` | 20 | 9 | 8 |
| `-smp 4`, pre-#162 release timing (`KSTACK_RELEASE_EARLY=1`) | 20 | 10 | 9 |

**The third row is why this is not [G-8]'s fix misfiring.** Restoring the pre-#162 release
timing gives 10/20 against the shipped 9/20: Fisher p ≈ 1.0, no difference. The leak predates
both G-8 fixes; what those fixes did was stop masking it. Before them the same workload failed
**20/20** on the shared park, and you cannot see a second defect while the first kills every
boot.

Without `SCHED_INVARIANTS` the failures present as a mix, which is why the checker was needed:
over 25 boots, 10 passed, 7 took a supervisor `#PF` (instruction fetch at `rip=0x2/0x12/0x82`,
i.e. a return through a corrupted pointer), 5 stalled with no marker, and 3 tripped the canary.

**Consequence for CI, now historical.** `smoke-kstack-park` **was advisory**, not gating: the
S20 park property it checks is sound and its control arm still reproduces the park defect on
demand, but requiring a workload that reddened for an unrelated defect teaches the re-run
reflex. It was promoted to **required on 2026-08-22**, one merge after [G-9] closed, with its
workload measured at 0 failures in 200 boots. It **stayed advisory** after the 2026-08-17
narrowing below and the 2026-08-18 close of [G-10]: the workload still fails **2 boots in 30**
(~7%), for a reason that is still not what the gate tests. Promote it in the same commit that
closes the rest of **[G-9]**, and quote a rate.

#### Measured 2026-08-27: the remainder is load-INDEPENDENT, and the gates stop watching too early

A 2×2 on `origin/main` (`{KSP_GUARD_INJECT, not}` × `{12 busy cores, idle}`) n=10 per cell, each
boot observed for a **uniform 25 s window** rather than until a marker (see below for why that
matters):

| Build | Idle | 12 cores busy |
|---|---|---|
| `PROC_SELFTEST=1 SCHED_INVARIANTS=1` | **1/10** | **1/10** |
| …`+ KSP_GUARD_INJECT=1` | **4/10** | **4/10** |

**Load makes no difference.** That corrects the obvious hypothesis, which was also the one that
prompted this measurement: a CI failure looked load-induced, and it is not. What CPU contention
changes is *whether a gate is still observing when the violation happens*, not whether it
happens. The rate on the shipped-workload build (no defect flag of any kind) is **2 in 20**,
consistent with the "2 in 30 of these boots" the `smoke-exec-reenter` target already records.

**`KSP_GUARD_INJECT` roughly quadruples it** (1/10 → 4/10), which is expected rather than
surprising: that arm forges a bogus `%rsp` so `task_exit_switch` is refused and the CPU parks,
and parking mid-switch is precisely the shape that strands a claim.

The signature, on the clean build, is not merely an idle CPU holding a claim:

```
PANIC: unclaimed running task at preempt_on_tick:  task 1 claimed by cpu 0 but that cpu was running 3
PANIC: unclaimed running task at enter_cpu_idle:   task 1 claimed by cpu 0 but that cpu was running 2
```

; a CPU holding a claim on one task **while running another**, persisting across two audits.

**Why no gate reports it, and why that is deliberate.** `smoke-exec-reenter` runs exactly this
build with `FAIL_MARKER='PANIC:'`, and throws the per-boot verdict away on purpose; the target
says so in an inline note, gating on completion "would make this pair a detector for that, not a
witness." That is a defensible choice while the finding is open, and it is recorded here so the
two facts sit together: the rate is known, and the gate that could see it is deliberately
looking elsewhere. **When the remainder of [G-9] closes, that `rc` becomes assertable**, and
picking it up is part of closing it.

**The measurement window is the methodological point.** Every one of these gates stops at its
`REQUIRE_MARKER` and quits QEMU, so a violation later in the same boot is invisible *by
construction* rather than rarely. The 2×2 above only shows a stable rate because each boot was
observed for a fixed span instead. A first attempt at this measurement used a different marker
and produced 6/10 for the same cell; the instrument was changing the observation window, which
is the [G-8] trace lesson in a new place.

#### Narrowed 2026-08-17: one component found, fixed, and falsified: the rest still open

**[G-9] as filed was a cluster, not one defect.** One component is now closed; the remainder is
not, and the finding stays **OPEN**.

The `sched_enter_user()` lead recorded above was **wrong**, and is retained rather than deleted
because the reason it was wrong is reusable: it does bypass `isr_common_stub64`, but every one
of its callers is a boot-time path on the BSP where no deferred release is ever pending, so it
cannot leak. Two further hypotheses died the same way: the unguarded "defensive claim" in
`preempt_on_tick`, and `create_task()` inheriting a stale claim through slot reuse. Both are
real shapes; neither is what fires. Probes beat reading, three times over.

**The component that was found.** `g_exec_reenter_task` was a single global naming the task
whose exec re-entry was pending, and `idt.c` consumed it on the exit of **every syscall on every
CPU** with no test that the exec belonged to the CPU reading it. An exec armed on one core was
routinely taken by another, which then claimed the exec'ing task, installed its CR3 and resumed
the trap frame the exec tail had just fabricated, while the core that actually ran the exec was
still executing on that same frame, at the top of that task's kernel stack.

That one race produces all three signatures recorded above: the leaked claim (the thief abandons
what it was running without releasing it, because `exec_reenter_switch` is written for the case
where the incoming task *is* the outgoing one and so has no release at all), the opposite
direction, and two CPUs on one kernel stack. It was caught in the act by a probe:

```
CLAIMORPHAN: cpu 0 entering task 1 at exec_reenter_switch while still claiming live task 3
  percpu_current=3  deferred=-1  state=1
```

`percpu_current=3` while entering task 1, a CPU consuming an exec re-entry for a task it was not
running, which violates that function's own contract.

**The fix** is per-CPU storage plus accessors (`exec_reenter_arm` / `exec_reenter_take`,
`kspawn.c`): the sharing is removed rather than guarded. A one-comparison assertion in
`exec_reenter_switch` (`SCHED_INVARIANTS` builds) is the standing witness that it stays removed.

**Falsification**, `EXEC_REENTER_GLOBAL=1` restoring the shared slot, 30 and 20 pinned boots at
`-smp 4`:

| Arm | Boots | Pass | exec-steal | stale claim | CPL-0 fault | stall |
|---|---|---|---|---|---|---|
| fixed | 30 | 22 | **0** | 2 | 6 | 0 |
| `EXEC_REENTER_GLOBAL=1` | 20 | 10 | **5** | 0 | 4 | 1 |

0/30 against 5/20 is Fisher p ≈ 0.008. The workload's overall failure rate falls from ~45–50%
to ~27%.

**What was still open after the exec fix.** Two residues, and neither was the exec race:

- a stale claim that appears in the **boot/spawn phase, before any exec runs** (2 in 30, e.g.
  `task 1 claimed by cpu 3 but that cpu was running 0`, immediately after `PROC_SELFTEST: begin`);
- a CPL-0 fault at **~20% of boots** (6 in 30), `vec=14 errc=0x2`: a supervisor *write* to a
  non-present page, resolving to `lapic_eoi` and `interrupt_handler64`. A CPU taking an
  interrupt on a CR3 that does not map the LAPIC is an address space that became reachable
  before its kernel half was built, which points at **[G-10]** below rather than at the
  scheduler.

**The second residue was [G-10]'s page-table use-after-free, and closing it (§5.2e) took the
first one with it.** Both the LAPIC fault and the boot-phase stale claim disappear: recycled
page tables under a live core corrupt whatever the freed frames are handed out as, and scheduler
state is as good a target as any. Measured on the ship config the gate actually builds,
`PROC_SELFTEST=1` at `-smp 4`, pinned:

| | Boots | Failed |
|---|---|---|
| before either fix | 20 | 9 (~45%) |
| after both | 30 | **2** (~7%) |

**What was still open in [G-9]** was that last ~7%, and it took three more components to close:
two real defects and, finally, a fault in the checker itself. It presented as a bogus resume
`%rsp` handed back by the dispatcher, with the claim invariant broken in the *unclaimed running
task* direction:

```
PAGE FAULT at 0xfffffffffffffff1 err=0x2(not-present,write,supervisor) task=1 'argtest'
  rip=0xffffffff801046f4 cs=0x8 rsp=0xfffffffffffffff9 rbp=0x0 cpu=3
  claim: task 1 running_cpu=-1  percpu_current=[0,0,3,1]
```

`rsp` is `-7` and the fault is at `rsp - 8`: a push onto a garbage stack pointer, i.e. the ISR
epilogue loaded `-7` as the kernel `%rsp` to resume on.

**The floor guard that exists to catch exactly this did not fire, because it had no ceiling:
fixed 2026-08-18.** `interrupt_handler64` rejected a resume value with `if (rsp <
0xFFFF800000000000ULL)`: a floor and nothing else, so it caught a returned `0`, `1` or `4` and
let every small *negative* value through, `-7` being `0xFFFFFFFFFFFFFFF9` and above the floor. A
guard whose own comment said it was there to catch "a returned 0/1/-1" tested for two of those
three.

It is now bounded at both ends, and bounded from the **linker** rather than a constant. A stack
that moves still satisfies such a bound; one allocated somewhere new fails loudly instead of
silently widening the guard.

> **That bound was wrong for one commit, and the correction is the more useful record.** It was
> first written as `[__bss_start, __bss_end)` alone, on the premise that *every* 64-bit kernel
> stack is a `.bss` array, `per_task_kstacks[]` (paging.c), `ap_idle_stacks[]` (smp.c), and
> `stack_top` / the IST stacks / `early_handler_stack_top` (multiboot.S). Four of those five are.
> **The IST stacks are in `.data`**, emitted in `multiboot.S`'s block beside `gdt64`/`tss64`.
> IST1 serves `#DF`/`#GP`/`#PF` and this guard halts on a rejection, so that kernel died on the
> first ring-3 page fault of any workload that took one: `bogus resume rsp=0xffffffff801a9f50`,
> an address `0xf50` into `ist1_stack_bottom`'s page. Ten CI gates went red at once, every one a
> userspace workload.
>
> The guard now accepts `[__bss_start, __bss_end)` **or** `[ist1_stack_guard, ist3_stack_top)`.
> The premise had been checked against the `.bss` arrays it named and never against the three
> objects it got wrong.

Witnessed by `make smoke-resume-guard-negative` (inject `-7`, the report must appear) against
`make smoke-resume-guard-negative-control` (`RESUME_GUARD_FLOOR_ONLY=1` restores the floor-only
test, the report must be **absent**).

Witnessed in the other direction (the direction whose absence let the `.bss` bound ship) by
`make smoke-resume-guard-ist` (no injection; the captest workload faults through IST1 and must
reach `CAPTEST: PASS` with the guard silent) against `make smoke-resume-guard-ist-control`
(`RESUME_GUARD_BSS_ONLY=1`, the false rejection must be **present**). Every other arm on this
guard injects a bogus value and asks whether the report appears, so all of them measure false
*negatives*; a predicate that rejected the whole address space would pass the lot, and one that
rejected the IST stacks did, with the resume-guard CI job green throughout.

#### Narrowed again 2026-08-20: four producers ruled out, and the fault located

The `-7` above is one signature; it is not the only one, and the search is now much smaller.

**It reproduces, and the earlier "does not reproduce" was a broken harness.** Pinning is what
opens the window, `tools/stress_boot.sh` pins to two host cores for exactly this reason, and an
unpinned run measures nothing:

| Tree | Pinned boots (`PROC_SELFTEST=1`, `-smp 4`, host cores 0,1) | Failed |
|---|---|---|
| `5fb95fe` (before 2026-08-20's work) | 40 | 3 (~7.5%) |
| `b36bc0f` | 40 | 1 |
| `d07b980` + the guard below | 57 | 2 |

**The fault is the same every time, and it is not a wild pointer.** Symbolised against the
`kernel.elf` that produced it:

```
PAGE FAULT at 0xffffffff806fa0a0 err=0x2(not-present,write,supervisor) task=1 'exectest'
  rip=0xffffffff80106658 cs=0x8 rflags=0x10086
  claim: task 1 running_cpu=0  percpu_current=[1,0,3,1]

  rip  0xffffffff80106658 -> interrupt_handler64 + 0x4a8
  addr 0xffffffff806fa0a0 -> ap_idle_stacks + 0x90a0
```

`AP_IDLE_STACK_SIZE` is `0x9000` and slot `c` is `[guard page][stack]`:

| slot | guard | stack | top |
|---|---|---|---|
| 0 | `0x00000`–`0x00fff` | `0x01000`–`0x08fff` | `0x09000` |
| 1 | `0x09000`–`0x09fff` | `0x0a000`–`0x11fff` | `0x12000` |

So `0x90a0` is `0xa0` into **CPU 1's guard page**, which is to say `0xa0` *above slot 0's stack
top*. `ap_park_stack_top(0)` returns exactly `0x9000`. The faulting address is therefore not a
corrupted pointer at all; it is a stack pointer that has ended up **above the top of the stack
it belongs to**, and slot 1's guard page happens to backstop slot 0's top as a side effect of
the layout. Whether that is an underflow on the park path or a top used with a positive offset
is not yet established, and this section will not guess.

**Two eliminations, both measured.**

1. **The claim invariant is intact in every capture from this run**, `running_cpu=0` with
   `percpu_current[0]=1`. The "unclaimed running task" description above belongs to the older
   `-7` signature and is *not* what this one shows. Two different things have been filed under
   one number.
2. **The four `saved_ksp` producers are ruled out.** `preempt_on_tick`, `ipc_block_switch`,
   `sched_yield_switch` and `task_exit_switch` all now validate the value they return, against
   the page tables rather than an address range, and **the guard did not fire once in 57 boots
   that included a reproduction.** Whatever produces this does not come through them. What is
   left is `exec_reenter_switch`, the page-fault path, and the possibility that the resume value
   was never wrong; that the CPU was *already* running on a bad stack when the interrupt
   arrived.

**Why a range check could never have caught it.** `per_task_kstacks`, `ap_idle_stacks` and
`ap_ist` all live inside `[__bss_start, __bss_end)`, and their guard pages are armed by being
made **absent**, not by being placed outside any range. A pointer that has walked into a guard
page passes every address-range test in the tree and then takes a not-present supervisor write
the moment anything pushes to it. The predicate now asks the page tables
(`kern_addr_present()`), which is the only thing that can distinguish a live stack from the
guard beside it.

**This does not fix the ~7%.** The guard is a detector: closing its blind spot converts an
obscure fault inside the ISR epilogue (a banner naming the stub and nothing about where the
value came from) into a line that names the value, the task and the CPU. What produces `-7` is
still unknown at the time, and that was what remained of **[G-9]** until 2026-08-21.

**[G-9] CLOSED 2026-08-21.** Three further components, in order of discovery:
`sched_enter_user()` carried a second copy of the ISR epilogue that omitted
`sched_release_deferred` (latent); `task_exit_switch()` committed a switch before validating the
resume value, and `ksp_refuse()` returns `0`, which is also that function's legal "nothing
runnable, caller parks" return, so a refusal orphaned the claim it had just taken; and (the last
and largest) the claim auditor's own exemption, `percpu_deferred_release[]`, was cleared
*before* the lock that drops the claim, so an audit landing in that window accused a release
that was in flight. **That final component was a false positive of the checker, not a scheduler
defect.** Natural rate 9 in 200 boots → 0 in 200 (Fisher p = 0.0036); mechanism proven
deterministically, 8/10 against 0/10 with the window widened in both arms (p ≈ 0.0007). Full
account in
[`investigations/G-09-scheduler-claim-leak.md`](investigations/G-09-scheduler-claim-leak.md).

**Widened 2026-08-21.** The same claim leak was observed in the **default boot** workload (task
4, the shell, on an idled CPU) at 1 boot in 120, not only in `PROC_SELFTEST` at `-smp 4`, which
is how this finding had been scoped. A control on the preceding commit was 0 in 270, but the
difference is not significant (Fisher exact, p ≈ 0.31). See
[`investigations/G-09-scheduler-claim-leak.md`](investigations/G-09-scheduler-claim-leak.md).

An earlier measurement of this fix reported 0 claim panics in 20 boots. It was taken with
diagnostic scaffolding that scanned every task slot on every ISR exit, and the perturbation hid
both residues; the table above is the unscaffolded run and is the one to trust. Recorded because
"the instrument changed the result" is the failure mode this section keeps rediscovering.

### 5.2e The spawn/exec path is process-wide singleton state, unserialised: **[G-10]**, closed

**Found 2026-08-17; closed 2026-08-18 in three parts** (page tables, then the authority half,
then the staging window). Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needs in flight lived in
file-scope singletons, with nothing serialising two CPUs through them:

| State | Then | Now |
|---|---|---|
| `loader_staging`: the one ELF staging buffer | unserialised | still one buffer, but every arm → consume window is bracketed by `spawn_stage_acquire()` |
| `g_args_argc`, `g_args_total`, `g_args_strbuf`, `g_args_len`, staged argv | unserialised | same bracket |
| `g_spawn_stdio_spec`, `g_spawn_caller` | globals read long after they were written | **gone**, parameters of `do_spawn_stdio` / `wire_child_stdio` |
| the armed image itself | anybody's to spawn | owned by the task that armed it (§5.2f, **[G-11]**) |

`g_exec_reenter_task` (§5.2d) was one instance of this pattern and became per-CPU. Per-CPU is
deliberately *not* how the rest was fixed: a staging buffer per core is `LOADER_STAGING_BYTES`
of real memory for state that is logically per-*spawn*, so the window is serialised instead.

Two consequences, of different severities; both of them past tense since 2026-08-18, and stated
here as they stood because the order in which they were understood is the useful part:

- **Correctness.** Concurrent spawns interleaved through one staging buffer, and a CR3 could
  become reachable before `create_user_pagedir` had populated its kernel half, which is exactly
  what a supervisor write-fault in `lapic_eoi` looks like, and was the ~20% residue in §5.2d.
- **Authority.** `g_spawn_caller` was written at `do_spawn` entry and read much later by
  `wire_child_stdio`, so a child could have its stdio wired from **the wrong parent's cspace**; 
  capability inheritance from a task that never spawned it. That is an authority question, not
  merely a correctness one, and it is why this was filed rather than left as a TODO.

#### The page-table half: fixed and falsified 2026-08-17

**Reproduced, diagnosed and closed the same day.** The "not yet reproduced" note this paragraph
replaces lasted about an hour, because the probe that settled it was cheap: record the CR3 each
CPU has loaded (`percpu_cr3[]`, written by `switch_cr3`) and ask, at the moment of reclaim,
whether anyone else still holds the one being freed. It fired on **19 boots in 20**.

```
CR3UAF: freeing the address space of slot 1 while cpu 3 still has it loaded
        (cr3=0x2c1f000, that cpu is running task 0 '')
```

`create_user_pagedir()` reclaims the previous occupant of a slot before rebuilding it, and
justified freeing with a comment that is worth quoting because the error is so easy to make:

> *"Safe here and nowhere earlier: the caller is on the kernel CR3, so the tree about to be
> freed is not the one any CPU is walking."*

That is **uniprocessor reasoning**. It establishes only that *this* core has left the tree. Two
others routinely have not:

- a CPU whose last runnable task died parks in `kernel_idle()` **without ever reloading CR3**,
  so it keeps translating through the dead task's tables for as long as it stays idle; the
  common case, and the one the probe caught;
- **`SYS_KILL` marks a task dead from another core while it is still executing in ring 3.**
  Nothing IPIs it, so it runs on until its next tick, and the slot allocator (`kspawn.c:167`)
  asks only for `state == 0`; it consults neither `task_running_cpu[]` nor whether any CPU has
  that CR3 loaded. A spawn can therefore recycle the page tables of a **running** task.

The freed frames went straight back to the free list and were handed out as ordinary pages, so
the other core carried on reading and writing through page tables that had come to describe
somebody else's memory. **That is a cross-address-space read/write primitive reachable from ring
3, not merely a crash**, see `SECURITY.md`, adversary A1.

The symptom that made it visible was narrow and specific: a supervisor **write** fault at
`0xFEE000B0`, the LAPIC EOI register. That register is reached through each task's *own*
`pml4[0]` identity map (`ensure_lapic_mapped` runs per pagedir), so when its leaf PTE was
recycled the next timer tick on that CPU could not acknowledge its own interrupt.

**The fix** is to refuse to free a tree any other CPU has loaded, and to park it for a later
attempt rather than leak it (`pending_aspace[]`, retried on the next rebuild, by which point the
idle CPU has almost always taken other work). Fail closed in both directions: the overflow leaks
rather than freeing in use. The check cannot go stale in the unsafe direction, because no CPU
can *newly* adopt the doomed tree; the only task naming it has already been rebuilt with a fresh
`cr3`, so holders can only leave.

| Arm | Boots | `0xFEE000B0` fault | free-in-use |
|---|---|---|---|
| guarded (`SCHED_INVARIANTS`) | 30 | 0 | 0 |
| guarded, ship config | 30 | **0** |, |
| ship config, before the fix | 30 | 6 |, |
| `CR3_RECLAIM_UNGUARDED=1` | 20 |, | **20** |

Gates: `make smoke-cr3-reclaim` (the fault must be **absent**) and `make
smoke-cr3-reclaim-control` (the free-in-use must be **present**). The two arms assert different
markers on purpose; the free-in-use happens every boot while the fault it causes lands on only
~20%, so gating the control arm on the fault would make it flaky for no gain.

**What this did to [G-9].** The `PROC_SELFTEST` workload at `-smp 4` went from ~45% of boots
failing to **2 in 30**, and `make smoke-kstack-park` passes in its exact form. It is not zero,
so the gate stays advisory (see §5.2d).

#### The authority half and the staging window: fixed 2026-08-18

**The authority half was removed, not guarded.** `g_spawn_caller` and `g_spawn_stdio_spec` are
parameters now: `do_spawn_stdio(spec)` → `do_spawn_inner(caller, spec)` →
`wire_child_stdio(child, caller, spec)`. There is no longer a window in which the identity of
the spawning parent can be observed by anyone but the spawn that set it, so "the child inherited
a pipe from a task that never spawned it" stops being unlikely and becomes unexpressible. The
same call also carries a *proof* rather than a memory: `do_spawn_stdio` has already refused to
consume an image the caller did not arm (§5.2f), so the parent whose cspace is read is the task
that staged the program being loaded.

**The staging window is serialised.** `spawn_stage_acquire()` / `spawn_stage_release()` bracket
every arm → consume region: `h_spawn`, `h_spawn_image`, `h_exec_named`, `h_exec_image`, the two
boot launchers in `kshell.c`, `h_sudo`'s consume, and all ten self-test sites that stage an
image by hand. Taken before the arm, because an arm landing inside another CPU's window *is* the
interleaving. It is the outermost lock in the kernel, entry points hold nothing when they take
it, and `cap_lock` / the untyped lock / `sched_raw_lock` are all taken underneath. Interrupt
latency is not a new cost: `int 0x80` is an interrupt gate, so the spawn already ran with `IF=0`
on that CPU, and `spin_lock`/`spin_unlock` have preserved the caller's `IF` since roadmap 1.1.

**On the measurement, and what it does and does not show.** The interleaving is not reachable in
any workload this repository can currently boot, and that is worth stating precisely rather than
quoting a rate that does not exist. `SPAWN_STAGE_TRACE=1` reports every entry to the staging
window and every arrival that finds another CPU inside it; `SPAWN_STAGE_WIDEN=1` holds the
window open for a fixed spin (12M `pause`, measured in the emitted code, bounded to the first 24
windows) to make an overlap likely if one is possible:

| Arm | Boots | Windows entered | Contended arrivals | Thefts |
|---|---|---|---|---|
| serialised (`SPAWN_STAGE_WIDEN=1 SPAWN_STAGE_TRACE=1`) | 8 | 112 | **0** | 0 |
| unserialised (`+ SPAWN_STAGE_UNSERIALISED=1`) | 8 | 102 | **0** | 0 |

The reason is structural, and the trace is what showed it: the 14 windows in a `PROC_SELFTEST`
boot come from three tasks (the in-kernel driver as task 0, `init`, and the proctest driver)
that never overlap, because **every spawner in the tree today is either the boot path or a child
of it**, `init` spawns its servers sequentially, and the driver that spawns the rest is itself
one of `init`'s children, so it cannot be running while `init` is mid-spawn. Two concurrent
spawners is a property of the OS this roadmap is building, not of the one it has.

**So no gate claims a rate here.** A probabilistic smoke target whose control arm cannot fail is
exactly the "test that cannot fail" this repository refuses to add. What is gated is the
deterministic half (`make smoke-spawn-owner` (§5.2f)) and the serialisation rests on the
structural argument plus the fail-closed ownership check, with `SPAWN_STAGE_UNSERIALISED=1`
retained so the arm is there the moment a workload with two live spawners exists.

**Still open, and unchanged by any of this:** a task can be `state == 0` and still executing in
ring 3 on another core. The CR3 guard makes that memory-safe without making it sensible, and the
slot allocator still reuses such a slot immediately.

### 5.2f The armed image was ambient state: **[G-11]**

**Found and closed 2026-08-18.** The staged image is one process-wide buffer, and until this
change nothing recorded the connection between the task that armed an image and the task that
spawned it. Authority-shaped state that a caller is trusted for *having* rather than for holding
a capability to is the same shape as [G-2]'s ambient `uid == 0`, and it had the same kind of
consequence hiding behind it.

`SYS_SUDO` is where it bites. It re-authenticates the caller and then spawns whatever image is
armed **as uid 0**, endowing it with `CAP_FRAME`, `CAP_USER` and a `CAP_TCB`, and the arm is a
*different syscall* from the consume, so the image being elevated need never have been staged by
the task that typed the password:

1. task A (any task holding the spawn capability) arms its own image;
2. task B authenticates correctly with `SYS_SUDO`;
3. B's successful sudo spawns **A's** program at uid 0.

A confused deputy, reachable from ring 3. It is a G-number rather than a C-number for one
reason: nothing in userspace calls `sudo` today (`include/syscall.h:805` is the only caller of
the wrapper) so the path is latent. Latency is not soundness, and this is exactly the shape of
defect that sat unnoticed for nineteen days as [H-1].

**The fix.** `loader_arm_commit()` is the only way to publish an armed image, and it records the
arming task; `loader_disarm()` clears both together, so a stale owner can never authorise a
later image. `do_spawn` refuses to consume an image whose owner is not the current task, and
`h_sudo` refuses before spending the elevation, auditing the refusal rather than logging a
failure, a correct password that was about to elevate somebody else's program is the interesting
event. Fail closed: an image with **no** recorded owner cannot be consumed at all, so forgetting
to stamp one is a broken spawn rather than a silent ambient one.

**The witness, falsified both ways.** `make smoke-spawn-owner` forges exactly the state a second
task's arm leaves behind (a legitimately staged image whose recorded owner is another task)
requires the spawn to be refused, then re-arms honestly and requires it to succeed, because a
check that refuses everything is not a check. `make smoke-spawn-owner-control`
(`SPAWN_OWNER_UNCHECKED=1`) removes the refusal and reports `SPAWN_OWNER_SELFTEST: FAIL
foreign-image-spawned pid 1` on every boot.

### 5.3 No release provenance: **[I-9]**

`kernel.elf` is verified reproducible and an SBOM is produced, but there are no tags, no
releases, no signed artifacts, and no SLSA provenance. A third party cannot verify that a
`boot.iso` they obtained came from this repository's CI, and, per §5.3a, could not confirm it by
rebuilding either.

*Inbound* dependency verification is in better shape than outbound provenance: the one network
dependency in the build path (the newlib tarball) is pinned by SHA-256, verified on every
invocation (not merely after a fetch), refused **before** unpacking, and quarantined rather than
left in place when it fails. `make smoke-newlib-tamper` exercises that gate in both directions,
so it is a control rather than an assumption. That says nothing about what leaves the build,
which is what **[I-9]** is actually about; it only means the tree is no longer trusting an
unverified 9 MiB blob on the way in.

### 5.3a `boot.iso` is not byte-reproducible, and `kernel.elf` is

**Found 2026-08-19**, while fixing the build-hash recording step, which had been concealing it
by construction.

The recording step read:

```make
@sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null || true
```

over a target whose build goal was `all`, and `all: kernel.elf`. `reproducible-build` deletes
`boot.iso` at the top and never rebuilds it, so that `sha256sum` failed on a missing operand
**every time it has ever run**: `2>/dev/null` discarded the message naming the file, `|| true`
discarded the status, and the target printed "Reproducible build recorded." over a `.build.sha`
that had only ever contained one line. The ISO was not compared because it was not built,
and it was not noticed because two of the three mechanisms existed to stop anyone noticing.

**With the ISO actually built, it does not reproduce.** Two clean builds of identical source
give a byte-identical `kernel.elf` and two different `boot.iso` files. The cause is entirely
outside this repository, and extracting both images and diffing them shows exactly how far it
reaches:

| Object | Across two builds |
|---|---|
| `kernel.elf`, every boot module, `grub.cfg`; everything this project authors | identical |
| `/.disk/YYYY-MM-DD-HH-MM-SS-00.uuid` | named for the wall-clock second |
| `efi.img`, `efi/boot/bootx64.efi`, `System/Library/CoreServices/boot.efi` | differ; grub embeds that UUID in the loaders it generates |

`grub-mkrescue` stamps that marker into the tree it hands to `xorriso`. `xorriso` itself
honours `SOURCE_DATE_EPOCH` and says so in its log; the marker is not `xorriso`'s to date.

**The first measurement of this said the opposite, and the reason is worth more than the
result.** Two ISOs built back to back were bit-identical, which read as "the ISO is
reproducible" and would have been written down as such. They were identical because both
`grub-mkrescue` invocations landed inside the same wall-clock second; the marker's resolution.
Repeat the pair across a second boundary and the hashes differ; repeat it inside one and they do
not. A measurement fast enough to be convenient was fast enough to be wrong, which is the
failure mode §5.2d keeps rediscovering under a different name.

**What is gated, and what is not.** The `reproducible` CI job compares the `kernel.elf` line of
`.build.sha` across two clean builds, and separately requires the record to name *both*
artifacts, so the ISO cannot silently drop out of the record again, which is the part that
actually failed. It does not compare the ISO, because gating a required check on a wall clock is
a flake, not a gate. `make smoke-repro-sha` holds the recording step to refusing an incomplete
build; `make smoke-repro-sha-control` (`REPRO_SHA_UNCHECKED=1`) restores the old line and
requires it to record one artifact of two and report success.

**Property S17 was worded more broadly than its witness supported**, "the shipped binary
corresponds to the published source", where the thing a third party is shipped is the ISO. It
now names the kernel image, which is what the CI job actually establishes. Closing the gap means
making the ISO reproducible rather than rewording it again: `grub-mkrescue` has no option to
suppress the marker, so the route is to assemble the image with `xorriso` directly, or
post-process the UUID to a value derived from `SOURCE_DATE_EPOCH`. Neither is done, and until
one is, **[I-9]** covers the ISO twice over: no provenance on the way out, and no rebuild that
would confirm it.

### 5.4 Cryptography is unaudited

Every primitive (ChaCha20, SHA-256, BLAKE2b, Argon2, the AEAD) is a from-scratch `no_std` Rust
implementation. None has been independently audited, and none is verified constant-time. Treat
them as research code.

### 5.5 Formal verification is narrow

Kani proves properties of capability revocation. TLA+ specifications exist for the capability
algebra and paging isolation (`docs/cap_algebra.tla`, `docs/paging_isolation.tla`) but are
**not model-checked in CI**. The kernel as a whole is not verified, and there is no
refinement proof connecting the specifications to the implementation.

### 5.6 Governance files were mislocated: **[M-3]**

The pull-request and issue templates lived in `docs/`, where GitHub does not look for them,
so neither was ever presented to a contributor. There was no code of conduct, and
`.github/CODEOWNERS` named seven files that do not exist while omitting the files containing
the IPC authorisation logic. All fixed as of 2026-07-27; the `require_code_owner_review`
setting that would make `CODEOWNERS` binding is still off (§5.1).

*(Repository hygiene itself is fine: `git ls-files` reports **254** tracked files with no build
artefacts or vendored binaries: no `kernel.elf`, no `boot.iso`, no object files. A working
checkout accumulates ~70 MB of untracked build output, which is correctly `.gitignore`d. This
sentence said 243 until 2026-08-15; it is a checkable number offered as evidence, so it is
re-derived rather than carried forward.)*

---

## 6. Honest completeness estimate

Against "a complete, self-hosting operating system":

| Area | Estimate |
|---|---|
| Boot and low-level x86-64 | 85% |
| Memory management | 70% |
| Capability model, *design* | 80% |
| Capability model, *enforcement* | **70%** (IPC namespace mediated and identity retired; three ambient console/version paths remain, §1.6) |
| Scheduling | 55% |
| SMP | 45% |
| IPC | 40% |
| Filesystem | 65% |
| Userspace and libc | 55% |
| Drivers | 15% |
| Networking | 0% |
| Formal verification | 10% |
| Build and supply chain | 80% |
| Governance and review | 35% |

**Overall: an early but unusually well-instrumented research kernel.** The infrastructure around
it (reproducible builds, measured boot, adversarial CI, formal proofs) is substantially more
mature than the kernel it verifies. Closing **[C-1]** and moving to untyped-memory object
allocation were the two changes that most raised the honest numbers above; both landed on
2026-07-27. The two that would raise them next are migrating `tasks[]` off `.bss` (**[I-7]**'s
remainder) and getting a second pair of eyes on the capability paths (**[C-5]**), which is not a
technical change at all and is the dominant residual risk.

*The enforcement row read "**45%** (IPC namespace unmediated)" until 2026-08-15: a parenthetical
naming the defect §1.1 of this same document records as fixed. It was never revised.*