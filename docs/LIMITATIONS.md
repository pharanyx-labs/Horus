# Horus — Current Limitations

An honest account of what Horus does not do, does not enforce, or does badly, so that nobody
draws an incorrect conclusion about its readiness. This document is deliberately unflattering.

**Where this document and the code disagree, the code is the source of truth — please open
an issue.**

Findings referenced as **[C-n]** / **[I-n]** / **[M-n]** are from
[`AUDIT-2026-07-27.md`](AUDIT-2026-07-27.md). **[G-n]** are the known architectural gaps in
[`ARCHITECTURE.md`](ARCHITECTURE.md) §14. **[H-n]** are from the independent external audit of
2026-08-15, which supersedes the 2026-07-27 status for several findings; that document is not
in the tree, so the findings it raised are recorded here and in `CHANGES.md`.

---

## 1. Security properties that are claimed elsewhere but not enforced

### 1.1 ~~IPC is not capability-mediated~~ — **FIXED 2026-07-27** — **[C-1]**

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

The `object` field of `CAP_ENDPOINT` — the field that names *which* endpoint — is read only
by `SYS_REGISTER_FS_SERVER` and `SYS_CONNECT_FS_SERVER`. It is never consulted on an IPC
operation. The dispatch table authorises IPC on cspace slot 3 with `SC_ANYTYPE`, and
`create_task` gives every task a `CAP_FRAME` in slot 3.

**Therefore any unprivileged ring-3 program can:**

- `SYS_IPC_RECV(FS_EP_REQ)` — dequeue another user's filesystem request, disclosing paths and
  data being written, and removing the request so the real server never sees it;
- `SYS_IPC_REPLY_TO(FS_EP_REQ, forged)` — have the kernel write a forged reply directly into
  the victim's blocked `SYS_IPC_CALL` buffer and wake it, indistinguishable from a genuine
  server reply. This forges file contents, `stat` results, and permission outcomes — and
  since the shell loads `/bin` binaries through the FS server, it can serve arbitrary bytes
  as the contents of a program another user is about to run;
- the same against `CON_EP_REQ`, intercepting or injecting console traffic including the
  masked-password path;
- `SYS_NOTIFY(any slot)` — forge hardware interrupt delivery to a ring-3 driver (**[C-2]**).

The endpoint indices are compile-time constants in public headers (`FS_EP_REQ = 4`,
`FS_EP_REP = 5`, `CON_EP_REQ = 6`).

**Consequence.** The isolation between userspace servers and their clients is not enforced.
`fs_server`'s POSIX permission model and the `SYS_IPC_SENDER` zero-trust identity anchor are
both correctly implemented and both bypassable, because an attacker impersonates the server
rather than lying to it.

Fixing this is the top roadmap item. Until it lands, **treat Horus as offering no isolation
between mutually distrusting ring-3 programs.**

### 1.2 ~~Root is an ambient authority parallel to capabilities~~ — **FIXED 2026-07-27, completed 2026-08-15** — **[I-1]**, **[H-1]**

**Resolved.** Every `tasks[current].uid != 0` gate is gone, replaced by a held capability:
`CAP_KERNEL_LOG` for `SYS_DMESG`, `CAP_BOOT_MODULE` for the boot-module surface, and
`CAP_ENCRYPTED_STORAGE` (enforced **by type**) for the object-store API. `SYS_GET_TASK_INFO`
no longer promotes uid 0. **The capability graph is now a complete description of kernel
authority** — the precondition for any confinement or MAC story later.

**One gate outlived the fix by nineteen days, and this section asserted otherwise the whole
time (**[H-1]**, fixed 2026-08-15).** Roadmap 0.2 swept `syscall.c` and `syscall_fs.c` for
`uid != 0` gates. It did not reach `src/kernel/kusers.c`, where `current_user_is_admin()`
ended `return tasks[get_current_task()].uid == 0;` — and since `SYS_USERADD`, `SYS_USERDEL`
and `SYS_PASSWD` are `SC_NONE` in the dispatch table, that function *was* the gate. A ring-3
task at uid 0 holding **no capability at all** could create an account with any uid/gid it
chose and reset any other user's password. Because uid is the identity `fs_server` authorises
every file operation against, authority over the account table is authority over the
filesystem's entire subject namespace.

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
to every logged-in user — strictly weaker than the `uid == 0` gate being removed, which is the
exact mistake `smoke-session` caught the first time round. `passwd` needs neither: the shell
always targets the caller's own uid, and `do_passwd` permits that without admin.

*Two notes on the process, both worth more than the defect.*

First, `captest` could not have caught this. Its checks probe refusals for capabilities it does
not hold, and there was no `useradd` probe at all — the suite tested the properties that had
been enumerated, and this one had not been. Four refusals now cover it. (A hypothesis worth
recording as **withdrawn**: that captest had been silently holding `CAP_USER` via
`do_spawn_inner`'s propagation. It does not, and the refusals pass identically with and without
the slot explicitly cleared. The propagation reads `cap_lookup(6, …)` *after*
`load_staged_image_into` has made the child current, so it inspects the child's own empty
cspace and never fires — `kspawn.c:188-197`. Dead, and dead in the fail-closed direction;
"fixing" it would silently widen authority to every spawned child and must not be done as a
tidy-up.)

Second, this section, `SECURITY.md` S18 and `ARCHITECTURE.md` §G-2 all recorded the finding as
closed for nineteen days while it was open — the exact failure mode §3 of `CLAUDE.md` now gates
against.

Two things fell out of the fix. The gates were additionally *type-confused* — the dispatch
table passed a type constant in the rights field with `ctype = SC_ANYTYPE`, so they never
checked the type at all (**[I-1a]**). And delegating the kernel log to the shell would have
handed it to every logged-in user, since capabilities are per-task and the shell serves
successive logins; the shell now enforces the per-user policy itself, with the kernel
enforcing possession. `smoke-session` caught that.

Note that `uid` still exists and still matters — it is the *identity* `fs_server` authorises
file access against (`SYS_IPC_SENDER`). What is gone is uid as a source of **kernel**
authority.

### 1.3 ~~`SYS_GET_TASK_INFO` discloses another task's instruction pointer~~ — **FIXED** — **[I-4]**

`info.cr3` is correctly zeroed with an explicit comment about not leaking physical layout,
but `info.eip` is returned verbatim, defeating userspace ASLR for any task a privileged
caller can observe.

### 1.4 ~~User copies truncate silently~~ — **FIXED 2026-08-13** — **[C-4]**

`copy_from_user` and `copy_to_user` clamped `n` to `USER_MEM_MAX_COPY` and returned success. A
caller requesting more got a partial copy it believed succeeded, leaving stale kernel-stack
bytes in the tail of the destination. No current caller was known to be exploitable, but this
was a latent kernel-memory disclosure that would bite the first time a larger struct was added.

Both helpers now **refuse** a request above the ceiling (`paging.c:1441-1462`). The ceiling was
never the defect — reporting a short copy as a complete one was.

Auditing all ~89 call sites found none that can reach it: each either bounds `n` by the kernel
scratch buffer it stages through (`h_write` 255, `h_dmesg` 1024, `pipe_read`/`pipe_write`
`PIPE_IO_CHUNK`, the block syscalls `BLOCK_SIZE`, the rest a `sizeof`), or chunks explicitly to
`USER_MEM_MAX_COPY` first (`arm_image_from_user`, `try_elf_load`, `load_staged_image_into`). So
refusing is behaviour-preserving, which an 11-target sweep confirms.

One handler *was* live rather than latent: `h_boot_module_read` copies straight out of the
`PHYS_KVA` window with no kernel staging buffer, and returned the **unclamped** `len` — so a
request above 64 KiB reported bytes it had not written. It now clamps to the ceiling itself and
returns the count it actually copied: a short read, which is what its ABI already promises and
what `fs_server`'s provisioning loop already handles by advancing on the returned value.

*Caveat on the witness.* Because every syscall clamps to its own buffer before calling the
helpers, the refusal itself is **not reachable from ring 3** — there is no userspace test that
can trigger it, and this section should not imply otherwise. The reachable behaviour, and the
one worth a falsification test, is the boot-module short read.

### 1.5 ~~Broad revocation can be forced by an unprivileged task~~ — **FIXED 2026-08-16** — **[I-3]**

**Was:** the descendant-closure worklist in `revoke_subtree` was bounded at 256 entries, and on
overflow the sweep over-approximated by nulling every capability sharing the root `object`. It
failed safe in the direction that matters — no descendant ever survived — but a task could
deliberately build a derivation subtree larger than 256 members, force the fallback, and
destroy an *unrelated* task's independent capability to the same object. A denial of service
against a peer, and an over-broad revocation the capability graph does not describe.

**Now:** the closure marks in place and iterates to a fixpoint, so it is exact at any subtree
size and the object-wide fallback is gone from the seeded path. The mark lives in the
capability's own `typ` field in two states (`CAP_MARK_NEW`, children not yet expanded;
`CAP_MARK_DONE`, expanded) while `serial` and `badge` stay readable, so no side array and no
allocation are needed — which is what forced the old bound in a `no_std` kernel with nowhere to
grow one. Each capability is marked at most once and promoted at most once, so the loop
terminates without a depth bound or a cycle check, at a cost proportional to the subtree the
revoker actually derived rather than to the whole system.

Revoke-*by-object* (`root_serial == 0`) still sweeps by object. That is not a fallback: with no
lineage seed it is the only complete answer, and it is exact for a shared-object lineage.

Witnesses: `test_revoke_large_subtree_is_exact_and_spares_independent_peers` (breadth, 3 levels
deep, past the old bound) and `test_revoke_deep_chain_is_fully_closed` (a 300-link chain). Both
falsified against `--features=revoke_legacy_bounded`, which restores the bounded closure; CI
runs that control arm and fails if the tests pass against it.

### 1.6 Three syscalls are still ungated by any capability — **[H-2]**

**[I-1]** and **[H-1]** removed authority derived from *identity*. They did not remove
authority derived from *nothing*, and README and the website have both stated the stronger
claim. The complete residual list, so that nobody has to take the absolute phrasing on trust:

| Path | Gate | Assessment |
|---|---|---|
| `SYS_WRITE` fd 1 | none (`syscall.c:257-274`) | Log forgery and eviction — **[H-2]**, below |
| `SYS_READ` fd 0 / `SYS_GET_LINE` | none, but both refuse once `console_hw_owned()` | Correctly mitigated; the guard is present and deliberate |
| `SYS_SYSINFO` | none | A version string. Acceptable, and marked ambient in `SYSCALLS.md` |

**[H-2]** is the one with teeth, and it is an asymmetry rather than an oversight in isolation:
the *read* side of the kernel log was converted to require `CAP_KERNEL_LOG` under **[I-1]**
(`SYS_DMESG`), and the write side was never considered. `h_write` clamps to 255 bytes and calls
`print()`, which appends to `klog` unconditionally — `terminal.c`'s `klog_append` runs before
the `drive_hw` test, so the append survives the handoff to `console_server`. `klog_buf` is
16 KiB. Any unprivileged ring-3 task can therefore forge lines that appear in `dmesg`
indistinguishable from kernel diagnostics, and can flood 16 KiB to evict genuine ones — an
anti-forensics primitive against the log a maintainer reads after an incident.

**What it does not reach**, and this is the part of the design that is right: the
tamper-evident audit chain in `src/kernel/kaudit.c` is a separate buffer under a ratcheted,
erased-after-use MAC key (property S19). Forging or evicting `klog` does not touch it.

Unfixed. The cheap remediation is to tag `klog` entries with their originating task and
rate-limit ring-3 appends, so forged lines are attributable and eviction is bounded; the
thorough one is a write-side capability. Either needs a `captest` check that a ring-3 write
cannot evict a marker line already in `klog`, falsified against the current behaviour.

---

## 2. Correctness limitations

### 2.0 ~~Spinlock interrupt state is global, and the bug is load-bearing~~ — **FIXED 2026-08-11** — **[C-3]**, **[C-3.1]**

**What it was.** `irq_lock_depth` was a single **global** counter shared by every CPU,
incremented and decremented non-atomically, and `spin_unlock` did an **unconditional** `sti`
when it reached zero. Under SMP one CPU's release could re-enable interrupts while another
still held a lock, and racing read-modify-writes lost counts outright. The unconditional `sti`
separately re-enabled interrupts inside a caller's own `cli` region, including `user_copy`'s
CR3 window, where a preemption leaves a stale CR3 to restore.

Worse, it was **load-bearing**: because that `sti` fired for any lock taken while interrupts
were masked — and `int 0x80` masks them on every syscall entry — interrupts came on earlier
and more often than any stated policy asked for, and the startup handshake had come to depend
on it. A correct per-CPU, IF-preserving lock written on 2026-07-27 passed every local gate and
broke the ring-3 handshake in CI; it was reverted.

**What fixed it.** The depth and the saved `RFLAGS.IF` are now per-CPU, and the outermost
release *restores the caller's own* `IF` instead of asserting one.

The July patch was not wrong — the tree was. Three subsystems were subsequently changed to
route around **[C-3.1]**, above all `preempt_on_tick`'s ring-0 guard, widened from `cpu == 0`
to every CPU precisely because a ring-0 tick could land mid-syscall. With that guard a ring-0
tick is never a switch point, so the accidental `sti` no longer produces the preemption
anything depended on.

Interrupt policy is now **stated** — see [`ARCHITECTURE.md` §6, "Interrupt policy"] — and
gated: `smoke-irq-policy` records `IF` at six milestones, the sixth being `IF` immediately
after the first outermost `spin_unlock`, which is the one observation separating the two locks.
`IRQ_LEGACY_GLOBAL_LOCK=1` rebuilds the defect exactly, as the control arm.

Measured on the same 14-command workload, the two builds count the same predicate (a release
whose caller had `IF` clear): legacy **1439 accidental + 720 benign = 2159**; per-CPU
**2159 suppressed + 0 benign = 2159**. Identical totals, 1439 unwanted enablements removed.
Interleaved pinned session rates: `-smp 1` 0/20 both arms; `-smp 4` 3/40 legacy vs 1/40
per-CPU — a difference well inside noise, and every failure in both arms was **G-8 signature
A** (the ring-3 shell faults and `init` relaunches it), not an interrupt-policy fault.
`smoke-console-smp-stress` and `smoke-sched-invariants-stress` both 30/30 on the new lock.

**An open question, recorded rather than rounded off.** Those session rates are one harness.
A separate boot-only harness — `-smp 4` squeezed onto a single host core against three CPU
hogs, arms interleaved — found a kernel page fault in the interrupt-return path at **3 boots
in 125 on the per-CPU arm, against 0/125 legacy and 0/105 on `main`**. p ≈ 0.045: marginal,
and not conclusive at that sample size. It is recorded here because the correct bar for a
fault on that path is *shown not to be mine*, not *not yet shown to be mine*, and because the
alternative reading — that the new lock changes when interrupts are masked and therefore
merely **exposes** a latent teardown-vs-selection race — puts the fix somewhere else entirely.
The capture is a corrupted trap frame being `iretq`'d (`err=0x11`, `rip` and `rsp` 0x80 apart
in the same kernel stack: the kernel executing from a stack), not a wild pointer, so a range
check on the resume `%rsp` cannot catch it and did not when it was armed for exactly this.

**Still open, and now visible.** The three workarounds written for C-3.1 are still in place and
were not removed here — `preempt_on_tick`'s ring-0 guard, `untyped.c`'s IF-transparent critical
section, and the deferred lock arming past boot. They are no longer load-bearing for interrupt
policy, but each was justified by this defect, and each now deserves its own re-examination
rather than a bulk revert on the strength of one green run.

### 2.1 ~~64-bit arithmetic is truncated in the heap syscalls~~ — **FIXED 2026-08-13** — **[I-2]**

`SYS_SBRK` and `SYS_BRK` computed the new break in `uint32_t` while `heap_start` and
`heap_max` are 64-bit. Correct only while every heap lived below 4 GiB. Both are now 64-bit
end to end, with the overflow check before the range test (roadmap 1.5).

**The finding was wider than this section described, and the extra part was not latent.** The
same truncation appeared a third time, in the *pager* rather than the syscalls —
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
could never be paged. **Silently** — a ring-3 fault prints nothing (`idt.c` says so in its own
comment), so the system simply wedged.

The tell was that the two gates disagreed: `page_fault_handler` passes the same values to the
same validator *untruncated* and admitted the fault, and then the pager rejected it. One
validator, two call sites, one of them narrowing.

Witnessed, in both directions, by `make smoke-heap64`: `USER_HEAP_HIGH_BASE=1` places every
heap at 8 GiB, which makes the truncation reachable, and `captest` exercises `sbrk`/`brk` and
then writes to the page it was given. Built without the fix the same target reports
`CAPTEST: FAIL (sbrk-grow-failed)`. That control arm is why this one is not filed as
"latent, believed fixed" the way **[C-4]** had to be.

### 2.2 ~~Endpoints are single-slot mailboxes~~ — **QUEUED + REPLY-CAP 2026-08-10** — **[I-5]**

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
sender of the message it dequeued; `SYS_IPC_REPLY_TO` requires it and consumes it. Replying to
a client you never received from, replying twice to one request, and replying to the wrong
client are no longer *refused* — they are **unrepresentable**, because the right names one
blocked caller and dies on use. That retires the convention a server previously had to honour:
the old routing read the endpoint's mutable `last_sender`, and the bounded queue above made
that sharper by letting a server hold several dequeued requests while only the newest was
nameable.

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
test. The single-core ranges do not overlap — slowest blocking boot 6.63 s, fastest polling
boot 14.63 s. The gain is smaller with four cores because spare cores absorb the wasted turns,
which is the expected shape if the cause is a runnable server competing for turns it cannot
use.

**A caution for anyone extending this path.** The interesting hazard is not the sleep, it is
that a blocked receiver is completed by the *sender's* syscall — on the sender's CPU, with the
sender's cspace current. The first version of this minted the receiver's one-shot reply right
after marking it runnable, so under `-smp 4` the woken server could reply before it held the
right, get `SYS_ERR_PERM`, and correctly drop the reply, hanging the client. It hung 8 of 25
loaded sessions (0 of 25 after the fix) while passing every single-CPU gate. The rule now is
**a receiver holds its reply right before it is schedulable**, and `TESTS.md` carries the
loaded reproduction, since an idle host will not show it.

**Still open.** Priority inheritance still cannot be expressed: the kernel now records that a
task is waiting on an endpoint, which is the prerequisite, but nothing propagates priority
along that edge — and there are no task priorities to propagate yet. `fs_server` also still
polls in one place by design, re-stating the root inode while a sealed ATA volume is locked;
it blocks only once provisioning has succeeded.

*(An earlier revision of this section claimed finding **[G-8]** signature C was a livelock
caused by this contention. **That was wrong.** It was a startup race — clients that lost the
race against `fs_server`'s registration held no endpoint capability, and every IPC then
returned `SYS_ERR_PERM` into a userspace loop that retried it forever. Evidence: not one byte
of traffic ever crossed any endpoint in a hung boot, which contention cannot produce. Fixed in
userspace; see `TESTS.md`. The queue above is a real improvement, but it did **not** fix that
hang and was never what caused it.)*

*(The shared global reply endpoint that used to compound this is gone: every task now has a
private one, so **[I-5]** is closed. The missing queue is not.)*

The block/wake protocol around these mailboxes is the delicate part, and it has now produced
two defects of the same shape. A caller becomes wake-visible in stages — `pending_block` set,
`saved_ksp` written, then `state` published — and any interval in which it is committed to
blocking without advertising it is a window where a wake can be lost. The publish-after-save
ordering covers `saved_ksp`; a reply arriving before `pending_block` was set, or between it
being cleared and `state` being written, used to be **dropped and reported as delivered**
(see CHANGES.md). Both are closed, and the declaration now spans the whole interval, but the
staged design means the next primitive added here has to reason about the same thing. A
proper reply capability consumed on reply (roadmap 1.3) would retire the class rather than
patch instances of it.

### 2.25 ~~The write-ahead journal is not durable on real hardware~~ — **FIXED 2026-08-16** — **[I-10]**

**Was:** `src/kernel/ata.c` issued exactly three ATA commands — `READ SECTORS` (0x20),
`WRITE SECTORS` (0x30), `IDENTIFY` (0xEC) — with **no `FLUSH CACHE` (0xE7)** anywhere in the
kernel. `WRITE SECTORS` completes once the data reaches the drive's volatile write cache,
which is enabled by default on essentially every ATA/SATA device, so a power failure between
the journal's commit record and the platter lost the record and left recovery in the state
the WAL exists to prevent.

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
— the original plan — does **not** distinguish a flushing kernel from a non-flushing one:
guest writes land in the host *page cache*, which outlives the QEMU process, so killing QEMU
loses nothing either way. There is no QEMU cache mode in which a two-boot test's outcome
depends on whether the guest flushed. The gates instead make the flush **fail**
(`blkdebug`, `inject-error` on `flush_to_disk`) and assert the kernel's reaction, and trace
the IDE command register to assert the barriers sit in the right *place*. See `TESTS.md`.

Witnesses: `make smoke-fs-wal-flush` (issued and checked) and `make smoke-fs-wal-order`
(ordering). Both falsified against `WAL_NO_FLUSH=1`.

### 2.3 Kernel object lifecycle covers retyped objects only

*Restated 2026-08-15. This section previously read "Endpoints and notifications are never
reference-counted or destroyed", which stopped being true when **[I-7]** landed and was never
revised.*

A **retyped** endpoint or notification — one carved from untyped memory, at an index at or
above `DYN_EP_BASE` / `DYN_NOTIF_BASE` — is destroyed when no capability names it any more.
That is computed by mark-and-sweep over the capability graph (`src/kernel/untyped.c:306-400`)
rather than by reference counting, on the reasoning that reachability derived from the same
graph the security argument is stated over cannot disagree with it. The sweep's imprecision is
deliberately biased toward leaking: a capability whose lineage generation was bumped still
marks its object, because the opposite bias — treating a slot as empty while a holder can
still resolve it — is a use-after-free reachable from ring 3.

What has no lifecycle is the **static shim** below those bases: the well-known service
endpoints and the per-task reply endpoints are named by the boot protocol rather than by any
single capability, so nothing can decide they are dead. They are immortal by construction and
will stop being so as they migrate to retyped objects. Destruction also does not return the
bytes — the arena is a monotonic bump allocator, so only the *name* is reclaimed.

### 2.4 Copy-on-write is implemented but narrow

COW works for the shared zero page and for the generic non-zero case (both tested). There is
no `fork` — the only COW producer is the demand pager. Full `fork` semantics need the frame
capabilities described in the roadmap.

---

## 3. Scale and performance limitations

### 3.1 Hard compile-time ceilings — **[I-7]**

| Resource | Limit | Where |
|---|---|---|
| Tasks | 64 | `MAX_TASKS` |
| Capabilities per task | 128 in use, 256 slots | `MAX_CAPS_PER_TASK`, `CNODE_SIZE` |
| CPUs | 4 | `MAX_CPUS` |
| Static endpoints (well-known + per-task reply) | 128 | `MAX_ENDPOINTS` |
| Retyped endpoint descriptors | 256 | `MAX_DYN_ENDPOINTS`, indices from `DYN_EP_BASE` |
| Static notifications | 64 | `MAX_NOTIFICATIONS` |
| Retyped notification descriptors | 256 | `MAX_DYN_NOTIFICATIONS`, indices from `DYN_NOTIF_BASE` |
| Untyped arena | 4 MiB | `UNTYPED_ARENA_BYTES` |
| IPC message | 256 bytes | `IPC_MSG_MAX` |
| Boot modules | 48 | `MAX_BOOT_MODULES` |
| Volume | 16 MiB | `BLOCKS_PER_DISK` |
| Staged program image | 8 MiB | `LOADER_STAGING_BYTES` |

*This table said "Endpoints 64 / Notifications 64 … These are `.bss` arrays, not dynamically
allocated objects. There is no retyping discipline and no per-task kernel-memory accounting"
until 2026-08-15. Both halves had been false since **[I-7]** landed on 2026-07-27, in the same
document whose §1.2 records the fix.*

There **is** a retyping discipline. `CAP_UNTYPED` + `SYS_RETYPE` carve cspaces, endpoints and
notifications out of a 4 MiB arena (`src/kernel/untyped.c`), so creating a kernel object is an
exercise of authority the capability graph describes and the memory is attributable to the task
that holds the untyped capability. The static tables survive as a **shim** below `DYN_EP_BASE`
/ `DYN_NOTIF_BASE` for the well-known service objects and the per-task reply endpoints, which
the boot protocol names positionally; `endpoint_by_index()` is the single resolver and nothing
indexes `endpoints[]` directly any more. The dynamic ceilings above bound only the descriptor
arrays, not the objects.

What remains genuinely fixed-size is `tasks[]` — a TCB is reachable from the scheduler's hot
path and from every trap frame, so migrating it is its own change, and reclaiming a dead task's
cspace additionally needs `cap_lookup`'s NULL-cspace → root-cnode fallback removed first.
**An OS cannot have a compile-time limit of 64 tasks** — that is the remaining structural
obstacle to Horus becoming general-purpose, and it is the last piece of **[I-7]**.

### 3.2 ~~`this_cpu()` reads LAPIC MMIO on every call~~ — **[I-6]**, fixed

`this_cpu()` now derives the CPU id from the TSS selector in `TR` — `cpu = (str() - 0x38) /
0x10`, a register read — instead of the uncached LAPIC MMIO read it used to do on every
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

## 4. Functionality that does not exist

- **Networking.** No drivers, no stack, no sockets.
- **Graphics.** VGA text mode only; no framebuffer graphics, no windowing.
- **USB, sound, or any modern bus.** ATA PIO and PS/2 only.
- **`fork`.** `SYS_SPAWN` and `SYS_EXEC_*` exist; POSIX `fork` does not.
- **Dynamic linking.** Every binary statically links newlib (~450 KiB each).
- **Multiple filesystems or mount points.** One `fs_server`, one volume.
- **Threads within a task.** One thread per address space.
- **Swap or memory pressure handling.** Pool exhaustion is a hard failure.
- **KASLR.** Userspace has 30-bit ASLR; the kernel is loaded at a fixed address.
- **IOMMU.** A DMA-capable device can read all of physical memory.
- **Signals beyond the basics.** No `SIGCHLD`, no job control, no process groups.
- **ARM or RISC-V.** x86-64 only, and the boot path is Multiboot2/BIOS (no UEFI).

---

## 5. Process and assurance limitations

### 5.1 No independent review — **[C-5]**

Horus is maintained by one person. The branch ruleset requires a pull request but sets
`required_approving_review_count: 0`, and every recent PR merged with zero reviews.

Automated verification is extensive; human verification is absent. **[C-1]** is the
demonstration of what that combination produces: a defect that passes every automated gate —
it builds, boots, and satisfies a 29-check capability conformance suite — because the suite
tests the property the author had in mind rather than the property the documentation claims.

The assurance Horus can honestly claim today is *"thoroughly automatically verified"*, not
*"independently reviewed"*.

### 5.2 Which tests gate a merge is reconciled by hand — **[C-6]**

`.github/workflows/ci.yml` defines **69** jobs, `codeql.yml` one more and `ruleset-audit.yml`
one more — **71** across the three, producing **74** status-check contexts. Ruleset `19007209`
required **22** of them before 2026-08-16, and
until 2026-08-15 exactly **zero** of those 22 were security gates: capability conformance,
kernel W^X, measured boot, boot-module tamper rejection, SMEP/SMAP presence, flush-on-switch and
stack-guard reseed could all fail while a PR merged green. The required set was inverted —
functional tests blocked merges, security tests did not.

**One of them is now fixed, and it is the one that mattered most.** `smoke-captest` is a
required check as of 2026-08-15. `SECURITY.md` names it as the witness for **eight** of its
S-numbered properties — S1, S5, S6, S7, S13, S13a, S13b and S18 — so until that change the
suite establishing most of the security argument could not block a merge, and the exact defect
class **[C-1]** was would have merged green. That is no longer true.

(An earlier revision of this section, and the audit that prompted it, both said *nine*. Counted
off the witness column: eight. Recorded because "re-derive every number you cite" is a rule this
document is subject to, not merely one it states.)

**The mechanism behind it was closed on 2026-08-16; the gap itself narrows in two steps, and
only the first has landed.** When this finding was filed there were roughly 30 jobs and 21
required. There were 66 and 22 immediately before this change, because every gate added after
the ruleset was written landed in the advisory set *by default* and nothing forced the
question — twice at the cost of a security gate, `smoke-captest` until 2026-08-15 and the two
[I-10] durability gates on 2026-08-16, the latter advisory in the very commit that fixed the
defect they witness.

`.github/ci-gating.yml` is now the checked-in decision record: every job in `ci.yml` and
`codeql.yml` must appear under `required:` or under `advisory:` **with a written reason**, and
the `ci-gating` job fails the build if any job is in neither, in both, or names a job that no
longer exists. There is deliberately no default, because defaulting is the defect. It caught
CodeQL sitting unclassified on its first run.

That intended set is **70 required contexts and 4 reasoned exemptions** — `fuzz` (a 30-second
time-boxed search is evidence of effort, not absence), `kani` (manual-only, so it has no
conclusion to gate on), `ruleset-audit` (schedule-only, so it never runs on a pull request) and
`smoke-kstack-park` (its workload trips **[G-9]**, §5.2d — the one exemption that again stands
for an open defect rather than a property of the test). `smoke-fs-wal` was a third until [I-11] was fixed on 2026-08-16 and it
was promoted back, and `smoke-session-smp-soak` a fourth until [G-8] was closed on 2026-08-17
and it was promoted with it — the last exemption in this repo that stood for an open defect
rather than for a property of the test itself. The
promotion list is justified by measurement rather than optimism: across 18 CI runs sampled on
2026-08-16, 64 of 66 jobs had **zero** failures over 1152 job-executions, and the only two that
failed are both on the exemption list or were deliberate.

**The ruleset was synced toward that set on 2026-08-16**, from 22 required contexts, with
`strict_required_status_checks_policy` true and no bypass actors. **Syncing it is a separate, manual, lagging step — and getting that wrong froze the
repository.** The first `--sync-ruleset` was run from a feature branch, so it wrote the
*intended* list, including three contexts `main` could not yet produce: the `ci-gating` job
itself and the two [I-10] journal gates. A required context no workflow on the base branch
produces **never reports**, so every pull request was blocked on it indefinitely — and it looks
like an ordinary red check, not a misconfiguration. `tools/prune_unsatisfiable_checks.py`
dropped the three (67 → 64) and now encodes the rule: **never require a context the base branch
cannot produce.** Promotion must lag the job landing by one merge, never lead it. Every security gate the
finding named — kernel W^X, SMEP/SMAP, measured boot, boot-module and newlib tamper rejection,
flush-on-switch, stack-guard reseed, the 64-bit heap, interrupt policy, per-CPU identity, the
resume-`%rsp` guard, CodeQL, and the two journal durability gates — now blocks a merge.

**What kept this finding open was that CI could not verify it stays that way**, and the
mechanism for that landed on 2026-08-17. Reading a ruleset needs the `Administration`
permission, which is not among the scopes a workflow `GITHUB_TOKEN` can be granted at all, so
the `ci-gating` job proves the classification is *complete* but not that the ruleset *matches*
it — the two could diverge through a change in the GitHub UI with nothing in CI noticing.
`.github/workflows/ruleset-audit.yml` now runs `--check-ruleset` daily as a **GitHub App scoped
to this repository with `Administration: read` and nothing else**: the token is minted per run,
expires within the hour, and cannot modify the ruleset it reads. Its log states the comparison
outcome explicitly (`live ruleset 19007209 : 71 required contexts, matches`, or `DIVERGED`, or
`NOT READ`), so a green run is self-evidencing rather than merely silent — the first live run
could only be shown to have read anything by falsifying it afterwards with a bad token.

That is a trade and it is written into the workflow header rather than left implicit — a
credential able to read repository administration now sits in Actions secrets, in order to
detect drift that requires administration access to cause. It is read-only, single-repository,
and revocable by uninstalling the App; the alternative was a check nobody runs, which is what
left the required set at 22 of 66 with no security gate among them.

**The finding stays open until the App is created and its two secrets exist.** The job fails
loudly on every scheduled run until then, deliberately: an audit that skips when unconfigured
is a check that cannot fail, and this repository has been bitten by that twice already
(`make test`'s `|| true`, and the scanner-presence step before #154). Until it is configured,
`tools/check_ci_gating.py --check-ruleset` is the check and has to be run deliberately. Read
the count from the API, never from this paragraph.

Two counts moved in the right direction since. `strict_required_status_checks_policy` is now
**true**, so a stale-base merge is no longer permitted. And the `security` job is a required
check whose scanner-presence step no longer carries `continue-on-error` (#154), so the job goes
red if the scanners are absent — a job that structurally could not fail now can. The scanners'
**findings** remain advisory, deliberately: five of the six swallow their exit status inside
`make security`, and the sixth (`semgrep --config=auto`) fetches rules from a registry that
changes with no commit here. Gating on content is what pinning those rulesets would unlock.

### 5.2b ~~One required check is nondeterministic by construction~~ — **FIXED 2026-08-16** — **[I-11]**

**Was:** `smoke-fs-wal` killed QEMU the instant a marker appeared on the serial console, then
rebooted on the same disk image. The marker proved the guest *reached* that point, not that
its journal writes had completed, so on a loaded runner boot 2 failed with
`WAL_CRASHTEST: FAIL read` against an unmodified kernel. The worse consequence was not the
spurious failure but that **a real WAL regression was indistinguishable from the race** — both
produced the same output.

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

Also fixed here: an exit the harness *asked for* was being reported as
`SMOKE FAIL: QEMU exited before the banner (triple fault?)`, because QEMU could die between the
inner and outer liveness checks — a window of microseconds, hit reliably in practice.

Witness: `make smoke-fs-wal`. **20/20 two-boot runs passed** on 2026-08-16 (`tools/`-driven
soak, one fresh 32768-block image per run). Falsified four ways — see `TESTS.md`; the decisive
one is that a serial log containing `WAL_CRASHTEST: crashed-after-commit` now **fails** when the
quit cannot be delivered, where the old harness scored that identical log a pass.

*Note on what the rate does and does not show.* 20/20 is the post-fix rate on this machine. The
pre-fix flakiness was load-dependent and did not reproduce here, so this is not a before/after
comparison — the substantive argument is structural (the marker alone can no longer pass, and
barrier B orders the write before the marker), and the rate is corroboration, not proof.

### 5.2c The SMP session soak — **[G-8]**, diagnosed and closed 2026-08-17

**Closed.** A task was published as claimable by another CPU while the CPU making the switch
was still executing ISR C frames on that task's kernel stack. `smoke-session-smp-soak` is
restored to **gating**.

*The mechanism.* Every switch path in `scheduler.c` — `preempt_on_tick`, `ipc_block_switch`,
`sched_yield_switch` — is called from `interrupt_handler64`, which runs on the outgoing task's
kernel stack: its C frames sit immediately below the trap frame the CPU pushed on entry.
Releasing `task_running_cpu[cur]` and dropping the scheduler lock there left this CPU with ~30
instructions still to execute on that stack — six callee-saved pops, a `ret` through a return
address on it, the floor guard, `fpu_restore`, a stack-protector canary read, four more pops
and a second `ret` — before `isr_common_stub64` reached `movq %rax,%rsp`. A CPU that claimed
the task inside that window resumed it to ring 3, and its next trap re-entered the ISR **on
the same stack, at the same depth, running the same functions**, rewriting exactly the words
the first CPU had not finished reading.

*Why it was invisible.* The overlap is exact, so the return addresses and the canary land back
at their own slots holding their own values: every frame validates, every `ret` goes where it
should, and only the data differs. The first datum out is the resume `%rsp`. That accounts for
the whole recorded signature — a plausible word from the wrong context (a `.text` return
address in one capture, `4` in another), a canary that passed, and a claim invariant that read
consistent.

*The correction this section owes.* The 2026-08-13 update below said the shared-stack
hypothesis had "nothing observed supporting it" because the one `t > 0` capture showed
`task_running_cpu[4] == 0` and `percpu_current_task[0] == 4`. **That is withdrawn.** A
deliberately reproduced collision prints `claim: task 4 running_cpu=3
percpu_current=[0,0,0,4]` — the invariant holds *while two CPUs are on one kernel stack*,
because it is true: the task is running on exactly one CPU, and the other is merely still
leaving. The instrument could not see this and never could. The capture was never evidence
against the hypothesis; it was evidence the invariant was scoped to the wrong question.

*The fix.* The claim is held until the CPU has physically left the stack.
`isr_common_stub64` calls `sched_release_deferred()` immediately after `movq %rax,%rsp` — the
first instruction at which this CPU is provably reading a different stack — and the hand-over
completes there. And the property is checked rather than asserted (`SECURITY.md` **S20**):
`g_kstack_inflight` carries bit *t* for the duration of that window on task *t*'s stack, and
`interrupt_handler64` tests it on entry, halting if two CPUs are ever on one stack.

*The rate.* Paired, adjacent-boot alternating on one host, `-smp 4`, 1600 boots:

| Arm | Failures | Rate |
|---|---|---|
| `KSTACK_RELEASE_EARLY=1` (pre-fix release site) | 31 / 800 | 3.9% |
| shipped (deferred release) | **0 / 800** | 0% (95% upper bound 0.38%) |

Fisher exact, two-sided: **p = 6.9 × 10⁻¹⁰**. The 3.9% decomposes onto what this section
already documented: 13 of the 31 were caught at the collision by the new detector, and the
other 18 — **2.25%** — ran on into a downstream failure, which is the 2–3% per boot this
section has carried since 2026-08-09, reproduced. An earlier run of the same design, on
binaries predating the detector's report deduplication, gave 44/800 against 0/800 — a different
total, an identical **18/800** downstream subset.

`make smoke-kstack-race` and `smoke-kstack-race-control` settle it in seconds instead of at
~1 boot in 150: `KSTACK_RACE_WIDEN=1` stretches the window so it is entered on essentially
every switch, and is set in **both** arms, so the same widened window must be harmless with
the fix and fatal without it.

**The second path, closed the same day.** The `#PF`/exit fallbacks in `idt.c` resumed a CPU
with `frame->rsp = tasks[0].kernel_stack_top` when nothing else was runnable, and every CPU
taking one landed on that one stack. This was recorded here as an unwitnessed lead — one soak
capture, all four CPUs idle on task 0, `PANIC: dispatcher returned a bogus resume rsp=0xfee000b0`,
the LAPIC EOI register address and therefore a word out of another CPU's `lapic_eoi` frame. It
has a witness now.

*Why it read as latent.* On a healthy session the path is **never entered** — 0 parks in 3
boots, measured with `KSTACK0_PARK_TRACE=1`. Tasks do not die, and when one does something else
is usually runnable. On a workload that kills tasks on purpose (`PROC_SELFTEST`, `-smp 4`) it is
entered **5–8 times per boot**, every park on the same `rsp`, and two CPUs were parked on that
one stack **2–3 times per boot, 3 boots of 3**. That is the difference between "unreachable" and
"unexercised", and only choosing the right workload distinguished them.

*The fix.* Each CPU parks on its own ring-0 stack — the one `enter_cpu_idle()` already uses — so
the fault path joins the kernel's single park mechanism instead of keeping a worse second one.
`sched_note_park()` records the choice and halts if two CPUs ever pick the same stack, so the
property is checked rather than intended. `make smoke-kstack-park` and its control arm gate it,
both asserting the same deterministic property: whether any one park stack was used by more than
one CPU.

*And it exposed a second gap.* The per-CPU idle stacks had **no guard page**, so `SECURITY.md`
S9 ("an unmapped guard page below every kernel stack") was false — independently of this
finding, since `enter_cpu_idle()` has always parked CPUs there. The guard is now the first page
of each slot, which leaves the stack *top* where `ap_trampoline.S` computes it and so needs no
change to the trampoline or its duplicated stride constant. `smoke-wx` / `smoke-wx-smp`
enumerate the family; falsified by disabling the arming, which reports
`WX_SELFTEST: FAIL armed 0 AP idle-stack guards, expected 4`.

The history below is the standing reminder of what a lead recorded rather than acted on costs —
in this case one day, and only because the next session went looking for it.

---

The record of how this was read wrongly, kept because the wrong readings are the point:

`smoke-session-smp-soak` failed at roughly **2–3% per boot** — 1 hang in 45 pinned to two host
cores, and 1 in 45 on a CI runner. Two distinct signatures were captured: one where the session
completes 9 of 12 checks and then stalls mid-output, and one where **boot never reaches the
login prompt at all** and the serial log ends at `[console_server] ready`. That second
signature is the `smoke-console-smp` deadlock's signature verbatim, and the open question was
read for weeks as whether that fix was incomplete. It was neither. It is **not** the IPC
lost-reply race (`#116` is in every tree measured).

**2026-08-13 — the proximate mechanism.** A 150-boot soak at `-smp 4` on `ba84e90`, the first
run after #140 made kernel fault reports audible during a live session, caught it once. The
fault is a `#GP` **at the `iretq`** in `isr_common_stub64`: `interrupt_handler64` returned a
resume `%rsp` pointing into `.text`, the stub's 15 `pop`s loaded registers from instruction
bytes, and `iretq` took `CS` from those bytes. Proved rather than inferred — the reported
`rbp` is bit-for-bit the code bytes at `resume_rsp + 64`. `TESTS.md` has the disassembly.
`#123`'s floor guard does not cover that value: it is higher-half, so `rsp < 0xFFFF800000000000`
passes it.

**2026-08-13 — a second capture, and two corrections.** A dual-arm run caught the fault again
on `main` at `e9aebdd`, in a boot carrying **two** corrupted resume values on two CPUs: a
`.text` return address, and **`4`**. It is not one bad write — no `saved_ksp` assignment
produces `4` — which correctly retired "find the line that stores the wrong value". The same
run was the control for **PR #135** (per-CPU IRQ lock): `main` 1/150, #135 rebased 0/150, not a
significant difference (Fisher p = 1.0) and no improvement claimed, but it established the
fault as `main`'s and unblocked that PR.

**2026-08-13 — the guard was mute, and that was fixed and gated.** The guard's report was
bracketed `kfault_begin(1)`, and `kfault_begin(1)` is `panic_begin()`, whose claim is
**permanent** — a CPU that asks for it after another CPU's fatal exception halts *inside*
`panic_begin` without emitting a byte. In the two-event capture the fatal `#GP` on cpu 3
printed first and kept the claim, so the guard **could not have been heard on that boot whether
or not it fired**. #140 made this report reach the UART but left it behind a claim the failure
itself takes away. Every "the guard did not catch it" statement about that capture was
withdrawn then, and `make smoke-resume-guard` / `-preclaim` / `-legacy` / `-nofloor` settle it
in seconds.

**2026-08-13 — a narrowing that was right about the window and wrong about the register.** The
guard-less arm showed a resume `%rsp` of `4` still present at `out->cs` faults at `0x94`, while
the capture faulted at `0x4` in the stub's first `pop` — so the value became `4` *after* the
guard. With the canary passing, that was read as "a register that did not survive". The window
was identified correctly and is the one closed above; the register reading was the wrong half,
because a callee-saved register restored from a slot a second CPU rewrote is both.

### 5.2d Claims leak and kernel stacks collide on the spawn/reap path under SMP — **[G-9]**

**Open, found 2026-08-17, pre-existing, and narrowed the same day** — one component fixed and
falsified, the rest still open; see the sub-section below. The original report follows as
written, because the leads it got wrong are part of the record.

Running `PROC_SELFTEST` at `-smp 4` violates the
claim invariant on roughly **40% of boots**. Nothing had ever run that workload at more than one
CPU: `smoke-proc` boots it uniprocessor, where it is clean.

Under `SCHED_INVARIANTS=1` the checker names it, always on the same task — task 3, the
self-test driver that spawns and reaps children:

```
PANIC: stale scheduler claim at preempt_on_tick: task 3 claimed by cpu 2
       but that cpu was running 0 (persisted across two audits; observed by cpu 1)
```

*"Persisted across two audits"* is the two-strike checker's own guard against crying wolf on a
mid-flight update, so this is a genuine leak rather than a transient.

**Both directions of the invariant break.** As well as the leaked claim above, a boot showed
`claim: task 1 running_cpu=-1  percpu_current=[0,0,1,0]` — a task **running with no claim**,
which `ARCHITECTURE.md` §7 names as the dangerous direction because an unclaimed running task
is selectable by a second CPU. The observed consequence is exactly that: two CPUs on one kernel
stack, reported by the stack canary in `h_write`
(`stack smashing detected in function at 0xffffffff8010ebbc`, always `task=1`).

| Configuration | Boots | Failed | Stale-claim reported |
|---|---|---|---|
| `-smp 1` | 20 | **0** | 0 |
| `-smp 4` | 20 | 9 | 8 |
| `-smp 4`, pre-#162 release timing (`KSTACK_RELEASE_EARLY=1`) | 20 | 10 | 9 |

**The third row is why this is not [G-8]'s fix misfiring.** Restoring the pre-#162 release
timing gives 10/20 against the shipped 9/20 — Fisher p ≈ 1.0, no difference. The leak predates
both G-8 fixes; what those fixes did was stop masking it. Before them the same workload failed
**20/20** on the shared park, and you cannot see a second defect while the first kills every
boot.

Without `SCHED_INVARIANTS` the failures present as a mix, which is why the checker was needed:
over 25 boots, 10 passed, 7 took a supervisor `#PF` (instruction fetch at `rip=0x2/0x12/0x82`,
i.e. a return through a corrupted pointer), 5 stalled with no marker, and 3 tripped the canary.

**Consequence for CI.** `smoke-kstack-park` is **advisory**, not gating: the S20 park property
it checks is sound and its control arm still reproduces the park defect on demand, but requiring
a workload that reddens for an unrelated defect teaches the re-run reflex. It **stays advisory**
after the 2026-08-17 narrowing below — the workload still fails ~27% of boots, for a reason that
is still not what the gate tests. Promote it in the same commit that closes the rest of
**[G-9]**, and quote a rate.

#### Narrowed 2026-08-17: one component found, fixed, and falsified — the rest still open

**[G-9] as filed was a cluster, not one defect.** One component is now closed; the remainder is
not, and the finding stays **OPEN**.

The `sched_enter_user()` lead recorded above was **wrong**, and is retained rather than deleted
because the reason it was wrong is reusable: it does bypass `isr_common_stub64`, but every one
of its callers is a boot-time path on the BSP where no deferred release is ever pending, so it
cannot leak. Two further hypotheses died the same way — the unguarded "defensive claim" in
`preempt_on_tick`, and `create_task()` inheriting a stale claim through slot reuse. Both are
real shapes; neither is what fires. Probes beat reading, three times over.

**The component that was found.** `g_exec_reenter_task` was a single global naming the task
whose exec re-entry was pending, and `idt.c` consumed it on the exit of **every syscall on every
CPU** with no test that the exec belonged to the CPU reading it. An exec armed on one core was
routinely taken by another, which then claimed the exec'ing task, installed its CR3 and resumed
the trap frame the exec tail had just fabricated — while the core that actually ran the exec was
still executing on that same frame, at the top of that task's kernel stack.

That one race produces all three signatures recorded above: the leaked claim (the thief abandons
what it was running without releasing it, because `exec_reenter_switch` is written for the case
where the incoming task *is* the outgoing one and so has no release at all), the opposite
direction, and two CPUs on one kernel stack. It was caught in the act by a probe:

```
CLAIMORPHAN: cpu 0 entering task 1 at exec_reenter_switch while still claiming live task 3
  percpu_current=3  deferred=-1  state=1
```

`percpu_current=3` while entering task 1 — a CPU consuming an exec re-entry for a task it was
not running, which violates that function's own contract.

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

**What is still open.** Two residues, and neither is the exec race:

- a stale claim that appears in the **boot/spawn phase, before any exec runs** (2 in 30, e.g.
  `task 1 claimed by cpu 3 but that cpu was running 0`, immediately after `PROC_SELFTEST: begin`);
- a CPL-0 fault at **~20% of boots** (6 in 30), `vec=14 errc=0x2` — a supervisor *write* to a
  non-present page — resolving to `lapic_eoi` and `interrupt_handler64`. A CPU taking an
  interrupt on a CR3 that does not map the LAPIC is an address space that became reachable
  before its kernel half was built, which points at **[G-10]** below rather than at the
  scheduler.

An earlier measurement of this fix reported 0 claim panics in 20 boots. It was taken with
diagnostic scaffolding that scanned every task slot on every ISR exit, and the perturbation hid
both residues; the table above is the unscaffolded run and is the one to trust. Recorded because
"the instrument changed the result" is the failure mode this section keeps rediscovering.

### 5.2e The spawn/exec path is process-wide singleton state, unserialised — **[G-10]**

**Open, found 2026-08-17.** Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needs in flight lives in
file-scope singletons, and nothing serialises two CPUs through them:

| State | Where |
|---|---|
| `loader_staging` — the one ELF staging buffer | `kernel.h:99` |
| `g_args_argc`, `g_args_total`, `g_args_strbuf`, `g_args_len` — staged argv | `kspawn.c:9-12` |
| `g_spawn_stdio_spec`, `g_spawn_caller` | `kspawn.c:21-22` |

There is no lock in `loader.c` and none around `do_spawn`. `g_exec_reenter_task` (§5.2d) was one
instance of this pattern and is now per-CPU; the rest are not.

Two consequences, of different severities:

- **Correctness.** Concurrent spawns interleave through one staging buffer, and a CR3 can become
  reachable before `create_user_pagedir` has populated its kernel half — which is exactly what
  a supervisor write-fault in `lapic_eoi` looks like, and is the ~20% residue in §5.2d.
- **Authority.** `g_spawn_caller` is written at `do_spawn` entry and read much later by
  `wire_child_stdio`, so a child can have its stdio wired from **the wrong parent's cspace** —
  capability inheritance from a task that never spawned it. That is an authority question, not
  merely a correctness one, and it is why this is filed rather than left as a TODO.

**Not yet reproduced in isolation.** The evidence is the fault signature above plus the code
being plainly unserialised; there is no control arm for it yet, so it is a lead with a
mechanism, not a diagnosis. The fix is almost certainly serialisation of the spawn/exec critical
section rather than making each singleton per-CPU, but that is a design change and belongs in
its own commit with its own witness.

### 5.3 No release provenance — **[I-9]**

The build is verified reproducible and an SBOM is produced, but there are no tags, no
releases, no signed artifacts, and no SLSA provenance. A third party cannot verify that a
`boot.iso` they obtained came from this repository's CI.

*Inbound* dependency verification is in better shape than outbound provenance: the one
network dependency in the build path — the newlib tarball — is pinned by SHA-256, verified on
every invocation (not merely after a fetch), refused **before** unpacking, and quarantined
rather than left in place when it fails. `make smoke-newlib-tamper` exercises that gate in
both directions, so it is a control rather than an assumption. That says nothing about what
leaves the build, which is what **[I-9]** is actually about; it only means the tree is no
longer trusting an unverified 9 MiB blob on the way in.

### 5.4 Cryptography is unaudited

Every primitive — ChaCha20, SHA-256, BLAKE2b, Argon2, the AEAD — is a from-scratch `no_std`
Rust implementation. None has been independently audited, and none is verified
constant-time. Treat them as research code.

### 5.5 Formal verification is narrow

Kani proves properties of capability revocation. TLA+ specifications exist for the capability
algebra and paging isolation (`docs/cap_algebra.tla`, `docs/paging_isolation.tla`) but are
**not model-checked in CI**. The kernel as a whole is not verified, and there is no
refinement proof connecting the specifications to the implementation.

### 5.6 Governance files were mislocated — **[M-3]**

The pull-request and issue templates lived in `docs/`, where GitHub does not look for them,
so neither was ever presented to a contributor. There was no code of conduct, and
`.github/CODEOWNERS` named seven files that do not exist while omitting the files containing
the IPC authorisation logic. All fixed as of 2026-07-27; the `require_code_owner_review`
setting that would make `CODEOWNERS` binding is still off (§5.1).

*(Repository hygiene itself is fine: `git ls-files` reports **254** tracked files with no build
artefacts or vendored binaries — no `kernel.elf`, no `boot.iso`, no object files. A working
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
| Capability model — *design* | 80% |
| Capability model — *enforcement* | **70%** (IPC namespace mediated and identity retired; three ambient console/version paths remain, §1.6) |
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

**Overall: an early but unusually well-instrumented research kernel.** The infrastructure
around it — reproducible builds, measured boot, adversarial CI, formal proofs — is
substantially more mature than the kernel it verifies. Closing **[C-1]** and moving to
untyped-memory object allocation were the two changes that most raised the honest numbers
above; both landed on 2026-07-27. The two that would raise them next are migrating `tasks[]`
off `.bss` (**[I-7]**'s remainder) and getting a second pair of eyes on the capability paths
(**[C-5]**), which is not a technical change at all and is the dominant residual risk.

*The enforcement row read "**45%** (IPC namespace unmediated)" until 2026-08-15 — a
parenthetical naming the defect §1.1 of this same document records as fixed. It was never
revised.*
