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

### 1.6 ~~Three syscalls are still ungated by any capability~~ — **[H-2] FIXED 2026-08-20**

**[I-1]** and **[H-1]** removed authority derived from *identity*. They did not remove
authority derived from *nothing*, and README and the website have both stated the stronger
claim. The complete residual list, so that nobody has to take the absolute phrasing on trust:

| Path | Gate | Assessment |
|---|---|---|
| `SYS_WRITE` fd 1 → the console | none | Correct and deliberate: every task has a stdout, and writing to a terminal is not an authority this system rations. Marked ambient in `SYSCALLS.md` |
| `SYS_WRITE` fd 1 → `klog` | `CAP_KERNEL_LOG` + `CAP_RIGHT_WRITE` | **Fixed 2026-08-20** — **[H-2]**, below |
| `SYS_READ` fd 0 / `SYS_GET_LINE` | none, but both refuse once `console_hw_owned()` | Correctly mitigated; the guard is present and deliberate |
| `SYS_SYSINFO` | none | A version string. Acceptable, and marked ambient in `SYSCALLS.md` |

**[H-2]** was the one with teeth, and it was an asymmetry rather than an oversight in
isolation: the *read* side of the kernel log was converted to require `CAP_KERNEL_LOG` under
**[I-1]** (`SYS_DMESG`), and the write side was never considered. `h_write` clamped to 255
bytes and called `print()`, which appended to `klog` unconditionally — `terminal.c`'s
`klog_append` ran before the `drive_hw` test, so the append survived the handoff to
`console_server`. `klog_buf` is 16 KiB. Any unprivileged ring-3 task could therefore forge
lines that appear in `dmesg` indistinguishable from kernel diagnostics, and could flood 16 KiB
to evict genuine ones — an anti-forensics primitive against the log a maintainer reads after
an incident.

**What it did not reach**, and this is the part of the design that was right: the
tamper-evident audit chain in `src/kernel/kaudit.c` is a separate buffer under a ratcheted,
erased-after-use MAC key (property S19). Forging or evicting `klog` never touched it.

#### The fix, and why it closes rather than narrows the finding

`print()` is split. Kernel-origin output goes through `print()` and always records;
ring-3-origin output goes through `print_from_user(str, may_klog)`, and `h_write` computes
`may_klog` by asking the capability graph — `cap_lookup(CAPSLOT_KERNEL_LOG, CAP_RIGHT_WRITE)`,
with the object type checked too. No uid, no task id, no slot convention: an ambient gate here
would have re-created **[I-1]** inside the fix for **[H-2]**.

The console still takes the bytes either way, which is the distinction the old code did not
draw. Writing to the *terminal* is ungated on purpose; writing to the *kernel's log* is an
authority.

**It closes the finding completely, and the reason is a property of the root cnode rather than
of `h_write`:** `root_cnode[15]` mints `CAP_KERNEL_LOG` with `CAP_RIGHT_READ` and nothing else,
and delegation may only ever reduce rights, so **no task in this system can hold the WRITE
right the gate asks for**. The authority is expressible — mint it with WRITE the day a
userspace logger has a reason to exist — without being granted to anyone. Deleting the append
outright would have been fewer lines and would have made that future case unexpressible.

Witness `make smoke-klog-forge`: a ring-3 probe endowed with `CAP_KERNEL_LOG` (READ — so it can
read the ring back and check its own work, and is still refused the direction it was not given)
pushes 28800 bytes through fd 1, more than the ring holds, and requires both that none of it
appears in `klog` and that a marker seeded before ring-3 entry is still there. Falsified by
`KLOG_WRITE_UNGATED=1` (`make smoke-klog-forge-control`), which restores the unconditional
append: `KLOGTEST: FAIL forged+evicted`, 3 boots in 3, and `smoke-klog-forge` goes red under
the same flag.

Both halves are asserted and both are evaluated before either is reported, so the control arm
exercises both branches on every boot. Asserting only one would pass a half-fix: rate-limiting
ring-3 appends would keep the marker and still leak the forgery, and dropping the bytes while
still advancing the ring would lose the marker.

> *An earlier revision of this section said the cheap remediation was to tag `klog` entries
> with their originating task and rate-limit ring-3 appends, and the thorough one a write-side
> capability. The capability turned out to be the cheap one too — the gate is four lines —
> because the rights that make it fail closed were already minted correctly in 2026-07-27's
> root cnode and nobody had asked what they implied.*

### 1.7 ~~Two syscall wrappers truncated their buffer pointer to 32 bits~~ — **FIXED 2026-08-20** — issue #176

`sys_dmesg()` and `sys_audit_digest()` passed their buffer as
`(uint32_t)(unsigned long)ptr`. The argument registers are 64-bit, so the cast was pure loss:
the kernel received the low 32 bits of the pointer and resolved *that* address in the caller's
own page tables.

**Why a 100-check conformance suite could not see it.** `USER_IMAGE_ASLR_BASE` is 16 GiB with
4 TiB of randomisation, so every static and global in a PIE image is above 4 GiB *by
construction* and was always truncated — while a stack buffer sits near 8 MiB and never was.
Every caller in the tree passed a stack buffer. The two `captest` checks that name these
syscalls both assert a **capability refusal**, and the dispatch gate returns before the handler
ever reads the pointer. The one success-path caller, the shell's `dmesg`, used
`char buf[512]` on the stack. So the defect was 100% reproducible for an entire class of
buffer and reachable by no test in the tree.

**It was not fail-closed.** The `SYS_ERR_FAULT` that surfaced it is what happens when nothing
is mapped at the truncated address. Low user addresses *are* populated — the stack at ~8 MiB,
the heap at 16 MiB in a non-high-heap build — and when the truncated address hits one,
`copy_to_user` writes kernel-supplied bytes into a page the caller never nominated. Confined to
the caller (`user_copy` walks `tasks[cur].cr3`, never another task's), so this is corruption
rather than a privilege boundary — but it invalidates any argument of the form "we validated
the pointer the caller gave us", because the pointer the kernel validated is not the one the
caller passed.

Both wrappers now use `SYSCALL_UPTR()`. Property **S24**. The gate is
`tools/check_syscall_abi.py` (required job `syscall-abi`), which decides the property for all
46 pointer arguments at build time rather than for whichever syscalls a probe happens to call;
the runtime arm is `make smoke-klog-forge`, whose probe reads the log into a `static` — hence
above-4-GiB — buffer, falsified by `SYSCALL_PTR_TRUNC32=1`
(`make smoke-klog-forge-abi-control`), 3 boots in 3.

`user_copy()` still **refuses** an absent page rather than resolving it through
`handle_demand_page_fault()`, and the comment there now says why: that refusal is what kept
this bug fail-closed in the case that was observed, and driving the pager would have allocated
a page at the bogus address and reported success.

> *Issue #176's original analysis was wrong and is corrected on the issue. It reported that
> `pt_walk(tasks[cur].cr3, v)` disagreed with the hardware walk. The two agreed exactly —
> measured, `ucr3 == livecr3` — and the kernel was faithfully walking a different address. The
> observations were right; the inference was not, and it pointed at `paging.c` for a defect
> that lived in `include/syscall.h`.*

### 1.8 A third of the syscall table has no test that runs its handler

**Measured 2026-08-20**, and gated since: **51 of 76** implemented syscalls have their handler
body entered by the three tracked workloads (the scripted ring-3 session, the conformance suite, and the
boot-modules session). The other 25 are listed in `.github/syscall-coverage.yml`, each with a written reason.

This is stated as a limitation rather than a finding because nothing here is known to be
broken. What is known is that a defect in any of those 25 handlers would be invisible in the
same way issue #176 was — and #176 is the reason the number exists at all. `captest` is a
**refusal** suite by construction: its checks for `SYS_DMESG` and `SYS_AUDIT_DIGEST` both
assert `SYS_ERR_PERM`, and the capability gate returns before the handler runs. Both syscalls
were named by the suite; neither handler had ever executed.

`tools/check_syscall_coverage.py` (required job `syscall-coverage`) fails on drift in either
direction, so the number cannot quietly fall. It deliberately does not require 76 of 76 —
that would be a large body of test-writing disguised as a gate. Property **S25**.

**Two of the 33 are cheap and worth doing next.** The pipe family and `SYS_STDIO_INFO` are
uncovered only because `tools/session_test.py` runs no pipeline — a gap in the workload, not
the kernel. And the `uncovered` reasons that name another build which *would* reach a syscall
are **hypotheses this manifest has not measured**; promoting them should be a measurement, not
an edit to the reason.

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

`.github/workflows/ci.yml` defines **77** jobs, `codeql.yml` one more and `ruleset-audit.yml`
one more — **79** across the three, producing **82** status-check contexts. Ruleset `19007209`
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

That intended set is **78 required contexts and 4 reasoned exemptions** — `fuzz` (a 30-second
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
outcome explicitly (`live ruleset 19007209 : <n> required contexts, matches`, or `DIVERGED`, or
`NOT READ`), so a green run is self-evidencing rather than merely silent — the first live run
could only be shown to have read anything by falsifying it afterwards with a bad token.

That is a trade and it is written into the workflow header rather than left implicit — a
credential able to read repository administration now sits in Actions secrets, in order to
detect drift that requires administration access to cause. It is read-only, single-repository,
and revocable by uninstalling the App; the alternative was a check nobody runs, which is what
left the required set at 22 of 66 with no security gate among them.

**The App went live on 2026-08-19, and the audit is now a real check.** The scheduled run at
07:56Z that morning reported

```
jobs across 3 workflows      : 74
live ruleset 19007209        : 73 required contexts, matches
PASS: every CI job is classified — merge-gating, or exempted with a reason
```

and the run 24 hours before it had failed at the secret-presence step with
`RULESET_AUDIT_APP_ID` missing. The workflow itself has not changed since it merged, so the
difference is the App and its two secrets. That the comparison line printed at all is the
evidence: reading a ruleset needs `Administration: read`, which no workflow token can hold.

It failed loudly rather than skipping for every day it was unconfigured, which is why the
transition is legible at all — an audit that skips when unconfigured is a check that cannot
fail, and this repository has been bitten by that twice already (`make test`'s `|| true`, and
the scanner-presence step before #154).

**What keeps [C-6] open is now only the second half.** `--sync-ruleset` writes the ruleset and
needs an admin token, so a PR that adds a gating job leaves the ruleset one context behind until
someone runs it afterwards. This very commit demonstrates it: adding the `doc-claims` job took
the checked-in set to 74 while the live ruleset stayed at 73, and `--check-ruleset` reports
`DIVERGED (1 missing, 0 unexpected)` until the sync is run. Promotion lags a merge by construction; the audit is what makes the
lag visible the next morning instead of indefinitely. Read the count from the API or from that
job's log, never from this paragraph.

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
`#123`'s floor guard did not cover that value: it is higher-half, so `rsp < 0xFFFF800000000000`
passed it. *(Superseded 2026-08-18: the guard is now bounded at both ends against
`[__bss_start, __bss_end)`, and a `.text` pointer is outside that range, so this capture's value
would be rejected and reported today. Detection only — see the ~7% note below.)*

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
after the 2026-08-17 narrowing below and the 2026-08-18 close of [G-10] — the workload still
fails **2 boots in 30** (~7%), for a reason that is still not what the gate tests. Promote it in
the same commit that closes the rest of **[G-9]**, and quote a rate.

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

**What was still open after the exec fix.** Two residues, and neither was the exec race:

- a stale claim that appears in the **boot/spawn phase, before any exec runs** (2 in 30, e.g.
  `task 1 claimed by cpu 3 but that cpu was running 0`, immediately after `PROC_SELFTEST: begin`);
- a CPL-0 fault at **~20% of boots** (6 in 30), `vec=14 errc=0x2` — a supervisor *write* to a
  non-present page — resolving to `lapic_eoi` and `interrupt_handler64`. A CPU taking an
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

**What is still open in [G-9]** is that last ~7%, and it is a different shape again — a bogus
resume `%rsp` handed back by the dispatcher, with the claim invariant broken in the *unclaimed
running task* direction:

```
PAGE FAULT at 0xfffffffffffffff1 err=0x2(not-present,write,supervisor) task=1 'argtest'
  rip=0xffffffff801046f4 cs=0x8 rsp=0xfffffffffffffff9 rbp=0x0 cpu=3
  claim: task 1 running_cpu=-1  percpu_current=[0,0,3,1]
```

`rsp` is `-7` and the fault is at `rsp - 8`: a push onto a garbage stack pointer, i.e. the ISR
epilogue loaded `-7` as the kernel `%rsp` to resume on.

**The floor guard that exists to catch exactly this did not fire, because it had no ceiling —
fixed 2026-08-18.** `interrupt_handler64` rejected a resume value with
`if (rsp < 0xFFFF800000000000ULL)`: a floor and nothing else, so it caught a returned `0`, `1`
or `4` and let every small *negative* value through, `-7` being `0xFFFFFFFFFFFFFFF9` and above
the floor. A guard whose own comment said it was there to catch "a returned 0/1/-1" tested for
two of those three.

It is now bounded at both ends, and bounded from the **linker** rather than a constant. A stack
that moves still satisfies such a bound; one allocated somewhere new fails loudly instead of
silently widening the guard.

> **That bound was wrong for one commit, and the correction is the more useful record.** It was
> first written as `[__bss_start, __bss_end)` alone, on the premise that *every* 64-bit kernel
> stack is a `.bss` array — `per_task_kstacks[]` (paging.c), `ap_idle_stacks[]` (smp.c), and
> `stack_top` / the IST stacks / `early_handler_stack_top` (multiboot.S). Four of those five are.
> **The IST stacks are in `.data`**, emitted in `multiboot.S`'s block beside `gdt64`/`tss64`.
> IST1 serves `#DF`/`#GP`/`#PF` and this guard halts on a rejection, so that kernel died on the
> first ring-3 page fault of any workload that took one — `bogus resume rsp=0xffffffff801a9f50`,
> an address `0xf50` into `ist1_stack_bottom`'s page. Ten CI gates went red at once, every one a
> userspace workload.
>
> The guard now accepts `[__bss_start, __bss_end)` **or** `[ist1_stack_guard, ist3_stack_top)`.
> The premise had been checked against the `.bss` arrays it named and never against the three
> objects it got wrong.

Witnessed by `make smoke-resume-guard-negative` (inject `-7`, the report must appear) against
`make smoke-resume-guard-negative-control` (`RESUME_GUARD_FLOOR_ONLY=1` restores the floor-only
test, the report must be **absent**).

Witnessed in the other direction — the direction whose absence let the `.bss` bound ship — by
`make smoke-resume-guard-ist` (no injection; the captest workload faults through IST1 and must
reach `CAPTEST: PASS` with the guard silent) against `make smoke-resume-guard-ist-control`
(`RESUME_GUARD_BSS_ONLY=1`, the false rejection must be **present**). Every other arm on this
guard injects a bogus value and asks whether the report appears, so all of them measure false
*negatives*; a predicate that rejected the whole address space would pass the lot, and one that
rejected the IST stacks did, with the resume-guard CI job green throughout.

#### Narrowed again 2026-08-20: four producers ruled out, and the fault located

The `-7` above is one signature; it is not the only one, and the search is now much smaller.

**It reproduces, and the earlier "does not reproduce" was a broken harness.** Pinning is what
opens the window — `tools/stress_boot.sh` pins to two host cores for exactly this reason, and an
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
corrupted pointer at all — it is a stack pointer that has ended up **above the top of the stack
it belongs to**, and slot 1's guard page happens to backstop slot 0's top as a side effect of
the layout. Whether that is an underflow on the park path or a top used with a positive offset
is not yet established, and this section will not guess.

**Two eliminations, both measured.**

1. **The claim invariant is intact in every capture from this run** — `running_cpu=0` with
   `percpu_current[0]=1`. The "unclaimed running task" description above belongs to the older
   `-7` signature and is *not* what this one shows. Two different things have been filed under
   one number.
2. **The four `saved_ksp` producers are ruled out.** `preempt_on_tick`, `ipc_block_switch`,
   `sched_yield_switch` and `task_exit_switch` all now validate the value they return, against
   the page tables rather than an address range, and **the guard did not fire once in 57 boots
   that included a reproduction.** Whatever produces this does not come through them. What is
   left is `exec_reenter_switch`, the page-fault path, and the possibility that the resume value
   was never wrong — that the CPU was *already* running on a bad stack when the interrupt
   arrived.

**Why a range check could never have caught it.** `per_task_kstacks`, `ap_idle_stacks` and
`ap_ist` all live inside `[__bss_start, __bss_end)`, and their guard pages are armed by being
made **absent**, not by being placed outside any range. A pointer that has walked into a guard
page passes every address-range test in the tree and then takes a not-present supervisor write
the moment anything pushes to it. The predicate now asks the page tables
(`kern_addr_present()`), which is the only thing that can distinguish a live stack from the
guard beside it.

**This does not fix the ~7%.** The guard is a detector: closing its blind spot converts an
obscure fault inside the ISR epilogue — a banner naming the stub and nothing about where the
value came from — into a line that names the value, the task and the CPU. What produces `-7` is
still unknown, and that is what remains of **[G-9]**.

An earlier measurement of this fix reported 0 claim panics in 20 boots. It was taken with
diagnostic scaffolding that scanned every task slot on every ISR exit, and the perturbation hid
both residues; the table above is the unscaffolded run and is the one to trust. Recorded because
"the instrument changed the result" is the failure mode this section keeps rediscovering.

### 5.2e The spawn/exec path is process-wide singleton state, unserialised — **[G-10]**, closed

**Found 2026-08-17; closed 2026-08-18 in three parts** (page tables, then the authority half,
then the staging window). Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needs in flight lived in
file-scope singletons, with nothing serialising two CPUs through them:

| State | Then | Now |
|---|---|---|
| `loader_staging` — the one ELF staging buffer | unserialised | still one buffer, but every arm → consume window is bracketed by `spawn_stage_acquire()` |
| `g_args_argc`, `g_args_total`, `g_args_strbuf`, `g_args_len` — staged argv | unserialised | same bracket |
| `g_spawn_stdio_spec`, `g_spawn_caller` | globals read long after they were written | **gone** — parameters of `do_spawn_stdio` / `wire_child_stdio` |
| the armed image itself | anybody's to spawn | owned by the task that armed it (§5.2f, **[G-11]**) |

`g_exec_reenter_task` (§5.2d) was one instance of this pattern and became per-CPU. Per-CPU is
deliberately *not* how the rest was fixed: a staging buffer per core is `LOADER_STAGING_BYTES`
of real memory for state that is logically per-*spawn*, so the window is serialised instead.

Two consequences, of different severities — both of them past tense since 2026-08-18, and stated
here as they stood because the order in which they were understood is the useful part:

- **Correctness.** Concurrent spawns interleaved through one staging buffer, and a CR3 could
  become reachable before `create_user_pagedir` had populated its kernel half — which is exactly
  what a supervisor write-fault in `lapic_eoi` looks like, and was the ~20% residue in §5.2d.
- **Authority.** `g_spawn_caller` was written at `do_spawn` entry and read much later by
  `wire_child_stdio`, so a child could have its stdio wired from **the wrong parent's cspace** —
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
  so it keeps translating through the dead task's tables for as long as it stays idle — the
  common case, and the one the probe caught;
- **`SYS_KILL` marks a task dead from another core while it is still executing in ring 3.**
  Nothing IPIs it, so it runs on until its next tick, and the slot allocator (`kspawn.c:167`)
  asks only for `state == 0` — it consults neither `task_running_cpu[]` nor whether any CPU has
  that CR3 loaded. A spawn can therefore recycle the page tables of a **running** task.

The freed frames went straight back to the free list and were handed out as ordinary pages, so
the other core carried on reading and writing through page tables that had come to describe
somebody else's memory. **That is a cross-address-space read/write primitive reachable from
ring 3, not merely a crash** — see `SECURITY.md`, adversary A1.

The symptom that made it visible was narrow and specific: a supervisor **write** fault at
`0xFEE000B0`, the LAPIC EOI register. That register is reached through each task's *own*
`pml4[0]` identity map (`ensure_lapic_mapped` runs per pagedir), so when its leaf PTE was
recycled the next timer tick on that CPU could not acknowledge its own interrupt.

**The fix** is to refuse to free a tree any other CPU has loaded, and to park it for a later
attempt rather than leak it (`pending_aspace[]`, retried on the next rebuild — by which point
the idle CPU has almost always taken other work). Fail closed in both directions: the overflow
leaks rather than freeing in use. The check cannot go stale in the unsafe direction, because no
CPU can *newly* adopt the doomed tree — the only task naming it has already been rebuilt with a
fresh `cr3`, so holders can only leave.

| Arm | Boots | `0xFEE000B0` fault | free-in-use |
|---|---|---|---|
| guarded (`SCHED_INVARIANTS`) | 30 | 0 | 0 |
| guarded, ship config | 30 | **0** | — |
| ship config, before the fix | 30 | 6 | — |
| `CR3_RECLAIM_UNGUARDED=1` | 20 | — | **20** |

Gates: `make smoke-cr3-reclaim` (the fault must be **absent**) and
`make smoke-cr3-reclaim-control` (the free-in-use must be **present**). The two arms assert
different markers on purpose — the free-in-use happens every boot while the fault it causes
lands on only ~20%, so gating the control arm on the fault would make it flaky for no gain.

**What this did to [G-9].** The `PROC_SELFTEST` workload at `-smp 4` went from ~45% of boots
failing to **2 in 30**, and `make smoke-kstack-park` passes in its exact form. It is not zero,
so the gate stays advisory (see §5.2d).

#### The authority half and the staging window: fixed 2026-08-18

**The authority half was removed, not guarded.** `g_spawn_caller` and `g_spawn_stdio_spec` are
parameters now — `do_spawn_stdio(spec)` → `do_spawn_inner(caller, spec)` →
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
interleaving. It is the outermost lock in the kernel — entry points hold nothing when they take
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

The reason is structural, and the trace is what showed it: the 14 windows in a
`PROC_SELFTEST` boot come from three tasks (the in-kernel driver as task 0, `init`, and the
proctest driver) that never overlap, because **every spawner in the tree today is either the
boot path or a child of it** — `init` spawns its servers sequentially, and the driver that
spawns the rest is itself one of `init`'s children, so it cannot be running while `init` is
mid-spawn. Two concurrent spawners is a property of the OS this roadmap is building, not of the
one it has.

**So no gate claims a rate here.** A probabilistic smoke target whose control arm cannot fail
is exactly the "test that cannot fail" this repository refuses to add. What is gated is the
deterministic half — `make smoke-spawn-owner` (§5.2f) — and the serialisation rests on the
structural argument plus the fail-closed ownership check, with `SPAWN_STAGE_UNSERIALISED=1`
retained so the arm is there the moment a workload with two live spawners exists.

**Still open, and unchanged by any of this:** a task can be `state == 0` and still executing in
ring 3 on another core. The CR3 guard makes that memory-safe without making it sensible, and the
slot allocator still reuses such a slot immediately.

### 5.2f The armed image was ambient state — **[G-11]**

**Found and closed 2026-08-18.** The staged image is one process-wide buffer, and until this
change nothing recorded the connection between the task that armed an image and the task that
spawned it. Authority-shaped state that a caller is trusted for *having* rather than for holding
a capability to is the same shape as [G-2]'s ambient `uid == 0`, and it had the same kind of
consequence hiding behind it.

`SYS_SUDO` is where it bites. It re-authenticates the caller and then spawns whatever image is
armed **as uid 0**, endowing it with `CAP_FRAME`, `CAP_USER` and a `CAP_TCB` — and the arm is a
*different syscall* from the consume, so the image being elevated need never have been staged by
the task that typed the password:

1. task A (any task holding the spawn capability) arms its own image;
2. task B authenticates correctly with `SYS_SUDO`;
3. B's successful sudo spawns **A's** program at uid 0.

A confused deputy, reachable from ring 3. It is a G-number rather than a C-number for one
reason: nothing in userspace calls `sudo` today — `include/syscall.h:805` is the only caller of
the wrapper — so the path is latent. Latency is not soundness, and this is exactly the shape of
defect that sat unnoticed for nineteen days as [H-1].

**The fix.** `loader_arm_commit()` is the only way to publish an armed image, and it records the
arming task; `loader_disarm()` clears both together, so a stale owner can never authorise a
later image. `do_spawn` refuses to consume an image whose owner is not the current task, and
`h_sudo` refuses before spending the elevation, auditing the refusal rather than logging a
failure — a correct password that was about to elevate somebody else's program is the
interesting event. Fail closed: an image with **no** recorded owner cannot be consumed at all,
so forgetting to stamp one is a broken spawn rather than a silent ambient one.

**The witness, falsified both ways.** `make smoke-spawn-owner` forges exactly the state a second
task's arm leaves behind — a legitimately staged image whose recorded owner is another task —
requires the spawn to be refused, then re-arms honestly and requires it to succeed, because a
check that refuses everything is not a check. `make smoke-spawn-owner-control`
(`SPAWN_OWNER_UNCHECKED=1`) removes the refusal and reports
`SPAWN_OWNER_SELFTEST: FAIL foreign-image-spawned pid 1` on every boot.

### 5.3 No release provenance — **[I-9]**

`kernel.elf` is verified reproducible and an SBOM is produced, but there are no tags, no
releases, no signed artifacts, and no SLSA provenance. A third party cannot verify that a
`boot.iso` they obtained came from this repository's CI — and, per §5.3a, could not confirm it
by rebuilding either.

*Inbound* dependency verification is in better shape than outbound provenance: the one
network dependency in the build path — the newlib tarball — is pinned by SHA-256, verified on
every invocation (not merely after a fetch), refused **before** unpacking, and quarantined
rather than left in place when it fails. `make smoke-newlib-tamper` exercises that gate in
both directions, so it is a control rather than an assumption. That says nothing about what
leaves the build, which is what **[I-9]** is actually about; it only means the tree is no
longer trusting an unverified 9 MiB blob on the way in.

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
| `kernel.elf`, every boot module, `grub.cfg` — everything this project authors | identical |
| `/.disk/YYYY-MM-DD-HH-MM-SS-00.uuid` | named for the wall-clock second |
| `efi.img`, `efi/boot/bootx64.efi`, `System/Library/CoreServices/boot.efi` | differ; grub embeds that UUID in the loaders it generates |

`grub-mkrescue` stamps that marker into the tree it hands to `xorriso`. `xorriso` itself
honours `SOURCE_DATE_EPOCH` and says so in its log; the marker is not `xorriso`'s to date.

**The first measurement of this said the opposite, and the reason is worth more than the
result.** Two ISOs built back to back were bit-identical, which read as "the ISO is
reproducible" and would have been written down as such. They were identical because both
`grub-mkrescue` invocations landed inside the same wall-clock second — the marker's resolution.
Repeat the pair across a second boundary and the hashes differ; repeat it inside one and they
do not. A measurement fast enough to be convenient was fast enough to be wrong, which is the
failure mode §5.2d keeps rediscovering under a different name.

**What is gated, and what is not.** The `reproducible` CI job compares the `kernel.elf` line of
`.build.sha` across two clean builds, and separately requires the record to name *both*
artifacts — so the ISO cannot silently drop out of the record again, which is the part that
actually failed. It does not compare the ISO, because gating a required check on a wall clock
is a flake, not a gate. `make smoke-repro-sha` holds the recording step to refusing an
incomplete build; `make smoke-repro-sha-control` (`REPRO_SHA_UNCHECKED=1`) restores the old
line and requires it to record one artifact of two and report success.

**Property S17 was worded more broadly than its witness supported** — "the shipped binary
corresponds to the published source", where the thing a third party is shipped is the ISO. It
now names the kernel image, which is what the CI job actually establishes. Closing the gap
means making the ISO reproducible rather than rewording it again: `grub-mkrescue` has no
option to suppress the marker, so the route is to assemble the image with `xorriso` directly,
or post-process the UUID to a value derived from `SOURCE_DATE_EPOCH`. Neither is done, and
until one is, **[I-9]** covers the ISO twice over — no provenance on the way out, and no
rebuild that would confirm it.

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
