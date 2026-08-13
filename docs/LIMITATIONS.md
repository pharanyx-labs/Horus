# Horus — Current Limitations

An honest account of what Horus does not do, does not enforce, or does badly, so that nobody
draws an incorrect conclusion about its readiness. This document is deliberately unflattering.

**Where this document and the code disagree, the code is the source of truth — please open
an issue.**

Findings referenced as **[C-n]** / **[I-n]** are from
[`AUDIT-2026-07-27.md`](AUDIT-2026-07-27.md).

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

### 1.2 ~~Root is an ambient authority parallel to capabilities~~ — **FIXED 2026-07-27** — **[I-1]**

**Resolved.** Every `tasks[current].uid != 0` gate is gone, replaced by a held capability:
`CAP_KERNEL_LOG` for `SYS_DMESG`, `CAP_BOOT_MODULE` for the boot-module surface, and
`CAP_ENCRYPTED_STORAGE` (enforced **by type**) for the object-store API. `SYS_GET_TASK_INFO`
no longer promotes uid 0. **The capability graph is now a complete description of kernel
authority** — the precondition for any confinement or MAC story later.

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

### 1.5 Broad revocation can be forced by an unprivileged task — **[I-3]**

The descendant-closure worklist in `revoke_subtree` is bounded at 256 entries. On overflow
the sweep safely over-approximates by nulling every capability sharing the root `object` —
which means a task that deliberately constructs a derivation subtree larger than 256 members
can force the fallback and destroy an unrelated task's independent capability to the same
object. Fails safe (no descendant survives) but is a denial-of-service on another task's
authority.

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

### 2.25 The write-ahead journal is not durable on real hardware — **[I-10]**

`src/kernel/ata.c` issues exactly three ATA commands: `READ SECTORS` (0x20), `WRITE SECTORS`
(0x30), and `IDENTIFY` (0xEC). There is **no `FLUSH CACHE` (0xE7)** anywhere in the kernel.

`WRITE SECTORS` completes once the data reaches the drive's volatile write cache, which is
enabled by default on essentially every ATA/SATA device. Without a flush after the journal's
commit record, a power failure between commit and platter-write loses the record, and
recovery lands in the state the WAL exists to prevent — the transaction neither applied nor
journalled.

**This is invisible to the test suite.** `smoke-fs-wal` runs QEMU with `cache=writethrough`,
so the emulator supplies the durability the kernel omits. The "crash-atomic" claim is
verified only in the configuration where it is guaranteed by something other than the code
under test. Treat filesystem crash-atomicity as **demonstrated under emulation, unproven on
hardware**.

### 2.3 No kernel object lifecycle

Endpoints and notifications are never reference-counted or destroyed. Nothing ties a kernel
object's existence to a capability holding it alive, and there is no way to release one.

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
| Endpoints | 64 | `MAX_ENDPOINTS` |
| Notifications | 64 | `MAX_NOTIFICATIONS` |
| IPC message | 256 bytes | `IPC_MSG_MAX` |
| Boot modules | 48 | `MAX_BOOT_MODULES` |
| Volume | 16 MiB | `BLOCKS_PER_DISK` |
| Staged program image | 8 MiB | `LOADER_STAGING_BYTES` |

These are `.bss` arrays, not dynamically allocated objects. `cspace_pool[64][256]` alone is
~1.5 MiB of `.bss` against a hard 16 MiB linker ceiling. There is no retyping discipline and
no per-task kernel-memory accounting, so kernel memory exhaustion is not attributable or
preventable. **An OS cannot have a compile-time limit of 64 tasks** — this is the main
structural obstacle to Horus becoming general-purpose.

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
a performance/DoS finding. It did *not* introduce the `%gs`-based per-CPU block itself, so
roadmap 1.2's other half — per-CPU IRQ-nesting state for **[C-3]**'s per-CPU lock — still
needs somewhere to live. See the note on `this_cpu()` in `src/kernel/scheduler.c` for why
`%gs` was not the right first step: the ring-3 return paths load a user selector into `%gs`,
which zeroes the GS base, so a per-CPU base only survives with `swapgs` in every ISR entry
and exit.

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

### 5.2 Security tests are not merge-gating — **[C-6]**

Of ~30 CI jobs, 21 are required status checks — but the security-specific ones are not among
them: capability conformance, kernel W^X, measured boot, boot-module tamper rejection,
SMEP/SMAP presence, flush-on-switch, and stack-guard reseed can all fail while a PR merges
green. The required set is inverted: functional tests block merges, security tests do not.

Additionally, `strict_required_status_checks_policy` is false (stale-base merges are
permitted), and every SAST tool in the security job runs under `continue-on-error`, so
Semgrep, Trivy, gitleaks, and cargo-audit findings are advisory only.

### 5.2b One required check is nondeterministic by construction — **[I-11]**

`smoke-fs-wal` (a *gating* context) kills QEMU the instant a marker appears on the serial
console, then reboots on the same disk image. The marker proves the guest reached that point,
not that its journal writes completed — the serial and IDE paths are independent, and
`cache=writethrough` only makes *completed* writes durable. On a loaded runner the
interleaving shifts and boot 2 fails with `WAL_CRASHTEST: FAIL read` against an unmodified
kernel.

The worse consequence is not the spurious failure but that **a real WAL regression is
indistinguishable from the race** — both produce the same output. A test that cannot tell
"the code is broken" from "the harness was too quick" is not evidence for the property it
claims to establish.

### 5.2c The SMP session soak is not clean, and the cause is unknown — **[G-8]**

`smoke-session-smp-soak` fails at roughly **2–3% per boot** on current `main` — 1 hang in 45
pinned to two host cores, and 1 in 45 on a CI runner. Two distinct signatures have been
captured: one where the session completes 9 of 12 checks and then stalls mid-output, and one
where **boot never reaches the login prompt at all** and the serial log ends at
`[console_server] ready`.

That second signature is the `smoke-console-smp` deadlock's signature verbatim — a defect
root-caused and fixed in PRs #112–#115, whose stress harness has held 24/24, 24/24 and 30/30
since. So the open question is whether that fix is incomplete or a second defect presents
identically. It is **not** the IPC lost-reply race (`#116` is in every tree measured).

The scheduler claim-invariant checker holds 30/30, but that does **not** exclude a leaked
claim: 30 boots witness a 2% event less than half the time. Re-running it at
`STRESS_RUNS=150` is the cheapest discriminator and is the next step.

**Update 2026-08-13 — the proximate mechanism is now established.** A 150-boot soak at
`-smp 4` on `ba84e90`, the first run taken after #140 made kernel fault reports audible during
a live session, caught it once. The fault is a `#GP` **at the `iretq`** in
`isr_common_stub64`: `interrupt_handler64` returned a resume `%rsp` pointing into `.text`, the
stub's 15 `pop`s then loaded registers from instruction bytes, and `iretq` took `CS` from
those bytes. This is proved rather than inferred — the reported `rbp` is bit-for-bit the code
bytes at `resume_rsp + 64`. `TESTS.md` has the disassembly and the arithmetic.

Two consequences for this section. `#123`'s floor guard does **not** cover it: the bad value is
higher-half, so `rsp < 0xFFFF800000000000` passes it. And the *origin* of the value is still
unknown, so **[G-8]** stays open and the job stays advisory. The capture also did not
discriminate on the shared-stack hypothesis — it landed on task 0, which the claim invariant
explicitly excludes (`t > 0`).

One number to keep honest: that run was **1 failure in 150**, which is *not* a measured
improvement on the 2–3% above. Under a true 2.5% rate, ≤1 event in 150 boots has probability
~11%.

**Update — a second capture, and two corrections (2026-08-13).** A dual-arm run (150 boots each
on one host) caught the fault again on `main` at `e9aebdd`, in a boot carrying **two** corrupted
resume values on two CPUs: a `.text` return address, and **`4`**. Three consequences:

- **The shared-stack hypothesis is not supported.** The second event is the first `t > 0`
  capture, and there `task_running_cpu[4] == 0` and `percpu_current_task[0] == 4` — the claim
  invariant **holds**. It is not disproved by one capture, but nothing observed supports it.
- **It is not one bad write.** Two different garbage values in one boot puts the cause upstream
  of any single assignment; no `saved_ksp` write produces `4`.
- **The floor guard did not fire for `rsp = 4`,** which is below its threshold and named in its
  own comment. So the statement above that the guard "does not cover it" is true for the
  higher-half value but must not be read as *the guard works and this slipped past its design* —
  on the one value it was built for, it produced nothing. Until that is explained, treat the
  guard's behaviour as unverified.

**Update — the guard was mute, and that is now fixed and gated (2026-08-13).** The last bullet
is resolved: the guard's report was bracketed `kfault_begin(1)`, and `kfault_begin(1)` is
`panic_begin()`, whose claim is **permanent** — a CPU that asks for it after another CPU's fatal
exception halts *inside* `panic_begin` without emitting a byte. In the two-event capture above,
the fatal `#GP` on cpu 3 printed first and kept the claim, so the guard **could not have been
heard on that boot whether or not it fired**. #140 made this report reach the UART but left it
behind a claim the failure itself takes away. The guard now reports under the bounded claim,
releases it, and only then halts — halting is unchanged and is the fail-closed answer, since
`iretq`-ing onto a rejected value is precisely what must not happen.

Two things follow for this section:

- **Withdraw every "the guard did not catch it" statement about that capture.** The absence of
  the line was never evidence about the guard. `make smoke-resume-guard` /
  `-preclaim` / `-legacy` / `-nofloor` now settle it in seconds instead of at ~1 boot in 150:
  the guard fires, its line reaches the wire even from behind a permanent claim, and both the
  pre-fix bracket and a guard-less build reproduce the silence on demand.
- **A new narrowing, offered as an inference.** The guard-less arm shows that a resume `%rsp`
  of `4` still present at `interrupt_handler64`'s `out->cs` read faults at **`0x94`** — G-8's
  original datapoint, reproduced deliberately. The capture faulted at **`0x4`**, in the stub's
  first `pop`, so on that boot the value was not `4` at the guard *or* at `out->cs`: it became
  `4` in the epilogue window, after the guard and before the stub's `movq %rax,%rsp`. The
  frame's stack canary passed, so this points at a **register** that did not survive rather than
  a smeared stack. It rests on the guard/`out->cs` ordering in a rebuild of an `idt.c` unchanged
  since the capture, not on a retained binary; `TESTS.md` records the check.

**[G-8] stays open** — the origin of the bad value is still unknown and the job stays advisory.
What is closed is the instrument.

The same run was the control for **PR #135** (per-CPU IRQ lock): `main` 1/150, #135 rebased
**0/150**. That is not a significant difference (Fisher p = 1.0) and no improvement is claimed —
but it establishes that the fault is `main`'s, not #135's, which is why #135 was no longer held
for it and merged the same day.

**Until it is diagnosed, the CI job is advisory rather than gating**, because at that rate a
required check goes red on about a third of runs and simply teaches everyone to press re-run —
the reflex that let the `smoke-console-smp` deadlock survive months of CI. That is a
mitigation, not a fix, and it is the second required check in this document to be downgraded
for nondeterminism (see **[I-11]**). See `TESTS.md` for the evidence and the next step.

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

*(Repository hygiene itself is fine: `git ls-files` reports 243 tracked files with no build
artefacts or vendored binaries. A working checkout accumulates ~70 MB of untracked build
output, which is correctly `.gitignore`d.)*

---

## 6. Honest completeness estimate

Against "a complete, self-hosting operating system":

| Area | Estimate |
|---|---|
| Boot and low-level x86-64 | 85% |
| Memory management | 70% |
| Capability model — *design* | 80% |
| Capability model — *enforcement* | **45%** (IPC namespace unmediated) |
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
untyped-memory object allocation are the two changes that would most raise the honest
numbers above.
