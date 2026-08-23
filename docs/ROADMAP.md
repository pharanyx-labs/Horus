# Horus Roadmap

**Objective: a complete operating system built from the ground up, on a kernel small enough
to be verified and a capability model strong enough to be relied on.**

The roadmap is ordered by *assurance value*, not by demo value. A feature that runs on an
unenforced foundation adds surface without adding capability, and increases the cost of
fixing the foundation later. So the sequence is: **make the object model true, make kernel
objects allocatable, then grow the OS on top.**

Findings referenced as **[C-n]** / **[I-n]** / **[F-n]** are from
[`AUDIT.md`](AUDIT.md).

---

## Status legend

| | |
|---|---|
| ✅ | Done and tested in CI |
| ◧ | Partly done — the item's own goal is met, but a **named** remainder keeps its finding open |
| 🚧 | In progress |
| ⬜ | Not started |
| 🔒 | Blocked on an earlier item (none currently) |

`◧` was in use on 1.2 before it was in this table, which is the kind of drift this document is
supposed to catch rather than commit. It earns its place: `✅` next to a finding that
`SECURITY.md` still lists as open is precisely the cross-file contradiction the finding-ID rule
exists to prevent.

---

## Track 0 — Fix the object model (blocking everything else)

This track is the difference between "a capability-based microkernel" and "a microkernel
that has capabilities in it". Nothing in Tracks 2–4 should land before it.

### 0.1 ✅ Capability-addressed IPC — **[C-1]**, **[C-2]** — *landed 2026-07-27*

**Problem.** Endpoints and notifications are addressed by an unmediated integer index; a
`CAP_ENDPOINT`'s `object` field is never consulted on an IPC operation. Any task can
intercept or forge messages to any userspace server.

**Change.** Make the first argument of every IPC syscall a *cspace slot*, not an object
index, and resolve it through the capability:

```c
static int ipc_ep_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out_ep) {
    struct capability *c = cap_lookup(slot, need_rights);
    if (!c || c->type != CAP_ENDPOINT) return -1;
    if (c->object >= MAX_ENDPOINTS)    return -1;
    *out_ep = (uint32_t)c->object;
    return 0;
}
```

Apply to `SEND` (WRITE), `RECV` (READ), `CALL` (both endpoints), `REPLY`, `REPLY_TO`,
`IPC_SENDER`, and to `NOTIFY`/`WAIT_NOTIFY` against `CAP_NOTIFICATION`. **Remove the slot-3
entries from the dispatch table for those syscalls** — the per-slot lookup *is* the gate, and
leaving the table entry would re-admit the `CAP_FRAME` every task holds there.

**Migration.**
- `create_task` stops installing ambient endpoint capabilities; slots 4/5 become `CAP_NULL`
  and are populated only by delegation from `init`.
- `SYS_CONNECT_FS_SERVER` becomes the legitimate acquisition path and mints
  **`CAP_RIGHT_WRITE` only**, so a client can send to the server but never receive on the
  server's endpoint.
- Each client gets a *private* reply endpoint allocated at connect time, retiring the shared
  global `FS_EP_REP` and fixing the `blocked_waiter` collision (**[I-5]**).
- Update `include/syscall.h` wrappers, `fs_server`, `console_server`, `init`.

**Security impact.** Restores confidentiality and integrity for every ring-3 service.
Converts `fs_server`'s reference-monitor design and the `SYS_IPC_SENDER` identity anchor from
aspirational to enforced.

**Witness to add.** Negative conformance tests in `userspace/captest.c`: a task holding an
endpoint capability for object *N* is refused `send`/`recv` on every other endpoint; a task
with no endpoint capability is refused all IPC. *The absence of exactly this test is what let
the defect stand.*

**Delivered.** `ipc_ep_from_slot` / `ipc_notif_from_slot` are the single choke point; the
slot-3 dispatch entries are gone; `create_task` grants only a private per-task reply
endpoint; `SYS_CONNECT_FS_SERVER` mints WRITE-only; `SYS_IPC_REPLY_TO` requires the receive
right; `SYS_IRQ_REGISTER` takes a notification capability. `captest` 29 → 41 checks, and the
suite was falsified against the pre-fix kernel to prove it detects the bug. Retires **[I-5]**
(the shared reply endpoint) as a side effect.

### 0.2 ✅ Retire ambient `uid == 0` authority — **[I-1]** — *landed 2026-07-27*

Replace each `tasks[cur].uid != 0` gate with a distinct capability type — `CAP_KERNEL_LOG`
(dmesg), `CAP_BOOT_MODULE` (module read surface), `CAP_OBJECT_STORE` (the encrypted store
API) — minted by `init` and delegated to exactly the server that needs it. Remove the root
promotion in `SYS_GET_TASK_INFO` and zero `info.eip` for other tasks (**[I-4]**).

**Security impact.** Makes the capability graph a *complete* description of authority, which
is the precondition for any confinement, sandboxing, or MAC story.

### 0.3 ◧ Kernel objects from untyped memory (`CAP_UNTYPED`) — **[I-7]** — *landed 2026-07-27*

> **Marked `◧`, not `✅`, as of 2026-08-17.** The item's goal landed in full and is gated. But
> `SECURITY.md` lists **[I-7]** as an open finding and `LIMITATIONS.md` §3.1 documents the
> remainder, so a `✅` here made one finding carry two statuses in two files. The remainder is
> named in "Not migrated" below and is revisited by 2.3.

**Problem.** `tasks[64]`, `endpoints[64]`, `notifications[64]`, `cspace_pool[64][256]` are
`.bss` arrays under a hard 16 MiB linker ceiling. No retyping discipline, no per-task
kernel-memory accounting, hard ceiling on system size.

**Change.** Follow seL4. `CAP_UNTYPED` names a physical region;
`SYS_RETYPE(untyped, type, count, dest_slots)` carves typed objects — TCB, CNode, Endpoint,
Notification, Frame, PageTable — out of it. Objects are destroyed when the last capability to
them is revoked.

Start by moving cspaces and endpoints off `.bss`, keeping the existing tables as a
compatibility shim during migration.

**Security impact.** Kernel-memory exhaustion becomes attributable and preventable — a task
can only consume kernel memory it holds untyped capability for. Object lifetimes become
capability-governed. This is the prerequisite for a general-purpose OS.

**Delivered.** A 4 MiB untyped arena reserved from the physical pool (`src/kernel/untyped.c`),
split once at boot into `UNTYPED_KERNEL` — the per-task cspace reserve, for which *no
capability is ever minted*, so ring 3 cannot starve task creation — and `UNTYPED_ROOT`, which
`init` holds and delegates onward. Allocation within a region is seL4's monotonic bump
pointer: destroying an object does not return its bytes, so bytes only become reusable once
every capability into the region is gone, and type-confusion-through-reuse is structurally
impossible rather than merely avoided.

`SYS_RETYPE` / `SYS_UNTYPED_INFO` are capability-*addressed* like the IPC syscalls — the slot
argument is the gate, both are `SC_NONE` in the dispatch table. Per-task cspaces are now
`KOBJ_CNODE`s from untyped memory, removing **516,096 bytes (504 KiB) of `.bss`**; endpoints
and notifications are retypable from ring 3 into an index range above the static tables, which
remain as a shim for the well-known service objects the boot protocol names by index.
`endpoint_by_index` / `notification_by_index` are the single resolvers.

Object destruction is a mark-and-sweep over the capability graph (`kobj_gc`, run from
`cap_revoke` and `task_teardown`) rather than a refcount — reachability is computed from the
same graph the security argument is stated over, so the two cannot disagree, and there is no
mint/transfer/grant/revoke site across the C and Rust halves that can be missed.

`captest` 41 → 84 checks. Four independent gates were falsified against the patched kernel to
prove the suite detects their removal: the reserved-slot floor, the cspace range checks, the
capability-type check together with the kernel-reserve guard, and `kobj_gc` itself.

**Not migrated.** `tasks[]` — a TCB is reachable from the scheduler's hot path and from every
trap frame. Retyping a `KOBJ_CNODE` from ring 3 is refused: the object is allocatable but no
capability type names it and no syscall installs one as a task's cspace, so minting one would
be authority with no defined meaning (revisit with 2.3). Reclaiming a dead task's cspace
needs `cap_lookup`'s NULL-cspace → root-cnode fallback removed first, or freeing one would be
an authority escalation rather than a crash.

---

## Track 1 — Correctness and performance foundations

### 1.1 ✅ Make boot-time interrupt enablement explicit, *then* fix the spinlock — **[C-3]**, **[C-3.1]** — *landed 2026-08-11*

The IRQ nesting depth is a single global shared across CPUs, with non-atomic increments and
an unconditional `sti` on release. Under SMP one CPU's release can re-enable interrupts while
another still holds a lock, and the unconditional `sti` re-enables interrupts inside a
caller's own `cli` region — including `user_copy`'s CR3 window, where a preemption leaves a
stale CR3 to restore.

**The obvious fix was attempted on 2026-07-27 and reverted.** Per-CPU depth plus per-CPU saved
`RFLAGS.IF` passes every local gate and then breaks the ring-3 startup handshake in CI
(`smoke-modules` timed out waiting for provisioning; `smoke-coreutils-shell` failed with
`ls: spawn fs_server first`). Base rate on `main` is ~0 — 14 of 15 recent runs fully green —
and the patched branch failed 2 for 2.

Cause (**[C-3.1]**): the unconditional `sti` means every lock taken with interrupts already
masked *enables* them as a side effect. Boot and early init take many such locks, so the
timer preemption the `init` → `fs_server` → shell handshake depends on is a consequence of
the locking defect, not of any stated policy. **The bug is load-bearing.**

**Step 1 has a measurement now (2026-08-10), not an argument.** `IRQ_POLICY_AUDIT=1`
records IF as the *outermost* lock is taken and counts the releases that flip interrupts on
against the caller's own intent — the load-bearing ones. A release restoring IF=1 to a caller
that already had IF=1 changes nothing and is counted separately. The `sti` still fires exactly
as before — but "observation only, so the build boots identically" was **wrong**, and the
numbers this section used to quote were wrong with it. See the correction below.

**The seven sites reproduce. The totals were withdrawn on re-measurement (2026-08-10, later
the same day), and the reason is a defect in the instrument.**

`IRQ_POLICY_AUDIT=1` reports through `panic_str`, straight at the UART, deliberately bypassing
the runtime suppression of `print()`. That suppression is not an inconvenience to route
around — it exists because ring-3 `console_server` owns the serial line, and a second writer
interleaves. The tick-41 report lands on the login prompt and splits it:

```
root@horus\n[irq-policy] handshake-early @tick=41: accidental_sti=96 benign_sti=65 sites=7
```

`root@horus#` then never appears contiguously anywhere in the transcript, so any harness
waiting for it waits forever. **The guest is healthy; the observer is broken.** This is the
`PA[NIC: console_server] ready` bug one level up — the same interleaving the single-writer
console was introduced to fix, reintroduced by an instrument that opted out of it.

Measured **interleaved** — adjacent boots, alternating builds, so host drift cannot explain
it (an earlier blocked design could not have distinguished the two, and its p-value was
withdrawn):

| Build | `session_test.py` failures |
|---|---|
| ship kernel (no audit) | **0 of 10** |
| `IRQ_POLICY_AUDIT=1`, as #124 shipped | **10 of 10** |

That in turn explains the published numbers. When the prompt is split, the harness stops
issuing commands, so the guest legitimately runs nothing more and the counters stop climbing:

| Trajectory | Counters at tick 201 | What it measured |
|---|---|---|
| harness sees the prompt | **420 accidental / 224 benign** | boot **plus** a shell session |
| prompt split by the report | **99 accidental / 67 benign** | boot **plus reaching the login prompt**, zero commands |

**99/67 over seven sites with hit counts 32/31/12/11/7/4/2 is exactly the table this section
used to publish.** It was never "across a scripted shell session" — it is the boot window of a
session that never ran a command, and it was mistaken for a session total. Note this is
*not* a hang, and not **G-8**: an early draft of this correction guessed it might be, on the
strength of frozen counters plus a live timer, and that guess was wrong. Frozen counters with
a live timer is exactly what an idle, healthy kernel looks like.

What still stands from step 1, because it reproduces in the healthy population too:

| Site | Hits @tick 201 (healthy) |
|---|---|
| `cap_install_object` | 189 |
| `cap_consume_slot` | 188 |
| `storage_decrypt_block` | 18 |
| `cap_grant_into` | 12 |
| `storage_encrypt_block` | 7 |
| `create_task` | 4 |
| `user_map_device_page` | 2 |

Seven sites, the same seven, no new ones since `cap_consume_slot`. The distribution, though,
is not the one that was published: the two IPC capability sites are **~90% of all accidental
`sti`s** in a healthy boot and they scale with message traffic, where the stalled table made
them look comparable to `cap_grant_into` and the storage pair. The IPC path *is* the startup
handshake path, which sharpens rather than weakens **[C-3.1]** — but it is a different claim
from the one the old table supported, and it is the reason the counts must be quoted with the
tick they were sampled at. They are cumulative and still climbing.

**Every one is a syscall-context lock user**, which is the whole mechanism in one line: `int
0x80` clears IF on entry, so a syscall handler always starts with interrupts masked, and the
first lock it takes and releases turns them back on for the rest of that syscall. That is
**[C-3.1]** measured rather than argued, and it explains why the ring-0 preemption guard in
`preempt_on_tick` was needed and why the naive per-CPU lock broke the handshake.

Two things this immediately tells step 3. The list is *short* — seven sites, not a diffuse
property of the whole kernel — so making each window explicit is tractable. And it is not
static: `cap_consume_slot` is second on that list and was added on 2026-08-10 by roadmap 1.3's
reply capability, so the set grows as the kernel does. Re-measure before changing the lock, not
once.

A third thing, learned by taking that instruction literally: **re-measuring is what caught the
instrument.** The site list was stable, so a session that trusted the published table would
have found nothing wrong and proceeded to build step 3 on a number drawn from a hung boot.
What exposed it was running a *control* — the ship kernel, same harness, same host — before
attributing anything. That is the same procedure that separated a real regression from a
pre-existing one in 1.3, and the same one that showed **G-7**'s checker rather than the
scheduler was at fault.

**The counting itself is sound** — what was wrong is the readout, and only once the shell is
up. `IRQ_POLICY_QUIET=1` suppresses every timer-driven report and leaves the counters intact,
which is both the fix and the falsification: same instrumentation, no printing, and the
session completes at the ship kernel's rate.

**Step 2b landed 2026-08-11: the readout is in band, and quiet is now the default.**
`SYS_IRQ_POLICY_INFO` hands the counters to userspace on request; the shell's `irqpolicy`
builtin prints them through `console_server` like any other program. The kernel is no longer a
second writer at all, so there is nothing to interleave — and because the readout is on
demand, it can be taken *after* a representative workload instead of at a fixed tick. That is
what makes a total session-scale rather than boot-scale, which was the whole defect.

`make measure-irq-policy` is the supported way to take it. Fourteen commands, every one a
`console_server` round trip:

```
irq-policy: accidental_sti=1439 benign_sti=720 sites=7 @tick=693
```

| Site | Hits |
|---|---|
| `cap_install_object` | 685 |
| `cap_consume_slot` | 684 |
| `storage_decrypt_block` | 41 |
| `cap_grant_into` | 12 |
| `storage_encrypt_block` | 11 |
| `create_task` | 4 |
| `user_map_device_page` | 2 |

**This is the table step 3 should be designed against**, and it says something the withdrawn
one did not: the two IPC capability sites are **95% of all accidental `sti`s** and they scale
with message traffic, while the other five are effectively fixed boot-time costs. Making the
windows explicit is therefore mostly a question about *two* functions on the IPC path — which
is the same path the startup handshake runs on, and so exactly where the July attempt broke.

Gated like `SYS_DMESG` (`CAP_KERNEL_LOG`, READ) rather than on fresh authority, and absent
from the dispatch table outside `IRQ_POLICY_AUDIT` builds, so the ship kernel answers
`SYS_ERR_NOSYS`. `captest` 88 → 89, falsified in both directions: removing the capability gate
fails `irq-policy-info-allowed-without-kernel-log-cap`, and a kernel/userspace flag mismatch
fails `irq-policy-info-present-in-ship-kernel`.

### Delivered 2026-08-11 — steps 1 and 3, together

**The policy is written down** in [`ARCHITECTURE.md` §6, "Interrupt policy"](ARCHITECTURE.md),
as a table of contexts and their `IF`, every row of which `make smoke-irq-policy` asserts. The
short version: ring 0 runs masked and is not preemptible; ring 3 and a parked CPU's idle loop
run with `IF=1`, each set explicitly in the trap frame that enters them; and **a critical
section returns the interrupt state it was given** rather than asserting one.

**One window genuinely needs interrupts on, and now asks.** The TLB-shootdown wait
(`smp_maybe_shootdown`) spins for acknowledgements that arrive as IPIs, so a CPU waiting there
with `IF=0` cannot ack another initiator and the two wedge until the backstop expires. Its
comment has always said "MUST be called with interrupts enabled"; nothing provided that except
the accidental `sti`. It now enables interrupts deliberately, restores the previous state
afterwards, and **panics if the caller holds a spinlock** — the other half of its stated
precondition, which had never been checked.

**Step 3: the lock.** `spin_lock`/`spin_unlock` keep a per-CPU nesting depth and a per-CPU
saved `RFLAGS.IF`; the outermost release restores the caller's own `IF`. That closes **[C-3]**
(a global non-atomic depth, so one CPU's release could unmask another's critical section) and
**[C-3.1]** (the unconditional `sti`) in one change. `IRQ_LEGACY_GLOBAL_LOCK=1` rebuilds the
old lock exactly, which is how this was measured rather than asserted — the role
`EP_QUEUE_SLOTS=1` plays for 1.3.

**Why it works now when the July attempt did not.** The 2026-07-27 patch was not wrong; the
tree was. The accidental `sti` was load-bearing because a ring-0 tick could switch a CPU away
mid-syscall, and three subsystems were subsequently changed to route around **[C-3.1]** —
above all `preempt_on_tick`'s ring-0 guard, widened from `cpu == 0` to every CPU precisely
because of it (the comment there names C-3.1). With that guard, a ring-0 tick is never a
switch point, so the `sti` no longer produces the preemption anything depended on. This change
is safe *because* those workarounds exist. It is also what makes them re-examinable, since
interrupt policy is now stated instead of emergent.

**The equivalence measurement.** Both builds count the same predicate — an outermost release
whose caller had `IF` clear. The legacy build fires an `sti` for it (`accidental`); the new one
suppresses it (`suppressed`). Same `make measure-irq-policy` workload, 14 commands:

| Build | accidental | suppressed | benign | total releases |
|---|---|---|---|---|
| `IRQ_LEGACY_GLOBAL_LOCK=1` | **1439** | 0 | 720 | **2159** |
| default (per-CPU) | **0** | **2159** | 0 | **2159** |

The totals are identical, which is the point: the same population of releases, with the 1439
unwanted enablements removed and nothing else changed. The 720 previously "benign" releases
were benign only *because an earlier accidental `sti` had already turned interrupts on* — once
that stops, every caller is correctly observed to have had `IF=0`. (The per-site table
saturates at `IRQ_SITE_SLOTS` in the new build for the same reason: the legacy lock hid every
lock site after the first in each syscall, so seven sites were visible where there are at
least twelve.)

**Rates, interleaved and pinned** (`tools/session_test.py`, adjacent alternating boots, host
CPUs 0,1):

| Harness | legacy lock | per-CPU lock |
|---|---|---|
| `session_test`, `-smp 1`, 20 boots/arm | 0/20 | 0/20 |
| `session_test`, `-smp 4`, 40 boots/arm | 3/40 | 1/40 |
| `modules_session`, 6 boots/arm | 0/6 | 0/6 |
| `coreutils_session`, 8 boots/arm | 0/8 | 0/8 |

`modules_session` and `coreutils_session` are the two harnesses the July attempt actually
failed (`smoke-modules` timed out waiting for provisioning; `smoke-coreutils-shell` failed with
`ls: spawn fs_server first`). Neither reproduces on either arm now.

**The `-smp 4` difference is not a claim of improvement** — 3/40 against 1/40 is well inside
noise at this sample size, and it is not what the change is for. Every failure in both arms was
inspected and every one is **G-8 signature A**: the ring-3 shell faults and `init` relaunches
it, which the exit-reason work (#130) now prints in band — `init: shell exited: faulted on
memory access at addr=0x1065e4f33b2 rip=0x1065e4f33b2 err=0x14`. `rip == addr` with `err=0x14`
is a ring-3 instruction fetch from an unmapped page, and it was read here as a userspace defect
unrelated to interrupt policy. **[G-8]**'s diagnosis on 2026-08-17 supersedes the "userspace
defect" half of that reading: a ring-3 task resumed from a trap frame two CPUs had been writing
will fetch from wherever the corrupted frame said, so an unmapped-page instruction fetch is a
*symptom* of the shared kernel stack rather than an independent bug. The load-bearing half
stands unchanged — the rate was the same on both arms, so it was never about the lock. The claim supported here is the negative
one: **the per-CPU lock does not raise the failure rate**, on a sample sized to see a ~5% rate,
and it does not cost wall clock (`-smp 1` means 14.44 s vs 14.47 s).

The two SMP gates that the accidental `sti` used to break, both 30 pinned boots on the new
lock: `smoke-console-smp-stress` **30/30**, `smoke-sched-invariants-stress` **30/30**.

**The gate.** `smoke-irq-policy` gains a sixth milestone, `outermost-lock-release`, recording
`IF` immediately after the first outermost `spin_unlock` of the boot — the one observation that
separates the two locks. Expected 0 by default and 1 under `IRQ_LEGACY_GLOBAL_LOCK=1`, so both
arms are gated rather than one merely tolerated, and an unconditional `sti` cannot come back
silently. Falsified by crossing the expectations: `IRQ_POLICY: FAIL outermost-lock-release
IF=0 expected 1`.

---

Original plan, retained for the record:

1. ~~Make boot-time interrupt enablement explicit — find every window relying on the accidental
   `sti`, issue or defer `sti` deliberately, and write the policy down.~~ **Done 2026-08-11.**
2. ~~Add a self-test asserting `IF` state at the boot milestones so the dependency cannot
   silently return.~~ **Done 2026-08-10** — `make smoke-irq-policy`, gated in CI. Records IF
   at `post-idt`, `post-paging`, `post-protections`, `kernel-ready` and
   `first-syscall-entry`; **all measure 0 today**, which is exactly why the accidental `sti`
   is load-bearing. Falsified both ways: flipping an expectation fails with the mismatch, and
   deleting a milestone hook fails with `milestone-never-reached` rather than quietly passing
   on four checks instead of five.
2b. ~~**Re-establish step 1's instrument.**~~ **Done 2026-08-11** — `SYS_IRQ_POLICY_INFO` plus
   the shell's `irqpolicy` builtin read the counters in band; `IRQ_POLICY_QUIET` defaults on so
   the kernel never writes at the UART behind `console_server`; every report carries `@tick=`;
   `make measure-irq-policy` reproduces the session-scale figure above.
3. ~~Then land the per-CPU, IF-preserving lock.~~ **Done 2026-08-11**, in the same PR as
   step 1 — the instruction not to attempt step 3 alone was followed: the policy step 1 writes
   down is exactly what step 3's diff has to state, and landing a policy document the code
   contradicted would have been worse than either.

### 1.2 ◧ `%gs`-based per-CPU data — **[I-6]** performance goal met by other means

**Done, differently.** The MMIO read is off the hot path: `this_cpu()` derives the CPU id
from the TSS selector in `TR` (`cpu = (str() - 0x38) / 0x10`) rather than reading the LAPIC.
Every CPU already `ltr`s a distinct TSS, so the identity was already in a register; `str`
costs a register read against the hundreds of cycles an uncacheable MMIO read costs. Verified
per-core against the LAPIC at bringup (`percpu_id_verify_self`, `make smoke-percpu`).

**Why not `swapgs` first.** The ring-3 return paths (`scheduler.c`'s iretq epilogue,
`drop_to_ring3`) load `0x33` into `%gs`, and loading a selector into `%gs` zeroes the GS base
in long mode — so a per-CPU base installed without `swapgs` does not survive the first return
to ring 3. Doing it properly needs a CS-conditional swap on every ISR entry (exceptions
arrive from ring 0), matching swaps on every exit including the epilogue that `iretq`s into a
*different* task's frame, and the NMI/IST re-entrancy hazard behind a long line of CVEs. That
is a large, high-risk change to the most safety-critical assembly in the tree, and the
performance argument for it is now spent.

**Still open.** A per-CPU *block* — somewhere to put the per-CPU IRQ-nesting state that
**[C-3]**'s per-CPU lock needs, and a current-TCB pointer. That is the remaining reason to do
this, and it should be justified by 1.1's needs rather than by syscall cost. Note the staged
`syscall_entry` stub already carries a balanced `swapgs` pair for whoever takes it on; the
preconditions blocking `EFER.SCE` are documented there and asserted by `smoke-percpu`.

### 1.3 ✅ Multi-slot endpoint queues, reply capability, and a blocking receive — **[I-5]**

*(A note here previously raised this item to a correctness fix on the strength of finding
**G-8** signature C. That diagnosis was wrong — C was a startup race plus a userspace loop
retrying `SYS_ERR_PERM` forever, not endpoint contention, and it is fixed in userspace. This
item returns to its original standing: the poll-on-contention busy-wait remains a real
limitation with no witness of it causing a hang. See `TESTS.md` for the corrected finding.)*

**Queues landed 2026-08-10; the reply capability has not.** Each endpoint now holds a bounded
FIFO of `EP_QUEUE_SLOTS` (4), so concurrent senders enqueue rather than collide. Measured on
the 4-client concurrency test under single-core starvation: mean **7042 ms → 5162 ms**, and the
single-slot build's completion times came in three discrete clusters ~520 ms apart — retry
rounds — which the queue removes entirely. `EP_QUEUE_SLOTS=1` restores the old design exactly,
which is how the benefit was measured rather than asserted.

**Reply capability landed 2026-08-10.** `CAP_REPLY` is minted by `SYS_IPC_RECV` naming the
sender of the dequeued message and consumed by `SYS_IPC_REPLY_TO`. Reply forgery is now
unrepresentable rather than gated: no capability, no reply; the first reply spends it; the
capability names the client and cannot be retargeted. `captest` 84 → 88 checks, falsified in
two directions.

**Blocking receive landed 2026-08-11 — this item is complete.** `SYS_IPC_RECV_BLOCK` sleeps on
an empty queue instead of returning `-2`, and both ring-3 servers use it.

The interesting half is not the sleep, it is the **authority**. A blocking receive is completed
by the *sender's* syscall, running on the sender's CPU in the sender's cspace, so the one-shot
`CAP_REPLY` cannot be minted by the path `SYS_IPC_RECV` uses — `cap_install_object` installs
into `get_current_task()`, which is the wrong task here. `cap_install_reply_for` mints it into
the receiver's cspace instead, with the type, rights and destination slot all fixed at the call
site so it cannot become a general "write authority into another cspace" primitive. Get this
wrong and a woken server holds a request it has no right to answer — a receive that is *not*
equivalent to the polling one. `make smoke-recvblock` fails if the mint is removed.

Measured on `tools/session_test.py`, interleaved and pinned, both arms completing the same
checks:

| Build | `-smp 1` mean | `-smp 4` mean | Failures |
|---|---|---|---|
| polling servers | **15.18 s** | 4.69 s | 0/10, 0/12 |
| blocking servers | **6.25 s** | 3.88 s | 0/10, 0/12 |

Single-core ranges do not overlap (slowest blocking boot 6.63 s, fastest polling boot 14.63 s).
The four-core gain is smaller, which is the expected shape: spare cores absorb the wasted turns.
`console_server`'s own comment had already named this — "a second busy-spin server alongside
fs_server starves the shell under emulation" — so the cost was known and the yield was treated
as the mitigation. It was not; a yielding server is still RUNNABLE at every scheduling decision.

`captest` 89 → 96 checks, and the new suite was falsified in four directions: a receive that
does not block, a wake that mints no reply right, a *polling* server (which must trip the
one-syscall-per-message assertion, or the test could not tell the two apart), and a dropped
READ requirement.

**The first version of this shipped a lost wakeup, and every one of those gates passed on it.**
Recorded because the reason they passed is structural, not careless.

The mint was placed after `state = TASK_RUNNABLE` and after `ipc_unlock`, to keep `cap_lock`
from nesting under the endpoint lock. But a task is schedulable the instant its state flips:
another CPU takes it, it returns to ring 3, services the request and calls `SYS_IPC_REPLY_TO`
before the mint lands. `cap_lookup` finds no `CAP_REPLY`, answers `SYS_ERR_PERM` — a
*permanent* code — and the server correctly drops the reply, because the retry contract forbids
looping on it. The client then waits forever.

Every single-CPU gate is blind to it: with one CPU there is no second CPU to run the server
inside the window. `smoke-recvblock`, `smoke-captest`, a 17-target sweep and 61 of 63 CI checks
all passed. What found it was running the thing the change was meant to improve — a session —
against a control, on a **loaded** host: 5 failures in ~15 boots against 0 for the control.
The mechanism was then *witnessed* rather than inferred, by instrumenting `console_server`'s
silent permanent-drop branch and reproducing with the marker present in 4 of 5 failing boots.

The fix mints under `ipc_lock`, before the wake, and both completion paths now obey one rule
without exception: **a receiver holds its reply right before it is schedulable.** `cap_lock`
nesting inside the endpoint lock is a new order and is safe because it is the only one — no
path takes an IPC lock while holding `cap_lock`. `TESTS.md` carries the reproduction recipe
(four guest vCPUs squeezed onto one host core against three hogs), because an idle host will
not show it. Interleaved under that recipe, 25 boots per arm: **8/25 failures pre-fix, 0/25
after.** All four falsifications were re-run against the fixed code, since the mint moved.

Two smaller defects came out of the same review: `SYS_IPC_RECV_BLOCK` could leak `IPC_AGAIN`
from its inline path if a second receiver drained the queue between the empty test and
`sys_ipc_recv` — a contract violation its own selftest asserts against, and one both servers
would treat as fatal — and an abandoned wait could leave `ipc_recv_block` set, which would make
`SYS_IPC_REPLY_TO` refuse every future reply to that task.

**Still open, and now a different item:** priority inheritance. The kernel records that a task
is waiting on an endpoint, which is the prerequisite, but nothing propagates priority along
that edge — and there are no task priorities to propagate yet.

A bounded FIFO per endpoint, plus a **one-shot reply capability** minted at call time and
consumed on reply (seL4's reply object). This makes reply forgery *structurally* impossible
rather than merely gated, removes the poll-on-contention busy-wait, and is the precondition
for priority inheritance.

### 1.4 ✅ Fail-closed user copies — **[C-4]**

*Landed 2026-08-13.* `copy_from_user`/`copy_to_user` clamped to `USER_MEM_MAX_COPY` and
returned success; they now refuse. No explicit partial-copy API was needed: an audit of all
~89 call sites found every one already bounded below the ceiling, by its own kernel staging
buffer or by chunking to `USER_MEM_MAX_COPY` before the call, so the refusal is
behaviour-preserving.

The one caller that was not merely latent was `h_boot_module_read`, which has no staging
buffer (it reads through `PHYS_KVA`) and returned the unclamped length — reporting bytes it had
not written. It now short-reads honestly, which its ABI already promised.

Note for anyone extending this: the refusal is **unreachable from ring 3**, because every
syscall clamps to a small kernel buffer first. It is defence in depth against the next caller,
not a hole that was open to userspace. See `docs/LIMITATIONS.md` §1.4.

### 1.5 ✅ 64-bit-clean heap arithmetic — **[I-2]**

*Landed 2026-08-13.* `SYS_SBRK`/`SYS_BRK` are `uint64_t` end-to-end, with the overflow check
before the range test as specified (and a correct signed-negative `sbrk` shrink, via
`-(x+1)+1` so `INT64_MIN` has no undefined step).

**The item was scoped too narrowly.** A third truncation lived in the *pager*, not the
syscalls: `handle_demand_page_fault`'s region gate cast the heap bounds to `uint32_t` when
calling `rust_validate_page_fault`, which takes `u64`. That one was not latent — it meant a
heap outside the premapped low window could not be demand-paged **at all**, and failed
silently, because a ring-3 fault prints nothing. So this item was partly a *functional ceiling
on the address space*, not only arithmetic hygiene — which matters for 2.1 (VM objects), whose
whole point is placing regions freely.

Witnessed by `make smoke-heap64` (`USER_HEAP_HIGH_BASE=1`, heap at 8 GiB, `captest`
exercising `sbrk`/`brk` and writing to the page). The control arm is real: without the fix the
same target reports `CAPTEST: FAIL`.

### 1.55 ✅ Make the write-ahead journal actually durable — **[I-10]**, **[I-11]** — *landed 2026-08-16*

**[I-10] landed 2026-08-16.** The driver now implements `FLUSH CACHE` (0xE7) with its own
BSY budget (~30 s, per ATA-8; the sector path's 2 s cap would time out mid-flush), and
`journal_commit()` places barriers at three points, not the two this item originally
specified:

1. after the journal data, **before** the commit header — the write-ahead rule itself. This
   is the one the original text omitted, and it is the most important: without it the header
   can reach the medium first and recovery redoes a valid, correctly-HMAC'd transaction from
   data sectors that were never written.
2. after the commit header, before applying home.
3. after applying home, before clearing the header.

`journal_recover()` carries the same barrier before clearing a replayed header. Barrier
failure is not advisory: 1 and 2 abort with home untouched, 3 leaves the header for the next
mount to replay.

**The originally specified test would not have worked, and the reason is worth recording.** A
`cache=writeback` variant does **not** distinguish a flushing kernel from a non-flushing one:
guest writes land in the host *page cache*, which outlives the QEMU process, so killing QEMU
loses nothing either way. No QEMU cache mode makes a two-boot outcome depend on whether the
guest flushed. What works is inverting the observation — `blkdebug` fails every
`flush_to_disk` and the gate asserts the kernel refuses the transaction (`smoke-fs-wal-flush`),
plus an IDE command-register trace asserting the barriers bracket the commit record in the
right order (`smoke-fs-wal-order`). Both are falsified by the `WAL_NO_FLUSH=1` control arm.

**[I-11] closed the same day, but not by the mechanism this item specified.** `isa-debug-exit`
does not work: on QEMU 10.0.11 the port write at `0x604` does not terminate the process (with
or without `-no-shutdown`), and the `lidt 0x0; int $0x0` triple-fault fallback faults while
*reading* its own descriptor at address 0 and is caught by the kernel's page-fault handler.
Both were tried and reverted, and the measurements are kept at the crash hook.

QMP does work. Boot 1 now ends by asking QEMU to quit over its monitor socket
(`tools/qmp_quit.py`) and **waiting for the process to exit**, so the end of a run is a process
exit rather than a signal sent on a string match; a guest that reaches the marker and then
fails to leave is a timeout, not a pass. The harness fails **closed** — no `python3`, no
executable helper, or an undeliverable quit each fail the run rather than reverting to
signalling, because a silent fallback would be this finding wearing the fix's name.

Half of the finding had already been closed by [I-10] without anyone noticing: barrier B runs
*before* the crash marker is printed, so the journal write is on stable media by the time the
harness sees it. The physical race was already gone; what remained was that the harness could
not distinguish "the guest finished" from "we were too quick".

Also fixed here: `qemu_alive()` replaced a bare `kill -0` that could never observe an exit (an
unreaped QEMU is a zombie whose PID still answers it), and an exit the harness had *asked for*
was being misreported as a triple fault.

`smoke-fs-wal` is promoted back to a required check — [I-11] was the entire reason for its
exemption, and a stale exemption reason is the drift **[C-6]**'s mechanism exists to prevent.
20/20 two-boot runs passed locally; if CI shows residual flakiness, demote it again *with the
evidence*, not silently.

### 1.6 ✅ Unbounded revocation closure — **[I-3]** — *landed 2026-08-16*

Replace the fixed 256-entry worklist with an iterate-to-fixpoint or mark-and-sweep closure,
removing the object-wide overflow fallback and with it the denial-of-service on a peer's
independent capability.

**Delivered** as mark-and-sweep in place. The mark lives in the capability's own `typ` field in
two states — `CAP_MARK_NEW` (in the subtree, children not yet expanded) and `CAP_MARK_DONE`
(expanded) — with `serial` and `badge` left intact so the derivation tree stays readable
mid-sweep. That needs no side array and no allocation, which is the point: the old 256 bound
existed precisely because a `no_std` kernel has nowhere to grow one.

Each capability is marked at most once and promoted `NEW -> DONE` at most once, so the fixpoint
loop terminates without a depth bound or a cycle check, and costs O(subtree x slots) —
proportional to what the revoker actually derived, not to the whole system.

The object sweep survives only on the revoke-by-object path (`root_serial == 0`), where there
is no lineage seed and it is the exact answer rather than a fallback.

Two regression tests witness it and both are falsified by `--features=revoke_legacy_bounded`,
which compiles the old bounded closure back in. The `rust` CI job runs that control arm and
fails if the tests pass against it — a falsification that is executed, not asserted.

### 1.7 ◧ Serialise the spawn/exec path — **[G-10]** closed, the rest of **[G-9]** open

Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needs in flight is a process-wide singleton — the one
ELF staging buffer `loader_staging`, the staged argv `g_args_*`, `g_spawn_stdio_spec` and
`g_spawn_caller` — with no lock in `loader.c` and none around `do_spawn`. The path was written
for a kernel that spawned from one core.

**Partially delivered 2026-08-17.** One of those singletons, the exec re-entry hand-off, was
being consumed on the exit of every syscall on *every* CPU with no ownership test, so an exec
armed on one core was taken by another — which resumed that task's freshly built trap frame
while the core that ran the exec was still on it. It is per-CPU now, with a standing assertion
and a control arm (`EXEC_REENTER_GLOBAL=1`): **0 thefts in 30 boots against 5 in 20**, gated by
`smoke-exec-reenter`. That took the `PROC_SELFTEST` workload at `-smp 4` from ~45–50% failing to
~27%.

**A second singleton fixed the same day, and it was the severe one.**
`create_user_pagedir()` recycled a slot's page tables while another CPU still had them in CR3 —
a CPU parked in `kernel_idle()` never reloads CR3, and `SYS_KILL` marks a task dead while it is
still running in ring 3 elsewhere. The frames returned to the pool and were handed out as
ordinary pages under a live core: a **cross-address-space read/write primitive reachable from
ring 3**, surfacing as a supervisor write fault at the LAPIC EOI register. `switch_cr3()` now
publishes each CPU's loaded CR3, the reclaim refuses to free a tree anyone else holds, and the
tree is parked for retry rather than leaked. Falsified with `CR3_RECLAIM_UNGUARDED=1`:
**20 free-in-use boots in 20** unguarded, and the fault **0 in 30 against 6 in 30**. Together
with the exec fix this took the workload from ~45% of boots failing to **2 in 30**, and
`make smoke-kstack-park` now passes in its exact form.

**The remaining singletons closed on 2026-08-18, and [G-10] with them.** The lock was the
likelier shape and it is what landed — per-CPU is right for a hand-off and wrong for a staging
buffer, which is `LOADER_STAGING_BYTES` of real memory for state that is logically per-*spawn*.

- **The authority half was deleted rather than guarded.** `g_spawn_caller` and
  `g_spawn_stdio_spec` are parameters now (`do_spawn_stdio` → `do_spawn_inner` →
  `wire_child_stdio`), so a child's stdio cannot be wired from a parent that did not spawn it.
  Not "unlikely": unexpressible.
- **The staging window is serialised.** `spawn_stage_acquire()` / `spawn_stage_release()`
  bracket every arm → consume region — the four syscall entry points, both boot launchers,
  `SYS_SUDO`'s consume and all ten self-test staging sites. Taken *before* the arm, because an
  arm landing inside another CPU's window is the interleaving. Outermost lock in the kernel;
  `IF` is already 0 for the whole spawn (`int 0x80` is an interrupt gate), so it costs no
  interrupt latency.
- **Closing it surfaced [G-11], which is the more serious half.** The armed image was ambient
  state: nothing recorded who armed it, and `SYS_SUDO` spawns whatever is armed **as uid 0** in
  a different syscall from the arm. A task's correct password could therefore elevate another
  task's program. `loader_arm_commit()` now stamps the arming task and consumption refuses any
  other, fail closed on an unowned image, audited on refusal. Witness `make smoke-spawn-owner`,
  falsified by `SPAWN_OWNER_UNCHECKED=1` — the control arm spawns the foreign image on every
  boot. See `SECURITY.md` **S21** and adversary **A1c**.

**On the rate this section would like to quote, and does not have.** The interleaving is not
reachable in any workload this tree can boot, and `SPAWN_STAGE_TRACE=1` is what established
that rather than an argument: it reports every entry to the staging window and every arrival
that finds another CPU inside one. A `PROC_SELFTEST` boot at `-smp 4` enters the window
14 times from three different tasks on three different CPUs, and **not once** do two overlap —
even with `SPAWN_STAGE_WIDEN=1` holding each window open for 12M `pause` iterations. The reason
is structural: every spawner in the tree today is `init` or one of `init`'s children, so the
driver that does most of the spawning cannot be running while `init` is mid-spawn. Two
concurrent spawners is a property of the OS this roadmap is building, not of the one it has.
**So no gate claims a rate here** — a control arm that cannot fail is not a control arm — and
`SPAWN_STAGE_UNSERIALISED=1` is kept for the day a workload with two live spawners exists.

**[G-9] closed 2026-08-21**, so what kept this ◧ is gone: the residue was three further
components, the last of which was the claim auditor clearing its own exemption before the release
it exempts — a false positive of the checker rather than a leak. Natural rate 9/200 → 0/200,
mechanism proven 8/10 against 0/10 with the window widened in both arms. `smoke-kstack-park` was
promoted on 2026-08-22, one merge later as [C-6] describes, with its workload measured at 0
failures in 200 boots. **No CI exemption now stands for an open defect.** Also unchanged: a task can be `state == 0` and
still executing in ring 3 on another core — the CR3 guard makes that memory-safe without making
it sensible, and the slot allocator still reuses such a slot immediately.

> *Corrected 2026-08-18: this paragraph read "still reddens ~27% of the time for this". ~27% was
> the rate after the exec fix and **before** the CR3 guard — the number eighteen lines above
> supersedes it, and the sentence also charged the residue to the wrong half of the item. A
> stale figure and a wrong attribution in the same clause, thirty lines from the measurement
> that refutes both.*

---

## Track 2 — Toward a complete OS *(Track 0 complete)*

### The order these are taken in, and why

Track 2's items are listed by subject below, but they are **worked in the order set out here**.
The dependencies are real, and taking them out of order means building twice.

| # | Item | Why here |
|---|---|---|
| 1 | **`libhorus`** — a freestanding mini-libc and a program template (part of 2.5) | Touches no security surface at all, and every later step multiplies its cost by every new server it adds |
| 2 | **2.1** Frame capabilities, shared memory, `mmap` — *frame capabilities landed 2026-08-22; `mmap` and multi-page regions have not* | Kernel work, and the continuation of "make the object model true". Prerequisite for real `fork`, shared buffers, and dynamic linking |
| 3 | **2.4** VFS and a mount table — *namespace landed 2026-08-22; the client migration has not* | Needs `libhorus`. Gives step 4 the `/dev` and `/proc` namespaces it wants |
| 4 | **2.3** Process and session model | Needs 1–3. This is what makes the shell a shell |

**Step 1 first, because the freestanding half of userspace has no shared runtime.** There are
two link paths. The newlib path is opt-in per binary and costs ~450 KiB statically (2.5). The
freestanding path — used by **every server**: `init`, `shell`, `fs_server`, `console_server` —
has nothing. So `umemset`/`umemcpy` are independently reimplemented four times
(`console_server.c`, `consoletest.c`, `fsclient.c`, `fs_server.c`), `println` twice with
different signatures (`fs_server.c`, `shell.c`), and `posix.c` carries a third private set.
Adding a server means re-deriving all of it, plus a bespoke Makefile stanza and a hand-written
`launch_*()` in `init.c`, because there is no template and no documented procedure. That tax is
paid again by 2.3, 2.4, 2.6 and 2.7 — so it is paid down first.

**This is a departure from the stance below, and deliberately so.** "Stop adding userspace
until the capability system means what the documentation says it means" was written when the
capability system did not. Steps 1 and 2 remain consistent with it: step 1 adds no authority
of any kind, and step 2 *is* capability work. Steps 3 and 4 are what that sentence warns
against, and they are sequenced last for exactly that reason — they begin once 2.1 has given
the object model real virtual-memory objects to name.


### 2.1 ◧ Virtual memory objects and shared memory — **[F-2.1]** — *frames landed 2026-08-22*

**Delivered: the frame object and the map path.** `KOBJ_FRAME` is retyped out of a
`CAP_UNTYPED` by the existing `SYS_RETYPE`, so a page of shared memory is paid for by untyped
authority somebody holds rather than conjured by a syscall — the continuation of 0.3 rather
than a parallel allocator. `SYS_MAP_FRAME(frame_slot, vaddr, rights)` and `SYS_UNMAP_FRAME`
map it into the caller's own address space, and `SYS_CAP_MINT` (syscall 4, in the dispatch
table since the beginning as an unnamed numeric entry and unreachable from ring 3 until now)
is how a holder narrows a copy before delegating it. Two mutually distrusting tasks share one
physical page at two virtual addresses, and the rights on the delegated copy bound what each
one's PTE may say. `SECURITY.md` **S26** and **S27**; witness `make smoke-frame`.

**What made this more than plumbing was the capability already called `CAP_FRAME`.** Every
task is born holding one in slot 3, `READ|WRITE|EXEC`, object `USER_AREA_BASE` — a decoy that
named a fixed window and authorised nothing, and the same capability that made **[C-1]**
reachable when the dispatch table gated IPC on slot 3. Giving `CAP_FRAME` a meaning put it
back in play: had `object` been a physical address, `SYS_MAP_FRAME(3, ...)` would have mapped
physical `0x400000` into ring 3 on the first boot, from a capability the kernel hands out
itself. So `object` is an **index** into a table the kernel populates, and the decoy is
refused by a bound rather than by an allowlist. `FRAME_INDEX_UNCHECKED=1` restores the address
form and the decoy maps on every boot, 3 in 3 — the arm is what makes that refusal a
measurement.

The rights arm is aimed at the `cap_lookup` floor rather than at the `have & want`
intersection, and that correction is worth recording: given the floor, the intersection is
arithmetically redundant at every reachable call, so the arm this section was first written
with **could not fail**. It would have shipped as a table row in `CLAUDE.md` claiming a
measurement nothing took.

**Still open, and what each needs:**

- `mmap` and multi-page regions. Today a capability names exactly one 4 KiB frame and the
  caller names the address. A region object wants a length, and a length wants a policy for
  partial failure part-way through a run.
- Copy-on-write over a shared frame. `cow_break_pte` already exists for anonymous pages; a
  frame is refcounted the same way, so this is mostly about what a COW break means for a
  capability two tasks hold.
- Reclaiming a frame's bytes. Bump allocation means a destroyed frame's page is not reusable
  until its untyped region is revoked and reset — see `docs/LIMITATIONS.md`. That is the
  deliberate seL4 trade, not an oversight, but the region reset it depends on is not written.
- `MAX_DYN_FRAMES` (256) bounds how many frames the kernel can NAME at once. The untyped
  region bounds how many an authority can create, and only the second is a security property,
  but the first is a ceiling a real workload will meet before the second.

### 2.2 ⬜ Time, timers, and a monotonic clock — **[F-2.6]**

`SYS_CLOCK_GETTIME`, per-task timers as notification sources, tickless operation.
Prerequisite for IPC timeouts, anything real-time, and sane userspace scheduling.

### 2.3 ⬜ Process and session model — **[F-2.4]**

Real `fork`/`exec` semantics, process groups, job control, and a `/proc`-equivalent served
over IPC. Needed before the shell can become a usable OS interface.

### 2.4 ◧ A VFS layer above `fs_server` — **[F-2.2]** — *namespace 2026-08-22, clients migrated 2026-08-23*

**Delivered: the mount table, the walker, and a second server.** `userspace/hvfs.c` is a
per-task mount table and **one** path walker, in `libhorus.a`; `userspace/dev_server.c` is a
second filesystem server speaking the existing `fs_proto`. `smoke-vfs` mounts `fs_server` at
`/` and `dev_server` at `/dev` and asserts which server each path reaches. `SECURITY.md` **S29**.

**The VFS is a library, not a server, and that is the security decision.** A VFS server would
have to hold a capability to every backing filesystem, making it the most privileged task in
ring 3 and a single point whose compromise is a compromise of every mount — the monolithic
trust this item exists to avoid. `dev_server` is the demonstration of the alternative: it holds
**one** capability, the listen end of its own endpoint. No object store, no boot modules, no
user database. A single server owning both `/` and `/dev` necessarily holds both sets.

**What the mount table does not do**, stated because a VFS that looked like it enforced a
boundary it does not is worse than one that never claimed to: the prefix is a **name**. A task
holding a server's capability reaches all of that server wherever it is mounted. Authority is
the capability; the prefix is how you spell it. See `docs/LIMITATIONS.md` §2.7.

**Still open, and what each needs:**

- ~~**The three clients still carry their own walkers.**~~ **Migrated 2026-08-23.** `posix.c`
  and `shell.c` call `hvfs_walk` / `hvfs_walk_parent`; `hvfs` has users in the ship build, and
  the shell, the libc and every coreutil resolve paths through one implementation.
  **`fsclient.c` was not one of the three, and this entry was wrong to say so**: it has no
  walker. It does flat single-name lookups in the root and a private `rpc()` built on
  `ipc_call_retry` with its own selftest markers — bounded retry semantics `hvfs_rpc`
  deliberately does not have. Migrating it would have removed the retry and the markers to
  satisfy a sentence in this file, so the sentence is corrected instead.
- ~~**`posix.c` needs a link-path decision first.**~~ **Taken 2026-08-23: `libhorus.a` is now
  linked into the newlib programs.** The feared collision does not arise — nothing in
  `libhorus.o` is named `memcpy`; the symbols are `umemcpy`, `umemset`, `ustrncpy`, `uslen`,
  `ustreq`, `kput*`, `spin_delay*`, `ipc_call_retry`, none of which collide with libc. It costs
  ~200 bytes per newlib binary. The alternative — private static copies inside `hvfs.o` — would
  have cost the *audited* helpers: `ustrncpy`'s termination is what
  `LIBHORUS_STRNCPY_UNTERMINATED` falsifies, and a private copy is outside that arm.
- **What the migration found.** `..` did not work below a mount root at all, in any client.
  `hvfs` resolved it by asking the server to look up a `..` **entry**, and `fs_server` creates
  none — `dir_add` links exactly the name `mkdir` was given — so that branch returned `NOENT`
  every time. It was dead from the day it landed in #195, and the only test touching `..` used
  the *pinned* case, which returns before the lookup. `..` now pops the walker's own descent
  stack: no round trip, and nothing a server asserts. Witnessed by `smoke-newlib`'s `.`/`..`
  checks against `smoke-newlib-dotdot-control`.
- **`init` cannot provision a mount yet.** It holds no `CAP_UNTYPED`, so it cannot retype an
  endpoint for a new server; the gate uses root-cnode endpoint capabilities instead. Giving the
  delegation root that authority is a real widening and belongs in its own commit.
- `dev_server` is gated behind `VFS_SELFTEST=1` rather than shipped: adding a server to every
  image changes the default system, which is a separate decision from proving the VFS works.
- Mount and unmount as syscalls, `/proc`, and namespace inheritance across `spawn` — the last
  is roadmap 2.3.

### 2.5 ◧ Dynamic linking and a shared libc — **[F-2.5]**

**The shared-runtime half landed 2026-08-21; dynamic linking has not.**

`libhorus` (`include/libhorus.h`, `userspace/libhorus.a`) is the shared runtime for the
**freestanding** link path — the one every server uses. It replaced 22 hand-copied definitions
across 7 files, and it carries `ipc_call_retry`, which makes the IPC retry contract (retry on
`ipc_transient()` only, and bound it) a library guarantee rather than something each program
re-derives from memory. `smoke-libhorus` is its gate; `LIBHORUS_RETRY_ANY=1` and
`LIBHORUS_STRNCPY_UNTERMINATED=1` are its control arms.

It is an archive rather than an object so a program that uses none of it pays nothing —
measured: `captest`'s `.text` is byte-identical to before libhorus existed.

**Still open:** the newlib half. Every newlib-linked binary statically links its own libc
(~450 KiB each; 11 in `/bin`). A shared-object loader with capability-mediated mapping cuts the
store requirement by an order of magnitude and makes a larger userspace practical — and it
needs 2.1's frame capabilities first, which is why it sits behind them in the Track 2 order.

### 2.6 ⬜ Network stack as a ring-3 server — **[F-2.3]**

A user-mode TCP/IP server holding `CAP_IO_DEVICE` for one NIC, with per-application socket
capabilities. A network-stack compromise is then contained to one address space with no
kernel authority — the highest-visibility demonstration of the architecture's value.

### 2.7 ⬜ Real device drivers as ring-3 servers

Following the `console_server` pattern: an AHCI/NVMe storage driver, a keyboard/mouse
server, and a framebuffer server. Each holds only the `CAP_IO_DEVICE` for its own hardware.

---

## Track 3 — Assurance and observability

### 3.1 ◧ Reproducible builds — `kernel.elf` yes, `boot.iso` no

`make reproducible-build` records one clean `SOURCE_DATE_EPOCH` build — `kernel.elf` **and**
`boot.iso`; the `reproducible` CI job runs it twice, requires the record to name both, and
diffs the `kernel.elf` hashes. Gated in CI.

`◧` rather than `✅` since 2026-08-19: **`boot.iso` is not byte-reproducible.** `grub-mkrescue`
stamps a wall-clock UUID into every image and embeds it in the EFI loaders it generates, so the
artifact a third party would actually obtain does not reproduce, while everything this project
authors inside it does. It went unnoticed because the recording step deleted the ISO, never
rebuilt it, and swallowed the error — see `docs/LIMITATIONS.md` §5.3a. Finishing this means
assembling the image with `xorriso` directly or deriving the UUID from `SOURCE_DATE_EPOCH`.

### 3.2 ✅ Measured boot and sealed volume key

TPM 2.0 PCR 8/9 measurement of kernel and modules; vdisk KEK sealed under `PolicyPCR`.
Adversarially tested: `smoke-tpm-tamper`, `smoke-tpm-seal`.

### 3.3 ✅ Boot-module integrity manifest

SHA-256 manifest embedded in the kernel image; unverified modules cannot be read, hence never
provisioned as executables. Adversarially tested: `smoke-modules-tamper`.

### 3.4 ✅ Kani proofs on capability revocation

Proves revocation hits exactly the target's derivation subtree.

### 3.5 ◧ Extend proofs to the full capability algebra — **[F-3.1]** — *lookup and grant proved, and gating, 2026-08-23*

**Delivered.** Seven new Kani harnesses over `rust_cap_lookup` and `rust_cap_grant_into`:
lookup succeeds **exactly when** the capability holds every requested right (an equivalence, so
a lookup that refused too much fails it too), never resolves an empty slot or an out-of-range
one; grant yields exactly `requested & source`, records the grantor as the grantee's parent
with a fresh derived serial, refuses an invalid source **without writing anything**, and is
bounded by the destination cspace. Each was falsified by mutating the property it claims.

**And they run now, which they did not.** The `kani` job is `workflow_dispatch`-only *and*
carries `continue-on-error: true` on both steps — so for as long as it has existed, none of
these proofs could have failed a build. `.github/kani-harnesses.yml` classifies every harness
as gating or excused-with-a-reason, `tools/check_kani_harnesses.py` refuses one in neither, and
the new required `kani-bounded` job runs the eleven that finish (**319 s**, measured) with no
`continue-on-error`. The four excused are the serial-keyed lineage pair and the two ELF
validators; a full `cargo kani` exceeded GitHub's 6-hour ceiling, which is why the answer is a
named subset rather than "run everything".

**Still open, and what each needs:**

- **Type confusion at lookup.** `rust_cap_lookup` does not check `typ`; the C `cap_lookup`
  does, against a caller-supplied expected type. Proving "lookup refuses a type-mismatched
  capability" means moving that test into the Rust side or modelling the C one — a change to
  the FFI contract, not a new harness, so it belongs in its own commit.
- **IPC authority implies a held endpoint capability naming that endpoint.** 0.1 landed, so
  this is now expressible; it needs a model of `ipc_ep_from_slot` on the Rust side.
- **The TLA+ specifications (`cap_algebra.tla`, `paging_isolation.tla`) are still only
  committed, not model-checked in CI.** TLC is a second toolchain (a JVM) on top of Kani's.

### 3.6 ◧ A debug/observability capability — **[F-3.2]** — *CAP_DEBUG and capview landed 2026-08-23*

**Delivered.** `CAP_DEBUG` (type 18, `CAPSLOT_DEBUG` 19) gates cross-task introspection and the
new `SYS_CAP_ENUMERATE`, which reports one cspace slot's type, rights, serial, badge and
generation. The shell's `capview` walks it and prints the graph. `SECURITY.md` **S32**.

**The ad-hoc root introspection was already gone** (finding I-1 replaced it with a capability
check). What this item actually found was subtler: `ps` required **`CAP_AUDIT`**, which also
rotates the audit chain's keys and reads the log. The gate was real — this is a *bundling*
mistake, not an ambient one, which is why two ambient-authority sweeps walked past it. The
shell now holds `CAP_DEBUG` and nothing more for that purpose, so the change **narrows** it.

`CAP_DEBUG` is minted READ-only at the root, and since rights only ever narrow, no delegate can
hold anything that writes. `SYS_CAP_ENUMERATE` deliberately does not report `object`: `serial`
and `badge` are the graph's nodes and edges, so derivation is fully visible without naming what
each capability points at.

**Found on the way, and now gated:** the cspace slot map is written down twice — `kernel.h` and
`syscall.h` — and nothing compared them. `CAPSLOT_DEBUG` was first added as 18, which
`CAPSLOT_UNTYPED` already was; the delegation then wrote a `CAP_DEBUG` into the slot init keeps
its `CAP_UNTYPED` in. `tools/check_capslots.py` refuses a duplicate number and a disagreement
between the two headers.

**Still open, and what each needs:**

- **A ring buffer of capability operations.** Mint/grant/revoke are audited (`audit_log`) but
  not queryable as a stream; this wants its own buffer and a readout gated on the same
  capability.
- **`capview` is a shell builtin, not a program.** Fine for now — it needs `CAP_DEBUG`, and the
  shell is what holds it — but a standalone `/bin/capview` would need init to delegate the
  capability to a spawned task, which is roadmap 2.3's inheritance question.
- **Task introspection still accepts `CAP_USER` and `CAP_AUDIT`** as well as `CAP_DEBUG`, for
  compatibility: `fs_server` holds `CAP_AUDIT` for the object store and the user-admin path
  holds `CAP_USER`. Narrowing `h_task_info` to `CAP_DEBUG` alone is a separate change with its
  own blast radius.

### 3.7 ⬜ Deterministic replay harness — **[F-3.3]**

Record syscall and IPC traces under QEMU and replay them, making SMP race reproduction
tractable and turning intermittent CI failures into artifacts.

### 3.8 ⬜ KASLR, CFI, and sanitizers — **[F-3.5]**

Kernel address-space randomisation, control-flow integrity on indirect calls in the C
kernel, and a sanitizer pass over the Rust core in CI.

### 3.9 ⬜ Virtualisation hooks (VT-x) — **[F-3.4]**

A `CAP_VCPU` object and an EPT-backed guest address space, so Horus can host a guest OS as a
ring-3 VMM holding only the capabilities for its guest's resources. The credible bridge from
research kernel to real workloads without compromising the model.

---

## Track 4 — Repository, governance, and SSDLC

Ordered as in the audit's §7.5.

### P0

- **4.1 ⬜ Require reviewer approval — [C-5].** `required_approving_review_count: 1`,
  `require_code_owner_review: true`, `dismiss_stale_reviews_on_push: true`,
  `require_last_push_approval: true`, `required_review_thread_resolution: true`.

  *This item previously also asked to "repair the stale `CODEOWNERS` paths (seven files listed
  do not exist; the files containing **[C-1]** are uncovered)". That was **already done** by
  4.7 on 2026-07-27 and this line had gone on asking for it since — the roadmap contradicting
  itself two tracks apart. Re-derived 2026-08-17: **0 of 57 patterns** name a path that does
  not exist, and both files carrying the **[C-1]** logic, `src/kernel/syscall_ipc.c` and
  `src/kernel/capability.c`, are covered.*

  **So the only thing left on [C-5] is a second person**, and no configuration change
  substitutes for one. Turning these settings on with a single maintainer either blocks every
  merge or is worked around with a bypass actor — which would undo 4.2's "no bypass actors" to
  buy an approval nobody independent gave. `SECURITY.md` scopes the claim to *"thoroughly
  automatically verified"* rather than *"independently reviewed"*; that is a mitigation and is
  labelled as one.
- **4.2 🚧 Gate the security tests — [C-6].** `strict_required_status_checks_policy` is now
  **true**, and `smoke-captest` — the witness for eight of `SECURITY.md`'s S-numbered
  properties, and the single most consequential omission — became a required check on
  2026-08-15, when the required set was 22 of 66 jobs and it was the only security gate among
  them. `smoke-wx` / `-wx-smp`, `smoke-cpu`, `smoke-modules-tamper`, `smoke-tpm*`,
  `smoke-flush`, `smoke-stackguard`, `smoke-heap64`, `smoke-irq-policy`, `smoke-percpu`,
  `smoke-resume-guard`, `smoke-newlib-tamper` and CodeQL are all promoted in the classification
  below, and **are gating** — the ruleset was synced to it on 2026-08-16 and again on
  2026-08-17.
  *Promoting jobs one at a time is not the fix.* The required list lives in the ruleset, which
  no commit touches, so every job added to `ci.yml` lands in the advisory set by default and
  nothing asks whether it should have — which is why the ratio drifted from 21-of-30 to
  21-of-64 without a decision ever being taken.

  **The mechanism was closed on 2026-08-16.** `.github/ci-gating.yml` is a checked-in decision
  record: every job in `ci.yml` and `codeql.yml` must be listed under `required:` or under
  `advisory:` with a written reason, and the `ci-gating` job fails the build when any job is in
  neither, in both, or names a job that no longer exists. No default — defaulting is the
  defect. It caught CodeQL unclassified on its first run, which is the same omission class the
  finding describes.

  The intended set is **92 required, 3 exempted** (92 jobs, 95 contexts — re-derive it with
  `tools/check_ci_gating.py`, never from this line) — `fuzz` (a 30-second time-boxed search is
  evidence of effort, not of absence), `kani` (manual-only, no conclusion to gate on),
  and `ruleset-audit` (schedule-only, so it never runs on a pull request).
  `smoke-fs-wal` was an exemption until **[I-11]** was fixed on 2026-08-16 and it was promoted
  back; `smoke-session-smp-soak` until **[G-8]** was closed on 2026-08-17 and it was promoted
  with it; `smoke-kstack-park` until **[G-9]** closed on 2026-08-21, promoted in #190 the day
  after. **All three that remain are properties of the test itself, and no exemption now stands
  for an open defect.** (Two earlier revisions of this paragraph got this wrong in opposite
  directions: one claimed no exemption stood for an open defect while listing
  `smoke-kstack-park` in the same sentence, and its replacement kept listing that gate as a
  fourth exemption for eleven days after #190 promoted it, beside a count that said three. A
  count and a list that disagree are two claims, and `doc-claims` can only check the one that is
  a number.) The count rose to 71 and
  then 72 on 2026-08-17 with `smoke-exec-reenter` and `smoke-cr3-reclaim`, the gates for
  [G-9]'s exec component and [G-10]'s page-table use-after-free, each with a control arm. The
  promotions are
  backed by measurement: across 18 CI runs sampled on 2026-08-16, 64 of 66 jobs had zero
  failures in 1152 job-executions. `smoke-fs-wal` is *demoted* — a flaky required check trains
  the maintainer to re-run red, and its durability claim is now carried by the deterministic
  `smoke-fs-wal-flush` / `smoke-fs-wal-order`.

  **Synced 2026-08-16**, 22 required contexts toward 67, strict policy true, no bypass actors.
  The first attempt was run from a feature branch and so required three contexts `main` could
  not produce — the `ci-gating` job and the two [I-10] gates — which blocks every PR on a check
  that never reports. `tools/prune_unsatisfiable_checks.py` dropped them (67 → 64) and encodes
  the rule: **never require a context the base branch cannot produce.** Promotion lags the job
  landing by one merge; re-run `--sync-ruleset` after each such PR.

  **What kept 4.2 open was verification, not promotion**, and the mechanism for it landed on
  2026-08-17. Reading a ruleset needs the `Administration` permission, which is not among the
  scopes the workflow `GITHUB_TOKEN` can be granted at all, so the `ci-gating` job proves the
  classification is complete but not that the ruleset matches it — the two could diverge via
  the GitHub UI with nothing in CI noticing. `.github/workflows/ruleset-audit.yml` now runs
  `--check-ruleset` daily, authenticating as a **GitHub App scoped to this repository with
  Administration: read and nothing else**, so the token is minted per run, expires in an hour,
  and cannot modify what it inspects. The trade is stated in that file's header: a credential
  that can read repository administration now lives in Actions secrets, in order to detect
  drift that requires administration access to cause.

  **The App went live on 2026-08-19.** The scheduled run at 07:56Z read the ruleset and
  reported `live ruleset 19007209 : 73 required contexts, matches`; the run 24 hours earlier had
  failed at the secret-presence step with `RULESET_AUDIT_APP_ID` missing, and the workflow has
  not changed since it merged. It failed loudly rather than skipping for every day it was
  unconfigured — an audit that skips when unconfigured is a check that cannot fail, which is the
  defect class this repository has already been bitten by twice — and that is why the day it
  started working is visible at all.

  **4.2 stays 🚧 for the other reason: syncing is still manual.** `--sync-ruleset` writes the
  ruleset and needs an admin token, so a PR adding a gating job leaves the ruleset one context
  behind until someone runs it afterwards. The audit now makes that lag visible the next
  morning rather than indefinitely, which is a different thing from removing it. **Marking this
  ✅ while promotion is still a human step would be the [G-2] mistake** — a document asserting a
  property that nothing yet enforces.

  Until then, `python3 tools/check_ci_gating.py --check-ruleset` is the check, and it has to be
  run deliberately. Read the count from the API, never from this paragraph.
- **4.3 ⬜ Hard-fail `gitleaks` and `cargo-audit`** (keep Semgrep/Trivy advisory until their
  false-positive rate on a freestanding kernel is characterised).

### P1

- **4.4 ⬜ Build provenance and signed artifacts — [I-9].**
  `actions/attest-build-provenance` (SLSA v1) plus cosign signatures on `kernel.elf` and
  `boot.iso`.
- **4.5 ⬜ Tagged releases** carrying artifacts, SBOM, provenance, and the expected
  PCR[8]/PCR[9] values, so a relying party can pre-compute the measured-boot quote.
- **4.6 ⬜ Move `horus.py` under `tools/` — [M-2].** Minor; the index is otherwise clean.
- **4.7 ✅ Governance files — [M-3].** *Landed 2026-07-27.* PR template moved to
  `.github/pull_request_template.md` (it was in `docs/`, where GitHub never looked for it,
  so no contributor had ever seen it); `.github/ISSUE_TEMPLATE/` added with security-report
  and bug-report forms; `CODE_OF_CONDUCT.md` added; `.github/CODEOWNERS` corrected — it
  listed seven files that do not exist and omitted the files containing the IPC
  authorisation logic (**[I-8]**).

### P2

- **4.8 ⬜ Enable secret-scanning non-provider patterns and validity checks — [M-4].**
- **4.9 ⬜ `.mailmap`** consolidating the five author identities — [M-9].
- **4.10 ⬜ Pin vendored `newlib`** by upstream URL and SHA-256 in a `THIRD_PARTY.md`, or
  fetch it at build time with verification instead of committing `.deb`s.
- **4.11 ⬜ `verify-release.sh`** a third party can run: rebuild from a tag, diff against the
  published artifact, check the signature, recompute the PCRs.
- **4.12 ⬜ A security-invariant registry — [F-4.1].** A machine-readable `invariants.yaml`
  naming each claimed property, the code enforcing it, and the test or proof witnessing it;
  CI fails if an invariant has no witness. This directly attacks the failure mode that
  produced **[C-1]**: a documented property with no test binding it to the code.
- **4.13 ⬜ Publish the threat model — [F-4.3]** as a versioned first-class document.
- **4.14 ⬜ Nightly long-running fuzz and Kani** in a scheduled workflow, filing findings as
  issues automatically.

---

## Completed milestones

| | Milestone |
|---|---|
| ✅ | 64-bit long mode, higher-half kernel, Multiboot2 |
| ✅ | Per-task 4-level page tables, demand paging, COW, NX stacks, kernel W^X |
| ✅ | Capability system with rights masking and system-wide subtree revocation |
| ✅ | Serial-keyed lineage generations (use-after-revoke backstop) |
| ✅ | Preemptive scheduling on a unified trap-frame switch path |
| ✅ | SMP by default: MADT enumeration, AP bringup, TLB shootdown, SMT parking |
| ✅ | Flush-on-switch microarchitectural barriers |
| ✅ | Ring-3 `fs_server` over an encrypted object store, with journal and fsck |
| ✅ | Ring-3 `console_server` owning UART and framebuffer; raw terminal mode |
| ✅ | ELF loader (header, phdrs, i386 and x86-64 relocations) in safe Rust |
| ✅ | ChaCha20 CSPRNG replacing an LCG-plus-TSC construction |
| ✅ | newlib libc, shell with pipelines, GNU coreutils, TCC |
| ✅ | Boot-module SHA-256 manifest; TPM measured boot; PCR-sealed volume KEK |
| ◧ | Reproducible builds (`kernel.elf`; the ISO carries a wall-clock UUID from `grub-mkrescue` — §5.3a), SBOM, CodeQL, Dependabot, signed commits, protected `main` |
| ✅ | 118 `smoke-*` targets (`grep -c '^smoke-[a-z0-9-]*:' Makefile`), nearly all QEMU integration self-tests, several adversarial, and 32 of them control arms that must reproduce a defect |
| ✅ | Kani proofs on revocation; cargo-fuzz on the FFI boundary |

---

## The shape of the next year

If one sentence had to describe the plan: **stop adding userspace until the capability
system means what the documentation says it means, then build the OS on a foundation that
holds.**

That sentence still governs, and Track 2's ordering above is how it is honoured rather than
abandoned: the two steps taken first are the one that adds no authority and the one that
extends the object model. The process and session model — the item most likely to accrete
ambient authority if rushed — is sequenced last, behind the frame capabilities it should be
built on.

Concretely — **Track 0 and Track 1 are done**, bar the named remainders. What is left is
Track 2 in order, with Track 3 and 4 items landing alongside. The single highest-leverage
non-technical change remains finding a second reviewer for the capability paths; automated
verification has been pushed about as far as it goes without one, and 4.1 now says so without
also asking for a `CODEOWNERS` repair that landed a month ago.

**Track 0 is complete** (0.1, 0.2, 0.3 all landed 2026-07-27), with 0.3 marked `◧` for the
`tasks[]` remainder that keeps **[I-7]** open. The object model is true: IPC is
capability-addressed, ambient root authority is retired, and creating a kernel object is an
exercise of authority the capability graph describes.

**Track 1 is complete** except 1.2 and 1.7, both `◧`: 1.1 landed 2026-08-11, then 1.3, 1.4,
1.5, 1.55 and 1.6 followed. 1.2's performance goal was met by other means and its remaining
reason to exist is a per-CPU *block*, not a per-CPU register base. 1.7 met its own goal on
2026-08-18 — **[G-10]** closed, and **[G-11]** found and closed with it — and stays `◧` only
because the rest of **[G-9]** does.

**The debt from 1.1 was collected on 2026-08-18, seven days late.** This section promised it
would be, and then did not: *"That is a workaround, and it is the third subsystem to route
around C-3.1 rather than fix it. Each one is another place that has to be revisited when 1.1
lands."* 1.1 landed on 2026-08-11, and as of 2026-08-17 both route-arounds in `untyped.c` were
still in place, with a comment still calling C-3.1 *"the defect roadmap 1.1 has to fix"* — wrong
for six days, which is how [G-2] survived nineteen.

Both are re-derived and gone:

- the **IF-transparent pushfq/popfq bracket** around each critical section is a no-op by
  construction now: `pushfq` → `spin_lock`'s `cli` and saved IF → `spin_unlock`'s restore →
  `popfq` puts back exactly what was captured. Removing it changes no `IRQ_POLICY_AUDIT` count
  either, because those counters increment inside `spin_unlock`, whose call sites are unchanged,
  so the legacy-vs-per-CPU comparison in `TESTS.md` stands as measured;
- the **deferral of locking past boot** (`untyped_arm_locking`) existed only because that
  unconditional `sti` would have enabled interrupts in the boot window. The one early-boot
  requirement `spin_lock` has is a valid `this_cpu()`, and `setup_tss64` (`src/boot/multiboot.S`)
  does `ltr $0x38` immediately before calling `kernel_main`, so the STR fast path returns 0 from
  the first C statement without touching the LAPIC. The tables are locked unconditionally.

Verified in both arms rather than argued: **3 boots in 3** to the ring-3 login prompt under the
default build *and* under `IRQ_LEGACY_GLOBAL_LOCK=1`. That second arm is the one this could
plausibly have broken — with the deferral gone it takes a lock in the boot window whose release,
in that build, still fires an unconditional `sti` — and a control arm that no longer boots is a
control arm that no longer measures anything.

**1.1's own prerequisite was met a fortnight before it landed — and it was not a flaky
test.** `smoke-console-smp` had been
failing about a third of the time and was treated as noise. It was correctly reporting an
intermittent **SMP scheduling deadlock**: `preempt_on_tick` claimed an incoming task
unconditionally but released the outgoing one only on a ring-3 tick, so a ring-0 tick leaked a
claim in `task_running_cpu[]` and left the victim `RUNNABLE`, resumable, and unschedulable by
every CPU — including the one holding the claim. Landed 2026-07-28 (PRs #112–#115):

| Build | Runs | Failures |
|---|---|---|
| before | 12 | **6** |
| after | 24 + 24 + 30 | **0** |

Three things from that episode bear directly on how 1.1 should be run:

1. **The startup-handshake measurement is now trustworthy**, which it was not before. `make
   smoke-console-smp-stress` reports a rate over N pinned boots, and 1.1 should quote one.
2. **Pin the CPUs when measuring.** On an idle workstation each guest vCPU gets a host core,
   the window never opens, and the *broken* kernel scored 10/10 green. The bug only appears
   where vCPUs outnumber cores — i.e. on CI runners. A green local run is not evidence.
3. **Do not "repair" a stale claim.** Two defensive repairs were written and measured: they
   took the harness from 24/24 to 13/20, because a claim is stale precisely when its task was
   abandoned mid-kernel, so freeing it resumes that task from a stale trap frame. Fix
   abandonment, never the bookkeeping. This is the same trap 1.1 will walk past.

**The last open item on this path is now closed** (2026-08-09), and its resolution is a fourth
lesson. The `SCHED_INVARIANTS=1` checker had been reporting, in ~1 boot in 5 (10 in 20 once
pinned), that `init` was left claimed by a CPU that had moved on — read at the time as `init`
stranded in `sys_wait()`, and made a blocker for 1.1 on that basis.

**It was not a scheduler defect. The checker's model was incomplete.** Task 1 is `init` and
task 4 is the shell it is in the middle of *spawning*: `do_spawn` → `load_staged_image_into`
makes the child the CPU's current task for the whole ELF load so the loader's `copy_to_user`
resolves through the child's address space, while `init` stays correctly claimed by that CPU.
The two IPC sites that pull the same trick had been declared to the checker; the spawn window
— by far the longest, hundreds of KiB of copying under TCG — had not.

`sched_impersonate_enter/exit` now record the task a CPU is *really* running, and the audit is
stated over that rather than skipping the CPU, so coverage stays continuous across a spawn
instead of going blind exactly where a real leak would be easiest to hide. The bracket is
balance-checked (a CPU reaching ring 3 mid-window panics). **10 failures in 20 → 0 in 30**,
pinned, and falsified in both directions: re-introducing a genuine claim leak still panics
3 boots in 3, and removing the bracket's `exit()` fails 3 in 3. `make
smoke-sched-invariants-stress` is now **a gating CI check** — 30 pinned boots reported as a
rate, since one green boot is not evidence about a scheduling change.

4. **A checker that reports a violation is asserting something about the code, and it can be
   the one that is wrong.** Falsify the checker against the code *and* the code against the
   checker. This one blocked 1.1 for a fortnight over an invariant that was never violated.

**1.1 is done** (2026-08-11). See §1.1 for the measurement and for why the July attempt failed
where this one did not: the accidental `sti` stopped being load-bearing when
`preempt_on_tick`'s ring-0 guard was widened to every CPU, which was itself a workaround for
the defect now fixed.
