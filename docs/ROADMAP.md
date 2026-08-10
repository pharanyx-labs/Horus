# Horus Roadmap

**Objective: a complete operating system built from the ground up, on a kernel small enough
to be verified and a capability model strong enough to be relied on.**

The roadmap is ordered by *assurance value*, not by demo value. A feature that runs on an
unenforced foundation adds surface without adding capability, and increases the cost of
fixing the foundation later. So the sequence is: **make the object model true, make kernel
objects allocatable, then grow the OS on top.**

Findings referenced as **[C-n]** / **[I-n]** / **[F-n]** are from
[`AUDIT-2026-07-27.md`](AUDIT-2026-07-27.md).

---

## Status legend

| | |
|---|---|
| ✅ | Done and tested in CI |
| 🚧 | In progress |
| ⬜ | Not started |
| 🔒 | Blocked on an earlier item |

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

### 0.3 ✅ Kernel objects from untyped memory (`CAP_UNTYPED`) — **[I-7]** — *landed 2026-07-27*

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

### 1.1 ⬜ Make boot-time interrupt enablement explicit, *then* fix the spinlock — **[C-3]**, **[C-3.1]**

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

Required order:

1. Make boot-time interrupt enablement explicit — find every window relying on the accidental
   `sti`, issue or defer `sti` deliberately, and write the policy down.
2. Add a self-test asserting `IF` state at the boot milestones so the dependency cannot
   silently return.
3. Then land the per-CPU, IF-preserving lock.

Own PR, with the startup handshake instrumented. Do not attempt step 3 alone.

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

### 1.3 ◧ Multi-slot endpoint queues and a reply-capability primitive — **[I-5]**

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

**Remaining:** a blocking receive. An empty queue still returns `-2` and the server polls, so a
server with no work spins instead of sleeping and priority inheritance is still inexpressible.
That is the last piece of this item.

A bounded FIFO per endpoint, plus a **one-shot reply capability** minted at call time and
consumed on reply (seL4's reply object). This makes reply forgery *structurally* impossible
rather than merely gated, removes the poll-on-contention busy-wait, and is the precondition
for priority inheritance.

### 1.4 ⬜ Fail-closed user copies — **[C-4]**

`copy_from_user`/`copy_to_user` currently clamp to `USER_MEM_MAX_COPY` and return success.
Refuse instead; add an explicit partial-copy API if a caller genuinely needs one.

### 1.5 ⬜ 64-bit-clean heap arithmetic — **[I-2]**

`SYS_SBRK`/`SYS_BRK` must be `uint64_t` end-to-end with an explicit overflow check before the
range test. Latent today; sharp the moment the user address space widens past 4 GiB.

### 1.55 ⬜ Make the write-ahead journal actually durable — **[I-10]**, **[I-11]**

The kernel issues no ATA `FLUSH CACHE` (0xE7) — the driver's entire command set is
`READ(0x20)`, `WRITE(0x30)`, `IDENTIFY(0xEC)`. On real hardware the journal's commit record
can sit in the drive's volatile write cache and be lost to a power failure, so the
crash-atomicity guarantee does not hold outside emulation.

It has gone unnoticed because `smoke-fs-wal` runs QEMU with `cache=writethrough`, where the
emulator provides the durability the kernel omits — the test verifies the property in the one
configuration where the code under test cannot fail it.

Two halves, both needed:

1. Issue `FLUSH CACHE` after the commit record and after the checkpoint that retires it,
   polling BSY (a real drive can take seconds).
2. Add a `cache=writeback` variant of the test, so the guarantee is exercised where the
   emulator is not silently supplying it. Fix the harness race at the same time (**[I-11]**):
   have boot 1 halt itself via `isa-debug-exit` once the write is genuinely durable, and have
   the harness wait for QEMU to *exit* rather than killing it on a serial string — currently
   a genuine WAL regression and a harness race produce identical output.

### 1.6 ⬜ Unbounded revocation closure — **[I-3]**

Replace the fixed 256-entry worklist with an iterate-to-fixpoint or mark-and-sweep closure,
removing the object-wide overflow fallback and with it the denial-of-service on a peer's
independent capability.

---

## Track 2 — Toward a complete OS *(Track 0 complete)*

### 2.1 ⬜ Virtual memory objects and shared memory — **[F-2.1]**

Frame capabilities backed by real pool frames; `SYS_MAP_FRAME(frame_cap, vaddr, rights)` and
unmapping. Gives genuine shared memory between mutually distrusting tasks, with rights that
narrow on delegation. Prerequisite for `mmap`, a windowing system, zero-copy network buffers,
and real `fork`.

### 2.2 ⬜ Time, timers, and a monotonic clock — **[F-2.6]**

`SYS_CLOCK_GETTIME`, per-task timers as notification sources, tickless operation.
Prerequisite for IPC timeouts, anything real-time, and sane userspace scheduling.

### 2.3 ⬜ Process and session model — **[F-2.4]**

Real `fork`/`exec` semantics, process groups, job control, and a `/proc`-equivalent served
over IPC. Needed before the shell can become a usable OS interface.

### 2.4 ⬜ A VFS layer above `fs_server` — **[F-2.2]**

Mount points, multiple filesystem servers, and a device-file namespace. Each server holds
only the object-store capabilities for its own subtree — per-mount isolation that a
monolithic VFS structurally cannot provide.

### 2.5 ⬜ Dynamic linking and a shared libc — **[F-2.5]**

Every binary currently statically links newlib (~450 KiB each; 11 in `/bin`). A shared-object
loader with capability-mediated mapping cuts the store requirement by an order of magnitude
and makes a larger userspace practical.

### 2.6 ⬜ Network stack as a ring-3 server — **[F-2.3]**

A user-mode TCP/IP server holding `CAP_IO_DEVICE` for one NIC, with per-application socket
capabilities. A network-stack compromise is then contained to one address space with no
kernel authority — the highest-visibility demonstration of the architecture's value.

### 2.7 ⬜ Real device drivers as ring-3 servers

Following the `console_server` pattern: an AHCI/NVMe storage driver, a keyboard/mouse
server, and a framebuffer server. Each holds only the `CAP_IO_DEVICE` for its own hardware.

---

## Track 3 — Assurance and observability

### 3.1 ✅ Reproducible builds

`make reproducible-build` builds twice and diffs `kernel.elf`; gated in CI.

### 3.2 ✅ Measured boot and sealed volume key

TPM 2.0 PCR 8/9 measurement of kernel and modules; vdisk KEK sealed under `PolicyPCR`.
Adversarially tested: `smoke-tpm-tamper`, `smoke-tpm-seal`.

### 3.3 ✅ Boot-module integrity manifest

SHA-256 manifest embedded in the kernel image; unverified modules cannot be read, hence never
provisioned as executables. Adversarially tested: `smoke-modules-tamper`.

### 3.4 ✅ Kani proofs on capability revocation

Proves revocation hits exactly the target's derivation subtree.

### 3.5 ⬜ Extend proofs to the full capability algebra — **[F-3.1]**

Prove: mint never widens rights; grant preserves the derivation tree; lookup refuses
type-mismatched capabilities; and — once 0.1 lands — that IPC authority implies a held
endpoint capability naming that endpoint. Model-check the existing TLA+ specifications
(`cap_algebra.tla`, `paging_isolation.tla`) **in CI** rather than merely committing them.

### 3.6 ⬜ A debug/observability capability — **[F-3.2]**

`CAP_DEBUG` gating task introspection, a ring buffer of capability operations, and
`SYS_CAP_ENUMERATE` backing a userspace `capview` tool. Replaces the ad-hoc root
introspection in `SYS_GET_TASK_INFO` with an explicit, revocable authority — and makes the
capability graph *visible*, which is essential for auditing a system whose security argument
rests on that graph.

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
  `require_last_push_approval: true`, `required_review_thread_resolution: true`. Repair the
  stale `CODEOWNERS` paths (seven files listed do not exist; the files containing **[C-1]**
  are uncovered).
  *If a second reviewer is genuinely unavailable, say so in `SECURITY.md` and scope the
  assurance claim accordingly — that is already done, and it is a mitigation, not a fix.*
- **4.2 ⬜ Gate the security tests — [C-6].** Promote every `smoke-*` security self-test and
  CodeQL to required status checks; set `strict_required_status_checks_policy: true`.
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
| ✅ | Reproducible builds, SBOM, CodeQL, Dependabot, signed commits, protected `main` |
| ✅ | 30+ QEMU integration self-tests, several adversarial |
| ✅ | Kani proofs on revocation; cargo-fuzz on the FFI boundary |

---

## The shape of the next year

If one sentence had to describe the plan: **stop adding userspace until the capability
system means what the documentation says it means, then build the OS on a foundation that
holds.**

Concretely — Track 0 in full, then Track 1.2–1.4, then Track 2 in order, with Track 3 and 4
items landing alongside. The single highest-leverage non-technical change remains finding a
second reviewer for the capability paths; automated verification has already been pushed
about as far as it goes without one.

**Track 0 is now complete** (0.1, 0.2, 0.3 all landed 2026-07-27). The object model is true:
IPC is capability-addressed, ambient root authority is retired, and creating a kernel object
is an exercise of authority the capability graph describes.

Track 1.1 is the next blocking item, and 0.3 raised its priority with evidence rather than
argument. Moving cspaces onto untyped memory made `create_task` take a spinlock for the first
time, and `task_teardown` likewise — both on paths that keep interrupts masked deliberately.
`spin_unlock`'s unconditional `sti` (**[C-3.1]**) turned that into `smoke-console-smp`
failures with the same signature as the reverted per-CPU-lock attempt, from the same cause:
2 failures in 3 runs, against 2 in 6 on `main`. An IF-transparent critical section in
`untyped.c`, plus deferring the lock's arming past boot, restored parity (1 failure in 6).

That is a workaround, and it is the third subsystem to route around C-3.1 rather than fix it.
Each one is another place that has to be revisited when 1.1 lands. The episode also says
something about cost: a change that touches task creation now has to reason about interrupt
policy that is nowhere written down, and the only way to tell a real regression from noise was
eighteen QEMU boots.

**That prerequisite is now met — and it was not a flaky test.** `smoke-console-smp` had been
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

**1.1 is unblocked.**
