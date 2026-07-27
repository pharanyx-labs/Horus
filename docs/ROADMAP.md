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

### 0.1 ⬜ Capability-addressed IPC — **[C-1]**, **[C-2]** — *Critical*

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

**Do not bundle this with feature work.** It is a focused, breaking, reviewable change.

### 0.2 ⬜ Retire ambient `uid == 0` authority — **[I-1]**

Replace each `tasks[cur].uid != 0` gate with a distinct capability type — `CAP_KERNEL_LOG`
(dmesg), `CAP_BOOT_MODULE` (module read surface), `CAP_OBJECT_STORE` (the encrypted store
API) — minted by `init` and delegated to exactly the server that needs it. Remove the root
promotion in `SYS_GET_TASK_INFO` and zero `info.eip` for other tasks (**[I-4]**).

**Security impact.** Makes the capability graph a *complete* description of authority, which
is the precondition for any confinement, sandboxing, or MAC story.

### 0.3 ⬜ Kernel objects from untyped memory (`CAP_UNTYPED`) — **[I-7]**

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

### 1.2 ⬜ `%gs`-based per-CPU data — **[I-6]**

`swapgs` at every ring transition; `%gs:0` holds CPU id, the current TCB pointer, and the
per-CPU IRQ-nesting state. Removes an uncached LAPIC MMIO read from the hottest kernel path
(currently several per syscall). Initialise `IA32_KERNEL_GS_BASE` per CPU at AP bringup.

### 1.3 ⬜ Multi-slot endpoint queues and a reply-capability primitive — **[I-5]**

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

### 1.6 ⬜ Unbounded revocation closure — **[I-3]**

Replace the fixed 256-entry worklist with an iterate-to-fixpoint or mark-and-sweep closure,
removing the object-wide overflow fallback and with it the denial-of-service on a peer's
independent capability.

---

## Track 2 — Toward a complete OS 🔒 *(gated on Track 0)*

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
