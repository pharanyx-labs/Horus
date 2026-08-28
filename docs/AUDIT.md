# Horus — High-Assurance Security & Engineering Audit (2026-07-27)

**Scope.** Full kernel source (C / Rust `no_std` security core / x86-64 assembly), build
system, userspace, tests, formal artifacts, documentation, repository metadata, branch
protection, CI/CD, and SSDLC posture.
**Method.** Whole-tree read against the local checkout as source of truth, cross-referenced
with the GitHub repository API (rulesets, protection, scanning, PR history). Empirical
verification by building and booting the kernel under QEMU and running the gated
self-tests.
**Baseline.** Commit `a4c7b1a`, branch `feat/nano-curses`, 337 commits, ~34.6 kLOC of
kernel/userspace source.
**Predecessor.** The July 2026 audit (findings A1–A4, P1–P5). This audit supersedes it and
re-verifies its remediations; it is reproduced as [Appendix A](#appendix-a--the-predecessor-audit-2026-07)
below, having been a separate file until 2026-08-21.

---

## 1. Executive Summary

### 1.1 Overall rating

> **Remediation status (updated 2026-07-27).** The critical finding **[C-1]** and its
> companion **[C-2]** are **fixed** — IPC is now capability-addressed. The ratings below are
> shown as-audited, then as-remediated, so the original assessment stays legible. The
> findings themselves are preserved verbatim as the record of what was found; each carries a
> resolution note. **[C-3]** was attempted, reverted, and reclassified — see **[C-3.1]**,
> which is the more serious finding of the two.

| Dimension | Rating (as audited) | Now | Direction |
|---|---|---|---|
| Kernel implementation security | **Moderate–High risk** | Moderate | Improving fast |
| Capability model *as implemented* | **High risk** (one systemic bypass) | **Low** | **Bypass closed; root no longer ambient** |
| Memory-safety posture | **Low risk** | Low | Strong |
| Boot / supply-chain integrity | **Low risk** | Low | Strong |
| Repository & CI/CD security | **Low risk** | Low | Strong |
| Governance / review process | **High risk** | **High risk** | Static |
| **Combined posture** | **Moderate–High risk** | **Moderate** | — |

Governance is unchanged and is now the dominant residual risk: no security-critical change
in this project has ever been reviewed by a second person (**[C-5]**), and the
security-specific CI jobs still do not gate merges (**[C-6]**).

Horus is a genuinely serious piece of engineering and one of the better-instrumented
hobby-to-research microkernels I have reviewed. It boots to a ring-3 shell on real
x86-64 with per-task page tables, a ring-3 filesystem server over an AEAD-encrypted
object store, a ring-3 console driver, TPM-backed measured boot with a PCR-sealed volume
key, SMP with software-parked SMT siblings, flush-on-switch side-channel hygiene,
byte-for-byte reproducible builds, and 30+ QEMU-driven integration self-tests wired into
CI. The Rust `no_std` security core takes the genuinely hard parsing and validation
surfaces — ELF loading, capability algebra, crypto — out of C. That is the right
architecture, and it is executed with unusual discipline.

### 1.2 The systemic risk — *resolved 2026-07-27*

> **Resolved.** IPC is now capability-addressed: every IPC syscall takes a cspace slot and the
> kernel derives the object from the capability there, checking type, right, and lineage.
> Clients hold send-only capabilities and every task has a private reply endpoint. The
> analysis below is retained as the record of what was found and why it mattered.

**The capability system does not mediate the IPC namespace.** Endpoints and notifications
are a flat global array addressed by an integer taken directly from a userspace register.
The `object` field of `CAP_ENDPOINT` — which the code plumbs, comments, and delegates
exactly as a capability-addressed design would — is *never consulted* by any IPC syscall.
The dispatch table gates IPC on "hold *something* in slot 3", and `create_task` places a
`CAP_FRAME` in slot 3 of every task. The result is that any ring-3 task can send to,
receive from, and forge replies on **any** endpoint in the system, including the
filesystem server's well-known request endpoint. This collapses the confidentiality and
integrity of the ring-3 server architecture that the rest of the design is built on.
See **[C-1]**.

This is not a coding slip in one function; it is a missing enforcement layer. Everything
above it — `fs_server` as reference monitor, `SYS_IPC_SENDER` as a zero-trust identity
anchor, per-file POSIX permissions against a kernel-attested uid — is sound in design and
correctly implemented, and all of it is bypassable from any unprivileged program because
the transport underneath is ambient. The documentation's claim that IPC is
"capability-gated" (`docs/LIMITATIONS.md`) is, as implemented, materially overstated.

### 1.3 The systemic process risk

The engineering environment is, with one exception, *ahead* of the kernel: SHA-pinned
actions, least-privilege `GITHUB_TOKEN`, enforced commit signing, enforced linear history,
no bypass actors, 21 required status checks, reproducible-build verification, SBOM,
CodeQL, Semgrep/Trivy/gitleaks, cargo-fuzz, and Kani proofs. The exception is decisive:

**`required_approving_review_count: 0`.** Every one of the last 25 merged pull requests
carries `NO_REVIEW`. The rule requires a PR but requires nobody to read it. For a project
whose entire value proposition is "high assurance", the single control that would catch a
class of defect no automated gate can catch — a human adversarially reading a capability
check — is configured off. **[C-5]**

Compounding it: the *security-specific* CI jobs (capability conformance, kernel W^X,
measured boot, boot-module tamper rejection, SMEP/SMAP, stack-guard reseed) are **not**
in the required-checks set, while ordinary functional tests are. A change that breaks the
capability refusal suite or the measured-boot gate can merge green. **[C-6]**

### 1.4 Assurance impact on the path to a full OS

The current trajectory adds *features* (TCC port, curses/nano, coreutils) on top of a
capability layer that does not yet enforce its own central abstraction. Every userspace
service added before **[C-1]** is fixed inherits an unauthenticated transport, and each one
increases the migration cost of fixing it later. The ordering that serves the long-term
goal is: **fix the object model, then grow the OS on top of it.** A complete OS built on
an ambient IPC namespace is a monolithic kernel with extra context switches.

*Update: this ordering was taken. **[C-1]**/**[C-2]** landed before further userspace work,
so no additional service was built on the unauthenticated transport. The remaining Track 0
item is retiring ambient `uid == 0` authority (**[I-1]**), after which the capability graph
is a complete description of authority.*

### 1.5 Key strengths

- Memory-safe Rust owns the highest-risk parsers (ELF header/phdr/relocations, capability
  algebra) — and doing so found two real OOB bugs, per project history.
- Boot integrity is end-to-end and *tested adversarially*: SHA-256 module manifest embedded
  in the kernel, TPM PCR 8/9 measurement, KEK sealed under `PolicyPCR`, plus CI jobs that
  **tamper** with a module and assert both rejection and PCR divergence.
- Reproducible builds are verified in CI by building twice and diffing, not merely claimed.
- `user_copy` does a software page-table walk enforcing `PAGE_USER`, which is stronger than
  relying on SMAP alone.
- The self-test corpus is exceptional: W^X sweeps, address-space reclaim, COW correctness,
  TLB shootdown, preemption, signals, TSD, E820, SMT parking.

---

## 2. Architecture Strengths and Weaknesses

### 2.1 Strengths

**Privilege separation is real, not aspirational.** The console driver and the filesystem
run in ring 3 (`userspace/console_server.c`, `userspace/fs_server.c`). Device authority is
delegated by an explicit `CAP_IO_DEVICE` capability that only `init` holds and only grants
to the console server, gating `SYS_MAP_PHYS`, `SYS_IOPORT_GRANT`, and `SYS_IRQ_REGISTER`.
The kernel never holds the volume key's plaintext outside itself, and the FS server
addresses storage as `(inode, logical block)` without ever seeing key material. This is a
correct microkernel factoring.

**The C/Rust FFI boundary is pinned by construction.** Layout drift between `capability_t`
and `Capability` is a compile error on *both* sides:

```c
/* src/kernel/capability.c:10 */
_Static_assert(__builtin_offsetof(capability_t, type)   == 0,  "cap.type offset");
_Static_assert(__builtin_offsetof(capability_t, object) == 8,  "cap.object offset");
```
```rust
// rust/src/capability.rs:29
const _: () = {
    assert!(core::mem::offset_of!(Capability, typ) == 0);
    assert!(core::mem::offset_of!(Capability, object) == 8);
};
```

This is the correct way to make an FFI boundary auditable, and it is rare to see it done
in both directions.

**Revocation semantics are principled.** `revoke_subtree` (`rust/src/capability.rs:427`)
computes the transitive derivation closure via `badge → parent serial` links, nulls exactly
that subtree, and — critically — over-approximates *safely* on worklist overflow by falling
back to an object-wide sweep, so a descendant can never survive its ancestor. Two
independent mechanisms invalidate a revoked capability (structural nulling *and* a
serial-keyed generation bump), which is proper defence in depth. Kani proofs back the
subtree property.

**Side-channel hygiene is unusually mature for this stage.** `set_current_task` is a single
chokepoint for flush-on-switch, and the predicate is factored out as a pure function
(`sched_domain_switch_would_flush`) precisely so it can be unit-tested. SMT siblings are
parked in software to close co-residency. Kernel stacks sit above genuinely unmapped guard
pages. `CR4.TSD` denies ring-3 `RDTSC`.

### 2.2 Weaknesses

**W-1 — The object model has a hole where its centre should be.** Capabilities correctly
mediate *type* authority (may this task talk to the block device at all?) but not *instance*
authority (which endpoint / which frame / which inode?). `cap->object` is carried,
delegated, revoked, and lineage-tracked — and then ignored at the point of use. See
**[C-1]** and **[C-2]**.

**W-2 — Ambient `uid == 0` authority runs in parallel with the capability system.** Nine
syscall handlers gate on `tasks[cur].uid != 0` rather than on a capability:

```c
/* src/kernel/syscall.c:831 (h_dmesg) */
if (tasks[get_current_task()].uid != 0) { r->rax = (uint32_t)SYS_ERR_PERM; return; }
```

`h_task_info` goes further and promotes root to full introspection over every task
(`syscall.c:468`). Two parallel authority systems — one capability-based, one
identity-based — means the capability graph is not a complete description of who can do
what, which defeats the primary reason to have a capability graph. seL4's discipline is
that *nothing* is ambient; Horus should converge on that.

**W-3 — Fixed-size global object tables.** `endpoints[64]`, `notifications[64]`,
`tasks[64]`, `cspace_pool[64][256]` (~1.5 MiB of `.bss`). Objects are not dynamically
allocated from a kernel memory capability, so there is no retyping discipline, no per-task
kernel-memory accounting, and a hard ceiling on system size. This is the main structural
obstacle to Horus becoming a complete OS: an OS cannot have a compile-time task limit of 64.

**W-4 — Endpoints are single-slot mailboxes.** One in-flight message per endpoint, no
queue. `sys_ipc_send` returns `-2` and expects userspace to poll. Under contention this is
a busy-wait, and it makes fair service and priority inheritance impossible to express. It
also means `FS_EP_REP = 5` is a *shared global* reply endpoint on which every client parks
its `SYS_IPC_CALL`, so concurrent clients collide on one `blocked_waiter` (masked today
only because `SYS_IPC_REPLY_TO` routes by recorded sender identity instead).

**W-5 — No kernel object lifecycle.** `task_teardown` clears signal/pipe/IO state but there
is no reference-counted destruction of endpoints or notifications, and no accounting that
ties a kernel object's existence to a capability holding it alive.

**W-6 — `this_cpu()` reads LAPIC MMIO on every call.** `get_current_task()` calls it, and
`get_current_task()` is called several times per syscall. An uncached MMIO read is on the
order of hundreds of cycles. This is the dominant avoidable cost in the syscall path and
should be a `GS`-based per-CPU block (`swapgs` + `%gs:offset`). *(Fixed — via the TSS
selector in `TR` rather than `%gs`; see the status note under **[I-6]**.)*

### 2.3 How development practice supports / undermines the architecture

Supports: the QEMU self-test corpus is what makes aggressive refactors (higher-half
kernel, 64-bit userspace, SMP-by-default) survivable, and the reproducible-build gate makes
"what shipped" answerable. Kani proofs on revocation and cargo-fuzz on the FFI predicates
are the right tools aimed at the right surfaces.

Undermines: zero-approval merges mean architectural drift is never challenged. **[C-1]** is
precisely the kind of defect that survives every automated gate and dies instantly in
review — the tests assert that *held* capabilities work and *unheld* ones are refused, but
no test asserts that holding an endpoint capability for object 4 does not grant endpoint 6,
because nobody was in the room to ask.

---

## 3. Critical Security & Correctness Issues

### [C-1] IPC endpoints are ambient: any task may send, receive, and forge replies on any endpoint — *Critical* — **FIXED (2026-07-27)**

**Location.** `src/kernel/syscall.c:885-890, 908, 914` (dispatch table);
`src/kernel/syscall_ipc.c:165, 252, 367, 437` (handlers); `src/kernel/scheduler.c:180-199`
(`create_task` capability endowment).

**Analysis.** The dispatch table authorises every IPC syscall on *slot 3*, with
`SC_ANYTYPE`:

```c
/* src/kernel/syscall.c */
[SYS_IPC_SEND]     = { h_ipc_send,     3, CAP_RIGHT_WRITE, SC_ANYTYPE },
[SYS_IPC_RECV]     = { h_ipc_recv,     3, CAP_RIGHT_READ,  SC_ANYTYPE },
[SYS_IPC_REPLY_TO] = { h_ipc_reply_to, 3, CAP_RIGHT_WRITE, SC_ANYTYPE },
[SYS_IPC_SENDER]   = { h_ipc_sender,   3, CAP_RIGHT_READ,  SC_ANYTYPE },
```

And `create_task` gives *every* task a slot 3 that satisfies it — a `CAP_FRAME`, not even
an endpoint capability:

```c
/* src/kernel/scheduler.c:180 */
tasks[id].cspace[3].type   = CAP_FRAME;
tasks[id].cspace[3].rights = CAP_RIGHT_READ | CAP_RIGHT_WRITE | CAP_RIGHT_EXEC;
```

The endpoint itself is then selected by an unmediated integer:

```c
/* src/kernel/syscall_ipc.c:353 */
void h_ipc_send(struct interrupt_frame64 *r) {
    r->rax = sys_ipc_send(r->rbx, (const void*)(addr_t)r->rcx, r->rdx);
}
/* src/kernel/syscall_ipc.c:166 */
if (ep >= MAX_ENDPOINTS) return -1;      /* the ONLY check on `ep` */
```

`cap->object` — the field that names *which* endpoint — is read in exactly two places
(`h_register_fs_server`, `h_connect_fs_server`) and never on an IPC operation. The intent
is documented in `src/kernel/kshell.c:393`: init is endowed with "two `CAP_ENDPOINT` caps
for a server's coarse IPC gate (slot 3) and its listen endpoint (slot 4, object
`FS_EP_REQ=4`)". That delegation happens; the enforcement does not.

**Exploit scenario.** `FS_EP_REQ = 4`, `FS_EP_REP = 5`, `CON_EP_REQ = 6` are compile-time
constants in public headers (`include/fs_proto.h`, `include/console_proto.h`). Any
unprivileged ring-3 program — a user's own binary compiled with the shipped `tcc` — can:

1. `sys_ipc_recv(FS_EP_REQ, buf, len)` — dequeue another user's filesystem request. This
   both **discloses** it (paths, file contents being written) and **removes** it, since
   `sys_ipc_recv` clears `has_message`. It also sets `e->last_sender` to the victim.
2. `sys_ipc_reply_to(FS_EP_REQ, forged, len)` — the kernel copies the attacker's buffer
   *directly into the victim's blocked `SYS_IPC_CALL` reply buffer* and wakes it
   (`syscall_ipc.c:466-493`). The victim cannot distinguish this from a genuine server
   reply.

Step 2 is the severe one: the attacker forges filesystem responses. Forged file contents,
forged `stat` results, forged success on a write that never happened. Because `fs_server`
is the reference monitor for POSIX permissions, forging its replies defeats the entire
permission model — and because the shell resolves and executes `/bin` binaries through the
FS server, an attacker can serve arbitrary bytes as the contents of a program another user
is about to execute. Symmetrically, `sys_ipc_send(CON_EP_REQ, …)` injects console output,
and `sys_ipc_recv(CON_EP_REQ, …)` intercepts console traffic including the masked-password
path.

**Fix.** Bind the endpoint index to a capability. Change the IPC ABI so the first argument
is a *cspace slot*, not an endpoint index, and resolve it:

```c
/* Resolve an endpoint capability slot to the endpoint it names. */
static int ipc_ep_from_slot(uint32_t slot, uint32_t need_rights, uint32_t *out_ep) {
    struct capability *c = cap_lookup(slot, need_rights);
    if (!c || c->type != CAP_ENDPOINT)   return -1;
    if (c->object >= MAX_ENDPOINTS)      return -1;
    *out_ep = (uint32_t)c->object;
    return 0;
}

void h_ipc_send(struct interrupt_frame64 *r) {
    uint32_t ep;
    if (ipc_ep_from_slot((uint32_t)r->rbx, CAP_RIGHT_WRITE, &ep) != 0) {
        r->rax = (uint32_t)SYS_ERR_PERM; return;
    }
    r->rax = sys_ipc_send(ep, (const void *)(addr_t)r->rcx, r->rdx);
}
```

Apply identically to `RECV` (`CAP_RIGHT_READ`), `CALL` (both endpoints), `REPLY`,
`REPLY_TO`, `IPC_SENDER`, and to `NOTIFY`/`WAIT_NOTIFY` against `CAP_NOTIFICATION`. Remove
the slot-3 entries from the dispatch table for those syscalls — the per-slot lookup *is*
the gate, and leaving the table entry would re-admit `CAP_FRAME`. Then:

- `create_task` must stop handing out ambient endpoint caps; slots 4/5 should be `CAP_NULL`
  and populated only by delegation from `init`.
- `SYS_CONNECT_FS_SERVER` already mints a correctly-objected endpoint cap
  (`cap_install_endpoint(dest_slot, fs_server_listen_ep_idx, …)`) — it becomes the
  legitimate acquisition path, and should mint **`CAP_RIGHT_WRITE` only**, so a client can
  send to the server but never `recv` on the server's endpoint.
- Give each client a *private* reply endpoint instead of the shared `FS_EP_REP = 5`,
  allocated at connect time. This also fixes **W-4**'s `blocked_waiter` collision.

**Resolution.** Implemented as described. Every IPC syscall now takes a cspace slot and
resolves it through `ipc_ep_from_slot` / `ipc_notif_from_slot` (`src/kernel/syscall_ipc.c`),
which enforce type, right, and lineage in one place before `object` is trusted. The slot-3
dispatch-table entries are gone, `create_task` no longer grants ambient endpoint
capabilities, `SYS_CONNECT_FS_SERVER` mints WRITE-only, `SYS_IPC_REPLY_TO` requires READ (the
receive right), and every task has a private kernel-chosen reply endpoint — so the shared
`FS_EP_REP` collision (**[I-5]**) is gone too.

**Regression tests** (`userspace/captest.c`, 29 → 41 checks). Twelve new checks assert the
refusals: a `CAP_FRAME` (the old gate) authorises no IPC operation; a WRITE-only client
capability is refused `recv`, `reply_to`, and `sender` — the interception and reply-forgery
halves of this finding; endpoint and notification capabilities do not authorise each other's
operations; empty slots are refused.

**These tests were themselves falsified.** They are asserted against the exact code
`SYS_ERR_PERM`, not merely "negative", because `sys_ipc_recv` returns `-2` for an empty
mailbox: a `< 0` assertion cannot distinguish "refused" from "allowed, but nothing there",
and the first draft of the suite passed with the vulnerable handler deliberately restored.
The fix was verified by reintroducing the pre-fix handler and confirming the suite fails
(`CAPTEST: FAIL ipc-recv-on-unheld-slot-allowed`), then restoring it and confirming 41/41.
A test that cannot fail on the bug it targets is not evidence — see **[I-11]** for the same
defect class found in `smoke-fs-wal`.

---

### [C-2] Notification objects are ambient — *High* — **FIXED (2026-07-27)**

**Location.** `src/kernel/syscall_ipc.c:295, 330`; dispatch entries `syscall.c:889-890`.

Same defect class as **[C-1]**: `sys_notify(notif_slot, badge)` bounds-checks
`notif_slot < MAX_NOTIFICATIONS` and nothing else. Any task can raise any badge on any
notification slot. Since `SYS_IRQ_REGISTER` routes hardware interrupts to notification
slots, an unprivileged task can **forge interrupt delivery** to the console driver —
spurious keyboard/UART IRQ notifications, driving the driver's state machine from
userspace. Fix is the `CAP_NOTIFICATION` half of **[C-1]**'s patch.

---

### [C-3] `spin_lock`/`spin_unlock` interrupt bookkeeping is global and IF-destroying — *High* — **OPEN; a fix was attempted and reverted, see 3.1**

**Location.** `src/kernel/scheduler.c:974-989`.

```c
static volatile int irq_lock_depth = 0;              /* ONE counter, all CPUs */
void spin_lock(spinlock_t *lock) {
    __asm__ volatile ("cli" ::: "memory");
    irq_lock_depth++;                                /* non-atomic RMW, shared */
    ...
}
void spin_unlock(spinlock_t *lock) {
    __sync_lock_release(&lock->locked);
    if (irq_lock_depth > 0 && --irq_lock_depth == 0)
        __asm__ volatile ("sti" ::: "memory");       /* unconditional re-enable */
}
```

Two defects, both live because **SMP is the default build**:

1. **Shared across CPUs.** CPU A acquiring and CPU B releasing decrement each other's
   nesting. B's release can drive the shared count to zero and `sti` *on B* while A still
   holds a lock; symmetrically A can be left masked indefinitely. The `++`/`--` are plain
   non-atomic read-modify-writes on a shared `volatile int`, so counts are also lost
   outright. Consequence: a timer tick delivered inside a critical section — the exact
   reentrancy the `cli`/`sti` discipline exists to prevent — and a hard deadlock the moment
   the ISR path takes the lock the CPU already holds.

2. **Destroys caller IF state.** The unconditional `sti` at depth 0 re-enables interrupts
   even when the caller entered with them already off — from inside an interrupt gate, or
   nested in a hand-rolled `cli` region. The sharpest instance is `user_copy`
   (`paging.c:1369`), which masks interrupts, switches `CR3` to the kernel PML4, saves
   `prev_cr3`, and may call `handle_demand_page_fault` (which takes `page_lock`) to break
   COW. The inner `spin_unlock` re-enables interrupts *inside that CR3 window*; a tick then
   preempts to another task and installs its `CR3`, and on return `user_copy` restores a
   now-stale `prev_cr3`. That is address-space corruption reachable from an ordinary
   `copy_to_user` into a COW page.

**Fix attempted, and reverted — this is finding [C-3.1], which matters more than [C-3].**

The obvious fix is per-CPU nesting depth plus per-CPU saved `RFLAGS.IF`, sampled atomically
with the mask at the outermost acquire and restored only if interrupts were on to begin
with. That was written and it passes every local gate — `make`, `make smoke`,
`make smoke-smp` (4 cores, 3 distinct CPUs ran tasks, TLB shootdown ok), `make smoke-captest`
(29 checks), `make smoke-wx`, 91 Rust tests, clippy clean — **and it breaks the system in
CI**, reproducibly, in a way local runs do not surface.

Two consecutive CI runs failed on two *different* ring-3 session tests:

- `smoke-modules`: timed out after 300 s waiting for `[fs_server] filesystem provisioned`.
  The kernel booted normally (2.08 s) and reached `horus login:`; the bulk provisioning work
  simply never progressed.
- `smoke-coreutils-shell`: hard failure — `ls: spawn fs_server first`, i.e. the shell never
  obtained an fs_server connection, preceded by
  `[fs_server] warning: registration failed; serving anyway.`

The base rate rules out coincidence: **14 of the last 15 `main` runs are fully green**, and
the single failure was an unrelated test (`smoke-session-smp`, the one PR #94 exists to give
a larger budget). `main` at `b7f4bd9` passed every job on the same runner pool the same day.
Base rate ≈ 0; the patched branch failed 2 for 2.

**[C-3.1] — The kernel's boot-time interrupt enablement is implicit, and depends on this
very bug.** *(High; arguably more serious than [C-3] itself.)*

Because the old `spin_unlock` does an **unconditional** `sti` whenever nesting reaches zero,
any `spin_lock`/`spin_unlock` pair executed in a context where `IF` was already clear
*enables interrupts as a side effect*. During boot and early init the kernel takes many such
locks (`page_lock`, `cap_lock`, `storage_lock`) with interrupts masked. Interrupts are
therefore being turned on earlier, and far more often, than any explicit policy in the code
calls for — and the `init` → `fs_server` → `console_server` → shell startup handshake has
come to rely on the timer preemption that results.

Correcting the lock keeps interrupts masked exactly as the surrounding code asks, the timer
stops firing during those windows, and the startup handshake stalls. So the observable
behaviour of the boot path is a consequence of a locking defect rather than of a stated
design. **The bug is load-bearing.**

That makes [C-3] not a drive-by fix. The correct sequence is:

1. Make boot-time interrupt enablement **explicit** — identify every window that currently
   depends on the accidental `sti` and issue (or defer) `sti` deliberately, with the policy
   written down.
2. Add a self-test asserting `IF` state at the boot milestones, so the dependency cannot
   silently return.
3. *Then* land the per-CPU, IF-preserving lock.

Attempting step 3 first is what this audit did, and CI caught it. Noting that plainly is
more useful than a green patch: it is direct evidence that the ring-3 startup path has an
undocumented timing dependency on kernel interrupt state, which is a latent hazard for the
SMP work and for any future real-time or tickless scheduling.

**Assurance note.** This also demonstrates the gap the local test suite has: every local gate
passed. The QEMU session tests that caught it are precisely the ones **[C-6]** shows are *not*
merge-gating — `smoke-modules` and `smoke-coreutils-shell` are both outside the required-checks
set. Had this been merged on a green required set, it would have shipped.

---

### [C-4] `copy_to_user`/`copy_from_user` silently truncate and report success — *Medium-High* — **FIXED (2026-08-13)**

**Location.** `src/kernel/paging.c:1434-1444`.

```c
int copy_from_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;   /* silent clamp */
    return user_copy(..., n, 0, 0);                     /* returns 0 == success */
}
```

A caller requesting more than `USER_MEM_MAX_COPY` gets a *partial* copy and a success
return. Every caller that copies a fixed-size struct and then trusts it is exposed: the
tail of the destination retains whatever was on the kernel stack. `h_task_info` and
`h_receive_program` are structurally at risk today; any future larger struct is a
kernel-stack information leak to ring 3.

**Fix.** Fail closed rather than truncate, and give callers an explicit partial-copy API if
one is genuinely needed:

```c
int copy_from_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) return -1;   /* refuse; do not silently short-copy */
    return user_copy((uint64_t)(uintptr_t)src, (uint8_t *)dst, n, 0, 0);
}
```

---

### [C-5] Merges require a pull request but require no reviewer — *Critical (process)*

**Location.** Repository ruleset `main protection` (id 19007209).

```json
{"type":"pull_request","parameters":{
   "required_approving_review_count": 0,
   "require_code_owner_review": false,
   "require_last_push_approval": false,
   "required_review_thread_resolution": false }}
```

All 25 most recent merged PRs report `reviewDecision: NO_REVIEW`. The PR requirement is
therefore a changelog mechanism, not a control. `CODEOWNERS` exists and is thorough, but
`require_code_owner_review: false` makes it inert — and it is additionally stale, naming
seven files that do not exist (`src/kernel/capability.h`, `paging.h`, `syscall.h`,
`scheduler.h`, `crypto.h`, `docs/SECURITY.md`) while omitting the files where **[C-1]**
actually lives (`syscall_ipc.c`, `syscall_fs.c`, `syscall_hw.c`, `loader.c`, `smp.c`).

**Assurance impact.** This is the direct causal link between process and the kernel's most
serious defect. **[C-1]** passes every automated gate — it builds, boots, and satisfies a
29-check capability conformance suite — because the suite tests the property the author
had in mind. Review is the control that catches "the property you tested is not the
property you claimed".

**Fix.**
```
required_approving_review_count: 1
require_code_owner_review: true
dismiss_stale_reviews_on_push: true
require_last_push_approval: true
required_review_thread_resolution: true
```
For a genuinely single-maintainer project, `1` is unachievable without a second human, and
that is the honest finding: **either recruit a second reviewer for security-critical paths,
or stop claiming high assurance for them.** A defensible interim is a mandatory
self-review checklist enforced by the PR template plus a required "adversarial review"
job — but it is a mitigation, not a substitute. Correct `CODEOWNERS` paths in the same
change.

---

### [C-6] Security-specific CI jobs are not merge-gating — *High (process)*

**Location.** Ruleset `required_status_checks` (21 contexts).

Required: build, smoke-boot, clippy, reproducible, filesystem suite, preempt, signals, SMP,
notify, ELF W^X, newlib, process-control, session, security-scan, alt-configs.

**Not required**: `smoke-captest` (capability conformance), `smoke-wx` (kernel W^X sweep),
`smoke-tpm` / `smoke-tpm-seal` / `smoke-tpm-tamper` (measured boot), `smoke-modules-tamper`
(module integrity rejection), `smoke-cpu` (SMEP/SMAP actually in CR4), `smoke-flush`
(side-channel barriers), `smoke-stackguard` (canary reseed), `smoke-aspace`, `smoke-smt`,
`smoke-e820`, `smoke-elf64`, CodeQL.

The set is inverted: the tests that verify *functionality* block merges; the tests that
verify *security properties* do not. A regression that silently disables SMEP, breaks the
capability refusal suite, or lets a tampered boot module through merges green.

Additionally `strict_required_status_checks_policy: false` permits merging a PR whose CI
passed against a stale base, and the `security` job wraps every scanner in
`continue-on-error: true`, so Semgrep/Trivy/gitleaks/cargo-audit findings are advisory only.

**Fix.** Promote all `smoke-*` security self-tests and CodeQL to required contexts; set
`strict: true`; make `gitleaks` and `cargo-audit` hard-fail (keep Semgrep/Trivy advisory
until their false-positive rate on a freestanding kernel is characterised).

---

## 4. Important Issues

### [I-1] Ambient `uid == 0` authority parallel to the capability system — *Medium-High* — **FIXED (2026-07-27)**

Nine handlers gate on `tasks[cur].uid != 0` (`h_dmesg`, `h_boot_module_info`,
`h_boot_module_read`, `h_fs_inode_alloc/free/link`, `h_fblock_read/write`, `h_fs_stat`,
`h_fs_set_size`, `h_fs_set_meta`), and `h_task_info:468` promotes root to full
cross-task introspection. Root is therefore a second, capability-invisible authority axis.
**Resolution.** Implemented. `CAP_KERNEL_LOG` (14) and `CAP_BOOT_MODULE` (15) were added and
the object-store syscalls now require `CAP_ENCRYPTED_STORAGE` **by type**; every
`tasks[cur].uid != 0` gate in `syscall.c` and `syscall_fs.c` is gone, as is the root
promotion in `h_task_info`. `init` mints nothing itself — it delegates from the primordial
root cnode to exactly the task that needs each authority (kernel log → shell, boot modules →
`fs_server`, object store → `fs_server`, `CAP_AUDIT` → shell for `ps`).

**[I-1a] — the gates were also type-confused (new, found while fixing this).** The dispatch
entries read `{ handler, 7, CAP_BLOCK_DEV, SC_ANYTYPE }`, but the third field is `rights`,
not `ctype`. `CAP_BLOCK_DEV` is the type constant `11` = `0b1011`, so the gate actually
demanded rights `READ|WRITE|GRANT` on a capability of **any** type. The FS self-test harness
had been installing a `CAP_CONSOLE` (`root_cnode[8]`) into slot 7 and passing. Same defect
class as **[C-1]**: authorisation by something other than the thing being authorised. All
twelve entries now specify the required type in `ctype`.

**A privilege widening this nearly introduced.** Delegating `CAP_KERNEL_LOG` to the shell
hands it to *every* logged-in user, because capabilities are per-task and the shell is one
long-lived task serving successive logins — strictly weaker than the `uid == 0` gate it
replaced. `smoke-session` caught it. The shell now enforces the per-user policy itself, which
is the correct split: the **kernel** asks "does this task hold the authority?", the **session
manager** asks "may this user use it?". Neither question subsumes the other.

**Regression tests** (`captest`, 41 → 47 checks). `captest` runs as uid 0 and is deliberately
denied these capabilities, so each check proves root alone is not authority — `dmesg`,
boot-module info/read, `fs_stat` and `inode_alloc` must all be refused. Asserted as exactly
`SYS_ERR_PERM`, and falsified: restoring the ambient `SYS_DMESG` entry makes the suite fail
(`CAPTEST: FAIL dmesg-allowed-by-uid0-without-CAP_KERNEL_LOG`).

### [I-2] `h_sbrk`/`h_brk` truncate 64-bit heap arithmetic to 32 bits — *Medium* — **FIXED (2026-08-13)**

```c
/* src/kernel/syscall.c:176 */
uint32_t new_current = tasks[tid].heap_current + (uint32_t)increment;
uint64_t heap_max    = tasks[tid].heap_start + USER_HEAP_MAX_SIZE;
/* src/kernel/syscall.c:222 */
uint32_t aligned = (addr + 0xFFFU) & ~0xFFFU;   /* addr is uint64_t */
```

Correct only while every heap lives below 4 GiB. With ASLR widening the user address space
(a stated roadmap goal), a heap based above 4 GiB makes `new_current` wrap and the
`heap_start`/`heap_max` bounds check pass on a truncated value — a heap pointer outside the
authorised region. **Fix:** make the arithmetic `uint64_t` end-to-end and check overflow
explicitly before the range test. Latent today, sharp the moment the address space widens.

### [I-3] `MAX_REVOKE_LINEAGE` overflow fallback is object-scoped — *Medium, fails safe*

`revoke_subtree` caps the descendant worklist at 256 and, on overflow, nulls every
capability sharing `root_object`. Complete (no descendant survives) but over-broad: an
independent, non-derived capability to the same object is destroyed. A task could
deliberately construct a >256-member derivation subtree to force the fallback and revoke a
*peer's* unrelated capability to a shared object — a denial-of-service on another task's
authority. **Fix:** make the closure iterative over the cspace set without a fixed worklist
(mark-and-sweep using a per-capability visited bit, or iterate to fixpoint), removing the
fallback entirely.

### [I-4] `h_task_info` leaks another task's `%rip` to any root task — *Medium* — **FIXED (2026-07-27)**

`info.eip = tasks[tid].eip` (`syscall.c:489`). `cr3` is correctly zeroed with an explicit
comment about not disclosing physical layout, but `eip` defeats user-space ASLR for the
observed task by directly revealing a code address. **Fixed:** `eip` is now reported only for the calling task and zeroed for any other, matching
the existing treatment of `cr3`.

### [I-5] Shared global reply endpoint `FS_EP_REP = 5` — *Medium*

Every client parks its `SYS_IPC_CALL` block on endpoint 5. Two concurrent clients overwrite
each other's `blocked_waiter`; correctness survives only because `SYS_IPC_REPLY_TO` routes
by `last_sender`. The remaining `blocked_waiter` write is dead state that will bite the
moment a second reply path is added. **Fix:** allocate a per-client reply endpoint at
`SYS_CONNECT_FS_SERVER` time (folds into **[C-1]**).

### [I-6] `this_cpu()` performs an uncached LAPIC MMIO read per call — *Medium (performance/DoS)*

`get_current_task()` → `this_cpu()` → `lapic[0x20/4]`, several times per syscall. Hundreds
of cycles each on an uncacheable mapping. **Fix:** `swapgs` + a per-CPU block at `%gs:0`
holding CPU id and current task; initialise `IA32_KERNEL_GS_BASE` per CPU at AP bringup.
This is the single largest syscall-path win available.

> **Status: fixed, by a different mechanism than the one proposed above.** The proposed fix
> was not taken: making a `%gs` base survive a ring transition requires `swapgs` in every ISR
> entry and exit, because the ring-3 return paths load a user selector into `%gs` and that
> zeroes the GS base in long mode. Instead `this_cpu()` now reads the CPU id out of the TSS
> selector already in `TR` — `cpu = (str() - 0x38) / 0x10` — since every CPU `ltr`s a distinct
> TSS for RSP0/IST purposes. A register read replaces the MMIO read; the non-SMP build folds
> to `return 0`. Cross-checked against the LAPIC on each core at bringup
> (`percpu_id_verify_self`, panics on disagreement) and gated by `make smoke-percpu`, which
> requires ≥2 cores so the mapping cannot pass by being trivially right on one. The `%gs`
> block is still wanted for **[C-3]**'s per-CPU IRQ-nesting state — see roadmap 1.2 — but no
> longer for syscall cost.
>
> Found while fixing this: `syscall_entry` carried a one-sided `swapgs` (entry, none before
> `sysretq`). Unreachable today (`EFER.SCE` is never set) and inert (no GS base exists), but
> armed for whoever changes either. Now balanced, with its remaining preconditions documented
> and `EFER.SCE == 0` asserted by `smoke-percpu`.

### [I-7] Fixed-size `.bss` object tables cap the system at 64 tasks — *Medium (capability ceiling)*

`static struct capability cspace_pool[MAX_TASKS][256]` inside `create_task` is ~1.5 MiB of
`.bss` against a hard `__bss_end <= USER_PHYS_BASE` (16 MiB) linker assertion. **Fix:** move
cspaces and kernel objects into pool-allocated frames governed by a `CAP_UNTYPED` /
retyping discipline (seL4's model). This is the prerequisite for a general-purpose OS and
should be scheduled before further userspace feature work.

### [I-8] `CODEOWNERS` is stale and inert — *Medium (process)*

Seven non-existent paths; the files containing **[C-1]** are covered only by the `*`
fallback; `require_code_owner_review: false` makes the whole file advisory. Fix alongside
**[C-5]**.

### [I-10] The write-ahead journal is never flushed to stable storage — *Medium-High (data integrity)*

**Location.** `src/kernel/ata.c` — the driver's complete command set.

```c
#define ATA_CMD_READ   0x20
#define ATA_CMD_WRITE  0x30
/* ... */
outb(ATA_COMMAND, 0xEC);        /* IDENTIFY */
```

Those three are the only ATA commands the kernel ever issues. There is **no `FLUSH CACHE`
(0xE7)** anywhere in the tree.

`WRITE SECTORS` completes as soon as the data reaches the drive's *volatile write cache*,
which is enabled by default on essentially every ATA/SATA device. Without a `FLUSH CACHE`
after the journal's commit record, a power failure between commit and platter-write loses
the record. The filesystem then recovers to a state where the transaction was neither
applied nor journalled — precisely the outcome the WAL exists to prevent.

**Why it has never been caught.** The test harness runs QEMU with
`-drive ...,cache=writethrough` (`tools/smoke_test.sh:67`), which commits every guest write
to the host image file immediately. Under writethrough the emulator provides the durability
the kernel omits, so `smoke-fs-wal` passes — it is verifying crash-atomicity in the one
configuration where crash-atomicity is guaranteed by something other than the code under
test. The claim "crash-atomic via a write-ahead journal" is therefore **unwitnessed on real
hardware**.

**Fix.** Issue `FLUSH CACHE` (0xE7 for LBA28, 0xEA for LBA48) after the commit record and
again after the checkpoint that retires it, and wait for BSY to clear:

```c
#define ATA_CMD_FLUSH  0xE7

int ata_flush_cache(void) {
    outb(ATA_DRIVE, 0xE0);
    outb(ATA_COMMAND, ATA_CMD_FLUSH);
    /* FLUSH CACHE may take seconds on a real drive; poll BSY, not a fixed delay. */
    while (inb(ATA_STATUS) & ATA_SR_BSY) { }
    return (inb(ATA_STATUS) & ATA_SR_ERR) ? -1 : 0;
}
```

Then add a test that runs with `cache=writeback` (or `cache=unsafe`) so the guarantee is
exercised where the emulator is *not* silently providing it. Without that, the new code is
as unwitnessed as the old.

### [I-11] `smoke-fs-wal` is nondeterministic by construction, and is a required check — *Medium (process)*

**Location.** `tools/smoke_test.sh:90-106`, `Makefile:1247`.

The harness polls the serial log every 0.5 s and kills QEMU the moment the required marker
appears:

```sh
if grep -qF "$REQUIRE_MARKER" "$LOG" 2>/dev/null; then status="ok"; break; fi
```

Boot 1 of the crash-recovery test prints `WAL_CRASHTEST: crashed-after-commit` and is then
SIGTERM'd. But the serial console and the IDE data path are independent: the marker
appearing proves the guest *reached* that point, not that its journal writes completed.
`cache=writethrough` makes *completed* writes durable; it does nothing for a write still in
flight, or not yet issued, when the process dies. The script's comment asserts otherwise:

> `cache=writethrough: every guest write is committed to the host image file immediately, so
> a two-boot persistence test ... never loses the first boot's writes`

Under TCG on a loaded runner the interleaving shifts and boot 2 fails with
`WAL_CRASHTEST: FAIL read`. Observed on this branch, whose only non-markdown change is
`.github/CODEOWNERS` — so the kernel is byte-identical to `main`, which passed.

Two consequences, the second worse than the first:

1. A required status check fails spuriously and blocks merges (this is one of the 21 gating
   contexts).
2. **It can mask a genuine WAL regression.** A kernel that truly failed to commit produces
   the identical `FAIL read`. A test that cannot distinguish "the code is broken" from "the
   harness was too quick" is not evidence for the property it claims to establish.

**Fix.** Make boot 1 signal completion *after* the disk write is durable rather than racing
it — have the guest halt itself (`isa-debug-exit`, already wired in the harness) once the
commit is genuinely on the device, and have the harness wait for QEMU to *exit* instead of
killing it on a serial string. Failing that, drain: after the marker, wait for the guest to
go quiescent before SIGTERM.

### [I-12] Self-test waiters busy-spin instead of yielding, and starve what they wait on — *Medium (test validity)* — **FIXED (2026-07-27)**

**Location.** `userspace/proctest.c` (three task-state poll loops).

`proctest` waits for a child to exit by polling `sys_get_task_info` in a loop with
no yield. Two things make that actively harmful rather than merely wasteful:

1. The awaited task can only progress if it gets the CPU, and the poller is competing
   with it for the same single core.
2. Every iteration issues a **syscall**, which runs in ring 0 — where a timer tick
   never switches tasks (`preempt_on_tick` only preempts ring 3). A syscall-heavy
   spin therefore holds a *disproportionate* share of the CPU.

The `sig-stuck` check had only a 1.5x margin: proctest's 12000-iteration budget had to
outlast `sigtarget`'s 8000-unit masked window. On a loaded CI runner, syscall overhead
under TCG (several uncached LAPIC MMIO reads per call — finding **[I-6]**) consumed it, and
`main` went red on a *required* check while the same commit passed 5/5 locally.

**Fixed** by yielding before spinning (`poll_wait`). Verified that the yield — not the
larger budget — is what does the work: with `sys_yield()` and a **3000**-iteration budget,
a quarter of the 12000 that failed on CI, the test passes.

**Why this is a test-validity finding, not just a flake.** A timing-marginal test fails
*non-deterministically*, so a genuine signal-delivery regression and a starved runner
produce the same red. That is the same defect class as **[I-11]** (`smoke-fs-wal`) and the
`< 0` assertion problem in **[C-1]**'s first draft: a test whose outcome does not depend
solely on the property under test is weak evidence for that property.

### [I-13] Spawn published a runnable child before its supervisor could endow it — *High* — **FIXED (2026-07-27)**

**Location.** `src/kernel/kspawn.c` (`do_spawn_inner`), every ring-3 supervisor.

A supervisor's only way to endow a child is `spawn → sys_cap_grant… → child runs`. But
spawn marked the child **runnable immediately**, so under SMP it genuinely began executing on
another core *before* the grants landed. The child then ran with a partially-populated cspace
and failed in whatever way its missing capability implied.

**This was one root cause behind three separate incidents**, each individually papered over
before the pattern was recognised:

| Symptom | Missing capability | Band-aid |
|---|---|---|
| `fs_server` registration failed | fs listen cap not yet granted | retry loop |
| Client had no filesystem | fs endpoint cap not yet granted | retry loop |
| **Shell came up silent; CI timed out** | console cap not yet granted | *none — it just hung* |

The third had no retry, so `smoke-session-smp` failed and `main` went red.

**Fix: spawn is now SUSPENDED.** `do_spawn` clears `runnable_ctx`, and a new
`SYS_TASK_RESUME(tid)` — authorised by a `CAP_TCB` on the target, exactly like `SYS_KILL` —
makes the child schedulable. Supervisors call it after endowment. Retrying in each client is
whack-a-mole; it requires every current *and future* client to anticipate a race it cannot
see. Suspending the child instead makes the safe ordering **the only expressible one**.

**The failure mode improves, which is the real point.** Forgetting to resume is a
*deterministic* hang — the child never runs, every time, locally as well as in CI. Racing an
endowment was *intermittent*, and intermittent failures get re-run rather than fixed.

**Witness** (`proctest`): spawn a child that exits promptly, wait long enough that it
certainly would have, assert it has **not**, then resume and assert it does. This cannot pass
on the pre-fix kernel.

Two things the witness itself exposed, both worth recording:

- It was initially placed mid-harness, where holding a task slot in the suspended state
  delayed slot reuse, shifted the ids handed to later spawns, and broke `proctest`'s
  timing-coupled signal choreography. Moved to the end.
- `smoke-proc` required a marker printed *partway through* by `sigtarget`, so the harness
  killed QEMU **before the witness ever ran** — it was dead code that reported success. The
  required marker is now the last line `proctest` prints. Worth checking for in other
  self-tests: *a marker that is not the final one silently truncates everything after it.*

### [I-9] No build provenance or artifact attestation — *Medium (supply chain)*

Reproducibility is verified, and an SBOM is produced, but nothing binds a published
`kernel.elf`/`boot.iso` to the commit and workflow that built it. A consumer cannot verify
that a downloaded ISO came from this repository's CI. **Fix:** add
`actions/attest-build-provenance` (SLSA v1 provenance) and Sigstore/cosign signing of
release artifacts; publish the expected TPM PCR values alongside each release so a relying
party can pre-compute the measured-boot quote.

---

## 5. Minor Issues & Style Suggestions

- **M-1 — Repository hygiene is good; verify before assuming otherwise.** A working
  checkout contains ~70 MB of build output (`kernel.elf`, `boot.iso`, `persist.img`,
  `wal.img`, `*.o`, newlib `.deb`s, `.venv/`, `__pycache__/`, `.aider.*`), which looks alarming
  on `ls`. **None of it is tracked** — `.gitignore` is comprehensive and correct, and
  `git ls-files` reports 243 tracked files with no build artefacts and no vendored binaries.
  The only development-tool file in the index is `horus.py`. Noted here because the
  discrepancy between working tree and index is easy to misread; the finding is that the
  hygiene is *fine*, not that it needs fixing.
- **M-2 — `horus.py` and `system_prompt.txt`** are development scaffolding; `horus.py` is
  tracked. Move it under `tools/` or drop it.
- **M-3 — No `CODE_OF_CONDUCT.md`,** no `.github/ISSUE_TEMPLATE/`, and the PR template
  sits at `docs/pull_request_template.md` where GitHub will not pick it up (it must be
  `.github/pull_request_template.md` or repo root). *(Fixed in this change.)*
- **M-4 — `secret_scanning_non_provider_patterns` and `secret_scanning_validity_checks`
  are disabled.** Both are free and should be on.
- **M-5 — `syscall_handler64` is dead and misleading** (`syscall.c:3`): it reads `rax` via
  an empty `asm` with an output constraint, which is not a defined way to obtain a register
  value. Delete it.
- **M-6 — `kassert_cap` hangs forever on failure** (`capability.c:225`): `for(;;){}` with
  interrupts on, no message. Should `println` and `cli; hlt` like `task_kstack_top`.
- **M-7 — Doc/implementation drift.** `docs/LIMITATIONS.md:44` states IPC is
  "capability-gated"; per **[C-1]** it is not. Addressed in the documentation rewrite
  accompanying this audit.
- **M-8 — `MAX_REV_SETS` machinery is unused.** `cap_create_revocation_set` has no callers
  and `rev_sets[]` is only cleaned. Either wire it to a syscall or delete it; dead security
  machinery invites false confidence.
- **M-9 — Two author identities and a bot** in `git shortlog` for what is one person
  (`Pharanyx Labs <horus@pharanyx.co.uk>`, `<305527349+…@users.noreply.github.com>`,
  `Yossi Cohen <horus@packetsync.org>`, `<horus@pharanyx.co.uk>`,
  `pharanyx-labs`). Consolidate via `.mailmap` so authorship is auditable.

---

## 6. Positive Aspects

**Kernel.**
- Fail-closed syscall dispatch with a compile-time completeness assertion
  (`_Static_assert(SYSCALL_TABLE_SIZE == SYS_DMESG + 1, …)`) — an unknown or reserved number
  cannot fall through to a handler.
- Deliberately reserved, never-reused syscall numbers 38–45 after removing the legacy capfs,
  so no future syscall inherits an old ring-3 caller. That is careful thinking.
- `user_copy`'s software page-walk enforcing `PAGE_USER` is stronger than SMAP alone and
  works identically on CPUs without SMAP.
- ChaCha20 fast-key-erasure CSPRNG with RDRAND health-checking, replacing a documented
  prior "LCG + raw TSC" that was ring-3-predictable. The commit message says so plainly.
- The publish-after-save IPC blocking protocol (`ipc_block_switch` writes `saved_ksp`,
  barriers, *then* publishes `blocked_waiter`) is the correct ordering and is explained at
  the site.
- FPU state is saved and restored across ring transitions (`idt.c:400,405`), closing an
  XMM-register cross-task leak.
- Explicit zero-padded `infobuf` in `h_sysinfo` fixing a prior ~7-byte `.rodata` leak —
  evidence of real leak-hunting.
- Comments consistently record *why*, including past failures ("Verified the hard way: with
  the r-x PTEs live but WP clear, a write …"). This is exemplary engineering prose and
  materially raises auditability.

**Process.**
- Every third-party action pinned to a full commit SHA with a version comment. No floating
  tags anywhere.
- Explicit least-privilege `permissions:` blocks on all three workflows; `pages.yml`
  deliberately isolated from `ci.yml` *because* it needs wider permissions, and the comment
  says so.
- Commit signing enforced by ruleset and verified true on every recent commit.
- `enforce_admins: true`, `bypass_actors: []`, `current_user_can_bypass: never`,
  linear history required, force-push and deletion blocked.
- Trivy installed via pinned release + `sha256sum --check` rather than `curl | sh`.
- Reproducible build *verified by double-build and diff*, not asserted.
- Adversarial CI: `smoke-modules-tamper` and `smoke-tpm-tamper` corrupt a module and assert
  both rejection and PCR divergence. Testing that the security control *fires* is rarer and
  more valuable than testing that the happy path works.
- Dependabot `cargo` ecosystem enabled with zero current dependencies, with a comment
  explaining it lights up the moment one is added.

---

## 7. Repository, Governance, CI/CD, and Development Workflow Assessment

### 7.1 Current state

| Control | State | Assessment |
|---|---|---|
| Branch protection on `main` | Ruleset, active, no bypass actors | **Strong** |
| Commit signing | Required + verified | **Strong** |
| Linear history / force-push / deletion | Required / blocked / blocked | **Strong** |
| Required PR | Yes | Weakened by ↓ |
| Required approvals | **0** | **Critical gap [C-5]** |
| Code-owner review | **Disabled**, file stale | **Gap [I-8]** |
| Required status checks | 21 contexts, `strict: false` | **Mixed [C-6]** |
| Action pinning | Full SHA, all workflows | **Strong** |
| `GITHUB_TOKEN` scopes | Least-privilege, per-workflow | **Strong** |
| Self-hosted runners | None | **Good** |
| Secret scanning + push protection | Enabled | **Strong** |
| Non-provider patterns / validity checks | Disabled | Minor gap **[M-4]** |
| Code scanning (CodeQL) | Enabled, advisory | Should gate **[C-6]** |
| Dependabot | Actions + Cargo, grouped, cooldown | **Strong** |
| SAST (Semgrep/Trivy/gitleaks/cargo-audit) | `continue-on-error` | Advisory only |
| SBOM | CycloneDX per run, artifact | **Good** |
| Build provenance / attestation | **None** | **Gap [I-9]** |
| Reproducible builds | Verified in CI | **Excellent** |
| Formal methods | Kani (revocation), TLA+ specs | **Excellent for stage** |
| Fuzzing | cargo-fuzz on FFI predicates, advisory | **Good** |
| `SECURITY.md` | Present, detailed | **Good** |
| `CODE_OF_CONDUCT.md` / issue templates | **Absent** | **[M-3]** |
| Releases / tags | **None** | See below |
| Contributor count | 1 (+ Dependabot) | **Structural [C-5]** |

### 7.2 SSDLC maturity

Against a BSIMM/SAMM-style reading, Horus is **Level 2–3 on tooling and Level 1 on
governance**. Automated verification is genuinely advanced — reproducible builds, formal
proofs, adversarial integrity tests, measured boot validated end to end in CI. Human
verification is absent. High assurance is the conjunction of the two; a system is not
high-assurance because its tests are good, it is high-assurance because *independent
parties* can and do check the claims.

**No tags, no releases, no changelog-to-artifact binding.** `CHANGES.md` is a rich
narrative history but nothing maps a version to a built artifact, a set of PCR values, or
an SBOM. For an OS intended to be deployed, versioned releases with attached
provenance + SBOM + expected PCRs are table stakes.

### 7.3 Traceability and auditability

Strong: every change lands via a PR, commits are signed, linear history, and commit
messages are unusually explanatory (often stating the invariant preserved and the failure
observed). Weak: no issue tracker use to speak of, no design-doc-to-code linkage beyond
`docs/proposals/`, no requirement that a security-relevant change state which invariant it
preserves — `CONTRIBUTING.md` asks for this but nothing enforces it.

### 7.4 Supply-chain posture

Excellent inputs, incomplete outputs. Inputs: no external Rust dependencies at all
(remarkable and deliberate), pinned actions, checksum-verified tool downloads, Dependabot
watching an empty graph so it lights up on the first addition, boot modules verified
against a manifest embedded in the kernel image. Outputs: no signed artifacts, no SLSA
provenance, no published PCR reference values, no release process. The chain is protected
up to the point where someone might actually consume it.

Vendored `newlib` (source + two `.deb`s, ~5.5 MB) is the one weak input: committed binaries
with no recorded provenance, hash, or upstream pin.

### 7.5 Targeted recommendations

**P0 (do first)**
1. `required_approving_review_count: 1` + `require_code_owner_review: true` + repair
   `CODEOWNERS` paths. If a second reviewer is genuinely unavailable, publish that fact in
   `SECURITY.md` and downgrade the project's assurance claims accordingly.
2. Promote all `smoke-*` security self-tests and CodeQL to required status checks; set
   `strict_required_status_checks_policy: true`.
3. Make `gitleaks` and `cargo-audit` hard-fail.

**P1**
4. `actions/attest-build-provenance` (SLSA v1) + cosign signing of `kernel.elf`/`boot.iso`.
5. Tagged releases carrying artifacts, SBOM, provenance, and expected PCR[8]/PCR[9] values.
6. ~~Purge build artefacts~~ — not needed; the index is already clean (**[M-1]**). Move
   `horus.py` under `tools/` (**[M-2]**).
7. `.github/pull_request_template.md` (move from `docs/`), `.github/ISSUE_TEMPLATE/`
   including a security-invariant-impact form, `CODE_OF_CONDUCT.md`. **Done in this change.**

**P2**
8. Enable secret-scanning non-provider patterns and validity checks.
9. `.mailmap` to consolidate the five author identities.
10. Pin vendored `newlib` by upstream URL + SHA-256 in a `THIRD_PARTY.md`, or fetch it at
    build time with verification instead of committing `.deb`s.
11. A `verify-release.sh` a third party can run: rebuild from a tag, diff against the
    published artifact, check the signature, recompute the PCRs.

---

## 8. Feature Additions & Enhancement Roadmap

Ordered by assurance-weighted value. Each item states rationale, security impact, and
implementation sketch.

### Tier 0 — Fix the object model (blocks everything else)

**F-0.1 — Capability-addressed IPC.**
*Rationale:* **[C-1]**/**[C-2]**. The single change that makes the capability system true.
*Security impact:* restores confidentiality and integrity of every ring-3 service;
converts `fs_server`'s reference-monitor design from aspirational to enforced.
*Sketch:* as in **[C-1]**. Migration: change `include/syscall.h` wrappers to take slot
numbers, update `fs_server`/`console_server`/`init` to use delegated slots, give clients
private reply endpoints at connect time, add the negative conformance tests. Budget one
focused change; do not bundle it with features.

**F-0.2 — Retype-based kernel object allocation (`CAP_UNTYPED`).**
*Rationale:* **[I-7]**, **W-3**, **W-5**. A 64-task ceiling and 1.5 MiB of `.bss` cspaces
cannot become an OS.
*Security impact:* per-task kernel-memory accounting (closes kernel-memory exhaustion DoS),
object lifetimes bound to capabilities, and the foundation for real isolation domains.
*Sketch:* follow seL4. `CAP_UNTYPED` names a physical region; `SYS_RETYPE(untyped, type,
count, dest_slots)` carves typed objects (TCB, CNode, Endpoint, Notification, Frame,
PageTable) from it. Objects are destroyed when the last capability is revoked. Start by
moving cspaces and endpoints off `.bss`; keep the existing tables as a compatibility shim
during migration.

**F-0.3 — Retire ambient `uid == 0` authority.**
*Rationale:* **[I-1]**, **W-2**. *Sketch:* `CAP_KERNEL_LOG`, `CAP_BOOT_MODULE`,
`CAP_OBJECT_STORE` minted by `init`; delete each `uid == 0` test as its capability lands.

### Tier 1 — Correctness and performance foundations

**F-1.1 — `%gs`-based per-CPU data.** **[I-6]**. `swapgs` at every ring transition;
`%gs:0` holds CPU id, current TCB pointer, and the per-CPU IRQ-nesting state introduced by
**[C-3]**'s fix. Removes an MMIO read from the hottest kernel path. *(The MMIO read is
already gone — `this_cpu()` reads `TR` instead. What is left of this item is the per-CPU
block itself, whose remaining justification is **[C-3]**'s IRQ-nesting state, not syscall
cost. Sequence it behind 1.1 accordingly.)*

**F-1.2 — Multi-slot endpoint queues + a proper `Call`/`ReplyWait` primitive.** **W-4**,
**[I-5]**. A bounded FIFO per endpoint plus a one-shot reply capability (seL4's reply
object) that is minted at call time and consumed on reply — this makes reply forgery
structurally impossible rather than merely gated, and enables priority inheritance later.

**F-1.3 — 64-bit-clean heap arithmetic.** **[I-2]**, before the address space widens.

**F-1.4 — Fail-closed user copies.** **[C-4]**.

### Tier 2 — Toward a complete OS

**F-2.1 — Virtual memory objects and shared memory.** `CAP_FRAME` today names a fixed
window. Introduce frame capabilities backed by real pool frames, `SYS_MAP_FRAME(frame_cap,
vaddr, rights)`, and unmapping — giving genuine shared memory between mutually distrusting
tasks with rights that can be reduced on delegation. Prerequisite for a windowing system,
a network stack with zero-copy buffers, and `mmap`.

**F-2.2 — A real VFS layer above `fs_server`.** Mount points, multiple filesystem servers,
and a device-file namespace. Each server holds only the object-store capabilities for its
own subtree — the capability model makes per-mount isolation natural in a way a monolithic
VFS cannot.

**F-2.3 — Network stack as a ring-3 server.** A user-mode TCP/IP server holding a
`CAP_IO_DEVICE` for one NIC, with per-application socket capabilities. Security impact is
large and positive: a network stack compromise is contained to one address space with no
kernel authority. This is the highest-visibility demonstration of the architecture's value.

**F-2.4 — Process/session model.** Real `fork`/`exec` semantics, process groups, job
control, and a `/proc`-equivalent served over IPC. Needed for the shell to become a usable
OS interface. *Partly addressed 2026-08-28: `SYS_FORK` gives a child a copy-on-write clone
of its parent's address space (`SECURITY.md` **S39**, **S40**; `make smoke-fork`). The child
inherits its parent's capabilities as DERIVED copies (**S41**, 2026-08-28), so revocation
still reaches them; process groups, job control and `/proc` are untouched — see
`docs/ROADMAP.md` §2.3.*

**F-2.5 — Dynamic linking and a shared libc.** Currently every binary statically links
newlib (~450 KiB each, 11 in `/bin`). A shared object loader with capability-mediated
mapping cuts the store requirement by an order of magnitude.

**F-2.6 — Time, timers, and a monotonic clock.** `SYS_CLOCK_GETTIME`, per-task timers as
notification sources, and a tickless design. Prerequisite for anything real-time and for
sane timeouts in IPC.

### Tier 3 — Assurance and observability

**F-3.1 — Extend Kani proofs from revocation to the full capability algebra.** Prove:
mint never widens rights (`effective = new & src.rights`); grant preserves the derivation
tree; lookup refuses type-mismatched capabilities; and — once **F-0.1** lands — that IPC
authority implies a held endpoint capability naming that endpoint. The TLA+ specs
(`docs/cap_algebra.tla`, `docs/paging_isolation.tla`) should be model-checked in CI, not
merely committed.

**F-3.2 — A kernel debug/observability capability.** `CAP_DEBUG` gating task introspection,
a ring buffer of capability operations, and a `SYS_CAP_ENUMERATE` for a userspace
`capview` tool. Replaces the ad-hoc root-introspection in `h_task_info` (**[I-4]**) with an
explicit, revocable authority — and makes the capability graph *visible*, which is
essential for auditing a system whose security argument rests on that graph.

**F-3.3 — Deterministic replay harness.** Record syscall/IPC traces under QEMU and replay
them; makes SMP race reproduction tractable and turns intermittent CI failures into
artifacts.

**F-3.4 — Virtualisation hooks (VT-x).** A `CAP_VCPU` object and an EPT-backed guest
address space, so Horus can host a guest OS as a ring-3 VMM holding only the capabilities
for its guest's resources. Strategically valuable: it is the credible bridge from "research
microkernel" to "runs real workloads" without compromising the model.

**F-3.5 — KASLR** (noted absent in `LIMITATIONS.md`), plus CFI on indirect calls in the C
kernel and a `-Z sanitizer` pass over the Rust core in CI.

### Tier 4 — Repository / SSDLC

Items **P0–P2** of §7.5, plus:

**F-4.1 — A security-invariant registry.** A machine-readable `invariants.yaml` naming each
claimed property, the code enforcing it, and the test or proof witnessing it. CI fails if
an invariant has no witness. This directly attacks the failure mode that produced
**[C-1]**: a documented property with no test binding it to the code.

**F-4.2 — Nightly long-running fuzz + Kani in a scheduled workflow**, with findings filed
automatically as issues.

**F-4.3 — Publish the threat model** as a first-class document: assets, adversaries
(unprivileged ring-3 program, malicious server, physical DMA attacker, hostile CI
contributor), trust boundaries, and which are in and out of scope. `SECURITY.md` gestures
at this; it should be explicit and versioned.

---

## 9. Refactoring & Long-term Improvement Recommendations

**R-1 — Make the capability the *only* authority.** Every `uid == 0` check, every
`SC_NONE` dispatch entry whose handler does bespoke authorisation, and every fixed-slot
convention (slot 3 means "IPC", slot 7 means "block device") is a place where authority is
expressed outside the capability graph. Converge on: authority is held, named, and checked
in exactly one way. The fixed-slot convention in particular is a latent bug factory — it is
what made **[C-1]** possible, because "slot 3" ended up meaning two different things.

**R-2 — Separate mechanism from policy in the syscall layer.** `syscall.c` currently mixes
dispatch, authorisation, and implementation. The dispatch table is a good start; complete it
so that *no* handler performs its own authorisation. Where the check is argument-dependent
(kill, grant, signal), express it as a declarative predicate in the table rather than
handler code, so the authorisation surface can be read in one place and diffed.

**R-3 — Move the remaining parsing surfaces into Rust.** The ELF loader migration was
correct and productive. The same argument applies to: the multiboot2 tag walker
(`multiboot.S` / `mb_scan_boot_info`), the ACPI MADT parser (`acpi.c`), the on-disk
superblock/inode parser (`storage.c`), and the TPM response parser (`tpm.c`). All four
parse attacker- or firmware-controlled bytes in C.

**R-4 — Introduce an internal `kresult_t` and stop overloading `int`.** Return values
currently mix `0/-1`, `SYS_ERR_*`, `-2` retry sentinels, and raw lengths, cast through
`uint32_t` into `rax`. Several bugs in the project's own history trace to this
(the `(uint32_t)-1` vs `(uint64_t)-1` sbrk bug is documented in the source). A single
result type with explicit conversion at the ABI boundary removes a whole defect class.

**R-5 — Establish a written architectural invariant list, and gate on it.** Pair with
**F-4.1**. Each invariant gets an ID; each security-relevant PR must cite the IDs it
touches; CI checks every ID has a live witness.

**R-6 — Governance: solve the reviewer problem explicitly.** This is the highest-leverage
long-term change and it is not technical. Options, in descending preference: recruit a
co-maintainer with kernel/capability background; establish a rotating external review panel
for security-critical paths; or formally scope the assurance claim to "single-maintainer,
automated-verification-only" and say so prominently. The current position — strong
assurance language with zero independent review — is the one option that should be
abandoned.

**R-7 — Version and release.** Tag, release, attest, publish PCRs. An OS nobody can verify
they received correctly is not deployable, however good its kernel.

---

## 10. End-to-End Assurance Statement

The build is reproducible, the boot chain is measured into a TPM and sealed against those
measurements, boot modules are verified against a manifest embedded in the signed kernel
image, and CI proves adversarially that tampering is both rejected and detected. That chain
— source to running system — is genuinely strong and better than most production systems.

Above it, the runtime authority model has a hole: **the capability system enforces type
authority but not instance authority for IPC**, so any ring-3 task can impersonate or
intercept any ring-3 server. Every isolation property claimed above the IPC layer is
therefore currently unenforced, including the filesystem permission model that the
kernel-attested `SYS_IPC_SENDER` identity was carefully built to support.

Behind both sits a process that verifies functionality thoroughly and authority weakly:
the security-specific test suite is not merge-gating, and no human is required to read any
change. **[C-1]** is the demonstration of what that combination produces — a defect that is
invisible to every automated gate, obvious to a reviewer, and load-bearing for the entire
security argument.

**Fix the object model, gate the security tests, get a second pair of eyes on the
capability paths.** With those three, Horus's assurance claims become defensible, and the
foundation is genuinely strong enough to build a complete operating system on.

---

*Audit conducted 2026-07-27 against commit `a4c7b1a`. Findings **[C-1]** and **[C-2]** were
fixed in the accompanying change, and **[I-1]** and **[I-7]** the same day; **[C-3]** was
attempted, reverted, and reclassified — see **[C-3.1]**, §3. All other findings were open at
the time of writing and are tracked in `docs/ROADMAP.md`.*

> *Correction, 2026-08-15.* This line previously read "Findings [C-3] fixed in the accompanying
> change; all other findings are open", which is the inverse of what §1.1 and §3 of this same
> document record — [C-3] was the one that did **not** land, and [C-1]/[C-2] were the ones that
> did. A reader arriving at the summary got the opposite of the truth. The findings themselves
> are preserved verbatim as the record of what was found on 2026-07-27; only this summary
> sentence is corrected.
>
> **This document's *status* has been superseded.** An independent external audit on
> 2026-08-15 re-verified every finding here against the tree. Since 2026-07-27, **[C-3]** and
> **[C-3.1]** were fixed (2026-08-11, per-CPU IRQ depth and restored `RFLAGS.IF`), **[C-4]**
> and **[I-2]** were fixed (2026-08-13), **[I-5]** was closed by endpoint queues, the one-shot
> `CAP_REPLY` and `SYS_IPC_RECV_BLOCK`, **[I-6]** was closed differently than proposed, and
> **[I-1]** was completed only on 2026-08-15 — its last gate, the user database in
> `src/kernel/kusers.c`, survived nineteen days of four documents asserting it was closed
> (**[H-1]**). Still open: **[C-5]**, **[C-6]**, **[I-3]**, **[I-9]**, **[I-10]**, **[I-11]**,
> **[G-8]**, and the `tasks[]` remainder of **[I-7]**. The live status of every finding is in
> [`LIMITATIONS.md`](LIMITATIONS.md), not here.

---

## Appendix A — the predecessor audit (2026-07)

The July 2026 audit, findings **A1–A4** and **P1–P5**, is reproduced in full below. It used a
different finding vocabulary from the one this document and the rest of the tree use, which is
why its IDs never appear elsewhere: it is a historical record, superseded by the audit above,
and its remediations are re-verified there.

It was a separate file until 2026-08-21. Two audit documents meant two places a reader had to
check to learn whether a finding was still open, and only one of them was maintained.

This document records the findings of a professional-grade audit of the Horus
microkernel **and its development ecosystem**, conducted July 2026 against the
`main` branch. It is the canonical, stable reference for the findings; the
remediation plan lives in [ROADMAP.md](ROADMAP.md) (Track 0–2), and the
subsystem-level consequences are folded into [LIMITATIONS.md](LIMITATIONS.md) and
[../SECURITY.md](../SECURITY.md).

The audit's headline conclusion: **the kernel code is disciplined research-grade,
but the engineering *process* that produces it is not yet commensurate with the
high-assurance goals the kernel itself pursues.** For a system whose entire value
proposition is *verifiable* isolation, the runtime assurance claims cannot be
stronger than the pipeline that builds and ships them — and several controls that
the repository *documents* (CODEOWNERS review, required CI) are not actually
*enforced*.

Findings are rated by their impact **against a high-assurance production bar**, not
against the "research kernel" bar the project currently sets for itself. Several
kernel findings **fail safe** (they remove authority or availability rather than
grant it); this is called out explicitly and is why they are not rated Critical.

---

### Summary table

| ID | Area | Finding | Severity | Fails safe? |
|---|---|---|---|---|
| **A1** | Capability engine | Revocation matched an object/badge/serial *equivalence set*, not a derivation subtree — it revoked ancestors, siblings, and same-`object` peers. **Fixed** (`revoke_subtree`: descendant-only closure). | High | Yes |
| **A2** | Capability engine | `SYS_CAP_GRANT` did a raw, unlocked cspace store — racing a concurrent SMP revoke, not counted against `caps_in_use`, and leaving a malformed lineage badge. **Fixed** (`cap_grant_into`). The originally-reported "reserved-slot floor" sub-point was withdrawn as incorrect. | Medium | Partly |
| **A3** | Capability engine | Lineage-generation table is a lossy 4096-slot hash, originally keyed by `object` and dormant (every cap created with generation 0, treated as always-valid). **Activated & re-keyed** (finding 3.3): now keyed by the unique `serial` with strict-equality checking and every creation site stamping the current generation, so the use-after-revoke backstop is a genuine second mechanism alongside structural revocation. Residual: the 4096-slot hash can still collide (availability-only, fail-safe) — exact per-serial storage is Track 1. | Low | Yes |
| **A4** | Boot / supply chain | GRUB boot-module images became root-owned `/bin` executables with no integrity check. **Fixed** — the kernel embeds a SHA-256 manifest of the modules it was built to ship and refuses any module that does not match exactly (`boot_module_verify_all`), plus a destination allowlist. Residual: the manifest's trust rests on the kernel image, i.e. on P4. | Medium | No |
| **P1** | Governance | `main` had **no branch protection**: CODEOWNERS and all CI jobs advisory only. **Mostly fixed** — required hard-gate checks + enforce-admins + no force-push/deletion now on; required review deferred (single maintainer, P2). | **Critical** | No |
| **P2** | Governance | Single-maintainer self-merge; no independent review on capability/crypto/paging changes | High | No |
| **P3** | CI / supply chain | Dependabot **security** updates disabled; no CodeQL/code-scanning; SAST/fuzz/Kani non-gating. **Mostly fixed** — Dependabot alerts + security updates + cargo ecosystem on, CodeQL workflow added; deterministic Kani/fuzz gate still to do. | Medium | n/a |
| **P4** | Supply chain | Build toolchain unpinned; no provenance/signing — reproducibility ≠ attestation | Medium | n/a |
| **P5** | Hygiene | ~55 stale branches, no commit signing, fragmented identities. **Partially fixed** — auto-delete-on-merge enabled; pruning the existing merged branches + commit signing remain. | Low | n/a |

---

### Kernel findings

#### A1 — Revocation was object/badge-scoped, not derivation-tree-scoped  *(High, fails safe — FIXED)*

**Where:** `rust/src/capability.rs` (the old `lineage_matches()` / `revoke_matching_in()`);
reached from `rust_cap_revoke` / `rust_cap_revoke_global`, driven by `cap_revoke` in
`src/kernel/capability.c`.

The old matcher nulled every capability matching *T*'s `serial`, *T*'s `badge`,
**or** *T*'s `object`:

```rust
fn lineage_matches(c: &Capability, ts: u32, tb: u32, to: u64) -> bool {   // OLD
    (ts != 0 && (c.serial == ts || c.badge == ts))
        || (tb != 0 && (c.serial == tb || c.badge == tb))   // tb = target's badge = its PARENT's serial
        || (to != 0 && c.object == to)                      // ANY cap to the same object, any lineage
}
```

Because a derived capability records its **parent's serial in its `badge`**, the
`badge` clause matched the parent (upward) and every sibling (sideways), and the
`object` clause matched **any** capability to the same object regardless of lineage.
So a supervisor that granted a revocable capability, then had the child revoke its
copy, would find its **own** capability (and same-object peers) nulled too. seL4-style
revocation deletes the *descendant subtree only*; Horus revoked an equivalence class.

**Fix (landed).** `revoke_matching_in` and `lineage_matches` were replaced by
`revoke_subtree`, which computes the exact **derivation subtree** of the target:
seed a bounded worklist with the target's `serial`, then repeatedly add any cap
whose `badge` is an already-revoked serial (child of a revoked node) until the set
is closed, and null exactly those. Ancestors, siblings, and independent
same-`object` capabilities are left intact. This relies on the A2 fix, which made
every derived cap record its immediate parent's serial in `badge`, so the
`serial → badge` links form a well-formed forest.

Completeness is preserved as a fail-safe: if a subtree ever exceeds the worklist
(`MAX_REVOKE_LINEAGE = 256` — hundreds of derived copies of one lineage, which does
not occur in practice), the null pass *also* nulls every cap sharing the target's
`object`. Because mint/transfer/grant all preserve `object`, that set is a complete
superset of the descendant set, so the fallback can only over-approximate — a
descendant can never survive. New regression tests cover: revoking a child leaves
the parent and siblings intact; revoking one of two independent same-object caps
leaves the other usable; and the overflow fallback revokes a whole oversized
subtree. A full CDT with explicit parent pointers remains a possible future
refinement, but the serial/badge forest already gives exact descendant-only
semantics.

#### A2 — `SYS_CAP_GRANT` did a raw, unlocked cspace store  *(Medium — FIXED)*

**Where:** `h_cap_grant` in `src/kernel/syscall.c` (the old code).

```c
capability_t granted = *src;                 /* old code */
uint32_t fresh = cap_alloc_fresh_serial();
granted.serial = fresh;
spin_lock(&cap_lock);
tasks[target].cspace[dest_slot] = granted;   /* raw store */
spin_unlock(&cap_lock);
```

The project's own `cap_install_endpoint` comment states the invariant that *every*
cap write must observe the locked discipline "rather than a raw, unsynchronised
cspace store." The old grant violated it in two ways that were **real**:

1. **Lookup outside the lock, then store** — the source was looked up unlocked and
   copied, so under SMP a concurrent `rust_cap_revoke_global` could null the source
   between the read and the write, materialising a copy of a just-revoked cap.
2. **No `caps_in_use` accounting** — the granted cap was invisible to the target's
   `MAX_CAPS_PER_TASK` ceiling, and a later revocation's saturating decrement then
   desynced the counter.

It also left a **malformed lineage badge**: it copied the source's `badge`
(the *grandparent*) instead of recording the grantor's cap as the parent, so the
derivation tree the A1 fix relies on was not well-formed.

**Withdrawn sub-point (correction).** The audit originally also claimed grant
should enforce a `dest_slot >= KERNEL_RESERVED_CAPS` floor. That is **wrong**: a
grantor already fully dominates the target (it holds the target's `CAP_TCB`), and
endowing a child's low slots — e.g. `init` granting the IPC gate into a server's
slot 3 (`init.c`) — is exactly what grant is for. The reserved-slot floor protects
a task's *own* primordial slots against its own mint/transfer; it does not apply to
a supervisor endowing a subordinate. Enforcing it would have broken boot.

**Fix (landed).** Grant now routes through `cap_grant_into` (C) →
`rust_cap_grant_into` (safe Rust): the source lookup and destination store happen
together under `cap_lock` (SMP-safe against a concurrent revoke), the write is
counted against the target's `caps_in_use` ceiling, rights are masked to
`new_rights & src.rights` (the plumbing for rights *reduction*; the 3-arg
`SYS_CAP_GRANT` ABI still passes full rights for compatibility), and the grantee
records the grantor's cap as its parent (`badge = src.serial`) so the derivation
tree is well-formed. New Rust unit tests cover rights masking, parent recording,
fail-closed inputs, and revoke-sweeps-grantee. Note the "copies full rights incl.
`REVOKE`" concern is neutralised for real once A1's descendant-only revocation lands
(a child's `REVOKE` can then only reach its own subtree, never its grantor).

#### A3 — Lineage-generation table is a lossy hash  *(Low, fails safe — activated & re-keyed by finding 3.3)*

**Where:** `rust/src/capability.rs` — `LINEAGE_SLOTS = 4096`, `lineage_idx()`
(splitmix64).

**As found (July 2026):** the generation table was a 4096-entry hash keyed by
`object`, and — critically — **dormant**: no code path assigned a capability a
non-zero `generation` (`cap_install_*` and the root cnode set it to 0, mint/grant
copied the source's 0), and `lineage_check(obj, gen)` returned `true` whenever
`gen == 0`. So the generation check never rejected a real capability, structural
revocation was the sole enforcement, and the object-keyed collision could not
invalidate anything.

**Resolution (finding 3.3):** the backstop was **activated and correctly keyed**.
The table is now keyed by a capability's globally-unique **`serial`** (not
`object`), `lineage_check` is **strict equality** with no gen-0 escape hatch, and
every C creation site stamps `generation = rust_lineage_current(serial)`. A revoke
bumps exactly its serial's cell (and its subtree's), so a stale snapshot of a
revoked capability now fails the check even if its bit pattern survived — a genuine,
independent second mechanism alongside the structural nulling. Proved over the whole
`u32` space by two Kani harnesses (`revoke_invalidates_recorded_generation`,
`revoke_does_not_touch_a_distinct_lineage_cell`).

**Residual (Track 1):** the 4096-slot table is still a lossy hash, so distinct
serials can collide into one cell and a bump can spuriously invalidate a colliding
serial's live caps at next use — availability-only, fails safe. The fix is exact
per-serial storage (a collision-free map). Until then, no correctness action is
required.

#### A4 — Boot modules became root-owned executables with no integrity check  *(Medium — FIXED)*

**Where:** module transport `SYS_BOOT_MODULE_INFO/READ`, provisioned by
`fs_server` (`provision_boot_modules`).

Coreutils binaries and man pages ship as multiboot2 GRUB modules and are written
into the encrypted store as **root-owned `0755` executables**, then run by the
shell. Trust rested entirely on boot-chain provenance — there was **no per-module
hash or signature check**, and the reproducible-build hash covers the *embedded*
binaries (`init`, `shell`, `fs_server`, …) but **not** the modules. Anyone able to
alter the ISO / GRUB config could inject an arbitrary root-owned binary into `/bin`.

**Fix (landed).** Two complementary halves:

1. **Content — an embedded SHA-256 manifest.** `tools/gen_module_manifest.sh`
   generates `src/kernel/boot_module_manifest.h` at build time from the same
   `BOOT_MODULES` list the ISO is assembled from, so the kernel embeds the digest
   of exactly the payloads it was built to carry. At boot — after the multiboot tag
   walk, before userspace exists — `boot_module_verify_all()` hashes each module in
   place (through `PHYS_KVA`, the same window the read syscall uses) and requires an
   exact **(destination path, size, SHA-256)** match. Unmatched modules are refused
   at the syscall choke point: `SYS_BOOT_MODULE_INFO` reports an empty slot (the
   provisioning loop skips it) and `SYS_BOOT_MODULE_READ` returns `SYS_ERR_PERM`, so
   the payload can never reach `/bin`.
2. **Destination — an allowlist.** `module_dest_ok` (`fs_server.c`) restricts a
   module to `/bin` or `/usr/share/man`, refusing absolute paths and `.`/`..`
   components.

No key is used, by design: the manifest ships *inside* the reproducible kernel
image, so the image is the root of trust and an embedded key would be equally
readable. A module-free build gets an **empty** manifest and refuses every module
it is handed — fail closed, and correct, since such a kernel attested to none.

**Gated by `make smoke-modules-tamper`** (CI): same kernel, one module payload
corrupted by a single byte flip (size unchanged, so only the hash differs); the
kernel must refuse exactly that module and still boot. Falsification-tested — with
verification neutered the tampered module provisions and the gate goes red.

**Residual.** The manifest is only as trustworthy as the kernel image carrying it,
so full closure depends on **P4** (pinned toolchain, SLSA provenance, signed
artifacts) and Track 2.2 (measured boot). Signing the image would also allow the
decoupled variant: an embedded ed25519 public key plus a separately-shipped signed
manifest — which needs ed25519 added to the Rust core.

#### Verified strengths (not findings)

- `user_copy` requires `PAGE_PRESENT|PAGE_USER` on the walked user CR3 and reaches
  frames through the higher-half physical alias (`PHYS_KVA`) — so a user pointer
  aimed at the kernel half fails closed, and the copy is immune to SMAP. (Note: the
  prose in ARCHITECTURE/crypto describing "clac/stac bracketing" is stale — the
  implementation uses the `PHYS_KVA` alias instead, which is at least as strong.)
- `rust/src/memory.rs` refcount trust boundary (registered table, exact
  pointer/length re-check) is a model zero-trust FFI.
- CSPRNG fail-closed seeding; the fake "AES" was removed for a KAT-validated
  ChaCha20+HMAC AEAD; stack canary re-seeded from the CSPRNG post-`entropy_init`.

---

### Process, governance & supply-chain findings

#### P1 — `main` has no branch protection  *(Critical)*

`GET /repos/pharanyx-labs/Horus/branches/main/protection` → **404 "Branch not
protected."** Consequences:

- CODEOWNERS (which covers `capability.rs`, `paging.c`, crypto, *and the CI
  workflows themselves*) is **not enforced** — its own header says "enforce via
  branch protection," and that enforcement does not exist.
- None of the ~30 CI jobs are **required status checks**: a red pipeline can merge.
- No linear-history / no-force-push / signed-commit requirement — history is
  rewritable.

For a kernel selling *verifiability*, this severs the chain between "the tests and
proofs pass" and "what is on `main` / in the artifact." **This is the single
highest-leverage fix.**

**Fix (Track 0):** a `main` ruleset requiring a PR before merge; the hard-gate
checks (`rust`, `kernel`, `smoke`, `reproducible`) as required; CODEOWNERS review;
dismiss-stale-approvals; linear history; block force-push; include administrators.

#### P2 — Single-maintainer self-merge  *(High for high-assurance)*

Every pull request was opened and merged by the same identity (across
`horus@pharanyx.co.uk`, `horus@packetsync.org`, `horus@pharanyx.co.uk`,
`pharanyx-labs`; Dependabot aside). CODEOWNERS `@pharanyx-labs` reviews
`@pharanyx-labs`. Acceptable for a research repo; **disqualifying for
high-assurance** — no independent review of capability/crypto/paging, bus factor 1.
**Fix (Track 0):** ≥1 independent reviewer with enforced CODEOWNERS review on the
security-critical paths; until staffed, record this as an accepted, documented risk
rather than an implied guarantee.

#### P3 — Native scanning gaps  *(Medium)*

- `dependabot_security_updates: disabled`; vulnerability alerts off. (Version
  updates for Actions *are* configured.)
- **No CodeQL / code scanning** ("no analysis found"). The CI's semgrep / trivy /
  cppcheck / flawfinder run **advisory** (`continue-on-error`) and are not uploaded
  as SARIF, so findings never gate a merge or surface in the Security tab.
- The `fuzz` and `kani` jobs are also non-gating, so a regression that breaks a
  proven invariant (e.g. `mint_never_escalates_rights`) can merge green.
- *Positive:* secret scanning **and** push protection are enabled.

**Fix (Track 0):** enable Dependabot security updates + alerts; add a CodeQL
workflow (C/C++ + Rust) uploading SARIF; promote a fast, deterministic Kani/fuzz
subset to a required check.

#### P4 — Reproducibility ≠ provenance  *(Medium)*

`make reproducible-build` proves *determinism on one runner image*, but CI runs on
`ubuntu-latest` and installs `build-essential` / `rustup` / `semgrep` / `cargo
install` **unpinned**. There is no hermetic build (Nix / pinned container digest),
no toolchain pin, no SLSA provenance, and no artifact signing. The reproducibility
guarantee is therefore "deterministic today, on GitHub's current image" and drifts
silently on a toolchain bump. **Fix (Track 0/2):** pin the toolchain
(`rust-toolchain.toml` + a digest-pinned container or Nix flake), record it in the
build, and emit SLSA provenance + a cosign-signed `kernel.elf` / `boot.iso`.

#### P5 — Hygiene  *(Low)*

~50 stale remote feature branches; `delete_branch_on_merge: false`; no commit
signing (`web_commit_signoff_required: false`); four committer identities for one
maintainer. **Fix (Track 0):** enable auto-delete + prune; require signed commits;
consolidate identities.

#### Positives on process

SHA-pinned GitHub Actions with version comments (Dependabot-maintained);
least-privilege `GITHUB_TOKEN` (`contents: read` default); concurrency
cancellation; an isolated Pages workflow keeping its wider permissions off the
merge-gate workflow; a reproducible-build verification job; Trivy installed via a
pinned release + checksum (not `curl|sh`); gitleaks full-history scan; CycloneDX
SBOM generation; thorough `.gitignore` secret rules; secret push protection.

---

### End-to-end assurance statement

**As first written (July 2026).** A reviewer who trusted a Horus `boot.iso` was
implicitly trusting (a) an unenforced merge gate (P1), (b) a single unaudited
maintainer (P2), (c) an unpinned toolchain (P4), and (d) unsigned boot modules
(A4) — none of which the kernel's runtime guarantees can compensate for.

**Status after the first remediation pass.** Two of those four have moved:

- **(a) is closed.** `main` is branch-protected: the four hard-gate checks are
  *required*, the rule is enforced for administrators, and force-push and branch
  deletion are blocked. A red pipeline can no longer merge, and history cannot be
  rewritten. CodeQL and Dependabot alerts/security updates are on (P3).
- **(d) is half-closed.** Boot modules can no longer land *anywhere*: the
  destination is constrained to `/bin` and `/usr/share/man`, with traversal
  refused (A4, destination half). Module **content** is still unverified — the
  remaining, larger half.
- **(b) is unchanged and is now the weakest link.** Every change is still authored
  and merged by one person; required review is deliberately off because with a
  single maintainer it would deadlock all merges. This is an accepted, documented
  risk, not a solved one.
- **(c) is unchanged.** The toolchain is still unpinned and artifacts unsigned, so
  "reproducible" remains "deterministic on one runner image" rather than
  attestable across time.

The capability algebra now matches the semantics the design advertises:
revocation is descendant-only (A1) with machine-checked Kani proofs that it hits
exactly the target's subtree, and delegation goes through the locked, accounted,
rights-masked path (A2). The remaining assurance gap is therefore **governance and
provenance (P2, P4) plus module-content verification (A4)** — not the kernel's
security logic. See [ROADMAP.md](ROADMAP.md) Tracks 0.2, 0.4 and 2.1.
