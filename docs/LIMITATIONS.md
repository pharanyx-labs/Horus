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

### 1.4 User copies truncate silently — **[I-4] / [C-4]**

`copy_from_user` and `copy_to_user` clamp `n` to `USER_MEM_MAX_COPY` and return success. A
caller requesting more gets a partial copy it believes succeeded, leaving stale kernel-stack
bytes in the tail of the destination. No current caller is known to be exploitable, but this
is a latent kernel-memory disclosure that will bite the first time a larger struct is added.

### 1.5 Broad revocation can be forced by an unprivileged task — **[I-3]**

The descendant-closure worklist in `revoke_subtree` is bounded at 256 entries. On overflow
the sweep safely over-approximates by nulling every capability sharing the root `object` —
which means a task that deliberately constructs a derivation subtree larger than 256 members
can force the fallback and destroy an unrelated task's independent capability to the same
object. Fails safe (no descendant survives) but is a denial-of-service on another task's
authority.

---

## 2. Correctness limitations

### 2.0 Spinlock interrupt state is global, and the bug is load-bearing — **[C-3]**, **[C-3.1]**

`irq_lock_depth` (`src/kernel/scheduler.c`) is a single **global** counter shared by every
CPU, incremented and decremented non-atomically, and `spin_unlock` does an **unconditional**
`sti` when it reaches zero.

Under SMP — the default build — one CPU's release can therefore re-enable interrupts while
another still holds a lock, and racing read-modify-writes lose counts outright. The
unconditional `sti` separately re-enables interrupts inside a caller's own `cli` region,
including `user_copy`'s CR3 window, where a preemption leaves a stale CR3 to restore.

**The complication.** Because that `sti` fires for *any* lock taken while interrupts were
already masked, and boot and early init take many, interrupts are enabled far earlier and
more often than any explicit policy asks for. The `init` → `fs_server` → `console_server` →
shell startup handshake depends on the timer preemption that results.

A correct per-CPU, IF-preserving lock was written on 2026-07-27, passed every local gate, and
**broke the ring-3 startup handshake in CI** (`smoke-modules` timed out waiting for
provisioning; `smoke-coreutils-shell` failed with `ls: spawn fs_server first`). It was
reverted. The kernel's boot-time interrupt enablement is thus an emergent property of a
locking defect rather than a stated design — a latent hazard for the SMP work and for any
future tickless or real-time scheduling.

Fixing it requires making boot interrupt enablement explicit first. Roadmap item 1.1.

### 2.1 64-bit arithmetic is truncated in the heap syscalls — **[I-2]**

`SYS_SBRK` and `SYS_BRK` compute the new break in `uint32_t` while `heap_start` and
`heap_max` are 64-bit. Correct only while every heap lives below 4 GiB. Widening the user
address space — a roadmap goal — will make the bounds check pass on a truncated value.

### 2.2 Endpoints are single-slot mailboxes — **[I-5]**

One in-flight message per endpoint, no queue. `SYS_IPC_SEND`/`RECV` return `-2` and expect
userspace to poll, so contention is a busy-wait. Fair service and priority inheritance cannot
be expressed.

**This now has a witness, and it is a livelock, not a slowdown — [G-8] signature C.**
`CONC_SELFTEST` puts four clients and one server on a single endpoint on one CPU. Under CPU
starvation, **3 boots in 30** never complete: the scheduler's own watchdog shows every task
`RUNNABLE`, nothing blocked, and the timer alive, while the completion times are bimodal —
17 runs finish in 6–8 seconds and 3 have not finished after **600**. The pollers settle into an
interleaving in which a client's send never meets the server's receive, and nothing in the
design breaks the cycle: no queue to park the message in, no blocking handoff to force
progress. Raising the timeout does not help, because the affected boots are not slow.

Treat multi-client contention on one endpoint as **unsafe under CPU pressure**, not merely
inefficient. Roadmap 1.3 is therefore a correctness fix, not a performance one.

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
