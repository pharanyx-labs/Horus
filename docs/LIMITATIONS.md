# Horus — Current Limitations

An honest account of what Horus does not do, does not enforce, or does badly, so that nobody
draws an incorrect conclusion about its readiness. This document is deliberately unflattering.

**Where this document and the code disagree, the code is the source of truth — please open
an issue.**

Findings referenced as **[C-n]** / **[I-n]** are from
[`AUDIT-2026-07-27.md`](AUDIT-2026-07-27.md).

---

## 1. Security properties that are claimed elsewhere but not enforced

### 1.1 IPC is not capability-mediated — **critical** — **[C-1]**

This is the most important entry in this document.

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

### 1.2 Root is an ambient authority parallel to capabilities — **[I-1]**

Nine syscall handlers gate on `tasks[current].uid != 0` rather than on a held capability
(`SYS_DMESG`, the boot-module read surface, and the object-store API).
`SYS_GET_TASK_INFO` additionally promotes uid 0 to full introspection over every task.

The capability graph is therefore *not* a complete description of who can do what. Two
parallel authority systems defeat much of the point of having a capability system, and make
confinement and any future mandatory-access-control story significantly harder.

### 1.3 `SYS_GET_TASK_INFO` discloses another task's instruction pointer — **[I-4]**

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

`FS_EP_REP = 5` is a *shared global* reply endpoint on which every client parks its
`SYS_IPC_CALL`, so concurrent clients overwrite each other's `blocked_waiter`. Correctness
survives today only because `SYS_IPC_REPLY_TO` routes by kernel-recorded sender identity
instead of by that field.

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

### 3.2 `this_cpu()` reads LAPIC MMIO on every call — **[I-6]**

`get_current_task()` calls it, several times per syscall, and each is an uncached MMIO read
costing hundreds of cycles. This is the dominant avoidable cost in the syscall path. The fix
is `%gs`-based per-CPU data.

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

### 5.3 No release provenance — **[I-9]**

The build is verified reproducible and an SBOM is produced, but there are no tags, no
releases, no signed artifacts, and no SLSA provenance. A third party cannot verify that a
`boot.iso` they obtained came from this repository's CI.

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
