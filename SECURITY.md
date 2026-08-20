# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/pharanyx-labs/Horus/security/advisories/new)
on this repository. If that is unavailable to you, email **horus@pharanyx.co.uk**.

Please include: affected component and commit, a description of the security property that
is violated, reproduction steps or a proof-of-concept, and your assessment of impact.

**What to expect.** Acknowledgement within 7 days; an initial assessment within 14 days;
and a fix or a documented decision within 90 days for confirmed issues. Horus is maintained
by a single person as a research project — these are honest targets, not a commercial SLA.

Reporters are credited in the advisory and in `CHANGES.md` unless they prefer otherwise.
There is no bug-bounty programme.

---

## Current security posture — read this first

Horus is a **research microkernel**. It is not production-ready, has not been independently
audited by a third party, and has known unfixed security defects.

> ### The 2026-07 critical finding is fixed
>
> IPC endpoints and notifications used to be addressed by a raw integer index, with the
> `CAP_ENDPOINT.object` field never consulted — so any unprivileged program could intercept
> and forge messages to any userspace server. **Fixed 2026-07-27** ([C-1]/[C-2]): IPC is now
> capability-addressed, clients hold send-only capabilities, and every task has a private
> reply endpoint. The regression suite was falsified against the pre-fix kernel to confirm it
> detects the bug.

Horus remains **research-grade**. It has not been independently audited, no security-critical
change has ever been reviewed by a second person (**[C-5]**). Every security-specific CI job
is classified as merge-gating as of 2026-08-16, taking the ruleset from 22 required contexts
toward 67, then to 71 with the three gates [G-8] added on 2026-08-17, then to 70 when
`smoke-kstack-park` was demoted to advisory that day for [G-9], and back up with
`smoke-exec-reenter` and `smoke-cr3-reclaim`, the gates for [G-9]'s exec component and
[G-10]'s page-table use-after-free, then to **73** with `smoke-spawn-owner`, the [G-11] gate
added on 2026-08-18. The checked-in set is **74** as of 2026-08-19, with `doc-claims` — the gate
that derives every documented count and fails the build when a document disagrees — and the live
ruleset is one context behind it until `--sync-ruleset` is run, which is what "lags a merge"
means in practice. A scheduled
`ruleset-audit` job now verifies the live ruleset against that classification daily, as a
GitHub App with `Administration: read` — the permission a workflow token cannot be granted.
**That App went live on 2026-08-19**: the scheduled run that morning read the ruleset and
reported `live ruleset 19007209 : 73 required contexts, matches`, where the run 24 hours
earlier had failed on the absent secrets. What keeps **[C-6]** open is now only the other half —
reconciliation is manual and lags by one merge — so it narrows again rather than closing. The
remaining open findings — the `tasks[]` table (**[I-7]**) and claims that leak and kernel stacks
that collide on the spawn/reap path under SMP (**[G-9]**, narrowed twice on 2026-08-17: its exec
hand-off and page-table components are fixed and falsified, ~7% of boots still fail) — are in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). **[G-10]** closed on 2026-08-18: the spawn/exec
path's remaining process-wide state is serialised, and the two globals that could wire a child's
stdio from the wrong parent's cspace are parameters, so that inheritance is now unexpressible
rather than unlikely. Closing it surfaced **[G-11]**, also closed that day — the armed program
image was ambient state, and `SYS_SUDO` would elevate whatever was armed to uid 0 whether or not
the authenticating task had staged it (**S21**).

**[G-8]** closed on 2026-08-17 in two parts, and it is the reason **S20** is in the table below. A switch
path published the outgoing task as claimable while the CPU making the switch was still
executing ISR frames on that task's kernel stack; a second CPU took it, resumed it to ring 3,
and its next trap rewrote those frames — memory corruption across a privilege boundary, and the
origin of every bogus resume `%rsp` the finding had recorded. The claim is now held until the
CPU has left the stack, and the property is checked on every interrupt rather than argued for.
Paired over 1600 boots: the pre-fix release site 31/800, the shipped one 0/800, Fisher
p = 6.9 × 10⁻¹⁰.

The finding's **second path** was closed the same day. When a task died and nothing else was
runnable, all three fault/exit fallbacks parked the CPU on `tasks[0].kernel_stack_top` — one
stack, shared by every CPU that took the path. A healthy session never enters it (0 parks in 3
boots), which is why it read as latent; on a workload that kills tasks it is entered 5–8 times
per boot and two CPUs were parked on that one stack 2–3 times per boot. Each CPU now parks on
its own. Closing it also required guarding the per-CPU idle stacks, which had **no guard page
at all** — so S9 below was overclaimed until 2026-08-17, independently of this finding, because
`enter_cpu_idle()` has always parked CPUs there.

Two closed on 2026-08-16. The write-ahead journal's missing `FLUSH CACHE` (**[I-10]**) — so
filesystem crash-atomicity no longer depends on the emulator supplying durability the kernel
never asked for. And the bounded revocation closure (**[I-3]**), whose object-wide overflow
fallback let an unprivileged task force the kernel to destroy an unrelated peer's capability;
the closure is now exact at any subtree size.

Ambient `uid == 0` authority (**[I-1]**) was retired in stages: the syscall and object-store
gates on 2026-07-27, and the last one — the user database, which roadmap 0.2's sweep of
`syscall.c` never reached — on 2026-08-15 (**[H-1]**). See `docs/LIMITATIONS.md` §1.2.

Its appropriate uses are research, education, and development of the capability model
itself.

Every other known limitation is documented openly in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). Horus does not conceal its weaknesses; an
honest account of what is not enforced is more useful than a confident one that is wrong.

---

## Threat model

### Assets

| Asset | Protected by |
|---|---|
| Kernel integrity | Ring separation, SMEP/SMAP, W^X, `CR0.WP`, stack guards and canaries |
| Capability unforgeability | Slot-indexed cspaces; userspace never sees a capability struct |
| Inter-task isolation | Per-task page tables, software-validated user copies, flush-on-switch |
| Data at rest | Per-`(inode, block)` AEAD; keys never leave the kernel |
| Boot chain integrity | SHA-256 module manifest embedded in the kernel; TPM PCR 8/9 measurement |
| Volume key | Sealed under `PolicyPCR(8,9)` — a tampered boot cannot unseal it |
| User identity | Established only by `SYS_AUTH`; servers read it via `SYS_IPC_SENDER`, never from the client |

### Adversaries considered

**A1 — Unprivileged ring-3 program.** Runs arbitrary code with a normal cspace. Wants kernel
compromise, another task's memory, another user's files, or privilege escalation.
*Status: defended for memory isolation, syscall authorisation, and — since 2026-07-27 — IPC
isolation.* A task can reach a service only through a delegated capability naming that
service's endpoint, and a client capability confers send only. Not defended against denial of
service (no CPU or kernel-memory quotas). **Kernel-log forgery and eviction were open until
2026-08-20** (**[H-2]**): `SYS_WRITE` fd 1 took no capability and appended unconditionally to
the 16 KiB `klog` that `SYS_DMESG` — which *does* require `CAP_KERNEL_LOG` — reads back, so any
task could forge lines indistinguishable from kernel diagnostics and flood the ring to evict
genuine ones. The append now requires `CAP_KERNEL_LOG` with the WRITE right (S23); the console
write it rides on stays ungated, because writing to a terminal is not the authority in
question. See `docs/LIMITATIONS.md` §1.6.

**Memory isolation was broken under SMP until 2026-08-17 (`[G-10]`), and the honest reading is
that this row was overclaimed.** `create_user_pagedir()` recycled a task slot's page tables
while another CPU still had them loaded in CR3 — a CPU parked in the idle loop never reloads
CR3, and `SYS_KILL` marks a task dead while it is still executing in ring 3 on another core,
after which a spawn may take its slot. The freed frames went back to the physical pool and were
handed out as ordinary pages to other tasks while the first core was still translating through
them, which is a **cross-address-space read and write primitive available to any ring-3 task
that can get itself killed while running** — no capability required. It is fixed (the reclaim
now refuses to free an address space any CPU holds) and falsified with
`CR3_RECLAIM_UNGUARDED=1` at 20 free-in-use boots in 20; witness `make smoke-cr3-reclaim`.
Recorded here rather than only in `LIMITATIONS.md` because it defeated the asset in the first
row of the table above, and a threat model that quietly omits the one time it failed is not a
threat model.

**A1b — A ring-3 task holding a privileged *identity* but no capabilities.** A task at uid 0
with an empty cspace. *Defended since 2026-08-15.* This adversary had no row here until
**[H-1]** was found, which is why the finding survived nineteen days of documents asserting it
was closed: A1 is defined as an *unprivileged* ring-3 program, and the residual authority
accrued to a privileged-identity, unprivileged-cspace task that no adversary described.
`current_user_is_admin()` (`src/kernel/kusers.c`) now tests possession of `CAP_USER` and
nothing else. Witnessed twice: `smoke-captest` runs as uid 0 holding no `CAP_USER` and is
refused `useradd`/`userdel`/`passwd`-of-another; `smoke-session` drives the real shell and
asserts root may add a user while a standard user is refused.

**A1c — A ring-3 task that can stage a program image, against a task that can authenticate.**
*Defended since 2026-08-18* (**[G-11]**, **S21**). Neither task is privileged in A1's sense and
neither confuses a rights check: the attacker arms an image it is perfectly entitled to arm, and
the victim authenticates with its own correct password. The authority came from the *pairing* —
`SYS_SUDO` consumed whatever image happened to be armed, in a different syscall from the arm, so
the deputy elevated the attacker's program to uid 0 on the victim's credential. Recorded as its
own adversary for the reason A1b was: a defect that no described adversary could reach is a
defect nobody goes looking for. The armed image now carries the identity of the task that armed
it, and a consume by any other task is refused and audited.

**A2 — Compromised userspace server.** `fs_server` or `console_server` under attacker
control. Confined to its own address space and its delegated capabilities; cannot reach
kernel memory or capabilities it was never granted. A compromised `fs_server` does control
all filesystem policy, and a compromised `console_server` sees all terminal traffic — both
are in the TCB by construction.

**A3 — Offline storage attacker.** Has the disk image but not a measured-good boot.
*Defended:* AEAD encryption with a TPM-sealed KEK; rollback detection via a hierarchical
MAC.

**A4 — Boot-chain tamperer.** Modifies the kernel image or a boot module.
*Defended:* module hashes are verified against a manifest inside the kernel image, and both
are measured into the TPM; changed measurements leave the volume sealed. Verified
adversarially in CI.

**A4b — Concurrent task exploiting kernel locking under SMP.** SMP is the default build, and
the spinlock's interrupt-nesting counter used to be a single global shared across CPUs
(**[C-3]**), so one CPU's lock release could re-enable interrupts while another still held a
lock — admitting a timer tick inside a critical section, the reentrancy the `cli`/`sti`
discipline exists to prevent. `spin_unlock` also issued an unconditional `sti`, which imposed
`IF=1` on callers that had deliberately masked interrupts and made boot-time interrupt
enablement a consequence of the locking bug (**[C-3.1]**).
*Defended since 2026-08-11.* Both the nesting depth and the caller's saved `RFLAGS.IF` are
per-CPU (`irq_depth_pc[]` / `irq_saved_if_pc[]`, `src/kernel/scheduler.c`), and the outermost
release **restores** the caller's own `IF` rather than asserting one. An equivalent patch was
written on 2026-07-27 and reverted because the ring-3 startup handshake depended on the
accidental `sti`; what made the August attempt safe is `preempt_on_tick`'s ring-0 guard, which
means a ring-0 tick is never a switch point. `IRQ_LEGACY_GLOBAL_LOCK=1` rebuilds the defect
exactly, and `make smoke-irq-policy` gates interrupt state at five named boot milestones, so
the fix was measured rather than asserted. See `docs/LIMITATIONS.md` §2.0 and
`docs/ROADMAP.md` 1.1.

**A5 — Local side-channel attacker.** Times another task's execution.
*Partially defended:* microarchitectural flush on task switch, SMT siblings parked,
`CR4.TSD` denying ring-3 `RDTSC`. Not defended against a concurrent sibling when SMT parking
is disabled, or against shared L2/L3 channels.

**A6 — Malicious contributor / build tamperer.** Attempts to introduce a backdoor via a pull
request or the CI pipeline.
*Partially defended:* signed commits, protected branch with no bypass actors, SHA-pinned
actions, least-privilege `GITHUB_TOKEN`, reproducible builds verified in CI, secret scanning
with push protection.
*Not defended:* **merges require no reviewer approval.** See
[Process security](#process-security).

### Explicitly out of scope

- **Physical attacks:** cold boot, bus probing, DMA from a malicious PCI device (there is no
  IOMMU support).
- **Firmware and hypervisor:** UEFI/BIOS and any underlying VMM are trusted.
- **Speculative-execution attacks** beyond the flush-on-switch and SMT-parking mitigations
  described above.
- **Denial of service by a local task.** There is no CPU or kernel-memory quota; a task can
  spin, allocate until the pool is exhausted, or force a broad capability revocation (see
  `docs/LIMITATIONS.md`).
- **Cryptographic primitives themselves.** Horus implements ChaCha20, SHA-256, BLAKE2b,
  Argon2, and an AEAD in `no_std` Rust. They are unaudited and not constant-time-verified.
  Treat them as research code.

---

## Security properties Horus attempts to provide

Stated as claims, with the mechanism and its witness, so each can be checked.

| # | Claim | Mechanism | Witness |
|---|---|---|---|
| S1 | A task cannot exercise authority it holds no capability for | Central capability check in the syscall dispatch table | `make smoke-captest` (100 checks) |
| S2 | Delegation cannot widen authority | `rights & src->rights` in mint/grant/transfer | Rust unit tests |
| S3 | Revoking a capability revokes its entire derivation subtree, system-wide | `rust_cap_revoke_global` + subtree closure | Rust unit tests, Kani proofs |
| S4 | Revoking a capability does *not* revoke ancestors, siblings, or independent peers | Descendant-only closure | Rust unit tests, Kani proofs |
| S5 | A revoked capability cannot be used, even from a stale snapshot | Structural nulling **and** serial-keyed generation bump | Rust unit tests, `smoke-captest` |
| S6 | An unknown or reserved syscall number cannot reach a handler | Table dispatch + compile-time size assertion | `_Static_assert`, `smoke-captest` |
| S7 | A user pointer cannot address kernel memory | Software page-walk requiring `PAGE_USER` | `smoke-captest`, SMEP/SMAP in `smoke-cpu` |
| S8 | No kernel page is simultaneously writable and executable | Per-section PTE permissions + `CR0.WP` | `make smoke-wx` (sweeps every leaf PTE) |
| S9 | A kernel stack overflow cannot reach adjacent memory | Unmapped guard page below every kernel stack: the 64 per-task stacks, the BSP boot stack, the boot and per-CPU IST fault stacks, and — since 2026-08-17 — the per-CPU ring-0 idle/park stacks, which had none | `smoke-wx`, `smoke-wx-smp` (each family enumerated, guard absent and stack above it present) |
| S10 | A boot module that fails its hash check cannot be executed | Manifest verified at boot; read path refuses unverified | `make smoke-modules-tamper` |
| S11 | Tampering with the boot chain is detectable | TPM PCR 8/9 measurement | `make smoke-tpm`, `smoke-tpm-tamper` |
| S12 | A tampered boot cannot unlock the volume | KEK sealed under `PolicyPCR(8,9)` | `make smoke-tpm-seal` |
| S13 | A server can determine a client's true identity | `SYS_IPC_SENDER` returns the kernel-recorded uid, gated on the receive right | `smoke-fs-perms`, `smoke-captest` |
| S13a | A task can operate on an IPC object only via a capability naming it | Slot-resolved `ipc_ep_from_slot` / `ipc_notif_from_slot` | `make smoke-captest` (12 refusal checks) |
| S13b | A client cannot intercept or forge a server's replies | Clients minted WRITE-only; `recv`/`reply_to` need READ | `make smoke-captest` |
| S18 | Being uid 0 confers no kernel authority by itself | Every ambient `uid == 0` gate replaced by a typed capability | `make smoke-captest` (10 checks, run as uid 0) |
| S14 | File permissions are enforced against that identity | `fs_server` reference monitor | `make smoke-fs-perms` |
| S15 | An address-space slot rebuilt after task death leaks nothing | Cspace zeroed on reuse; page pool reclaimed | `make smoke-aspace` |
| S16 | A task cannot read another's XMM register file | `fxsave`/`fxrstor` across ring transitions | — |
| S22 | A number stated in the documentation matches the tree it describes | `.github/doc-claims.yml` declares each derivable count and every place that states it; `tools/check_doc_claims.py` derives and compares, and rejects a declared claim whose pattern has stopped matching | `doc-claims`, a required check. Falsified three ways: a stale number, a reworded sentence that deletes a claim, and a retired phrasing reasserted |
| S17 | The shipped **kernel image** corresponds to the published source | Byte-for-byte reproducible build of `kernel.elf` | the `reproducible` CI job, a required check, which builds twice and diffs the recorded hash, and which since 2026-08-19 also runs `make smoke-repro-sha` (the record must cover every artifact) against `make smoke-repro-sha-control` (the pre-fix step, which records one of two and reports success). `make reproducible-build` builds **once** and records both artifacts in `.build.sha`. **`boot.iso` is deliberately not covered by this property**: grub-mkrescue stamps a wall-clock UUID into it, so it is not byte-reproducible — see `docs/LIMITATIONS.md` §5.3a. This row said "the shipped binary" until 2026-08-19, which read as the ISO |
| S19 | Audit-log history committed before a kernel compromise cannot be forged or rewritten | Forward-secure hash chain in `src/kernel/kaudit.c`: the MAC key is ratcheted one-way and erased after every entry | Rust unit tests (`rust/src/audit.rs`) |
| S20 | A task's kernel stack is executed by at most one CPU at a time | Two paths. (a) The scheduler's claim on the outgoing task is held until the CPU has *left* its stack — released from `sched_release_deferred()`, called by `isr_common_stub64` after `movq %rax,%rsp` — with `g_kstack_inflight` halting the kernel if two CPUs are ever on one stack. (b) A CPU whose last runnable task dies parks on its **own** ring-0 stack, not on the one `tasks[0].kernel_stack_top` every CPU used to share; `sched_note_park()` halts if two ever pick the same one | `make smoke-kstack-race` and `smoke-kstack-park`, each with a control arm that restores the defect and must reproduce it |
| S24 | The kernel never reads or writes a user address the caller did not name | Argument registers are 64-bit; every pointer-taking wrapper in `include/syscall.h` passes its pointer through `SYSCALL_UPTR()`, and `user_copy` refuses an address the task does not already have mapped rather than materialising one | `tools/check_syscall_abi.py`, a required check (`syscall-abi`), falsified two ways — a narrowed pointer in one wrapper, and a narrowed `SYSCALL_UPTR` definition. Runtime arm: `make smoke-klog-forge` reads the log into a buffer above 4 GiB, against `make smoke-klog-forge-abi-control` (`SYSCALL_PTR_TRUNC32=1`), 3 boots in 3 |
| S23 | A ring-3 task cannot forge entries into the kernel message ring, nor evict what is already there | `h_write` resolves `CAP_KERNEL_LOG` + `CAP_RIGHT_WRITE` through `cap_lookup` (type checked) and passes the result to `print_from_user`; without it the bytes reach the console and not `klog`. `root_cnode[15]` mints that capability READ-only and delegation may only narrow, so no task can currently hold the write right at all | `make smoke-klog-forge`, with `smoke-klog-forge-control` (`KLOG_WRITE_UNGATED=1`) reporting `FAIL forged+evicted` on every boot, 3 in 3 |
| S21 | A program image can only be spawned by the task that armed it, and a child inherits its stdio from that same task | `loader_arm_commit()` records the arming task; `do_spawn` and `h_sudo` refuse a foreign or unowned image; the spawner's identity is a parameter of `wire_child_stdio` rather than a global | `make smoke-spawn-owner`, with `smoke-spawn-owner-control` (`SPAWN_OWNER_UNCHECKED=1`) spawning the foreign image on every boot |

S13 and S14 were undermined until 2026-07-27 by the [C-1] defect — an attacker could
impersonate the server rather than lie to it. S13a and S13b are the properties that now hold
the transport up, and are tested by the refusal checks in `smoke-captest`.

---

## Cryptography

| Purpose | Primitive |
|---|---|
| CSPRNG | ChaCha20, fast-key-erasure construction, seeded from RDRAND (health-checked), TSC, and interrupt jitter |
| Data at rest | AEAD with per-`(inode, block)` subkeys and a fresh nonce per write |
| Hashing / measurement | SHA-256 (TPM PCRs, boot-module manifest), BLAKE2b |
| Password hashing | Argon2 |
| Key derivation | HKDF for the vdisk KEK |
| Integrity | Hierarchical rollback MAC over block metadata |

All primitives are implemented in `no_std` Rust in `rust/src/`. They are **not** independently
audited and **not** verified constant-time. The CSPRNG replaced an earlier LCG-plus-raw-TSC
construction that was predictable from ring 3.

---

## Process security

The engineering environment is part of the trusted base. Current state:

**In place:** signed commits enforced by ruleset; protected `main` with no bypass actors;
linear history required; force-push and deletion blocked; all third-party GitHub Actions
pinned to full commit SHAs; least-privilege `GITHUB_TOKEN` scopes per workflow; 22 required
status checks — including, since 2026-08-15, the capability conformance suite that witnesses
most of the table above — with `strict_required_status_checks_policy: true`, so a stale-base
merge is no longer permitted; reproducible-build verification; CodeQL, Semgrep, Trivy, gitleaks,
cargo-audit; CycloneDX SBOM per run; Dependabot on Actions and Cargo; secret scanning with
push protection; cargo-fuzz on the FFI boundary; Kani proofs on capability revocation.

**Known gaps**, all tracked in the audit:

- **Merges require no reviewer approval** (`required_approving_review_count: 0`). Every
  recent pull request merged with zero reviews. For a single-maintainer project this is a
  structural limitation, and it is stated here rather than glossed over: **the assurance
  Horus can currently claim is "thoroughly automatically verified", not "independently
  reviewed".** Finding **[C-5]**.
- **Which CI jobs gate a merge cannot be verified by CI itself.** Finding **[C-6]**, and what
  remains of it is narrow. *This bullet said "most security-specific CI jobs are **not**
  merge-gating … the rest are still advisory, and the mechanism that produced the omission is
  untouched" for a day after all three of those clauses stopped being true. Corrected
  2026-08-17.*

  Every security gate now blocks a merge — kernel W^X, measured boot, module and newlib tamper
  rejection, SMEP/SMAP, flush-on-switch, stack-guard reseed, the 64-bit heap, interrupt policy,
  per-CPU identity, the resume-`%rsp` guard, both S20 kernel-stack gates, the SMP soak and
  CodeQL. `.github/ci-gating.yml` is the checked-in decision record and the `ci-gating` job
  fails the build if any job is unclassified, double-classified, or names a job that no longer
  exists; there is no default, because defaulting is what produced the finding. The ruleset
  required **22** contexts before 2026-08-16.

  **What keeps it open:** reading a ruleset needs the `Administration` permission, which is not
  among the scopes a workflow `GITHUB_TOKEN` can be granted, so `ci-gating` proves the
  classification is *complete* and not that the ruleset *matches* it. A scheduled
  `ruleset-audit` job closes that by authenticating as a GitHub App with `Administration: read`
  scoped to this repository. **Live since 2026-08-19** — it now reads the ruleset and states the
  comparison, having failed loudly rather than skipped for the days it was unconfigured. Syncing
  the ruleset remains a manual step that must lag a job landing by one merge, which is what is
  left of this finding. Read the count from
  `gh api repos/pharanyx-labs/Horus/rulesets/19007209`, not from this sentence.
- No build provenance attestation or signed release artifacts. Finding **[I-9]**.

If you are evaluating Horus, weigh those gaps against the claims in the table above.

---

## Supported versions

Horus has no tagged releases yet. Security fixes land on `main`. Anyone deploying Horus for
research should track `main` and rebuild.

---

## Hardening the build

- Ship with default flags. `DEBUG_SHELL=1` enables an in-kernel debug shell and additional
  syscall surface; it is a development aid, not a shipping configuration.
- `PREEMPT_SELFTEST` and the other `*_SELFTEST` builds add test-only syscalls that are
  absent (and fail closed) in the default kernel.
- Verify reproducibility before trusting a binary: run `make reproducible-build` twice and
  compare the `kernel.elf` line of `.build.sha`. A single run records hashes; it does not
  compare them. The `boot.iso` line will differ between runs and that is expected (§5.3a).
- For measured boot, record the expected PCR values with `tools/tpm_expected_pcr.py` and
  compare them against the running system.
