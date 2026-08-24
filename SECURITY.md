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
remaining open findings — the `tasks[]` table (**[I-7]**) and the `tasks[]` table alone now that
**[G-9]** closed on 2026-08-21 (its last component was the claim auditor clearing its own
exemption before the release it exempts — a false positive of the checker, not a leak; 9/200 → 0/200
boots, mechanism proven 8/10 against 0/10 with the window widened in both arms) — are in
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
| S1 | A task cannot exercise authority it holds no capability for | Central capability check in the syscall dispatch table | `make smoke-captest` (114 checks) |
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
| S12 | A tampered boot cannot unlock the volume | KEK sealed under `PolicyPCR(8,9)` | `make smoke-tpm-seal` | **Since 2026-08-23 this property can be made mandatory**: `MEASURED_BOOT_REQUIRED=1` halts the machine when measured boot is unavailable, and refuses to unlock a persistent volume that was never sealed — closing the downgrade where a re-formatted, password-only disk made the requirement evaporate. Off by default; the ephemeral RAM vdisk is exempt (its key never outlives the boot). Witness `make smoke-measured-boot-required`, against `-control` (no TPM must halt) and `-volume-control` (an unsealed volume must be refused).
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
| S25 | Which syscalls a test actually exercises is measured, not assumed | `SYSCALL_COVERAGE=1` records first entry into each handler body; `.github/syscall-coverage.yml` classifies all 81 implemented syscalls as covered or uncovered-with-a-reason; `tools/check_syscall_coverage.py` diffs the measured union against it. Currently **54 of 81** — the property is that the number is decided and stable, not that it is 83. *(It read 76 until 2026-08-22, and the correction is not a regression: three syscalls with real handlers — `SYS_CAP_MINT`, `SYS_CAP_TRANSFER`, `SYS_CAP_MOVE` — sat in the dispatch table as bare numeric literals, and the derivation reads `[SYS_NAME] = { handler`, so it could not see them. They were unclassified and unmeasured, and nothing could fail on it. Naming them made them countable.)* *(It read 81 until 2026-08-23, and that correction went **both ways**. The deriver read the table as flat text, so three entries compiled only under a defect arm or a selftest flag — `SYS_OPEN`, `SYS_PREEMPT_TRACE`, `SYS_IRQ_POLICY_INFO` — counted as shipped; and seven more were still bare numeric literals, five of them live in the ship build. So the figure described no kernel that has ever booted. `scan_table` now evaluates the preprocessor, guarded entries are declared under `conditional:` with the flag that guards them, and a bare numeric entry is refused outright. The same blind spot had been recorded in prose beside `SYS_OPEN` since 2026-08-22 — naming the wrong three, since two of the three it named were invisible to the regex that was supposed to be overcounting them. An unenforced note is worth that much.)* | `syscall-coverage`, a required check (`make smoke-syscall-coverage`). Falsified eleven ways: an unclassified syscall, a covered one that stopped being entered, an uncovered one that started being entered, a serial log carrying no `SYSCOV` lines at all, and — added 2026-08-23, one arm per new rule — a guarded entry becoming unconditional, a guarded entry nobody declared, a `conditional:` naming the wrong flag, a guarded syscall declared covered, a bare numeric index, an `#if` form the deriver cannot evaluate, and a `SYSCOV` number no active entry claims |
| S24 | The kernel never reads or writes a user address the caller did not name | Argument registers are 64-bit; every pointer-taking wrapper in `include/syscall.h` passes its pointer through `SYSCALL_UPTR()`, and `user_copy` refuses an address the task does not already have mapped rather than materialising one | `tools/check_syscall_abi.py`, a required check (`syscall-abi`), falsified two ways — a narrowed pointer in one wrapper, and a narrowed `SYSCALL_UPTR` definition. Runtime arm: `make smoke-klog-forge` reads the log into a buffer above 4 GiB, against `make smoke-klog-forge-abi-control` (`SYSCALL_PTR_TRUNC32=1`), 3 boots in 3 |
| S23 | A ring-3 task cannot forge entries into the kernel message ring, nor evict what is already there | `h_write` resolves `CAP_KERNEL_LOG` + `CAP_RIGHT_WRITE` through `cap_lookup` (type checked) and passes the result to `print_from_user`; without it the bytes reach the console and not `klog`. `root_cnode[15]` mints that capability READ-only and delegation may only narrow, so no task can currently hold the write right at all | `make smoke-klog-forge`, with `smoke-klog-forge-control` (`KLOG_WRITE_UNGATED=1`) reporting `FAIL forged+evicted` on every boot, 3 in 3 |
| S29 | Reaching a mounted subtree requires the capability for that mount, not the path | The VFS is a per-task library (`userspace/hvfs.c`), not a server, so no privileged intermediary holds capabilities to every backing filesystem. `hvfs_mount` refuses a slot holding no usable capability, and `hvfs_rpc` sends on the mount's own slot — an empty or wrong-type slot fails the kernel's IPC gate. **The prefix is a name, not a boundary**: a task holding a server's capability reaches all of that server wherever it is mounted; confinement is the server's job | `make smoke-vfs` — two servers, two mounts, 14 checks, **and since 2026-08-23 the ship build's own clients**: `posix.c` and `shell.c` walk every path through this library, so `smoke-newlib`, `smoke-session` and the coreutils gates exercise it too. `..` pops the walker's own descent stack rather than asking the server, which both removes a round trip and removes a thing a compromised server could lie about. Falsified by `smoke-newlib-walk-control` (the private walker restored) and `smoke-newlib-dotdot-control` (`..` asked of the server, which creates no such entry — the branch as it shipped in #195, dead on arrival), and by `smoke-vfs-mount-control` (`VFS_MOUNT_UNGATED=1`, a prefix alone installs a mount) and `smoke-vfs-prefix-control` (`VFS_FIRST_MATCH=1`, `/dev/zero` is answered by the wrong server) |
| S28 | A gate satisfied by a capability every task already holds is not a gate | The in-kernel ramfs surface — `SYS_OPEN`, ramfs create/list, and `SYS_READ` for fd ≥ 3 — authorised on cspace slot 3 with `SC_ANYTYPE`, which the legacy `CAP_FRAME` in every task satisfies. All four are retired (**[H-3]**, 2026-08-22); an absent dispatch entry fails closed at `SYS_ERR_NOSYS` | `make smoke-passwd-probe`: an ordinary uid-1000 task holding no delegated capability is refused all four — **and, since 2026-08-23, a fifth**: `SYS_EXEC_LEGACY` (14) wore the same slot-3 authority and **created a task**. Measured from that probe before removal: it returned task id 2 to a uid-1000 caller. It survived the [H-3] sweep because its dispatch entry was written `[14]` — a bare number matching none of the `[SYS_NAME]` patterns that sweep, the coverage manifest, and every audit grep are built on; naming it in #201 is what made it visible. `create_task` assigns no uid, so the task it made carried whatever the slot held. Falsified by `smoke-passwd-probe-legacy-control` (`LEGACY_SYSCALLS_PRESENT=1`), under which the probe is handed a task id again. Falsified by `smoke-passwd-probe-control` (`RAMFS_SLOT3_GATE=1`), under which it opens a seeded file, reads bytes out of two more, creates a file and lists the store. *(Until 2026-08-22 the first of those was the file the user database was written into; that path has since been deleted as code that never ran — see `docs/LIMITATIONS.md` §2.6. The property is unchanged: it was never about what sat behind the gates.)* |
| S26 | Memory can only be mapped through a capability naming a kernel-managed frame object | `CAP_FRAME.object` is an INDEX into the frame table `SYS_RETYPE` populates, bounds-checked against `[DYN_FRAME_BASE, FRAME_INDEX_MAX)`, never a caller-supplied physical address. This is what makes the legacy `CAP_FRAME` every task is born holding in slot 3 — object `USER_AREA_BASE`, `READ\|WRITE\|EXEC`, and the capability that made [C-1] reachable — map nothing at all | `make smoke-frame`, with `smoke-frame-index-control` (`FRAME_INDEX_UNCHECKED=1`, which makes the object a physical address) mapping physical `0x400000` into ring 3 from that legacy capability on every boot |
| S27 | A memory mapping conveys no authority the capability does not carry | `SYS_MAP_FRAME` resolves the caller-named slot with `cap_lookup(slot, rights)`, so the capability must hold at least every right requested, and the PTE is built from `cap->rights & requested`. `SYS_CAP_MINT` is how a holder narrows a copy before delegating it — the only rights-reducing operation ring 3 has, since `SYS_CAP_GRANT` copies the source's rights whole | `make smoke-frame`: a `READ`-only delegate sees the sharer's bytes and cannot obtain a writable mapping. Falsified by `smoke-frame-rights-control` (`FRAME_RIGHTS_UNCHECKED=1`), under which its write lands |
| S21 | A program image can only be spawned by the task that armed it, and a child inherits its stdio from that same task | `loader_arm_commit()` records the arming task; `do_spawn` and `h_sudo` refuse a foreign or unowned image; the spawner's identity is a parameter of `wire_child_stdio` rather than a global | `make smoke-spawn-owner`, with `smoke-spawn-owner-control` (`SPAWN_OWNER_UNCHECKED=1`) spawning the foreign image on every boot |
| S30 | The CSPRNG never emits output before it is seeded from real entropy | `RngState::fill` (`rust/src/rng.rs`) returns false and zeroes the caller's buffer while `seeded` is false, instead of running ChaCha20 under the hardcoded startup key in `RngState::new()` — a **published** constant, since the build is reproducible. The two C wrappers (`secure_random_bytes`, `secure_random_u64`) halt on a refusal, the same way `entropy_init` already halted on a pool that did not take, and `rust_rng_u64()` — which returned a `uint64_t` and so had nowhere to put a refusal — was replaced by `rust_rng_u64_checked(uint64_t *)`. **This was previously true by boot ordering rather than by construction**: `entropy_init()` runs before the first consumer, which is a fact about one call site, not a property of the RNG | `make smoke-rng-seed` — a probe asks the pool for output before `entropy_init()` and must be refused, in a boot that must still reach the ring-3 shell banner. Falsified three ways: `smoke-rng-seed-control` (`RNG_UNSEEDED_LEGACY=1`, the check compiled out of `fill`) serves keystream and reddens the base gate; the Rust arm `cargo test --features rng_unseeded_legacy` fails `rng_refuses_before_seeding` and only that test; and an `if true` mutation making `fill` refuse *everything* reddens the base gate too, on the boot half rather than the marker |
| S31 | The capability algebra's authority invariants are proved over the whole input space, and the proofs run | Fifteen `#[kani::proof]` harnesses; `.github/kani-harnesses.yml` classifies each as gating or excused-with-a-reason, and `tools/check_kani_harnesses.py` fails the build on one in neither. Proved for **every** input: mint and grant yield exactly `requested & source`; lookup succeeds **exactly when** the capability holds every requested right; grant records its grantor as parent with a fresh derived serial, refuses an invalid source without writing anything, and is bounded by the destination cspace; revocation nulls exactly the target's subtree — no ancestors, all descendants. **The proofs did not gate anything until 2026-08-23**: the `kani` job is `workflow_dispatch`-only *and* carries `continue-on-error` on both steps, so no harness could redden a build — the `smoke-kstack-park` shape (required and unfailable at once) applied to formal verification | `kani-bounded`, a required check: eleven harnesses, **319 s** measured, no `continue-on-error`. Each new proof was falsified by mutating the property it claims — weakening lookup's rights test to "any overlap", dropping grant's `& src.rights`, zeroing the recorded parent, removing a bound — and confirming `VERIFICATION:- FAILED`. The four excused harnesses (the serial-keyed lineage pair and the two ELF validators) run in the manual `kani` job; a full `cargo kani` exceeded GitHub's 6-hour ceiling |
| S32 | The capability graph is observable, under an authority that observes and nothing else | `CAP_DEBUG` (roadmap 3.6) gates cross-task introspection and `SYS_CAP_ENUMERATE`, which reports one cspace slot's type, rights, serial, badge and generation. Minted **READ-only** in the root cnode, so no delegation can widen it — rights only ever narrow, so a primordial that never held WRITE cannot produce a descendant that does. It replaces the `CAP_AUDIT` init used to hand the shell for `ps`, which **also** rotates the audit chain's keys and reads the log: a bundling mistake rather than an ambient one, and invisible to an ambient-authority sweep because the gate was real — it just named far more authority than the caller needed. **Since 2026-08-24 cross-task introspection requires `CAP_DEBUG` specifically**: `SYS_GET_TASK_INFO` accepted `CAP_USER` or `CAP_AUDIT` as well until then, so "do you administer users" and "do you hold the audit log's keys" were both answers to "may I see the process list". Every holder that legitimately observes now holds the capability for observing — `proctest` keeps its `CAP_AUDIT` only because its *delegation* test needs a capability with an observable effect to hand a child. `object` is deliberately not reported: `serial` and `badge` are the graph's nodes and edges, so derivation is fully visible without naming what each capability points at (the same reasoning that suppresses `cr3` and another task's `eip`, finding I-4) | `make smoke-session` runs `capview` and requires the shell's own `debug` capability with `r-----` rights — not merely that something printed, since "no capabilities anywhere" is what a broken readout looks like. `make smoke-captest` requires refusal — four checks of its own — for a task holding no `CAP_DEBUG`, **including for its own cspace**. Falsified by `smoke-captest-capenum-control` (`CAP_ENUMERATE_UNGATED=1`), which removes the declared capability so the central gate admits everyone, and by `smoke-proc-taskinfo-control` (`TASKINFO_WIDE_AUTHORITY=1`), under which `grantee` — holding a granted `CAP_AUDIT` and no `CAP_DEBUG` — reads another task's info again |
| S33 | The security core's `unsafe` FFI code is free of the undefined behaviour an interpreter can see | `cargo miri test` over `rust/src` — 77 tests, every module that has tests except four crypto ones excused with a reason in `.github/miri-scope.yml`. Miri checks out-of-bounds access, invalid pointer use, and the Stacked Borrows aliasing rules that raw-pointer FFI is easiest to break, which is what this crate is: 80 `unsafe` blocks across `capability.rs`, `lib.rs`, `rng.rs` and `memory.rs`, each at the boundary where the C kernel hands in a pointer. **The first run found UB in three places, all of them in the TESTS** — a test would take `x.as_mut_ptr()`, store it, then reach the same array a second way, which retags and invalidates the first pointer. The C kernel holds one pointer and passes it twice, so the harness was modelling its own caller wrongly; the library was not at fault, which was established by **ablation** rather than assumed | `miri`, a required check, with no `continue-on-error`. `tools/check_miri_scope.py` fails the build on a test module that is neither run nor excused, and the job derives its `--skip` flags from that manifest so the scope and the command cannot drift. Falsified three ways: a rotted skip entry, an excuse of under eight words, and a new module (which defaults to RUN — the safe direction) |
| S34 | A clock is available to ring 3 without restoring the timer `CR4.TSD` denies | `SYS_CLOCK_GETTIME` reports monotonic time since boot from the **PIT tick counter**, not the TSC, so `nsec` is always a multiple of one tick (10 ms at `PIT_TICK_HZ`). `CR4.TSD` exists to remove "the cycle-accurate timer that cache/covert-channel attacks between mutually distrusting ring-3 tasks lean on" (`src/kernel/crypto.c`), and a nanosecond clock behind a syscall would hand it straight back. **This is not a claim of side-channel safety** — the TSD comment already says the mitigation is partial, and a counting loop still builds a finer timer; it is a refusal to make it easy. Ambient by design: a coarse count of time since boot is not authority over an object, and gating it would push callers toward a worse clock of their own. Every clock id but `HORUS_CLOCK_MONOTONIC` is refused rather than approximated — there is no RTC here, and answering `CLOCK_REALTIME` with uptime would be a number shaped like a date with nothing behind it. Monotonic **by construction**: the source is a counter the timer interrupt only increments, widened to 64 bits because a u32 at 100 Hz wraps in ~497 days | `make smoke-captest`: 7 checks — the resolution is a whole tick, `nsec` is in range, `reserved` is zeroed, a second read never goes backwards, and three refused clock ids. Falsified by `smoke-captest-clock-control` (`CLOCK_TSC_RESOLUTION=1`), whose defect is that it is **better**: real microseconds off the TSC, more accurate and more useful, undoing TSD |

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
