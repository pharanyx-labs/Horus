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
toward 67. But CI cannot verify that the ruleset matches the checked-in classification, and the
reconciliation is manual and lags by one merge, so **[C-6]** narrows rather than closes. Open findings — an unbounded revocation closure
(**[I-3]**), an SMP fault whose origin is not yet known (**[G-8]**), the remaining `tasks[]`
table (**[I-7]**), and a nondeterministic WAL harness (**[I-11]**) — are in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). The write-ahead journal's missing `FLUSH CACHE`
(**[I-10]**) was fixed on 2026-08-16; filesystem crash-atomicity no longer depends on the
emulator supplying durability the kernel never asked for.

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
service (no CPU or kernel-memory quotas), and not defended against kernel-log forgery or
eviction: `SYS_WRITE` fd 1 takes no capability and appends unconditionally to the 16 KiB
`klog` that `SYS_DMESG` — which *does* require `CAP_KERNEL_LOG` — reads back. See
`docs/LIMITATIONS.md` §1.6.

**A1b — A ring-3 task holding a privileged *identity* but no capabilities.** A task at uid 0
with an empty cspace. *Defended since 2026-08-15.* This adversary had no row here until
**[H-1]** was found, which is why the finding survived nineteen days of documents asserting it
was closed: A1 is defined as an *unprivileged* ring-3 program, and the residual authority
accrued to a privileged-identity, unprivileged-cspace task that no adversary described.
`current_user_is_admin()` (`src/kernel/kusers.c`) now tests possession of `CAP_USER` and
nothing else. Witnessed twice: `smoke-captest` runs as uid 0 holding no `CAP_USER` and is
refused `useradd`/`userdel`/`passwd`-of-another; `smoke-session` drives the real shell and
asserts root may add a user while a standard user is refused.

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
| S9 | A kernel stack overflow cannot reach adjacent memory | Unmapped guard page below every kernel stack | `smoke-wx`, `smoke-wx-smp` |
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
| S17 | The shipped binary corresponds to the published source | Byte-for-byte reproducible build | the `reproducible` CI job, a required check, which builds twice and diffs. `make reproducible-build` builds **once** and only records the hash |
| S19 | Audit-log history committed before a kernel compromise cannot be forged or rewritten | Forward-secure hash chain in `src/kernel/kaudit.c`: the MAC key is ratcheted one-way and erased after every entry | Rust unit tests (`rust/src/audit.rs`) |

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
- Most security-specific CI jobs (kernel W^X, measured boot, module tamper rejection,
  SMEP/SMAP, flush-on-switch, stack-guard reseed, CodeQL) are **not** merge-gating. Finding
  **[C-6]**. `ci.yml` defines **67** jobs and `codeql.yml` one more; the ruleset required **22** of them
  before 2026-08-16, and `.github/ci-gating.yml` now records the intended set. The one that
  most needed promoting has been: `smoke-captest`, the named witness for S1, S5, S6, S7, S13,
  S13a, S13b and S18, became a required check on 2026-08-15 — until then a change that broke
  the capability refusal suite merged green. The rest are still advisory, and the mechanism
  that produced the omission is untouched: the required list is maintained by hand in the
  ruleset, which no commit touches, so it falls behind `ci.yml` on every addition. Read the
  count from `gh api repos/pharanyx-labs/Horus/rulesets/19007209`, not from this sentence.
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
- Verify reproducibility before trusting a binary: `make reproducible-build`.
- For measured boot, record the expected PCR values with `tools/tpm_expected_pcr.py` and
  compare them against the running system.
