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

> ### Known critical defect: IPC is not capability-addressed
>
> Endpoints and notifications are addressed by a raw integer index taken from a userspace
> register. The `object` field of `CAP_ENDPOINT` — which names *which* endpoint a capability
> confers authority over — is never consulted by any IPC syscall. The authorisation check
> confirms only that the caller holds *something* in a fixed cspace slot, and every task is
> created holding a `CAP_FRAME` there.
>
> **Consequence.** Any unprivileged ring-3 program can receive on, send to, and forge
> replies on any endpoint in the system — including the filesystem server's well-known
> request endpoint. It can therefore intercept another user's filesystem requests and forge
> the server's replies, defeating the POSIX permission model that `fs_server` enforces.
>
> Full analysis, exploit path, and fix: finding **[C-1]** in
> [`docs/AUDIT-2026-07-27.md`](docs/AUDIT-2026-07-27.md). This is the top roadmap item.

**Do not deploy Horus where isolation between mutually distrusting programs matters.**
Its current appropriate uses are research, education, and the development of the capability
model itself.

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
*Status: partially defended.* Memory isolation and syscall authorisation hold; **IPC
isolation does not** (see above).

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
the spinlock's interrupt-nesting counter is a single global shared across CPUs (**[C-3]**), so
one CPU's lock release can re-enable interrupts while another still holds a lock. That admits
a timer tick inside a critical section — reentrancy the `cli`/`sti` discipline exists to
prevent. *Not defended.* The obvious fix is blocked on **[C-3.1]**: the boot path depends on
the defect. See `docs/LIMITATIONS.md` §2.0.

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
| S1 | A task cannot exercise authority it holds no capability for | Central capability check in the syscall dispatch table | `make smoke-captest` (29 checks) |
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
| S13 | A server can determine a client's true identity | `SYS_IPC_SENDER` returns the kernel-recorded uid | `smoke-fs-perms` |
| S14 | File permissions are enforced against that identity | `fs_server` reference monitor | `make smoke-fs-perms` |
| S15 | An address-space slot rebuilt after task death leaks nothing | Cspace zeroed on reuse; page pool reclaimed | `make smoke-aspace` |
| S16 | A task cannot read another's XMM register file | `fxsave`/`fxrstor` across ring transitions | — |
| S17 | The shipped binary corresponds to the published source | Byte-for-byte reproducible build | `make reproducible-build` (CI-gated) |

**S13 and S14 are currently undermined by the [C-1] IPC defect**, because an attacker can
impersonate the server rather than lie to it. The mechanisms are correct; the transport
beneath them is not authenticated.

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
pinned to full commit SHAs; least-privilege `GITHUB_TOKEN` scopes per workflow; 21 required
status checks; reproducible-build verification; CodeQL, Semgrep, Trivy, gitleaks,
cargo-audit; CycloneDX SBOM per run; Dependabot on Actions and Cargo; secret scanning with
push protection; cargo-fuzz on the FFI boundary; Kani proofs on capability revocation.

**Known gaps**, all tracked in the audit:

- **Merges require no reviewer approval** (`required_approving_review_count: 0`). Every
  recent pull request merged with zero reviews. For a single-maintainer project this is a
  structural limitation, and it is stated here rather than glossed over: **the assurance
  Horus can currently claim is "thoroughly automatically verified", not "independently
  reviewed".** Finding **[C-5]**.
- Security-specific CI jobs (capability conformance, kernel W^X, measured boot, module
  tamper rejection, SMEP/SMAP) are **not** merge-gating. Finding **[C-6]**.
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
