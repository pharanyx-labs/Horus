# Horus Roadmap

This roadmap is organised around a single objective: **close the gap between what
Horus's code achieves and what its engineering process guarantees.** A July 2026
audit ([AUDIT-2026-07.md](AUDIT-2026-07.md)) found the kernel to be disciplined
research-grade work, but the *ecosystem that produces it* — branch protection,
review, supply-chain provenance — not yet commensurate with the high-assurance
goals the kernel pursues. It also surfaced a real capability-algebra defect. Those
findings now set the priority order.

The plan is three **audit-remediation tracks** at the top (do these first), then
the ongoing capability-maturity work (SMP, userspace, verification, driver
isolation) that continues underneath them. A record of completed foundations is at
the end.

Nothing here is a commitment — priorities shift as contributors join. If you want
to work on something, open an issue first; coordination saves effort. Finding IDs
(A1–A4, P1–P5) reference [AUDIT-2026-07.md](AUDIT-2026-07.md).

---

## Where things stand

Horus is a working x86-64 capability microkernel that boots a ring-3 `init`
supervising a ring-3 shell across multiple cores, with a userspace filesystem
server over an encrypted, persistent, crash-atomic store, a newlib libc port,
ring-3 process control, and a safe-Rust security core (capability algebra, page
refcounting, the whole ELF-loader parse, the crypto primitives). It passes a broad
headless QEMU self-test suite in CI. The completed foundations are summarised at
the bottom of this document; the audit did not dispute any of that — it found that
the surrounding **assurance chain** is the weak link, plus one correctness defect in
the capability engine.

**Priority framing after the audit:**

| Track | Theme | Blocking finding(s) | Priority |
|---|---|---|---|
| **0** | Assurance & governance | P1, P2, P3, P4, P5 | **Now — highest leverage** |
| **1** | Capability-model correctness | A1, A2, A3 | **Now — real defect** |
| **2** | Boot & supply-chain integrity | A4, P4 | Next |
| **3** | SMP maturity | — | Ongoing |
| **4** | Userspace ecosystem | — | Ongoing |
| **5** | Verification & assurance scaffolding | expands Track 1 | Ongoing |
| **6** | Driver privilege separation | — | Ongoing |

---

## Track 0 — Assurance & governance *(highest priority)*

The kernel's runtime claims can be no stronger than the pipeline that builds and
ships it. Right now several controls the repository *documents* are not *enforced*.
This track makes the process match the promise. None of it touches kernel code, and
all of it is high-leverage.

### 0.1 — Enforce `main` (P1) — *mostly done*

`main` is now branch-protected. Enabled:

- **Required status checks** (the hard gates): *Rust unit tests + clippy
  (deny-warnings gate)*, *Build kernel.elf + bootable ISO (x86_64)*, *QEMU
  smoke-boot (headless)*, and *Verify reproducible kernel build* — a PR cannot
  merge while any is red.
- **Enforce for administrators** (the rule is not owner-bypassable).
- **Block force-push and branch deletion** (history cannot be rewritten).
- **Linear history** (merges are squash/rebase, no merge commits).

*Deferred:* **required CODEOWNERS review** is intentionally **not** enabled while
the project has a single maintainer — a required review with no second reviewer
would deadlock all merges. This is the P2 gap, documented as an accepted risk in
[../SECURITY.md](../SECURITY.md); turn required review on the moment a second
reviewer exists. (`strict`/up-to-date-before-merge is also off for now, to avoid
serial-rebase friction.)

### 0.2 — Independent review (P2)

Add at least one independent reviewer for the security-critical paths
(`capability.*`, `paging.c`, `scheduler.c`, `crypto.*`, `.github/workflows/`).
Until a second engineer exists, **document the single-maintainer risk as an
accepted limitation** in [../SECURITY.md](../SECURITY.md) rather than leaving
"CODEOWNERS review" to imply four-eyes that does not happen. Consolidate the four
committer identities and **require signed commits** (P5).

### 0.3 — Turn on the native security controls (P3) — *mostly done*

- **Dependabot vulnerability alerts + automated security updates** enabled at the
  repository level, and the **cargo** ecosystem (`/rust`) added to
  `.github/dependabot.yml` alongside GitHub Actions.
- **CodeQL** workflow added (`.github/workflows/codeql.yml`): it builds the C
  kernel under CodeQL's tracer (`security-and-quality` suite) and uploads SARIF to
  the Security tab. Advisory, not a merge hard-gate.
- *Remaining:* promote a **fast, deterministic Kani/fuzz subset** (pinned nightly,
  fixed seed corpus) to a **required** check so a regression in a proven invariant
  — `mint_never_escalates_rights`, `serial_never_reserved_or_zero`, the ELF
  validators — cannot merge green.

### 0.4 — Hermetic, attestable builds (P4)

- Pin the toolchain: `rust-toolchain.toml` plus a **digest-pinned container or Nix
  flake** for the C/binutils/GRUB toolchain, so "reproducible" means reproducible
  *across time*, not only within one ephemeral runner image.
- Emit **SLSA provenance** for `kernel.elf` / `boot.iso` and **sign the artifacts**
  (cosign / sigstore), recording the reference hashes alongside the existing
  `.build.sha`.

### 0.5 — Repository hygiene (P5) — *partially done*

- **`delete_branch_on_merge` enabled** — merged PR branches are auto-deleted going
  forward.
- *Remaining:* prune the ~55 already-merged feature branches (a bulk-delete the
  maintainer should run — e.g. `git branch -r --merged origin/main | ... | xargs
  git push origin --delete`); consolidate the committer identities and **require
  signed commits** (P2/P5).

---

## Track 1 — Capability-model correctness *(highest priority)*

The audit found the revocation algebra revokes an **equivalence set**, not a
**derivation subtree** (A1), the grant path skips the locked write discipline (A2),
and the lineage table is a lossy hash (A3). These are correctness defects in the
system's core security mechanism. A1 fails safe (it over-revokes) but violates the
advertised least-privilege-delegation and transitive-revocation semantics.

### 1.1 — Replace equivalence-set revocation with a derivation tree (A1) — *done*

`revoke_matching_in`/`lineage_matches` were replaced by `revoke_subtree`, which
computes the exact **derivation subtree** of the target: seed a bounded worklist
with the target's serial, then close it under "child (`badge`) of an already-revoked
serial", and null exactly those. Ancestors, siblings, and independent same-`object`
capabilities are left intact (this builds on the A2 fix, which makes every derived
cap record its immediate parent's serial in `badge`). Completeness is a fail-safe:
if a subtree exceeds the worklist (`MAX_REVOKE_LINEAGE = 256`, never in practice),
the null pass also sweeps every cap sharing the target's `object` — a complete
superset, so no descendant can survive.

Regression tests landed: revoking a child leaves the parent and siblings intact;
two independent same-object caps are independent; the overflow fallback revokes a
whole oversized subtree; the existing transitive-chain / other-cspace / grant tests
still pass. Covered on real hardware by `smoke-captest` / `smoke-proc` /
`smoke-aspace` / `smoke-session` / `smoke-fs-conc`.

*Follow-up:* an explicit CDT with parent pointers would remove the (documented,
never-hit) worklist bound; extend the Kani harnesses to the revised revocation once
the shared mutable state is modelled (Track 5).

### 1.2 — Route `SYS_CAP_GRANT` through the locked discipline (A2) — *done*

Replaced the raw `tasks[target].cspace[dest_slot] = granted` store with
`cap_grant_into` (C) → `rust_cap_grant_into` (safe Rust): the source lookup and
destination store now happen together under `cap_lock` (SMP-safe against a
concurrent revoke), the write is counted against the target's `caps_in_use`
ceiling, rights are masked to `new_rights & src.rights` (rights-reduction plumbing
in place; the 3-arg `SYS_CAP_GRANT` ABI still passes full rights for
compatibility), and the grantee records the grantor's cap as its parent
(`badge = src.serial`) so the derivation tree the A1 fix relies on is well-formed.
The originally-reported "reserved-slot floor" sub-point was withdrawn — grant
legitimately endows a dominated child's low slots (e.g. a server's IPC gate at slot
3). Covered by new Rust unit tests and the `smoke-proc` / `smoke-captest` /
`smoke-init-fs` / `smoke-session` self-tests.

*Follow-up:* expose the `new_rights` mask through the syscall ABI (a 4th argument
or a dedicated `SYS_CAP_GRANT_RIGHTS`) so a supervisor can delegate with reduced
rights and, by default, without `CAP_RIGHT_REVOKE`.

### 1.3 — Make lineage generations exact (A3) — *deferred (latent)*

Investigation during the A1 fix established that the generation mechanism is
**dormant**: no code path assigns a capability a non-zero `generation`, and
`lineage_check` treats generation 0 as "untracked / always valid", so the
object-keyed generation check never rejects a real capability and its hash
collisions cannot invalidate anything today. Structural (descendant-only)
revocation is the sole enforcement. If per-lineage generations are ever *activated*
as real use-after-revoke defense-in-depth, store the generation per-object (exact)
rather than in the shared 4096-slot hash so activation does not reintroduce
over-invalidation. Until then, no action is required.

---

## Track 2 — Boot & supply-chain integrity

### 2.1 — Verify the boot modules (A4) — *done*

**Landed.** The kernel now embeds a **SHA-256 manifest** of exactly the modules it
was built to ship, generated at build time by `tools/gen_module_manifest.sh` from
the same `BOOT_MODULES` list the ISO is assembled from
(`src/kernel/boot_module_manifest.h`, generated — not checked in). At boot, right
after the multiboot tag walk and before any userspace exists,
`boot_module_verify_all()` hashes every module where GRUB left it and requires an
exact **(destination path, size, SHA-256)** match. Unmatched modules are marked
unverified, and the two syscalls that expose them fail closed:
`SYS_BOOT_MODULE_INFO` reports an empty slot (so the `fs_server` provisioning loop
skips it) and `SYS_BOOT_MODULE_READ` refuses the payload — so an unverified module
can never be provisioned into `/bin` as a root-owned executable.

Design notes: no key is involved by choice — the manifest ships *inside* the
reproducible kernel image, so the image is the root of trust and any embedded key
would be equally readable. A build that ships no modules gets an **empty** manifest
and therefore refuses every module it is handed (fail closed, and correct: such a
kernel never attested to any). Verification runs once at boot, so the syscalls only
test a flag.

Gated by **`make smoke-modules-tamper`** (CI): it builds the kernel with the
manifest, assembles a second ISO carrying the *same kernel* but one module payload
corrupted (one byte flipped — size unchanged, so only the hash differs), and
asserts the kernel refuses exactly that module and still boots. Falsification-
tested: with the verification neutered the tampered module provisions happily and
the gate goes red. `make reproducible-build` remains byte-for-byte identical.

*Remaining for a full A4 close:* the manifest's integrity rests on the kernel image
being unmodified, which is Track 0.4's job (pinned toolchain, SLSA provenance,
signed artifacts) and 2.2's (measured boot). Signing the kernel image itself would
also let the manifest be decoupled from the build (an embedded public key + a
separately-shipped signed manifest), which needs ed25519 in the Rust core.

#### Design record — why the embedded hash manifest, not a signed one

Two designs were scoped. The **embedded per-module hash manifest** (chosen) needs
no new crypto: the build hashes each module and bakes the table into `kernel.elf`,
so security rests on the kernel image being the reproducible root of trust. Its one
real cost is that the kernel build must learn the module hashes before it compiles
— handled by generating the header from `BOOT_MODULES` as a prerequisite of
`main.o`, with an empty manifest (and no rebuild churn) when no modules ship, so a
plain `make` and the `reproducible` job are unaffected.

The alternative — an embedded **ed25519 public key** plus a separately-shipped
signed manifest — decouples the kernel build from module contents, but requires
adding curve25519/ed25519 verification to the Rust core: a substantial,
security-sensitive primitive the crate does not have. (A symmetric HMAC key would
be pointless: it would sit readable inside the reproducible image.) That remains
the upgrade path once the kernel image itself is signed (Track 0.4).

#### Companion — destination allowlist

`module_dest_ok` in `fs_server.c` constrains *where* a module may land: only a bare
name (→ `/bin`), a path under `bin/`, or one under `usr/share/man/`; absolute paths
and any empty, `.` or `..` component are refused, and a rejected module is skipped
with a log line. With 2.1's content check this closes both halves — **what** a
module contains and **where** it may go.

### 2.2 — Toward measured boot

With 2.1 and the attestable build (0.4) in place, extend to **measured boot** (TPM)
so the reproducible hash chain — kernel + module manifest — is attested at runtime,
not only at build time.

---

## Track 3 — SMP maturity

The SMP foundation is in place and default-on (ACPI-MADT CPU count, per-CPU
LAPIC-timer preemption, cross-CPU IPC/notification locking, acknowledged
TLB-shootdown IPIs). Remaining, in priority order:

- **Per-CPU run queues** with explicit load-balancing/migration, replacing the
  shared runnable pool; then **scheduling priorities and fairness**.
- **Flush-on-switch between mutually distrusting tasks** — the microarchitectural
  side-channel the audit and [../SECURITY.md](../SECURITY.md) both flag. This is the
  security-relevant SMP item, not just a performance one.

---

## Track 4 — Userspace ecosystem

The libc surface for a coreutils/binutils port is complete, eleven coreutils are
ported and load from the filesystem as boot modules, and program-size caps are
lifted (`MAX_PROGRAM_SIZE` = 8 MiB). Forward work:

- **Port binutils** (now shippable as a signed module once Track 2 lands).
- **More servers**, each following the capability-delegation model: a network-stack
  server, a block-device driver server (see Track 6), and a name server.
- **Multi-slot / worker-pool IPC** so a server can process requests in parallel
  rather than one-in-flight-at-a-time; add IPC send/recv timeouts.
- Continue growing the `captest` conformance exerciser — especially new **refusal**
  cases for the revised revocation and grant semantics (Track 1).

---

## Track 5 — Verification & assurance scaffolding

Cross-cutting work that should grow alongside every track, and the natural home for
proving the Track 1 fixes.

- **Wire the TLA+ specs into CI.** `docs/cap_algebra.tla` and
  `docs/paging_isolation.tla` exist but are not model-checked; run TLC on every PR
  and extend `cap_algebra.tla` to the **revised (CDT) revocation** so the fix is
  specified, not just coded.
- **Extend Kani to the revocation paths** — *done for the A1 invariant*. Two new
  harnesses prove, over the **entire** serial space, that revoking a descendant
  never nulls its ancestors (`revoke_descendant_never_nulls_ancestors`) and that
  revoking a root nulls every descendant (`revoke_root_nulls_every_descendant`) —
  together pinning revocation to exactly the target's subtree. Six harnesses now
  verify. *Remaining:* a multi-cspace + overflow-fallback model, and the
  lineage-generation paths (they mutate a shared static needing a heavier model);
  keep the deterministic subset in the required check from 0.3.
- **Syscall-boundary fuzzer** under QEMU (syzkaller-style), complementing the
  existing host FFI fuzzers.
- **Broaden the scripted session harness** (`tools/session_test.py`): add
  W^X-violation and IPC/FS round-trip scenarios, and — once Track 1 lands — an
  end-to-end negative test proving a granted-then-revoked capability does **not**
  disturb the grantor.

---

## Track 6 — Driver privilege separation

The console is out of the kernel (ring-3 `console_server`, `CAP_IO_DEVICE`-gated,
fault-contained). Continue shrinking the flat trust domain:

- Move **PS/2 keyboard input** into the console server.
- Separate the **block/ATA driver** into a ring-3 server the same way, so a storage
  driver bug is a contained ring-3 fault rather than kernel-wide — this is the
  larger remaining slice of the "one bug = whole-kernel blast radius" problem the
  audit and [LIMITATIONS.md](LIMITATIONS.md) describe.

---

## Completed foundations *(record)*

These landed before the audit and were not disputed by it. Kept here as a status
record; see the git history and [ARCHITECTURE.md](ARCHITECTURE.md) for detail.

- **Process lifecycle** — ring-3 `init` (PID 1) spawns, capability-endows (purely
  via `SYS_CAP_GRANT`), and blocking-supervises the shell; full `argv`; signals
  (`SYS_SIGNAL`/`SIGMASK`/`SIGALTSTACK`); exec-from-a-file
  (`SYS_SPAWN_IMAGE`/`EXEC_IMAGE`); `fork` a deliberate non-goal. (`smoke-proc`,
  `smoke-init-fs`.)
- **Production filesystem** — ring-3 `fs_server` over an encrypted object store:
  persistent on ATA (sealed until login), per-file POSIX ownership/permissions
  against a kernel-attested identity, multi-client (identity-routed replies),
  crash-atomic (write-ahead redo journal + mount-time `fsck`), large files
  (double-indirect), 16 MiB volume (multi-block bitmap). Legacy capfs removed.
  (`smoke-fs`, `-perms`, `-conc`, `-persist`, `-wal`, `-large`.)
- **SMP** — default-on, ACPI-MADT CPU count, per-CPU preemption, TLB-shootdown IPIs
  (the *maturity* work is Track 3). (`smoke-smp`.)
- **Cryptography** — from-scratch, vector-validated Argon2id / BLAKE2b, HKDF/HMAC
  over SHA-256, a ChaCha20 fast-key-erasure CSPRNG (fail-closed seeding), and a
  ChaCha20 + HMAC-SHA256 AEAD for encryption-at-rest — all safe `no_std` Rust.
- **Userspace runtime** — 64-bit `EM_X86_64` static-PIE with demand-paged heap,
  userspace `malloc`, and an `x86_64-elf` newlib libc port; eleven coreutils ported
  and loaded from the filesystem as boot modules. (`smoke-newlib`, `smoke-modules`,
  `smoke-coreutils-shell`.)
- **Security core in safe Rust** — the capability algebra, the page-refcount trust
  boundary, the crypto primitives, and the **entire ELF-loader parse** (header,
  program headers, i386 + x86-64 relocations) run memory-safe in Rust, with Kani
  proofs and `cargo-fuzz` targets over the FFI predicates.
- **Driver privilege separation (console)** — the VGA/serial console runs as a
  ring-3 server; a bug in it is a contained ring-3 fault. (`smoke-console`,
  `smoke-console-isolation`.)
- **Hardening** — higher-half kernel (no kernel address is a user address);
  SMEP/SMAP/UMIP/`CR4.TSD`; W^X for user *and* kernel memory (whole-address-space
  leaf sweep); guarded kernel/IST stacks; CSPRNG-seeded stack canary; image-base
  ASLR; reproducible builds. All CI-gated.

---

## Contributing

**The highest-value work right now is Track 0** (assurance & governance) and
**Track 1** (capability-model correctness) — the two the audit made urgent. Track 0
is mostly repository configuration and CI, approachable without deep kernel
knowledge; Track 1 is the meatiest kernel/Rust work and the most security-critical.
Track 4 (userspace ecosystem) remains the most self-contained on-ramp for a first
contribution.

See [../CONTRIBUTING.md](../CONTRIBUTING.md) for environment setup and how to submit
work, and [AUDIT-2026-07.md](AUDIT-2026-07.md) for the full findings behind the
tracks above.
