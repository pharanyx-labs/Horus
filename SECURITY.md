# Security Policy

## Project security posture

Horus is a **research microkernel** in early development. It is not suitable for production or for handling sensitive workloads. The properties in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) reflect design intent; [docs/LIMITATIONS.md](docs/LIMITATIONS.md) is a candid, subsystem-by-subsystem account of where the line sits, and a July 2026 security & engineering audit ([docs/AUDIT-2026-07.md](docs/AUDIT-2026-07.md)) records the findings that set the current [roadmap](docs/ROADMAP.md). Its four code findings (A1–A4) are fixed; the open items are about the engineering *process*.

These are documented, known limitations — not undisclosed vulnerabilities.

### Known limitations

- **Capability revocation is descendant-only (audit A1 — fixed).** It previously matched an object/badge/serial equivalence set, so revoking a delegated capability could also null the grantor's original and same-object peers. It now computes the target's exact derivation subtree (`revoke_subtree`); ancestors, siblings, and independent same-object capabilities survive. A fail-safe object-sweep fallback preserves completeness for the (never-in-practice) oversized subtree. Kani-proved.
- **`SYS_CAP_GRANT` uses the locked write discipline (audit A2 — fixed).** It routes through `cap_grant_into`/`rust_cap_grant_into`: source lookup and destination store under `cap_lock` (SMP-safe), the write counted against `caps_in_use`, rights masked to the source's, a well-formed derivation-tree parent recorded. Exposing rights-reduction through the ABI is a follow-up.
- **Lineage-generation table is a lossy hash (audit A3; keyed by `serial` per finding 3.3).** The use-after-revoke backstop is now active and precise (serial-keyed, strict-equality, no gen-0 escape hatch). The residual is the 4096-slot hash: distinct serials can collide, so a bump can spuriously invalidate a colliding live cap — availability-only, fails safe. Exact per-serial storage is Roadmap Track 1.
- **Boot modules: content verified, but the manifest lives in the kernel image (audit A4 — fixed).** Coreutils/man-page GRUB modules become root-owned `/bin` executables; the kernel embeds a SHA-256 manifest of exactly the modules it shipped and refuses any mismatch at the `SYS_BOOT_MODULE_INFO`/`_READ` choke point, with a `/bin`+`/usr/share/man` destination allowlist. Residual: full closure depends on pinned/attested builds (P4).
- **Encrypted storage is persistent but early.** Persistent on an attached ATA disk (crypto metadata survives reboot; volume sealed until login; crash-atomic via a write-ahead journal; per-file POSIX ownership/permissions enforced by `fs_server`); a diskless boot still uses the ephemeral RAM vdisk, and scaling the 16 MiB volume much further would want a multi-block inode allocator.
- **The audit log is forward-secure, not absolutely tamper-proof.** History *before* a compromise is cryptographically unforgeable; entries logged *after* a compromise, and whole-machine rollback, still need an external append-only anchor (TPM NV counter / remote WORM) — the honest ceiling for a self-hosting kernel.
- **The multi-core scheduler shares a single runnable pool** (no per-CPU run queues, priorities, or affinity), and **cache partitioning is not done** (flush-on-switch and SMT-parking cover the security-relevant cases; see the side-channel section).

## Development process & governance (the open findings)

The audit's central finding was that the **engineering process** is not yet commensurate with the kernel's high-assurance goals: for a system whose value is *verifiable* isolation, the runtime guarantees are only as trustworthy as the pipeline that builds them. Tracked in [Roadmap Track 0](docs/ROADMAP.md):

- **`main` branch protection (P1, Critical) — enforced.** `main` requires the four hard-gate checks (Rust+clippy, kernel+ISO build, QEMU smoke-boot, reproducible build), enforces the rule for administrators, and blocks force-pushes and deletion. **Required CODEOWNERS review is intentionally deferred** — with a single maintainer it would deadlock every merge (P2); enable it the moment a second reviewer exists.
- **Single-maintainer self-merge (P2) — accepted risk.** No independent review of capability/crypto/paging changes today (bus factor 1). An explicitly accepted limitation until a second reviewer joins.
- **Native scanning (P3) — mostly closed.** Dependabot vulnerability alerts + security updates on (cargo ecosystem monitored); a **CodeQL** workflow scans the C kernel (SARIF → Security tab); secret scanning + push protection on. Remaining: promote a deterministic Kani/fuzz subset to a required check.
- **Reproducibility ≠ provenance (P4) — open.** The reproducible build is deterministic on one runner image but the toolchain is unpinned and artifacts are unsigned; SLSA provenance and a hermetic, pinned build are planned.

Until P2 (independent review) and P4 (pinned, attested builds) close, the build's integrity still leans on the maintainer's workstation.

## Hardening currently in place

**Hardware isolation.** Ring 0/3 separation with per-task page tables. **SMEP** + **SMAP** (ring 0 cannot execute or casually read/write user pages; user copies resolve the physical address under the kernel mapping) and **UMIP** (denying ring 3 `SGDT`/`SIDT`/`SLDT`/`STR`/`SMSW`) are enabled when advertised. `make smoke-cpu` boots under a CPU advertising all three and asserts each is both detected *and* present in CR4 — these were silently disabled for the project's entire history (a stale CPUID subleaf returned zeros), which is why the gate checks CR4 rather than trusting the kernel's own detection.

**W^X for user memory.** `EFER.NXE` + PTE NX: writable pages never executable, user stacks non-executable, ELF `PT_LOAD` `p_flags` honoured (code r-x, data/rodata NX). Shipped userspace is static-PIE and takes this path.

**W^X for the kernel's own image.** `.text` r-x, `.rodata` r-- NX, `.data`/`.bss` rw- NX; the low megabyte, the dead `.boot` stage, and the slack above `.bss` are absent outright. **`CR0.WP` is set** and is not optional: with WP clear a supervisor write ignores the PTE read-only bit, so read-only kernel pages would be advisory for ring 0 — the only ring that can reach them. Until this landed the kernel's own `.text` was writable and `.bss` executable, because `multiboot.S` aliased one no-NX page directory from three entries at once.

**W^X is gated, not asserted.** `make smoke-wx` boots and sweeps **every present leaf** in the address space, failing if any is simultaneously writable and executable (both permissions accumulated across page-table levels), and asserts `CR0.WP` + `EFER.NXE` are engaged. The sweep — not a per-section check — because every W^X hole this kernel had was an *alias*, invisible to any check of `.text`'s own (always-correct) PTE. It found the last violation itself: the LAPIC MMIO registers, mapped W+X outside the image.

**Stack guard pages.** Every ring-3 task's kernel stack, all `MAX_TASKS` slots (task 0 included), the BSP boot stack, the three boot IST fault stacks, and every AP's IST stacks sit above an unmapped guard page, so an overflow faults on the guard. `smoke-wx`/`smoke-wx-smp` assert each guard is absent *and* the stack just above it still present. Only the dead early 32-bit boot stack (unmapped after boot) is uncovered.

**Kernel stack-smashing detection.** Built `-fstack-protector-strong -mstack-protector-guard=global`, ~80 functions carry a canary; a failed check halts (`PANIC: stack smashing detected`, which the smoke harness treats as failure). The guard is drawn from the CSPRNG at boot rather than left at its reproducible compile-time value.

**Image-base ASLR (30 bits).** A static-PIE image is relocated at load to a base drawn from the CSPRNG across a 4 TiB window above 16 GiB (2³⁰ page-aligned positions). The `SYS_SIGACTION` handler-address check is per-task (a handler must lie inside the calling task's own `[image_base, image_end)`), so wider ASLR did not loosen it. `make smoke-aslr` gates the entropy floor.

**Register-file isolation.** Each task's x87/SSE file is saved/restored around every ring-3 kernel entry (FXSAVE/FXRSTOR into the TCB); the kernel is `-mno-sse -mno-mmx -mno-80387` with no FPU state of its own to leak. `make smoke-fs-conc` is the regression test.

**Centralised syscall authorisation.** Dispatch is a descriptor table enforcing each syscall's required capability at one choke point; an unlisted number fails closed; a `_Static_assert` prevents adding a syscall without a table slot.

**No ambient authority.** Revoke requires `CAP_RIGHT_REVOKE`, mint/transfer require `CAP_RIGHT_MINT`; a non-kernel task with no cspace is refused, not defaulted to the kernel root. Revocation is system-wide, descendant-only, and bumps the lineage generation. Task slots are zeroed on reuse (`create_task` clears all 256 slots), so an inheriting task cannot acquire the dead task's `CAP_USER`/`CAP_CONSOLE`/`CAP_ENCRYPTED_STORAGE`.

**Least-privilege process control.** A spawned child returns its `CAP_TCB` only to the spawner; `SYS_KILL`, `SYS_SIGNAL`, and `SYS_CAP_GRANT` are gated on holding it (or `CAP_USER`). Grant goes through the locked, accounted, rights-masked path (A2).

**FFI integrity.** The C and Rust capability layouts are pinned by mirrored compile-time assertions; the page-refcount table is registered once and any later inc/dec presenting a different (pointer, length) is refused.

**Attacker-facing parsing in memory-safe Rust.** The entire ELF loader parse — header, program headers, and both i386 and x86-64 relocations — runs in the safe `no_std` core (the C loader keeps only the privileged mapping and copies), which fixed two real out-of-bounds reads. Parts carry Kani proofs and `cargo-fuzz` fuzzers (advisory CI).

**Driver privilege separation (console).** The highest-risk ring-3-reachable driver — the VGA/serial console, which parses input and handles password entry — runs as a ring-3 server (`console_server`) holding only its own `CAP_IO_DEVICE`, which gates the three mechanisms it uses (map an allowlisted device frame, native port I/O via a per-task TSS I/O bitmap, an IRQ→notification bridge). A bug in it is an ordinary ring-3 fault (`make smoke-console-isolation`). First step of shrinking the kernel's flat trust domain; other drivers have not yet followed.

**Encryption-at-rest.** One ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust (`aead.rs`), independent HKDF enc/mac subkeys, fresh random per-write nonce, `(ino, block)` bound as AAD, constant-time fail-closed verification — so a block cannot be replayed at a different offset or inode.

**No ring-3 code in ring 0.** `SYS_REGISTER_STORAGE_BACKEND` (which used to register userspace function pointers the kernel called from ring 0) fails closed; any storage/FS provider runs as a ring-3 IPC server.

**Forward-secure audit log.** Each entry's MAC and the running chain head are keyed by an evolving key that is ratcheted one-way and **erased in place** after each entry, so a kernel compromised at time _t_ cannot forge any entry committed before _t_. A running hash-chain head commits to the whole ordered history (verified externally via `SYS_AUDIT_DIGEST`); an unkeyed sliding-window hash still self-checks the retained ring for accidental corruption. Logic in safe Rust (`audit.rs`).

**Measured boot + TPM-sealed storage.** A minimal TPM 2.0 TIS driver records the reproducible boot hash chain (`PCR[8]` kernel identity, `PCR[9]` each verified module). A TPM-formatted volume's `disk_key` KEK is two-factor `HKDF(password-KEK, tpm_secret)`, where `tpm_secret` is TPM2-sealed under `PolicyPCR(PCR[8],PCR[9])` and released only by a measured-good boot (TPM-enforced). No-TPM machines are unaffected. Gated by `make smoke-tpm{,-tamper,-seal,-seal-roundtrip}`.

**Signals grant no new authority.** A handler runs at ring 3 with unchanged privileges; the entry is validated in safe Rust against the task's own image window; a fault inside a handler is not re-delivered; async cross-task signalling requires a `CAP_TCB` on the target (same authority as killing it).

**Filesystem reference monitor (zero-trust ownership).** The ring-3 `fs_server` is the single filesystem and enforces per-file POSIX rwx/ownership against the caller's kernel-attested identity (`SYS_IPC_SENDER`, unforgeable), with root the only ambient authority; only the server holds the object-store capability. The weaker in-memory capfs is removed (its syscalls fail closed).

**Account & password hygiene.** Accounts without an explicit initial password get a CSPRNG-random hash no Argon2id invocation matches (locked until `SYS_PASSWD`); changes persist; `h_passwd`/`h_auth` scrub cleartext with `secure_zero`.

**Supply chain / CI.** Every change is gated by **52 CI jobs** (three advisory: the `security` SAST/SBOM scan, `fuzz`, and `kani` — they never block a merge): `cargo test` (91 unit tests) + `clippy -D warnings`; a kernel + ISO build; an alt-config matrix; ~45 headless QEMU self-tests (boot, the kernel W^X leaf sweep single- and multi-core, the CR4 protections, `CR4.TSD`, stack guards, E820 pool sizing, ELF/W^X for both ELF classes, image-base ASLR, preemption, signals, process-control, COW/non-zero-COW, notifications, address-space reclaim, flush-on-switch, SMT parking, capability conformance, a scripted ring-3 shell session single- and multi-core, the filesystem/libc suite, pipes, the driver-isolation suite, TPM measured boot + sealing, and the coreutils-from-the-filesystem tests); a byte-for-byte reproducible-build check; and the advisory scan + CycloneDX SBOM.

The security-critical primitives live in safe `no_std` Rust and carry unit tests; the rest of the kernel is C and has **not** undergone systematic fuzzing or third-party review.

---

## Cryptography & entropy

Audited-standard algorithms in safe Rust, validated against published known-answer vectors:

- **Password hashing:** Argon2id (RFC 9106) on the crate's own BLAKE2b, validated against `argon2-cffi` vectors; multi-lane capable (validated at p=2/p=4); cost configurable (`ARGON2_M_COST_KIB`/`_T_COST`/`_P_COST`), the kernel runs 4 MiB / 3 passes / 1 lane; per-user salt + per-boot pepper folded in, raw 32-byte tag stored.
- **User-database integrity:** HMAC-SHA256 over the serialized records, keyed by the per-boot pepper.
- **Audit-log integrity:** forward-secure — each entry's MAC and the chain head are keyed by a one-way-ratcheted, erased-in-place key (`audit.rs`). Pre-compromise history is unforgeable; verification is external via the chain head.
- **Key derivation** (per-file / per-block / user master / volume / TPM-mode KEK): HKDF-SHA256 (RFC 5869) with context binding.
- **Encryption-at-rest:** ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD, fresh 96-bit nonce per write, 128-bit tag verified constant-time, fail-closed.
- **Randomness:** one ChaCha20 fast-key-erasure CSPRNG, reseeded at boot from RDRAND (with retry + health check), TSC jitter, and boot counters. All salts, peppers, nonces, keys, and the ASLR seed draw from this pool; raw TSC is never used directly as randomness; the pool is asserted seeded before any key material is derived.

---

## Side-channel threat model

Horus preempts and switches between mutually distrusting ring-3 tasks on one core and — SMP default-on — across cores.

**Architectural** state is isolated across the switch: general-purpose registers in the per-task trap frame, x87/SSE saved/restored around every ring-3 kernel entry; the kernel holds no FPU state of its own.

**Microarchitectural** state — Horus mitigates the practical cases and is explicit about the rest:

- **Timestamp counter:** ring-3 `RDTSC`/`RDTSCP` is disabled via **`CR4.TSD`** (`cpu_enable_protections`), so the highest-resolution timer a cache/covert-channel attack leans on raises `#GP` at ring 3 and is delivered as a fault signal. Horus exposes no userspace timing API; ring 0 keeps `RDTSC` (TSD gates CPL>0 only). Partial: coarser timers / counting-thread constructions remain. `make smoke-tsd`.
- **Flush-on-context-switch:** on a switch to a *different* ring-3 task the kernel evicts the microarchitectural state the incoming task could snoop the outgoing one with — the indirect-branch predictor (**IBPB**), the L1 data cache (**L1D_FLUSH**), and the store/fill/load buffers (**MDS**, via `VERW`). It hooks the single switch chokepoint (`set_current_task`) so no path bypasses it; each barrier is CPUID-gated (a safe no-op otherwise); same-task resumes and idle-task switches are skipped. `make smoke-flush` gates detection + policy (the barriers engage on hardware/KVM; TCG does not emulate them).
- **SMT co-residency:** flush-on-switch covers *time-sliced* co-tenancy; a sibling hyperthread sharing L1/L2 *concurrently* is covered by **disabling SMT in software** — at AP bringup a secondary thread (non-zero SMT bits per CPUID leaf 0x0B) is **parked** (TLB-coherent, services shootdown IPIs, never starts its scheduler timer or runs a task), so no untrusted work co-resides on a core. Boot logs `smp: N cores online, K SMT siblings parked`; `make smoke-smt`. **Residual:** cache *partitioning* is not done — the primary thread's own successive tasks share a warmed cache between the flush and the next eviction.
- **Constant-time comparisons** for password-hash and MAC/tag checks; **secret zeroization** (`secure_zero`, volatile) after use; **RNG health** (RDRAND retried, degenerate all-zeros/all-ones rejected; hardware output mixed with timing entropy so one failed source cannot zero the pool).

---

## Reporting a vulnerability

If you find a security issue not already in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), report it responsibly rather than disclosing publicly first.

**How:** open a GitHub Security Advisory (Settings → Security → Advisories → New draft advisory) — a private thread visible only to maintainers. Include: a description and affected component; reproduction / PoC if applicable; your impact assessment; whether you want credit. We aim to acknowledge within a few days and respond substantively within two weeks.

## Scope

**In scope:** capability-system bypass; memory-safety issues in the C kernel or Rust FFI boundary; authentication bypass; Ring 3 → Ring 0 privilege escalation; a task terminating/signalling/endowing another without the required `CAP_TCB`.

**Out of scope (known and documented):** absence of cache *partitioning* and complete covert-channel elimination; SMP scheduler *performance* maturity (single shared run queue, no per-CPU queues/priorities/affinity); the audit log's post-compromise/rollback ceiling; unpinned/unsigned build provenance.

## Supported versions

No stable releases yet. Security fixes are applied to the `main` branch only.
