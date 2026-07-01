# Security Policy

## Project security posture

Horus is a **research microkernel** in early development. It is not suitable for use in production environments or for handling sensitive workloads. The security properties described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) reflect the design intent; several of them are not yet fully implemented. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) describes the current gaps honestly.

Known weaknesses include:

- SMP and preemptive scheduling are not yet implemented
- Load-base ASLR is not applied (userspace binaries are non-PIE)
- Disk-backed persistent storage is not the live backing store (the filesystem is in-memory); the encrypted-block path, though now cryptographically sound, is not yet wired in as the default
- The audit log is tamper-*evident* (an HMAC chain detects modification), not tamper-*proof* — an attacker who can read the per-boot key can recompute a consistent chain (see the audit-log note below)

These are not undisclosed vulnerabilities — they are documented, known limitations of an incomplete system.

## Hardening currently in place

For balance, the following are implemented and enforced today (single-core, cooperative build):

- **Hardware isolation:** Ring 0/3 separation with per-task page tables; **SMEP** and **SMAP** enabled when advertised (ring 0 cannot execute, and cannot casually read/write, user pages — user copies resolve the physical address under the kernel mapping rather than dereferencing a user virtual address).
- **W^X for user memory:** `EFER.NXE` is enabled and the kernel sets the PTE NX bit so a writable page is never executable. User stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags` (code read+execute, data/rodata no-execute). The flat-binary fallback (the shipped, non-ELF userspace) keeps its image executable; its boot is covered by the smoke-boot test.
- **Centralised syscall authorisation:** dispatch is a descriptor table that enforces each syscall's required capability at a single choke point; an unlisted syscall number fails closed, and a compile-time assertion prevents adding a syscall without a table slot.
- **No ambient authority:** capability revoke requires `CAP_RIGHT_REVOKE` on the target and mint/transfer require `CAP_RIGHT_MINT`; a non-kernel task with no cspace is refused rather than defaulting to the kernel root cnode. Revocation is system-wide (every task's cspace plus the kernel root) and bumps the lineage generation, so derived copies in other tasks cannot outlive their parent.
- **Use-after-revoke / TOCTOU:** per-lineage generation counters invalidate stale capabilities; a snapshot + revalidate-at-use guard is wired into the IPC send/recv paths so a revoke during the cooperative yield aborts the operation.
- **FFI integrity:** the C and Rust capability layouts are pinned by mirrored compile-time assertions; the page refcount table is registered once and any later inc/dec presenting a different (pointer, length) is refused, not trusted.
- **Encryption-at-rest:** block encryption is a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust, with per-block HKDF subkeys, a fresh random per-write nonce, `(ino, block)` bound as AAD, and constant-time fail-closed verification. (Replaced a hand-rolled non-AES "AES-128".)
- **No ring-3 code in ring 0:** `SYS_REGISTER_STORAGE_BACKEND` — which used to register userspace function pointers the kernel called from ring 0 — fails closed; any userspace storage/FS provider must run as a ring-3 IPC server.
- **Audit trail:** capability mint/transfer/move/revoke (and the FS/auth paths) record their outcome to the audit log.
- **Tamper-evident audit log:** every audit entry is bound by an HMAC keyed to the per-boot secret pepper (the MAC binds the entry's absolute sequence number, so an in-place edit, a ring-slot swap, or a replay no longer verifies), and a running hash-chain head commits to the *entire* ordered history — including entries already overwritten in the ring. `SYS_AUDIT_DIGEST` (a `CAP_AUDIT`-gated read) returns the event count, the chain-head MAC, and a constant-time verify status, so an external monitor can detect dropped, rewritten, or rolled-back events over time. The keyed-hash logic lives in safe Rust (`rust/src/audit.rs`).
- **Supply chain / CI:** every change is gated by a CI pipeline of seven jobs — `cargo test`, `clippy` with all warnings denied, a kernel + ISO build, an alt-config build matrix (`DEBUG_SHELL=1`, `MINIMAL_SECURE=1`), a headless QEMU smoke-boot, an ELF-loader + W^X boot self-test, a byte-for-byte reproducible-build check, and a security-scan job (Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`) that also emits a CycloneDX SBOM.

The security-critical primitives (capabilities, memory refcounting, hashing, RNG, FFI validation) live in safe `no_std` Rust and carry unit tests; the rest of the kernel is C and has **not** undergone systematic fuzzing or third-party review.

---

## Cryptography & entropy (current implementation)

As of the crypto/entropy hardening pass, the security-sensitive primitives are
audited-standard algorithms implemented in safe Rust (`rust/src/sha256.rs`,
`rust/src/rng.rs`) and validated against published known-answer vectors:

- **Password hashing:** PBKDF2-HMAC-SHA256 (RFC 8018), 120 000 iterations, with a
  per-user random salt and a per-boot secret pepper folded into the salt. The
  raw 32-byte derived key is stored. (Replaces the previous custom 4096-round
  XOR-rotate scheme.)
- **User database integrity:** HMAC-SHA256 over the serialized records, keyed by
  the per-boot pepper.
- **Audit-log integrity:** each entry carries `HMAC(pepper, LE64(seq) || event)`
  and the log keeps a running chain head `HMAC(pepper, head || mac)` over every
  event ever appended (`rust/src/audit.rs`). This is an integrity *detector* and
  defence-in-depth: it defeats tampering by code that cannot read the pepper
  (stray writes, logic bugs, a confined task reading the log), and lets an
  external monitor that records the chain head detect drops, rewrites, and
  rollbacks. It is **not** a guarantee against a full kernel compromise that can
  read the pepper — the same accepted limit as the user-database tag above.
- **Key derivation** (per-file keys, per-block keys, user file master keys,
  volume key): HKDF-SHA256 (RFC 5869) with context binding.
- **Encryption-at-rest:** a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD
  (`rust/src/aead.rs`), composed from the crate's RFC-tested ChaCha20 and HMAC
  primitives (no new primitive cryptography). Each block write draws a fresh
  random 96-bit nonce (so a rewrite never reuses a keystream), uses independent
  per-block HKDF enc/mac subkeys, binds `(ino, block)` as AAD, verifies the
  128-bit tag in constant time, and fails closed (the buffer is zeroed) on any
  authentication failure. This replaced a hand-rolled "AES-128" that was not in
  fact AES (broken AES-NI key schedule + an unaudited ARX software fallback).
- **Randomness:** a single ChaCha20 fast-key-erasure CSPRNG, reseeded at boot
  from RDRAND (with retry + health check, when CPUID advertises it), TSC jitter,
  and boot counters. All salts, peppers, nonces, per-file keys, and the ASLR
  PRNG seed are drawn from this pool. Raw TSC is never used directly as
  randomness (it is readable from ring 3 and therefore predictable). The pool is
  asserted seeded at boot before any key material is derived.

---

## Side-channel threat model

Horus runs single-core and cooperatively today, so classic cross-core cache and
SMT side channels do not yet apply. The following are tracked for when
preemption / SMP land:

- **Timestamp counter (TSC):** `rdtsc` is readable from ring 3. The kernel
  therefore treats it as *public* and never uses it as a source of secret
  randomness — only as one (whitened) input to the CSPRNG, whose output an
  attacker cannot reconstruct from TSC alone. Disabling ring-3 `rdtsc` via
  `CR4.TSD` is a possible future mitigation but breaks userspace timing APIs.
- **Constant-time comparisons:** password-hash and MAC/tag comparisons use a
  data-independent accumulating compare (`constant_time_compare`) to avoid
  early-exit timing oracles.
- **Secret zeroization:** derived keys and intermediate key material are wiped
  with `secure_zero` (volatile, non-elidable) after use.
- **Cache partitioning / flush-on-context-switch:** not implemented. On a future
  preemptive or SMP build, a context switch between mutually distrusting tasks
  should flush or partition shared microarchitectural state (L1D, BTB) to limit
  Spectre/Meltdown-class leakage. This is deferred and explicitly out of scope
  for the current single-core build.
- **RNG health:** RDRAND draws are retried and rejected on the degenerate
  all-zeros / all-ones outputs a stuck hardware RNG would emit; the CSPRNG mixes
  hardware output with timing entropy so a single failed source cannot zero the
  pool.

---

## Reporting a vulnerability

If you discover a security issue in Horus that is not already documented in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), please report it responsibly rather than disclosing it publicly right away.

**How to report:**

Open a GitHub Security Advisory in this repository (Settings → Security → Advisories → New draft advisory). This creates a private thread visible only to repository maintainers.

Include:

- A description of the issue and the component it affects
- Steps to reproduce or a proof-of-concept if applicable
- Your assessment of the impact
- Whether you want to be credited in the fix

We will acknowledge the report within a few days and aim to respond substantively within two weeks.

---

## Scope

Given the project's status, the following are in scope for responsible disclosure:

- Bugs in the capability system that allow a task to bypass access control
- Memory safety issues in the C kernel or Rust FFI boundary
- Authentication bypass in the user authentication path
- Privilege escalation from Ring 3 to Ring 0

The following are out of scope for now, because they are known and documented:

- Missing load-base ASLR (userspace is non-PIE; stack and heap are randomized)
- Absence of covert-channel / cache side-channel mitigations (single-core today)
- Missing preemption or SMP support
- Stub implementations that return errors

---

## Supported versions

There are no stable releases yet. Security fixes are applied to the `main` branch only.
