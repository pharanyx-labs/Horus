# Security Policy

## Project security posture

Horus is a **research microkernel** in early development. It is not suitable for use in production environments or for handling sensitive workloads. The security properties described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) reflect the design intent; several of them are not yet fully implemented. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) describes the current gaps honestly.

Known weaknesses include:

- The audit log has no integrity protection
- SMP and preemptive scheduling are not yet implemented
- Bulk block encryption still uses an AES-CTR implementation whose AES-NI key
  schedule is not a correct AES-128 expansion (see "Remaining crypto work")
- Load-base ASLR is not applied (userspace binaries are non-PIE)

These are not undisclosed vulnerabilities — they are documented, known limitations of an incomplete system.

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
- **Key derivation** (per-file keys, per-block keys, user file master keys):
  HKDF-SHA256 (RFC 5869) with context binding.
- **Block authentication:** HMAC-SHA256 (truncated to 128 bits), encrypt-then-MAC.
- **Randomness:** a single ChaCha20 fast-key-erasure CSPRNG, reseeded at boot
  from RDRAND (with retry + health check, when CPUID advertises it), TSC jitter,
  and boot counters. All salts, peppers, nonces, per-file keys, and the ASLR
  PRNG seed are drawn from this pool. Raw TSC is never used directly as
  randomness (it is readable from ring 3 and therefore predictable).

### Remaining crypto work

- The AES-128 block routine used for CTR-mode bulk encryption
  (`crypto_aes128_block_encrypt`) has an incorrect key schedule on the AES-NI
  path; confidentiality of stored block data should not be relied upon until it
  is replaced with a correct AES-128 (or a ChaCha20 stream). The KDF and MAC
  around it are now sound.

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
- The known-incorrect AES-128 key schedule on the bulk-encryption path
- Missing preemption or SMP support
- Stub implementations that return errors

---

## Supported versions

There are no stable releases yet. Security fixes are applied to the `main` branch only.
