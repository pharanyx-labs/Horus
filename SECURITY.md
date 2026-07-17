# Security Policy

## Project security posture

Horus is a **research microkernel** in early development. It is not suitable for use in production environments or for handling sensitive workloads. The security properties described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) reflect the design intent; several of them are not yet fully realised. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) describes the current gaps honestly.

Known weaknesses include:

- SMP works behind the `SMP=1` build gate but is not default-on; the multi-core scheduler shares a single runnable pool (no per-CPU run queues, no priorities), and there is no flush-on-switch between mutually distrusting tasks
- Load-base ASLR is applied (userspace is static-PIE, relocated at a random base), but image-base entropy is bounded (~9 bits) — now by page-table geometry (the premap must fit one 2 MiB PD entry), not by the ABI: userspace is 64-bit and the kernel is in the higher half
- Encrypted storage is persistent by default when an ATA disk is present (crypto metadata survives reboot; volume sealed until login; multi-block updates crash-atomic via a write-ahead journal; per-file POSIX ownership/permissions enforced by the `fs_server`), but diskless boots still use the ephemeral RAM vdisk and volumes are size-capped at 2 MiB by single-bitmap geometry
- The audit log is tamper-*evident* (an HMAC chain detects modification), not tamper-*proof* — an attacker who can read the per-boot key can recompute a consistent chain (see the audit-log note below)

These are not undisclosed vulnerabilities — they are documented, known limitations of an incomplete system.

## Hardening currently in place

The following are implemented and enforced today:

- **Hardware isolation:** Ring 0/3 separation with per-task page tables; **SMEP** and **SMAP** enabled when advertised (ring 0 cannot execute, and cannot casually read/write, user pages — user copies resolve the physical address under the kernel mapping rather than dereferencing a user virtual address). **UMIP** enabled when advertised, denying ring 3 the `SGDT`/`SIDT`/`SLDT`/`STR`/`SMSW` instructions, which are unprivileged but disclose the linear addresses of the GDT, IDT, LDT and TSS. A gating CI job (`make smoke-cpu`) boots under a CPU that advertises all three and asserts each is both detected *and* present in CR4 — these were claimed here while silently disabled for the project's entire history (a stale CPUID subleaf made the feature query return zeros), and asking the kernel what it detected could not have caught it.
- **W^X for user memory:** `EFER.NXE` is enabled and the kernel sets the PTE NX bit so a writable page is never executable. User stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags` (code read+execute, data/rodata no-execute). The shipped userspace is static-PIE and takes this path; a flat-binary fallback (kept executable) remains for non-ELF images.
- **W^X for the kernel's own image:** the kernel maps itself `.text` read-only + executable, `.rodata` read-only + NX, `.data`/`.bss` writable + NX, with the low megabyte, the dead `.boot` stage and the slack above `.bss` absent outright. Until this landed the kernel's own `.text` was *writable* and its `.bss` *executable*: `multiboot.S` builds one page directory of 2 MiB `P|W` pages with no NX and aliases it from three entries at once (the identity map, the PHYS_KVA window, and the kernel's own mapping), so tightening any view tightened all three. The kernel's mapping now has a page directory of its own, split to 4 KiB so section boundaries are expressible. **`CR0.WP` is set as part of this** and is not optional: with WP clear — as it had been since boot — a supervisor write ignores the PTE read/write bit entirely, so read-only kernel pages would be enforced against ring 3 and disregarded for ring 0, the only ring that can reach them. NX needs no such switch, which is why the executable half of the policy would have worked and the read-only half would not.
- **Stack-smashing detection in the kernel:** built with `-fstack-protector-strong`, so ~80 functions carry a canary below their return address; a failed check halts the machine rather than returning through a corrupted frame (`PANIC: stack smashing detected`, which the smoke harness treats as a failure, so a smash anywhere turns CI red). The guard is drawn from the CSPRNG at boot rather than left at its compile-time value — the build is reproducible, so a fixed canary is a *published* constant that stops accidents but not anyone who has read the binary. Note this requires `-mstack-protector-guard=global`: GCC's x86-64 default reads the canary from `%gs:0x28`, which in a kernel with no per-CPU GS base is a garbage address.
- **W^X is gated, not asserted:** `make smoke-wx` (a gating CI job) boots the kernel and sweeps **every present leaf in the address space**, failing if any is simultaneously writable and executable — accumulating both permissions across page-table levels, since NX at any level vetoes execute below it and (with `CR0.WP`) a clear write bit at any level refuses writes below it. The sweep rather than a per-section check, because every W^X hole this kernel had was an *alias*: a second mapping of the same frames with different bits, invisible to any check of `.text`'s own PTE — which was always correct. It also asserts `CR0.WP` and `EFER.NXE` are engaged, since the bits are only a policy if the CPU applies them. The sweep found the last violation itself: the LAPIC's MMIO registers were mapped writable *and* executable, outside the kernel image where no per-section check would ever have looked.
- **Centralised syscall authorisation:** dispatch is a descriptor table that enforces each syscall's required capability at a single choke point; an unlisted syscall number fails closed, and a compile-time assertion prevents adding a syscall without a table slot.
- **No ambient authority:** capability revoke requires `CAP_RIGHT_REVOKE` on the target and mint/transfer require `CAP_RIGHT_MINT`; a non-kernel task with no cspace is refused rather than defaulting to the kernel root cnode. Revocation is system-wide (every task's cspace plus the kernel root) and bumps the lineage generation, so derived copies in other tasks cannot outlive their parent.
- **Least-privilege process control:** a spawned child returns its `CAP_TCB` only to the spawner. `SYS_KILL`, `SYS_SIGNAL`, and `SYS_CAP_GRANT` on a task are gated on holding that `CAP_TCB` (or `CAP_USER` admin), so a task cannot terminate, signal, or endow another task it was not given authority over. A supervisor delegates one cap slot at a time into a child's cspace with `SYS_CAP_GRANT`.
- **Use-after-revoke / TOCTOU:** per-lineage generation counters invalidate stale capabilities; a snapshot + revalidate-at-use guard is wired into the IPC send/recv paths so a revoke during a lookup/use window aborts the operation.
- **FFI integrity:** the C and Rust capability layouts are pinned by mirrored compile-time assertions; the page refcount table is registered once and any later inc/dec presenting a different (pointer, length) is refused, not trusted.
- **Encryption-at-rest:** the block-storage layer uses one ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust (`rust/src/aead.rs`), with independent HKDF-SHA256 enc/mac subkeys, a fresh random per-write nonce, context bound as AAD, and constant-time fail-closed verification. It keys per block and binds `(ino, block)` as AAD, so a block cannot be replayed at a different offset or inode.
- **No ring-3 code in ring 0:** `SYS_REGISTER_STORAGE_BACKEND` — which used to register userspace function pointers the kernel called from ring 0 — fails closed; any userspace storage/FS provider must run as a ring-3 IPC server (as `fs_server` does).
- **Tamper-evident audit log:** every audit entry is bound by an HMAC keyed to the per-boot secret pepper (the MAC binds the entry's absolute sequence number, so an in-place edit, a ring-slot swap, or a replay no longer verifies), and a running hash-chain head commits to the *entire* ordered history — including entries already overwritten in the ring. `SYS_AUDIT_DIGEST` (a `CAP_AUDIT`-gated read) returns the event count, the chain-head MAC, and a constant-time verify status. The keyed-hash logic lives in safe Rust (`rust/src/audit.rs`).
- **Signals grant no new authority:** a task may register *its own* ring-3 handler (`SYS_SIGACTION`) so a fault or an async signal is delivered to it instead of killing it outright. The handler entry is validated to the user code window in safe Rust (fail-closed), a fault *inside* a handler is not re-delivered (no loops), and the handler runs at ring 3 with unchanged privileges — the worst a malformed handler can do is fault again and terminate its own task. Async cross-task signalling (`SYS_SIGNAL`) requires a `CAP_TCB` on the target, the same authority as killing it, so it opens no new cross-task reach.
- **Capability space zeroed on task-slot reuse:** `cspace_pool` is a static array; when a task exits and its slot is reused, `create_task` zeroes all 256 capability slots before installing the new task's initial capabilities, preventing an inheriting task from acquiring the dead task's `CAP_USER`, `CAP_CONSOLE`, or `CAP_ENCRYPTED_STORAGE`.
- **Filesystem reference monitor (zero-trust ownership):** the ring-3 `fs_server` is the single filesystem and enforces per-file POSIX owner/group/other rwx and ownership against the caller's *kernel-attested* identity. `SYS_IPC_SENDER` returns the sending task's login uid/gid taken from `tasks[]` — set at login, never from anything the client puts in the request — so a client cannot forge who it is; root (uid 0) is the only ambient authority (`chmod` owner-or-root, `chown` root-only). Only the server holds the object-store capability, so a client cannot reach the store directly or bypass the checks. The earlier parallel in-memory capfs (with its own weaker permission model and no persistence) has been **removed** — its syscalls fail closed — shrinking the ring-3 filesystem attack surface to one.
- **Account and password hygiene:** accounts created without an explicit initial password get a CSPRNG-random `pass_hash` that no Argon2id invocation can match (locked until `SYS_PASSWD`); password changes persist across reboots; `h_passwd`/`h_auth` scrub their cleartext buffers with `secure_zero` before returning.
- **Supply chain / CI:** every change is gated by a pipeline of 24 jobs (23 gating) — `cargo test`, `clippy` with all warnings denied, a kernel + ISO build, an alt-config build matrix (`DEBUG_SHELL=1`, `MINIMAL_SECURE=1`), nineteen headless QEMU self-tests (boot, ELF-loader + W^X for both ELF classes, image-base ASLR, preemption, signals, process-control, copy-on-write, notifications, SMP, a scripted ring-3 shell session, and the filesystem/libc suite), a byte-for-byte reproducible-build check, and an advisory security-scan job (Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`) that also emits a CycloneDX SBOM.

The security-critical primitives (capabilities, memory refcounting, hashing, RNG, FFI validation) live in safe `no_std` Rust and carry unit tests; the rest of the kernel is C and has **not** undergone systematic fuzzing or third-party review.

---

## Cryptography & entropy (current implementation)

The security-sensitive primitives are audited-standard algorithms implemented in safe Rust and validated against published known-answer vectors:

- **Password hashing:** Argon2id (RFC 9106), the memory-hard KDF, implemented from scratch in safe Rust on the crate's own BLAKE2b (`rust/src/argon2.rs`, `blake2b.rs`) and validated against the `argon2-cffi` reference vectors. Multi-lane capable (`p ≥ 1`, validated at p=2/p=4); cost is configurable (`ARGON2_M_COST_KIB`/`_T_COST`/`_P_COST` in `kernel.h`) and the kernel runs 4 MiB / 3 passes / 1 lane. A per-user random salt and a per-boot secret pepper are folded in; the raw 32-byte tag is stored.
- **User database integrity:** HMAC-SHA256 over the serialized records, keyed by the per-boot pepper.
- **Audit-log integrity:** each entry carries `HMAC(pepper, LE64(seq) || event)` and the log keeps a running chain head `HMAC(pepper, head || mac)` over every event ever appended (`rust/src/audit.rs`). This is an integrity *detector* and defence-in-depth: it defeats tampering by code that cannot read the pepper, and lets an external monitor recording the chain head detect drops, rewrites, and rollbacks. It is **not** a guarantee against a full kernel compromise that can read the pepper.
- **Key derivation** (per-file keys, per-block keys, user file master keys, volume key): HKDF-SHA256 (RFC 5869) with context binding.
- **Encryption-at-rest:** a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`), composed from the crate's RFC-tested ChaCha20 and HMAC primitives. Every write draws a fresh random 96-bit nonce, uses independent HKDF enc/mac subkeys, binds context as AAD, verifies the 128-bit tag in constant time, and fails closed (buffer zeroed) on any authentication failure. Its one caller is the **block-storage** layer, which keys per block and binds `(ino, block)` as AAD.
- **Randomness:** a single ChaCha20 fast-key-erasure CSPRNG, reseeded at boot from RDRAND (with retry + health check when advertised), TSC jitter, and boot counters. All salts, peppers, nonces, per-file keys, and the ASLR PRNG seed are drawn from this pool. Raw TSC is never used directly as randomness. The pool is asserted seeded at boot before any key material is derived.

---

## Side-channel threat model

Horus preempts and switches between mutually distrusting ring-3 tasks on a single core, and — under `SMP=1` — across cores.

**Architectural** state is isolated across that switch: general-purpose registers live in the per-task trap frame, and the x87/SSE register file is saved/restored around every ring-3 kernel entry (`FXSAVE`/`FXRSTOR` into the TCB), so one task cannot read what another left in `xmm`. The kernel itself is built `-mno-sse -mno-mmx -mno-80387`, so it has no FPU state of its own to leak into ring 3 either. (This was not always true — see CHANGES.md; it was latent for as long as userspace was i386 and could not hold a live `xmm` across a syscall.)

**Microarchitectural** state is a different matter, and Horus makes no claim of resistance:

- **Timestamp counter (TSC):** `rdtsc` is readable from ring 3, so the kernel treats it as *public* and never uses it as a source of secret randomness — only as one whitened input to the CSPRNG. Disabling ring-3 `rdtsc` via `CR4.TSD` is a possible future mitigation but breaks userspace timing APIs.
- **Constant-time comparisons:** password-hash and MAC/tag comparisons use a data-independent accumulating compare (`constant_time_compare`) to avoid early-exit timing oracles.
- **Secret zeroization:** derived keys and intermediate key material are wiped with `secure_zero` (volatile, non-elidable) after use.
- **Cache partitioning / flush-on-context-switch:** not implemented. A context switch between distrusting tasks (single-core time-slicing or cross-core under SMP) should ideally flush or partition shared microarchitectural state (L1D, BTB); this is not yet done and is tracked as future hardening.
- **RNG health:** RDRAND draws are retried and rejected on the degenerate all-zeros / all-ones outputs a stuck hardware RNG would emit; the CSPRNG mixes hardware output with timing entropy so a single failed source cannot zero the pool.

---

## Reporting a vulnerability

If you discover a security issue in Horus that is not already documented in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), please report it responsibly rather than disclosing it publicly right away.

**How to report:** open a GitHub Security Advisory in this repository (Settings → Security → Advisories → New draft advisory). This creates a private thread visible only to repository maintainers.

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
- A task terminating, signalling, or endowing another task without the required `CAP_TCB`

The following are out of scope for now, because they are known and documented:

- Bounded load-base ASLR entropy (userspace is static-PIE with a randomised base, but the premap must fit one 2 MiB PD entry, so ~9 bits)
- Absence of covert-channel / cache side-channel mitigations
- SMP scheduler maturity (works behind `SMP=1`; not default, no per-CPU queues/priorities)

---

## Supported versions

There are no stable releases yet. Security fixes are applied to the `main` branch only.
