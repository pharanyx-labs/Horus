# Horus — Current Limitations

This document is an honest account of what Horus does and does not do. The goal is to prevent anyone from drawing incorrect conclusions about its readiness or security properties.

Horus is a research and learning project. It is not a production operating system and makes no claim to be one. Where this document and the code disagree, the code is the source of truth — please open an issue.

---

## What actually works

These subsystems are functional in the current codebase:

- **Boot sequence** — Multiboot2 boot via GRUB2 into x86-64 long mode
- **VGA terminal** — text mode, colour output, kernel log buffer, serial mirror
- **Hardware isolation** — Ring 0/Ring 3 separation, per-task page tables, user/kernel memory split. SMEP and SMAP are enabled when the CPU advertises them (ring 0 cannot execute or casually read user pages; user copies go through a kernel mapping rather than the user mapping), and the boot CPU brings these up after feature detection.
- **W^X for user memory** — `EFER.NXE` is on and the kernel sets the PTE NX bit so writable pages are never executable: user stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags` (code read+execute, data/rodata read[+write]+no-execute). The W^X policy decision lives in Rust and is unit-tested; the live shell boot (which runs through the flat-binary fallback) is covered by the smoke-boot test.
- **Capability mint, transfer, and revoke** — the core capability operations work, including transitive revocation across every task's cspace and the kernel root cnode. Revocation requires `CAP_RIGHT_REVOKE` on the target (mint/transfer require `CAP_RIGHT_MINT`); a "no ambient authority" guard refuses cap operations from any non-kernel task that lacks its own cspace.
- **Lineage tracking** — use-after-revoke is prevented via per-lineage generation counters; a looked-up capability can be snapshotted and re-validated at point of use (wired into the IPC send/recv paths to close a lookup/use TOCTOU window across the cooperative yield).
- **Capability/FFI integrity** — the C `capability_t` and Rust `Capability` layouts are pinned by mirrored compile-time assertions; the refcount table is registered once and every later inc/dec must present the exact (pointer, length) or is refused.
- **User authentication** — login, lockout after failed attempts, per-user UID assignment
- **Audit log** — kernel-side circular buffer of security events; capability mint/transfer/move/revoke and the FS/auth paths record outcomes. The log is **tamper-evident**: each entry is HMAC'd (binding its sequence number) and a running hash-chain head commits to the whole ordered history, both keyed by the per-boot pepper (`rust/src/audit.rs`); `SYS_AUDIT_DIGEST` returns the digest + constant-time verify status. See the security note below for the scope (detector, not tamper-proof).
- **Keyboard input** — PS/2 scancode translation, key buffer
- **Preemptive round-robin scheduling** — the timer (PIT at 100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch, so CPU-bound tasks time-share without cooperating. A tick that lands in ring 0 never switches (the kernel stays effectively non-preemptible, avoiding lock/reentrancy hazards). Proven at runtime by `make smoke-preempt`, which spawns two non-yielding tracers and asserts they interleave. (The legacy cooperative `yield()`/IPC switch between multiple tasks is a separate, older path and is not hardened.)
- **Fault signals** — a task can register its own fault handler (`SYS_SIGACTION`); a ring-3 fault (page fault → `SIG_SEGV`, `#UD` → `SIG_ILL`) is then delivered to that handler in ring 3 — signal number in `ebx`, faulting address in `ecx` — instead of the task being summarily killed, and `SYS_SIGRETURN` resumes the exact pre-signal context. Attack-surface controls: the handler address is validated to the user code window in safe Rust (fail-closed); a fault *inside* a handler is not re-delivered (no loops); the handler runs at ring 3 with unchanged privileges. Proven at runtime by `make smoke-signal` (a task faults on purpose and its handler runs). **Scope:** synchronous fault signals only — there is no asynchronous *task-to-task* signalling yet (that would require a capability on the target's TCB), no alternate signal stack, and no per-signal masking.
- **Reproducible builds** — `make reproducible-build` yields a byte-for-byte identical `kernel.elf` across clean builds (verified in CI)
- **Userspace task spawning** — `SYS_SPAWN` loads an ELF image, sets up paging/heap/ASLR and a capability space, and is gated on a capability (`CAP_RIGHT_WRITE | CAP_RIGHT_EXEC` on slot 3)

---

## Partial implementations

These subsystems compile and run but are incomplete:

### Userspace shell

The shell accepts input and dispatches commands. Several are implemented end-to-end; others parse their arguments but return errors or do little. Coverage is uneven and should not be assumed complete for any given command.

### IPC

The endpoint-based `send`/`recv` cycle works (256-byte messages, capability-gated, with the TOCTOU revalidation noted above). It is a busy-spin-with-`yield()` rendezvous rather than a true blocking/queueing endpoint, so semantics under contention are simplistic. `SYS_IPC_CALL`/`SYS_IPC_REPLY` are thin wrappers over send. **Notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) are not implemented** — they perform their capability check and then return a distinct `SYS_ERR_NOSYS` (-38).

### Filesystem (capfs / ramfs)

An in-memory capability-addressed filesystem works: lookup, create, delete, read, write, and readdir each enforce the relevant `CAP_RIGHT_FS_*` right, with per-file encryption support. It is a single in-memory tree; persistence and richer POSIX semantics are absent (see below).

### Copy-on-write paging

The `PAGE_COW` flag and refcount infrastructure are in place, and the page-fault handler calls into Rust to decide demand-zero vs. COW-copy. The common cases work and the Rust decision logic is unit-tested, but the end-to-end paths have not been stress-tested and likely have edge cases.

### Disk-backed storage

`storage.c` implements encrypted block storage — a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`) with per-block HKDF-SHA256 keys, a fresh random per-write nonce, and `(ino, block)` bound as AAD — plus key rotation over a virtual disk, and `ata.c` is a working 28-bit-LBA PIO driver. However the live filesystem is the in-memory tree above; the encrypted-storage path and mounting are partial and not wired in as the default backing store.

---

## What does not work / is not yet present

### Persistent storage as the default

All filesystem contents live in memory and are lost on reboot. The encrypted-storage and ATA code exist but are not the active backing store for the filesystem.

### Userspace filesystem server

`userspace/fs_server.c` is a skeleton; its IPC dispatch is not implemented end-to-end.

### SMP / multicore

LAPIC detection and AP-bringup scaffolding exist, but no AP is brought up and the scheduler/IPC paths assume a single core. Running on real multi-core hardware will not crash but will use one core.

### Full ASLR (PIE userspace)

Per-spawn stack top and heap gap are randomised from the CSPRNG, but userspace binaries are linked non-PIE at a fixed load address (`0x400000`), so load-base randomisation is not applied. See the security note below.

---

## Security limitations

These matter specifically for anyone evaluating Horus as a security system:

### Encrypted storage is not the live backing store

The block cipher itself is now sound: a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD with independent per-block HKDF subkeys and a fresh random per-write nonce, which replaced an earlier hand-rolled routine that was not actually AES. The remaining limitation is *integration, not cryptography* — the live filesystem is the in-memory tree, so this encrypted-block path is not yet the default backing store and has not been exercised end-to-end at runtime.

### No load-base ASLR

Stack and heap are randomised per spawn; the load address is fixed (non-PIE), so code/GOT layout is predictable to an attacker who knows the binary.

### Audit log is tamper-evident, not tamper-proof

The audit log is now integrity-protected: every entry carries an HMAC that binds its absolute sequence number, and a running chain head (`HMAC(pepper, head || mac)`) commits to the entire ordered history, so edits, ring-slot swaps, replays, drops, and sequence rollbacks are all *detectable* — including by an external monitor that periodically records the chain head via `SYS_AUDIT_DIGEST`. The residual limitation is that this is a **detector**, not a guarantee: an attacker who fully compromises the kernel and reads the per-boot pepper can recompute a self-consistent chain. That is the same accepted trust boundary as the user-database integrity tag.

### No covert / cache side-channel mitigation

Single-core today, so cross-core/SMT channels do not yet apply. The timer now preempts and switches between mutually distrusting ring-3 tasks on that single core, but there is no flush-on-switch or cache partitioning to limit microarchitectural leakage across the switch. Tracked in `SECURITY.md`.

### No privilege separation within the kernel

All kernel code runs at the same privilege level with access to all kernel data; a bug in the terminal driver has the same blast radius as one in the capability system.

---

## Code quality notes

- Compilation success is not evidence of correct runtime behaviour; some paths are partial.
- Error codes are mostly bare integers; only a few (e.g. `SYS_ERR_NOSYS`) are named.
- The Rust crate is named `horus_shell` for historical reasons; the name does not reflect its current role (it is the security core: capabilities, memory refcounting, SHA-2/HMAC/HKDF/PBKDF2, ChaCha20 RNG, FFI validation).
- `src/kernel/minimal_secure_stubs.c` supplies the stub implementations used by the `MINIMAL_SECURE=1` build (which strips the filesystem/storage stack); it is build configuration, not security logic.
- Tests: 53 Rust unit tests cover the capability engine, the memory/refcount trust boundary, the RNG and SHA-2 family against published vectors, the ChaCha20+HMAC AEAD (round-trip, tamper, wrong-AAD, nonce separation), the tamper-evident audit MAC/chain (`audit.rs`), BLAKE2b + Argon2id against RFC 7693 / `argon2-cffi` reference vectors, the W^X page policy, the signal-handler-address window, and the FFI validation/policy functions. CI runs nine gated jobs (`cargo test` + `clippy -D warnings`, kernel/ISO build, an alt-config build matrix, a headless QEMU smoke-boot, an ELF-loader + W^X boot self-test, a preemptive-scheduling self-test, a signal-handling self-test, a reproducible-build check, and security scans + SBOM). The smoke-boot tests confirm the kernel boots to userspace with no fault, that the ELF loader enforces W^X, that the timer preempts and time-slices two ring-3 tasks, and that a ring-3 fault is delivered to a registered handler, but there is no *deeper* integration harness (scripted shell sessions) or fuzzing yet, and no automatic checking of the TLA+ specs in `docs/`.

---

## Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part of the project.

| Area | Estimate |
|---|---|
| Capability model (design and core implementation) | ~85% |
| Boot and hardware initialisation | ~85% |
| Memory management | ~55% |
| Task scheduling | ~55% (preemptive round-robin; single-core, no priorities) |
| IPC | ~35% (send/recv; no notifications, no real blocking) |
| Filesystem | ~35% (in-memory, capability-gated; no persistence) |
| Cryptography (Argon2id/BLAKE2b + KDF/MAC/RNG + ChaCha20/HMAC AEAD; all standard primitives) | ~80% |
| Storage / disk I/O | ~25% (driver + sound encrypted-block code, not wired as default) |
| SMP | ~5% (detection/scaffolding only) |
| Testing | ~40% (53 unit tests + CI + smoke-boot + ELF/W^X + preemption + signal self-tests; no deeper integration/fuzz) |
