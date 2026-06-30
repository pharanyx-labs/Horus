# Horus — Current Limitations

This document is an honest account of what Horus does and does not do. The goal is to prevent anyone from drawing incorrect conclusions about its readiness or security properties.

Horus is a research and learning project. It is not a production operating system and makes no claim to be one. Where this document and the code disagree, the code is the source of truth — please open an issue.

---

## What actually works

These subsystems are functional in the current codebase:

- **Boot sequence** — Multiboot boot via GRUB2, 32-bit and 64-bit
- **VGA terminal** — text mode, colour output, kernel log buffer, serial mirror
- **Hardware isolation** — Ring 0/Ring 3 separation, per-task page tables, user/kernel memory split. SMEP and SMAP are enabled when the CPU advertises them (ring 0 cannot execute or casually read user pages; user copies go through a kernel mapping rather than the user mapping), and the boot CPU brings these up after feature detection.
- **W^X for user memory** — `EFER.NXE` is on and the kernel sets the PTE NX bit so writable pages are never executable: user stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags` (code read+execute, data/rodata read[+write]+no-execute). The W^X policy decision lives in Rust and is unit-tested; the live shell boot (which runs through the flat-binary fallback) is covered by the smoke-boot test.
- **Capability mint, transfer, and revoke** — the core capability operations work, including transitive revocation across every task's cspace and the kernel root cnode. Revocation requires `CAP_RIGHT_REVOKE` on the target (mint/transfer require `CAP_RIGHT_MINT`); a "no ambient authority" guard refuses cap operations from any non-kernel task that lacks its own cspace.
- **Lineage tracking** — use-after-revoke is prevented via per-lineage generation counters; a looked-up capability can be snapshotted and re-validated at point of use (wired into the IPC send/recv paths to close a lookup/use TOCTOU window across the cooperative yield).
- **Capability/FFI integrity** — the C `capability_t` and Rust `Capability` layouts are pinned by mirrored compile-time assertions; the refcount table is registered once and every later inc/dec must present the exact (pointer, length) or is refused.
- **User authentication** — login, lockout after failed attempts, per-user UID assignment
- **Audit log** — kernel-side circular buffer of security events; capability mint/transfer/move/revoke and the FS/auth paths record outcomes
- **Keyboard input** — PS/2 scancode translation, key buffer
- **Round-robin scheduling** — cooperative task switching
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

### Preemptive scheduling

There is no preemption. The timer interrupt is handled but does not forcibly switch tasks; a task runs until it yields, blocks, or exits. A long-running computation starves others.

### Signal handling

There is no signal mechanism. A userspace fault is fatal to the faulting task (or drops into the kernel debug shell when `DEBUG_SHELL=1`).

### Full ASLR (PIE userspace)

Per-spawn stack top and heap gap are randomised from the CSPRNG, but userspace binaries are linked non-PIE at a fixed load address (`0x400000`), so load-base randomisation is not applied. See the security note below.

---

## Security limitations

These matter specifically for anyone evaluating Horus as a security system:

### Encrypted storage is not the live backing store

The block cipher itself is now sound: a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD with independent per-block HKDF subkeys and a fresh random per-write nonce, which replaced an earlier hand-rolled routine that was not actually AES. The remaining limitation is *integration, not cryptography* — the live filesystem is the in-memory tree, so this encrypted-block path is not yet the default backing store and has not been exercised end-to-end at runtime.

### No load-base ASLR

Stack and heap are randomised per spawn; the load address is fixed (non-PIE), so code/GOT layout is predictable to an attacker who knows the binary.

### Audit log is not tamper-resistant

The audit log is a plain circular buffer in kernel memory with no integrity protection. Kernel code — or a kernel-mode exploit — can overwrite or clear it.

### No covert / cache side-channel mitigation

Single-core and cooperative today, so cross-core/SMT channels do not yet apply, but there is no flush-on-switch or cache partitioning for when preemption/SMP land. Tracked in `SECURITY.md`.

### No privilege separation within the kernel

All kernel code runs at the same privilege level with access to all kernel data; a bug in the terminal driver has the same blast radius as one in the capability system.

---

## Code quality notes

- Compilation success is not evidence of correct runtime behaviour; some paths are partial.
- Error codes are mostly bare integers; only a few (e.g. `SYS_ERR_NOSYS`) are named.
- The Rust crate is named `horus_shell` for historical reasons; the name does not reflect its current role (it is the security core: capabilities, memory refcounting, SHA-2/HMAC/HKDF/PBKDF2, ChaCha20 RNG, FFI validation).
- `src/kernel/minimal_secure_stubs.c` supplies the stub implementations used by the `MINIMAL_SECURE=1` build (which strips the filesystem/storage stack); it is build configuration, not security logic.
- Tests: 41 Rust unit tests cover the capability engine, the memory/refcount trust boundary, the RNG and SHA-2 family against published vectors, the ChaCha20+HMAC AEAD (round-trip, tamper, wrong-AAD, nonce separation), the W^X page policy, and the FFI validation/policy functions. CI runs five gated jobs (`cargo test` + `clippy -D warnings`, kernel/ISO build, a headless QEMU smoke-boot, reproducible-build check, and security scans + SBOM). The smoke-boot test confirms the kernel boots to userspace with no fault, but there is no *deeper* integration harness (scripted shell sessions) or fuzzing yet, and no automatic checking of the TLA+ specs in `docs/`.

---

## Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part of the project.

| Area | Estimate |
|---|---|
| Capability model (design and core implementation) | ~85% |
| Boot and hardware initialisation | ~85% |
| Memory management | ~55% |
| Task scheduling | ~40% (round-robin, no preemption) |
| IPC | ~35% (send/recv; no notifications, no real blocking) |
| Filesystem | ~35% (in-memory, capability-gated; no persistence) |
| Cryptography (KDF/MAC/RNG + ChaCha20/HMAC AEAD; all standard primitives) | ~75% |
| Storage / disk I/O | ~25% (driver + sound encrypted-block code, not wired as default) |
| SMP | ~5% (detection/scaffolding only) |
| Testing | ~35% (41 unit tests + CI + smoke-boot; no deeper integration/fuzz) |
