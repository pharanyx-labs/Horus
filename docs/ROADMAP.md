# Horus Roadmap

This document describes where the project is headed. Items are grouped into phases; later phases depend on earlier ones being stable. Nothing here is a commitment — priorities can shift as contributors join and the design evolves.

If you want to work on something listed here, open an issue or start a discussion. Coordination before coding saves effort.

---

## Recently completed

Several items from the phases below have since landed on `main`. They are kept in their phases for context, but are done:

- **`SYS_SPAWN`** — userspace can spawn ELF tasks, with paging/heap/ASLR set up and the syscall gated on a capability.
- **Argon2id password hashing** — the memory-hard KDF (RFC 9106; the kernel runs 4 MiB / 3 passes / 1 lane) implemented from scratch in safe Rust on an in-house BLAKE2b (`argon2.rs`, `blake2b.rs`), validated against the `argon2-cffi` reference vectors, replacing PBKDF2-HMAC-SHA256 (which had itself replaced a custom XOR-rotate scheme). Memory-hardness defeats the cheap GPU/ASIC brute force PBKDF2 is vulnerable to. The implementation is **multi-lane** (`p ≥ 1`, cross-lane references + final-block XOR, validated against `p = 2` / `p = 4` vectors) and the cost (`m`/`t`/`p`) is configurable via three defines in `kernel.h` (the scratch buffer resizes to match).
- **Consistent, descriptive error codes** — a shared `include/errno.h` gives the kernel and userspace one errno-aligned `SYS_ERR_*` vocabulary (`SYS_ERR_PERM`, `SYS_ERR_NOENT`, `SYS_ERR_AUTH`, `SYS_ERR_FAULT`, `SYS_ERR_INVAL`, …) plus `sys_strerror()`; the syscall dispatcher and the auth / user-copy paths now return the specific code (e.g. unknown-syscall vs permission-denied are no longer both `-1`), and the shell prints `sys_strerror()`.
- **Hardware entropy** — a ChaCha20 CSPRNG seeded from RDRAND and timing jitter; raw TSC is no longer used as secret randomness.
- **Per-spawn stack/heap ASLR** — seeded from the CSPRNG (load-base / PIE randomisation still pending).
- **Audited-standard cryptography** — primitives moved to `sha256.rs` / `rng.rs`, and bulk encryption-at-rest is now a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`) with per-write random nonces and per-block HKDF subkeys, replacing a hand-rolled routine that was not actually AES. (`crypto.rs` remains intentionally empty.)
- **Kernel hardening** — SMEP/SMAP enabled; capability "no ambient authority" guard; IPC use/revoke TOCTOU revalidation; C/Rust FFI layout assertions; audit logging of capability mutations.
- **W^X for user memory** — non-executable user stacks, and the ELF loader honours `PT_LOAD` `p_flags` (code R+X, data/rodata R[+W]+NX) via the PTE NX bit. Policy lives in Rust and is unit-tested.
- **Table-driven syscall dispatch** — one descriptor table enforces each syscall's required capability centrally; unlisted numbers fail closed; a compile-time assertion pins the table to the syscall number space. Fixed a ring-0 wild-write in the ELF loader and a `sudo` lock-ordering deadlock along the way.
- **Attack-surface reduction** — removed the ring-3 storage-backend callback that the kernel invoked from ring 0 (`SYS_REGISTER_STORAGE_BACKEND` now fails closed); closed several information-leak, timing, and buffer-handling issues in the syscall and authentication paths.
- **Preemptive scheduling** — the PIT (100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch, so CPU-bound tasks time-share without cooperating; ring-0 ticks never switch (kernel stays effectively non-preemptible). Runtime-proven by a gated 2-task self-test (`make smoke-preempt`).
- **Fault signals** — a ring-3 fault is delivered to the task's registered handler (`SYS_SIGACTION`; signal # in `ebx`, fault addr in `ecx`) instead of killing it, with `SYS_SIGRETURN` to resume; the handler address is validated in safe Rust and faults inside a handler are not re-delivered. Runtime-proven by `make smoke-signal`. (Synchronous fault signals only; async cross-task signalling is future work.)
- **Tamper-evident audit log** — each audit entry is HMAC'd (binding its sequence number) and a running hash-chain head commits to the entire ordered history, keyed by the per-boot pepper (`rust/src/audit.rs`); `SYS_AUDIT_DIGEST` exposes the digest + verify status for an external monitor. A detector, honestly scoped (not tamper-proof against a key-reading kernel compromise).
- **x86-64 only** — the dead 32-bit kernel build target (`BITS=32`, `linker.ld`, `lowlevel.S`, the legacy 32-bit GDT/TSS/IDT, and all `#if defined(__x86_64__)` branches) was removed. The kernel is now unconditionally long-mode; ring-3 userspace remains 32-bit compatibility-mode binaries.
- **CI + smoke-boot** — GitHub Actions runs nine gated jobs: the unit tests + `clippy -D warnings`, a kernel/ISO build, an alt-config build matrix (`DEBUG_SHELL`/`MINIMAL_SECURE`), a **headless QEMU smoke-boot** (boots to the shell banner with no fault), an **ELF-loader + W^X boot self-test**, a **preemptive-scheduling self-test**, a **signal-handling self-test**, a reproducible-build check, and a security-scan/SBOM job on every push/PR. (Deeper scripted integration tests and fuzzing are still pending.)

---

## Phase 1 — Stabilise the foundation

These items address the roughest edges in what already exists. They are good starting points for new contributors because they are self-contained and do not require deep kernel knowledge.

- **Preemptive scheduling** *(done)*: the timer forces a full-context switch of ring-3 tasks (see "Recently completed"). Remaining scheduler work: priorities/fairness, and hardening the cooperative `yield()`/IPC switch to the same full-context mechanism.
- **`SYS_SPAWN` implementation**: Allow userspace to create new tasks from ELF binaries. The TCB infrastructure exists; what is missing is a proper ELF loader and the syscall plumbing.
- **IPC call/reply semantics**: Complete `SYS_IPC_CALL` so that a client can send a message and block until the server replies atomically.
- **Consistent error codes** *(done)*: a shared `include/errno.h` defines a descriptive, errno-aligned `SYS_ERR_*` vocabulary used by both the kernel and userspace, with `sys_strerror()` to render a reason. The central dispatcher now distinguishes an unknown syscall (`SYS_ERR_NOSYS`) from a missing capability (`SYS_ERR_PERM`), and the auth and user-copy paths return `SYS_ERR_AUTH` / `SYS_ERR_FAULT`. See "Recently completed".
- **Shell command completion**: Fill in the stubbed shell commands (`ls`, `cat`, `mkdir`, `rm`, `spawn`, `kill`) so they invoke the correct syscalls end-to-end.
- **Page fault recovery** *(done)*: a task registers its own ring-3 fault handler (`SYS_SIGACTION`) and a fault is delivered to it instead of the task being killed; `SYS_SIGRETURN` resumes. See "Recently completed". Remaining: asynchronous task-to-task signalling (capability-gated on the target TCB), alternate signal stacks, masking.

---

## Phase 2 — Functional filesystem

- **RAM filesystem extension**: Multi-level directory support, proper ownership and permission bits tied to the capability model.
- **Filesystem server IPC**: Complete the `fs_server` userspace program so that filesystem operations flow through IPC rather than direct kernel calls. This is the microkernel architecture in practice.
- **ATA driver integration**: Wire the working ATA read/write code to the storage layer so that the virtual disk in QEMU is actually used.
- **Persistent inode store**: Implement the on-disk inode format that `storage.c` scaffolds, including a working superblock, block bitmap, and inode table. Crash recovery via the intent log.
- **Capability-gated file access**: Enforce the filesystem capability rights (`CAP_RIGHT_FS_READ`, `CAP_RIGHT_FS_WRITE`, etc.) consistently in all filesystem syscalls.

---

## Phase 3 — Cryptography and security hardening

- **Replace custom password hashing** *(done)*: Argon2id (RFC 9106) — memory-hard, implemented from scratch in safe `no_std` Rust (`argon2.rs` on `blake2b.rs`), validated against the `argon2-cffi` reference vectors and wired into the auth path (see "Recently completed").
- **Hardware entropy** *(done)*: the kernel PRNG is a ChaCha20 fast-key-erasure CSPRNG seeded from RDRAND (with retry + health check), TSC jitter, and boot counters (`rng.rs`); raw TSC is never used as secret randomness.
- **ASLR enforcement** *(done for stack/heap)*: per-spawn stack top and heap gap are randomised from the CSPRNG on every task spawn. Load-base (PIE userspace) randomisation remains an open multi-day epic — userspace is linked non-PIE at a fixed address.
- **Audit log integrity** *(done)*: a per-entry HMAC (sequence-bound) plus a running hash-chain head over the whole history make tampering detectable, keyed by the per-boot pepper (`rust/src/audit.rs`, exposed via `SYS_AUDIT_DIGEST`).
- **Encrypted storage** *(crypto done; integration pending)*: the block-level AEAD, per-block keys, and key rotation exist and are sound; what remains is wiring the encrypted store in as the default backing store (tracked under Phase 2).
- **`crypto.rs` implementation** *(done)*: real primitives now live in safe Rust — SHA-256/HMAC/HKDF/PBKDF2 (`sha256.rs`), a ChaCha20 CSPRNG (`rng.rs`), and a ChaCha20+HMAC-SHA256 AEAD (`aead.rs`). `crypto.rs` itself is intentionally empty.

---

## Phase 4 — Symmetric multiprocessing

- **AP bringup**: Get at least one additional CPU core running using the existing LAPIC and AP startup code in `lowlevel64.S`.
- **Per-CPU scheduler**: Extend the scheduler to maintain a run queue per CPU and perform load balancing.
- **IPC locking**: Audit all endpoint and notification operations for correct behaviour under concurrent access from multiple CPUs.
- **TLB shootdowns**: Implement inter-processor interrupts for TLB shootdown when page mappings are changed.

---

## Phase 5 — Userspace ecosystem

- **`libc` stub**: A minimal freestanding C library for userspace programs covering the syscall wrappers, string functions, and basic I/O. This will dramatically reduce the friction of writing new userspace programs.
- **Additional userspace servers**: A network stack server, a block device driver server, and a name server following the capability-delegation model.
- **`captest` expansion**: A comprehensive test program that exercises every syscall and every capability operation, usable as both a regression test and a demonstration.
- **Process manager**: A userspace init process that launches and supervises other services, replacing the current arrangement where the kernel spawns the shell directly.

---

## Phase 6 — Testing and verification

- **Integration test suite**: A headless smoke-boot test (`make smoke`) now runs in CI and asserts the kernel boots to userspace with no fault. The remaining work is a harness that *drives* scripted sessions (login, capability denials, ELF-under-W^X) and asserts on the responses.
- **Fuzzing**: Apply coverage-guided fuzzing (libFuzzer or AFL++) to the syscall interface.
- **TLA+ model coverage**: Extend the existing formal specifications (`docs/cap_algebra.tla`, `docs/paging_isolation.tla`) to cover IPC, the scheduler, and SMP interactions.
- **Formal verification of the Rust core**: Explore using a verification tool (Verus, Kani) on the capability operations in `rust/src/capability.rs`.

---

## Contributing

All phases are open. If you are new to the project, Phase 1 items are the recommended starting point. If you have kernel or systems programming experience and want to work on something more involved, Phase 2 or 3 items are good targets.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and submit work.
