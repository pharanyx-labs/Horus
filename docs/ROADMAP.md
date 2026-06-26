# Horus Roadmap

This document describes where the project is headed. Items are grouped into phases; later phases depend on earlier ones being stable. Nothing here is a commitment — priorities can shift as contributors join and the design evolves.

If you want to work on something listed here, open an issue or start a discussion. Coordination before coding saves effort.

---

## Recently completed

Several items from the phases below have since landed on `main`. They are kept in their phases for context, but are done:

- **`SYS_SPAWN`** — userspace can spawn ELF tasks, with paging/heap/ASLR set up and the syscall gated on a capability.
- **Standard password hashing** — PBKDF2-HMAC-SHA256 replaced the custom XOR-rotate scheme.
- **Hardware entropy** — a ChaCha20 CSPRNG seeded from RDRAND and timing jitter; raw TSC is no longer used as secret randomness.
- **Per-spawn stack/heap ASLR** — seeded from the CSPRNG (load-base / PIE randomisation still pending).
- **`crypto.rs`** — resolved by moving to audited-standard primitives in `sha256.rs` / `rng.rs`; `crypto.rs` is now intentionally empty. The remaining bulk-cipher work is a correct AES-128 (or a ChaCha20 stream) for CTR encryption.
- **Kernel hardening** — SMEP/SMAP/NX enabled; capability "no ambient authority" guard; IPC use/revoke TOCTOU revalidation; C/Rust FFI layout assertions; audit logging of capability mutations.
- **CI** — GitHub Actions runs the unit tests, `clippy -D warnings`, a kernel/ISO build, and a reproducible-build check on every push/PR. (Phase 6 integration tests and fuzzing are still pending.)

---

## Phase 1 — Stabilise the foundation

These items address the roughest edges in what already exists. They are good starting points for new contributors because they are self-contained and do not require deep kernel knowledge.

- **Preemptive scheduling**: Hook the timer interrupt to force a task switch rather than just noting elapsed time. This unblocks all liveness guarantees.
- **`SYS_SPAWN` implementation**: Allow userspace to create new tasks from ELF binaries. The TCB infrastructure exists; what is missing is a proper ELF loader and the syscall plumbing.
- **IPC call/reply semantics**: Complete `SYS_IPC_CALL` so that a client can send a message and block until the server replies atomically.
- **Consistent error codes**: Replace the bare `-1`, `-2`, `-3` pattern with a named enumeration visible to both kernel and userspace.
- **Shell command completion**: Fill in the stubbed shell commands (`ls`, `cat`, `mkdir`, `rm`, `spawn`, `kill`) so they invoke the correct syscalls end-to-end.
- **Page fault recovery**: Deliver a signal-like notification to a faulting task instead of killing it unconditionally.

---

## Phase 2 — Functional filesystem

- **RAM filesystem extension**: Multi-level directory support, proper ownership and permission bits tied to the capability model.
- **Filesystem server IPC**: Complete the `fs_server` userspace program so that filesystem operations flow through IPC rather than direct kernel calls. This is the microkernel architecture in practice.
- **ATA driver integration**: Wire the working ATA read/write code to the storage layer so that the virtual disk in QEMU is actually used.
- **Persistent inode store**: Implement the on-disk inode format that `storage.c` scaffolds, including a working superblock, block bitmap, and inode table. Crash recovery via the intent log.
- **Capability-gated file access**: Enforce the filesystem capability rights (`CAP_RIGHT_FS_READ`, `CAP_RIGHT_FS_WRITE`, etc.) consistently in all filesystem syscalls.

---

## Phase 3 — Cryptography and security hardening

- **Replace custom password hashing**: Use a standard, reviewed algorithm. Argon2id is the preferred target. This requires either porting a `no_std` implementation or compiling a small C library into the kernel.
- **Hardware entropy**: Seed the kernel's PRNG from RDRAND (already detected at boot but not used) and from interrupt timing jitter, not solely from TSC.
- **ASLR enforcement**: Apply address space layout randomisation on every task spawn using the existing entropy infrastructure.
- **Audit log integrity**: Add a rolling MAC over audit log entries so that tampering is detectable.
- **Encrypted storage**: Complete the per-file encryption that `storage.c` sketches, using the Rust crypto module as the implementation layer.
- **`crypto.rs` implementation**: Replace the placeholder with real primitives — at minimum AES-128-CTR and a SHA-256 implementation, both in safe Rust.

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

- **Integration test suite**: Automated tests that boot Horus under QEMU, execute a sequence of operations, and verify the output. Should run in CI on every pull request.
- **Fuzzing**: Apply coverage-guided fuzzing (libFuzzer or AFL++) to the syscall interface.
- **TLA+ model coverage**: Extend the existing formal specifications (`docs/cap_algebra.tla`, `docs/paging_isolation.tla`) to cover IPC, the scheduler, and SMP interactions.
- **Formal verification of the Rust core**: Explore using a verification tool (Verus, Kani) on the capability operations in `rust/src/capability.rs`.

---

## Contributing

All phases are open. If you are new to the project, Phase 1 items are the recommended starting point. If you have kernel or systems programming experience and want to work on something more involved, Phase 2 or 3 items are good targets.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and submit work.
