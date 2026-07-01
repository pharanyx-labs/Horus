# Changelog

All notable changes to Horus are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Horus has not yet reached a versioned release. Changes below reflect the state of the `main` branch at the point noted.

---

## Unreleased

### Working

- Capability-based access control: mint, transfer, move, and revoke with transitive cross-task invalidation
- No ambient authority — capability operations from a non-kernel task without its own cspace are refused; revoke requires `CAP_RIGHT_REVOKE`, mint/transfer require `CAP_RIGHT_MINT`
- Lineage tracking to prevent use-after-revoke; a snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window in the IPC paths
- Primordial capability protection (root capabilities cannot be revoked)
- Capability/FFI layout pinned by mirrored C and Rust compile-time assertions; the page refcount table uses a registered-once trust boundary
- Audit log records capability mint/transfer/move/revoke and the FS/auth outcomes; the log is **tamper-evident** (per-entry HMAC binding the sequence number + a running hash-chain head over the whole history, keyed by the per-boot pepper), and `SYS_AUDIT_DIGEST` returns the digest + constant-time verify status
- x86-64 (long mode) only; ring-3 userspace remains 32-bit compatibility-mode binaries
- Multiboot2 boot via GRUB2
- VGA terminal, kernel log buffer, serial mirror
- Hardware user/kernel isolation: Ring 0/3, per-task page tables, SMEP/SMAP (when advertised) and NX enabled
- Preemptive round-robin scheduling: the PIT (100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch; ring-0 ticks never switch (kernel stays effectively non-preemptible). Runtime-proven by a gated 2-task self-test (`make smoke-preempt`)
- Fault signals: a task registers its own ring-3 fault handler (`SYS_SIGACTION`); a ring-3 fault is delivered to it (signal # in `ebx`, fault addr in `ecx`) instead of the task being killed, and `SYS_SIGRETURN` resumes the pre-signal context. Handler address validated in safe Rust; faults inside a handler are not re-delivered. Runtime-proven by `make smoke-signal`. (Synchronous fault signals only — no async task-to-task signalling yet)
- Endpoint-based IPC send/recv (capability-gated); `SYS_IPC_CALL`/`SYS_IPC_REPLY` wrap send
- Userspace task spawning (`SYS_SPAWN`): ELF load, paging/heap/ASLR setup, capability-gated
- Table-driven syscall dispatch: one descriptor table enforces each syscall's required capability at a single choke point; unlisted numbers fail closed; a compile-time assertion pins the table to the syscall number space
- W^X for user memory: non-executable stacks, and the ELF loader honours `PT_LOAD` `p_flags` (code R+X, data/rodata R[+W]+NX) via the PTE NX bit
- User authentication with lockout (PBKDF2-HMAC-SHA256), plus a global anti-spray throttle
- Reproducible builds (byte-for-byte deterministic `kernel.elf`, verified in CI)
- PS/2 keyboard input
- In-memory capability-addressed filesystem (capfs/ramfs); each operation enforces its `CAP_RIGHT_FS_*`
- Rust security core: capabilities, memory reference counting, SHA-256/HMAC/HKDF/PBKDF2, a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (encryption-at-rest), ChaCha20 CSPRNG (RDRAND + timing-jitter seeded), FFI validation
- Per-spawn stack and heap ASLR seeded from the CSPRNG
- 49 Rust unit tests; headless QEMU boot self-tests (`make smoke`; `make smoke-elf` for the ELF loader + W^X; `make smoke-preempt` for preemption; `make smoke-signal` for fault-signal delivery); GitHub Actions CI runs nine gated jobs (rust test + `clippy -D warnings`, kernel/ISO build, alt-config build matrix, smoke-boot, ELF/W^X boot self-test, preemptive-scheduling self-test, signal-handling self-test, reproducible-build check, security scans + SBOM)

### Security

Recent hardening pass (see git history for individual commits):

- **Tamper-evident audit log added.** Each audit entry is now bound by `HMAC(pepper, LE64(seq) || event)` — the sequence number defeats in-place edits, ring-slot swaps, and replays — and the log keeps a running chain head `HMAC(pepper, head || mac)` over every event ever appended (including entries already overwritten in the ring). The keyed-hash logic is safe Rust (`rust/src/audit.rs`); a new `SYS_AUDIT_DIGEST` (52), gated by the same `CAP_AUDIT` READ capability as `SYS_READ_AUDIT`, returns the event count, chain-head MAC, and a constant-time verify status so an external monitor can detect drops/rewrites/rollbacks. Scoped honestly as a detector, not tamper-proof against a kernel compromise that can read the pepper.
- **Ring-0 wild-write in the ELF loader fixed.** `try_elf_load` walked the target page tables by hand without present-bit checks, so a crafted ELF segment over an unmapped/huge-page mapping could make the kernel dereference and write a garbage physical address at ring 0. Segment copies now go through `copy_to_user`, which checks present/user/write at every level and fails closed.
- **`sudo` deadlock fixed.** `SYS_SUDO` called `cap_alloc_fresh_serial()` (which takes `cap_lock`) three times while already holding `cap_lock`; the non-recursive lock would hang the kernel on the first `sudo`. Serials are now allocated before the lock is taken.
- **Syscall dispatch made table-driven.** The ~50-arm `switch` with per-case capability checks became a descriptor table enforced at one choke point, with a compile-time guard that every syscall number has a table slot. Removes the "forgot a check / forgot a case" bug class; unknown numbers fail closed.
- **W^X enforced.** User stacks are mapped non-executable and the ELF loader honours each segment's `p_flags` (code read+execute, data/rodata no-execute), closing the previous all-RWX user mappings. Verified by the new smoke-boot test for the live path.
- **Smaller fixes.** Stopped leaking the page-table physical base (`cr3`) to ring 3 via `SYS_GET_TASK_INFO`; hardened the (unused but exported) `cap_create_revocation_set` to take `cap_lock` and require authority like its siblings; removed a stray `spin_unlock` on an unheld lock in the demand-fault handler.

- **Encryption-at-rest cipher replaced.** The storage layer's hand-rolled "AES-128" — a broken AES-NI key schedule plus an unaudited ARX software fallback, neither of which was actually AES — has been removed. Block encryption now uses a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust, with a fresh random per-write nonce (eliminating CTR keystream reuse), per-block HKDF subkeys, `(ino, block)` bound as AAD, and constant-time fail-closed verification. The volume key is now HKDF-SHA256-derived. This also removed a latent 4080-byte-into-512-byte-buffer overflow in the old encrypt/decrypt path.
- **Ring-3 storage backend callback removed.** `SYS_REGISTER_STORAGE_BACKEND` previously let userspace register function pointers the kernel then invoked from ring 0 (an SMEP violation and a TCB escape). The syscall now fails closed (`SYS_ERR_NOSYS`); the ABI slot is reserved.
- **Information-leak and hygiene fixes.** Eliminated a kernel `.rodata` over-read in the version syscall; cleartext passwords are now zeroed from the kernel stack after authentication; the filesystem-listing syscall honours the caller's buffer length; and the authentication path was equalised so it no longer reveals valid usernames by timing.
- **CSPRNG seeding is asserted at boot** before any key material is derived (fail-closed if the pool is somehow unseeded).

### Changed

- **Fault signals added.** A userspace fault was previously fatal — the kernel killed the task unconditionally. A task can now register its own ring-3 fault handler (`SYS_SIGACTION`); on a page fault or CPU exception in ring 3, `try_deliver_fault_signal` saves the full trap frame and redirects the task into its handler (signal number in `ebx`, faulting address in `ecx`) instead of killing it, and `SYS_SIGRETURN` (serviced in `interrupt_handler64`, since it rewrites the live frame) resumes the exact pre-signal context. Controls: the handler address is validated to the user code window in safe Rust (`rust_signal_handler_addr_ok`); a fault inside a handler is not re-delivered (`in_signal` guard, no loops); the handler runs at ring 3 with unchanged privileges, so no new authority is granted and there is still no cross-task signalling. Verified by a gated self-test (`make smoke-signal`).
- **Preemptive scheduling added.** The scheduler was cooperative-only, and its context switch saved just `%esp` + a return address into 32-bit TCB fields, so it could never correctly switch two running tasks. Real preemption now works: the ISR already saves a full 64-bit trap frame per task, so `interrupt_handler64` returns the kernel `%rsp` to resume on and the timer (PIT, 100 Hz) switches ring-3 tasks by swapping between their per-task kernel stacks. Switching only happens when a tick interrupts ring 3 (no lock held, whole state captured by the frame); ring-0 ticks never switch. Freshly spawned tasks get a fabricated initial frame so the timer can `iretq` into them. Verified by a gated 2-task self-test.
- **32-bit kernel build removed; x86-64 only.** The kernel has run exclusively in 64-bit long mode for a long time (`BITS=64` default, CI 64-bit only), so the dead 32-bit build path was removed: the `BITS=32` Makefile branch, the `i686` Rust target, `linker.ld`, `src/kernel/lowlevel.S`, the legacy 32-bit GDT table / TSS / IDT setup, and every `#if defined(__x86_64__)` guard (collapsed to the long-mode arm). Ring-3 userspace stays 32-bit (compatibility-mode binaries). Net −676 lines. As a side effect, `serial_init()` — previously reachable only from the dead 32-bit init — is now wired into the 64-bit boot, so serial is configured on real hardware rather than relying on the emulator's default 16550 state.

### Known incomplete

- Scheduler: preemption is single-core with no priorities/fairness; the legacy cooperative `yield()`/IPC switch between multiple tasks is a separate, un-hardened path
- IPC notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY` return `SYS_ERR_NOSYS`); no true blocking endpoints
- Disk-backed persistent storage as the default (encrypted-block and ATA code exist but are not the live backing store)
- SMP / multicore
- Userspace filesystem server
- Load-base ASLR (userspace is non-PIE; stack and heap are randomised)
- Deeper booted-kernel integration tests (beyond the smoke-boot check) and fuzzing

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for detail.
