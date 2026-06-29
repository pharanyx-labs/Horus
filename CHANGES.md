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
- Audit log records capability mint/transfer/move/revoke and the FS/auth outcomes
- x86 and x86-64 builds from the same codebase
- Multiboot boot via GRUB2
- VGA terminal, kernel log buffer, serial mirror
- Hardware user/kernel isolation: Ring 0/3, per-task page tables, SMEP/SMAP (when advertised) and NX enabled
- Round-robin (cooperative) task scheduling
- Endpoint-based IPC send/recv (capability-gated); `SYS_IPC_CALL`/`SYS_IPC_REPLY` wrap send
- Userspace task spawning (`SYS_SPAWN`): ELF load, paging/heap/ASLR setup, capability-gated
- User authentication with lockout
- Reproducible builds (byte-for-byte deterministic `kernel.elf`, verified in CI)
- PS/2 keyboard input
- In-memory capability-addressed filesystem (capfs/ramfs); each operation enforces its `CAP_RIGHT_FS_*`
- Rust security core: capabilities, memory reference counting, SHA-256/HMAC/HKDF/PBKDF2, a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (encryption-at-rest), ChaCha20 CSPRNG (RDRAND + timing-jitter seeded), FFI validation
- Per-spawn stack and heap ASLR seeded from the CSPRNG
- 31 Rust unit tests; GitHub Actions CI (test, `clippy -D warnings`, kernel/ISO build, reproducible-build check)

### Security

Recent hardening pass (see git history for individual commits):

- **Encryption-at-rest cipher replaced.** The storage layer's hand-rolled "AES-128" — a broken AES-NI key schedule plus an unaudited ARX software fallback, neither of which was actually AES — has been removed. Block encryption now uses a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust, with a fresh random per-write nonce (eliminating CTR keystream reuse), per-block HKDF subkeys, `(ino, block)` bound as AAD, and constant-time fail-closed verification. The volume key is now HKDF-SHA256-derived. This also removed a latent 4080-byte-into-512-byte-buffer overflow in the old encrypt/decrypt path.
- **Ring-3 storage backend callback removed.** `SYS_REGISTER_STORAGE_BACKEND` previously let userspace register function pointers the kernel then invoked from ring 0 (an SMEP violation and a TCB escape). The syscall now fails closed (`SYS_ERR_NOSYS`); the ABI slot is reserved.
- **Information-leak and hygiene fixes.** Eliminated a kernel `.rodata` over-read in the version syscall; cleartext passwords are now zeroed from the kernel stack after authentication; the filesystem-listing syscall honours the caller's buffer length; and the authentication path was equalised so it no longer reveals valid usernames by timing.
- **CSPRNG seeding is asserted at boot** before any key material is derived (fail-closed if the pool is somehow unseeded).

### Known incomplete

- Preemptive scheduling (cooperative only)
- IPC notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY` return `SYS_ERR_NOSYS`); no true blocking endpoints
- Disk-backed persistent storage as the default (encrypted-block and ATA code exist but are not the live backing store)
- SMP / multicore
- Userspace filesystem server
- Load-base ASLR (userspace is non-PIE; stack and heap are randomised)
- Booted-kernel integration tests and fuzzing

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for detail.
