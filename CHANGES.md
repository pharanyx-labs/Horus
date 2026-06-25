# Changelog

All notable changes to Horus are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Horus has not yet reached a versioned release. Changes below reflect the state of the `main` branch at the point noted.

---

## Unreleased

### Working

- Capability-based access control: mint, transfer, move, and revoke with transitive cross-task invalidation
- Lineage tracking to prevent use-after-revoke
- Primordial capability protection (root capabilities cannot be revoked)
- x86 and x86-64 builds from the same codebase
- Multiboot2 boot via GRUB2
- VGA terminal (80×50), kernel log buffer, serial mirror
- Hardware user/kernel isolation (Ring 0 / Ring 3, per-task page tables)
- Round-robin task scheduling
- Endpoint-based IPC (partial: send/recv working; call/reply incomplete)
- User authentication with lockout
- Kernel audit log (256-entry circular buffer)
- Reproducible builds (byte-for-byte deterministic on same toolchain)
- PS/2 keyboard input
- RAM filesystem (partial)
- Rust security core: capability operations, memory reference counting

### Known incomplete

- Preemptive scheduling (cooperative only)
- `SYS_SPAWN` (userspace task creation)
- IPC call/reply
- Disk-backed persistent storage
- SMP / multicore
- Userspace filesystem server
- Standard cryptographic primitives
- ASLR enforcement

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for detail.
