# Horus — Current Limitations

This document is an honest account of what Horus does and does not do. The goal is to prevent anyone from drawing incorrect conclusions about its readiness or security properties.

Horus is a research and learning project. It is not a production operating system and makes no claim to be one.

---

## What actually works

These subsystems are functional in the current codebase:

- **Boot sequence** — Multiboot2 boot via GRUB2, 32-bit and 64-bit
- **VGA terminal** — 80×50 text mode, colour output, kernel log buffer, serial mirror
- **Hardware isolation** — Ring 0/Ring 3 separation, per-task page tables, user/kernel memory split
- **Capability mint, transfer, and revoke** — the core capability operations work correctly, including transitive revocation across all tasks
- **Lineage tracking** — use-after-revoke is prevented via generation counters
- **User authentication** — login, lockout after failed attempts, per-user UID assignment
- **Audit log** — kernel-side circular buffer of security events
- **Keyboard input** — PS/2 scancode translation, key buffer
- **Round-robin scheduling** — basic task switching

---

## Partial implementations

These subsystems compile and run but are incomplete:

### Userspace shell

The shell accepts input and dispatches commands. Several commands are implemented end-to-end (`whoami`, `uname`, `login`, `logout`, `help`). Others (`ls`, `cat`, `mkdir`, `spawn`, `cap_grant`) are stubs that parse their arguments but return errors or do nothing.

### IPC

The basic `send`/`recv` cycle works. The `call`/`reply` path (`SYS_IPC_CALL`) is not fully implemented. Blocking semantics exist in the data structures but are inconsistently enforced.

### RAM filesystem

A filesystem exists in memory with up to 8 pre-allocated files. File read and write work at the syscall level. Directory traversal, permissions, and symbolic links are not implemented. There is only one level of naming; no subdirectory support.

### Copy-on-write paging

The `PAGE_COW` flag and the reference counting infrastructure are in place. The page fault handler calls into Rust to handle demand-page and COW faults. The mechanism works for the common case but has not been stress-tested and likely has edge cases.

---

## What does not work

### Disk I/O

The ATA driver (`ata.c`) implements 28-bit LBA read/write over the standard port-I/O interface. Under QEMU it targets the virtual disk. However, all filesystem operations currently use an in-memory structure — no kernel code writes to or reads from the ATA device as part of normal operation. **There is no persistent storage.** All filesystem contents are lost on reboot.

### Userspace filesystem server

`userspace/fs_server.c` registers as a filesystem server and waits for IPC messages. The message dispatch skeleton is in place but no operations are implemented. The shell's IPC connection to the fs_server is not established reliably.

### Task spawning from userspace

`SYS_SPAWN` is a stub. Userspace cannot create new tasks.

### SMP / multicore

The LAPIC is detected and the AP bringup code exists in `lowlevel64.S`. No AP has successfully started. The `MAX_CPUS=4` constant and the per-CPU current-task array are in the data structures but the scheduler and IPC paths assume a single CPU. Running on a real multi-core machine will not cause a crash, but no additional cores will be used.

### Preemptive scheduling

There is no preemption. The timer interrupt is handled but does not forcibly switch tasks. Tasks run until they yield, make a blocking syscall, or exit. A long-running computation will starve all other tasks.

### Signal handling

There is no signal mechanism. Page faults and other exceptions in userspace are currently fatal to the faulting task (or fall through to the kernel debug shell if `DEBUG_SHELL=1`).

---

## Security limitations

These limitations matter specifically for anyone evaluating Horus as a security system:

### Custom cryptography

The password hashing scheme is a custom 4,096-round XOR-rotate mixing function — not PBKDF2, bcrypt, scrypt, or Argon2. It has not been reviewed by a cryptographer and should not be considered strong. The `crypto.rs` Rust module is a placeholder with no implemented primitives.

The kernel pepper is derived from runtime state that an attacker with code execution in the kernel can potentially reconstruct.

### No ASLR enforcement

ASLR data structures and entropy seeding are present, but load-address randomisation is not enforced on every task spawn. A determined attacker can likely infer or brute-force addresses.

### Audit log is not tamper-resistant

The audit log is a circular buffer in kernel memory. There is no integrity protection. Kernel code (or a kernel-mode exploit) can overwrite or clear it.

### No covert channel mitigation

There is no mitigation for timing side-channels (e.g., cache-timing attacks between tasks). Shared page tables, shared TLB entries, and shared hardware counters are all potential leakage channels that are unaddressed.

### No privilege separation within the kernel

All kernel code runs at the same privilege level with access to all kernel data. A bug in the terminal driver has the same impact as a bug in the capability system.

### TSC-only entropy

All randomness (ASLR, salts) is seeded exclusively from the TSC (`rdtsc`). The TSC is readable from userspace and is low-entropy early in boot. Proper entropy gathering (hardware RNG, interrupt timing jitter) is not implemented.

---

## Code quality notes

- Several subsystems have stub implementations that compile cleanly but return errors or do nothing at runtime. Compilation success is not evidence of correct operation.
- Error codes are bare integers (`-1`, `-2`, `-3`) without a consistent enumeration.
- The Rust crate is named `horus_shell` for historical reasons; the name does not reflect its actual role.
- `src/kernel/minimal_secure_stubs.c` exists as a compatibility shim and contains no security logic despite the filename.
- There is one unit test in the Rust crate and no integration test suite.

---

## Estimated completeness

| Area | Estimate |
|---|---|
| Capability model (design and core implementation) | ~80% |
| Boot and hardware initialisation | ~85% |
| Memory management | ~50% |
| Task scheduling | ~40% (round-robin only, no preemption) |
| IPC | ~35% |
| Filesystem | ~20% |
| Storage / disk I/O | ~10% |
| Cryptography | ~5% (scaffolding only) |
| SMP | ~5% (detection only) |
| Testing | ~5% |

These are rough estimates for orientation, not guarantees. The capability system is the most complete part of the project.
