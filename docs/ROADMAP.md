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
- **Per-spawn ASLR (stack, heap, and image base)** — seeded from the CSPRNG. Userspace is built static-PIE (`ET_DYN`) and loaded at a random base by `try_elf_load`, which applies `R_386_RELATIVE` relocations; image-base entropy is bounded (~9 bits) by the 32-bit low-memory window.
- **Audited-standard cryptography** — primitives moved to `sha256.rs` / `rng.rs`, and encryption-at-rest is now a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`) with per-write random nonces and HKDF subkeys. Both callers share this one construction: the block-storage layer (replacing a hand-rolled routine that was not actually AES) and the in-memory capfs per-file encryption (replacing a separate unauthenticated XOR keystream). (`crypto.rs` remains intentionally empty.)
- **Kernel hardening** — SMEP/SMAP enabled; capability "no ambient authority" guard; IPC use/revoke TOCTOU revalidation; C/Rust FFI layout assertions; audit logging of capability mutations.
- **W^X for user memory** — non-executable user stacks, and the ELF loader honours `PT_LOAD` `p_flags` (code R+X, data/rodata R[+W]+NX) via the PTE NX bit. Policy lives in Rust and is unit-tested.
- **Table-driven syscall dispatch** — one descriptor table enforces each syscall's required capability centrally; unlisted numbers fail closed; a compile-time assertion pins the table to the syscall number space. Fixed a ring-0 wild-write in the ELF loader and a `sudo` lock-ordering deadlock along the way.
- **Attack-surface reduction** — removed the ring-3 storage-backend callback that the kernel invoked from ring 0 (`SYS_REGISTER_STORAGE_BACKEND` now fails closed); closed several information-leak, timing, and buffer-handling issues in the syscall and authentication paths.
- **Preemptive scheduling** — the PIT (100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch, so CPU-bound tasks time-share without cooperating; ring-0 ticks never switch (kernel stays effectively non-preemptible). Runtime-proven by a gated 2-task self-test (`make smoke-preempt`).
- **Fault signals** — a ring-3 fault is delivered to the task's registered handler (`SYS_SIGACTION`; signal # in `ebx`, fault addr in `ecx`) instead of killing it, with `SYS_SIGRETURN` to resume; the handler address is validated in safe Rust and faults inside a handler are not re-delivered. Runtime-proven by `make smoke-signal`. (Synchronous fault signals only; async cross-task signalling is future work.)
- **Tamper-evident audit log** — each audit entry is HMAC'd (binding its sequence number) and a running hash-chain head commits to the entire ordered history, keyed by the per-boot pepper (`rust/src/audit.rs`); `SYS_AUDIT_DIGEST` exposes the digest + verify status for an external monitor. A detector, honestly scoped (not tamper-proof against a key-reading kernel compromise).
- **x86-64 only** — the dead 32-bit kernel build target (`BITS=32`, `linker.ld`, `lowlevel.S`, the legacy 32-bit GDT/TSS/IDT, and all `#if defined(__x86_64__)` branches) was removed. The kernel is now unconditionally long-mode; ring-3 userspace remains 32-bit compatibility-mode binaries.
- **Security hardening pass** — a focused review of every kernel C file produced fifteen targeted fixes committed to `main`: capability-space zeroing on task-slot reuse (dead task's caps no longer leak to a successor); consistent `fs_resolve_cap` in all capfs operations (generation-checked, eliminating raw pointer casts, use-after-free, and the packed-vs-raw object-value mismatch that caused wild kernel reads); key-material zeroization on capfs object deletion; locked initial passwords for accounts created without an explicit password; password changes now persist across reboots (the unconditional `set_user_password("password")` after loading the persisted database was removed); kernel stack cleared after `h_passwd`; entry-point integer overflow guard in `h_exec`/`h_run`; page-fault demand-pager called exactly once (double-call could kill a task whose fault was already handled); `sys_fs_mint_file` dead raw-pointer cast removed; flat binary loader guard against writing to the wrong physical address; shell `passwd` command fixed to pass `sys_getuid()` instead of hardcoded uid 0.
- **CI + smoke-boot** — GitHub Actions runs ten gated jobs: the unit tests + `clippy -D warnings`, a kernel/ISO build, an alt-config build matrix (`DEBUG_SHELL`/`MINIMAL_SECURE`), a **headless QEMU smoke-boot** (boots to the shell banner with no fault), an **ELF-loader + W^X boot self-test**, a **preemptive-scheduling self-test**, a **signal-handling self-test**, an **SMP self-test** (boots under `-smp 4` and asserts the APs run scheduled tasks + a TLB-shootdown round-trip), a reproducible-build check, and a security-scan/SBOM job on every push/PR. (Deeper scripted integration tests and fuzzing are still pending.)
- **Blocking `SYS_IPC_CALL`** — `SYS_IPC_CALL` now sends a message and atomically blocks the calling task until the server replies, with no ring-3 polling loop. The kernel saves the blocked task's trap frame (`saved_ksp`) and switches to the next runnable task via the same preemptive ISR mechanism used by the timer. When the server calls `SYS_IPC_REPLY`, the kernel delivers the reply directly into the waiting task's reply buffer (cross-address-space copy via temporary CR3 switch), patches the saved `rax`, and marks the task runnable. The shell's `fss_*` filesystem commands were also migrated from the old bespoke `fss_req`/`fss_rep` structs to the canonical `fs_request`/`fs_response` protocol (`fs_proto.h`), fixing the endpoint index mismatch that prevented them from actually communicating with the fs_server.
- **Blocking `SYS_WAIT_NOTIFY`** — `SYS_WAIT_NOTIFY` now blocks the calling task in `TASK_BLOCKED_NOTIF` state using the same `ipc_block_switch` mechanism as IPC call. `SYS_NOTIFY` ORs incoming badges into a pending-badge accumulator per notification slot; if a task is waiting it is unblocked immediately with the badge patched directly into its saved trap frame's `rbx` (avoiding any cross-address-space pointer copy). Multiple `notify()` calls before a `wait()` accumulate via OR. `interrupt_handler64` was extended to write back `frame->rbx` from `r.ebx` so badge-returning syscalls work without extra copy.
- **ATA cross-reboot persistence** — per-block AEAD metadata (nonce + auth tag) is now persisted to disk in a dedicated 64-sector region immediately after the superblock (`meta_start = 1`, `meta_blocks = 64`, 32 bytes per entry, 16 entries per sector). `storage_format` zeros the region and records its location in the superblock; `storage_mount` loads it into `g_block_meta[]` before any read/decrypt; `storage_encrypt_block` flushes the affected metadata sector synchronously before writing the ciphertext block (crash-safe ordering: stale ciphertext + new meta → AEAD reject, never silent plaintext exposure); `storage_free_inode_blocks` flushes cleared entries so freed blocks present=0 survives reboot. On-disk version bumped to 2 — v1 disks reformat on first boot rather than mounting with an incompatible layout.
- **LUKS-style disk_key wrapping** — the per-volume `disk_key` (root of all block key and metadata MAC derivation) is now sealed on disk with a password-derived KEK so the volume is unreadable without the login password even with physical disk access. `KEK = Argon2id(password, kek_salt)` (no `kernel_pepper` — must be stable across reboots); `disk_key` is wrapped with `AEAD(HKDF(KEK), nonce, aad=volume_key_salt, disk_key)`. Wrong password → AEAD tag mismatch → unlock denied. On first boot `storage_init` sets a deferred-format flag instead of formatting; `storage_unlock()` (called from the login handler after `verify_password`) runs `storage_format_sealed()` then unlocks, so the format only happens once a real password exists. Subsequent boots: `storage_mount()` reads the superblock (version check only), `storage_unlock()` unwraps `disk_key`, derives keys, loads and verifies the metadata HMAC. Superblock bumped to v4; the single 4 MiB Argon2id scratch buffer is shared via `kernel_argon2id()` to avoid a second 4 MiB static allocation.
- **Real `ls`, `cat`, `mkdir`, `rm`, `touch`, `echo > file`** — the shell's placeholder `ls` and `cat` stubs are replaced with real fs_server calls over blocking IPC. `mkdir`, `rm`, `touch`, and `echo text > file` (with auto-create) are added. The entire file-management surface now flows through the capability-gated, encrypted, persistent userspace FS.
- **Password-change key re-wrapping (`storage_rekey`)** — changing a login password used to leave the on-disk `wrapped_key_ct` sealed to the *old* password's KEK, so the next boot's `storage_unlock(new_password)` failed its AEAD tag check and locked the volume out permanently. `do_passwd` now calls `storage_rekey()` when a user changes their own password: it reads `disk_key` from RAM (already unwrapped since login), generates a fresh `kek_salt` and nonce for forward secrecy, re-derives the KEK via Argon2id, and re-seals `disk_key` before writing the updated superblock — no old password needed, since the in-RAM `disk_key` is the source of truth.
- **On-unlock filesystem consistency pass (`storage_fsck_pass`)** — runs at the end of `storage_unlock()`, once the metadata HMAC has verified, to reclaim inode-bitmap slots leaked by a crash mid-write: bits set by `storage_alloc_inode` before the inode itself was ever written, and inodes freed (`links == 0`, data blocks already released) before the bitmap bit was cleared. The bitmap is rewritten only if something was reclaimed, and the pass is itself crash-safe — idempotent, so an interrupted pass leaves the bitmap untouched and the same orphans are found on the next boot. Inodes that are fully written but never linked into a directory are not reclaimed by this pass; that needs a directory-tree walk (see Phase 2).
- **`SYS_BRK` (62) + dynamic heap growth** — `SYS_BRK` sets the program break to an absolute address, matching Linux `brk(2)` semantics (`addr=0` queries the current break without changing it). `SYS_SBRK`'s previous hard 64 KiB ceiling is gone: `heap_end` now grows on demand up to `USER_HEAP_MAX_SIZE` (64 MiB), with the demand pager committing physical pages only on first touch, so nothing is pre-reserved. Both handlers validate the new break against `heap_start .. heap_start + USER_HEAP_MAX_SIZE` so the heap cannot escape into the stack or kernel address space.
- **Userspace `malloc`/`free`/`calloc`/`realloc`** — a first-fit, coalescing allocator (`userspace/malloc.c`) backed by `sys_sbrk`: a 16-byte `blk_t` header precedes every allocation (size, used flag, prev/next in physical-address order), payloads are 8-byte aligned, `free()` coalesces with both physical neighbours in O(1) with no heap walk, and `realloc()` extends in place by absorbing a following free block before falling back to allocate-copy-free. The heap grows in 4 KiB multiples to amortise the `sbrk` syscall cost. `malloc.o` is linked into every `.pie.elf` automatically.
- **Symmetric multiprocessing (Phase 4)** — the kernel now brings up and uses the application processors, gated behind `SMP=1` so the default build stays single-CPU and byte-for-byte unchanged; `make smoke-smp` boots under QEMU `-smp 4` and asserts a runtime `SMP_SELFTEST: PASS`. **AP bringup**: a from-scratch real-assembly trampoline (`src/boot/ap_trampoline.S`) walks each AP real→protected→long mode, linked flat at its SIPI load address and embedded via `.incbin`; the BSP wakes every AP at once with a broadcast INIT-SIPI-SIPI ("all excluding self", so no MADT/APIC-id enumeration), and each AP picks a private idle stack by LAPIC id, installs a per-CPU TSS (own RSP0 + IST fault stacks — mandatory so two cores taking `int 0x80`/`#PF` at once don't share one kernel stack), enables SSE to match the BSP, and checks in via an atomic counter. This replaced inert scaffolding whose SIPI was never even sent. **Per-CPU scheduler**: each AP runs a LAPIC timer (calibrated against the PIT on the BSP) since the legacy PIC IRQ0 only interrupts the BSP; `preempt_on_tick` is SMP-safe under a raw ISR-safe scheduler lock with a per-task running-CPU guard (`task_running_cpu[]`), and the shared runnable pool + per-CPU pull is the load-balancing mechanism — verified by spawning one forever-looping worker per core and confirming they ran concurrently on multiple distinct CPUs. **IPC locking**: `ipc_block_switch` was brought under the same guard, and the endpoint mailbox, badge accumulator, and wake handoff are serialised by `endpoint_lock` (which had been declared but never taken) via locks that compile to nothing in the single-CPU build. **TLB shootdown**: a vector-0xFB IPI with a deadlock-free acknowledgement protocol (initiator broadcasts and waits — interrupts enabled, no scheduler lock held — until every receiver flushes and acks), verified by a round-trip in the self-test; the previous incorrect per-`switch_cr3` broadcast was removed. All seven gated self-tests (`elf`/`preempt`/`signal`/`fs`/`newlib`/`smp`) plus the default boot remain green.
- **A real libc: newlib port** — userspace programs can now link against newlib instead of hand-rolling every string/stdio routine. `userspace/crt0.c` provides `_start` → `posix_init()` → `main()`; `userspace/posix.c` is a per-process POSIX fd table (fds 0–2 wired to the console, fds 3+ routed to the `fs_server` over IPC, access-mode and bounds checked on every call, large I/O transparently split across `FS_IO_MAX`-sized round trips) that `userspace/newlib_glue.c` / `newlib_glue64.c` bridge into newlib's reentrant `_read_r`/`_write_r`/`_open_r`/`_fstat_r`/`_sbrk_r`/… family. `NEWLIB_SELFTEST=1` embeds and spawns `hello_newlib` at boot, exercising `printf`/`sprintf`/`malloc`/`free`/string ops end-to-end (`make smoke-newlib` asserts on the `PASS` marker). Landed alongside a `do_spawn` fix: `heap_start` was computed from the raw staged file size, which undercounts `.bss` and ignores the PIE ASLR slide; it now uses the ELF loader's actual highest `PT_LOAD` `vaddr + memsz`. With malloc, `sbrk`/`brk`, and a real libc all in place, porting a subset of GNU binutils/coreutils against Horus is now unblocked.

---

## Phase 1 — Stabilise the foundation

These items address the roughest edges in what already exists. They are good starting points for new contributors because they are self-contained and do not require deep kernel knowledge.

- **Preemptive scheduling** *(done)*: the timer forces a full-context switch of ring-3 tasks (see "Recently completed"). Remaining scheduler work: priorities/fairness, and hardening the cooperative `yield()`/IPC switch to the same full-context mechanism.
- **Consistent error codes** *(done)*: a shared `include/errno.h` defines a descriptive, errno-aligned `SYS_ERR_*` vocabulary used by both the kernel and userspace, with `sys_strerror()` to render a reason. The central dispatcher now distinguishes an unknown syscall (`SYS_ERR_NOSYS`) from a missing capability (`SYS_ERR_PERM`), and the auth and user-copy paths return `SYS_ERR_AUTH` / `SYS_ERR_FAULT`. See "Recently completed".
- **Shell command completion** *(mostly done)*: `ls`, `cat`, `mkdir`, `rm`, `touch`, `echo > file`, and `spawn` all invoke real syscalls end-to-end (see "Recently completed"). Remaining: `kill` — there is no kernel syscall to terminate another task at all yet, so a runaway or misbehaving spawned process cannot be stopped short of a reboot.
- **Page fault recovery** *(done)*: a task registers its own ring-3 fault handler (`SYS_SIGACTION`) and a fault is delivered to it instead of the task being killed; `SYS_SIGRETURN` resumes. See "Recently completed". Remaining: asynchronous task-to-task signalling (capability-gated on the target TCB), alternate signal stacks, masking.

---

## Phase 2 — Functional filesystem

A first robust increment has landed (`make smoke-fs`): filesystem semantics run in
a ring-3 `fs_server` over the kernel's persistent, encrypted object store, reached
by clients over IPC. See "Recently completed" and `docs/ARCHITECTURE.md`.

- **Filesystem server IPC** *(done, first increment)*: `fs_server` implements a
  hierarchical FS (dirs as inode data; root = inode 0) with lookup/create/mkdir/
  read/write/readdir/delete/stat over a versioned IPC protocol, backed by the
  encrypted object-store syscalls (56-61). Remaining: concurrent/multi-client IPC.
- **Persistent inode store** *(done, in-boot)*: `storage.c`'s superblock/inode/
  bitmap layout works and is exercised end-to-end; geometry is computed from the
  device. An on-unlock `fsck` pass now reclaims inode-bitmap slots orphaned by a
  mid-write crash (see "Recently completed"). Remaining: a directory-tree walk to
  catch orphaned-but-never-linked inodes, multi-block bitmaps, and double-indirect
  data blocks — there is still no write-ahead intent log, only this targeted
  bitmap-consistency pass.
- **ATA driver integration** *(done, selectable)*: `STORAGE_ATA=1` makes the ATA
  disk the block backend (probe + format-on-first-boot); the default build still
  uses the non-persistent RAM-backed vdisk. Per-block crypto metadata (nonces/tags)
  is now flushed to a dedicated on-disk region ahead of each ciphertext write, and
  the volume's `disk_key` is itself sealed with a password-derived KEK, LUKS-style
  (see "Recently completed"). Remaining: making `STORAGE_ATA=1` the default rather
  than an opt-in build flag.
- **RAM filesystem extension**: multi-level directories now exist in the server;
  proper ownership/permission bits tied to the capability model are still to do.
- **Capability-gated file access**: FS access is gated at the service boundary
  (endpoint capability + storage capability); per-file ACLs are the next step,
  along with reconciling the legacy in-memory capfs (`SYS_FS_*`) with the server.

---

## Phase 3 — Cryptography and security hardening

- **Replace custom password hashing** *(done)*: Argon2id (RFC 9106) — memory-hard, implemented from scratch in safe `no_std` Rust (`argon2.rs` on `blake2b.rs`), validated against the `argon2-cffi` reference vectors and wired into the auth path (see "Recently completed").
- **Hardware entropy** *(done)*: the kernel PRNG is a ChaCha20 fast-key-erasure CSPRNG seeded from RDRAND (with retry + health check), TSC jitter, and boot counters (`rng.rs`); raw TSC is never used as secret randomness.
- **ASLR enforcement** *(done: stack, heap, and load base)*: per-spawn stack top, heap gap, and image load base are randomised from the CSPRNG on every task spawn. Userspace is built static-PIE (`ET_DYN`); `do_spawn` picks a random page-aligned base and `try_elf_load` applies `R_386_RELATIVE` relocations there (verified end-to-end by `make smoke-elf`). Image-base entropy is bounded (~9 bits) by the 32-bit low-memory compatibility window; wider entropy would require a 64-bit userspace ABI.
- **Audit log integrity** *(done)*: a per-entry HMAC (sequence-bound) plus a running hash-chain head over the whole history make tampering detectable, keyed by the per-boot pepper (`rust/src/audit.rs`, exposed via `SYS_AUDIT_DIGEST`).
- **Encrypted storage** *(done, selectable)*: the block-level AEAD, per-block keys, key rotation, cross-reboot metadata persistence, and LUKS-style `disk_key` wrapping (password-derived KEK, re-wrapped on every password change) are all implemented and exercised via `STORAGE_ATA=1` (see "Recently completed"). What remains is making it the default backing store rather than an opt-in build flag (tracked under Phase 2).
- **`crypto.rs` implementation** *(done)*: real primitives now live in safe Rust — SHA-256/HMAC/HKDF/PBKDF2 (`sha256.rs`), a ChaCha20 CSPRNG (`rng.rs`), and a ChaCha20+HMAC-SHA256 AEAD (`aead.rs`). `crypto.rs` itself is intentionally empty.

---

## Phase 4 — Symmetric multiprocessing

Implemented and runtime-verified end-to-end, gated behind `SMP=1` so the default
build stays single-CPU and byte-for-byte unchanged (`make smoke-smp` boots under
QEMU `-smp 4` and asserts the marker). See "Recently completed".

- **AP bringup** *(done)*: a real-assembly real→protected→long-mode trampoline
  (`src/boot/ap_trampoline.S`) started via a broadcast INIT-SIPI-SIPI; each AP
  gets a private idle stack and per-CPU TSS (own RSP0 + IST fault stacks) and
  checks in via an atomic online counter.
- **Per-CPU scheduler** *(done)*: every AP runs a calibrated LAPIC timer (the
  legacy PIC IRQ0 only reaches the BSP) and pulls runnable tasks from a shared
  pool under a raw ISR-safe scheduler lock, guarded by a per-task running-CPU
  marker so no task runs on two cores at once — the shared pool + per-CPU pull is
  the load balancing. Remaining: priorities/fairness and true per-CPU run queues
  with task migration (the current shared pool balances by construction).
- **IPC locking** *(done)*: `ipc_block_switch` uses the same lock + running-CPU
  guard as the timer path, and the endpoint mailbox / badge accumulator / wake
  handoff are serialised (no-ops in the single-CPU build). Remaining: an
  atomic-publish fix for the narrow block→save→wake window under concurrent
  cross-CPU IPC (documented; not hit by the current system).
- **TLB shootdowns** *(done)*: a vector-0xFB IPI with a deadlock-free
  acknowledgement protocol (the initiator broadcasts and waits, interrupts
  enabled and no scheduler lock held, until every receiver has flushed and
  acked). The incorrect per-`switch_cr3` broadcast was removed (a local CR3
  reload already flushes the local TLB).

---

## Phase 5 — Userspace ecosystem

- **`libc`** *(done)*: newlib is ported and linked against a POSIX fd layer routed through the `fs_server` (see "Recently completed"). Remaining: `fork`/`exec` semantics (only `spawn` exists), `unlink`/`link` (currently `ENOSYS` stubs), signal delivery through `kill()` (blocked on the missing kernel syscall — see Phase 1), and actually porting real userspace programs (a coreutils/binutils subset) against it.
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
