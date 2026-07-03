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
- User authentication with lockout (Argon2id memory-hard password hashing), plus a global anti-spray throttle
- Reproducible builds (byte-for-byte deterministic `kernel.elf`, verified in CI)
- PS/2 keyboard input
- In-memory capability-addressed filesystem (capfs/ramfs); each operation enforces its `CAP_RIGHT_FS_*`
- Rust security core: capabilities, memory reference counting, SHA-256/HMAC/HKDF/PBKDF2, BLAKE2b + Argon2id (memory-hard password hashing), a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (encryption-at-rest), ChaCha20 CSPRNG (RDRAND + timing-jitter seeded), FFI validation
- Per-spawn stack and heap ASLR seeded from the CSPRNG
- 54 Rust unit tests; headless QEMU boot self-tests (`make smoke`; `make smoke-elf` for the ELF loader + W^X; `make smoke-preempt` for preemption; `make smoke-signal` for fault-signal delivery); GitHub Actions CI runs nine gated jobs (rust test + `clippy -D warnings`, kernel/ISO build, alt-config build matrix, smoke-boot, ELF/W^X boot self-test, preemptive-scheduling self-test, signal-handling self-test, reproducible-build check, security scans + SBOM)

### Added — Phase 2: userspace filesystem server over a persistent encrypted store

A first robust increment of the Phase 2 "functional filesystem" work: filesystem
semantics now run in a **ring-3 server** backed by the kernel's encrypted block
store, reachable by clients over IPC.

- **Encrypted object-store syscalls (56-61).** The kernel exposes a capability-
  gated, encrypted inode/block API to ring 3 — `SYS_FS_INODE_ALLOC`/`_FREE`,
  `SYS_FBLOCK_READ`/`_WRITE` (per-(ino,block) ChaCha20+HMAC AEAD, decrypt-and-
  verify / fresh-nonce seal in the kernel), `SYS_FS_STAT`, and `SYS_FS_SET_SIZE`
  — all gated on `CAP_BLOCK_DEV` (slot 7) + uid 0. **AEAD keys never leave the
  kernel TCB**; the server addresses storage by (inode, logical block) only.
- **Userspace `fs_server`.** Rewritten from a demo into a real hierarchical FS:
  directories are inode data holding packed dir entries (root = inode 0), with
  lookup/create/mkdir/read/write/readdir/delete/stat over a versioned IPC
  protocol (`include/fs_proto.h`) that fits the 256-byte mailbox. Requests and
  replies use two well-known endpoints (4/5) so a single-slot mailbox can't
  alias a request as its own reply.
- **Block store made real & selectable.** `storage.c` geometry is now computed
  from the device size (the old hardcoded `inode_count=16384` overran a 1024-
  block disk, so it had never functioned), fixed `INODES_PER_BLOCK` (2, not 4 —
  a 240-byte inode overran the block buffer at inode 2/3), added inode/block
  free-on-delete, and a **selectable backend**: RAM vdisk by default, ATA disk
  with `STORAGE_ATA=1` (probe + format-on-first-boot).
- **IPC is now non-blocking.** `SYS_IPC_SEND`/`RECV` return a would-block code
  instead of spinning on the cooperative `yield()` (which cannot correctly
  switch two ring-3 tasks); callers poll from ring 3 where timer preemption
  interleaves them. `sys_connect_fs_server` now mints a valid (fresh-serial) cap.
- **`make smoke-fs`** — a gated `FS_SELFTEST=1` boot self-test spawns the server
  + a client that drives the full path over IPC and prints `FS_SELFTEST: PASS`;
  `make smoke-fs STORAGE=ata` runs it against a real ATA disk image.

Deferred (tracked follow-ups): concurrent/multi-client IPC, cross-reboot
persistence of the per-block crypto metadata (nonces/tags), per-file ACLs,
double-indirect data blocks and multi-block bitmaps, and reconciling the legacy
in-memory capfs (`SYS_FS_*`) with the server.

### Security — hardening pass (this session)

A focused security review of every kernel file produced the following fixes, each
committed individually (see git log `fix(security): …`):

- **Capability space not zeroed on task-slot reuse** (`scheduler.c`). `cspace_pool`
  is a static array whose slots are reused when a task exits. Without a clear, a
  newly spawned task at slot *N* inherited the dead task's `CAP_USER`,
  `CAP_CONSOLE`, and `CAP_ENCRYPTED_STORAGE` — granting it unearned authority with
  no capability mint or grant. `create_task` now zeroes all 256 slots before
  installing the initial capabilities.
- **Page-fault handler double-call** (`idt.c`). The `rust_handle_demand_page_fault`
  weak stub called `handle_demand_page_fault` internally; `page_fault_handler` then
  called it again for `action == 0/1`. The second call found the page already
  present (returns −2), fell through to `rust_validate_page_fault`, and could kill
  a task whose page fault had already been correctly handled. The stub now returns
  −1 ("not handled") so there is one authoritative C call site.
- **New accounts created with empty password** (`syscall.c`). `h_useradd` passed
  `""` as the initial password; `do_useradd` hashed the empty string with
  `argon2id("", random_salt ‖ pepper)` — a valid hash anyone could match. Accounts
  created without an explicit initial password now receive a CSPRNG-random
  `pass_hash` that no Argon2id invocation can produce, locking the account until
  `SYS_PASSWD` sets a real password.
- **Entry-point integer overflow** (`syscall.c`). Both `h_exec` and `h_run` accept
  user-supplied `load_base` and `entry_offset` as `uint32_t` and added them without
  an overflow check. A crafted pair whose sum wraps could produce an entry point at
  an arbitrary address. Both handlers now reject `load_base + entry_offset ≥
  USER_MAX_VADDR`.
- **Duplicate `#define PAGE_COW`** (`paging.c`). Removed the second definition at
  line 313; the first (line 15) is authoritative and matches `idt.c`.
- **capfs: raw `fs_object *` casts bypassed generation check** (`ramfs.c`). Four
  functions — `capfs_create`, `capfs_delete`, `capfs_readdir`, `capfs_read`,
  `capfs_write` — cast `cap->object` directly to `struct fs_object *`, bypassing
  the generation check that `capfs_lookup` (the only correct caller) enforced via
  `fs_resolve_cap`. This allowed: (a) use-after-free — a deleted file's slot
  reached through a stale cap; (b) mismatched object-value formats — `capfs_lookup`
  stores a packed `(idx | gen<<32)` value while `capfs_create` stored a raw
  pointer, so a lookup-derived cap passed to `capfs_read` dereferenced the packed
  integer as an address, producing a kernel fault or wild read. All five functions
  now use `fs_resolve_cap(cap)`, and `capfs_create` now stores `fs_pack_object()`
  to match `capfs_lookup`.
- **capfs: pool object leaked on Rust validation failure** (`ramfs.c`). The old
  `capfs_create` allocated a pool object (marking it `in_use = 1`) before running
  the Rust FS policy check; a rejection returned −20 but left the slot permanently
  live and unlinked — unrecoverable until reboot. Validation now runs first.
- **capfs: key material not zeroed on delete** (`ramfs.c`). `capfs_delete` set
  `in_use = 0` without zeroing `enc_key`, `mac_key`, `file_nonce`, or `file_tag`.
  The deleted object's key material sat in the pool until the next allocation.
  All four fields are now wiped with `secure_zero` before release, and the
  generation counter is bumped so outstanding packed capabilities immediately fail
  the `fs_resolve_cap` generation check.
- **Password reset every reboot** (`syscall.c`). `users_init` unconditionally
  called `set_user_password(uid, "password")` after loading the persisted user
  database from ramfs — resetting every changed password on every boot and making
  `SYS_PASSWD` effectively non-functional for the `"user"` account. The call is
  removed; password changes now survive across reboots. Additionally, the
  first-boot creation branch passed the array *index* (not the uid) to
  `set_user_password`, so the call always failed silently — fixed to pass uid 1000.
- **h_passwd kernel stack not cleared** (`syscall.c`). The `newpass[]` buffer was
  not zeroed after `do_passwd` returned, leaving the cleartext password sitting in
  the kernel stack frame until the next function at the same stack depth. Added
  `secure_zero`.
- **shell `passwd` hardcoded uid 0** (`userspace/shell.c`). The `passwd` command
  always passed `target = 0` to `sys_passwd`, so non-root users got "passwd
  failed" (kernel correctly rejects uid != self unless admin), and root would be
  changing uid 0's password rather than the current user's. Fixed to pass
  `sys_getuid()`. The branch also required a trailing space (`"passwd "`) so
  typing `passwd` alone never matched; expanded to also accept the bare command.
- **`sys_fs_mint_file` raw pointer crash** (`syscall.c`). After the `capfs`
  refactor, `cap->object` is a packed `(idx | gen<<32)` value, not a raw pointer.
  `sys_fs_mint_file` cast it to `struct fs_object *` to re-read the object type;
  this produced a garbage address and could fault or mislabel a `CAP_DIR` as
  `CAP_FILE`. The cast is redundant: `rust_cap_mint` already copies `src.typ` into
  the destination slot. The dead cast was removed.
- **Flat binary loader: write to wrong physical address** (`syscall.c`). If the
  page-table walk in `do_spawn`'s flat-binary fallback path failed to find a mapped
  page (present bit clear), `dphys` was left equal to the user virtual address;
  writing to that value as a physical address would corrupt kernel memory at that
  offset. Unmapped pages are now skipped rather than written.

### Fixed

- **Interactive login hung after entering the password.** `SYS_AUTH` runs the
  Argon2id hash on the caller's per-task kernel stack, which was only 8 KiB —
  too small for Argon2's several stacked 1 KiB blocks, so the hash overran the
  stack and wedged the task. (Boot-time hashing worked because it runs on the
  larger boot stack.) Raised `KERNEL_STACK_SIZE` to 32 KiB. Verified with a
  scripted serial login (root → prompt) under both KVM and TCG.
- **`make run` serial console showed nothing.** The console chardev on port
  4445 used `wait=off`, so the banner/prompt were emitted before a client
  connected and lost. Switched to `wait=on` (boot waits for `nc localhost 4445`)
  and added `-machine accel=kvm:tcg` so interactive use gets KVM when available.

### Security

Recent hardening pass (see git history for individual commits):

- **Tamper-evident audit log added.** Each audit entry is now bound by `HMAC(pepper, LE64(seq) || event)` — the sequence number defeats in-place edits, ring-slot swaps, and replays — and the log keeps a running chain head `HMAC(pepper, head || mac)` over every event ever appended (including entries already overwritten in the ring). The keyed-hash logic is safe Rust (`rust/src/audit.rs`); a new `SYS_AUDIT_DIGEST` (52), gated by the same `CAP_AUDIT` READ capability as `SYS_READ_AUDIT`, returns the event count, chain-head MAC, and a constant-time verify status so an external monitor can detect drops/rewrites/rollbacks. Scoped honestly as a detector, not tamper-proof against a kernel compromise that can read the pepper.
- **Ring-0 wild-write in the ELF loader fixed.** `try_elf_load` walked the target page tables by hand without present-bit checks, so a crafted ELF segment over an unmapped/huge-page mapping could make the kernel dereference and write a garbage physical address at ring 0. Segment copies now go through `copy_to_user`, which checks present/user/write at every level and fails closed.
- **`sudo` deadlock fixed.** `SYS_SUDO` called `cap_alloc_fresh_serial()` (which takes `cap_lock`) three times while already holding `cap_lock`; the non-recursive lock would hang the kernel on the first `sudo`. Serials are now allocated before the lock is taken.
- **Syscall dispatch made table-driven.** The ~50-arm `switch` with per-case capability checks became a descriptor table enforced at one choke point, with a compile-time guard that every syscall number has a table slot. Removes the "forgot a check / forgot a case" bug class; unknown numbers fail closed.
- **W^X enforced.** User stacks are mapped non-executable and the ELF loader honours each segment's `p_flags` (code read+execute, data/rodata no-execute), closing the previous all-RWX user mappings. Verified by the new smoke-boot test for the live path.
- **Smaller fixes.** Stopped leaking the page-table physical base (`cr3`) to ring 3 via `SYS_GET_TASK_INFO`; hardened the (unused but exported) `cap_create_revocation_set` to take `cap_lock` and require authority like its siblings; removed a stray `spin_unlock` on an unheld lock in the demand-fault handler.

- **Encryption-at-rest cipher replaced (block storage).** The storage layer's hand-rolled "AES-128" — a broken AES-NI key schedule plus an unaudited ARX software fallback, neither of which was actually AES — has been removed. Block encryption now uses a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust, with a fresh random per-write nonce (eliminating CTR keystream reuse), per-block HKDF subkeys, `(ino, block)` bound as AAD, and constant-time fail-closed verification. The volume key is now HKDF-SHA256-derived. This also removed a latent 4080-byte-into-512-byte-buffer overflow in the old encrypt/decrypt path.
- **ramfs per-file cipher replaced (in-memory filesystem).** The block-storage rework above missed a *second*, independent homebrew cipher: `efs_apply_keystream` in `ramfs.c`, which encrypted `is_encrypted` capfs files with an unauthenticated ad-hoc XOR keystream, derived per-file keys by XORing the task master key with the object index, and refreshed no nonce (deterministic keystream reused across rewrites). The live in-memory filesystem now seals encrypted files with the same `rust/src/aead.rs` AEAD as block storage: independent HKDF-SHA256 enc/mac subkeys (fresh random salt per file, fail-closed if HKDF yields no key material), a fresh CSPRNG nonce on every write, the object identity bound as AAD, and a 16-byte tag over the whole ciphertext. Reads decrypt-and-verify the entire object before returning any prefix, so a tampered file or a wrong key yields an authentication error instead of plaintext. `fs_object` now stores `enc_key`/`mac_key`/`file_nonce`/`file_tag` in place of the old `enc_file_key`/`file_key_iv`, and per-file key derivation is unified in `capfs_alloc_object`.
- **Ring-3 storage backend callback removed.** `SYS_REGISTER_STORAGE_BACKEND` previously let userspace register function pointers the kernel then invoked from ring 0 (an SMEP violation and a TCB escape). The syscall now fails closed (`SYS_ERR_NOSYS`); the ABI slot is reserved.
- **Information-leak and hygiene fixes.** Eliminated a kernel `.rodata` over-read in the version syscall; cleartext passwords are now zeroed from the kernel stack after authentication; the filesystem-listing syscall honours the caller's buffer length; and the authentication path was equalised so it no longer reveals valid usernames by timing.
- **CSPRNG seeding is asserted at boot** before any key material is derived (fail-closed if the pool is somehow unseeded).

### Changed

- **Consistent, descriptive error codes.** Added `include/errno.h` — one shared, errno-aligned `SYS_ERR_*` vocabulary (`SYS_ERR_PERM`, `SYS_ERR_NOENT`, `SYS_ERR_AUTH`, `SYS_ERR_FAULT`, `SYS_ERR_INVAL`, `SYS_ERR_NOSYS`, `SYS_ERR_REVOKED`, `SYS_ERR_NORIGHT`, …) plus `sys_strerror()`, included verbatim by both the kernel (`src/include/kernel.h`) and userspace (`include/syscall.h`). The central syscall dispatcher now distinguishes an unknown syscall (`SYS_ERR_NOSYS`) from a missing capability (`SYS_ERR_PERM`) — previously both `-1` — and the auth/sudo and user-copy paths return `SYS_ERR_AUTH` / `SYS_ERR_FAULT`; the shell prints `sys_strerror()`. (Deeper internal helpers keep their ad-hoc small negatives for now.)
- **Argon2 multi-lane + configurable cost.** `rust/src/argon2.rs` now supports `p ≥ 1` lanes (cross-lane referencing and final-block XOR per RFC 9106), validated against `argon2-cffi` `p=2`/`p=4` reference tags; the `m`/`t`/`p` cost is set by `ARGON2_M_COST_KIB`/`ARGON2_T_COST`/`ARGON2_P_COST` in `kernel.h` and the static scratch buffer sizes to match. The kernel profile stays 4 MiB / 3 passes / 1 lane.
- **Argon2id password hashing (Phase 3).** Replaced PBKDF2-HMAC-SHA256 with Argon2id (RFC 9106), the memory-hard KDF, so an attacker must spend memory as well as time — defeating the cheap GPU/ASIC parallel brute force PBKDF2 is vulnerable to. BLAKE2b (`rust/src/blake2b.rs`) and Argon2id (`rust/src/argon2.rs`) are implemented from scratch in safe `no_std` Rust — no external dependency — and validated against the RFC 7693 BLAKE2b vector and `argon2-cffi` Argon2id reference tags (including the kernel's exact 4 MiB / 3-pass / single-lane profile). The kernel supplies a 4 MiB static scratch buffer (no allocator); hashing runs non-preemptibly inside the syscall, so one shared buffer is safe, and the buffer is `.bss` so the reproducible build is unaffected. Boot-time hashing of the default accounts adds ~3 s under emulation. With this, Phase 3 (crypto hardening) is complete — hardware entropy, per-spawn ASLR, and audit-log integrity were already in place.
- **Full ASLR: image load base randomised (PIE userspace).** Userspace was linked non-PIE at a fixed `0x400000`, so only the stack and heap were randomised. The shipped binaries are now built static-PIE (`ET_DYN`, `-fPIE`, linked with `userspace/pie.ld`); `do_spawn` picks a random page-aligned load base for ELF images, and `try_elf_load` applies `R_386_RELATIVE` relocations at that base (failing closed on any other relocation type, `DT_RELA`, or an out-of-segment target). `create_user_pagedir` premaps the image window at the per-task base, and the per-task base is recorded on the TCB. Non-PIE flat images (the legacy fallback) still load at the fixed base. Image-base entropy is bounded (~9 bits) by the low 32-bit compatibility-mode window userspace runs in. Verified end-to-end: the live PIE shell boots at a varying base (`make smoke`), and a gated ELF self-test proves relocation correctness + W^X at the randomised base (`make smoke-elf`), with the reproducible build unchanged.
- **Fault signals added.** A userspace fault was previously fatal — the kernel killed the task unconditionally. A task can now register its own ring-3 fault handler (`SYS_SIGACTION`); on a page fault or CPU exception in ring 3, `try_deliver_fault_signal` saves the full trap frame and redirects the task into its handler (signal number in `ebx`, faulting address in `ecx`) instead of killing it, and `SYS_SIGRETURN` (serviced in `interrupt_handler64`, since it rewrites the live frame) resumes the exact pre-signal context. Controls: the handler address is validated to the user code window in safe Rust (`rust_signal_handler_addr_ok`); a fault inside a handler is not re-delivered (`in_signal` guard, no loops); the handler runs at ring 3 with unchanged privileges, so no new authority is granted and there is still no cross-task signalling. Verified by a gated self-test (`make smoke-signal`).
- **Preemptive scheduling added.** The scheduler was cooperative-only, and its context switch saved just `%esp` + a return address into 32-bit TCB fields, so it could never correctly switch two running tasks. Real preemption now works: the ISR already saves a full 64-bit trap frame per task, so `interrupt_handler64` returns the kernel `%rsp` to resume on and the timer (PIT, 100 Hz) switches ring-3 tasks by swapping between their per-task kernel stacks. Switching only happens when a tick interrupts ring 3 (no lock held, whole state captured by the frame); ring-0 ticks never switch. Freshly spawned tasks get a fabricated initial frame so the timer can `iretq` into them. Verified by a gated 2-task self-test.
- **32-bit kernel build removed; x86-64 only.** The kernel has run exclusively in 64-bit long mode for a long time (`BITS=64` default, CI 64-bit only), so the dead 32-bit build path was removed: the `BITS=32` Makefile branch, the `i686` Rust target, `linker.ld`, `src/kernel/lowlevel.S`, the legacy 32-bit GDT table / TSS / IDT setup, and every `#if defined(__x86_64__)` guard (collapsed to the long-mode arm). Ring-3 userspace stays 32-bit (compatibility-mode binaries). Net −676 lines. As a side effect, `serial_init()` — previously reachable only from the dead 32-bit init — is now wired into the 64-bit boot, so serial is configured on real hardware rather than relying on the emulator's default 16550 state.

### Known incomplete

- Scheduler: preemption is single-core with no priorities/fairness; the legacy cooperative `yield()`/IPC switch between multiple tasks is a separate, un-hardened path
- IPC notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY` return `SYS_ERR_NOSYS`); no true blocking endpoints
- Disk-backed persistent storage as the default (encrypted-block and ATA code exist but are not the live backing store)
- SMP / multicore
- Userspace filesystem server
- Wider load-base ASLR entropy (userspace is static-PIE with a randomised base, but bounded to ~9 bits by the 32-bit low-memory window)
- Deeper booted-kernel integration tests (beyond the smoke-boot check) and fuzzing

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for detail.
