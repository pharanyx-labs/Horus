# Horus Roadmap

This document describes where Horus is **headed** — the work that is still ahead.
For what already exists, see the summary below, the git history, and
`docs/ARCHITECTURE.md`.

The phases are roughly ordered by dependency and priority, but they are largely
independent and can be picked up in any order. Nothing here is a commitment —
priorities shift as contributors join and the design evolves. If you want to work
on something, open an issue or start a discussion first; coordination saves
effort.

---

## Where things stand

The foundation is a working x86-64 capability microkernel that boots a ring-3
`init` supervising a ring-3 shell, and passes nineteen headless QEMU self-tests
in CI. Already in place:

- **Kernel core** — long-mode microkernel linked into the higher half at
  `0xFFFFFFFF80000000`, so no kernel address is a user address; capability-based
  access control with table-driven, fail-closed syscall dispatch; preemptive
  scheduling; ring-3 fault signals delivered to a registered handler; per-spawn
  ASLR; W^X user memory; per-task x87/SSE context; SMEP/SMAP; a tamper-evident
  HMAC-chained audit log.
- **Process control** — a ring-3 `init` (PID 1) launches at boot and spawns,
  capability-endows, and *blocking*-supervises the shell (`SYS_WAIT`). A task
  can spawn a child from ring 3 (`SYS_SPAWN`, which hands the caller a `CAP_TCB`
  to the child), replace its own image (`SYS_EXEC_NAMED`), delegate a capability
  to a child it supervises (`SYS_CAP_GRANT`), signal a task it holds a `CAP_TCB`
  for (`SYS_SIGNAL`), terminate itself (`SYS_EXIT`) or such a task (`SYS_KILL`),
  and block until one exits (`SYS_WAIT`), with waiter wake-up on both a clean
  exit and a fault. A task can also spawn/exec a program image it read from a
  file (`SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE`, execve-from-fd) and run signal
  handlers on an alternate stack (`SYS_SIGALTSTACK`) (`make smoke-proc`).
- **Multiprocessing** — the application processors are brought up and run
  scheduled tasks across cores with acknowledged TLB-shootdown IPIs, behind an
  `SMP=1` build gate (`make smoke-smp`).
- **Cryptography** — from-scratch, test-vector-validated Argon2id password
  hashing, a ChaCha20 CSPRNG seeded from RDRAND, and a ChaCha20 + HMAC-SHA256
  AEAD for encryption-at-rest, all in safe `no_std` Rust.
- **Filesystem** — a ring-3 `fs_server` over an encrypted object store, reached
  over IPC; real `ls` / `cat` / `mkdir` / `rm` / `touch` / redirection from the
  shell. Persistent by default: the kernel probes for an ATA disk at boot and uses
  the encrypted store (files survive a reboot, unsealed at login) when one is
  present, falling back to an in-RAM disk when it is not. Per-file ownership and
  POSIX permissions are enforced by the server against the caller's kernel-attested
  identity, multiple clients can use it concurrently (replies routed to each caller
  by identity via `SYS_IPC_REPLY_TO`), and multi-block updates are crash-atomic via
  an HMAC-authenticated write-ahead redo journal replayed at mount (`make smoke-fs`,
  `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`).
- **Userspace runtime** — ring-3 tasks run the 64-bit ABI (`EM_X86_64`
  static-PIE, relocated at load), with a demand-paged heap via `sbrk`/`brk`, a
  userspace `malloc`, and an `x86_64-elf` newlib libc port over a per-process
  POSIX fd layer (`make smoke-newlib`). The only 32-bit code left is the boot
  on-ramp that must be: the multiboot entry stage and the AP SIPI trampoline.
- **CI** — twenty-three gated jobs (twenty-four total; the `security` SAST/SBOM
  scan is advisory): `rust` (`cargo test` + `clippy -D warnings`), `kernel`
  (build + ISO), `altconfigs` (DEBUG_SHELL/MINIMAL_SECURE matrix), the headless
  QEMU boot `smoke`, seventeen runtime self-tests (`smoke-elf`, `smoke-elf64`,
  `smoke-aslr`, `smoke-preempt`, `smoke-signal`, `smoke-proc`, `smoke-cow`,
  `smoke-notify`, `smoke-smp`, `smoke-fs`, `smoke-fs-perms`, `smoke-fs-conc`,
  `smoke-fs-persist`, `smoke-fs-wal`, `smoke-fs-large`, `smoke-init-fs`,
  `smoke-newlib`), the scripted `smoke-session` integration test, and a
  `reproducible` build check. The whole filesystem suite (persistence,
  permissions, concurrency, journal crash-recovery, large files), the newlib
  libc port, and async notifications are now CI-enforced, not local-only.

---

## Phase 1 — Process lifecycle and control — *complete*

The process model is complete; the remaining work has moved into the phases
below. For the record, the phase delivered:

- **Signals** — `SYS_SIGNAL` delivers async task-to-task signals into a
  registered handler, the pending set is a full 1..31 bitmask, `SYS_SIGMASK`
  blocks/unblocks signals (delivering the lowest unmasked one), a signal to a
  task parked in `SYS_WAIT` interrupts the wait (`SYS_ERR_INTR`) and delivers
  promptly, and `SYS_SIGALTSTACK` runs a handler on a registered alternate stack
  (an `SS_ONSTACK` guard, so a corrupt or overflowed primary stack cannot stop
  the handler running).
- **Full `argv`** — `SYS_SPAWN` and `SYS_EXEC_NAMED` marshal a full argument
  vector onto the child's stack, read back via `SYS_GET_ARGV`.
- **`exec` from a file** — `SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE` spawn or exec a
  program image the caller supplies in its own memory (execve-from-fd): the
  caller reads the image from a file via the `fs_server` — the shell's `run
  <file>` does exactly this — and the kernel validates it with the same loader a
  named binary uses (`arm_image_from_user` → `try_elf_load`: W^X, bounds,
  fail-closed relocations), gated by the same slot-3 `WRITE|EXEC` capability. This
  decouples exec from any one filesystem and adds no kernel↔server IPC
  reentrancy.
- **`fork` — deliberately not adopted** — the ring-3 `SYS_SPAWN` +
  `SYS_CAP_GRANT` model already gives create-a-task and hand-it-capabilities
  without fork's whole-address-space aliasing and its least-privilege problem (a
  forked child would inherit *every* parent capability).
- **Init launches the servers** — the default boot brings up the system through
  `init`: it is endowed from the root cnode with a `CAP_USER` admin cap, two
  `CAP_ENDPOINT` caps and (via slot 9) the object-store cap, launches `fs_server`
  and provisions **all four** of its capabilities purely with `SYS_CAP_GRANT` —
  no direct root-cnode installs — then launches and supervises the shell
  alongside it. Spawned children inherit their spawner's uid (closing a latent
  "child comes up as uid 0" hole), and the root shell can see every task (`ps`)
  under the same uid==0 authority the object-store syscalls enforce.

Proven by `make smoke-proc` (exit + kill + spawn + exec + grant + image +
altstack + signal) and `make smoke-init-fs` (the delegated server driven by an
automated client end-to-end).

---

## Phase 2 — A production filesystem — *complete*

The filesystem persists by default, enforces per-file ownership and permissions,
serves multiple clients, is crash-atomic, supports large files, and is the
system's single filesystem (the legacy parallel capfs is gone).

**Persistence is done:** the shipped kernel probes for an ATA disk at boot and
uses the encrypted store when one is present (the per-block crypto metadata is
flushed on write and reloaded + HMAC-verified at login, so files survive a
reboot), falling back to the ephemeral RAM vdisk when no disk is attached; a
persistent disk comes up sealed and is unwrapped at login. Proven by
`make smoke-fs-persist`.

**Ownership and permissions are done:** the `fs_server` is the filesystem
reference monitor, enforcing POSIX owner/group/other rwx and ownership against the
caller's *kernel-attested* uid/gid — `SYS_IPC_SENDER` gives the server the sender's
login identity, never anything the client puts in the request — with root (uid 0)
as the only ambient authority. New inodes are owned by their creator; `chmod` is
owner-or-root, `chown` is root-only. Proven by `make smoke-fs-perms` (a non-root
client is denied what its real uid disallows and cannot claim to be another user).

**Multi-client concurrency is done:** several clients can use the one
(single-threaded) `fs_server` at once without their replies colliding. The server
replies with `SYS_IPC_REPLY_TO`, which routes each reply to the request's
kernel-recorded sender — delivered directly into that client's blocked
`SYS_IPC_CALL`, never via a shared reply endpoint that another client could poll
or overwrite. Requests still serialise through the server (one processed at a
time), which is appropriate for a single-core-default kernel; genuine parallel
processing (a worker pool) is a later step. Proven by `make smoke-fs-conc` (three
clients hammer the server concurrently, each verifying it receives only its own
replies).

**Crash resilience is done** (the atomicity core): every multi-block object-store
update runs inside a **write-ahead redo journal** (v5 on-disk layout) — the block
bitmap, inode, per-block crypto metadata, superblock `meta_hmac` and data all
commit together via an HMAC-authenticated journal header, then apply to their home
locations; a crash mid-update is completed (or discarded) by replay at the next
mount, so the filesystem is always fully before or fully after the operation. This
also closed a latent bug where a crash between a metadata-sector write and the
superblock write could desync `meta_hmac` and refuse to mount the whole volume.
The mount-time `fsck` reclaims both orphaned inodes and leaked data blocks. Proven
by `make smoke-fs-wal` (boot 1 commits a write then crashes before applying it;
boot 2 replays it and the data survives), alongside `smoke-fs` and
`smoke-fs-persist`.

**Large files are done:** double-indirect data blocks are implemented and the
volume is 4096 blocks (2 MiB), so a single file maps through the direct +
single-indirect + double-indirect range (up to 12 + 64 + 64×64 = 4172 blocks).
Proven by `make smoke-fs-large`, which also frees a ~130-block file in one journal
transaction (every freed block clears the same block-bitmap sector, so the writes
coalesce and the transaction stays well under the 16-sector journal limit — a
large-file free never overflows or aborts). This pass also fixed a latent
single-indirect fanout bug: the pointers-per-block count was 1024 instead of the
correct 64, which would have overrun a stack buffer for any file past block 76.

**The legacy capfs is gone:** the parallel in-memory capability filesystem
(`SYS_FS_*` 38–45, `fs_objects[]`, the `capfs_*` engine and its own at-rest AEAD)
has been removed — the syscalls fail closed, the numbers are reserved, and the
encrypted `fs_server` is the system's single filesystem. This shrinks the ring-3
attack surface to one, capability-mediated, permission-enforcing FS.

### Deliberate non-goals

- **Per-file ACLs — not adopted.** POSIX owner/group/other plus a `uid 0`
  superuser, enforced by the `fs_server` against the caller's kernel-attested
  identity, is a complete discretionary access-control model. Full ACLs would add
  a large, security-sensitive surface (on-disk ACL storage, evaluation, new proto
  ops) for no gain in what can be *expressed* securely with the existing model, so
  they are intentionally out of scope.
- **Multi-block allocation bitmaps — not adopted.** The single 512-byte bitmap
  block caps the volume at 4096 blocks, which the allocator already enforces
  safely (it never allocates past the cap). Growing the cap is a pure capacity
  feature with no security value; it is deferred rather than built.

---

## Phase 3 — SMP maturity

The SMP foundation is in place behind a build gate; this phase makes it
production-grade and default.

- **Default-on**: retire the `SMP=1` gate once the multi-core scheduler is
  hardened, so the shipped kernel uses every core.
- **Real per-CPU run queues**: replace the shared runnable pool with per-CPU
  queues plus explicit load-balancing/migration, and add scheduling priorities
  and fairness.
- **Finish retiring the cooperative switch** — *done*: boot of `init`, first
  entry of every task, `SYS_YIELD`, blocking IPC/`SYS_WAIT`, and preemption all
  use the full-context trap-frame path (`sched_enter_user` /
  `sched_yield_switch` / `ipc_block_switch` / `preempt_on_tick`). The legacy
  cooperative `schedule()`/`yield()` switch has been removed.
- **Concurrent-IPC correctness** — *done*: syscall handlers only set
  `pending_block`; `ipc_block_switch` writes `saved_ksp` first, barriers, then
  `ipc_publish_pending_block` publishes the waiter (endpoint / SYS_WAIT link /
  notification) so a cross-CPU wake always patches a valid trap frame. A reply
  that races into the mailbox before publish is consumed immediately.

---

## Phase 4 — Userspace ecosystem

With a libc and a heap in place, grow what runs on top.

- **Complete the libc surface**: `unlink()` is now wired end-to-end (libc
  `unlink` → `posix_unlink` → the `fs_server`'s permission-checked `FS_OP_DELETE`,
  with path resolution and `errno` mapping), and `stat()`/`fstat()` now report the
  file's real mode, uid and gid from the server instead of hardcoded `0644`/`0755`
  — both proven by `make smoke-newlib`. Wiring `unlink` also fixed a latent
  `posix.h`/newlib `O_*` flag-value mismatch that had silently dropped `O_CREAT`
  on the newlib `open()` path. `rename()` and `O_TRUNC`/`ftruncate()` are now
  wired too (new `FS_OP_RENAME` / `FS_OP_TRUNCATE` protocol ops, both
  permission-checked against the caller's attested uid; truncate zeroes the
  freed tail so a later grow can't read stale bytes) — the two BFD-critical file
  primitives, also proven by `make smoke-newlib`. `O_APPEND` is honoured on
  write as of the `FS_OP_APPEND` op — the flag had been accepted by `open()` and
  then ignored by `write()`, so an append silently overwrote the file from byte
  0. The offset is now chosen by the *server*, at the file's current end, which
  a client-side stat-then-write could not do without racing another writer.
  **Directory iteration and a working directory are wired too:**
  `opendir`/`readdir`/`closedir` run over a new permission-checked `FS_OP_READDIR`
  op (a `read` on the directory is required; `opendir` on a regular file is
  `ENOTDIR`, on a missing path `ENOENT`), and `chdir`/`getcwd` maintain a
  per-process cwd with relative-path resolution (a relative create lands under the
  cwd, `..` walks up, and a `chdir` to a missing path fails leaving the cwd
  unchanged). All proven by `make smoke-newlib`.
  **The environment, `fcntl`, `kill()` and `mkstemp` are wired too:** an empty
  `environ` is provided (so libc's `getenv` links and returns "not found"),
  `fcntl` validates the fd and no-ops the flag words (`F_GETFL`/`F_SETFL`/
  `F_GETFD`/`F_SETFD`; anything else `EINVAL`), and `mkstemp` round-trips a named
  temp file through the object store. `kill()` now forwards onto `SYS_SIGNAL`
  — the "descendants-only" resolution of the pid→capability question, which fell
  straight out of the existing gating rather than needing a broker: `SYS_SIGNAL`
  already looks a `CAP_TCB` for the target up in the *caller's* cspace (or accepts
  `CAP_USER` admin, and always allows self), so `kill(pid, sig)` reaches your own
  descendants and yourself and is `EPERM` for anything else, with no ambient pid
  namespace exposed. Signal numbers already agree with newlib's for the set that
  matters (`SIGKILL`/`SIGTERM`/`SIGSEGV`/`SIGILL`); the null signal (sig 0) is a
  best-effort success since Horus has no reachability-probe syscall. All proven by
  `make smoke-newlib`.
  **`link()` and `tmpfile()` are wired too, completing the libc surface.**
  `link()` is a genuine store-level hard link: a new `FS_OP_LINK` op (write on the
  new name's parent dir, owner-or-root on the source, directories refused) adds a
  second directory entry for a file and increments its on-disk link count via a
  new `SYS_FS_INODE_LINK`; `unlink` (`SYS_FS_INODE_FREE`) now *decrements* that
  count and frees the inode and its blocks only when the last name is gone. `stat`
  reports the real count (`st_nlink`), plumbed through `FS_OP_STAT`. `tmpfile()`
  did **not** need the harder unlinked-but-open inode semantics: it keeps the temp
  file *named* for its lifetime and unlinks it when the fd is closed (a `close()`
  hook), which meets the observable contract — a stream removed on `fclose` —
  without making the security-critical `fs_server` track open fds; the one
  deviation is a briefly-visible name, and a stream abandoned without `fclose`
  leaves that name until removed. Both proven by `make smoke-newlib` (link:
  two names → one inode with `nlink==2`, unlink one and the data survives under
  the other at `nlink==1`, a hard link to a directory is refused, the last unlink
  frees; tmpfile: a write/rewind/read round-trip then `fclose`). The libc surface
  itself is complete, and the two program-*size* caps that used to block a real
  binutils port are both lifted (see the address-separation item in Phase 5): the
  image-window premap is sized to the whole image (no longer 128 KiB), and the
  staged-image buffer moved off `.bss` into a pool reservation, so
  `MAX_PROGRAM_SIZE` is now 8 MiB and trivially raisable. `make smoke-newlib`
  loads a ~1.5 MiB image end-to-end. What is left for the port itself is bringing
  up the coreutils/binutils sources against newlib.
- **Port real programs** — *started*: GNU coreutils `echo(1)` (coreutils 9.5
  `src/echo.c`, vendored byte-identical and never edited) builds against the
  newlib port and runs as a ring-3 task, gated by `make smoke-coreutils`. The
  marker is produced by upstream's own code path — argv joined with spaces and
  `-e` escapes expanded — so a pass means real third-party source ran correctly.
  Upstream's autoconf + gnulib build does not survive the trip to a freestanding
  target (no `x86_64-elf` cross toolchain, `configure` runs target probes, and
  every utility pulls `src/system.h` → ~25 headers → 478 gnulib `.c` files), so
  the port supplies what those would have: `config.h`, a trimmed `system.h`,
  `assure.h`, `c-ctype.h` and a small `port.c`. The vendored sources are **GPLv3**
  and isolated in `userspace/ports/coreutils/` with their own `COPYING`; the port
  glue is MIT like the rest of the tree (see that directory's `README.md`).
  Doing this found four real bugs — `crt0` never passed `argv` and exited without
  running `atexit` (so stdio never flushed), `SYS_GET_ARGV` truncated its pointer
  to 32 bits, and the ELF loader refused `R_X86_64_GLOB_DAT`, which every libc
  program reaching `exit()` emits. Next: more utilities (`cat`, `wc`), then
  binutils.
- **More servers**: a network-stack server, a block-device driver server, and a
  name server, each following the capability-delegation model.
- **`captest` expansion** — *done*: it was a seven-line stub of raw `int $0x80`
  calls with no assertions; it is now a conformance exerciser that drives the
  syscall surface and the capability model from ring 3 and asserts on the
  results, gated by `make smoke-captest` (29 checks). The emphasis is on the
  **refusals**, since that is what a capability system has to get right: syscalls
  gated on capabilities the task does not hold (block device, audit log), IPC on
  an unheld slot, revoking without `CAP_RIGHT_REVOKE` (possession is not
  authority) and confirming the refused revoke had no side effects, `SYS_CAP_GRANT`
  outside the descendants rule, an unmaskable `SIG_KILL`, signalling/killing a
  task no `CAP_TCB` names, an undersized alternate signal stack, unknown syscall
  numbers, and bad user pointers. It also caught `SYS_GETPID` being declared in
  both headers and wrapped for libc but never implemented — every call had been
  silently taking the fail-closed deny path.

---

## Phase 5 — Testing, verification and assurance

Cross-cutting work that should grow alongside every other phase.

- **Scripted integration harness**: beyond the boot smoke-test, drive scripted
  sessions (login, capability denials, W^X violations, IPC round-trips) and assert
  on the responses. *Seeded*: `make smoke-session` (`tools/session_test.py`) boots
  the shipped kernel and drives the **real** ring-3 shell over serial as a black
  box — asserting that a wrong password is rejected, the right one is accepted, the
  kernel-attested identity is what `whoami` reports, and a capability-gated admin
  op (`useradd`) is allowed for root but denied for a standard user (no ambient
  authority). Gated in CI. Remaining: broaden the scenarios (W^X violation, IPC/FS
  round-trips) and grow the assertion vocabulary.
- **Fuzzing**: coverage-guided fuzzing (libFuzzer or AFL++) of the syscall
  interface and the Rust FFI boundary.
- **Model checking**: extend the TLA+ specifications (`docs/cap_algebra.tla`,
  `docs/paging_isolation.tla`) to cover IPC, the scheduler, and SMP interactions,
  and wire a checker into CI.
- **Formal verification**: apply Verus or Kani to the capability operations in
  `rust/src/capability.rs`.
- **User/kernel address separation**: **the kernel now runs at `KERNEL_VMA`
  (`0xFFFFFFFF80000000`)**, so no kernel address is a user address and nothing a
  task maps can shadow kernel state. This was the "full fix" this item asked for.
  It also removed the guards that existed only to work around the overlap — the
  `h_sbrk`/`h_brk` heap clamp and the image-ASLR clamp against
  `kernel_lowmem_critical_floor()` (the function itself is gone) — and lifted
  image-base ASLR to its structural ceiling of 480 pages ≈ 8.91 bits, bounded now
  only by the premap fitting one 2 MiB PD entry.

  **Done in full.** `create_user_pagedir` no longer identity-fills the low window:
  a user page directory now contains *only* the task's own mappings (image premap
  + low stack), so a user mapping cannot shadow kernel state by construction. That
  also un-broke demand paging in the low window — a fault there reaches the pager
  instead of finding an identity-supervisor page — and `rust_validate_page_fault`
  independently refuses any fault outside the calling task's own image/heap/stack.
  `make smoke-aslr` gates the entropy claim.

  **The image-window premap is now sized to the image** — *done*: it used to be a
  fixed 128 KiB (32 pages), and since `try_elf_load` writes each `PT_LOAD` segment
  with `copy_to_user` — which walks the page tables and needs a present USER page
  rather than faulting one in — that 128 KiB was the hard cap on a loadable image,
  regardless of the address space. `create_user_pagedir` now premaps the staged
  image's actual loaded span (`staged_image_span_pages()`: `max(p_vaddr+p_memsz) −
  page_floor(min_vaddr)`, set on the TCB by the spawn/exec path before the address
  space is built, clamped to `USER_IMAGE_MAX_PAGES` = 16 MiB so a crafted `p_memsz`
  cannot request the whole pool). A loadable image is now bounded by
  `MAX_PROGRAM_SIZE`, not by the premap. `make smoke-newlib` gates it: the newlib
  self-test image carries a ~160 KiB `.bss` array taking its loaded span to ~275
  KiB (~69 pages), touched end-to-end past the old 32-page boundary; with the premap
  forced back to 32 pages the image fails to load and the test fails.
  The low user stack is still a fixed, known mapping at `[0x7df000, 0x7ff000)`.

  **The staged-image buffer moved off `.bss`, lifting the file-size cap** —
  *done*: `loader_staging` used to be a static `.bss` array, which pinned
  `MAX_PROGRAM_SIZE` at ~1 MiB — `.bss` must end below `USER_PHYS_BASE` (16 MiB)
  and only ~1.9 MiB of headroom was left. It is now a fixed region reserved at the
  *base of the physical pool* — `[USER_PHYS_BASE, USER_PHYS_BASE +
  LOADER_STAGING_BYTES)`, which `init_user_page_allocator` holds back from the free
  list and points `loader_staging` at through the `PHYS_KVA` window. That decouples
  the cap from the `.bss` ceiling entirely: `MAX_PROGRAM_SIZE` is now **8 MiB** and
  costs no `.bss`, only a few pool frames of the ~495 MiB E820 pool (the
  `PHYS_POOL_MIN_PAGES` floor keeps 16 MiB *usable* after the reserve).
  `make smoke-newlib` gates it: the self-test image carries a ~1.06 MiB `const`
  array taking its on-disk size to ~1.5 MiB, well past the old 1 MiB cap; with the
  cap forced back to 1 MiB the image fails to even spawn (`arm` rejects it) and the
  test fails. Raising it further is now a one-line constant change. The low user
  stack is still a fixed, known mapping at `[0x7df000, 0x7ff000)`.

  **The physical allocator now parses the E820 map** — *done*: `_start` saves the
  multiboot2 magic and info pointer before reusing the register (`saved_mb_magic` /
  `saved_mb_info`), and `kernel_main` walks the memory-map tag to size the pool
  from real RAM instead of the old hardcoded `[16 MiB, 80 MiB)` window
  (`e820_detect_pool_pages` → `phys_set_pool_pages`, before `paging_init`). Under
  the harness's `-m 512M` the pool is ~495 MiB (up from 64 MiB); a boot that
  cannot parse a map falls back to the conservative default. The metadata array
  capacity (`USER_PHYS_PAGES` = 131072) bounds the pool at 512 MiB, kept below the
  1 GiB `PHYS_KVA` window and the `.bss` ceiling. `make smoke-e820` gates it.
  Remaining: the pool is still contiguous from `USER_PHYS_BASE` and bounded by the
  static metadata arrays; scaling to *all* RAM (multi-GiB, fragmented maps) needs
  the `PHYS_KVA` window widened past 1 GiB and the refcount/free-stack metadata
  bootstrapped from the pool itself rather than sized in `.bss`. (`MAX_PROGRAM_SIZE`
  is now 8 MiB, reserved from the base of this same pool rather than sized in
  `.bss` — see the staged-image-buffer item above.)

---

## Contributing

Phases 1 and 2 are complete. Phase 4 (userspace ecosystem) holds the most
self-contained items and is the recommended starting point for new contributors.
If you have kernel or systems experience and want something more involved, Phase
3 (SMP maturity) is a good target.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and
submit work.
