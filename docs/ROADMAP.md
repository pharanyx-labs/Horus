# Horus Roadmap

This document is the map of the whole program — each phase records what it has
delivered and what remains, so the roadmap doubles as an honest status report and
a guide to where Horus is **headed**. For the finer-grained "what exists today,"
see the summary below, the git history, and `docs/ARCHITECTURE.md`; for the
honest account of current limitations, `docs/LIMITATIONS.md`.

The phases are roughly ordered by dependency and priority, but they are largely
independent and can be picked up in any order. Phases 1 and 2 (process model,
filesystem) are complete; Phase 6 (security hardening) has completed most of its
program; Phases 3–5 are ongoing. Nothing here is a commitment — priorities shift
as contributors join and the design evolves. If you want to work on something,
open an issue or start a discussion first; coordination saves effort.

---

## Where things stand

The foundation is a working x86-64 capability microkernel that boots a ring-3
`init` supervising a ring-3 shell, and passes a broad suite of headless QEMU
self-tests in CI (31 `smoke-*` targets, all gated). Already in place:

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
- **Security core in safe Rust** — the security-critical logic lives in the
  `no_std` `horus_shell` crate: the capability algebra (mint/transfer/revoke +
  lineage/generation), the page-refcount trust boundary, the crypto primitives,
  and the FFI validation predicates. The **entire ELF loader parse** — header,
  program headers, and both i386 and x86-64 dynamic relocations — now runs
  memory-safe in Rust too, so no attacker-controlled image can walk a hand-rolled
  C parser off its buffer (the C loader keeps only the privileged page mapping
  and copies). Parts of that core carry machine-checked proofs (Kani) and
  coverage-guided fuzzers. See **Phase 6** for the hardening program.
- **Driver privilege separation** — the highest-risk, ring-3-reachable driver, the
  **VGA/serial console**, now runs as a ring-3 server (`console_server`) reached
  over IPC, holding only its own capabilities. It maps the framebuffer into its own
  address space, runs port I/O through a per-task TSS I/O-permission bitmap, and
  serves the shell's output and its line input (echo + masked password entry) — all
  gated by a new `CAP_IO_DEVICE` capability. A fault in it is contained as an
  ordinary ring-3 fault, so a console-driver bug can no longer reach kernel memory
  or the capability system. See **Phase 6 → C** for the program.
- **CI** — every `smoke-*` target is gated (the advisory jobs are the `security`
  SAST/SBOM scan, the `fuzz` FFI fuzzers, and the `kani` formal-verification run):
  `rust` (`cargo test` + `clippy -D warnings`), `kernel` (build + ISO),
  `altconfigs` (DEBUG_SHELL/MINIMAL_SECURE/SMP matrix), the headless QEMU boot
  `smoke`, the runtime self-tests (`smoke-elf`, `smoke-elf64`, `smoke-aslr`,
  `smoke-preempt`, `smoke-signal`, `smoke-tsd`, `smoke-cpu`, `smoke-stackguard`,
  `smoke-e820`, `smoke-wx`, `smoke-wx-smp`, `smoke-aspace`, `smoke-captest`,
  `smoke-proc`, `smoke-cow`, `smoke-notify`, `smoke-smp`, `smoke-fs`,
  `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-persist`, `smoke-fs-wal`,
  `smoke-fs-large`, `smoke-init-fs`, `smoke-newlib`), the driver-isolation
  self-tests (`smoke-mapphys`, `smoke-ioport`, `smoke-irq`, `smoke-console`,
  `smoke-console-isolation`), the shell-driven session tests (`smoke-session`,
  `smoke-modules`, `smoke-coreutils-shell`), and a `reproducible` build check. The whole filesystem suite (persistence,
  permissions, concurrency, journal crash-recovery, large files), the newlib
  libc port, async notifications, the CPU-protection / W^X / stack-guard sweeps,
  and loading programs from the filesystem via boot modules are all CI-enforced,
  not local-only.

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

**Large files are done:** double-indirect data blocks are implemented, so a single
file maps through the direct + single-indirect + double-indirect range (up to
12 + 64 + 64×64 = 4172 blocks). Proven by `make smoke-fs-large`, which also frees a
~130-block file in one journal transaction (the file's blocks fall within one
block-bitmap sector, and `do_block_write` coalesces repeat writes to it, so the
transaction stays well under the 16-sector journal limit — a large-file free never
overflows or aborts). This pass also fixed a latent single-indirect fanout bug:
the pointers-per-block count was 1024 instead of the correct 64, which would have
overrun a stack buffer for any file past block 76. The volume is **16 MiB** (32768
blocks, ~14 MiB usable) — see the multi-block-bitmap item below.

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
- **Multi-block allocation bitmaps — done.** A single 512-byte bitmap block caps a
  volume at 4096 blocks; the *data* allocator now spans as many bitmap blocks as
  the data region needs (`storage_alloc_block`/`storage_free_block` and the
  mount-time `fsck`), and `storage_format_sealed` solves for the bitmap span and
  lays the inode table + data region out past it. The inode allocator stays
  single-block (4096 inodes is ample). This is what let the volume grow to 16 MiB
  so every ported coreutils binary lives in `/bin` at once. The metadata
  rollback-HMAC was reworked in the same pass to be hierarchical (per-meta-block
  MACs under one top MAC) so the per-block-write cost no longer scales with the
  volume, and the RAM vdisk's backing store moved off `.bss` into the physical pool
  so a 16 MiB volume does not blow the `.bss` ceiling.

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
- **Port real programs** — *eleven coreutils ported*: `echo`, `true`, `false`,
  `basename`, `dirname`, `cat`, `head`, `seq`, `wc`, `printf` and `tail`
  (coreutils 9.5, each vendored byte-identical and never edited) build against the
  newlib port and run as ring-3 tasks. Upstream's autoconf + gnulib build does not
  survive the trip to a freestanding target (no `x86_64-elf` cross toolchain,
  `configure` runs target probes, and every utility pulls `src/system.h` → ~25
  headers → 478 gnulib `.c` files), so the port supplies what those would have:
  `config.h`, a trimmed `system.h`, and a shim (`port.c` + `gnulib.c`)
  implementing the gnulib modules the utilities need — the `xalloc` family (with
  overflow-checked size multiplies), `inttostr`, `xstrtol`, `argmatch`,
  `argv-iter`, `readtokens0`, `cl-strtod`, C-locale multibyte, `printf`'s `xprintf`
  and `unicodeio`, and `tail`'s follow shims (`isapipe`, `posix2_version`,
  `iopoll`, `xnanosleep`, `stat-time`). `tail -f` follow is best-effort — Horus has
  no inotify/`poll`/pipes/wall-clock sleep, so it degrades to a stat-polling loop;
  `-n`/`-c` are full upstream behaviour. The vendored sources are **GPLv3** and
  isolated in `userspace/ports/coreutils/` with their own `COPYING`; the port glue
  is MIT (see that directory's `README.md`), and no GPLv3 code is in the shipped
  kernel. Porting real software found five real bugs — `crt0` never passed `argv`
  and exited without running `atexit` (so stdio never flushed), `SYS_GET_ARGV`
  truncated its pointer to 32 bits, the ELF loader refused `R_X86_64_GLOB_DAT`
  (which every libc program reaching `exit()` emits), and `SYS_GETPID` was declared
  and wrapped but never implemented.

  **The utilities load from the filesystem, not the kernel image.** Each
  newlib-linked binary is ~400–610 KiB, and the old `incbin`/`CU_EMBED_<name>`
  embedding meant a build could only carry the subset its test drove before
  overrunning the kernel image's 16 MiB budget. They now ship as **GRUB
  multiboot2 modules**: the kernel records them from the boot tags, the
  `fs_server` copies each into `/bin` on the encrypted store at boot
  (`provision_boot_modules`, gated on `SYS_BOOT_MODULE_INFO`/`READ` = 77/78), and
  the shell runs them from there (`try_run_from_bin` resolves `/bin/<name>`, loads
  the image over the `fs_server`, spawns it). The kernel-image budget no longer
  limits them — a full build can ship every utility. Two gated shell-driven tests:
  `make smoke-modules` (ships the full set + man pages, checks the directory
  skeleton, and runs `printf`/`tail`) and `make smoke-coreutils-shell`
  (`head`/`wc`/`seq`), each asserting on output produced by upstream's own code. A
  `/bin/<name>` shadows the shell's lighter builtin. The `fs_server` also lays down
  a **directory skeleton** (`/bin /etc /home /lib /usr /usr/share/man`) at boot so a
  fresh `ls` shows a real layout, and each utility's **man page** ships as its own
  module to `/usr/share/man/<name>` (plus `hier(7)`); `man <name>` reads it from the
  store. Modules carry a destination path (`bin/<name>`, `usr/share/man/<name>`), so
  the same transport places binaries and their docs. `make run` ships all of this by
  default (`RUN_MODULES=1`) for an interactive session.
  **All eleven fit in `/bin` at once:** the store volume was grown from 2 MiB to
  **16 MiB** (multi-block data-allocation bitmap + off-`.bss` RAM vdisk +
  hierarchical metadata rollback-MAC — see the Phase 2 multi-block-bitmap item),
  and `make smoke-modules` ships the full set and asserts every one provisions with
  none dropped (provisioning is still ordered and skips anything that would not
  fit, but nothing does). Next: binutils — now shippable as a module (the image
  budget no longer blocks it) and holdable in the larger volume; what remains is
  bringing its sources up against newlib.
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

- **Scripted integration harness** — *seeded and growing*: `make smoke-session`
  (`tools/session_test.py`) boots the shipped kernel and drives the **real** ring-3
  shell over serial as a black box — a wrong password is rejected, the right one
  accepted, the kernel-attested identity is what `whoami` reports, and
  capability-gated admin ops are allowed for root but denied for a standard user
  (no ambient authority). Phase 6 (J8) added cross-user authority-bypass scenarios:
  a standard user is refused `userdel`, and the `fs_server` reference monitor lets
  it *read* a world-readable root-owned file but refuses a *write*, with the file
  proven unchanged afterwards. Gated in CI. Remaining: W^X-violation and IPC/FS
  round-trip scenarios, and a broader assertion vocabulary.
- **Fuzzing** — *done, and expanding*: a `cargo-fuzz` / libFuzzer harness
  (`rust/fuzz/`) exercises the pointer- and scalar-taking FFI predicates — the
  functions the C kernel calls to make security decisions — over arbitrary input:
  `rust_ct_eq`, `rust_validate_page_fault`, `rust_signal_handler_addr_ok`, and the
  four ELF-loader parsers (`elf_validate_header`, `elf_load_plan`,
  `elf_i386_reloc`, `elf_x86_64_reloc`). Runs as the advisory `fuzz` CI job; each
  target is also driven for tens of millions of executions locally. See Phase 6
  (J5, J10). Remaining: a syscall-boundary fuzzer under QEMU (syzkaller-style).
- **Model checking**: extend the TLA+ specifications (`docs/cap_algebra.tla`,
  `docs/paging_isolation.tla`) to cover IPC, the scheduler, and SMP interactions,
  and wire a checker into CI. *Not yet started.*
- **Formal verification** — *done for the crown-jewel paths, expandable*: Kani
  (bounded model checking) proves, over their entire input space, that
  `assign_fresh_serial` never returns a reserved or zero serial and that
  `rust_cap_mint` can only ever reduce rights (no privilege escalation), plus that
  the ELF header and load-plan validators never panic/read out of bounds and only
  accept in-range fields. Runs as the advisory `kani` CI job; see `rust/KANI.md`
  and Phase 6 (J9, J10). Remaining: extend proofs to the lineage/revocation paths
  (they touch a shared static that needs a heavier model) and consider Verus for
  the parts Kani's loop bounds make impractical.
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

## Phase 6 — Security hardening

A dedicated program to shrink the two things that most limit Horus as a security
kernel: the amount of **unverified, security-critical C**, and the **blast
radius** of any single bug. `docs/LIMITATIONS.md` states the core problem plainly
— the kernel is largely one flat trust domain, so a bug in an in-kernel driver has
the same blast radius as one in the capability system, and a full kernel compromise
also defeats the audit log and the user-DB tag. This phase attacks that on two
axes: move attacker-facing parsing and secret-comparison logic into the
memory-safe, machine-checkable Rust core (reducing bug *likelihood* where it
matters most), and introduce privilege separation inside the kernel (reducing bug
*consequence*). Both axes have now delivered: the whole ELF-loader parse runs in
Rust, and the console — the highest-risk, ring-3-reachable driver — runs as a
ring-3 server. Separating the remaining in-kernel drivers is the ongoing work.

Each job below was landed as one focused, behavior-verified change (smoke tests
and, where applicable, fuzzing and Kani proofs), on a commit-per-job cadence.

### A. Close concrete authority gaps — *done*

- **fs_server connect through the locked cap path** — `SYS_CONNECT_FS_SERVER`
  minted its endpoint capability with a raw, unsynchronised cspace store — the one
  cap-installing path that skipped the discipline every other one follows. It now
  goes through `cap_install_endpoint` (under `cap_lock`, with the no-ambient
  authority guard and `caps_in_use` accounting), closing an `SMP=1` race against a
  concurrent global revoke and an accounting gap. Open-connect is deliberately
  *kept*: the `fs_server` is a reference monitor that authorises every request by
  kernel-attested identity, so the endpoint alone grants nothing.
- **Constant-time comparison in Rust** — the last hand-rolled constant-time
  primitive in the auth path (`constant_time_compare` in `kusers.c`, used for
  password-hash and user-DB-tag checks) was replaced by a unit-tested, generic
  `rust_ct_eq` in the security core. No hand-rolled secret comparison remains.

### B. Stand up the safety net — *done*

- **FFI fuzzing** — a `cargo-fuzz` / libFuzzer harness (`rust/fuzz/`) over the
  pure FFI predicates the kernel trusts for security decisions, run as an advisory
  CI job. (See Phase 5 → Fuzzing.)
- **Capability-engine property tests** — five adversarial unit tests pinning
  invariants the existing suite missed: a mint into a kernel-reserved slot is
  refused, a mint from an empty / serial-0 source is refused, lookup/mint/revoke
  fail closed on out-of-range slots (no OOB access), revocation is transitive
  across a multi-level derivation chain, and `caps_in_use` saturates at zero
  instead of underflowing (which would permanently defeat `MAX_CAPS_PER_TASK`).
- **"Assert what the hardware actually does" audit** — an audit of every
  set-and-assumed protection bit confirmed each has a self-test asserting the
  *effective* register/MSR state (SMEP/SMAP/UMIP in CR4, `CR0.WP`, `EFER.NXE`,
  `CR4.TSD`), and closed the one gap it found: the `-fstack-protector-strong`
  canary is re-seeded from the CSPRNG at boot, but nothing checked that it *was* —
  a skipped re-seed would leave the published reproducible-build constant in place,
  protection on but bypassable. `make smoke-stackguard` now asserts the live guard
  is no longer the compile-time default (falsification-tested: neutering the
  re-seed makes the test go red).

### C. Chip at the architectural root — *the ELF loader and the console driver both done*

- **Authority-bypass integration scenarios** — the scripted session harness gained
  end-to-end negative tests proving the reference-monitor guarantee from ring 3.
  (See Phase 5 → Scripted integration harness.)
- **Formal verification of the capability engine** — Kani proofs over the whole
  input space. (See Phase 5 → Formal verification.)
- **The ELF loader moved to memory-safe Rust — *done*.** The loader parses fully
  attacker-controlled program images; every hand-rolled C parse in `try_elf_load`
  now runs in the Rust core, with the C loader keeping only the privileged page
  mapping and `copy_to_user`. Delivered in four behaviour-preserving steps, each
  with parity unit tests, a fuzz target, and (for the first two) a Kani proof:
  the ELF **header** validation, the **PT_LOAD program-header** load-plan builder,
  and the **i386** and **x86-64** dynamic relocation parsers (the last including
  the `R_X86_64_GLOB_DAT` dynamic-symbol lookup and undefined-weak → NULL
  resolution). Moving the program-header walk also fixed **two real
  out-of-bounds-read bugs** the C carried: a `u32` `p_offset + p_filesz` overflow
  that let a crafted header pass the bound and then read far out of the staging
  buffer, and a program-header-table read that could run past the buffer for a
  large `e_phoff`.
- **Reduce driver blast radius (privilege separation) — *done for the console*.**
  Everything above reduces the *likelihood* of a memory-safety bug in the highest
  risk C; this adds privilege separation, so a bug's *consequence* shrinks too. The
  microkernel-native move the filesystem already made has now been made for the
  highest-risk, ring-3-reachable driver: the **VGA/serial console runs as a ring-3
  server** (`console_server`) holding only its own capabilities, reached over IPC —
  so a console-driver bug is no longer automatically a capability-system compromise.
  It began with a design proposal (`docs/proposals/console-server.md`), then landed
  as a commit-per-job program:
    - three new device-delegation mechanisms, each `CAP_IO_DEVICE`-gated and
      falsification-tested — map an allowlisted device frame into a user address
      space (`SYS_MAP_PHYS`, `smoke-mapphys`), native ring-3 port I/O via a per-task
      TSS I/O-permission bitmap (`SYS_IOPORT_GRANT`, `smoke-ioport`), and an
      IRQ→notification bridge (`SYS_IRQ_REGISTER`, `smoke-irq`);
    - `console_server` itself, which owns the framebuffer and serial/VGA ports and
      serves the shell's **output** and its **input** — line editing, echo, and
      masked password entry — over IPC (`smoke-console`, and the real-shell
      `smoke-session` / `smoke-modules` with the in-kernel fallback removed to prove
      input and output genuinely traverse ring 3);
    - a blast-radius proof: a deliberate fault in the ring-3 console driver is
      contained as a ring-3 fault and the kernel stays alive (`smoke-console-isolation`).

  A minimal in-kernel serial writer is deliberately retained for early-boot and
  panic output, and an in-kernel reader remains as a fallback. Remaining as future
  work: move PS/2 keyboard input into the server too (the tests and headless
  deployment drive serial), and separate the other in-kernel drivers (block/ATA).

### Deliberate non-goal: don't wire up empty validators

Two Rust functions (`rust_validate_ipc`, `rust_validate_fs_operation`) exist but
are never called. They *look* like disconnected safety nets, but they are empty
scaffolding (`return rights != 0 ? 0 : -1`), and the IPC and FS paths they would
guard are already fully defended (central capability gate + snapshot/revalidate
TOCTOU protection + bounds checks for IPC; `CAP_BLOCK_DEV` + `uid == 0` for the FS
path). Wiring them in would add the *appearance* of a control without the
substance — security theater — and, if made unconditional, would break the
in-kernel shell caller. They are intentionally left unwired. The lesson: an unused
symbol is not the same as a missing defense.

---

## Contributing

Phases 1 and 2 are complete, and the Phase 6 hardening program has moved the whole
ELF-loader parse into memory-safe Rust and the console driver into a ring-3 server.
Phase 4 (userspace ecosystem) holds the most self-contained items and is the
recommended starting point for new contributors. If you have kernel or systems
experience and want something more involved, Phase 3 (SMP maturity) and the next
steps in Phase 6 driver isolation — moving PS/2 keyboard input into the console
server, then separating the block/ATA driver the same way — are the meatiest targets.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and
submit work.
