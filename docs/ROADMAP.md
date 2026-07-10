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
`init` supervising a ring-3 shell, and passes a headless boot smoke-test plus
five runtime self-tests in CI. Already in place:

- **Kernel core** — long-mode microkernel; capability-based access control with
  table-driven, fail-closed syscall dispatch; preemptive scheduling; ring-3
  fault signals delivered to a registered handler; per-spawn ASLR; W^X user
  memory; SMEP/SMAP; a tamper-evident HMAC-chained audit log.
- **Process control** — a ring-3 `init` (PID 1) launches at boot and spawns,
  capability-endows, and *blocking*-supervises the shell (`SYS_WAIT`). A task
  can spawn a child from ring 3 (`SYS_SPAWN`, which hands the caller a `CAP_TCB`
  to the child), replace its own image (`SYS_EXEC_NAMED`), delegate a capability
  to a child it supervises (`SYS_CAP_GRANT`), signal a task it holds a `CAP_TCB`
  for (`SYS_SIGNAL`), terminate itself (`SYS_EXIT`) or such a task (`SYS_KILL`),
  and block until one exits (`SYS_WAIT`), with waiter wake-up on both a clean
  exit and a fault (`make smoke-proc`).
- **Multiprocessing** — the application processors are brought up and run
  scheduled tasks across cores with acknowledged TLB-shootdown IPIs, behind an
  `SMP=1` build gate (`make smoke-smp`).
- **Cryptography** — from-scratch, test-vector-validated Argon2id password
  hashing, a ChaCha20 CSPRNG seeded from RDRAND, and a ChaCha20 + HMAC-SHA256
  AEAD for encryption-at-rest, all in safe `no_std` Rust.
- **Filesystem** — a ring-3 `fs_server` over an encrypted object store, reached
  over IPC; real `ls` / `cat` / `mkdir` / `rm` / `touch` / redirection from the
  shell (`make smoke-fs`).
- **Userspace runtime** — a demand-paged heap via `sbrk`/`brk`, a userspace
  `malloc`, and a newlib libc port over a per-process POSIX fd layer
  (`make smoke-newlib`).
- **CI** — eleven gated jobs: `rust` (`cargo test` + `clippy -D warnings`),
  `kernel` (build + ISO), `altconfigs` (DEBUG_SHELL/MINIMAL_SECURE matrix), the
  headless QEMU boot `smoke`, five runtime self-tests (`smoke-elf`,
  `smoke-preempt`, `smoke-signal`, `smoke-smp`, `smoke-proc`), a `reproducible`
  build check, and a `security` SAST/SBOM scan. (`smoke-fs` and `smoke-newlib`
  are additional local targets, not yet gated in CI.)

---

## Phase 1 — Process lifecycle and control

The process model is now largely complete. **Signals** are done bar one niche
feature: `SYS_SIGNAL` delivers async task-to-task signals into a registered
handler, the pending set is a full 1..31 bitmask, `SYS_SIGMASK` blocks/unblocks
signals (delivering the lowest unmasked one), and a signal to a task parked in
`SYS_WAIT` interrupts the wait (`SYS_ERR_INTR`) and delivers promptly
(`make smoke-proc`). **`argv` is done:** `SYS_SPAWN` and `SYS_EXEC_NAMED` marshal
a full argument vector onto the child's stack, read back via `SYS_GET_ARGV`.
**`fork` has been evaluated and deliberately not adopted:**
the ring-3 `SYS_SPAWN` + `SYS_CAP_GRANT` model already gives create-a-task and
hand-it-capabilities without fork's whole-address-space aliasing and its
least-privilege problem (a forked child would inherit *every* parent capability).

What remains:

- **`exec` from a file descriptor**: `SYS_SPAWN` and `SYS_EXEC_NAMED` both take a
  full `argv` now (marshalled onto the child's stack; read via `SYS_GET_ARGV`),
  and load a *named embedded* binary. The remaining piece is loading the program
  image from a file/descriptor (an `execve`-from-fd path) rather than the fixed
  embedded set, which depends on the filesystem read path.
- **Alternate signal stacks**: signals run on the interrupted user stack; a
  `sigaltstack`-style separate handler stack (with an `SS_ONSTACK` guard) is a
  low-priority robustness feature.
- **Init launches the servers**: `init` blocking-supervises the shell; have it
  also launch `fs_server`. This needs `init` endowed at boot with `CAP_BLOCK_DEV`
  + `CAP_USER` + an endpoint cap so it can express the server's provisioning as
  `SYS_CAP_GRANT` delegations (replacing the current direct root-cnode installs),
  plus a boot-time FS integration test to prove the delegated server still
  serves.

---

## Phase 2 — A production filesystem

The filesystem works end-to-end but is opt-in, single-client, and permission-less.

- **Persistent by default**: make the encrypted ATA store (`STORAGE_ATA=1`) the
  default backend instead of the in-RAM virtual disk, and persist the per-block
  crypto metadata (nonces/tags) so files survive a reboot.
- **Concurrency**: multi-client `fs_server` IPC — it currently serves one request
  at a time.
- **Ownership and permissions**: per-file ownership/permission bits tied to the
  capability model, and per-file ACLs; reconcile the legacy in-memory capfs
  (`SYS_FS_*`) with the server.
- **Crash resilience**: a write-ahead intent log for atomic multi-block updates, a
  directory-tree `fsck` pass to reclaim written-but-never-linked inodes,
  multi-block allocation bitmaps, and double-indirect data blocks for larger
  files.

---

## Phase 3 — SMP maturity

The SMP foundation is in place behind a build gate; this phase makes it
production-grade and default.

- **Default-on**: retire the `SMP=1` gate once the multi-core scheduler is
  hardened, so the shipped kernel uses every core.
- **Real per-CPU run queues**: replace the shared runnable pool with per-CPU
  queues plus explicit load-balancing/migration, and add scheduling priorities
  and fairness.
- **Finish retiring the cooperative switch**: console input, `SYS_WAIT`, `init`,
  and IPC now use the full-context trap-frame mechanism; migrate the last
  cooperative `yield()`/`schedule()` corners (e.g. the boot launch of the first
  task) so the legacy path can be deleted.
- **Concurrent-IPC correctness**: close the narrow block→save→wake window under
  simultaneous cross-CPU IPC by publishing a blocked task's saved frame before it
  becomes visible to a notifier on another core.

---

## Phase 4 — Userspace ecosystem

With a libc and a heap in place, grow what runs on top.

- **Complete the libc surface**: implement the `unlink`/`link` stubs, wire signal
  delivery through `kill()` onto `SYS_SIGNAL`, and fill remaining POSIX gaps.
- **Port real programs**: bring up a subset of GNU coreutils/binutils against
  newlib now that `malloc`/`sbrk`/`brk` exist.
- **More servers**: a network-stack server, a block-device driver server, and a
  name server, each following the capability-delegation model.
- **`captest` expansion**: grow it into a comprehensive program exercising every
  syscall and every capability operation — usable as both a regression test and a
  demonstration.

---

## Phase 5 — Testing, verification and assurance

Cross-cutting work that should grow alongside every other phase.

- **Scripted integration harness**: beyond the boot smoke-test, drive scripted
  sessions (login, capability denials, W^X violations, IPC round-trips) and assert
  on the responses. Gate `smoke-fs` and `smoke-newlib` in CI.
- **Fuzzing**: coverage-guided fuzzing (libFuzzer or AFL++) of the syscall
  interface and the Rust FFI boundary.
- **Model checking**: extend the TLA+ specifications (`docs/cap_algebra.tla`,
  `docs/paging_isolation.tla`) to cover IPC, the scheduler, and SMP interactions,
  and wire a checker into CI.
- **Formal verification**: apply Verus or Kani to the capability operations in
  `rust/src/capability.rs`.
- **User/kernel address separation**: the kernel is linked low (1 MiB) and its
  BSS extends past `USER_AREA_BASE` (4 MiB), so a task's low-memory mappings
  (image, heap) share virtual addresses with kernel data like `tasks[]`. Two
  interim guards are in place: image ASLR is pinned so the premap window can't
  reach the kernel globals (`choose_image_placement`), and the user heap is
  bounded below `kernel_lowmem_critical_floor()` (`h_sbrk`/`h_brk`). Residual
  gaps a determined program could still hit — the low user stack overlaps
  `kernel_stacks`, and a direct (non-`sbrk`) fault into the critical window isn't
  yet refused by the demand pager. The full fix is to move the user address space
  above the kernel image (or the kernel to the higher half) so no user mapping
  can ever shadow kernel state, which would also widen image-base ASLR entropy.

---

## Contributing

Phase 1 items are the most self-contained and the recommended starting point for
new contributors. If you have kernel or systems experience and want something
more involved, Phase 2 or 3 are good targets.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and
submit work.
