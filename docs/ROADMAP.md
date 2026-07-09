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

The foundation is a working x86-64 capability microkernel that boots to a ring-3
shell and passes a headless boot smoke-test plus six runtime self-tests in CI.
Already in place:

- **Kernel core** — long-mode microkernel; capability-based access control with
  table-driven, fail-closed syscall dispatch; preemptive scheduling; ring-3
  fault signals delivered to a registered handler; per-spawn ASLR; W^X user
  memory; SMEP/SMAP; a tamper-evident HMAC-chained audit log.
- **Multiprocessing** — the application processors are brought up and run
  scheduled tasks across cores with acknowledged TLB-shootdown IPIs, behind an
  `SMP=1` build gate (`make smoke-smp`).
- **Cryptography** — from-scratch, test-vector-validated Argon2id password
  hashing, a ChaCha20 CSPRNG seeded from RDRAND, and a ChaCha20 + HMAC-SHA256
  AEAD for encryption-at-rest, all in safe `no_std` Rust.
- **Filesystem** — a ring-3 `fs_server` over a persistent, encrypted object store
  (LUKS-style password-wrapped volume key), reached over blocking IPC; real
  `ls` / `cat` / `mkdir` / `rm` / `touch` / redirection from the shell.
- **Userspace runtime** — a demand-paged heap via `sbrk`/`brk`, a userspace
  `malloc`, and a newlib libc port over a per-process POSIX fd layer.
- **Process control** — a ring-3 `init` (PID 1) launches at boot and spawns,
  capability-endows and supervises the shell. A task can spawn a child from ring 3
  (`SYS_SPAWN`, which runs in the kernel address space and hands the caller a
  `CAP_TCB` to the child), replace its own image (`SYS_EXEC_NAMED`), delegate a
  capability down to a child it supervises (`SYS_CAP_GRANT`), terminate itself
  (`SYS_EXIT`), or terminate a task it holds a `CAP_TCB` for (`SYS_KILL`), with
  waiter wake-up and SMP-safe teardown (`make smoke-proc`).
- **CI** — eleven gated jobs: headless QEMU smoke-boot, seven runtime self-tests
  (ELF loader + W^X, preemption, fault signals, filesystem, newlib, SMP,
  process-control), a reproducible-build check, `clippy -D warnings`, and a
  SAST/SBOM scan.

---

## Phase 1 — Process lifecycle and control

Task termination has landed (`SYS_EXIT` / capability-gated `SYS_KILL`, see the
foundation summary); the rest of this phase makes processes fully first-class.
Good starting points for new contributors.

- **Asynchronous signals**: task-to-task signalling (`SYS_SIGNAL`, gated on a
  `CAP_TCB` to the target) has landed — a queued signal is redirected into the
  target's registered handler when it next returns to ring 3, reusing the
  fault-signal delivery path; an unhandled signal (or the uncatchable
  `SIG_KILL`) takes the default terminate action. Still to do: signal masking,
  alternate signal stacks, queued delivery to a *blocked* target (today a
  pending signal only lands once the target is next scheduled to run), and a
  richer signal set.
- **`exec` / `fork`**: `SYS_EXEC_NAMED` replaces the caller's image in place with
  a named embedded binary (same task id, capabilities preserved), so a shell can
  launch-and-replace programs. Still to do: `exec` with caller-supplied arguments
  and an `exec`-from-file-descriptor path, and evaluate `fork` (or a
  spawn-with-inheritance primitive).
- **Userspace init / servers**: a ring-3 init (PID 1) now launches at boot and
  spawns, capability-endows (`SYS_CAP_GRANT`) and supervises the shell — the
  kernel no longer spawns the shell directly. Remaining: have init also launch
  the servers (`fs_server` is still started on demand from the shell), which
  needs each server's boot capability provisioning expressed as delegations from
  init rather than the current direct root-cnode installs.

---

## Phase 2 — A production filesystem

The filesystem works end-to-end but is opt-in, single-client, and permission-less.

- **Persistent by default**: make the encrypted ATA store (`STORAGE_ATA=1`) the
  default backend instead of the in-RAM virtual disk.
- **Concurrency**: multi-client `fs_server` IPC — it currently serves one request
  at a time.
- **Ownership and permissions**: per-file ownership/permission bits tied to the
  capability model, and per-file ACLs; reconcile the legacy in-memory capfs
  (`SYS_FS_*`) with the server.
- **Crash resilience**: a write-ahead intent log for atomic multi-block updates, a
  directory-tree `fsck` pass to reclaim written-but-never-linked inodes (the
  current pass only catches orphaned bitmap slots), multi-block allocation
  bitmaps, and double-indirect data blocks for larger files.

---

## Phase 3 — SMP maturity

The SMP foundation is in place behind a build gate; this phase makes it
production-grade and default.

- **Default-on**: retire the `SMP=1` gate once the multi-core scheduler is
  hardened, so the shipped kernel uses every core.
- **Real per-CPU run queues**: replace the shared runnable pool with per-CPU
  queues plus explicit load-balancing/migration, and add scheduling priorities
  and fairness.
- **Unified switch path**: route the cooperative `yield()`/IPC switch through the
  same full-context trap-frame mechanism the timer preemption uses.
- **Concurrent-IPC correctness**: close the narrow block→save→wake window under
  simultaneous cross-CPU IPC by publishing a blocked task's saved frame before it
  becomes visible to a notifier on another core.

---

## Phase 4 — Userspace ecosystem

With a libc and a heap in place, grow what runs on top.

- **Complete the libc surface**: implement the `unlink`/`link` stubs, wire signal
  delivery through `kill()` (depends on Phase 1), and fill remaining POSIX gaps.
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
  on the responses.
- **Fuzzing**: coverage-guided fuzzing (libFuzzer or AFL++) of the syscall
  interface.
- **Model checking**: extend the TLA+ specifications (`docs/cap_algebra.tla`,
  `docs/paging_isolation.tla`) to cover IPC, the scheduler, and SMP interactions.
- **Formal verification**: apply Verus or Kani to the capability operations in
  `rust/src/capability.rs`.
- **User/kernel address separation**: the kernel is linked low (1 MiB) and its
  BSS extends past `USER_AREA_BASE` (4 MiB), so a task's low-memory mappings
  (image, heap) share virtual addresses with kernel data like `tasks[]`. Two
  interim guards are in place: image ASLR is pinned so the premap window can't
  reach the kernel globals (`choose_image_placement`), and the user heap is
  bounded below `kernel_lowmem_critical_floor()` so it can't grow up into the
  always-live kernel state (`h_sbrk`/`h_brk`). Residual gaps a determined program
  could still hit — the low user stack overlaps `kernel_stacks`, and a direct
  (non-`sbrk`) fault into the critical window isn't yet refused by the demand
  pager. The full fix is to move the user address space above the kernel image
  (or the kernel to the higher half) so no user mapping can ever shadow kernel
  state, which would also restore image-base
  ASLR.

---

## Contributing

Phase 1 items are the most self-contained and the recommended starting point for
new contributors. If you have kernel or systems experience and want something
more involved, Phase 2 or 3 are good targets.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and
submit work.
