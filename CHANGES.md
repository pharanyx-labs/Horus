# Changelog

All notable changes to Horus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a public ABI to break.

**The reasoning behind these lines is in [`docs/history/DEVLOG-2026.md`](docs/history/DEVLOG-2026.md)** —
117 entries recording what was tried, what failed, and how each measurement was taken. In a
security project that record is evidence, not commentary, so it is kept in full rather than
compressed away. Entries here cite finding IDs; their **current** status is in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), never in this file.

---

## [Unreleased]

### Added

- **`libhorus`, the shared runtime for freestanding userspace** (`include/libhorus.h`,
  `userspace/libhorus.a`). Replaces 22 hand-copied definitions across 7 files. Linked as an
  archive so a program that uses none of it pays nothing — `captest`'s `.text` is
  byte-identical to before it existed.
- **`ipc_call_retry`** makes the IPC retry contract a library guarantee: retry only while
  `ipc_transient()`, bound even that, and return a permanent refusal unretried. The
  pre-libhorus loop spun on `SYS_ERR_PERM` forever, turning a capability denial into an
  indistinguishable hang (**[G-8]** signature C). Two programs had independently re-derived
  the correct loop; it is now written once.
- **`smoke-libhorus`** (required job `libhorus`), with control arms `LIBHORUS_RETRY_ANY=1`
  and `LIBHORUS_STRNCPY_UNTERMINATED=1`. The first executable witness that a permanent IPC
  refusal is not retried — the property had been asserted by comments and tested by nothing.
- **`$(call USERPROG,name)`**, so adding a freestanding program is one line. Capability
  delegation stays hand-written in `init.c` on purpose: a macro that guessed would be a macro
  that granted.

### Changed

- **[G-9] is reproducible now** — 2–4% of boots on `PROC_SELFTEST` at `-smp 4`, captured
  per-boot (2/60, 3/80, 1/80). It previously took "eighteen boots across three builds, by hand".
- **[G-9]'s recorded signature was wrong.** Every document described a claim held by a CPU that
  had *gone idle*. All five 2026-08-21 captures show the holder **running another live task**,
  owing no deferred release and not impersonating — so the leak is **not** in the
  deferred-release machinery, which is where the two previous fixes went.
- Four leads killed with instruments rather than arguments (`CLAIM_TRACE=1`, zero hits in 220
  boots): deferred-slot overwrite, `sched_enter_user` owing a release, a declined release in
  `sched_release_deferred`, and the SYSCALL fast path (unreachable — `EFER.SCE` is never set).
- **[G-9]'s scope is wider than recorded.** The scheduler claim leak was documented against
  `PROC_SELFTEST` at `-smp 4` (~40% of boots, always task 3). On 2026-08-21 the same shape
  appeared in the **default boot** — `init` spawning the shell, task 4, on an idled CPU — at
  1 boot in 120. A control on the preceding commit was 0 in 270; the difference is not
  significant (Fisher p ≈ 0.31) and is recorded rather than concluded.
- **`smoke-sched-invariants-stress`'s green runs never established what they were read as.**
  Thirty boots has ~26% power against a 1%-per-boot event. `TESTS.md` now states the power
  beside the sample size. The gate stays **required**: unlike `smoke-kstack-park`, which is
  advisory because it reddens for a defect it does not test, this gate tests the claim
  invariant and what it caught was a claim leak. A red here is a [G-9] reproduction to
  capture, not a flake to re-run.

### Fixed

- **[G-9] root cause found: a switch was committed before its resume value was validated.**
  `task_exit_switch()` returns `0` both for "nothing runnable, caller parks" and — via
  `ksp_refuse()` — for "I already claimed `next`, but its resume value is bogus". Its three
  callers cannot tell those apart, so they park the CPU and the claimed task is orphaned
  forever. The resume guard added *for* [G-9] is what created this. All four switch paths now
  validate before committing. Deterministically gated by `smoke-switch-commit` /
  `smoke-switch-commit-control` (`SWITCH_COMMIT_EARLY=1` + `KSP_GUARD_INJECT=1`).
  **[G-9] remains open**: the natural rate moved 2–4% → 2 in 130 boots, which is not a
  statistically distinguishable improvement, and a second path is still leaking.

- **`sched_enter_user()` reached ring 3 without paying its deferred release.** It carried a
  second hand-written copy of the ISR epilogue that omitted `call sched_release_deferred`, so a
  CPU arriving there while owing a release orphaned that task's claim — and its
  `g_kstack_inflight` bit, which makes the **[G-8]** detector report a collision that is not
  happening. Latent in current workloads; fixed because it is wrong, not because it explains
  the observed leak.

### Added

- **The invariant that makes the class non-recurrable:** *a CPU in ring 3 owes no deferred
  release*, asserted in `preempt_on_tick` under `SCHED_INVARIANTS`. The periodic claim audit
  **cannot** catch an unpaid debt — it exempts exactly that state as a legitimate mid-handover —
  so an orphaned release hides inside the exemption that keeps the auditor honest. Gated by
  `make smoke-claim-release` (required job `claim-release`), falsified by `CLAIM_RELEASE_SKIP=1`.
- `CLAIM_TRACE=1`, an instrument recording claim provenance and reporting two orphaning events
  as they happen.

### Fixed

- `fsclient.c`'s `put_int` negated a signed `int` (`(unsigned)(-v)`), which is undefined for
  `INT_MIN` and reachable, since the value printed is an IPC rc a server chooses. libhorus's
  `kput_int` accumulates in unsigned.

- `tools/check_defect_flags.py` and the required `defect-flags-documented` job. The
  defect-flag table in `docs/BUILDING.md` claimed to be the complete list and was not:
  `RESUME_RSP_INJECT`, `RESUME_RSP_INJECT_PRECLAIM` and `WAL_CRASHTEST` had no row, and one
  appeared nowhere in the file. The claim is now derived from the Makefile rather than asserted.

### Changed

- The changelog is versioned. The 117 narrative entries that were this file moved to
  [`docs/history/DEVLOG-2026.md`](docs/history/DEVLOG-2026.md), which is exempt from the
  documentation ratchet because a historical record reports a past state rather than
  asserting a present one.
- The G-8/G-9/G-10/G-11 investigations moved out of `TESTS.md` into
  [`docs/investigations/`](docs/investigations/) and are cited from the three documents that
  used to retell them. `TESTS.md` 2327 → ~1180 lines.
- The two audit documents merged into `docs/AUDIT.md`, the July 2026 one as Appendix A.
  `docs/proposals/console-server.md` moved to `docs/design/`, since it records what was built.
- The README's assurance banner states the standing position instead of narrating every
  finding's history, which the linked documents already do authoritatively.

### Removed

- `src/kernel/shell.c` and `userspace/include/captest.c` — 1396 lines of byte-identical,
  never-built source superseded by `src/kernel/kshell.c` and `userspace/shell.c`.
- Three prototypes in `src/include/kernel.h` with no definition and no caller anywhere:
  `console_putc`, `console_puts`, `untyped_selftest`.
- `tests/`. Its one file defined its own `struct capability` and its own `cap_lookup` and
  tested those; the real `capability_t` has a `uint64_t object` and a `generation` field —
  the use-after-revoke backstop — and the copy had neither, so no kernel regression could
  have failed it. `tests/README.md` also claimed `make test` ran it, which nothing did. The
  binding coverage it pointed to is now listed in `TESTS.md`.
- `.build1.sha` / `.build2.sha`, tracked since the initial commit and holding the same stale
  `kernel.elf` hash.

### Fixed

- Four stale citations, each pointing at unrelated code: `docs/BUILDING.md` sent readers
  ~1,980 lines from `smoke-irq-policy`, `docs/ARCHITECTURE.md` cited the wrong *file* for
  `SYS_IPC_RECV_BLOCK`, and `kspawn.c:188` had drifted ~156 lines in three documents. Where a
  line number will drift again, the symbol is named instead.

---

## [0.1.0] — 2026-08-21

The first tagged state of Horus: a capability-based x86-64 microkernel that boots on hardware
and under QEMU, drops to a ring-3 shell, and runs ordinary C programs — including GNU
coreutils and TCC — with its filesystem and console drivers in userspace.

**This release is research-grade.** It has not been independently audited, and
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) is the honest accounting of what it does not do.
Version `0.1.0` marks a coherent starting point for versioned change, not a readiness claim.

### Added

**Capabilities and the object model**

- A capability is `{type, rights, object, badge, serial, generation}`, held in a per-task
  cspace and named only by slot index, so ring 3 can never see or forge the struct.
- Mint derives a child with `rights & new_rights`: delegation can only ever *reduce* authority.
  Grant pushes a capability into a supervised child, never upward.
- Revocation is system-wide and subtree-scoped, backed by serial-keyed generation counters as
  an independent second mechanism. Both must hold. Machine-checked by Kani proofs.
- Kernel objects — cspaces, endpoints, notifications — are carved from untyped memory via
  `CAP_UNTYPED` and `SYS_RETYPE`, replacing fixed `.bss` tables (**[I-7]**). `tasks[]` remains.
- IPC is capability-addressed: every IPC syscall names a cspace slot, and the kernel derives
  the endpoint from the capability there (**[C-1]**, **[C-2]**).
- One-shot reply capabilities and per-task private reply endpoints, making reply forgery
  unrepresentable rather than merely refused.
- Endpoints are a bounded FIFO with a blocking receive that sleeps on an empty queue
  (**[I-5]**), plus async notifications and bounded byte-stream pipes.

**Memory and scheduling**

- Per-task 4-level page tables, demand paging, copy-on-write, NX stacks, kernel W^X swept
  rather than asserted, unmapped stack guard pages, 30-bit userspace ASLR.
- Preemptive scheduling at 100 Hz (PIT, or per-CPU LAPIC under SMP) with full trap-frame
  context switches and a microarchitectural flush between distrusting tasks.
- SMP on by default: ACPI MADT enumeration, INIT-SIPI-SIPI bringup, a shared runnable pool,
  acknowledged TLB-shootdown IPIs, and SMT siblings parked in software to close the
  co-residency side channel.

**Storage and boot integrity**

- `fs_server` in ring 3 over an AEAD-encrypted kernel object store, enforcing POSIX rwx
  against a **kernel-attested** uid (`SYS_IPC_SENDER`) that a client cannot forge.
- A write-ahead journal with mount-time fsck, and double-indirect block mapping for large files.
- Per-`(inode, block)` AEAD subkeys under a hierarchical rollback MAC; key material never
  leaves the kernel.
- SHA-256 boot-module manifest embedded in the kernel image; TPM 2.0 measurement into PCR 8
  and 9; the vdisk KEK sealed under `PolicyPCR`.

**Userspace**

- Ring-3 `init` (PID 1) that delegates every capability its children hold and supervises the
  shell with a blocking `SYS_WAIT`.
- `console_server` in ring 3 owning the UART and VGA framebuffer, with raw terminal mode.
- A shell with pipelines and redirection, a newlib libc port, GNU coreutils, and TCC.

**Assurance**

- `kernel.elf` is byte-for-byte reproducible, verified by building twice and diffing in CI.
  `boot.iso` is not; see [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) §5.3a for why.
- Every boot prints `DEFECT FLAGS: <list>`, so a serial transcript records the configuration
  that produced it, and a flag change forces a rebuild.
- Fifteen defect-reproducing control arms, each rebuilding a specific closed defect on demand
  so its gate can be falsified rather than trusted.
- Which CI jobs may block a merge is a checked-in decision in `.github/ci-gating.yml`,
  enforced by the `ci-gating` job (**[C-6]**, mechanism half).
- Documented counts are derived and gated by `tools/check_doc_claims.py` (**S22**), control-arm
  structure by `tools/check_gate_pairs.py`, and the defect-flag table by
  `tools/check_defect_flags.py`.

### Fixed

Security-relevant defects closed before this release. Each has a falsified witness; the
control arm is named in [`docs/BUILDING.md`](docs/BUILDING.md).

- **[C-1]**, **[C-2]** — IPC endpoints were not capability-addressed, so any ring-3 task could
  intercept or forge messages to any userspace server.
- **[C-3]**, **[C-3.1]** — one global IRQ nesting counter shared by every CPU, incremented
  non-atomically, with an unconditional `sti` on release. The lock is per-CPU and restores the
  caller's own `RFLAGS.IF`.
- **[C-4]** — user copies truncated instead of refusing.
- **[H-1]** — the user database still granted authority for ambient `uid == 0`, for nineteen
  days after three documents said that authority had been retired. It now tests `CAP_USER`.
- **[H-2]** — a ring-3 write to fd 1 was appended to the kernel message ring with no authority
  tested, though the *read* side had required `CAP_KERNEL_LOG` since **[I-1]**.
- **[I-1]** — ambient `uid == 0` authority across the root-gated syscalls.
- **[I-2]** — 32-bit truncation in the heap syscalls and the pager's region gate.
- **[I-3]** — a revocation closure an unprivileged task could force to over-approximate,
  destroying unrelated peers' authority. Now exact.
- **[I-5]** — a single-slot endpoint, replaced by a bounded queue.
- **[I-6]** — `this_cpu()` read LAPIC MMIO on every call.
- **[I-10]** — the write-ahead journal had no `FLUSH CACHE` barriers and was not durable on
  real hardware.
- **[I-11]** — the journal recovery test ended on a signal rather than a process exit.
- **[G-8]** — a switch path handed a task to another CPU while the CPU making the switch was
  still executing on that task's kernel stack. Measured over 1600 alternating boots: the
  pre-fix release site fails 31/800, the shipped one 0/800. A second path — every CPU whose
  last task died parking on `tasks[0]`'s stack — was closed with it.
- **[G-10]** — a page-table use-after-free giving a cross-address-space read/write primitive
  reachable from ring 3, plus the unserialised spawn staging around it.
- **[G-11]** — the armed program image was ambient state, so `SYS_SUDO` would elevate whatever
  was armed to uid 0 whether or not the authenticating task had staged it.

### Known open

- **[C-5]** — no independent review of security-critical changes. Single maintainer.
- **[C-6]** — reconciling the branch ruleset to `.github/ci-gating.yml` is still a manual step
  that lags a merge.
- **[G-9]** — a scheduler claim leaks and kernel stacks collide on the spawn/reap path under
  SMP. Two components fixed, taking it from ~45% of boots to roughly 1–2%; the rest is open.

The full list, with what each means for a reader, is in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

---

[Unreleased]: https://github.com/pharanyx-labs/Horus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pharanyx-labs/Horus/releases/tag/v0.1.0
