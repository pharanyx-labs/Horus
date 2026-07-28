# Testing Horus

Horus's security argument rests on its tests, so they are treated as first-class engineering
artifacts rather than an afterthought. This document catalogues them and states what each one
actually proves.

**The design principle: test that the control *fires*, not merely that the happy path
works.** Several tests deliberately corrupt inputs or attempt forbidden operations and assert
refusal. Those are the valuable ones.

---

## The three layers

| Layer | Runs | Command |
|---|---|---|
| **Rust unit tests + Kani proofs** | On the host, in seconds | `cargo test --manifest-path rust/Cargo.toml` |
| **QEMU integration self-tests** | Boot a purpose-built kernel, assert a serial marker | `make smoke-<name>` |
| **Scripted shell sessions** | Type into the real ring-3 shell over serial | `make smoke-session` |

```bash
make smoke     # the basic gate: boots to the ring-3 shell banner and login prompt
make test      # the full local sweep
```

---

## How a self-test works

Most follow one shape. A `*_SELFTEST` compile flag guards a routine in
`src/kernel/selftest.c` — or a ring-3 program in `userspace/` — that runs the check and
prints `NAME: PASS` on the serial console. A `make smoke-name` target builds that
configuration, boots it headless under QEMU with a timeout, and greps for the marker.

The test-only code and any test-only syscalls are **absent from the default kernel**, so they
fail closed in a shipping build. `SYS_PREEMPT_TRACE` is the clearest example: defined and
wrapped, but with no dispatch-table entry outside `PREEMPT_SELFTEST`, so it returns
`SYS_ERR_NOSYS`.

Timeouts default to 40 s and are overridable: `make smoke-tcc SMOKE_TIMEOUT=320`. TCG
emulation is slow, and CI runners are slower; a timeout is usually not a real failure.

---

## Capability and authorisation

| Target | Proves |
|---|---|
| `smoke-captest` | **84 checks**: an unheld capability is refused; a revoked capability cannot be used; a stale snapshot fails revalidation; minting into a kernel-reserved slot is refused; bad input is rejected. Twelve cover capability-addressed IPC (finding C-1) and twenty-two cover untyped memory and retyping (finding I-7) — see below. The central conformance suite. |
| `cargo test` (`rust/src/capability.rs`) | Mint masks rights and cannot widen them; transfer shares lineage; system-wide revoke reaches another task's cspace; an unrelated capability survives; primordial roots cannot be revoked; the generation counter skips the pristine sentinel on wrap; serial allocation never yields 0 or a reserved value. |
| Kani proofs | Revocation nulls **exactly** the target's derivation subtree — no descendant survives, no non-descendant is touched. |

**The C-1 refusal checks, and why they are asserted precisely.** Twelve checks in
`smoke-captest` cover capability-addressed IPC: a `CAP_FRAME` (the pre-fix authorisation
gate) authorises no IPC operation; a WRITE-only client capability is refused `recv`,
`reply_to`, and `sender` — the interception and reply-forgery halves of the finding; endpoint
and notification capabilities do not authorise each other's operations; empty slots are
refused.

Each asserts the **exact** code `SYS_ERR_PERM`, never merely "negative". `sys_ipc_recv`
returns `-2` for an empty mailbox, so a `< 0` assertion cannot distinguish "the kernel refused
me" from "I was allowed to read, and nothing was there" — and under the pre-fix kernel these
probes hit empty endpoints and returned `-2`. The first draft of the suite used `< 0` and
**passed with the vulnerable handler deliberately restored**, proving nothing.

The fix was therefore verified by falsification: reintroduce the pre-fix handler, confirm the
suite fails (`CAPTEST: FAIL ipc-recv-on-unheld-slot-allowed`), restore it, confirm 41/41.
**A test that cannot fail on the bug it targets is not evidence** — the same defect class as
**[I-11]** in `smoke-fs-wal`.

**The I-7 untyped-memory checks.** Twenty-two checks cover `CAP_UNTYPED` and `SYS_RETYPE`,
and unlike the C-1 set they deliberately run in **both directions**. `captest` is endowed with
a real `CAP_UNTYPED` (`captest_selftest`), so the suite asserts that a held capability actually
creates usable, mutually distinct endpoints — a refusal-only suite would be passed by a kernel
whose `SYS_RETYPE` returned `SYS_ERR_PERM` unconditionally. It then asserts every malformed
request is refused, that no refused call spends any of the region (a refusal that consumes what
it refused is a denial-of-service primitive against the caller's own budget), and that revoking
the last capability to a retyped endpoint **destroys the object** while leaving its sibling
intact.

Four gates were falsified against the patched kernel, each in isolation:

| Removed | Check that fired |
|---|---|
| the reserved-slot floor | `retype-into-reserved-slot-allowed` |
| the cspace range checks | `retype-past-cspace-end-allowed` |
| the capability-type check **and** the kernel-reserve guard | `retype-allowed-through-notification-cap-onto-kernel-reserve` |
| `kobj_gc` from `cap_revoke` | `revoked-endpoint-object-not-destroyed` |

The third row is the instructive one. Removing the type check *alone* was **not** detected:
the probes used a `CAP_FRAME` and a `CAP_ENDPOINT`, whose `object` fields fall far outside the
untyped index space, so the range check caught them and the type gate was never the thing
under test. The probe was rewritten to use a `CAP_NOTIFICATION` whose `object` is `0` — a
*valid* untyped index, and specifically the kernel's own cspace reserve — which passes range
and lands on the two gates that actually matter. Defence in depth is why the first attempt
survived; it is also why a falsification that "passes" must be read as a broken test, not as
a strong kernel.

### Known flaky: `smoke-console-smp`

**`smoke-console-smp` fails roughly a third of the time on `main`** — measured at 2 failures
in 6 consecutive runs (2026-07-27, TCG, no KVM). The failure is always the same: boot reaches
`[console_server] ready` and the shell banner never arrives within the 40 s timeout. The
`HHoorruuss` doubled-banner `FAIL_MARKER` does *not* trip, so this is not the single-writer
regression the test was written to catch.

This is recorded rather than quietly retried because of what it costs. The test's purpose is
to guard the ring-3 startup handshake, which is precisely the thing roadmap 1.1 has to
instrument and change — and a test that fails a third of the time for unrelated reasons cannot
distinguish a real handshake regression from noise. It is the same defect class as **[I-11]**
in `smoke-fs-wal`: *a genuine regression and a harness artefact produce identical output.*

It was found while landing roadmap 0.3, and it made that work substantially harder. A real
C-3.1 regression in the untyped locking was masked by it, and separating the two took eighteen
QEMU boots across three builds:

| Build | Runs | Failures |
|---|---|---|
| `main` | 6 | 2 |
| 0.3 branch, before the IF-transparency fix | 3 | 2 |
| 0.3 branch, after the fix | 6 | 1 |

A single run of any of those three would have supported the wrong conclusion. **Treat a
`smoke-console-smp` result as evidence only in aggregate**, and fix or characterise it before
1.1 begins.

*Diagnosis and fix in progress; see `make smoke-console-smp-stress` below.*

### Measuring an intermittent failure: `make smoke-console-smp-stress`

```sh
make smoke-console-smp-stress                        # 20 boots, must be 20/20
STRESS_RUNS=40 make smoke-console-smp-stress         # tighter bound
STRESS_MAX_FAIL=2 make smoke-console-smp-stress      # characterise, don't gate
```

Builds once, then boots that ISO N times with QEMU pinned to a small host CPU set, and
reports a **rate**. Two design points, both learned the hard way:

**It builds once.** Every `make smoke-*` target starts with `clean` and a full rebuild, so
looping one spends nearly all its wall time in the compiler rather than in the kernel under
test.

**It pins the CPUs, and this is not a detail.** Under TCG each guest vCPU is a host thread.
On an idle workstation a 4-vCPU guest gets a core each, the scheduling windows never open, and
the failing build above scores **10/10 green**. Pinned to 2 host cores — what a CI runner
actually has — the same build hangs repeatedly. An unpinned stress run reporting 20/20 on a
kernel that fails a third of the time in CI is worse than no measurement, because it converts
absence of evidence into a claim. `STRESS_CPUSET=` disables pinning and the script says so
loudly when it does.

The corollary for reviewers: **a scheduling or IPC change is not evidenced by one green CI
run.** Ask for a rate.

### `make smoke-sched-invariants` — and an open finding

`SCHED_INVARIANTS=1` machine-checks the scheduler's claim invariant

```
task_running_cpu[t] == c  <=>  percpu_current_task[c] == t     (t > 0)
```

at every timer tick, panicking with the offending task, CPU and observer instead of
livelocking silently thousands of ticks later. Off in the ship kernel; **not wired into CI,
because on today's `main` it fails.**

**Open finding (not root-caused).** In roughly one boot in five it reports:

```
stale scheduler claim at preempt_on_tick: task 1 claimed by cpu N
but that cpu was running 4 (persisted across two audits)
```

`init`, blocked in `sys_wait()` on the shell, remains claimed by a CPU that has moved on to
the shell. Provenance instrumentation puts the claim at `preempt_on_tick`'s selection. It is
**real** — it survives two audits ~10 ms apart — and **latent rather than fatal**: a blocked
task is not selectable, so nothing livelocks until something wakes it, at which point `init`
would never be rescheduled and would never reap its child. It is *not* the console-smp hang,
which is fixed and holds 24/24 on the stress harness. Root-causing it is follow-up work and
should happen before roadmap 1.1 touches this path.

**Three things this checker cost to get right, all worth knowing before extending it:**

1. **It must not panic on first sight.** Not every writer of `task_running_cpu[]` holds the
   scheduler lock, so an auditor on another core legitimately catches mid-flight updates. The
   check requires a violation to survive two audits. A first-sight version reported failures
   on a correct kernel.
2. **It must not print through `print()`.** Once a ring-3 console server owns the console the
   kernel's `print()` is suppressed, and during handover both writers touch COM1 from
   different cores — the panic arrived as `PA[NIC: console_server] ready`, i.e. the one
   message that had to survive was the one that did not, and the halt then looked like an
   ordinary timeout. It writes bytes to the UART directly.
3. **Dead tasks are exempt.** `task_teardown` releases the claim but the CPU keeps naming the
   task until `task_exit_switch` runs, and in between it does a full capability-graph sweep —
   long enough to span several audits. Exempting them costs nothing, since selection requires
   `state == 1`.

**And one thing the checker's own development established, by measurement:** "defensively"
clearing a stale claim makes things *worse*, not better. Two such repairs — sweeping claims
in `enter_cpu_idle`, and marking a CPU idle early in `task_exit_switch` — took the stress
harness from **24/24 to 13/20**, because a stale claim marks a task whose kernel context was
abandoned, and freeing it resumes that task from a stale frame. Both are now recorded as
explicit "do not do this" comments at the sites that invited them.

## Memory protection and isolation

| Target | Proves |
|---|---|
| `smoke-wx` | The kernel image is r-x / r-- / rw-, and a sweep of **every leaf PTE** finds no writable-and-executable page. |
| `smoke-wx-smp` | The same under SMP, and that every AP's IST fault stack sits above an unmapped guard page. |
| `smoke-cpu` | SMEP and SMAP are detected **and actually set in CR4** — not merely attempted. Boots under `-cpu +smep,+smap`. |
| `smoke-aspace` | Rebuilding a task slot repeatedly returns every physical page to the pool — a dead task's address space leaks nothing. |
| `smoke-cow` | Copy-on-write breaks correctly for the shared zero page. |
| `smoke-nzcow` | The generic (non-zero) COW break is correct — added after a real bug in that path. |
| `smoke-stackguard` | The stack canary is re-seeded from the CSPRNG at boot and is no longer the compile-time default. |
| `smoke-aslr` | Image, heap, and stack bases are randomised. |
| `smoke-e820` | The physical pool is sized from the multiboot2 memory map, not a hardcoded fallback. |

## Boot integrity and measured boot

These are the most adversarial tests in the suite.

| Target | Proves |
|---|---|
| `smoke-modules` | Boot modules are provisioned into `/bin` and run from the filesystem. |
| `smoke-modules-tamper` | **Corrupts a module payload inside the ISO** and asserts the kernel refuses it — the manifest gate fires. |
| `smoke-tpm` | Kernel and modules are measured into PCR 8 and 9, and the values equal an independent host recomputation (`tools/tpm_expected_pcr.py`). |
| `smoke-tpm-tamper` | A corrupted module is refused **and** the measured PCRs diverge — detection as well as prevention. |
| `smoke-tpm-seal-roundtrip` | A secret sealed under `PolicyPCR(8,9)` unseals on a good boot and is **denied after a PCR change**. |
| `smoke-tpm-seal` | The real vdisk KEK: a measured-good boot unlocks the volume; a changed PCR leaves it locked. |

Requires `swtpm` and `swtpm-tools`. Driven through `tools/run_with_swtpm.sh`.

## Scheduling, SMP, and side channels

| Target | Proves |
|---|---|
| `smoke-preempt` | The timer genuinely time-slices two ring-3 tasks. |
| `smoke-signal` | A ring-3 fault is delivered to a registered handler. |
| `smoke-smp` | APs come online from the MADT, run scheduled tasks on distinct CPUs, and TLB shootdown completes. |
| `smoke-smt` | SMT sibling threads are parked, closing same-core co-residency. |
| `smoke-flush` | Flush-on-switch detection matches CPUID, the gated barriers execute without faulting, and the **policy** flushes only on a genuine task change. (Barriers are no-ops under TCG; they engage on hardware or KVM.) |
| `smoke-tsd` | A ring-3 `RDTSC` faults under `CR4.TSD`. |
| `smoke-proc` | Process control: spawn, wait, kill, signals (incl. mask/unmask and altstack delivery), and the `CAP_TCB` authority behind them. |
| `smoke-notify` | Async notifications wake a blocked waiter with the accumulated badge. |

## ELF loading

| Target | Proves |
|---|---|
| `smoke-elf` | `try_elf_load` enforces W^X on loaded segments. |
| `smoke-elf64` | x86-64 RELA relocations are applied correctly. |
| `cargo fuzz` (`rust/fuzz/`) | The pointer and scalar predicates at the FFI boundary do not panic or misbehave on adversarial input. |

The ELF loader migration to Rust found two real out-of-bounds bugs in the C original.

## Filesystem

| Target | Proves |
|---|---|
| `smoke-fs` | Basic file operations over the encrypted object store. |
| `smoke-init-fs` | `init` provisions the filesystem at boot. |
| `smoke-fs-perms` | POSIX rwx is enforced against the **kernel-attested** uid/gid, not a client-supplied one. |
| `smoke-fs-persist` | Data survives a reboot (two-boot test). |
| `smoke-fs-wal` | The write-ahead journal recovers a crash-interrupted write (two-boot test). **Known flaky and known weak — see below.** |
| `smoke-fs-conc` | Multiple clients are served concurrently without cross-talk, via `SYS_IPC_REPLY_TO`. |
| `smoke-fs-large` | Double-indirect blocks address large files. |

> **`smoke-fs-wal` — two known defects (findings [I-10], [I-11]).**
>
> **It is nondeterministic.** The harness kills QEMU the moment boot 1's marker appears on
> serial, then reboots on the same image. The marker proves the guest *reached* that point,
> not that its journal writes completed — serial and IDE are independent paths, and
> `cache=writethrough` only makes *completed* writes durable. On a loaded runner boot 2 fails
> with `WAL_CRASHTEST: FAIL read` against an unmodified kernel. It is a **required** status
> check, so it blocks merges spuriously.
>
> **It cannot detect the bug it exists to catch.** The kernel issues no ATA `FLUSH CACHE`
> (0xE7) — ever. On real hardware the commit record can sit in the drive's volatile cache and
> be lost to a power failure. `cache=writethrough` hides this completely: the emulator
> supplies the durability the kernel omits. The test therefore verifies crash-atomicity in
> the one configuration where it is guaranteed by something other than the code under test.
>
> A green `smoke-fs-wal` is not evidence of crash-atomicity on hardware. Fixing it needs a
> `cache=writeback` variant *and* a real flush in the driver.

## Device delegation and the console

| Target | Proves |
|---|---|
| `smoke-mapphys` | `SYS_MAP_PHYS` maps an allowlisted device frame — and only an allowlisted one. |
| `smoke-ioport` | The TSS I/O-bitmap grant gives native ring-3 port I/O to the holder. |
| `smoke-irq` | A hardware IRQ is routed to a userspace notification. |
| `smoke-console` | The ring-3 console server owns the hardware and serves clients. |
| `smoke-console-isolation` | A task **without** `CAP_IO_DEVICE` cannot reach the device-delegation syscalls. |
| `smoke-console-smp` | The single-writer console discipline holds under SMP. |
| `smoke-term` | Raw terminal mode: termios, winsize, and a keystroke through the real shell. |

## Userspace and libc

| Target | Proves |
|---|---|
| `smoke-newlib` | The newlib libc works in ring 3. |
| `smoke-pipe` | Bounded pipes with `EAGAIN` back-pressure and EOF/EPIPE on close. |
| `smoke-coreutils-shell` | `head`, `wc`, and `seq` run on real files, driven through the actual ring-3 shell. |
| `smoke-tcc` | TCC is provisioned into `/bin` and `tcc -v` runs. (Needs `SMOKE_TIMEOUT=320`.) |
| `smoke-session` | A scripted session drives the real shell over serial and asserts on output. |
| `smoke-session-smp` | The same under SMP. |

## Build integrity

| Target | Proves |
|---|---|
| `reproducible-build` | `kernel.elf` is byte-for-byte identical across two clean builds. **A required CI check.** |
| `security` | Semgrep, Trivy, gitleaks, cppcheck, flawfinder, cargo-audit, plus a CycloneDX SBOM. Currently **advisory** (`continue-on-error`). |

---

## CI

`.github/workflows/ci.yml` runs roughly 30 jobs on every push and pull request;
`codeql.yml` adds C/C++ static analysis (advisory, plus a weekly schedule).

All third-party actions are pinned to full commit SHAs. Workflow `permissions:` blocks are
least-privilege. There are no self-hosted runners.

### A known weakness in the gate

Of those jobs, **21 are required status checks** — but the security-specific ones are not
among them. `smoke-captest`, `smoke-wx`, `smoke-cpu`, `smoke-tpm*`, `smoke-modules-tamper`,
`smoke-flush`, and `smoke-stackguard` can all fail while a pull request merges green.

The required set is inverted: functional tests block merges, security tests do not. This is
finding **[C-6]** and roadmap item 4.2. Until it is fixed, **run the security targets locally
before opening a PR** — CI will not stop you.

Additionally, `strict_required_status_checks_policy` is false, so a PR can merge having passed
CI against a stale base.

---

## Host-side tests

`tests/` holds host-compiled test code (`test_capability.c`) used for quick iteration on the
capability logic outside QEMU. The authoritative capability tests are the Rust unit tests,
the Kani proofs, and `smoke-captest`.

---

## Writing a new test

1. Decide which layer it belongs to. Algebraic properties → Rust unit test or Kani proof.
   Kernel behaviour → QEMU self-test. End-to-end user-visible behaviour → scripted session.
2. For a self-test: add a `*_SELFTEST`-guarded routine that prints `NAME: PASS`, and a
   `make smoke-name` target that boots it and greps for the marker. Copy an existing target.
3. **Make it adversarial where you can.** Assert the refusal, not just the success.
4. Reference it in your PR body and in the invariant statement (see `CONTRIBUTING.md`).
