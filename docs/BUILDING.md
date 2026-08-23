# Building Horus

Toolchain, build targets, configuration flags, and how to run Horus under QEMU or on
hardware.

Horus is **x86-64 only**. The kernel runs in 64-bit long mode; there is no 32-bit kernel
build. Boot is Multiboot2 via GRUB (BIOS); UEFI is not supported.

---

## Requirements

A Linux host with an x86-64 native toolchain. No cross-compiler is needed — the kernel is
built freestanding with your system `gcc`.

```bash
sudo apt-get install -y --no-install-recommends \
    build-essential binutils make \
    xorriso grub-pc-bin grub-common mtools \
    qemu-system-x86

rustup target add x86_64-unknown-none
```

| Tool | Purpose |
|---|---|
| `gcc`, `binutils`, `make` | Compile and link the kernel and userspace |
| `rustup` + `x86_64-unknown-none` | The `no_std` security core |
| `xorriso`, `grub-pc-bin`, `grub-common`, `mtools` | Build the bootable ISO |
| `qemu-system-x86` | Run and test |
| `swtpm`, `swtpm-tools` *(optional)* | Measured-boot and sealed-key testing |
| `python3` *(optional)* | Scripted shell sessions and PCR recomputation |

---

## Building

```bash
make            # kernel.elf
make iso        # boot.iso (implies kernel.elf)
make clean      # remove build products
make clean-rust # also clear the Cargo target directory
```

The build links the Rust staticlib with `--whole-archive` (so `#[no_mangle]` FFI symbols
survive), then the C kernel objects, under `linker64.ld`.

**Kernel compile flags of note:**

```
-ffreestanding -fno-pic -fno-pie -mcmodel=kernel
-mno-sse -mno-mmx -mno-80387        # the kernel never touches FP/SIMD registers
-fstack-protector-strong -mstack-protector-guard=global
-Wall -Wextra -Wformat-security -Werror=vla
-frandom-seed=horus -fdebug-prefix-map=...   # reproducibility
```

The kernel is built without SSE deliberately: ring-3 owns the FPU/SIMD register file, and the
kernel's only job is to save and restore it. `fxsave`/`fxrstor` are therefore inline
assembly, since the compiler is forbidden from emitting SSE.

---

## Running

```bash
make run        # boot boot.iso under QEMU with a serial console
make run-tpm    # same, under an emulated TPM (requires swtpm)
```

Log in as **`root`** / **`horus`**.

Useful once you are in:

```
ls /bin              # the provisioned coreutils and test programs
dmesg                # the kernel message ring (root only)
ps                   # tasks, including the userspace servers
cat /etc/motd | wc -l
tcc -v
help
```

`Ctrl-A X` exits QEMU.

### On real hardware

`boot.iso` is a standard El Torito BIOS-boot ISO. Write it to a USB stick with `dd` and boot a
machine in legacy/CSM mode. Horus expects a serial port for its console; without one you get
VGA text output only. This is genuinely exercised, but expect rough edges — driver coverage
is minimal (ATA PIO and PS/2 only).

---

## Configuration flags

Pass as `make VAR=value`. Each toggles `#ifdef` regions, so a flag change forces a rebuild of
the affected objects.

| Flag | Default | Effect |
|---|---|---|
| `SMP` | `1` | Multi-core: ACPI MADT enumeration, AP bringup, per-CPU LAPIC timers, TLB shootdown, SMT parking. `SMP=0` compiles it all out. |
| `DEBUG_SHELL` | off | In-kernel debug shell and command-execution syscall. **Development only** — it widens the syscall surface. |
| `MINIMAL_SECURE` | off | Reduced-surface build for security experiments. |

CI builds `SMP=1`, `SMP=0` (via the default job), `DEBUG_SHELL=1`, and `MINIMAL_SECURE=1`, so
all four keep compiling.

### Interrupt-policy flags

| Flag | Default | Effect |
|---|---|---|
| `IRQ_LEGACY_GLOBAL_LOCK` | off | Rebuilds the **pre-1.1 spinlock**: one global nesting depth shared by every CPU, incremented non-atomically, with an unconditional `sti` on the outermost release — findings **[C-3]** and **[C-3.1]** exactly as they stood. This is the **control arm** the IF-preserving per-CPU lock is measured against. Under `IRQ_POLICY_AUDIT=1` both builds count the same predicate (a release whose caller had `IF` clear); the legacy build reports it as `accidental` and fires the `sti`, the default reports it as `suppressed` and does not. Equal totals is the evidence. **Never ship this.** |
| `IRQ_POLICY_AUDIT` | off | Counts and attributes those releases, and adds the `smoke-irq-policy` milestones. |
| `IRQ_POLICY_QUIET` | `1` | Keeps the audit's counting off the console. `0` reports each milestone as it passes — a figure quoted without its tick is not a measurement, so the report carries one. |

A flag that rebuilds a defect is not a curiosity: without one, a gate has only ever been run
against the fixed kernel, and "it passes" says nothing about what it can detect.

### Self-test builds

Each security self-test is a separate kernel configuration whose test-only code is **absent**
from the default build (and whose test-only syscalls therefore fail closed). You rarely
invoke these directly — the `make smoke-*` targets build and run them for you.

`WX_SELFTEST`, `ELF_SELFTEST`, `ELF64_SELFTEST`, `PREEMPT_SELFTEST`, `SIGNAL_SELFTEST`,
`TSD_SELFTEST`, `E820_SELFTEST`, `SMP_SELFTEST`, `FLUSH_SELFTEST`, `CAPTEST_SELFTEST`,
`PERM_SELFTEST`, `SPAWN_OWNER_SELFTEST` (the **[G-11]** staged-image ownership witness), and
others.

### Booting with a TPM

`make run` boots **with an emulated TPM when `swtpm` is installed** and without one otherwise.
The measured-boot path — PCR 8/9, and the sealed volume KEK — is the configuration the security
properties are stated over, so it is the one you get by default. `NO_TPM=1 make run` forces the
plain boot; the fallback is what a machine without a TPM gets and should not be a path nobody
ever exercises deliberately. `make run-plain` and `make run-tpm` name the two explicitly.

Any smoke gate can boot with a TPM by passing `TPM=1` to `tools/smoke_test.sh`, which routes
through the same `tools/swtpm_lib.sh` the measured-boot gates use. `KEEP_TPMSTATE=<dir>` carries
one TPM across two boots, which is what a sealing test needs.

**`SWTPM_REQUIRED=1` makes a missing `swtpm` an error rather than a skip**, and CI sets it on
all four TPM jobs. Without it those gates print `SKIP` and **exit 0** — so `smoke-tpm-seal`, a
required merge-gating job carrying **S11** and **S12**, could report success while measuring
nothing at all. CI has in fact been installing swtpm all along (verified against a real run's
log: the measured PCRs are there and they match the host-computed manifest), so this was latent
rather than live — but a renamed package or a changed runner image would have turned four
security gates into green no-ops with no signal. Locally the skip stays, because blocking a
developer without swtpm buys nothing.

### Defect-reproducing builds (control arms)

A handful of flags exist to rebuild a defect on purpose, so that the gate for its fix has a
failing arm. A gate that has only ever been run against the fixed kernel is not evidence.

| Flag | Reproduces | Gate |
|---|---|---|
| `IRQ_LEGACY_GLOBAL_LOCK=1` | The pre-1.1 spinlock: one global nesting depth shared by every CPU, incremented non-atomically, with an unconditional `sti` on the outermost release — findings **[C-3]** and **[C-3.1]** exactly as they stood. Detailed in the interrupt-policy table above. | `make smoke-irq-policy` (`Makefile`, `smoke-irq-policy:`) |
| `USER_HEAP_HIGH_BASE=1` | Places every user heap at **8 GiB** instead of 16 MiB — above the 4 GiB line — so the 32-bit truncation in the heap syscalls and the pager's region gate (**[I-2]**) is *reachable* rather than latent. Built from a tree without the fix, the gate reports `CAPTEST: FAIL (sbrk-grow-failed)`. | `make smoke-heap64` |
| `EP_QUEUE_SLOTS=1` | A single-slot endpoint queue, pre-**[I-5]**, for the roadmap 1.3 queue and blocking-receive gates. | `make smoke-recvblock` |
| `KFAULT_INJECT` | Takes a deliberate supervisor page fault (a read of `0x94`, G-8's address) on a timer tick **after** `console_server` owns the console. `KFAULT_INJECT_TICKS` (default 400) sets how long after. | `make smoke-kfault` |
| `KFAULT_LEGACY_PRINTLN` | Reports a CPL-0 page fault through `println()` as the kernel used to — i.e. into the klog, where nothing on the wire can hear it. | `make smoke-kfault-legacy`, which requires the report to be **absent** |
| `LIBHORUS_RETRY_ANY=1` | Restores the pre-libhorus IPC retry loop — `while (r < 0) spin_delay();` — which retries **every** negative return including `SYS_ERR_PERM`. That is finding **[G-8]** signature C on demand: a task denied an endpoint spins forever instead of reporting, and the refusal becomes indistinguishable from a hang. Ring-3 only (libhorus is a userspace library), so it applies to `USERSPACE_CFLAGS`. | `make smoke-libhorus-retry-control`, which requires the pre-call line to be present and `LIBHORUS_SELFTEST: PASS` to be **absent** — the assertion has to be an absence, because under the defect the call never returns to be compared. `make smoke-libhorus` must go **red** under the same flag (it times out). |
| `LIBHORUS_STRNCPY_UNTERMINATED=1` | Gives `ustrncpy` C `strncpy`'s semantics: terminate only if the source fit. Its callers copy a name into a fixed buffer and then treat it as a C string, so the unterminated case is the one nobody tests and an attacker picks. Ring-3 only, as above. | `make smoke-libhorus-strncpy-control`, which requires `LIBHORUS_SELFTEST: FAIL strncpy-truncate-unterminated` to be **present** (three separate checks catch it); `make smoke-libhorus` must go **red** under the same flag. |
| `DEFER_CLEAR_EARLY=1` | Restores the pre-2026-08-21 order in `sched_release_deferred`: clear `percpu_deferred_release[]` — which is the **claim auditor's exemption**, not just a to-do note — *before* taking the lock that drops the claim. The task is then claimed, un-exempt and mid-release for the width of a lock acquisition, and an audit landing in that window reports a leak that is not one. The last component of **[G-9]**, and a false positive of the checker rather than a scheduler defect. | `make smoke-defer-exemption-control` (with `DEFER_WINDOW_WIDEN=1`), which requires `stale scheduler claim` to be **present** within `DEFER_EXEMPTION_BOOTS` (8) boots — it reproduces 8 in 10, so never assert it from one boot. |
| `DEFER_WINDOW_WIDEN=1` | Not a defect — a **window widener**, and set in **both** arms. Spins between the deferred-release consume and the claim being dropped, so that window is entered on essentially every release. Without it the event sits at ~4.5% with variance wide enough that 200-boot arms could not distinguish 4.5% from 6.5% (measured: the baseline itself ran 2/50 then 9/200). Widened, the pair answers in one boot each. | `make smoke-defer-exemption` (silent) **and** `make smoke-defer-exemption-control` (accuses) |
| `SWITCH_COMMIT_EARLY=1` | Restores the pre-2026-08-21 ordering in `task_exit_switch`: commit the switch — claim `next`, install its address space, name it current — and only **then** validate the resume value. `ksp_refuse()` returns `0`, which is **also** that function's legal *"nothing runnable, caller parks"* return, so its three callers in `idt.c` park the CPU and `next` stays claimed forever, unschedulable by every CPU including the holder. This is **[G-9]**'s root cause, and the resume guard added *for* **[G-9]** is what produced it. | `make smoke-switch-commit-control` with `KSP_GUARD_INJECT=1`, which requires `stale scheduler claim` to be **present** — deterministic, where the natural event reproduces at ~3%; `make smoke-switch-commit` must be **silent** under the same injection. |
| `CLAIM_RELEASE_SKIP=1` | Removes `call sched_release_deferred` from the ISR epilogue, so every CPU that switches tasks reaches ring 3 still owing a release and the claim it holds is orphaned — unschedulable by every CPU including its holder. The falsifying arm for the *"a CPU in ring 3 owes no deferred release"* invariant (**[G-9]**'s class). | `make smoke-claim-release-control`, which requires `ring 3 reached with a deferred release outstanding` to be **present**; `make smoke-claim-release` must be **silent** on a clean build (measured 0 in 30). |
| `CLAIM_TRACE=1` | Not a defect — an instrument. Records which site last claimed each task and from which CPU, prints that provenance in the stale-claim panic, and reports two orphaning events at the instant they happen: a deferred-release slot overwritten while occupied, and a release declined because the claim names another CPU. Built to answer *"what last touched it?"* rather than *"which path could?"* — the question that closed **[G-9]**'s exec component. Same role `SPAWN_STAGE_TRACE` plays for the staging window. | Used for measurement; not a gate. Requires `SCHED_INVARIANTS=1` for the auditor it complements. |
| `RESUME_RSP_INJECT=1` | Forces `interrupt_handler64`'s resume `%rsp` to a bogus value once, after the console handover, so the floor guard in `idt.c` can be **gated** rather than waited on: the natural event is about 1 boot in 150, and "no `PANIC` line appeared" is worth nothing until the guard is known to be able to speak on that path. `RESUME_RSP_INJECT_VALUE` (default `4`) picks which half of the guard is exercised — `4` is the 2026-08-13 capture and tests the **floor**; `-7` is the 2026-08-17 capture and tests the **ceiling** added after a real boot showed `-7` sailing over a floor-only predicate (`0xFFFFFFFFFFFFFFF9` is above `0xFFFF800000000000`). Both halves need an arm. `RESUME_RSP_INJECT_TICKS` (default `400`) sets how long after the handover. | `make smoke-resume-guard`, which requires the guard's report to be **present** |
| `RESUME_RSP_INJECT_PRECLAIM=1` | The same injection, but taken with another CPU's **fatal** exception claim already held — the state a real `FATAL` leaves behind, and the exact state of the 2026-08-13 capture, where cpu 3 halted holding it. The guard used to report under `kfault_begin(1)`, which loses that claim and halts **without printing**; this arm is what makes the difference audible. | `make smoke-resume-guard-preclaim` (report **present**), against `make smoke-resume-guard-preclaim-control`, which restores the pre-fix bracket and requires it **absent** |
| `WAL_CRASHTEST=1` | Not a defect — builds the in-kernel journal crash-recovery test. Boot 1 commits a write and halts **before** applying it; boot 2 replays the committed transaction at mount. Pure kernel, no userspace binaries, which is why it is a build flag rather than a workload. | `make smoke-fs-wal`, a two-boot gate requiring `WAL_CRASHTEST: crashed-after-commit` then `WAL_CRASHTEST: PASS` |
| `RESUME_GUARD_LEGACY_FATAL=1` | Restores the resume-`%rsp` floor guard's pre-fix `kfault_begin(1)`/`kfault_end(1)` bracket, so the report is swallowed by a permanent panic claim another CPU already holds. The report must **not** reach serial. | `make smoke-resume-guard-legacy` |
| `RESUME_GUARD_DISABLE=1` | Compiles the floor guard out entirely; the kernel instead faults at `0x94` on `out->cs`, which is **[G-8]**'s original datapoint reproduced deliberately. | `make smoke-resume-guard-nofloor` |
| `--features=revoke_legacy_bounded` (cargo) | Restores the pre-2026-08-16 revocation closure: a fixed 256-entry worklist of revoked serials, falling back to nulling every capability that merely shares the root object when a subtree overflows it (**[I-3]**). Reachable from ring 3, and it destroys unrelated peers' authority. | `cargo test --manifest-path rust/Cargo.toml --release --features=revoke_legacy_bounded` — the two subtree-exactness tests must **fail**. The `rust` CI job runs exactly this and fails if they pass. |
| `WAL_NO_FLUSH=1` | Compiles out every write-ahead-journal durability barrier, restoring the pre-2026-08-16 kernel in which the ATA driver had no `FLUSH CACHE` opcode and the journal's ordering held only because the emulator persisted each write anyway (**[I-10]**). | `make smoke-fs-wal-flush-control` (the refusal must be **absent**) and `make smoke-fs-wal-order-control` (the ordering check must **reject**) |
| `KSTACK_RELEASE_EARLY=1` | Restores the pre-2026-08-17 release site: a switch path publishes the outgoing task as claimable while the CPU making the switch still has ~30 instructions of ISR epilogue to run **on that task's kernel stack** (**[G-8]**). Another CPU takes it, resumes it to ring 3, and its next trap rewrites the frames the first CPU has not finished reading. | `make smoke-kstack-race-control`, which requires `PANIC: two CPUs on one kernel stack` to be **present** | Gate: `make smoke-kstack-race-control`, which boots up to `KSTACK_RACE_CONTROL_BOOTS` (8) times and stops at the first reproduction — the race appears in about 7 boots of 12, so a single boot could not assert it and reddened `main` twice on 2026-08-19.
| `KSTACK_RACE_WIDEN=1` | Not a defect — a *window widener*, and the only entry here that is set in **both** arms. Spins after the hand-over and before the ISR epilogue leaves the stack, so the **[G-8]** window is entered on essentially every switch instead of at its natural 2–3% per boot. `KSTACK_RACE_WIDEN_SPINS` (default `200000`) is the spin count, and is the value that was measured rather than a round number: a draft default of ten times that made the widened session time out instead of concluding. `KSTACK_RACE_WIDEN_CPUMASK` (default `0x5`) picks which CPUs linger — spinning on *every* CPU is self-defeating, because the CPU that must take the released task is then a full spin behind, and it reproduced only 2 boots in 7 against 12 in 12 for the split. | `make smoke-kstack-race` (with the fix: session completes, marker **absent**) and `make smoke-kstack-race-control` (without it: marker **present**) |
| `KSTACK0_SHARED_PARK=1` | Restores the pre-2026-08-17 park target: when a task dies with nothing else runnable, all three fallbacks in `idt.c` resume the CPU on `tasks[0].kernel_stack_top` — one stack shared by every CPU that takes the path (**[G-8]**, second path). | `make smoke-kstack-park-control`, which requires at least one park stack to come back used by **more than one CPU** — within `KSTACK_PARK_CONTROL_BOOTS` (8) boots **that ran to completion**, or `KSTACK_PARK_CONTROL_ATTEMPTS` (24) attempts, whichever comes first. Either the duplicated `PARKTRACE` or the kernel's own collision PANIC counts; the PANIC halts the machine, so on those boots the second trace line never prints. A boot the workload *died* in (`PROC_SELFTEST: FAIL`) is **inconclusive** and is re-booted rather than counted: the park path was never exercised to the end, and the *fixed* build produces the same shape — that is `KSTACK0_PARK_TRACE` killing the run (see its row below), so it is evidence in neither direction. Of the boots that complete, 10 of 12 measured on 2026-08-22 reproduced — and all 10 that completed did |
| `KSTACK0_PARK_TRACE=1` | Not a defect, and **not passive** — prints a line each time a CPU parks in the ring-0 idle/reaper loop. It is how the park path's reachability was *measured* rather than assumed: 0 parks in 3 healthy sessions, 5–8 per boot on a task-killing workload. It emits through `kfault_*`, straight to COM1 from interrupt context: that corrupts ring-3 output and **kills the workload on ~40% of boots** — 8 of 20 against 0 of 20 without it on the same fixed kernel, Fisher one-sided p = 0.0016 (2026-08-22). Only the control arm builds it, because only its assertion *is* the trace. | `make smoke-kstack-park-control` |
| `RESUME_GUARD_FLOOR_ONLY=1` | Restores the pre-2026-08-18 resume-`%rsp` predicate, `rsp < 0xFFFF800000000000ULL` — a floor with no ceiling, which catches a returned `0`, `1` or `4` and misses every small *negative* value, since `-7` is `0xFFFFFFFFFFFFFFF9` and sits above the floor. Pair with `RESUME_RSP_INJECT_VALUE=-7`. | `make smoke-resume-guard-negative-control`, which requires the guard's report to be **absent** |
| `RESUME_GUARD_BSS_ONLY=1` | Restores the bound the ceiling first shipped with: `[__bss_start, __bss_end)` alone, on the premise that every 64-bit kernel stack is a `.bss` array. The three IST stacks are in `.data`, IST1 serves `#PF`, and the guard halts on a rejection — so this build dies on the first ring-3 page fault any workload takes. The **false-positive** arm: every other `RESUME_GUARD_*` flag makes the guard miss something, this one makes it reject something legal. | `make smoke-resume-guard-ist-control`, which requires the false rejection to be **present** (against `smoke-resume-guard-ist`, where `CAPTEST: PASS` must appear and the report must be absent) |
| `RESUME_RSP_INJECT_VALUE=<v>` | Not a defect — chooses which bogus resume `%rsp` `RESUME_RSP_INJECT` forces. `4` (the default) is the 2026-08-13 capture and exercises the guard's floor; `-7` is the 2026-08-17 capture and exercises its ceiling. Both halves need an arm, and until 2026-08-18 only the floor had one. | `make smoke-resume-guard` (4) and `make smoke-resume-guard-negative` (-7) |
| `CR3_RECLAIM_UNGUARDED=1` | Restores the pre-2026-08-17 slot reclaim in `create_user_pagedir`: free the previous occupant's page tables unconditionally, on the uniprocessor argument that the caller being on the kernel CR3 means no CPU is walking the tree. A CPU parked in `kernel_idle` never reloads CR3, and `SYS_KILL` marks a task dead while it still runs in ring 3 elsewhere, so the frames return to the pool and are handed out as ordinary pages under a live core (**[G-10]**). | `make smoke-cr3-reclaim-control`, which requires the free-in-use report to be **present** (measured 20 boots in 20; the guarded arm's fault count is 0 in 30) |
| `EXEC_REENTER_GLOBAL=1` | Restores the pre-2026-08-17 exec hand-off: ONE shared `int` naming the task whose exec re-entry is pending, consumed on the exit of every syscall on every CPU with no test that the exec belonged to that CPU. An exec armed on one core is then taken by another, which claims the exec'ing task, installs its CR3 and resumes the frame the exec tail just built — while the core that ran the exec is still on it (**[G-9]**, exec component). | `make smoke-exec-reenter-control`, which requires the wrong-CPU report to be **present** in at least one of `EXEC_REENTER_RUNS` boots (measured 5 in 20; the fixed arm is 0 in 30) |
| `SPAWN_OWNER_UNCHECKED=1` | Restores the pre-2026-08-18 consume of the staged program image: any task may spawn whatever image is armed, whoever armed it. Since `SYS_SUDO` spawns the armed image **as uid 0** in a different syscall from the arm, a correct password could elevate another task's program (**[G-11]**). | `make smoke-spawn-owner-control`, which requires `SPAWN_OWNER_SELFTEST: FAIL foreign-image-spawned` to be **present** (against `make smoke-spawn-owner`, where the refusal must happen and the task's own image must still spawn) |
| `SPAWN_STAGE_UNSERIALISED=1` | Restores the pre-2026-08-18 spawn path: no lock over the arm → consume window on the process-wide staging (the ELF staging buffer, the armed header, the staged argv), so two CPUs interleave through it (**[G-10]**). Kept buildable even though **no current workload reaches the window twice** — see `TESTS.md`, finding G-10 — so the arm exists the day a second live spawner does. | No gate: a control arm that cannot fail cannot gate anything. The refusal it would produce is `SPAWN STAGE: theft`, and `do_spawn`'s owner check makes it fail closed. |
| `SPAWN_STAGE_WIDEN=1` | Not a defect — holds each of the first `SPAWN_STAGE_WIDEN_WINDOWS` (24) staging windows open for `SPAWN_STAGE_WIDEN_SPINS` (12,000,000) `pause` iterations, so an overlap happens if one is possible at all. Set in **both** arms when measuring. | Used with `SPAWN_STAGE_TRACE=1` for the measurement in `TESTS.md`; not a gate |
| `SPAWN_STAGE_TRACE=1` | Not a defect — reports every entry to the staging window and every arrival that finds another CPU already inside one. This is the *reachability* instrument: a serialised build with zero incidents says nothing unless the window was entered twice, and this is what established that in this tree it never is. Same role `KSTACK0_PARK_TRACE` plays for the park path. | Used for the measurement in `TESTS.md`; not a gate |
| `REPRO_SHA_UNCHECKED=1` | Restores the pre-2026-08-19 build-hash recording step **and** the goal list that made it silent: `reproducible-build` builds `all` (which is `kernel.elf` alone) and records with `sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null \|\| true`. Both halves are needed — a swallowed status is harmless while every artifact exists, so restoring only the `\|\| true` makes the arm pass for the wrong reason. Gate: `make smoke-repro-sha-control`, which requires the incomplete record **and** the success report; `make smoke-repro-sha` must FAIL under the same flag. |
| `KSP_GUARD_ALWAYS=1` | Makes `ksp_is_bogus()` reject **every** stack pointer — the false-positive mutation that every inject-and-look arm passes happily. `make smoke-ksp-guard` must go red under it; if it does not, that gate is testing nothing. | `make smoke-ksp-guard` must **FAIL** under this flag (against the unflagged run, where the guard must stay silent through a boot to ring 3) |
| `BUILD_FLAGS_UNSTAMPED=1` | Restores the pre-2026-08-21 build, in which a `-D` flag was invisible to make: objects do not depend on the flag strings, so `make FLAG=1` followed by `make` recompiles nothing and the flag silently survives. That sequence produced a false **[G-9]** "reproduction" on 2026-08-20 — the guard fired in 2 boots of 3 with the control arm's own injected constant. | `make smoke-defect-flags-rebuild-control`, which requires the stale `DEFECT FLAGS: KSP_GUARD_INJECT` to be **present** after a flagless rebuild (against `make smoke-defect-flags-rebuild`, where it must report `none`) |
| `KSP_GUARD_INJECT=1` | Forges `-7` — the exact value **[G-9]** was seen to hand back — as the return of `task_exit_switch`, the producer the `PROC_SELFTEST` workload drives. Not a defect arm in the usual sense: it exists so the producer-side guard has a falsifying arm, because a guard nobody has seen fire is not a guard. | `make smoke-ksp-guard-control`, which requires `SCHED BOGUS KSP from task_exit_switch` to be **present** |
| `SYSCALL_COVERAGE=1` | Not a defect — records the first entry into each syscall **handler body** and reports it as `SYSCOV <n>`, through `kfault_str()` so it is audible on the wire after `console_server` takes the console. The reachability instrument for test coverage, the same role `SPAWN_STAGE_TRACE` plays for the staging window. | `make smoke-syscall-coverage`, which unions two workloads and diffs against `.github/syscall-coverage.yml` |
| `SYSCALL_PTR_TRUNC32=1` | Restores the pre-2026-08-20 `sys_dmesg` / `sys_audit_digest` wrappers, which passed their buffer as `(uint32_t)(unsigned long)ptr` — so the kernel received the low 32 bits of an address the caller never named and resolved it in the caller's own address space (issue #176). Reaches userspace only: `USERSPACE_CFLAGS` is assigned with `=`, and the flag must be applied at top level after that and outside any other flag's `ifeq`, which is where it was first written and silently never fired. | `make smoke-klog-forge-abi-control`, which requires `KLOGTEST: FAIL setup` to be **present** (3 boots in 3, `rc=-14`), against `make smoke-klog-forge`, whose probe reads the log into a static — hence above-4-GiB — buffer |
| `VFS_FIRST_MATCH=1` | Makes `hvfs_resolve` return the **first** matching mount instead of the longest-prefix one (roadmap 2.4). `"/"` matches every path, so with it installed first every `/dev` path is addressed to the root filesystem — which has an inode 0 of its own and therefore **answers about a different object rather than failing**. Wrong-server-answered, not permission-denied, which is why the witness checks which server replied. Ring-3 only (`hvfs` is a userspace library), so it goes on `USERSPACE_CFLAGS`. | `make smoke-vfs-prefix-control`, which requires `VFSTEST: FAIL wrong-server-answered` to be **present**; `make smoke-vfs` goes red under the same flag |
| `VFS_MOUNT_UNGATED=1` | Removes `hvfs_mount`'s capability probe, so a prefix string alone installs a mount over a slot holding nothing, and every path under it is addressed to an empty slot one failed operation at a time. Ring-3 only, as above. | `make smoke-vfs-mount-control`, which requires `VFSTEST: FAIL mounted-without-a-capability` to be **present** |
| `RAMFS_SLOT3_GATE=1` | Restores the four pre-2026-08-22 gates into the in-kernel ramfs — `SYS_OPEN`, syscall 15 (create), syscall 16 (list) and `SYS_READ`'s `fd >= 3` branch — each of which authorised on cspace slot 3 with `SC_ANYTYPE` (**[H-3]**). Slot 3 holds the legacy `CAP_FRAME` `create_task` installs in every task, so all four were satisfied by a capability nobody asked for and everybody has. It also rebuilds the in-kernel ramfs itself, which left the ship build entirely on 2026-08-22 when its last consumer was deleted — restoring the gates onto an empty store reproduces only two of the four doors. | `make smoke-passwd-probe-control`, which requires `PASSWDPROBE: FAIL opened-a-ramfs-file` to be **present**; `make smoke-passwd-probe` must go red under the same flag |
| `FRAME_INDEX_UNCHECKED=1` | Makes `CAP_FRAME.object` a **physical address** that `SYS_MAP_FRAME` maps directly, instead of an index bounds-checked against the frame table — the shortcut a frame-mapping syscall invites (**[F-2.1]**, roadmap 2.1). It is reachable from a capability the kernel hands out itself: every task is born holding a `CAP_FRAME` in slot 3 whose object is `USER_AREA_BASE`, so under this arm any task maps physical `0x400000` into ring 3. Deliberately not written as "delete the bounds check" — `dyn_frames[0x400000 - 1]` is a wild read that faults, so that arm would measure the check crashing rather than the authority being wrong. | `make smoke-frame-index-control`, which requires `FRAMETEST: FAIL legacy-cap-mapped` to be **present** (3 boots in 3); `make smoke-frame` must go red under the same flag |
| `FRAME_RIGHTS_UNCHECKED=1` | Asks `cap_lookup` for **no rights at all** in `SYS_MAP_FRAME`, so any live `CAP_FRAME` satisfies it and the PTE is built from the request: a `READ`-only delegate obtains a writable mapping and its write lands. Delegation stops reducing. It targets the rights **floor** rather than the `have & want` intersection deliberately — given the floor, the intersection is arithmetically redundant at every reachable call, so an arm against it could not fail, and a control arm that cannot fail measures nothing. | `make smoke-frame-rights-control`, which requires `FRAMETEST: FAIL readonly-delegate-wrote` to be **present** (3 boots in 3); `make smoke-frame` must go red under the same flag |
| `KLOG_WRITE_UNGATED=1` | Restores the pre-2026-08-20 `h_write`: a ring-3 write to fd 1 is appended to the kernel message ring with no authority tested at all, so any task can forge `dmesg` lines and flood the 16 KiB ring to evict genuine ones (**[H-2]**). | `make smoke-klog-forge-control`, which requires `KLOGTEST: FAIL forged+evicted` to be **present** (3 boots in 3), against `make smoke-klog-forge`, which must go red under the same flag |
| `LEGACY_SYSCALLS_PRESENT=1` | Restores the four dispatch entries retired on 2026-08-23: `SYS_CLEAR` (5), `SYS_SYSINFO` (6), `SYS_DEBUG_EXEC` (7) and — the reason the flag exists — `SYS_EXEC_LEGACY` (14), which **creates a task**, authorised on cspace slot 3 with `SC_ANYTYPE`. That is the legacy `CAP_FRAME` every task is born holding: [H-3]'s shape on a fifth door, which that sweep could not see because the entry was written `[14]` and matched none of the `[SYS_NAME]` patterns. | `make smoke-passwd-probe-legacy-control`, which requires `PASSWDPROBE: FAIL legacy-exec-spawned-a-task` to be **present** — that specific marker, so an arm reddening the probe for any other reason does not satisfy it; `make smoke-passwd-probe` must go red under the same flag |
| `MEASURED_BOOT_REQUIRED=1` | **A policy, not a defect.** Makes an unavailable measured boot fatal — no TPM, a locality/transport failure, or a PCR readback failure halts the machine instead of logging and continuing — and refuses to unlock a **persistent** volume that was never sealed, which is the downgrade a password-only volume represents on a machine that requires measurement. Off by default: this kernel is expected to boot on TPM-less machines (`docs/LIMITATIONS.md` §2.9). It is in the defect-flag table because a transcript taken under it describes a different machine, which is what `DEFECT FLAGS` records. | `make smoke-measured-boot-required` (with swtpm: must reach `tpm: measured boot OK`) against `make smoke-measured-boot-required-control` (no TPM: must halt) |
| `MEASURED_VOLUME_EXEMPT_NONE=1` | Removes the ephemeral-vdisk exemption from the rule above. The default boot runs on a RAM-only volume whose key is generated this boot and discarded at power-off, so it is exempt by design — and that exemption is the flag's one hole, which means the refusal branch is unreachable on an ordinary boot. This arm reaches it. | `make smoke-measured-boot-required-volume-control`, which requires `PANIC: measured boot required but the volume is not sealed` (via `EXPECT_FAULT`, since the refusal is a halt) |
| `POSIX_LEGACY_WALK=1` | Restores `posix.c`'s private path walker, the copy that stood until 2026-08-23 (roadmap 2.4). It resolves neither `.` nor `..`: both are looked up as literal directory entries, and `fs_server` creates no such entries — `dir_add` links exactly the name `mkdir` was given — so every libc path containing one fails with `ENOENT`. Ring-3 only, so it belongs on `USERSPACE_CFLAGS` at top level, outside any other flag's `ifeq`. | `make smoke-newlib-walk-control`, which requires `NEWLIB_SELFTEST: FAIL dot-here` to be **present**; `make smoke-newlib` must go red under the same flag |
| `HVFS_DOTDOT_SERVER=1` | Restores the `..` branch `hvfs` shipped with in #195: it asks the SERVER to look up a `..` entry. Nothing in this tree creates one, so the branch was **dead from the day it landed** — and the only test that touched `..` used the pinned case, which returns before the lookup. `..` now pops the walker's own descent stack instead. | `make smoke-newlib-dotdot-control`, which requires `NEWLIB_SELFTEST: FAIL dotdot-back` to be **present** — specifically that marker, since `.` still resolves under this arm and only the descending `..` does not |
| `RNG_UNSEEDED_PROBE=1` | **Not a defect — the instrument.** Asks the CSPRNG for 16 bytes immediately before `entropy_init()` in `kernel_main`, at the one moment the pool is still the hardcoded startup state, and prints which of three things happened: `RNGPROBE: SERVED unseeded keystream`, `RNGPROBE: REFUSED unseeded request`, or `REFUSED but modified the buffer`. It calls the FFI directly rather than `secure_random_bytes` so it can *report* a refusal instead of halting on one — both arms of the gate then read their answer off the wire in the same shape. Set in **both** arms; that is what makes the pair a measurement. | `make smoke-rng-seed` requires `RNGPROBE: REFUSED unseeded request` **present**, in a boot that must also reach the ring-3 shell banner |
| `RNG_UNSEEDED_LEGACY=1` | Restores the pre-2026-08-23 `RngState::fill`, which never consulted `seeded`: asked for output before the pool was reseeded it emits ChaCha20 keystream under the published startup constant in `RngState::new()`, and the caller cannot tell that from randomness (S30). Unlike every other flag in this table it is **not a `-D`** — the defect is in Rust, so the Makefile turns it into `cargo --features rng_unseeded_legacy`; it is stamped into `DEFECT FLAGS` all the same. | `make smoke-rng-seed-control`, which requires `RNGPROBE: SERVED unseeded keystream` to be **present**; `make smoke-rng-seed` must go red under the same flag. Rust arm: `cargo test --manifest-path rust/Cargo.toml --release --features rng_unseeded_legacy`, under which `rng_refuses_before_seeding` must **fail** and `rng_serves_after_seeding` must still pass |

**A flag change now forces a rebuild.** The `CFLAGS`/`ASFLAGS` strings are stamped into
`.build-flags` and every object depends on it, so `make FLAG=1` followed by `make` recompiles
rather than silently keeping the flagged objects. Every boot also prints
`DEFECT FLAGS: <list>` (or `none`), so a serial transcript records the configuration that
produced it — check that line before believing any measurement. `make print-defect-flags`
answers the same question without building. Both mechanisms exist because on 2026-08-20 a
stale `KSP_GUARD_INJECT` turned a [G-9] measurement into a false reproduction, and it was
noticed by luck rather than by method.

None of these is a shipping configuration. `IRQ_LEGACY_GLOBAL_LOCK` also appears in the
interrupt-policy table above, and until 2026-08-15 that was the only place it was documented;
`USER_HEAP_HIGH_BASE` was not documented anywhere. This table is the complete list, and `tools/check_defect_flags.py`
(CI job `defect-flags`) fails the build if it stops being — it derives the flag set from the
Makefile's `DEFECT_FLAGS` and compares. It has to be checked rather than promised: this
sentence was already false when it was written, and three flags were missing from the table
below when that was noticed on 2026-08-21. A control arm nobody can find is one nobody will
re-run.

Note that `WAL_NO_FLUSH=1` is unusual among these in being **deterministic**: the barriers are
either compiled in or they are not, so its gates do not need a rate quoted over N boots the
way a concurrency control arm does.

`KSTACK_RACE_WIDEN=1` is the other unusual one, and in the opposite direction. Every other flag
here rebuilds a defect; this one rebuilds a *window*, and it is deliberately applied to the
fixed kernel as well as the broken one. That is what makes the pair a measurement: the same
widened window must be harmless with the fix and fatal without it. Applied to one arm only it
would prove nothing — which is the mistake `TESTS.md` records this project making twice on
**[G-8]** before it was diagnosed.

---

## Testing

```bash
make smoke      # headless boot; asserts the ring-3 shell banner and login prompt
make test       # Rust unit tests, then a clean rebuild (does NOT boot QEMU)
```

Individual self-tests are `make smoke-<name>`. A few of the important ones:

| Target | Asserts |
|---|---|
| `smoke-captest` | Unheld capabilities, post-revoke use, and bad input are all refused (100 checks — read the count off `CAPTEST: PASS <n> checks` on the wire, not from here) |
| `smoke-wx` | No kernel page is both writable and executable (sweeps every leaf PTE) |
| `smoke-cpu` | SMEP and SMAP are actually set in CR4 |
| `smoke-smp` | APs run scheduled tasks; TLB shootdown completes |
| `smoke-aspace` | A rebuilt task slot leaks no physical pages |
| `smoke-cow` | Copy-on-write breaks correctly |
| `smoke-modules-tamper` | A corrupted boot module is refused |
| `smoke-tpm-tamper` | A corrupted module additionally diverges the measured PCRs |
| `smoke-tpm-seal` | A changed PCR leaves the volume locked |
| `smoke-repro-sha` | The build-hash record covers every artifact, or the recording step refuses and writes nothing |
| `smoke-vfs` | Two filesystem servers, two mounts, one namespace; a mount needs a capability |
| `smoke-passwd-probe` | The in-kernel ramfs is unreachable from ring 3 |
| `smoke-frame` | A frame capability names a kernel-managed object, and a delegate maps only what its rights allow |
| `smoke-fs-perms` | POSIX rwx is enforced against the kernel-attested uid |
| `smoke-fs-wal` | The journal recovers a crash-interrupted write |

The full catalogue is in [`../TESTS.md`](../TESTS.md).

Tests that need a TPM (`smoke-tpm*`) require `swtpm`; they drive it through
`tools/run_with_swtpm.sh`. Note that QEMU's `tpmdev` wants `swtpm --ctrl` on a socket, not
`--server`.

**Timeouts.** Some targets need a larger budget than the 40 s default — for example
`make smoke-tcc SMOKE_TIMEOUT=320`, because the ~1 MiB `tcc` image loads block-by-block over
the FS server. Under TCG emulation everything is slow, and four cores are measurably *slower*
than one.

---

## Reproducible builds

```bash
make reproducible-build   # ONE clean SOURCE_DATE_EPOCH build; records .build.sha
make verify-build         # alias
```

**The target does not build twice, and its name suggests otherwise.** It removes
`kernel.elf`/`boot.iso`, builds both once with `SOURCE_DATE_EPOCH` pinned, and records their
hashes in `.build.sha`. The double-build-and-diff that actually proves reproducibility lives
only in the `reproducible` CI job, which runs the target twice, requires the record to name
both artifacts, and diffs the `kernel.elf` hashes. Locally, run it twice and diff yourself — a
single invocation records hashes and compares them to nothing.

`.build.sha` is plain `sha256sum` output, so `sha256sum -c .build.sha` checks the artifacts you
have against the record.

**Two things this section used to get wrong, both now gated rather than merely reworded.**

1. It said the target built twice. It never has.
2. The recording step could not fail. It was
   `sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null || true`, run over a build goal of
   `all` — and `all: kernel.elf`. The target deletes `boot.iso` and never rebuilt it, so that
   `sha256sum` failed on a missing operand every time it ran, `2>/dev/null` hid the message and
   `|| true` hid the status. `.build.sha` had only ever held one line, and the artifact a third
   party actually obtains was the one the supply-chain control did not cover.

The step is now `tools/record_build_sha.sh`, which fails on a missing artifact and writes
`.build.sha` by rename so a failed run leaves no file rather than a plausible partial. Witness
`make smoke-repro-sha`, falsified by `make smoke-repro-sha-control` (`REPRO_SHA_UNCHECKED=1`).

**`boot.iso` is not byte-reproducible**, which is what building it revealed. `grub-mkrescue`
stamps `/.disk/<wall-clock-second>.uuid` into the image and embeds that UUID in the EFI loaders
it generates; everything this project authors inside the ISO is identical across builds. Two
builds within one second are bit-identical and two seconds apart are not — which is also how a
first, too-quick measurement of this called the ISO reproducible. See `docs/LIMITATIONS.md`
§5.3a.

This is a required CI check. Reproducibility comes from `-frandom-seed`,
`-fdebug-prefix-map`, `--build-id=none`, and avoiding any timestamp or path leakage into the
image.

**A reproducible build is a supply-chain control, not a nicety:** it is what lets a third
party confirm that a binary corresponds to the source beside it. What is still missing is the
outbound half — no tags, no releases, no signed artifacts, no SLSA provenance — so a third
party cannot tie a `boot.iso` they obtained to this repository's CI (**[I-9]**,
`docs/LIMITATIONS.md` §5.3).

This paragraph previously said the repository "currently also *commits* a prebuilt
`kernel.elf`" and pointed at §5.6. Neither half was true: `kernel.elf` and `boot.iso` are
gitignored (`.gitignore:10-11`), `git ls-files` tracks no build artefact, and §5.6 is the
mislocated-governance-files finding. Recorded rather than silently deleted, because
`docs/LIMITATIONS.md` had been asserting the opposite — "no `kernel.elf`, no `boot.iso`, no
object files" — for as long as this paragraph asserted it.

---

## Boot modules

Program images reach the system as GRUB `module2` entries rather than being compiled into
`kernel.elf`, so they cost nothing against the `__bss_end <= USER_PHYS_BASE` (16 MiB) linker
assertion.

At build time, `tools/gen_module_manifest.sh` hashes each module and generates
`src/kernel/boot_module_manifest.h`, which is compiled **into the kernel image**. At boot the
kernel re-hashes each module and compares. A module that does not match is reported as an
empty slot and its payload cannot be read — so it can never be provisioned into `/bin` as an
executable.

`init` reads verified modules over `SYS_BOOT_MODULE_READ` and writes them into the encrypted
store. Destinations are constrained to `/bin` and `/usr/share/man`. Nothing ever executes a
module in place.

To add one: build a PIE binary into `userspace/`, add a `module2` line to `grub.cfg`, and
rebuild. The manifest regenerates automatically.

---

## Rust core

```bash
cargo test   --manifest-path rust/Cargo.toml --release
cargo clippy --manifest-path rust/Cargo.toml --release --all-targets -- -D warnings
```

Both are CI hard gates — clippy warnings fail the build.

Fuzzing (nightly toolchain):

```bash
cargo +nightly fuzz run <target>    # targets in rust/fuzz/
```

Kani proofs over the capability algebra run under `cargo kani`.

The crate has **no external runtime dependencies**. That is deliberate: it keeps the
supply-chain graph empty. Dependabot is configured for Cargo anyway, so it lights up the
moment one is added.

---

## Troubleshooting

**`error: linker ... cannot find -lhorus_shell`** — the Rust staticlib did not build. Run
`cargo build --manifest-path rust/Cargo.toml --release --target x86_64-unknown-none` and read
the error.

**`can't find target x86_64-unknown-none`** — `rustup target add x86_64-unknown-none`.

**`xorriso: command not found` on `make iso`** — install `xorriso grub-pc-bin grub-common
mtools`.

**QEMU boots to a blank screen** — Horus's console is on serial. Use `make run`, which wires
`-serial mon:stdio`, rather than invoking QEMU by hand.

**A smoke test times out** — raise the budget (`make smoke-x SMOKE_TIMEOUT=180`). CI runners
and TCG are slow; this is usually not a real failure.

**Linker assertion `__bss_end <= USER_PHYS_BASE`** — you added a large static array. Move it
into a physical-pool reservation instead (see how `loader_staging` and `g_vdisk_backing` are
handled in `src/include/kernel.h`).
