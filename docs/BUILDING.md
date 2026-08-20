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

### Defect-reproducing builds (control arms)

A handful of flags exist to rebuild a defect on purpose, so that the gate for its fix has a
failing arm. A gate that has only ever been run against the fixed kernel is not evidence.

| Flag | Reproduces | Gate |
|---|---|---|
| `IRQ_LEGACY_GLOBAL_LOCK=1` | The pre-1.1 spinlock: one global nesting depth shared by every CPU, incremented non-atomically, with an unconditional `sti` on the outermost release — findings **[C-3]** and **[C-3.1]** exactly as they stood. Detailed in the interrupt-policy table above. | `make smoke-irq-policy` (`Makefile:665-678`) |
| `USER_HEAP_HIGH_BASE=1` | Places every user heap at **8 GiB** instead of 16 MiB — above the 4 GiB line — so the 32-bit truncation in the heap syscalls and the pager's region gate (**[I-2]**) is *reachable* rather than latent. Built from a tree without the fix, the gate reports `CAPTEST: FAIL (sbrk-grow-failed)`. | `make smoke-heap64` |
| `EP_QUEUE_SLOTS=1` | A single-slot endpoint queue, pre-**[I-5]**, for the roadmap 1.3 queue and blocking-receive gates. | `make smoke-recvblock` |
| `KFAULT_INJECT` | Takes a deliberate supervisor page fault (a read of `0x94`, G-8's address) on a timer tick **after** `console_server` owns the console. `KFAULT_INJECT_TICKS` (default 400) sets how long after. | `make smoke-kfault` |
| `KFAULT_LEGACY_PRINTLN` | Reports a CPL-0 page fault through `println()` as the kernel used to — i.e. into the klog, where nothing on the wire can hear it. | `make smoke-kfault-legacy`, which requires the report to be **absent** |
| `RESUME_GUARD_LEGACY_FATAL=1` | Restores the resume-`%rsp` floor guard's pre-fix `kfault_begin(1)`/`kfault_end(1)` bracket, so the report is swallowed by a permanent panic claim another CPU already holds. The report must **not** reach serial. | `make smoke-resume-guard-legacy` |
| `RESUME_GUARD_DISABLE=1` | Compiles the floor guard out entirely; the kernel instead faults at `0x94` on `out->cs`, which is **[G-8]**'s original datapoint reproduced deliberately. | `make smoke-resume-guard-nofloor` |
| `--features=revoke_legacy_bounded` (cargo) | Restores the pre-2026-08-16 revocation closure: a fixed 256-entry worklist of revoked serials, falling back to nulling every capability that merely shares the root object when a subtree overflows it (**[I-3]**). Reachable from ring 3, and it destroys unrelated peers' authority. | `cargo test --manifest-path rust/Cargo.toml --release --features=revoke_legacy_bounded` — the two subtree-exactness tests must **fail**. The `rust` CI job runs exactly this and fails if they pass. |
| `WAL_NO_FLUSH=1` | Compiles out every write-ahead-journal durability barrier, restoring the pre-2026-08-16 kernel in which the ATA driver had no `FLUSH CACHE` opcode and the journal's ordering held only because the emulator persisted each write anyway (**[I-10]**). | `make smoke-fs-wal-flush-control` (the refusal must be **absent**) and `make smoke-fs-wal-order-control` (the ordering check must **reject**) |
| `KSTACK_RELEASE_EARLY=1` | Restores the pre-2026-08-17 release site: a switch path publishes the outgoing task as claimable while the CPU making the switch still has ~30 instructions of ISR epilogue to run **on that task's kernel stack** (**[G-8]**). Another CPU takes it, resumes it to ring 3, and its next trap rewrites the frames the first CPU has not finished reading. | `make smoke-kstack-race-control`, which requires `PANIC: two CPUs on one kernel stack` to be **present** | Gate: `make smoke-kstack-race-control`, which boots up to `KSTACK_RACE_CONTROL_BOOTS` (8) times and stops at the first reproduction — the race appears in about 7 boots of 12, so a single boot could not assert it and reddened `main` twice on 2026-08-19.
| `KSTACK_RACE_WIDEN=1` | Not a defect — a *window widener*, and the only entry here that is set in **both** arms. Spins after the hand-over and before the ISR epilogue leaves the stack, so the **[G-8]** window is entered on essentially every switch instead of at its natural 2–3% per boot. `KSTACK_RACE_WIDEN_SPINS` (default `200000`) is the spin count, and is the value that was measured rather than a round number: a draft default of ten times that made the widened session time out instead of concluding. `KSTACK_RACE_WIDEN_CPUMASK` (default `0x5`) picks which CPUs linger — spinning on *every* CPU is self-defeating, because the CPU that must take the released task is then a full spin behind, and it reproduced only 2 boots in 7 against 12 in 12 for the split. | `make smoke-kstack-race` (with the fix: session completes, marker **absent**) and `make smoke-kstack-race-control` (without it: marker **present**) |
| `KSTACK0_SHARED_PARK=1` | Restores the pre-2026-08-17 park target: when a task dies with nothing else runnable, all three fallbacks in `idt.c` resume the CPU on `tasks[0].kernel_stack_top` — one stack shared by every CPU that takes the path (**[G-8]**, second path). | `make smoke-kstack-park-control`, which requires at least one park stack to come back used by **more than one CPU** |
| `KSTACK0_PARK_TRACE=1` | Not a defect — prints a line each time a CPU parks in the ring-0 idle/reaper loop. It is how the park path's reachability was *measured* rather than assumed: 0 parks in 3 healthy sessions, 5–8 per boot on a task-killing workload. Both park arms build with it, because both assertions are about what the trace shows. | `make smoke-kstack-park` and `smoke-kstack-park-control` |
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
| `KLOG_WRITE_UNGATED=1` | Restores the pre-2026-08-20 `h_write`: a ring-3 write to fd 1 is appended to the kernel message ring with no authority tested at all, so any task can forge `dmesg` lines and flood the 16 KiB ring to evict genuine ones (**[H-2]**). | `make smoke-klog-forge-control`, which requires `KLOGTEST: FAIL forged+evicted` to be **present** (3 boots in 3), against `make smoke-klog-forge`, which must go red under the same flag |

None of these is a shipping configuration. `IRQ_LEGACY_GLOBAL_LOCK` also appears in the
interrupt-policy table above, and until 2026-08-15 that was the only place it was documented;
`USER_HEAP_HIGH_BASE` was not documented anywhere. This table is the complete list — if you
add a control arm, it belongs here in the same commit, because a control arm nobody can find
is one nobody will re-run.

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
