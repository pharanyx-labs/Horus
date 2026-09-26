# Testing Horus

Horus's security argument rests on its tests. This document lists them and what each one proves.
Two rules shape all of them:

- **Test that the control fires**, not only that the happy path works. Many tests try the
  forbidden thing and require the refusal.
- **A test that cannot fail is not a test.** A gate that guards a security property has a
  **control arm**: a build flag that puts the defect back, under which the gate itself must go
  red. `.github/gate-pairs.yml` pairs every arm with its gate, the defect-flag table in
  [`docs/BUILDING.md`](docs/BUILDING.md) names each flag, and every kernel prints
  `DEFECT FLAGS:` at boot so an instrumented build cannot pass for a clean one.

## The layers

| Layer | What it is | Run with |
|---|---|---|
| Rust unit tests | The capability algebra, the ELF loader, crypto and the CSPRNG, beside the code in `rust/src/` | `cargo test --manifest-path rust/Cargo.toml` |
| Kani proofs | Bounded proofs over the capability algebra, the ELF validators and page reference counts ([`rust/KANI.md`](rust/KANI.md)) | `cd rust && cargo kani` |
| Miri | The security core's tests, interpreted for undefined behaviour | the `miri` CI job |
| Fuzzing | The pure FFI predicates, under cargo-fuzz ([`rust/fuzz/README.md`](rust/fuzz/README.md)) | `cargo +nightly fuzz run <target>` |
| QEMU integration tests | A purpose-built kernel boots headless and the test reads its serial output | `make smoke-<name>` |
| Scripted sessions | Python drivers under `tools/` type into the real shell, over serial or the emulated keyboard | `make smoke-session` and others below |
| Repository checkers | `tools/check_*.py`, each with a harness `tools/test_check_*.sh` that has one failing case per rule | the CI jobs below |

There is deliberately no host-side C test directory: anything algebraic belongs in the Rust crate,
where it can carry a proof, and anything touching kernel state belongs in a QEMU test.

`make smoke` is the basic gate (boot to the ring-3 login prompt). `make test` runs the Rust unit
tests and a clean rebuild; it boots nothing.

## How an integration test works

A `*_SELFTEST` flag builds a check into the kernel (`src/kernel/selftest.c`) or a ring-3 program
(`userspace/`) that prints `NAME: PASS` or `NAME: FAIL <reason>` on the serial console, and a
`make smoke-<name>` target boots it under QEMU and waits for the marker (`tools/smoke_test.sh`).
Test-only code and test-only syscalls are absent from the default kernel, so they fail closed in a
shipped build. Timeouts default to 40 s and can be raised with `SMOKE_TIMEOUT`; a timeout on a
slow runner is usually not a real failure, and a probabilistic gate is sized from a measured rate,
not retried until green.

A marker a gate matches must be written in one piece (`tools/check_split_markers.py`), because
another task's output can land between two writes. Kernel reports are one byte at a time, so the
gates that match kernel strings are moving to COM3, which only the kernel can write
(`docs/LIMITATIONS.md` 2.6c).

## The integration gates


There are 430 `smoke-*` targets: 204 gates and 226 control arms. Each row is a gate; the last column lists its control arms. The properties column names the `SECURITY.md` rows the gate is a witness for. Four gates run locally only, each with its reason in `.github/gate-exceptions.yml`. The measurements behind a gate (its rates, and the run that showed its arm turns it red) are in the pull request that added it and in this file's git history.


### Capabilities and authorisation

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-cap-lookup` | `cap_lookup` resolves only against the caller's own cspace: no cspace, or a slot past its end, is refused rather than served from the root | S55 | `smoke-cap-lookup-control`, `smoke-cap-lookup-range-control` |
| `smoke-cspace-release` | A dead task holds no capability: teardown empties its cspace and leaves the slot reusable | S56 | `smoke-cspace-release-control` |
| `smoke-captest` | **198 checks** in the conformance suite: unheld, revoked, stale and mistyped capabilities are refused across the syscall table, including capability-addressed IPC, untyped memory and "identity is not authority" | S1, S5, S6, S7, S13, S13a, S13b, S18, S28, S32, S34, S46, S52, S58, S60, S72, S78, S80, S93, S94, S95 | `smoke-cap-accounting-control`, `smoke-captest-capenum-control`, `smoke-captest-clock-control`, `smoke-captest-devcap-control`, `smoke-captest-getline-control`, `smoke-captest-irq-ack-control`, `smoke-captest-lookup-type-control`, `smoke-captest-mint-hang-control`, `smoke-captest-poll-notify-control`, `smoke-captest-split-control`, `smoke-captest-storage-format-control`, `smoke-captest-userlist-control` |
| `smoke-captoken` | Endpoint tokens: a server with no mint authority hands out capabilities only by reply-mint, which can only narrow what the caller invoked it with | S105 | `smoke-captoken-unmasked-control` |
| `smoke-captoken-smp` | The same under four CPUs, where the reply-mint has a cross-CPU racer to lose to | S105 |  |
| `smoke-auditprobe` | **13 checks** from a task holding one `CAP_AUDIT`, which enters the audit syscalls' handlers that `captest` only sees refused | S24, S71 | `smoke-auditprobe-abi-control`, `smoke-auditprobe-control` |
| `smoke-blockprobe` | A task holding one storage capability enters the raw block syscalls; each reports a refused block as an I/O error, not as a permission error |  | `smoke-blockprobe-control` |
| `smoke-execprobe` | `SYS_EXEC_IMAGE` keeps the caller's capabilities and lineage, checked from inside the image it entered, and a program image cannot read past its own bytes | S42, S84 | `smoke-execprobe-reset-control`, `smoke-execprobe-root-control` |
| `smoke-reply-ep` | Every task's private reply endpoint is an object no other task can hold a capability for | S95 | `smoke-reply-ep-control` |
| `smoke-console-pass` | A console client that registers another task as input owner is still refused the password | S93 | `smoke-console-pass-control` |
| `smoke-console-isolation` | A task without a device capability cannot reach the device-delegation syscalls |  |  |
| `smoke-devcap-fb` | `SYS_FB_INFO` reveals the display's geometry only to the holder of the framebuffer's device | S43 | `smoke-devcap-fb-control` |
| `smoke-devcap` | A device capability reaches its own device's frame, port and interrupt, and is refused another device's | S43 | `smoke-devcap-irq-control`, `smoke-devcap-object-control`, `smoke-devcap-ports-control` |
| `smoke-kdiag-ioport` | A ring-3 write to the kernel's diagnostic port faults: no device declares it, so no grant can open it | S81 | `smoke-kdiag-grant-control` |
| `smoke-init-provision` | `init` provisions a server on an endpoint it retyped from its own untyped budget | S59 | `smoke-init-provision-control` |
| `smoke-ioport` | A port grant gives the holder native ring-3 port I/O through the TSS bitmap |  |  |
| `smoke-klog-forge` | A ring-3 task cannot forge entries into the kernel log or evict what is there | S23, S24 | `smoke-klog-forge-abi-control`, `smoke-klog-forge-control` |
| `smoke-mapphys` | `SYS_MAP_PHYS` maps a frame the named device declares, and nothing else |  |  |
| `smoke-passwd-probe` | An unprivileged task cannot reach the in-kernel ramfs, and the six retired syscalls answer `SYS_ERR_NOSYS` | S28, S79 | `smoke-passwd-probe-control`, `smoke-passwd-probe-exec19-control`, `smoke-passwd-probe-legacy-control`, `smoke-passwd-probe-recv27-control` |
| `smoke-spawn-owner` | A staged program image can be spawned only by the task that armed it | S21 | `smoke-spawn-owner-control` |
| `smoke-task-ceiling` | The task count is derived at boot from the untyped reserve, and tasks at the top of the range (255 and its aliases) are distinct | S20 | `smoke-task-ceiling-control`, `smoke-task-ceiling-stack-control` |

### Memory and isolation

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-aslr` | Image, heap and stack bases are randomised |  |  |
| `smoke-aspace` | Rebuilding a task slot repeatedly returns every page to the pool | S15 |  |
| `smoke-cow` | Copy-on-write of the shared zero page |  |  |
| `smoke-cpu` | SMEP and SMAP are actually set in CR4 | S7 |  |
| `smoke-mem-seal` | A program can make a page of its own image read-only for good, and cannot seal a page outside it | S107 | `smoke-mem-seal-window-control`, `smoke-mem-seal-write-control` |
| `smoke-e820` | The physical pool is sized from the firmware's memory map |  |  |
| `smoke-fork` | A forked child's memory is a copy-on-write copy, and a fork is refused while a kernel object's page is mapped | S39, S40, S41 | `smoke-fork-arena-control`, `smoke-fork-cspace-flat-control`, `smoke-fork-cspace-orphan-control`, `smoke-fork-share-control` |
| `smoke-fpu` | A task cannot read another task's XMM registers | S16 | `smoke-fpu-leak-control`, `smoke-fpu-save-control` |
| `smoke-frame` | **58 parent checks** + 9 peer checks. Frame capabilities: a mapping carries no more than the capability's rights, a delegate maps only what it holds, and region maps are all-or-nothing | S26, S27, S35, S36, S37, S44 | `smoke-frame-dma-control`, `smoke-frame-index-control`, `smoke-frame-info-control`, `smoke-frame-pages-control`, `smoke-frame-region-control`, `smoke-frame-region-wide-control`, `smoke-frame-rights-control` |
| `smoke-heap64` | The heap syscalls and the pager's region check work above 4 GiB |  |  |
| `smoke-pagefree` | The physical free path refuses a double free, an address outside the pool, an unaligned one, and a frame it never lent | S102 | `smoke-pagefree-control` |
| `smoke-nzcow` | The general copy-on-write break, and its refusal on a page that belongs to a kernel object | S38 | `smoke-nzcow-arena-control` |
| `smoke-stackguard` | The stack canary is reseeded from the CSPRNG at boot |  |  |
| `smoke-tsd` | A ring-3 `RDTSC` faults under `CR4.TSD` | S80 |  |
| `smoke-wx` | The kernel image is r-x, r-- and rw-, and no page anywhere is writable and executable | S8, S9 |  |
| `smoke-wx-smp` | The same under SMP, and every CPU's fault stack sits above an unmapped guard page | S9 |  |

### Scheduling, SMP and kernel stacks

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-claim-release` | A CPU in ring 3 owes no deferred claim release |  | `smoke-claim-release-control` |
| `smoke-console-smp-stress` | The console start-up handshake, as a rate over repeated boots pinned to two host cores (local only) |  |  |
| `smoke-cr3-reclaim` | A task's page tables are not recycled while any CPU still has them loaded |  | `smoke-cr3-reclaim-control` |
| `smoke-defer-exemption` | The claim auditor's exemption lasts until the release it exempts has happened |  | `smoke-defer-exemption-control` |
| `smoke-exec-reenter` | An exec's re-entry hand-off is taken by the CPU that armed it |  | `smoke-exec-reenter-control` |
| `smoke-flush` | The microarchitectural flush runs on a genuine switch between tasks, and only then |  |  |
| `smoke-ksp-guard` | The resume-stack guard stays silent on a healthy boot |  | `smoke-ksp-guard-control` |
| `smoke-kstack-park` | A CPU whose last task dies parks on its own kernel stack, never one another CPU is on | S20 | `smoke-kstack-park-control` |
| `smoke-kstack-race` | A task's kernel stack is run by one CPU at a time, with the hand-off window deliberately widened | S20 | `smoke-kstack-race-control` |
| `smoke-kstack-reuse` | A spawn never reuses a slot whose kernel stack a CPU is still on | S20 | `smoke-kstack-reuse-control` |
| `smoke-percpu` | Each CPU's identity from its TSS selector agrees with its LAPIC |  |  |
| `smoke-preempt` | The timer time-slices two ring-3 tasks | S80 |  |
| `smoke-killed-task` | A task killed while it runs on another CPU stops, and stops writing memory it shares | S56 | `smoke-proc-killed-task-control` |
| `smoke-resume-guard` | A bogus resume stack pointer is caught and reported after the console handover |  | `smoke-resume-guard-legacy`, `smoke-resume-guard-nofloor`, `smoke-resume-guard-preclaim` |
| `smoke-resume-guard-ist` | The resume guard never fires on a legitimate return to an IST stack |  | `smoke-resume-guard-ist-control` |
| `smoke-resume-guard-negative` | The resume guard rejects a negative bogus value |  | `smoke-resume-guard-negative-control` |
| `smoke-sched-invariants` | A kernel built with the scheduler's claim checks boots clean (local only) | S20 |  |
| `smoke-sched-invariants-stress` | The same, as a rate over thirty boots pinned to two host cores |  |  |
| `smoke-kstack-imp` | The stack-collision detector identifies CPUs by what they run, not by the task they are impersonating | S20 | `smoke-kstack-imp-control` |
| `smoke-claim-reread` | The claim auditor re-reads a suspect state before accusing it |  | `smoke-claim-reread-control` |
| `smoke-enter-user-claim` | The first entry to ring 3 never claims a task another CPU already holds | S20 | `smoke-enter-user-claim-control`, `smoke-enter-user-collide-control` |
| `smoke-smp` | Every CPU in the MADT comes online and runs a task, no task runs on an SMT sibling, and TLB shootdown completes | S80 |  |
| `smoke-smp-topology` | Eight CPUs on four topologies, including sparse LAPIC ids and hyperthreads, where primary threads get the CPU slots first | S101 | `smoke-smp-topology-sibling-control`, `smoke-smp-topology-sparse-control` |
| `smoke-smp-kvm` | The SMP race gates again under KVM, as a second detector |  |  |
| `smoke-smt` | SMT siblings are parked | S101 |  |
| `smoke-switch-commit` | A refused switch leaves no stale scheduler claim behind |  | `smoke-switch-commit-control` |

### IPC, processes and signals

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-forkexec` | After `fork` and `exec`, a child's capabilities stay derived from its parent's, three generations deep | S39, S42 | `smoke-forkexec-reset-control`, `smoke-forkexec-root-control` |
| `smoke-kdiag` | Every kernel marker arrives intact on COM3, the channel only the kernel can write | S81 | `smoke-kdiag-legacy-control`, `smoke-kdiag-split-control` |
| `smoke-kfault` | A kernel-mode page fault is reported on the serial line after the console handover |  | `smoke-kfault-legacy` |
| `smoke-kfault-record` | A task's exit record carries no kernel address | S97 | `smoke-kfault-record-control` |
| `smoke-notify` | A notification wakes a blocked waiter with the accumulated badge |  |  |
| `smoke-pipe` | Bounded pipes with back-pressure, EOF and EPIPE |  | `smoke-pipe-cspace-order-control` |
| `smoke-proc` | Spawn, wait, kill and signals, and the `CAP_TCB` authority behind each: a wait or kill needs a capability naming that task | S32, S57, S80, S84, S98, S99, S100 | `smoke-proc-exit-record-control`, `smoke-proc-overreach-control`, `smoke-proc-spawn-decoy-control`, `smoke-proc-taskinfo-control`, `smoke-proc-tcb-reuse-control`, `smoke-proc-truncated-image-control`, `smoke-proc-wait-control` |
| `smoke-recvblock` | A server waiting in a blocking receive makes one receive per message, so it slept rather than polled |  |  |
| `smoke-recvblock-smp` | The same across CPUs |  |  |
| `smoke-signal` | A ring-3 fault reaches a registered handler | S80 |  |

### Boot, measured boot and integrity

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-boot-module-reserve` | A boot module the kernel verified is the one it serves, even when modules land above 16 MiB | S96 | `smoke-boot-module-image-control`, `smoke-boot-module-reserve-control`, `smoke-boot-module-reverify-control` |
| `smoke-boot-media` | The image boots under BIOS and UEFI, from optical media and from a raw disk |  | `smoke-boot-media-control` |
| `smoke-tpm-cmdline` | The kernel command line is part of the PCR 8 measurement | S91 | `smoke-tpm-cmdline-control` |
| `smoke-boot-menu` | The install media's default entry is the live boot, and it changes nothing, even on a blank disk | S91 | `smoke-boot-menu-control` |
| `smoke-boot-pin` | GRUB refuses a kernel that does not match the hash pinned in the boot image | S11, S92 | `smoke-boot-pin-control` |
| `smoke-tpm-bootimg` | A volume sealed under one boot image is found but not opened under another | S11, S92 | `smoke-tpm-bootimg-control` |
| `smoke-nvcounter` | The TPM monotonic counter provisions once, reads back, and only goes up | S70 |  |
| `smoke-rollback` | A whole volume restored from an older image is refused | S70 | `smoke-rollback-control` |
| `smoke-irq-policy` | The interrupt state at five named boot milestones matches the stated policy |  |  |
| `smoke-measured-boot-required` | A `MEASURED_BOOT_REQUIRED` kernel halts when measured boot is unavailable | S12, S85 | `smoke-measured-boot-required-control`, `smoke-measured-boot-required-volume-control` |
| `smoke-measured-persist` | Under that policy, a persistent disk that was never sealed is refused | S85 | `smoke-measured-persist-control` |
| `smoke-measured-persist-sealed` | Under that policy, a disk sealed to the same measurements still opens | S85 |  |
| `smoke-modules` | Boot modules are provisioned into `/bin` and run from the filesystem |  |  |
| `smoke-modules-tamper` | A corrupted module is refused against the manifest | S10 |  |
| `smoke-rng-seed` | The CSPRNG refuses to produce output before it is seeded | S30 | `smoke-rng-seed-control` |
| `smoke-tpm` | The kernel and modules are measured into PCR 8 and 9, matching an independent host computation | S11 |  |
| `smoke-tpm-seal` | A measured-good boot unlocks the volume key; a changed PCR leaves it locked |  |  |
| `smoke-tpm-seal-roundtrip` | A secret sealed to PCR 8 and 9 unseals on a good boot and not after a change |  |  |
| `smoke-tpm-tamper` | A corrupted module is refused and the PCRs diverge | S11 |  |

### Storage and the filesystem

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-readdir-end` | The end of a directory is distinguished from a directory that cannot be read |  | `smoke-readdir-end-control` |
| `smoke-replace-live` | An unlocked volume cannot be reformatted; a recognised but locked one can | S90 | `smoke-replace-live-control` |
| `smoke-replace-oneshot` | The permission to format is spent by the format that uses it | S90 | `smoke-replace-oneshot-control` |
| `smoke-keyslots` | Several passwords open one volume, and revoking one revokes exactly that one | S61 | `smoke-keyslots-control` |
| `smoke-meta-crash` | A committed metadata update survives a crash whether or not its cache line was evicted | S65 | `smoke-meta-crash-control`, `smoke-meta-crash-txn-control`, `smoke-meta-crash-vacuity-control` |
| `smoke-merkle-replay` | A metadata block rolled back on the disk is refused | S66 | `smoke-merkle-parent-bind-control`, `smoke-merkle-replay-control` |
| `smoke-fsck-refs` | `fsck` never frees a live file's blocks | S67 | `smoke-fsck-refs-control` |
| `smoke-fs-16g` | A 16 GiB volume formats, survives a reboot and a crash, and holds a file past the old 1 GiB limit | S68 |  |
| `smoke-fs-shrink` | A volume larger than its disk is refused | S68 | `smoke-fs-shrink-control` |
| `smoke-alloc-hint` | Block allocation starts where the last one ended, and still finds a free block behind it |  | `smoke-alloc-hint-control` |
| `smoke-ata-ready` | An ATA transfer happens only when the drive reports ready | S69 | `smoke-ata-ready-control` |
| `smoke-storage-survey` | A capability holder learns which disks the machine has, and whether each holds a volume | S72, S82 | `smoke-storage-device-clamp-control`, `smoke-storage-survey-single-control` |
| `smoke-vdisk-bound` | The RAM disk accepts only blocks it has memory for | S64 | `smoke-vdisk-bound-control` |
| `smoke-users-persist` | Accounts survive a reboot | S62 | `smoke-users-persist-control` |
| `smoke-users-tamper` | A tampered account table refuses every login | S62 |  |
| `smoke-storage-noformat` | A login is not consent to format: an unrecognised disk is refused | S63 | `smoke-storage-noformat-control` |
| `smoke-fs` | File operations over the encrypted store | S80 |  |
| `smoke-fs-conc` | Several clients are served concurrently without cross-talk |  |  |
| `smoke-fs-large` | Large files through indirect blocks |  |  |
| `smoke-fs-perms` | File permissions are checked against the kernel-attested user, not a client's claim | S13, S14 |  |
| `smoke-fs-persist` | Data survives a reboot |  |  |
| `smoke-fs-wal` | The journal replays a write interrupted by a crash |  |  |
| `smoke-fs-wal-flush` | A failed cache flush stops the journal committing |  | `smoke-fs-wal-flush-control` |
| `smoke-fs-wal-order` | The journal's writes and flushes reach the disk in the required order |  | `smoke-fs-wal-order-control` |
| `smoke-init-fs` | `init` provisions the filesystem at boot |  |  |
| `smoke-meta-evict` | An evicted dirty metadata block is written back |  | `smoke-meta-evict-control` |
| `smoke-image-abi` | The kernel reads the program-image container exactly as the build tool wrote it | S80 | `smoke-image-abi-control` |
| `smoke-vfs` | Two filesystem servers mounted in one namespace, each reachable only through its capability | S29 | `smoke-vfs-mount-control`, `smoke-vfs-prefix-control` |

### The installer and accounts

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-installer-emmc` | A whole install onto a 64 GiB eMMC shaped like the test laptop's (local only) |  |  |
| `smoke-installer-replace` | Install media replaces an earlier volume, and only the new password opens it | S90 |  |
| `smoke-installer` | Install onto a bare disk, power off, and log into what was installed; the compiled-in root password is refused | S73, S103, S104 | `smoke-installer-defaults-control`, `smoke-installer-sealed-control` |
| `smoke-installer-clear` | The installer's final clear leaves the screen clear |  | `smoke-installer-clear-control` |
| `smoke-installer-refuse` | Any word but the required one at the last question writes nothing | S73 | `smoke-installer-refuse-control` |
| `smoke-installer-provision` | A machine powered off before its first login finishes provisioning on the next boot | S74 | `smoke-installer-provision-control` |
| `smoke-installer-accounts` | The everyday account can be the first login after a power cycle | S76 | `smoke-installer-accounts-control` |
| `smoke-installer-target` | An install onto the second of two disks leaves the first untouched | S83 | `smoke-installer-target-control` |
| `smoke-installer-back` | The installer's questions can be walked backwards |  |  |
| `smoke-installer-sized` | A volume smaller than the disk is the size chosen, and boots |  | `smoke-installer-sized-control` |
| `smoke-installer-failed` | A failed install says why on the screen and waits to be read |  | `smoke-installer-failed-control` |
| `smoke-live-no-seed` | Even with the live-boot lock removed, no compiled-in password is written to a disk | S109 | `smoke-live-no-seed-control` |
| `smoke-live-locked` | A live boot neither opens nor changes an installed disk | S110 | `smoke-live-locked-control` |
| `smoke-installer-unsealed` | An unencrypted install says so at every boot and still requires the password | S104 | `smoke-installer-unsealed-control` |
| `smoke-installer-sd` | A whole install onto an SD card, through a power cycle |  | `smoke-installer-sd-devregs-control`, `smoke-installer-sd-stride-control` |
| `smoke-installer-sd-smp` | The same with two CPUs, which the driver's lock makes safe |  | `smoke-installer-sd-smp-control` |
| `smoke-passwd-target` | `passwd <uid>` changes that account and only that one | S75 | `smoke-passwd-target-control` |
| `smoke-installer-slowdisk` | A slow disk is not mistaken for a wedged install |  | `smoke-installer-wedge-control` |

### Console, keyboard and display

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-console-handover` | A console driver that fails after taking the console is still heard |  | `smoke-console-handover-control` |
| `smoke-keyboard` | A login typed on the machine's own PS/2 keyboard | S89 | `smoke-keyboard-control` |
| `smoke-console-idle` | An idle prompt sleeps, and a key or the tick still wakes it |  | `smoke-console-idle-control` |
| `smoke-console-scrollback` | Lines that scrolled off can be paged back with Shift+PgUp and PgDn |  | `smoke-console-scrollback-control` |
| `smoke-klog-console` | In a diagnostic build, Alt+F2 shows the kernel log and gives the console back intact |  | `smoke-klog-console-control` |
| `smoke-klog-console-fb` | The same view covers the whole of a framebuffer display |  | `smoke-klog-console-fb-control` |
| `smoke-klog-console-absent` | A shipped build does nothing on Alt+F2 |  | `smoke-klog-console-absent-control` |
| `smoke-keyboard-noserial` | The keyboard works on a machine with no serial port |  | `smoke-keyboard-noserial-control` |
| `smoke-keyboard-installer-noserial` | A full-screen program is drawn on the display of a machine with no serial port |  | `smoke-keyboard-installer-noserial-control` |
| `smoke-console-backspace` | Backspace erases on the screen, not only in the line buffer |  | `smoke-console-backspace-control` |
| `smoke-console-scroll` | A full screen scrolls rather than wrapping to the top |  | `smoke-console-scroll-control` |
| `smoke-console-cursor` | The hardware cursor follows the text |  | `smoke-console-cursor-control` |
| `smoke-console-resume` | Nothing is stranded below the prompt when the console changes hands |  | `smoke-console-resume-control` |
| `smoke-console-escape` | An arrow key does not type its own escape sequence |  | `smoke-console-escape-control` |
| `smoke-keymap-us` | The US layout, which is also the fallback for an unknown layout name |  |  |
| `smoke-keymap-uk` | The UK layout produces the UK characters for the keys that differ |  | `smoke-keymap-uk-control` |
| `smoke-keyboard-installer` | The arrow keys drive the installer's disk menu | S89 | `smoke-keyboard-installer-control` |
| `smoke-keyboard-install` | An entire install and login typed on the keyboard, with nothing sent over serial | S89 |  |
| `smoke-serial-bound` | A stuck serial port cannot stop the machine |  | `smoke-serial-bound-control` |
| `smoke-console` | The ring-3 console server owns the hardware and serves clients |  |  |
| `smoke-console-smp` | The console's single-writer rule holds under SMP |  |  |
| `smoke-console-timestamps` | Every boot-log line is stamped, and the stamps never run backwards |  | `smoke-console-timestamps-control`, `smoke-console-timestamps-epoch-control` |
| `smoke-tui` | The TUI library's damage tracking, bounds and input, checked against its own buffers |  | `smoke-tui-acs-control`, `smoke-tui-bound-control`, `smoke-tui-clamp-control`, `smoke-tui-diff-control`, `smoke-tui-invalidate-control`, `smoke-tui-mask-control`, `smoke-tui-menu-control`, `smoke-tui-wrap-control` |
| `smoke-fb-tag` | The kernel records the display GRUB describes |  | `smoke-fb-tag-control` |
| `smoke-fb-tag-gfx` | The same when GRUB sets a graphics mode |  | `smoke-fb-tag-gfx-control` |
| `smoke-fb-map` | The framebuffer is mapped into the shared kernel half |  | `smoke-fb-map-control` |
| `smoke-fb-console` | The kernel's framebuffer console draws the right pixels |  | `smoke-fb-console-control` |
| `smoke-fb-console-24bpp` | The framebuffer console draws correctly on a 24-bit display, and a UEFI machine reaches a login |  | `smoke-fb-console-24bpp-control` |
| `smoke-fb-console-server` | `console_server` takes over the framebuffer and paints the login prompt |  | `smoke-fb-console-server-control` |
| `smoke-fb-grid` | The console grid is sized to what the display can show |  | `smoke-fb-grid-control` |
| `smoke-term` | Raw terminal mode, termios and window size through the real shell |  |  |

### Devices, drivers and interrupts

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-ahci-detect` | An AHCI controller and its drive are identified |  | `smoke-ahci-capacity-control`, `smoke-ahci-detect-control` |
| `smoke-sdhci-detect` | An SD host controller and its card are found and read |  | `smoke-sdhci-addr-control`, `smoke-sdhci-csd-control`, `smoke-sdhci-detect-control` |
| `smoke-sdhci-fast` | After identification the card switches to a 4-bit bus at speed, proved with a read |  | `smoke-sdhci-fast-control` |
| `smoke-sdhci-write` | SD writes reach the backing file, in a build of their own |  |  |
| `smoke-sdhci-bridge` | A controller behind a PCI-to-PCI bridge is found |  | `smoke-sdhci-bridge-control` |
| `smoke-sdhci-crowded` | A controller at the end of a crowded bus is found |  | `smoke-sdhci-crowded-control` |
| `smoke-sdhci-v3clock` | An SDHCI 3.00 host identifies its card at 400 kHz or less |  | `smoke-sdhci-v3clock-control` |
| `smoke-sdhci-emmc` | The eMMC branch: power-up, extended CSD capacity and a read (local only) |  |  |
| `smoke-iommu-teardown` | A device's translation of a frame goes when the frame or its driver does | S53 | `smoke-iommu-teardown-control`, `smoke-iommu-teardown-task-control` |
| `smoke-irq` | A hardware interrupt reaches a ring-3 notification |  |  |
| `smoke-net` | A ring-3 driver holding one device capability exchanges ARP on the wire, its DMA confined by the IOMMU | S44, S45, S46, S47, S48 | `smoke-net-busmaster-control`, `smoke-net-decode-control`, `smoke-net-iommu-control`, `smoke-net-irq-storm-control`, `smoke-net-mask-control`, `smoke-net-msi-vector-control`, `smoke-net-msix-table-control` |
| `smoke-net-intx` | The same driver on a device with no MSI, through the masked legacy interrupt line |  |  |

### Userspace, loading and shared libraries

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-ls-path` | `ls` takes a path argument |  | `smoke-ls-path-control` |
| `smoke-coreutils-shell` | `head`, `wc` and `seq` on real files through the shell |  |  |
| `smoke-shlib-inherit` | The library reaches only a program whose image asks for it, with fresh private data at every spawn and exec | S106 | `smoke-shlib-inherit-data-control`, `smoke-shlib-inherit-exec-control`, `smoke-shlib-inherit-image-control`, `smoke-shlib-inherit-pin-control` |
| `smoke-shlib-link` | crt0 resolves a program's libc references by name, refuses a mismatched library or an unknown name, and seals the table | S108 | `smoke-shlib-link-abi-control`, `smoke-shlib-link-seal-control`, `smoke-shlib-link-unknown-control` |
| `smoke-coreutils-shared` | Every shipped coreutil and `tcc` links the shared libc instead of carrying its own, and runs |  | `smoke-coreutils-shared-control` |
| `smoke-elf` | The loader enforces W^X on loaded segments |  |  |
| `smoke-elf64` | x86-64 relocations are applied correctly |  |  |
| `smoke-libhorus` | The shared runtime keeps its bounds and its bounded IPC retry |  | `smoke-libhorus-retry-control`, `smoke-libhorus-strncpy-control` |
| `smoke-newlib` | newlib runs in ring 3, including `.` and `..` in paths | S29 | `smoke-newlib-dotdot-control`, `smoke-newlib-walk-control` |
| `smoke-newlib-tamper` | A tampered newlib tarball is refused before unpacking, and the genuine one is accepted |  |  |
| `smoke-session` | A scripted login and session in the real shell, including permissions, ownership, home directories and hard links | S29, S32, S77, S78, S93 | `smoke-session-chmod-control`, `smoke-session-chown-control`, `smoke-session-fs-err-control`, `smoke-session-hardlink-control`, `smoke-session-home-control`, `smoke-session-usage-control` |
| `smoke-session-smp` | The same under SMP |  |  |
| `smoke-session-smp-soak` | Repeated SMP sessions, all of which must complete |  |  |
| `smoke-shlib` | Shared library text is executable by many tasks and writable by none, and its data is private to each | S49, S50, S51 | `smoke-shlib-data-init-control`, `smoke-shlib-data-shared-control`, `smoke-shlib-info-control`, `smoke-shlib-info-object-control`, `smoke-shlib-writable-control` |
| `smoke-shlib-aslr` | The shared library's address differs between boots | S51 | `smoke-shlib-aslr-control` |
| `smoke-shlibc` | The real shared libc is mapped and called from ring 3 |  |  |
| `smoke-shlibc-link` | A program links against the libc stub archive and runs |  |  |
| `smoke-tcc` | TCC is provisioned and runs |  |  |

### Build and harness integrity

| Gate | What it proves | Properties | Control arms |
|---|---|---|---|
| `smoke-ap-trampoline` | The embedded secondary-CPU trampoline is exactly its code, whatever the host assembler emits |  | `smoke-ap-trampoline-control` |
| `smoke-defect-flags` | Every boot states which defect flags built it |  | `smoke-defect-flags-control` |
| `smoke-defect-flags-rebuild` | Changing a defect flag rebuilds what it affects |  | `smoke-defect-flags-rebuild-control` |
| `smoke-repro-sha` | The build record refuses an incomplete build and names every artifact of a complete one | S17 | `smoke-repro-sha-control` |
| `smoke-syscall-coverage` | Which syscall handlers the tracked workloads enter matches `.github/syscall-coverage.yml` | S25 | `smoke-syscall-coverage-control` |

## Coverage of the syscall table

`captest` is a refusal suite: the capability gate returns before a refused handler runs, so a
syscall it names may never have had its handler executed. `make smoke-syscall-coverage` records
which handler bodies three tracked workloads actually enter (the scripted session, the
conformance suite and the boot-modules session) and compares that with
`.github/syscall-coverage.yml`, which gives a reason for every syscall not covered.

Capability conformance (198 checks in `userspace/captest.c`, which prints its own count) is the widest single suite, and it is still only a refusal suite.

Currently **91 of 102** implemented syscalls are covered (`SECURITY.md` S25; `docs/LIMITATIONS.md` 1.8 lists what the rest would cost).

## CI


`.github/workflows/ci.yml` defines **135** jobs, run on every push and pull request; most are sharded runs of the gates above. With CodeQL and the scheduled ruleset audit the total is below: **137** jobs, **140** contexts, counted by `tools/check_ci_gating.py`.

`.github/ci-gating.yml` classifies every job as gating or exempt with a written reason, and the `ci-gating` job fails on a job in neither list. The branch ruleset requires two checks: `gates`, which needs every gating job and passes only if each succeeded (skipped or cancelled counts as failed), and CodeQL.
The set is **136 gating contexts and 4 reasoned exemptions**: `fuzz` (a short time-boxed search is evidence of effort, not absence), `kani` (manual only, and unable to fail as written; `docs/LIMITATIONS.md` 5.8), `ruleset-audit` (runs on a schedule, never on a pull request) and `smoke-smp-kvm` (a second run of required gates under KVM, until its pass rate is measured).

The jobs that are not boot tests:

| Job | What it enforces |
|---|---|
| `ci-gating` | Every CI job is classified as gating or exempted (with a reason) |
| `gates` | All required gates passed |
| `installer-accounts` | An installed machine has two accounts and either one boots it (S76) |
| `invariants` | Every security property is bound to a witness that exists |
| `unsafe-safety` | Every unsafe in the security core states the caller's obligations |
| `apt-hardening` | No build depends on a repository this project does not use |
| `doc-claims` | Every documented count matches the tool that derives it |
| `site` | The website is its sources, its links resolve, and it loads nothing from elsewhere |
| `conflict-markers` | No tracked file carries a merge-conflict marker |
| `prose-style` | The docs and the website use no em dash and British spelling |
| `rust` | Rust unit tests + clippy (deny-warnings gate) |
| `kernel` | Build kernel.elf + bootable ISO (x86_64) |
| `altconfigs` | Build alternate configs (each configuration) |
| `measured-boot-required` | Measured boot can be required, and then an unmeasured boot does not proceed |
| `defect-flags` | Every boot states which defect flags built it (and a flag change forces a rebuild) |
| `ksp-guard` | A bogus resume %rsp is refused where it is produced (G-9) |
| `syscall-coverage` | Which syscall handlers a test actually enters is decided, not drifting |
| `gate-pairs` | Every control arm has a base gate, and every gate runs |
| `defer-exemption` | The claim audit's exemption outlives the release it exempts (G-9; control arm proves it) |
| `switch-commit` | A refused switch leaves no claim behind (G-9 root cause; control arm proves it) |
| `claim-release` | A CPU in ring 3 owes no deferred release (G-9 class; control arm proves it) |
| `console-timestamps` | Every line of the boot log carries a timestamp, and they run forwards |
| `libhorus` | The shared userspace runtime keeps its bounds, and refuses rather than spins |
| `installer` | Install onto a bare disk, then boot and log into what was installed (2.9) |
| `store-locked` | A sealed volume answers nothing, and the next boot finishes the install (S74) |
| `passwd-target` | passwd <uid> changes that account, and only that account (S75) |
| `vfs` | Two filesystem servers, two mounts, one namespace (2.4) |
| `passwd-probe` | The in-kernel ramfs is unreachable from ring 3 (H-3) |
| `image-abi` | The kernel reads the .bin container the build tool wrote (S80) |
| `frame` | A frame capability names an object, and a delegate maps only what it holds |
| `devcap` | A device capability names one device, and reaches only that device |
| `net` | A network driver in ring 3, holding one device capability |
| `shared-objects` | Every shared object is one the kernel's loader would accept |
| `shlib` | Shared library text is executed by many tasks and writable by none |
| `fpu` | A task cannot read another's XMM register file |
| `fork` | A forked child's memory is a copy, and a kernel object is never forked |
| `forkexec` | An exec replaces the image, not the authority |
| `rng-seed` | The CSPRNG refuses to emit keystream before it is seeded |
| `cap-writes` | Every write to a capability slot is a declared write |
| `defect-flags-documented` | Every defect flag has a row in the table that claims to list them all |
| `ffi-deadsurface` | Every symbol the security core exports across the FFI has a live caller |
| `ring0-budget` | Every object linked into the kernel is classified, and the core stays in budget |
| `lock-order` | The kernel's lock order is declared, and no path violates it |
| `syscall-abi` | Every user pointer reaches the kernel full-width (issue #176) |
| `reproducible` | Verify reproducible kernel build |
| `security` | Security scans + SBOM generation (Semgrep, Trivy, gitleaks, etc.) |
| `fuzz` | FFI fuzzing (cargo-fuzz, advisory) |
| `miri` | Undefined-behaviour check of the security core (Miri) |
| `kani-bounded` | Formal verification of the capability algebra (the proofs that finish) |
| `kani` | Formal verification (Kani, advisory) |

Two of those deserve a sentence each.
**`kani-bounded` is the Kani job that can fail anything.** **21** harnesses run
there with no `continue-on-error`; the
**2** excused harnesses are named, with their measured cost, in
`.github/kani-harnesses.yml`. And **`invariants`** requires every property in `SECURITY.md` to
name a witness that exists and runs; its exemption list, `.github/invariants.yml`, is
currently **empty**: all 112 properties name a witness that resolves.

Every `tools/check_*.py` has a falsification harness, `tools/test_check_*.sh`, with one case per
rule showing the rule can fail, and each checker asserts a floor on what it parsed, so a parser
that silently matches nothing cannot report a clean tree.

## Writing a new test

1. Choose the layer: an algebraic property is a Rust test or a Kani proof, kernel behaviour is a
   QEMU test, and end-to-end behaviour is a scripted session.
2. For a QEMU test, add a `*_SELFTEST`-guarded check that prints `NAME: PASS`, and a
   `make smoke-<name>` target. Copy an existing one.
3. Make it adversarial: assert the refusal, not only the success.
4. Add its control arm: a flag in the Makefile's `DEFECT_FLAGS`, a `smoke-<name>-control` target
   that requires the failure, the pair in `.github/gate-pairs.yml`, and a row in the
   defect-flag table of `docs/BUILDING.md`. Measure the gate red under the flag.
5. Classify the CI job in `.github/ci-gating.yml`, add it here, and cite it in the pull request.
