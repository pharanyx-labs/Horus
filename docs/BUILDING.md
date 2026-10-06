# Building Horus

How to build Horus, run it under QEMU or on a real machine, install it, and choose its build
flags. Horus is x86-64 only and boots through GRUB under BIOS or UEFI.

---

## Requirements

A Linux host with its native x86-64 toolchain; no cross-compiler is needed.

```bash
sudo apt-get install -y --no-install-recommends \
    build-essential binutils make \
    xorriso grub-pc-bin grub-common mtools \
    qemu-system-x86

rustup target add x86_64-unknown-none
```

| Tool | For |
|---|---|
| `gcc`, `binutils`, `make` | The kernel and userspace |
| `rustup` with `x86_64-unknown-none` | The `no_std` security core |
| `xorriso`, `grub-pc-bin`, `grub-common`, `mtools` | The bootable ISO |
| `qemu-system-x86` | Running and testing |
| `swtpm`, `swtpm-tools` *(optional)* | Measured boot and the sealed volume key |
| `python3` *(optional)* | Scripted sessions and PCR recomputation |

CI runs Ubuntu. Other distributions build too, but their toolchains differ in defaults the build
must not depend on: Void Linux's assembler, for one, adds a `.note.gnu.property` section to every
object, so every flat image the build makes strips notes explicitly, and `make smoke-ap-trampoline`
forces the note on so CI tests that case. newlib is not in the tree: `tools/build_newlib.sh`
fetches it (from sourceware.org, falling back to a mirror) and refuses it unless it matches the
pinned SHA-256, on every run, however it arrived.

---

## Building

```bash
make             # kernel.elf
make iso         # horus.iso (implies kernel.elf)
make install.iso # install media: a boot menu offering live boot or install
make clean       # remove build products
make clean-rust  # also clear Cargo's target directory
```

The Rust core is linked with `--whole-archive` so its `#[no_mangle]` FFI symbols survive, then the
C objects, under `linker64.ld`. Kernel flags of note:

```
-ffreestanding -fno-pic -fno-pie -mcmodel=kernel
-mno-sse -mno-mmx -mno-80387        # the kernel never touches FP or SIMD registers
-fstack-protector-strong -mstack-protector-guard=global
-Wall -Wextra -Wformat-security -Werror=vla -Werror=comment
-frandom-seed=horus -fdebug-prefix-map=...   # reproducibility
```

`-Werror=vla` keeps attacker-influenced lengths off the kernel stack, and `-Werror=comment`
catches a `/*` inside a comment, which silently swallows the text after it. The kernel has no
SSE, so `fxsave` and `fxrstor` are inline assembly.

**Shipped programs are stripped** (`--strip-all`) before `tools/mkheadered` wraps them; the
unstripped `userspace/*.pie.elf` is kept for a debugger or `addr2line`. **They link the shared
libc** (`userspace/libc.so`: newlib, its port glue and `libhorus`), which `make
check-shared-objects` (the `shared-objects` CI job) checks is an object the kernel's loader
accepts: only `R_X86_64_RELATIVE` relocations, no undefined symbols, within `SHLIB_MAX_PAGES`, and
one page-aligned writable segment. newlib is built `-fPIC -fvisibility=hidden`, and a change to
those flags forces a rebuild through a stamp kept inside `newlib/install`, the directory CI
caches.

---

## Running under QEMU

```bash
make run         # horus.iso in QEMU, console on this terminal; Ctrl-A X quits
make run-tpm     # the same with an emulated TPM (make run uses one when swtpm is installed)
make run-plain   # the same without a TPM
```

`make run` has no disk attached, so it runs on the in-RAM volume, which is formatted afresh under
a throwaway key on every boot. Log in as `root` / `toor`, or `user` / `password` for an
unprivileged session: those compiled-in accounts exist only on a boot with no installed disk
(`SECURITY.md` S103). A `make run` build includes GNU coreutils, `tcc` and `man` pages as boot
modules (`RUN_MODULES=0` leaves them out). Try `ls /bin`, `ps`, `capview`, `dmesg`, `man hier`,
`tcc -v`, or `help`.

### A persistent disk

```bash
make run-ata        # boot with a persistent volume on horus.img
make run-ata-wipe   # throw the volume away; the next run-ata installs from scratch
./rebuild-and-run.sh   # a clean rebuild, then run-ata
```

`run-ata` attaches `$(HORUS_DISK)` (default `horus.img`, sparse) as the primary IDE drive and
creates it only if it is missing. On a blank disk `init` runs the **installer**: you choose the
target, answer its questions (a root password, an everyday account and its password, whether to
encrypt), review the answers and type the confirmation word. Every later run finds the volume and
goes to a login prompt, where either of the passwords you chose opens it; the compiled-in
accounts no longer work. `run-ata` boots without a TPM on purpose: a volume sealed to one build's
measurements will not open under the next build, which is measured boot working as intended.

### On real hardware

| Image | Built by | What it does |
|---|---|---|
| `install.iso` | `make install.iso` | A menu: **live boot** (the default; opens no disk and writes nothing, `SECURITY.md` S110) or **install** |
| `horus.iso` | `make iso`, and every smoke gate | One entry, no menu: opens the installed volume if the machine has one, runs the installer on a blank disk, and otherwise boots on the in-RAM volume |

```sh
make install.iso
sudo dd if=install.iso of=/dev/sdX bs=4M status=progress conv=fsync   # the device, not a partition
```

Write the file you just built and check its timestamp: every smoke gate rebuilds `horus.iso`
with its own configuration, so a `horus.iso` left in the tree is whichever gate ran last. Both
images are hybrid and boot from a USB stick or optical media under BIOS or UEFI
(`make smoke-boot-media` covers all four combinations).

**After installing,** the disk holds the volume but no bootloader, and the install media's live
entry never opens an installed disk. Start the installed system from a stick holding `horus.iso`
(`make iso`). A disk that boots by itself is roadmap 2.11.

What a real machine needs:

| | Supported |
|---|---|
| Console | VGA text, or a framebuffer (including a 24-bit one under UEFI), in both rings |
| Storage | Legacy IDE and SD/eMMC, including a laptop's soldered eMMC. SATA drives are identified but not read; NVMe is not supported |
| Keyboard | PS/2, or a firmware's PS/2 emulation. There is no USB stack |
| Serial | Optional; the machine works without one |

`PS2_PROBE=1`, `PCI_SCAN_TRACE=1` and `SDHCI_HW_TRACE=1` (below) are instruments for finding out
why a machine does not work, from the screen alone.

---

## Configuration flags

Pass as `make VAR=value`. A change of flag forces a rebuild of what it affects.

| Flag | Default | Effect |
|---|---|---|
| `SMP` | `1` | Several CPUs: MADT enumeration, AP bring-up, per-CPU timers, TLB shootdown, SMT parking. `SMP=0` compiles it out |
| `DEBUG_SHELL` | off | An in-kernel debug shell and a command-execution syscall. **Development only**; it widens the syscall surface |
| `MINIMAL_SECURE` | off | A reduced-surface build for experiments |
| `KEYMAP` | `us` | The keyboard layout compiled in, `us` or `uk`, for both rings. Layouts are rows in `ps2_layouts[]` (`include/ps2_scancode.h`); a key with no ASCII character (UK Shift+3) types nothing |
| `KEYMAP_SHIPPED` | `uk` | The layout `make install.iso` builds, and the one every gate that types on the emulated keyboard uses |
| `RUN_MODULES` | `1` | Whether `make run` adds the coreutils, `tcc` and `man` pages as boot modules |

CI builds `SMP=1`, `SMP=0`, `DEBUG_SHELL=1` and `MINIMAL_SECURE=1`, so all of them keep compiling.

### Interrupt-policy flags

| Flag | Default | Effect |
|---|---|---|
| `IRQ_POLICY_AUDIT` | off | Counts where interrupts are enabled, and adds the `smoke-irq-policy` milestones |
| `IRQ_POLICY_QUIET` | `1` | Keeps the audit off the console; `0` reports each milestone as it passes |

### Self-test builds

Each self-test is a kernel configuration whose test-only code, and test-only syscalls, are absent
from the default build. The `make smoke-*` targets build and run them: `WX_SELFTEST`,
`ELF_SELFTEST`, `PREEMPT_SELFTEST`, `CAPTEST_SELFTEST`, `PROC_SELFTEST`, `NET_SELFTEST` and many
more.

### Booting with a TPM

`make run` boots with an emulated TPM when `swtpm` is installed, because the measured-boot path
is the configuration the security properties are stated over. `NO_TPM=1 make run` forces the plain
boot. Any smoke gate can boot with a TPM by passing `TPM=1` to `tools/smoke_test.sh`, and
`KEEP_TPMSTATE=<dir>` carries one TPM across boots. **`SWTPM_REQUIRED=1` makes a missing `swtpm`
an error rather than a skip**, and CI sets it, so a TPM gate cannot pass by measuring nothing.

### Defect-reproducing builds (control arms)

Each flag here rebuilds a known defect on purpose, or adds an instrument, so that a gate can be
shown to fail. None is ever shipped, and every kernel prints `DEFECT FLAGS: ...` at boot, so a
build carrying one cannot pass for a clean one. **This table is the complete list**:
`tools/check_defect_flags.py` fails the build if a member of the Makefile's `DEFECT_FLAGS` has no
row, if a row names a flag that is not a member, or if nothing in the tree reads a flag. The last
column names the targets that build with the flag; an arm must turn its gate red, and
`.github/gate-pairs.yml` records each pairing.

| Flag | Defect or instrument | Used by |
|---|---|---|
| `IRQ_LEGACY_GLOBAL_LOCK=1` | The pre-1.1 spinlock: one global nesting depth shared by every CPU, incremented non-atomically, with an unconditional `sti` on the outermost release, findings [C-3] and [C-3.1] exactly as they stood. | `smoke-irq-policy` |
| `USER_HEAP_HIGH_BASE=1` | Places every user heap at 8 GiB instead of 16 MiB (above the 4 GiB line) so the 32-bit truncation in the heap syscalls and the pager's region gate ([I-2]) is *reachable* rather than latent. | `smoke-heap64` |
| `EP_QUEUE_SLOTS=1` | A single-slot endpoint queue, pre-[I-5], for the roadmap 1.3 queue and blocking-receive gates. | `smoke-recvblock` |
| `KFAULT_INJECT` | Takes a deliberate supervisor page fault (a read of `0x94`, G-8's address) on a timer tick after `console_server` owns the console. | `smoke-kfault`, `smoke-kfault-legacy` (arm of `smoke-kfault`) |
| `KFAULT_LEGACY_PRINTLN` | Reports a CPL-0 page fault through `println()` as the kernel used to, i.e. into the klog, where nothing on the wire can hear it. | `smoke-kfault-legacy` (arm of `smoke-kfault`) |
| `KFAULT_RECORD_SELFTEST` | Instrument, never shipped: With `PROC_SELFTEST=1`, compiles a hook into `h_yield` that lets a task named `kfaulter` make the kernel read an address of its choosing at CPL 0, and appends a phase to `proctest` that reads the resulting exit record back from ring 3. | `smoke-kfault-record`, `smoke-kfault-record-control` (arm of `smoke-kfault-record`) |
| `EXIT_RECORD_KERNEL_RIP` | A supervisor fault's `rip`, and a kernel-half fault address, written into the task's exit record verbatim, as before S97 ([HORUS-20260920-01]). | `smoke-kfault-record-control` (arm of `smoke-kfault-record`) |
| `EXIT_RECORD_STALE_ON_REUSE` | `create_task` leaves a reused slot's `exit_info` and `wait_exit_info` as the previous occupant left them, as before S98 ([HORUS-20260920-02]). | `smoke-proc-exit-record-control` (arm of `smoke-proc`) |
| `WAIT_TCB_UNCHECKED` | `h_wait` tests no authority again, as before S99 ([HORUS-20260921-01]): any task may wait on any tid and collect its exit record. | `smoke-proc-wait-control` (arm of `smoke-proc`) |
| `APIC_ID_IS_CPU_INDEX` | CPU index equals LAPIC id again, whatever the MADT lists, as before 2026-09-21: a core whose id reaches `MAX_CPUS` gets no slot and parks. | `smoke-smp-topology-sparse-control` (arm of `smoke-smp-topology`) |
| `SMT_SIBLING_BY_INDEX` | `ap_entry64` decides SMT sibling-ness from the dense CPU index instead of the LAPIC id (S101), which parks the wrong threads and schedules siblings. | `smoke-smp-topology-sibling-control` (arm of `smoke-smp-topology`) |
| `SLOT_REUSE_UNCHECKED` | Slot selection by `state == 0` alone, as before 2026-09-21 (S20, [HORUS-20260921-03]): a spawn can reuse a slot whose kernel stack a CPU is still on. | `smoke-kstack-reuse-control` (arm of `smoke-kstack-reuse`) |
| `KSTACK_REUSE_WIDEN=1` | Instrument, never shipped: Holds a dying CPU on the dead task's stack for the first sixteen exits, so a respawn meets the window, and logs each slot the picker skips for it. | `smoke-kstack-reuse`, `smoke-kstack-reuse-control` (arm of `smoke-kstack-reuse`) |
| `DEAD_TASK_RUNS` | A task torn down by another CPU while it runs is handled as before 2026-09-21 ([HORUS-20260921-04]): the tick returns into it, its system calls are dispatched, it can be torn down twice, and no kill IPI is sent. | `smoke-proc-killed-task-control` (arm of `smoke-killed-task`) |
| `TCB_GENERATION_UNCHECKED` | `task_tcb_held` compares a `CAP_TCB` by slot number alone, as before S100 ([HORUS-20260921-02]): a capability for a dead task names whatever reused its slot. | `smoke-proc-tcb-reuse-control` (arm of `smoke-proc`) |
| `PAGE_FREE_UNGUARDED` | `free_user_physical_page` pushes any frame it is handed, with no on-loan test, as before S102 ([HORUS-20260919-01]). | `smoke-pagefree-control` (arm of `smoke-pagefree`) |
| `KDIAG_LEGACY_COM1=1` | The pre-2026-09-03 kernel reporter: markers go to the shared console UART and nowhere else, so ring-3 output can cut one in half between two characters (S81, `docs/LIMITATIONS.md` 2.6c). | `smoke-kdiag-legacy-control` (arm of `smoke-kdiag`) |
| `KDIAG_PORTS_GRANTABLE=1` | Declares `0x3E8`, the kernel's diagnostic channel, among the platform device's grantable ports, so `console_server`'s existing `SYS_IOPORT_GRANT` covers it and ring 3 writes into the kernel's own channel. | `smoke-kdiag-grant-control` (arm of `smoke-kdiag-ioport`) |
| `KDIAG_SPLIT_WIDEN=1` | Instrument, never shipped: each character of a kernel marker waits for the AP timer tick to advance, so a marker spans ~0.5 s of *guest* time on any host and a concurrently-printing task lands inside it. | `smoke-kdiag`, `smoke-kdiag-split-control` (arm of `smoke-kdiag`), `smoke-kdiag-legacy-control` (arm of `smoke-kdiag`), `smoke-kdiag-ioport`, `smoke-kdiag-grant-control` (arm of `smoke-kdiag-ioport`) |
| `KDIAG_NOISE=1` | Instrument, never shipped: `init` talks to the console forever instead of launching a shell, because the ordinary session goes silent almost immediately (the shell blocks on input, `console_server` blocks serving it) and a probe firing on a tick count either lands in that fraction of a second or does not. | `smoke-kdiag`, `smoke-kdiag-split-control` (arm of `smoke-kdiag`), `smoke-kdiag-legacy-control` (arm of `smoke-kdiag`), `smoke-kdiag-ioport`, `smoke-kdiag-grant-control` (arm of `smoke-kdiag-ioport`) |
| `KDIAG_PROBE=1` | Instrument, never shipped: the marker these gates are about: a survivable kernel report emitted `KDIAG_PROBE_COUNT` (8) times, every `KDIAG_PROBE_EVERY` (20) ticks, after the console handover. | `smoke-kdiag`, `smoke-kdiag-split-control` (arm of `smoke-kdiag`), `smoke-kdiag-legacy-control` (arm of `smoke-kdiag`), `smoke-kdiag-ioport`, `smoke-kdiag-grant-control` (arm of `smoke-kdiag-ioport`) |
| `INSTALLER_NO_BACK=1` | Restores the pre-2026-09-10 installer: the questions are a straight pipeline, so `esc` ends the run and every answer already given is discarded instead of stepping back one screen. | `smoke-installer-back` |
| `PS2_PROBE=1` | Instrument, never shipped: paints the PS/2 interrupt count, last scancode and 8042 status in the screen's corner about once a second, to show on real hardware whether anything arrives from the keyboard. | `make iso` |
| `PCI_SCAN_TRACE=1` | Instrument, never shipped: walks all 256 PCI buses and prints every function, naming storage controllers and bridges with their secondary bus. It reads and prints only, and adds nothing to the device table. | `make horus.iso` |
| `PCI_BUS0_ONLY=1` | Restores the PCI enumeration as it stood before 2026-09-12: walk bus 0 and do not follow PCI-to-PCI bridges. | `smoke-sdhci-bridge-control` (arm of `smoke-sdhci-bridge`); `make smoke-sdhci-bridge` must go red under it |
| `IODEV_TABLE_16=1` | Restores the device table as it stood before 2026-09-22: `IODEV_MAX` = 16, which is fourteen PCI functions once index 0 and the platform device are taken. | `smoke-sdhci-crowded-control` (arm of `smoke-sdhci-crowded`); `make smoke-sdhci-crowded` must go red under it |
| `SDHCI_HW_TRACE=1` | Instrument, never shipped: prints an SD/eMMC controller's registers and BARs, puts it in D0 with memory decode on, and reports every failed command, data-phase failure, abandoned flush and long wait. It writes configuration space, so it is never shipped. | None; a hardware diagnostic (`make install.iso SDHCI_HW_TRACE=1`, read the `SDTRACE` lines on the screen) |
| `SDHCI_BAR_HIGHEST=1` | Restores the BAR choice as it stood before 2026-09-22: the highest-based memory region, not the one the SDHCI Slot Information register names. | No gate: QEMU's `sdhci-pci` has one BAR, so both choices pick it; witnessed on the laptop |
| `SDHCI_DIV_V2_ONLY=1` | Restores the 2.00-only clock divider on every host: a power-of-two `N` up to `0x80`, so the slowest clock is base/256. | `smoke-sdhci-v3clock-control` (arm of `smoke-sdhci-v3clock`); `make smoke-sdhci-v3clock` must go red under it |
| `SDHCI_EMBEDDED_NEEDS_CD=1` | Restores the wait for card detect on an embedded slot (capabilities bits 31:30 = `01`), whose soldered device the specification does not require to drive the detect line: a laptop's only disk would read as an empty slot. | No gate: QEMU refuses the embedded slot type; witnessed on the laptop |
| `SDHCI_EMMC_CSD_ONLY=1` | Restores sizing a sector-mode eMMC from its CSD, where a device over 2 GiB states only a placeholder: a 64 GiB eMMC reports 1024 MiB and would be installed onto as a 1 GiB volume. | `smoke-sdhci-emmc` |
| `KDIAG_RING3_PROBE=1` | Instrument, never shipped: Set in both directions of the authority pair; only the kernel's port declaration moves, which is what separates *ring 3 did not write the channel* from *ring 3 cannot*. | `smoke-kdiag-ioport`, `smoke-kdiag-grant-control` (arm of `smoke-kdiag-ioport`) |
| `LIBHORUS_RETRY_ANY=1` | Restores the pre-libhorus IPC retry loop (`while (r < 0) spin_delay();`) which retries every negative return including `SYS_ERR_PERM`. | `smoke-libhorus-retry-control` (arm of `smoke-libhorus`) |
| `LIBHORUS_STRNCPY_UNTERMINATED=1` | Gives `ustrncpy` C `strncpy`'s semantics: terminate only if the source fit. | `smoke-libhorus-strncpy-control` (arm of `smoke-libhorus`) |
| `DEFER_CLEAR_EARLY=1` | Restores the pre-2026-08-21 order in `sched_release_deferred`: clear `percpu_deferred_release[]` (which is the claim auditor's exemption, not just a to-do note) *before* taking the lock that drops the claim. | `smoke-defer-exemption-control` (arm of `smoke-defer-exemption`) |
| `DEFER_WINDOW_WIDEN=1` | Instrument, never shipped: Spins between the deferred-release consume and the claim being dropped, so that window is entered on essentially every release. | `smoke-defer-exemption`, `smoke-defer-exemption-control` (arm of `smoke-defer-exemption`) |
| `SWITCH_COMMIT_EARLY=1` | Restores the pre-2026-08-21 ordering in `task_exit_switch`: commit the switch (claim `next`, install its address space, name it current) and only then validate the resume value. | `smoke-switch-commit-control` (arm of `smoke-switch-commit`) |
| `CLAIM_RELEASE_SKIP=1` | Removes `call sched_release_deferred` from the ISR epilogue, so every CPU that switches tasks reaches ring 3 still owing a release and the claim it holds is orphaned, unschedulable by every CPU including its holder. | `smoke-claim-release-control` (arm of `smoke-claim-release`) |
| `CLAIM_TRACE=1` | Instrument, never shipped: Records which site last claimed each task and from which CPU, prints that provenance in the stale-claim panic, and reports two orphaning events at the instant they happen: a deferred-release slot overwritten while occupied, and a release declined because the claim names another CPU. | Used for measurement; not a gate. Requires `SCHED_INVARIANTS=1` for the auditor it complements. |
| `CLAIM_AUDIT_NO_REREAD=1` | Restores the pre-2026-09-02 claim auditor: accuse on the strength of two sightings alone, without asking whether the mismatch is still there. | `smoke-claim-reread-control` (arm of `smoke-claim-reread`); `make smoke-claim-reread` must go red under it |
| `KSTACK_COLLIDE_IMPERSONATED=1` | Restores the pre-2026-09-02 identity in the stack-collision detector: `get_current_task()`, which reports the impersonated task during an impersonation window, so CPUs that were only impersonating were accused. | `smoke-kstack-imp-control` (arm of `smoke-kstack-imp`); `make smoke-kstack-imp` must go red under it |
| `CLAIM_IMP_TRACE=1` | Instrument, never shipped: on the claim auditor's mismatch path only, re-reads the accused CPU's impersonation state at the moment of accusation and prints it, to test whether the auditor is telling the truth. | Used for measurement; not a gate. Requires `SCHED_INVARIANTS=1` for the auditor it instruments. |
| `ENTER_USER_STEAL_WIDEN=1` | Instrument, never shipped: holds `sched_enter_user`'s entry open until another CPU claims the task it is about to enter, or `ENTER_USER_STEAL_WIDEN_SPINS` expires, so the steal window is entered on demand. | `smoke-enter-user-claim`, `smoke-enter-user-claim-control` (arm of `smoke-enter-user-claim`), `smoke-enter-user-collide-control` (arm of `smoke-enter-user-claim`) |
| `ENTER_USER_PUBLISH_EARLY=1` | The pre-2026-09-03 ordering at the one live launch site (`spawn_initial_userspace_init`, `kshell.c`): publish the task as schedulable, arm preemption, and only then go and claim it. | `smoke-enter-user-claim-control` (arm of `smoke-enter-user-claim`), `smoke-enter-user-collide-control` (arm of `smoke-enter-user-claim`); `make smoke-enter-user-claim` must go red under it |
| `ENTER_USER_CLAIM_UNCHECKED=1` | Removes the guard in `enter_user_impl` entirely, both the foreign-claim test and the still-schedulable test. | `smoke-enter-user-collide-control` (arm of `smoke-enter-user-claim`) |
| `STORAGE_FORMAT_WEDGE=1` | Spins forever halfway through the format's metadata region, so the disk image is provably being written and then stops. | `smoke-installer-wedge-control` (arm of `smoke-installer-slowdisk`) |
| `DEFAULT_ACCOUNTS_ON_DISK=1` | Keeps the compiled-in `root`/`toor` and `user`/`password` on a machine with a disk, which is the kernel before 2026-09-24: an installed machine accepted the compiled-in root password until its volume was unlocked. | `smoke-installer-defaults-control` (arm of `smoke-installer`) |
| `STORAGE_FORMAT_SIZE_IGNORED=1` | Accepts and bounds the volume size an installer asked for, then lays the volume over the whole device anyway. | `smoke-installer-sized-control` (arm of `smoke-installer-sized`) |
| `INSTALLER_FAIL_NO_SCREEN=1` | Restores the installer's failure path as it stood before 2026-09-25: the reason goes to the wire as `INSTALLER: FAIL ...` and the program exits at once, with no failure screen and no wait, so a machine with no serial port shows the operator nothing and init's next line covers the screen. | `smoke-installer-failed-control` (arm of `smoke-installer-failed`) |
| `USERS_PERSIST_COMPILED_IN=1` | Lets `users_persist` write an account table that still holds a compiled-in password, as the kernel did before 2026-09-25: a live boot whose login opens an installed volume with no table seeds it with `root`/`toor` and `user`/`password`. | `smoke-live-no-seed-control` (arm of `smoke-live-no-seed`) |
| `LIVE_OPENS_VOLUME=1` | Restores the kernel before 2026-09-26, in which a live boot mounted the installed volume as its store and a login whose password opened a key slot unlocked it, so the installed root logged in on a live boot. | `smoke-live-no-seed`, `smoke-live-locked-control` (arm of `smoke-live-locked`) |
| `INSTALLER_STOP_AFTER_FORMAT=1` | Instrument, never shipped: The installer stops between the format and the first account write, as a power cut or a `SYS_PASSWD` failure there would, leaving a volume that opens with the chosen password and has no account table. | `smoke-live-no-seed` |
| `SHLIB_INHERIT_ANY_IMAGE=1` | A spawn passes the shared libc's text capabilities to the child whether or not the child's image asked for them (`DT_NEEDED "libc.so"`), so the library's authority spreads to every child of a holder, the widening D1 in `docs/design/shared-libc.md` rules out. | `smoke-shlib-inherit-image-control` (arm of `smoke-shlib-inherit`) |
| `SHLIB_DATA_TEMPLATE_SHARED=1` | Maps the library's writable template into every task instead of a private copy, so one program's errno, stdio buffers and heap state are the next program's starting state. | `smoke-shlib-inherit-data-control` (arm of `smoke-shlib-inherit`) |
| `SHLIB_EXEC_NO_DATA=1` | Exec forgets the library's data: the new image asks for the library and holds the text, and is given no data, so its bind is refused. | `smoke-shlib-inherit-exec-control` (arm of `smoke-shlib-inherit`) |
| `SHLIB_TEMPLATE_UNPINNED=1` | The library's frames are not roots of the object collector, which is how the tree stood until 2026-09-25: the data template, which no capability names, is collected, zeroed and its name released when the first program to exit after boot exits. | `smoke-shlib-inherit-pin-control` (arm of `smoke-shlib-inherit`) |
| `MEM_SEAL_KEEPS_WRITE=1` | `SYS_MEM_SEAL` marks the page sealed and leaves `PAGE_WRITE` on it: the bookkeeping of a seal with none of its effect, so the next write lands. | `smoke-mem-seal-write-control` (arm of `smoke-mem-seal`) |
| `MEM_SEAL_ANY_ADDRESS=1` | Removes `SYS_MEM_SEAL`'s image-window check, so a task can seal its heap or stack and the call reaches every present user page rather than the program's own image. | `smoke-mem-seal-window-control` (arm of `smoke-mem-seal`) |
| `DYNLINK_ABI_UNCHECKED=1` | crt0's linker does not compare the library's table hash with the one the program was built against, so a program runs against a library it was not built for and a name that moved resolves to whatever is there now. | `smoke-shlib-link-abi-control` (arm of `smoke-shlib-link`) |
| `DYNLINK_UNKNOWN_ZERO=1` | A name the library does not export resolves to zero instead of refusing the program, which then runs until it first uses the name. | `smoke-shlib-link-unknown-control` (arm of `smoke-shlib-link`) |
| `DYNLINK_NO_SEAL=1` | crt0's linker fills the program's table of library addresses and leaves it writable. | `smoke-shlib-link-seal-control` (arm of `smoke-shlib-link`) |
| `COREUTILS_STATIC_LIBC=1` | Links every coreutil the way it was before step 4 of `docs/design/shared-libc.md`, newlib inside each image. | `smoke-coreutils-shared-control` (arm of `smoke-coreutils-shared`) |
| `STORAGE_UNSEALED_IGNORED=1` | Drops an operator's choice not to encrypt: the volume is sealed to the password as usual and the boot calls it encrypted. | `smoke-installer-unsealed-control` (arm of `smoke-installer-unsealed`) |
| `STORAGE_UNSEALED_ALWAYS=1` | The dangerous direction: every persistent volume is written unsealed whatever was chosen, so an operator who asked for encryption gets a disk anyone can read. | `smoke-installer-sealed-control` (arm of `smoke-installer`) |
| `RESUME_RSP_INJECT=1` | Forces the dispatcher's resume `%rsp` to a bogus value once after the console handover (the value is `RESUME_RSP_INJECT_VALUE`), so the floor guard in `idt.c` is gated rather than waited for. | `smoke-resume-guard`, `smoke-resume-guard-negative`, `smoke-resume-guard-negative-control` (arm of `smoke-resume-guard-negative`), `smoke-resume-guard-preclaim` (arm of `smoke-resume-guard`), `smoke-resume-guard-legacy` (arm of `smoke-resume-guard`), `smoke-resume-guard-nofloor` (arm of `smoke-resume-guard`) |
| `RESUME_RSP_INJECT_PRECLAIM=1` | The same injection, but taken with another CPU's fatal exception claim already held; the state a real `FATAL` leaves behind, and the exact state of the 2026-08-13 capture, where cpu 3 halted holding it. | `smoke-resume-guard-preclaim` (arm of `smoke-resume-guard`), `smoke-resume-guard-legacy` (arm of `smoke-resume-guard`) |
| `WAL_CRASHTEST=1` | Instrument, never shipped: Boot 1 commits a write and halts before applying it; boot 2 replays the committed transaction at mount. | `smoke-fs-wal`, `smoke-fs-wal-flush`, `smoke-fs-wal-flush-control` (arm of `smoke-fs-wal-flush`), `smoke-fs-wal-order`, `smoke-fs-wal-order-control` (arm of `smoke-fs-wal-order`) |
| `RESUME_GUARD_LEGACY_FATAL=1` | Restores the resume-`%rsp` floor guard's pre-fix `kfault_begin(1)`/`kfault_end(1)` bracket, so the report is swallowed by a permanent panic claim another CPU already holds. | `smoke-resume-guard-legacy` (arm of `smoke-resume-guard`) |
| `RESUME_GUARD_DISABLE=1` | Compiles the floor guard out entirely; the kernel instead faults at `0x94` on `out->cs`, which is [G-8]'s original datapoint reproduced deliberately. | `smoke-resume-guard-nofloor` (arm of `smoke-resume-guard`) |
| `WAL_NO_FLUSH=1` | Compiles out every write-ahead-journal durability barrier, restoring the pre-2026-08-16 kernel in which the ATA driver had no `FLUSH CACHE` opcode and the journal's ordering held only because the emulator persisted each write anyway ([I-10]). | `smoke-fs-wal-flush-control` (arm of `smoke-fs-wal-flush`), `smoke-fs-wal-order-control` (arm of `smoke-fs-wal-order`) |
| `KSTACK_RELEASE_EARLY=1` | Restores the pre-2026-08-17 release site: a switch path publishes the outgoing task as claimable while the CPU making the switch still has ~30 instructions of ISR epilogue to run on that task's kernel stack ([G-8]). | `smoke-kstack-race-control` (arm of `smoke-kstack-race`) |
| `KSTACK_RACE_WIDEN=1` | Instrument, never shipped: Spins after the hand-over and before the ISR epilogue leaves the stack, so the [G-8] window is entered on essentially every switch instead of at its natural 2–3% per boot. | `smoke-kstack-race`, `smoke-kstack-race-control` (arm of `smoke-kstack-race`) |
| `KSTACK0_SHARED_PARK=1` | Restores the pre-2026-08-17 park target: when a task dies with nothing else runnable, all three fallbacks in `idt.c` resume the CPU on `tasks[0].kernel_stack_top`: one stack shared by every CPU that takes the path ([G-8], second path). | `smoke-kstack-park-control` (arm of `smoke-kstack-park`) |
| `KSTACK0_PARK_TRACE=1` | Instrument, never shipped: prints a line each time a CPU parks in the ring-0 idle/reaper loop. | `smoke-kstack-park-control` (arm of `smoke-kstack-park`) |
| `RESUME_GUARD_FLOOR_ONLY=1` | Restores the pre-2026-08-18 resume-`%rsp` predicate, `rsp < 0xFFFF800000000000ULL`, a floor with no ceiling, which catches a returned `0`, `1` or `4` and misses every small *negative* value, since `-7` is `0xFFFFFFFFFFFFFFF9` and sits above the floor. | `smoke-resume-guard-negative-control` (arm of `smoke-resume-guard-negative`) |
| `RESUME_GUARD_BSS_ONLY=1` | Restores the bound the ceiling first shipped with: `[__bss_start, __bss_end)` alone, on the premise that every 64-bit kernel stack is a `.bss` array. | `smoke-resume-guard-ist-control` (arm of `smoke-resume-guard-ist`) |
| `RESUME_RSP_INJECT_VALUE=<v>` | Instrument, never shipped: chooses which bogus resume `%rsp` `RESUME_RSP_INJECT` forces. | `smoke-resume-guard`, `smoke-resume-guard-negative` |
| `CR3_RECLAIM_UNGUARDED=1` | Restores the pre-2026-08-17 slot reclaim in `create_user_pagedir`: free the previous occupant's page tables unconditionally, on the uniprocessor argument that the caller being on the kernel CR3 means no CPU is walking the tree. | `smoke-cr3-reclaim-control` |
| `EXEC_REENTER_GLOBAL=1` | Restores the pre-2026-08-17 exec hand-off: ONE shared `int` naming the task whose exec re-entry is pending, consumed on the exit of every syscall on every CPU with no test that the exec belonged to that CPU. | `smoke-exec-reenter-control` |
| `SPAWN_OWNER_UNCHECKED=1` | Restores the pre-2026-08-18 consume of the staged program image: any task may spawn whatever image is armed, whoever armed it. | `smoke-spawn-owner-control` (arm of `smoke-spawn-owner`) |
| `SPAWN_STAGE_UNSERIALISED=1` | Restores the pre-2026-08-18 spawn path: no lock over the arm → consume window on the process-wide staging (the ELF staging buffer, the armed header, the staged argv), so two CPUs interleave through it ([G-10]). | No gate: no current workload reaches the window twice, so the arm cannot fail; kept buildable for when one does |
| `SPAWN_STAGE_WIDEN=1` | Instrument, never shipped: holds each of the first `SPAWN_STAGE_WIDEN_WINDOWS` (24) staging windows open for `SPAWN_STAGE_WIDEN_SPINS` (12,000,000) `pause` iterations, so an overlap happens if one is possible at all. | Used with `SPAWN_STAGE_TRACE=1` for measurement; not a gate |
| `SPAWN_STAGE_TRACE=1` | Instrument, never shipped: This is the *reachability* instrument: a serialised build with zero incidents says nothing unless the window was entered twice, and this is what established that in this tree it never is. | Used for the measurement in `TESTS.md`; not a gate |
| `REPRO_SHA_UNCHECKED=1` | Restores the pre-2026-08-19 build-hash recording step and the goal list that made it silent: `reproducible-build` builds `all` (which is `kernel.elf` alone) and records with `sha256sum kernel.elf horus.iso > .build.sha 2>/dev/null \|\| true`. | `smoke-repro-sha-control` (arm of `smoke-repro-sha`) |
| `AP_TRAMPOLINE_FLAT_LINK=1` | Restores the pre-2026-09-19 AP trampoline link, `ld -m elf_i386 -Ttext=0x8000 --oformat binary`, and forces the assembler's `.note.gnu.property` on with `-Wa,-mx86-used-note=yes`. | `smoke-ap-trampoline-control` (arm of `smoke-ap-trampoline`); `make smoke-ap-trampoline` must go red under it |
| `BOOT_MODULE_RESERVE_UNCHECKED=1` | Removes `boot_module_placement_check`: a boot module is recorded and verified wherever GRUB put it and nothing asks whether the kernel is about to write there. | `smoke-boot-module-reverify-control` (arm of `smoke-boot-module-reserve`), `smoke-boot-module-image-control` (arm of `smoke-boot-module-reserve`); `make smoke-boot-module-reserve` must go red under it |
| `POOL_RESERVE_FIXED_BASE=1` | Puts the page pool's base reserves (loader staging, the RAM vdisk, the untyped arena) back at `USER_PHYS_BASE` whatever GRUB loaded there, the layout before 2026-09-19. | `smoke-boot-module-reserve-control` (arm of `smoke-boot-module-reserve`), `smoke-boot-module-reverify-control` (arm of `smoke-boot-module-reserve`); `make smoke-boot-module-reserve` must go red under it |
| `BOOT_MODULE_IMAGE_PROBE=1` | Instrument, never shipped: records a synthetic boot module over the first page of the kernel's `.text` before `boot_module_placement_check` runs, because GRUB never places a real module inside the image and the image half of the check could not otherwise be reached. | `smoke-boot-module-reserve`, `smoke-boot-module-image-control` (arm of `smoke-boot-module-reserve`) |
| `KSP_GUARD_ALWAYS=1` | Makes `ksp_is_bogus()` reject every stack pointer: the false-positive mutation that every inject-and-look arm passes happily. | `smoke-ksp-guard`; `make smoke-ksp-guard` must go red under it |
| `BUILD_FLAGS_UNSTAMPED=1` | Restores the pre-2026-08-21 build, in which a `-D` flag was invisible to make: objects do not depend on the flag strings, so `make FLAG=1` followed by `make` recompiles nothing and the flag silently survives. | `smoke-defect-flags-rebuild-control` (arm of `smoke-defect-flags-rebuild`) |
| `KSP_GUARD_INJECT=1` | Forges `-7` (the exact value [G-9] was seen to hand back) as the return of `task_exit_switch`, the producer the `PROC_SELFTEST` workload drives. | `smoke-defect-flags-control` (arm of `smoke-defect-flags`), `smoke-defect-flags-rebuild`, `smoke-defect-flags-rebuild-control` (arm of `smoke-defect-flags-rebuild`), `smoke-ksp-guard-control` (arm of `smoke-ksp-guard`), `smoke-switch-commit`, `smoke-switch-commit-control` (arm of `smoke-switch-commit`) |
| `SYSCALL_COVERAGE=1` | Instrument, never shipped: The reachability instrument for test coverage, the same role `SPAWN_STAGE_TRACE` plays for the staging window. | `smoke-syscall-coverage`, `smoke-syscall-coverage-control` (arm of `smoke-syscall-coverage`), `smoke-passwd-probe-exec19-control` (arm of `smoke-passwd-probe`) |
| `SYSCALL_PTR_TRUNC32=1` | Restores the pre-2026-08-20 `sys_dmesg` / `sys_audit_digest` wrappers, which passed their buffer as `(uint32_t)(unsigned long)ptr`: so the kernel received the low 32 bits of an address the caller never named and resolved it in the caller's own address space (issue #176). | `smoke-auditprobe-control` (arm of `smoke-auditprobe`), `smoke-klog-forge-abi-control` (arm of `smoke-klog-forge`); `make smoke-auditprobe` must go red under it |
| `VFS_FIRST_MATCH=1` | Makes `hvfs_resolve` return the first matching mount instead of the longest-prefix one (roadmap 2.4). | `smoke-vfs-prefix-control` (arm of `smoke-vfs`) |
| `VFS_MOUNT_UNGATED=1` | Removes `hvfs_mount`'s capability probe, so a prefix string alone installs a mount over a slot holding nothing, and every path under it is addressed to an empty slot one failed operation at a time. | `smoke-vfs-mount-control` (arm of `smoke-vfs`) |
| `RAMFS_SLOT3_GATE=1` | Restores the four pre-2026-08-22 gates into the in-kernel ramfs (`SYS_OPEN`, syscall 15 (create), syscall 16 (list) and `SYS_READ`'s `fd >= 3` branch) each of which authorised on cspace slot 3 with `SC_ANYTYPE` ([H-3]). | `smoke-passwd-probe-control` (arm of `smoke-passwd-probe`); `make smoke-passwd-probe` must go red under it |
| `FRAME_INDEX_UNCHECKED=1` | Makes `CAP_FRAME.object` a physical address that `SYS_MAP_FRAME` maps directly, instead of an index bounds-checked against the frame table; the shortcut a frame-mapping syscall invites ([F-2.1], roadmap 2.1). | `smoke-frame-index-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `FRAME_RIGHTS_UNCHECKED=1` | Asks `cap_lookup` for no rights at all in `SYS_MAP_FRAME`, so any live `CAP_FRAME` satisfies it and the PTE is built from the request: a `READ`-only delegate obtains a writable mapping and its write lands. | `smoke-frame-rights-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `FRAME_REGION_NO_ROLLBACK=1` | Removes the unwind from `SYS_MAP_REGION`, so a run that fails part-way keeps the pages it already mapped and still reports the failure. | `smoke-frame-region-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `FRAME_REGION_ROLLBACK_WIDE=1` | The unwind of a failed region map walks the whole requested range instead of the pages it installed, so it tears down the pre-existing mapping that caused the refusal. | `smoke-frame-region-wide-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `FRAME_PAGES_SAME_PHYS=1` | Advances the virtual cursor and not the physical one when mapping a sized frame, so every page of the run aliases the frame's first page. | `smoke-frame-pages-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `FRAME_INFO_BY_INDEX=1` | Makes `SYS_FRAME_PAGES` read its argument as a frame index rather than a cspace slot, so no capability is consulted at all. | `smoke-frame-info-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `COW_ARENA_UNGUARDED=1` | Removes the guard at the top of `cow_break_pte`, so a copy-on-write break proceeds on a page belonging to a kernel object. | `smoke-nzcow-arena-control` (arm of `smoke-nzcow`); `make smoke-nzcow` must go red under it |
| `FORK_SHARE_WRITABLE=1` | Clones a forked child's address space without downgrading the leaves: both trees point at the same frames, both still writable, neither marked `PAGE_COW`. | `smoke-fork-share-control` (arm of `smoke-fork`); `make smoke-fork` must go red under it |
| `FORK_ARENA_UNCHECKED=1` | Removes `clone_user_aspace`'s refusal to clone a PTE whose frame belongs to the untyped arena, so forking with a `CAP_FRAME` mapped succeeds. | `smoke-fork-arena-control` (arm of `smoke-fork`); `make smoke-fork` must go red under it |
| `FORK_CSPACE_FLAT_COPY=1` | Copies the parent's capabilities into the forked child verbatim (same serial, badge and generation) instead of deriving them. | `smoke-fork-cspace-flat-control` (arm of `smoke-fork`); `make smoke-fork` must go red under it |
| `FORK_CSPACE_ORPHAN_COPY=1` | Gives each copy a fresh serial (so the flat-copy defect above is absent) but leaves `badge` as the source's, so the copy is not a child of the parent's capability in the derivation tree. | `smoke-fork-cspace-orphan-control` (arm of `smoke-fork`); `make smoke-fork` must go red under it |
| `EXEC_RESET_CSPACE=1` | Makes `SYS_EXEC_NAMED` / `SYS_EXEC_IMAGE` discard every capability at or above `KERNEL_RESERVED_CAPS`, so the execed image keeps only the birth endowment `create_task` installs. | `smoke-execprobe-reset-control` (arm of `smoke-execprobe`), `smoke-forkexec-reset-control` (arm of `smoke-forkexec`); `make smoke-forkexec` must go red under it |
| `EXEC_ROOT_CSPACE=1` | Keeps every capability across the exec but re-mints each as a root: fresh serial, no badge. | `smoke-execprobe-root-control` (arm of `smoke-execprobe`), `smoke-forkexec-root-control` (arm of `smoke-forkexec`); `make smoke-forkexec` must go red under it |
| `FPU_NO_RESTORE=1` | Drops the `fxrstor` on the way back to ring 3, so a task inherits whatever the previously-running task left in the physical xmm/x87 registers. | `smoke-fpu-leak-control` (arm of `smoke-fpu`); `make smoke-fpu` must go red under it |
| `FPU_NO_SAVE=1` | Drops the `fxsave` on the way out of ring 3, so a task's register file is never captured and it is handed a stale image on its next entry. | `smoke-fpu-save-control` (arm of `smoke-fpu`); `make smoke-fpu` must go red under it |
| `IO_DEVICE_OBJECT_UNCHECKED=1` | `SYS_MAP_PHYS` ignores the capability's `object` and tests the requested frame against the old compiled-in VGA allowlist, so any device capability maps the console's framebuffer. | `smoke-devcap-object-control` (arm of `smoke-devcap`); `make smoke-devcap` must go red under it |
| `IO_DEVICE_PORTS_GLOBAL=1` | The port half: `SYS_IOPORT_GRANT` loads the TSS I/O bitmap with the platform device's ports whatever device the capability named, which is the pre-2026-08-28 single boot-time console allowlist. | `smoke-devcap-ports-control` (arm of `smoke-devcap`); `make smoke-devcap` must go red under it |
| `IO_DEVICE_IRQ_UNCHECKED=1` | The interrupt half: `SYS_IRQ_REGISTER` does not test the line against the named device, so a NIC driver subscribes to the console's keyboard IRQ. | `smoke-devcap-irq-control` (arm of `smoke-devcap`); `make smoke-devcap` must go red under it |
| `IO_DEVICE_CAP_UNCHECKED=1` | Removes the capability lookup from `iodev_from_slot` altogether, so every caller of a device syscall resolves to the platform device while holding nothing. | `smoke-captest-devcap-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `NET_IOMMU_NO_MAP=1` | `netd` asks `SYS_DMA_ADDR` for its frames' addresses with `DMA_ADDR_NO_MAP`, so every capability check still runs and every address is still correct, but no device mapping is installed. | `smoke-net-iommu-control` (arm of `smoke-net`); `make smoke-net` must go red under it |
| `IRQ_NO_MASK_ON_FIRE=1` | A registered interrupt line is left unmasked when it fires: what a kernel does if it treats an EOI as the end of the story. | `smoke-net-mask-control` (arm of `smoke-net`), `smoke-net-irq-storm-control` (arm of `smoke-net`) |
| `POLL_NOTIFY_UNGATED=1` | `SYS_POLL_NOTIFY` with no capability check, so the slot is used as a raw notification index and any task consumes any other task's badges, finding [C-2] arriving in a new syscall, which is what a "convenience" variant invites. | `smoke-captest-poll-notify-control` (arm of `smoke-captest`) |
| `MSI_VECTOR_FROM_USER=1` | `SYS_MSI_REGISTER` honours a vector the CALLER supplies; the shape this syscall takes the moment anyone decides a driver "knows best" which vector it wants. | `smoke-net-msi-vector-control` (arm of `smoke-net`) |
| `MSIX_TABLE_MAPPABLE=1` | Drops the refusal on the page holding a device's MSI-X vector table, so a driver maps it like any other register page and writes its own interrupt vector; no syscall, no capability check, nothing to gate. | `smoke-net-msix-table-control` (arm of `smoke-net`) |
| `SHLIB_TEXT_WRITABLE=1` | Mints the shared library's frame capability with the write right, so a task can map the library writable and patch code another task executes. | `smoke-shlib-writable-control` (arm of `smoke-shlib`) |
| `SHLIB_DATA_SHARED=1` | Endows every task with the same frame for the shared library's writable data, instead of a private copy carved from the template. | `smoke-shlib-data-shared-control` (arm of `smoke-shlib`) |
| `SHLIB_DATA_UNINITIALISED=1` | Gives each task a private data frame but zero-fills it rather than copying the library's initial image. | `smoke-shlib-data-init-control` (arm of `smoke-shlib`) |
| `SHLIB_BASE_FIXED=1` | Restores the compiled-in shared-library base, so the library loads at the same address every boot. | `smoke-shlib-aslr-control` (arm of `smoke-shlib-aslr`) |
| `SHLIB_INFO_UNGATED=1` | `SYS_SHLIB_INFO` with no capability test at all, so the library's base is ambient information: an attacker with execution in any task can ask where the shared code is, and the randomisation protects nothing. | `smoke-shlib-info-control` (arm of `smoke-shlib`) |
| `SHLIB_INFO_TYPE_ONLY=1` | The type checked and the object not, so any `CAP_FRAME` answers, including the caller's own private copy of the library's writable page, which it legitimately holds and which says nothing about holding the code. | `smoke-shlib-info-object-control` (arm of `smoke-shlib`) |
| `CSPACE_RELEASE_BEFORE_PIPES=1` | Moves the cspace release ahead of `pipe_close_task_ends`, so a dying task's `CAP_PIPE` entries are gone before anything looks for them, no end is unreffed, and the peer never sees EOF. | `smoke-pipe-cspace-order-control` (arm of `smoke-pipe`); `make smoke-pipe` must go red under it |
| `INIT_PROVISION_NO_UNTYPED=1` | `init` retypes its server's endpoint from a slot holding no `CAP_UNTYPED`: the state `docs/ROADMAP.md` 2.4 asserted `init` was permanently in. | `smoke-init-provision-control` (arm of `smoke-init-provision`); `make smoke-init-provision` must go red under it |
| `UNTYPED_SPLIT_FREE_BYTES=1` | `SYS_UNTYPED_SPLIT` hands out a sub-region without advancing the parent's watermark, so the split mints memory rather than spending it and two capabilities name overlapping bytes, the type-confusion the bump discipline exists to forbid, reached through the syscall meant to *spend* budget. | `smoke-captest-split-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `SPAWN_SLOT3_DECOY_GATE=1` | Restores the pre-2026-08-30 gate on the task-creating syscalls: cspace slot 3 with `SC_ANYTYPE`, which every task satisfies, so any task can spawn and the child is charged to the kernel reserve. | `smoke-proc-spawn-decoy-control` (arm of `smoke-proc`); `make smoke-proc` must go red under it |
| `CSPACE_KEEP_ON_TEARDOWN=1` | Restores the pre-2026-08-30 `task_teardown`, which released every device resource a task held and left its capabilities in its cspace until the slot was next used, which may be never. | `smoke-cspace-release-control` (arm of `smoke-cspace-release`); `make smoke-cspace-release` must go red under it |
| `CAP_LOOKUP_ROOT_FALLBACK=1` | Restores the pre-2026-08-30 `else` in `cap_lookup`, so a task with no cspace resolves every slot against the primordial root cnode: `CAP_TCB` over task 0, the console, the kernel log, the user database, the object store. | `smoke-cap-lookup-control` (arm of `smoke-cap-lookup`); `make smoke-cap-lookup` must go red under it |
| `CAP_LOOKUP_RANGE_FALLBACK=1` | The out-of-range half of that same `else`, on its own: the caller keeps its cspace, and only a slot past the end of it resolves in the root cnode, the identical escalation reached by arithmetic rather than by a null pointer, needing no missing cspace at all. | `smoke-cap-lookup-range-control` (arm of `smoke-cap-lookup`); `make smoke-cap-lookup` must go red under it |
| `CAP_LOOKUP_TYPE_UNCHECKED=1` | The pre-2026-08-31 resolver: `cap_lookup` returns whatever the slot holds and leaves the TYPE to each of its ~40 callers. | `smoke-captest-lookup-type-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `KEYSLOT_REMOVE_NOOP=1` | `storage_keyslot_remove` reports success and leaves the wrap openable, so a revoked password still opens the volume (S61). | `smoke-keyslots-control` (arm of `smoke-keyslots`); `make smoke-keyslots` must go red under it |
| `META_CACHE_TINY=1` | Instrument, never shipped: Drops the bounded metadata cache from 32 lines to 2, so a working set of a few hundred blocks provably exceeds it and eviction is forced rather than hoped for. | `smoke-meta-evict`, `smoke-meta-evict-control` (arm of `smoke-meta-evict`) |
| `META_CACHE_NO_WRITEBACK=1` | Removes the metadata cache's write-back entirely: `journal_commit` does not flush dirty lines and eviction drops them, so a metadata update a committed transaction promised never reaches the disk (failure modes E1 and E4 in `docs/design/meta-cache-merkle.md`, S65). | `smoke-meta-crash-control` (arm of `smoke-meta-crash`); `make smoke-meta-crash` must go red under it |
| `META_CACHE_WB_OUTSIDE_TXN=1` | Keeps the write-back and moves it past the end of `journal_commit`, where `do_block_write` goes straight home instead of into the journal. | `smoke-meta-crash-txn-control` (arm of `smoke-meta-crash`); `make smoke-meta-crash` must go red under it |
| `META_CACHE_EVICT_NOWB=1` | Removes only the eviction write-back, leaving the commit flush in place. | `smoke-meta-evict-control` (arm of `smoke-meta-evict`); `make smoke-meta-evict` must go red under it |
| `MERKLE_NODE_TRUST_CACHED=1` | Sets a Merkle node line's `verified` flag where the line is filled rather than where it is checked, so residency in the node cache becomes the trust criterion instead of a path from the root (failure mode R1, S66). | `smoke-merkle-replay-control` (arm of `smoke-merkle-replay`); `make smoke-merkle-replay` must go red under it |
| `MERKLE_SKIP_PARENT_BIND=1` | Checks a metadata block's hash against the level-0 node that records it and does not place that node under the root. | `smoke-merkle-parent-bind-control` (arm of `smoke-merkle-replay`); `make smoke-merkle-replay` must go red under it |
| `FSCK_SHALLOW_REFS=1` | Restores the pre-2026-08-31 `storage_fsck_pass` reference walk: `direct[]` and the single-indirect block, and nothing below. | `smoke-fsck-refs-control` (arm of `smoke-fsck-refs`); `make smoke-fsck-refs` must go red under it |
| `ROLLBACK_ANCHOR_IGNORE=1` | Drops the comparison of `sb.rollback_gen` against the TPM NV counter, so a volume older than the machine mounts and serves the state it held when the disk was imaged (S70). | `smoke-rollback-control` (arm of `smoke-rollback`); `make smoke-rollback` must go red under it |
| `ATA_READY_ERR_ONLY=1` | Restores the pre-2026-09-01 transfer rule: ERR alone decides. | `smoke-ata-ready-control` (arm of `smoke-ata-ready`); `make smoke-ata-ready` must go red under it |
| `ALLOC_NO_HINT=1` | Restores the pre-2026-09-01 block allocator: every scan starts at data-bitmap block 0, so a volume whose first N bitmap blocks are full costs N+1 reads per allocation. | `smoke-alloc-hint-control` (arm of `smoke-alloc-hint`); `make smoke-alloc-hint` must go red under it |
| `STORAGE_MOUNT_ANY_SIZE=1` | Drops the check that a superblock's `total_blocks` fits the device it is on, so a volume formatted on a larger disk mounts on a smaller one, part of a filesystem served as whole, with the data region's tail simply not there (S68). | `smoke-fs-shrink-control` (arm of `smoke-fs-shrink`); `make smoke-fs-shrink` must go red under it |
| `VDISK_TOTAL_UNBOUNDED=1` | Restores the pre-2026-08-31 RAM vdisk: `total_blocks = BLOCKS_PER_DISK` over a `VDISK_BLOCKS`-sized reservation, and no second bound against the backing store. | `smoke-vdisk-bound-control` (arm of `smoke-vdisk-bound`); `make smoke-vdisk-bound` must go red under it |
| `TUI_NO_DAMAGE_DIFF=1` | `tui_flush` repaints every cell instead of only the changed ones. | `smoke-tui-diff-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_CLAMP_OFF=1` | Removes the single bounds check every TUI drawing call funnels through, so a write past the last row or column lands in the cell buffers. | `smoke-tui-clamp-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `INSTALLER_NO_CONFIRM=1` | The installer reads the typed confirmation word and then does not compare it, so the install proceeds whatever was typed, including nothing (S73). | `smoke-installer-refuse-control` (arm of `smoke-installer-refuse`); `make smoke-installer-refuse` must go red under it |
| `CONSOLE_TIMESTAMPS_LEGACY=1` | The pre-2026-09-06 console: a line carries a `[ S.uuuuuu] ` prefix only if its author remembered to ask for one, which roughly half the boot log did not, ` [ OK ] ...`, and every ring-3 line arriving through `SYS_WRITE`, which had no way to ask at all. | `smoke-console-timestamps-control` (arm of `smoke-console-timestamps`); `make smoke-console-timestamps` must go red under it |
| `CLOCK_EPOCH_FROM_FIRST_TICK=1` | Restores the pre-2026-09-06 `SYS_CLOCK_GETTIME` epoch: time counted from the first timer interrupt rather than from boot, which is whatever the machine spent getting there: 1.07 s on the boot measured on 2026-09-06, nearly all of it SMP bring-up. | `smoke-console-timestamps-epoch-control` (arm of `smoke-console-timestamps`); `make smoke-console-timestamps` must go red under it |
| `STORE_LOCKED_UNCHECKED=1` | The pre-2026-09-01 object-store handlers, which tested `mfs->mounted` and not `mfs->unlocked` (S74). | `smoke-installer-provision-control` (arm of `smoke-installer-provision`); `make smoke-installer-provision` must go red under it |
| `PASSWD_TARGET_IGNORED=1` | The pre-2026-09-01 shell `passwd`, which MATCHED an argument (`strncmp(cmd, "passwd ", 7)`) and then dropped it: every call went to `sys_getuid()` (S75). | `smoke-passwd-target-control` (arm of `smoke-passwd-target`); `make smoke-passwd-target` must go red under it |
| `PASSWD_NO_KEYSLOT=1` | The pre-2026-09-02 `do_passwd`: an administrator sets another account's password and no key slot is granted (S76), so that password opens the account and not the volume. | `smoke-installer-accounts-control` (arm of `smoke-installer-accounts`); `make smoke-installer-accounts` must go red under it |
| `SHELL_FS_ERR_FLAT=1` | The pre-2026-09-02 shell, which had the `fs_server`'s rc in its hand and printed a guess: one sentence for every outcome of every file command, `failed (name exists or server not running)`, naming two causes and not the one that fires most often. | `smoke-session-fs-err-control` (arm of `smoke-session`); `make smoke-session` must go red under it |
| `USERLIST_UNGATED=1` | Removes `SYS_USERLIST`'s `CAP_USER` test, so any ring-3 task reads the account table (S78). | `smoke-captest-userlist-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `HOME_DIR_ROOT_OWNED=1` | `fs_server` creates `/home/<name>` and then does not give it away, so the directory exists and the account cannot write in it (S78). | `smoke-session-home-control` (arm of `smoke-session`); `make smoke-session` must go red under it |
| `SHELL_BARE_UNKNOWN=1` | The shell before 2026-09-24: a builtin typed without its operand (`touch`, `cat`, `cp`, `rm`, ...) is reported as "Unknown command", because each is matched with its trailing space and a bare word matches none of them. | `smoke-session-usage-control` (arm of `smoke-session`) |
| `FS_CHMOD_ANY_OWNER=1` | Removes `FS_OP_CHMOD`'s owner-or-root test in `fs_server`, so any caller sets the mode of any file (S77). | `smoke-session-chmod-control` (arm of `smoke-session`); `make smoke-session` must go red under it |
| `FS_CHOWN_ANY_UID=1` | Removes `FS_OP_CHOWN`'s root-only test, so any caller gives a file to any uid, in practice, takes one (S77). | `smoke-session-chown-control` (arm of `smoke-session`); `make smoke-session` must go red under it |
| `TUI_INPUT_ECHO_SECRET=1` | Drops the mask in `tui_input`, so a password field paints what was typed. | `smoke-tui-mask-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_INPUT_UNBOUNDED=1` | Drops the `cap` bound in `tui_input` and keeps the visible-width bound, so a caller that passed a small buffer and a wide field is written past the end of it. | `smoke-tui-bound-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_MENU_UNCLAMPED=1` | Lets a menu's selection run past either end of its item list. | `smoke-tui-menu-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_ACS_NO_RESTORE=1` | Stops `tui_flush` emitting the shift back from the DEC Special Graphics charset, while leaving the bookkeeping that says it did. | `smoke-tui-acs-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_WRAP_NO_BREAK=1` | Lets `tui_wrap` emit a word longer than its column whole instead of breaking it at the column, so the text runs out of its column and across whatever is beside it. | `smoke-tui-wrap-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_NO_INVALIDATE=1` | Makes `tui_invalidate` a no-op, so the library keeps believing a screen something else has written over. | `smoke-tui-invalidate-control` (arm of `smoke-tui`); `make smoke-tui` must go red under it |
| `TUI_NO_CELLS=1` | Stops `tui_flush` sending its cells to `CON_OP_DRAW_CELLS`, leaving only the escape sequences that reach the serial line. | `smoke-keyboard-installer-noserial-control` (arm of `smoke-keyboard-installer-noserial`); `make smoke-keyboard-installer-noserial` must go red under it |
| `STORAGE_SINGLE_DEVICE=1` | Restores the pre-2026-09-06 ATA probe: only the primary master is ever looked at. | `smoke-storage-survey-single-control` (arm of `smoke-storage-survey`); `make smoke-storage-survey` must go red under it |
| `STORAGE_DEVICE_INDEX_CLAMP=1` | Answers an out-of-range device index with the LAST device instead of refusing it. | `smoke-storage-device-clamp-control` (arm of `smoke-storage-survey`); `make smoke-storage-survey` must go red under it |
| `STORAGE_FORMAT_TARGET_IGNORED=1` | Validates the device index handed to `SYS_STORAGE_FORMAT` and then discards it, so the format lands on whatever device the machine nominated at boot rather than the one the operator chose (S83). | `smoke-installer-target-control` (arm of `smoke-installer-target`); `make smoke-installer-target` must go red under it |
| `USERS_PEPPER_PER_BOOT=1` | Account hashes are peppered with the per-boot `kernel_pepper` again, so a password set in one boot cannot verify in the next however faithfully the table was stored (S62). | `smoke-users-persist-control` (arm of `smoke-users-persist`); `make smoke-users-persist` must go red under it |
| `USERS_TAMPER_INJECT=1` | Instrument, never shipped: Flips a byte inside the sealed user table on the platter, raw, before it is read, which is what an attacker with disk access does. | `smoke-users-tamper` |
| `STORAGE_AUTOFORMAT=1` | The pre-2026-08-31 behaviour: meeting an unformatted ATA volume at the login prompt runs `storage_format_sealed` on the strength of whatever password was typed, so a mistyped password on a machine whose disk the kernel did not recognise formats it and becomes key slot 0. | `smoke-e820`, `smoke-fs-persist`, `smoke-fs-wal`, `smoke-fs-wal-flush`, `smoke-fs-wal-flush-control` (arm of `smoke-fs-wal-flush`), `smoke-fs-wal-order`, `smoke-fs-wal-order-control` (arm of `smoke-fs-wal-order`), `smoke-keyslots`, `smoke-keyslots-control` (arm of `smoke-keyslots`), `smoke-users-persist`, `smoke-users-persist-control` (arm of `smoke-users-persist`), `smoke-users-tamper`, `smoke-passwd-target`, `smoke-passwd-target-control` (arm of `smoke-passwd-target`), `smoke-storage-noformat-control` (arm of `smoke-storage-noformat`) |
| `STORAGE_REPLACE_UNLOCKED=1` | Drops `storage_authorize_format`'s refusal of a target whose volume is unlocked, so a disk can be reformatted out from under the running system that has it open. | `smoke-replace-live-control` (arm of `smoke-replace-live`) |
| `STORAGE_FORMAT_AUTH_STICKY=1` | Restores the pre-2026-09-11 lifetime of `g_format_authorized`: set once by `storage_authorize_format` and never cleared. | `smoke-replace-oneshot-control` (arm of `smoke-replace-oneshot`) |
| `BOOT_CMDLINE_UNMEASURED=1` | Restores the pre-2026-09-11 PCR[8] serialisation, which covered the boot-module manifest and not the kernel command line. | `smoke-tpm-cmdline-control` (arm of `smoke-tpm-cmdline`) |
| `STORAGE_FORMAT_UNGATED=1` | Removes the dispatch-table row in front of `SYS_STORAGE_FORMAT` entirely, no slot, no rights floor, no type, so any ring-3 task may authorise a format of the attached disk (S72). | `smoke-captest-storage-format-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `BLOCK_ERRNO_LEGACY=1` | Restores the bare return values `h_block_read` and `h_block_write` shipped with: the storage layer's raw `-1` for a block the device refuses, and a raw `-3` for a failed user copy. | `smoke-blockprobe-control` (arm of `smoke-blockprobe`); `make smoke-blockprobe` must go red under it |
| `ELF_LOAD_BOUND_STAGING=1` | Restores the pre-2026-09-09 bound in the ELF loader: every attacker-controlled parse (header, load-plan, relocations) is bounded by the size of the 8 MiB `loader_staging` region instead of by the bytes the image actually staged. | `smoke-proc-overreach-control` (arm of `smoke-proc`) |
| `IMAGE_LEN_UNCHECKED=1` | Drops the refusal `arm_image_from_user` makes when a user-supplied container's header claims more payload than the buffer it came in (`HORUS_IMAGE_HDR_BYTES + h.size > len`): under the flag the loader copies `h.size` bytes from a `len`-byte buffer, reading past the caller's image. | `smoke-proc-truncated-image-control` (arm of `smoke-proc`) |
| `FS_LINK_UNCOUNTED=1` | Makes `SYS_FS_INODE_LINK` (`h_fs_inode_link`) report success without incrementing the inode's on-disk link count. | `smoke-session-hardlink-control` (arm of `smoke-session`) |
| `PIPE_CAP_UNACCOUNTED=1` | Restores the pre-2026-09-12 `SYS_PIPE`: the two pipe-end capabilities are written into the caller's cspace by a raw, field-by-field store that takes no `cap_lock` and never touches `caps_in_use`. | `smoke-cap-accounting-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `TOKEN_REPLY_MINT_UNMASKED=1` | Removes the reply-mint's rights bound, so a server is given whatever rights it asks for rather than at most those of the capability the client invoked it with (S105). | `smoke-captoken-unmasked-control` (arm of `smoke-captoken`); `make smoke-captoken` must go red under it |
| `REPLY_EP_SPACE_OVERLAP=1` | Restores the pre-2026-09-12 endpoint index space, in which the static table was the literal `128` while the map above it declared the per-task reply region as `[REPLY_EP_BASE, REPLY_EP_BASE + MAX_TASKS)` = `[64, 320)`. | `smoke-reply-ep-control` (arm of `smoke-reply-ep`); `make smoke-reply-ep` must go red under it |
| `READDIR_END_IS_NOENT=1` | Restores the overloaded readdir reply: `SYS_ERR_NOENT` for both "the offset is past the last entry" and "I could not stat that directory", together with `fs_server` flattening `h_fs_stat`'s reason instead of passing it through. | `smoke-readdir-end-control` (arm of `smoke-readdir-end`); `make smoke-fs` must go red under it |
| `SHELL_LS_NO_PATH_ARG=1` | Restores the pre-2026-09-06 `ls` dispatch: the builtin matched the literal strings `ls` and `ls -l` and nothing else, so `ls /bin` fell through the entire builtin chain and answered `Unknown command`. | `smoke-ls-path-control` (arm of `smoke-ls-path`) |
| `BOOT_ROOT_CD_ONLY=1` | Restores the pre-2026-09-07 `grub.cfg` line `set root=(cd)`, which named the BIOS El Torito CD-ROM. | `smoke-boot-media-control` (arm of `smoke-boot-media`) |
| `BOOT_MENU_NO_LIVE_TOKEN=1` | Strips `horus.live` from the boot menu's live entry, so it passes no command line at all, which is how that entry was first written, and it was a lie. | `smoke-boot-menu-control` (arm of `smoke-boot-menu`) |
| `CONSOLE_PASS_UNGATED=1` | Restores the pre-2026-09-12 console server, which served `CON_OP_GETPASS` to any holder of the send-only console capability, which is every task the shell has ever spawned, since that capability is how a child gets a stdout. | `smoke-console-pass-control` (arm of `smoke-console-pass`) |
| `BOOT_PIN_UNCHECKED=1` | Rewrites the boot image's kernel hash check to `true`, so GRUB boots whatever is at `/boot/kernel.elf` and the pin inside the measured image is decorative. | `smoke-boot-pin-control` (arm of `smoke-boot-pin`), `smoke-tpm-bootimg`, `smoke-tpm-bootimg-control` (arm of `smoke-tpm-bootimg`) |
| `BOOT_IMAGE_UNBOUND=1` | Takes `PCR[4]` back out of the seal policy (`put_pcr_selection`), restoring the pre-2026-09-11 `PolicyPCR(8,9)`, a policy over the two PCRs this kernel extends about itself, from a tag, the command line and the manifest compiled into it. | `smoke-tpm-bootimg-control` (arm of `smoke-tpm-bootimg`) |
| `AHCI_PROBE_ABSENT=1` | Compiles out the SATA probe, so a machine that has an AHCI controller reports nothing about it: the state this tree was in before 2026-09-07, and the reason the installer surveys a laptop and finds no disk. | `smoke-ahci-detect-control` (arm of `smoke-ahci-detect`) |
| `SDHCI_PROBE_ABSENT=1` | Compiles out the SD/eMMC probe, so a machine that has a host controller reports nothing about it: the state this tree was in before 2026-09-07, and the reason the installer surveys a laptop whose storage is soldered eMMC and finds no disk. | `smoke-sdhci-detect-control` (arm of `smoke-sdhci-detect`) |
| `SDHCI_CSD_SPEC_BITS=1` | Decodes the card's CSD at the field positions the SD specification documents, without the eight-bit shift a stored 136-bit response has because its CRC byte is dropped. | `smoke-sdhci-csd-control` (arm of `smoke-sdhci-detect`) |
| `SDHCI_ADDR_MODE_INVERTED=1` | Swaps the two card addressing units: a high-capacity card is handed a byte offset and a standard-capacity card a block number, so every read lands 512x from where it was meant to, except block 0, which is address 0 in both units and reads correctly either way. | `smoke-sdhci-addr-control` (arm of `smoke-sdhci-detect`) |
| `SDHCI_WRITE_SELFTEST=1` | Compiles in a boot-time write round trip (write block 200, flush, read back, compare). | `smoke-sdhci-write` |
| `SDHCI_WRITE_NO_FLUSH=1` | Drops the wait for the card to finish programming, so a write returns while the card is still busy. | `smoke-sdhci-write` |
| `SDHCI_NO_LOCK=1` | The SD/eMMC driver before 2026-09-24: no `sdhci_lock`, so on two CPUs a write on one and a read on the other run on the controller at once and corrupt each other. | `smoke-installer-sd-smp-control` (arm of `smoke-installer-sd-smp`) |
| `SDHCI_STAY_SLOW=1` | The SD/eMMC driver before 2026-09-25: after identification it never switched the card to a 4-bit bus or raised the clock from 400 kHz, so on the IdeaPad every 4 KiB read spent about 83 ms moving data and a command took seconds. | `smoke-sdhci-fast-control` (arm of `smoke-sdhci-fast`) |
| `FB_REQUEST=1` | Not a defect: adds the multiboot2 framebuffer request tag to the kernel header, which is the only way to make GRUB set a graphics mode for this kernel. | `smoke-klog-console-fb`, `smoke-fb-tag-gfx`, `smoke-fb-tag-gfx-control` (arm of `smoke-fb-tag-gfx`), `smoke-fb-grid`, `smoke-fb-grid-control` (arm of `smoke-fb-grid`), `smoke-fb-console-server`, `smoke-fb-console-server-control` (arm of `smoke-fb-console-server`), `smoke-devcap-fb`, `smoke-devcap-fb-control` (arm of `smoke-devcap-fb`), `smoke-fb-console`, `smoke-fb-console-control` (arm of `smoke-fb-console`), `smoke-fb-map`, `smoke-fb-map-control` (arm of `smoke-fb-map`) |
| `FB_TAG_IGNORED=1` | The framebuffer tag walked past without being read: the state this kernel was in before 2026-09-08. | `smoke-fb-tag-control` (arm of `smoke-fb-tag`) |
| `FB_TAG_ASSUME_TEXT=1` | `framebuffer_type` parsed, validated, stored, and not consulted when choosing a console path, so every display is character cells. | `smoke-fb-tag-gfx-control` (arm of `smoke-fb-tag-gfx`) |
| `FB_MAP_SELFTEST=1` | Instrument, never shipped: Writes a pattern through the framebuffer window and reads it back, at boot and again on each freshly built user address space, and reports whether the window is present in that address space's real page tables. | `smoke-fb-map`, `smoke-fb-map-control` (arm of `smoke-fb-map`) |
| `FB_MAP_LOW_HALF=1` | The window built in `pml4[0]` (the low half, which `create_user_pagedir` builds from nothing) instead of `high_pdpt[509]`. | `smoke-fb-map-control` (arm of `smoke-fb-map`) |
| `FB_CONSOLE_SELFTEST=1` | Instrument, never shipped: Draws a known glyph (`L`) below the 80x50 grid, in the region the console never scrolls over, so a host-side screendump can inspect the pixels after the boot log has settled. | `smoke-fb-console`, `smoke-fb-console-24bpp`, `smoke-fb-console-24bpp-control` (arm of `smoke-fb-console-24bpp`), `smoke-fb-console-control` (arm of `smoke-fb-console`) |
| `FB_CONSOLE_MIRRORED=1` | The blitter reads the font's bit 0 as the leftmost pixel instead of bit 7, mirroring every glyph. | `smoke-fb-console-control` (arm of `smoke-fb-console`) |
| `FB_INFO_ANY_DEVICE=1` | `SYS_FB_INFO`'s object check dropped, so any device capability reads the display's geometry, a NIC driver learns the screen's dimensions. | `smoke-devcap-fb-control` (arm of `smoke-devcap-fb`) |
| `CONSOLE_FB_ABSENT=1` | `console_server` as it was before 2026-09-08: it never asks what the display is, so on a machine with no VGA text window it maps one anyway, fails its own round-trip check and parks. | `smoke-fb-console-server-control` (arm of `smoke-fb-console-server`) |
| `CONSOLE_NO_KBD=1` | `console_server` as it was before 2026-09-11: it drives the screen but reads only COM1, so on a machine whose only input device is the keyboard there is no way to answer the prompt it has just painted. | `smoke-keyboard-control` (arm of `smoke-keyboard`) |
| `CONSOLE_INPUT_SPIN=1` | `console_server` before 2026-09-25: it never routes IRQ 1 and the tick to its notification, so every wait for input is a `sys_yield` loop and an idle prompt keeps a core busy (100% of a host core under QEMU at the login prompt). | `smoke-console-idle-control` (arm of `smoke-console-idle`) |
| `CONSOLE_CLEAR_DRAWN=1` | `CON_OP_CLEAR` before 2026-09-24: after blanking the screen it wrote `ESC [2J ESC [H` through `con_putc`, which draws on the screen as well as sending to serial, so seven glyphs appeared in front of `init: the installer finished`. | `smoke-installer-clear-control` (arm of `smoke-installer-clear`) |
| `KLOG_NARROW=1` | The Alt+F2 view before 2026-09-25: it is laid out on the console's 80-column grid and clears the display only when a surface is centred, so on a framebuffer wider than 80 cells the log covers the left of the screen and the rest keeps what the installer drew. | `smoke-klog-console-fb-control` (arm of `smoke-klog-console-fb`) |
| `CONSOLE_NO_SCROLLBACK=1` | `console_server` before 2026-09-24: a line that scrolls off the top of the machine's own screen is gone, and Shift+PgUp does nothing. | `smoke-console-scrollback-control` (arm of `smoke-console-scrollback`) |
| `KLOG_CONSOLE=1` | Instrument, never shipped: Alt+F2 shows the kernel log across the whole of the machine's own screen with nobody logged in; Shift+PgUp/PgDn page it and Up/Down move it a row, every other key is ignored, and Alt+F1 puts the console back exactly as it was (`klog_view` in `userspace/console_server.c`). | `smoke-klog-console`, `smoke-klog-console-absent-control` (arm of `smoke-klog-console-absent`) |
| `SERIAL_PRESENCE_UNCHECKED=1` | The console input path as it stood before 2026-09-12: `inb(COM1_LSR) & 1` believed without first asking whether there is a UART at `0x3F8` to answer. | `smoke-keyboard-noserial-control` (arm of `smoke-keyboard-noserial`); `make smoke-keyboard-noserial` must go red under it |
| `CONSOLE_BACKSPACE_NO_ERASE=1` | `console_server`'s screen output as it stood before 2026-09-12: neither `fb_putc` nor `vga_putc` had a case for `0x08`, so a backspace fell through to the glyph branch and was drawn. | `smoke-console-backspace-control` (arm of `smoke-console-backspace`); `make smoke-console-backspace` must go red under it |
| `CONSOLE_NO_SCROLL=1` | Restores `console_server`'s screen as it stood before 2026-09-12: both putc paths ended a full screen with `pos = 0`, so the newest line overwrote the oldest and the display became a ring buffer with nothing marking the seam, its bottom half older than its top half, and no way to tell by looking. | `smoke-console-scroll-control` (arm of `smoke-console-scroll`); `make smoke-console-scroll` must go red under it |
| `CONSOLE_NO_CURSOR=1` | Restores `console_server` as it stood before 2026-09-12: it never wrote the 6845's cursor registers at all. | `smoke-console-cursor-control` (arm of `smoke-console-cursor`); `make smoke-console-cursor` must go red under it |
| `CONSOLE_NO_RESUME=1` | Restores `console_server` starting at the top-left when it takes the text console, as it did before 2026-09-12. | `smoke-console-resume-control` (arm of `smoke-console-resume`); `make smoke-console-resume` must go red under it |
| `CONSOLE_ESC_LITERAL=1` | Restores `con_getline` as it stood before 2026-09-12: the ESC is dropped as a control byte and the rest of the escape sequence is typed into the line as ordinary text. | `smoke-console-escape-control` (arm of `smoke-console-escape`); `make smoke-console-escape` must go red under it |
| `FB_24BPP_REFUSED=1` | Restores the framebuffer console's 32-bit-only check, in both rings, as it stood before 2026-09-12. | `smoke-fb-console-24bpp-control` (arm of `smoke-fb-console-24bpp`); `make smoke-fb-console-24bpp` must go red under it |
| `PS2_LAYOUT_IGNORED=1` | Restores the keyboard reader as it stood before 2026-09-14: one hardcoded US layout, and a scancode range that stopped at space (`0x39`). | `smoke-keymap-uk-control` (arm of `smoke-keymap-uk`); `make smoke-keymap-uk` must go red under it |
| `CONSOLE_KBD_SPLIT_ESC=1` | Stops `con_read_raw` draining the tail of an expanded arrow into the same reply, so the escape sequence reaches `tui_getkey` split across two. | `smoke-keyboard-installer-control` (arm of `smoke-keyboard-installer`) |
| `FB_REQUEST_W=` / `FB_REQUEST_H=` | Instrument, never shipped: Overridable because the console's grid is *derived* from what firmware grants, and a derived property can only be tested by varying what it derives from: `FB_REQUEST_H=360` is a real 45-row display, where a flag would only assert that a number was written down. | `smoke-fb-grid` |
| `FB_GRID_FIXED_ROWS=1` | The console's row count nailed to 50 whatever the display can show: what it was before 2026-09-08. | `smoke-fb-grid-control` (arm of `smoke-fb-grid`) |
| `DEVREGS_KERNEL_ONLY=1` | Stops `ensure_storage_regs_mapped_current` replaying the AHCI/SDHCI register pages into a freshly built user address space: what the kernel did until 2026-09-08. | `smoke-installer-sd-devregs-control` (arm of `smoke-installer-sd`) |
| `SD_BLOCK_ADDR_UNSCALED=1` | The filesystem block number handed to the card as an LBA, and one 512-byte sector moved where the block layer asked for 4096, the first version of `storage.c`'s SD block device, which did not scale by `SD_SECTORS_PER_BLOCK` the way `atadisk_read` scales by `ATA_SECTORS_PER_BLOCK`. | `smoke-installer-sd-stride-control` (arm of `smoke-installer-sd`) |
| `AHCI_CAPACITY_CONSTANT=1` | Reports a fixed 128 MiB instead of the capacity the drive returned, what a driver that read the right IDENTIFY words from the wrong offset looks like, or one that filled in a default it never checked. | `smoke-ahci-capacity-control` (arm of `smoke-ahci-detect`) |
| `CONSOLE_VGA_CHECK_FAIL=1` | Forces `console_server`'s VGA round-trip check to fail without touching the hardware, which is what a firmware-set graphics mode does to the legacy text window at `0xB8000`. | `smoke-console-handover-control` (arm of `smoke-console-handover`) |
| `SERIAL_TX_NEVER_DRAINS=1` | Polls the UART's line-status register and never accepts the answer, the wedged-port case: a COM1 that decodes and never asserts THRE. | `smoke-serial-bound-control` (arm of `smoke-serial-bound`) |
| `KSTACK_INFLIGHT_LEGACY_WORD=1` | The pre-2026-08-30 `g_kstack_inflight`: ONE `uint64_t`, bit selected by `1ULL << t` with no bound on `t`. | `smoke-task-ceiling-control` (arm of `smoke-task-ceiling`); `make smoke-task-ceiling` must go red under it |
| `KSTACK_SLOT_INDEX_TRUNC=1` | The kernel-stack slot index truncated to 6 bits, so task *t* and task *t*−64 are permanently bound to one kernel stack: S20 by construction rather than by race. | `smoke-task-ceiling-stack-control` (arm of `smoke-task-ceiling`); `make smoke-task-ceiling` must go red under it |
| `SYSCOV_PROBES_ABSENT=1` | Compiles out the coverage probes: `captest` section 13, which enters the twelve `SC_NONE` handler bodies promoted on 2026-08-30, and `auditprobe`'s four calls into the two audit handlers promoted on 2026-09-01. | `smoke-syscall-coverage-control` (arm of `smoke-syscall-coverage`); `make smoke-syscall-coverage` must go red under it |
| `AUDIT_ABI_LEGACY=1` | The pre-2026-09-01 `SYS_READ_AUDIT` ABI: ring 3 declares a 72-byte `struct audit_record` and `h_read_audit` copies the kernel's 256-byte internal event at the kernel's stride into it, so every field is read from the wrong offset and the copy runs 184 bytes past the array per record (S71). | `smoke-auditprobe-abi-control` (arm of `smoke-auditprobe`); `make smoke-auditprobe` must go red under it |
| `IRQ_FORCE_PIC=1` | Instrument, never shipped: Skips I/O APIC bring-up so interrupts route through the 8259; the configuration every machine with no MADT I/O APIC entry runs. | `smoke-net-irq-storm-control` (arm of `smoke-net`) |
| `IRQ_ACK_UNGATED=1` | `SYS_IRQ_ACK` without its capability check, so re-enabling an interrupt line stops being an authority question and any task can do it for hardware it does not hold. | `smoke-captest-irq-ack-control` (arm of `smoke-captest`) |
| `NET_NO_DECODE=1` | `netd` asks `SYS_DEVICE_ENABLE` for no decode bits, so the device stops answering its own I/O BAR and its register file reads back as floating bus. | `smoke-net-decode-control` (arm of `smoke-net`); `make smoke-net` must go red under it |
| `NET_NO_BUSMASTER=1` | I/O decode without bus mastering: the register file answers and the device's DMA does not. | `smoke-net-busmaster-control` (arm of `smoke-net`); `make smoke-net` must go red under it |
| `DMA_ADDR_FRAME_ONLY=1` | `SYS_DMA_ADDR` gated on the frame capability alone; the shape it takes if the device capability is read as documentation rather than as a requirement. | `smoke-frame-dma-control` (arm of `smoke-frame`); `make smoke-frame` must go red under it |
| `KLOG_WRITE_UNGATED=1` | Restores the pre-2026-08-20 `h_write`: a ring-3 write to fd 1 is appended to the kernel message ring with no authority tested at all, so any task can forge `dmesg` lines and flood the 16 KiB ring to evict genuine ones ([H-2]). | `smoke-klog-forge-control` (arm of `smoke-klog-forge`) |
| `GETLINE_SLOT3_FALLBACK=1` | Restores `h_get_line`'s pre-2026-08-24 fallback: an untyped `cap_lookup` on slot 3 (the legacy `CAP_FRAME` every task is born holding) as an alternative to `CAP_CONSOLE`. | `smoke-captest-getline-control` (arm of `smoke-captest`) |
| `CAP_LOOKUP_ASSERT_HANG=1` | Restores the pre-2026-08-29 source-slot resolver in `cap_mint` and `cap_transfer`: `cap_lookup` followed by `kassert_cap`, an unconditional `for(;;){}` on NULL, run while holding `cap_lock` with interrupts masked by `spin_lock`'s own `cli`. | `smoke-captest-mint-hang-control` (arm of `smoke-captest`) |
| `IOMMU_NO_FRAME_TEARDOWN=1` | Restores the pre-2026-08-29 `destroy_dyn_frame`: the frame's bytes are scrubbed and the pages returned to the untyped arena while every device translation of them stays installed. | `smoke-iommu-teardown-control` (arm of `smoke-iommu-teardown`) |
| `IOMMU_NO_TASK_TEARDOWN=1` | Restores the pre-2026-08-29 `task_teardown`, which released every other device resource a dying task held (the IRQ route, the MSI route, the port grant, the console) and left its IOMMU domain populated. | `smoke-iommu-teardown-task-control` (arm of `smoke-iommu-teardown`); `make smoke-iommu-teardown` must go red under it |
| `TASKINFO_WIDE_AUTHORITY=1` | Restores the pre-2026-08-24 acceptance set for `SYS_GET_TASK_INFO`: `CAP_USER` or `CAP_AUDIT` also answer "may I see the process list" (roadmap 3.6). | `smoke-proc-taskinfo-control` (arm of `smoke-proc`); `make smoke-proc` must go red under it |
| `CLOCK_TSC_RESOLUTION=1` | Makes `SYS_CLOCK_GETTIME` report real microseconds from the calibrated TSC instead of PIT ticks (roadmap 2.2). | `smoke-captest-clock-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `CAP_ENUMERATE_UNGATED=1` | Removes `SYS_CAP_ENUMERATE`'s declared capability from the dispatch table, so the central gate admits every caller and any ring-3 task can read any other's capability slots (roadmap 3.6). | `smoke-captest-capenum-control` (arm of `smoke-captest`); `make smoke-captest` must go red under it |
| `IMAGE_HDR_WRITER_SKEW=1` | Makes `tools/mkheadered` emit `name` four bytes further into the same 44-byte `.bin` header, as if a `uint32_t flags` had been inserted before it on the WRITER side only. | `smoke-image-abi-control` (arm of `smoke-image-abi`); `make smoke-image-abi` must go red under it |
| `LEGACY_SYSCALLS_PRESENT=1` | Restores six retired dispatch entries (5, 6, 7, 14, 19 and 27), all but one of them gated on the slot-3 capability every task holds. | `smoke-passwd-probe-legacy-control` (arm of `smoke-passwd-probe`), `smoke-passwd-probe-recv27-control` (arm of `smoke-passwd-probe`), `smoke-passwd-probe-exec19-control` (arm of `smoke-passwd-probe`); `make smoke-passwd-probe` must go red under it |
| `MEASURED_BOOT_REQUIRED=1` | A policy, not a defect: halts when measured boot is unavailable, and refuses to unlock a persistent volume that was never sealed to the TPM. | `smoke-measured-boot-required`, `smoke-measured-boot-required-control` (arm of `smoke-measured-boot-required`), `smoke-measured-boot-required-volume-control` (arm of `smoke-measured-boot-required`), `smoke-measured-persist`, `smoke-measured-persist-control` (arm of `smoke-measured-persist`), `smoke-measured-persist-sealed`, `smoke-tpm-bootimg`, `smoke-tpm-bootimg-control` (arm of `smoke-tpm-bootimg`) |
| `MEASURED_VOLUME_EXEMPT_NONE=1` | Removes the ephemeral-vdisk exemption from the rule above. | `smoke-measured-boot-required-volume-control` (arm of `smoke-measured-boot-required`) |
| `MEASURED_VOLUME_UNCHECKED=1` | Removes the sealed-volume refusal itself, which is the opposite of the flag above and is why the two sit together: `MEASURED_VOLUME_EXEMPT_NONE` makes the refusal *reachable* on the vdisk, this one deletes it. | `smoke-measured-persist-control` (arm of `smoke-measured-persist`); `make smoke-measured-persist` must go red under it |
| `POSIX_LEGACY_WALK=1` | Restores `posix.c`'s private path walker, the copy that stood until 2026-08-23 (roadmap 2.4). | `smoke-newlib-walk-control` (arm of `smoke-newlib`); `make smoke-newlib` must go red under it |
| `HVFS_DOTDOT_SERVER=1` | Restores the `..` branch `hvfs` shipped with in #195: it asks the SERVER to look up a `..` entry. | `smoke-newlib-dotdot-control` (arm of `smoke-newlib`) |
| `RNG_UNSEEDED_PROBE=1` | Instrument, never shipped: the instrument. | `smoke-rng-seed`, `smoke-rng-seed-control` (arm of `smoke-rng-seed`) |
| `RNG_UNSEEDED_LEGACY=1` | Restores the pre-2026-08-23 `RngState::fill`, which never consulted `seeded`: asked for output before the pool was reseeded it emits ChaCha20 keystream under the published startup constant in `RngState::new()`, and the caller cannot tell that from randomness (S30). | `smoke-rng-seed-control` (arm of `smoke-rng-seed`); `make smoke-rng-seed` must go red under it |

Some instruments take a value that tunes them rather than selecting a defect:
`KFAULT_INJECT_TICKS` (for `KFAULT_INJECT`), `KSTACK_RACE_WIDEN_SPINS` and
`KSTACK_RACE_WIDEN_CPUMASK` (for `KSTACK_RACE_WIDEN`), `SPAWN_STAGE_WIDEN_SPINS` and
`SPAWN_STAGE_WIDEN_WINDOWS` (for `SPAWN_STAGE_WIDEN`), and `RESUME_RSP_INJECT_VALUE` (for
`RESUME_RSP_INJECT`).

**Stale objects.** Userspace objects do not depend on the build flags, so `make clean` before
switching configuration, or a gate can pass against the wrong binary.

### Session-harness knobs

Environment variables `tools/session_test.py` and `tools/installer_session.py` read; they change no
build.

- `SESSION_DISK_IOPS=<n>` throttles the guest's disk to *n* operations a second with QEMU's own
  limiter; `make smoke-installer-slowdisk` sets it to reproduce a slow disk.
- `SESSION_DISK_BPS=<n>` does the same for bandwidth.
- `SESSION_SERIAL_LOG=<path>` is where the guest's serial output goes; multi-boot scenarios append
  one labelled section per boot.

---

## Testing

```bash
make smoke      # boot headless and wait for the ring-3 login prompt
make test       # Rust unit tests, then a clean rebuild; it boots nothing
```

Every integration test is `make smoke-<name>`; [`../TESTS.md`](../TESTS.md) lists them all. A few
of the most important:

| Target | Asserts |
|---|---|
| `smoke-captest` | Unheld capabilities, post-revoke use, and bad input are all refused (198 checks, printed by the suite as `CAPTEST: PASS <n> checks`) |
| `smoke-wx` | No kernel page is both writable and executable |
| `smoke-modules-tamper` | A corrupted boot module is refused |
| `smoke-tpm-seal` | A changed PCR leaves the volume locked |
| `smoke-installer` | An install onto a blank disk boots and logs in, and the compiled-in root password is refused |
| `smoke-session` | A scripted session in the real shell |

The TPM gates need `swtpm`. Some targets need more than the 40 s default timeout
(`make smoke-tcc SMOKE_TIMEOUT=320`); under TCG everything is slow.

---

## Reproducible builds

```bash
make reproducible-build   # one clean SOURCE_DATE_EPOCH build; records .build.sha
make verify-build         # the same
```

The target builds **once** and records `sha256sum` of `kernel.elf` and `horus.iso` in
`.build.sha`, refusing (and writing nothing) if either is missing (`tools/record_build_sha.sh`).
The `reproducible` CI job runs it twice and compares the `kernel.elf` hashes; to check locally, run
it twice and compare that line, or run `sha256sum -c .build.sha` against artifacts you have.
`kernel.elf` is byte-for-byte reproducible. **`horus.iso` is not**: `grub-mkrescue` writes a file
named for the wall-clock second and embeds a UUID in the EFI loaders it generates
(`docs/LIMITATIONS.md` 5.3a).

---

## Boot modules

Programs other than the boot-critical servers reach the system as GRUB `module2` entries rather
than inside `kernel.elf`. At build time `tools/gen_module_manifest.sh` hashes each module into
`src/kernel/boot_module_manifest.h`, which is compiled into the kernel; at boot the kernel checks
every module against it, and one that does not match cannot be read. `init` copies verified
modules into the encrypted store under `/bin` and `/usr/share/man`. To add one, build it
into `userspace/`, add a `module2` line to the GRUB configuration, and rebuild; the manifest
regenerates.

---

## Rust core

```bash
cargo test   --manifest-path rust/Cargo.toml --release
cargo clippy --manifest-path rust/Cargo.toml --release --all-targets -- -D warnings
cargo +nightly fuzz run <target>    # from rust/, targets in rust/fuzz/
cd rust && cargo kani               # see rust/KANI.md
```

The crate has no external runtime dependency, which keeps the supply chain empty; Dependabot
watches Cargo anyway.

---

## Troubleshooting

- **`cannot find -lhorus_shell`**: the Rust library did not build. Run `cargo build --manifest-path
  rust/Cargo.toml --release --target x86_64-unknown-none` and read its error.
- **`can't find target x86_64-unknown-none`**: `rustup target add x86_64-unknown-none`.
- **`xorriso: command not found`**: install `xorriso grub-pc-bin grub-common mtools`.
- **QEMU shows nothing**: `make run` puts the console on your terminal; use it rather than calling
  QEMU by hand.
- **A smoke test times out**: raise `SMOKE_TIMEOUT`. CI runners and TCG are slow.
- **Linker assertion `__bss_end <= USER_PHYS_BASE`**: a large static array pushed `.bss` past
  16 MiB. `.bss` has an exact budget (`.github/image-budget.yml`); move the array into a
  physical-pool reservation as `loader_staging` is.
- **A real machine shows no disk to install onto**: its storage is probably NVMe or SATA, which
  Horus cannot drive yet. `PCI_SCAN_TRACE=1` lists what is on the bus.
