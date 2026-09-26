# Horus

**An x86-64 microkernel in which no code acts on anything it was not explicitly handed a
capability for.**

[![CI](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml)
[![Pages](https://github.com/pharanyx-labs/Horus/actions/workflows/pages.yml/badge.svg)](https://horus.pharanyx.co.uk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Horus is a small C kernel with a `no_std` Rust core for the code that must not go wrong:
capability checks, ELF parsing, cryptography and the random number generator. Drivers, the
filesystem server and the console run as ordinary unprivileged tasks. It boots under QEMU and on
real machines, installs itself onto a disk, and gives you a login and a shell in which GNU
coreutils and the Tiny C Compiler run against a shared C library.

The aim is a complete operating system. The kernel is the part everything else has to trust, so
it is built first and kept small.

## Before you rely on it

Horus is a research system. Nobody independent has reviewed it. Most of its code is written by
Claude, an AI model, which also merges its own pull requests once every automated check passes;
the maintainer sets direction and decides anything that touches the security model. No human
reads a change before it lands. The checks are extensive and every one of them is built to fail
when the defect it guards against is put back, but that is not the same as review.

What does not work, or is not enforced, is listed in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), which is the single authoritative status for every
known finding. Read it before drawing conclusions.

## The rule it is built around

There is one source of authority in Horus: a **capability**, an unforgeable reference to one
kernel object with a set of rights. A task holds capabilities in its own table and names them by
slot number; it never sees the capability itself.

- **Nothing is granted for who you are.** Being user 0, being the first task, or being spawned by
  the kernel confers nothing. `init` and the shell work because they were handed capabilities.
- **Rights only shrink.** A capability can be copied with fewer rights, never more.
- **Revocation reaches everything derived.** Revoking a capability removes every copy made from
  it, in every task, and leaves unrelated capabilities to the same object alone. A generation
  counter backs this up, so a stale copy that the sweep somehow missed still fails.
- **Even memory is paid for.** Creating an endpoint, a shared page or a whole task spends an
  untyped memory budget the creator holds a capability to. A task with no budget cannot create a
  task.
- **Refusal is the default.** Every system call passes a dispatch table that states the
  capability it needs; an unknown number returns an error rather than reaching a handler.

The one deliberate exception is the console: any task may write to standard output
(`docs/LIMITATIONS.md` 1.6).

## What it can do

**Kernel.** Preemptive scheduling on up to eight CPUs, with hyperthread siblings parked and caches
flushed between tasks that do not trust each other. Per-task four-level page tables, demand
paging, copy-on-write, `fork` and `exec`, signals. IPC over bounded queues with one-shot reply
capabilities, notifications and pipes. SMEP, SMAP, kernel W^X, guard pages and reseeded stack
canaries. User programs load at a randomised address.

**Servers in ring 3.** `init` starts and supervises everything else. `console_server` owns the
serial port, the screen (VGA text or a framebuffer, under BIOS or UEFI) and the PS/2 keyboard.
`fs_server` serves files from an encrypted volume. `netd` drives an Intel network card and
exchanges ARP with its gateway. Each holds only the capabilities it was given; a driver's
capability names one device, and the IOMMU confines that device's DMA to the memory its driver
mapped.

**Storage.** Every block of the volume is encrypted and authenticated with a per-block key, a
Merkle tree catches a block rolled back to an older version, and a TPM counter catches the whole
volume being swapped for an older copy. The key never leaves the kernel. A journal keeps the
filesystem consistent across a power cut.

**Installing.** Booted from install media, Horus offers a live session or an installer. The
installer is the only task that can format a disk, asks for a typed word before it does, sets up
an administrator and an everyday account, and can replace an earlier Horus volume. It installs
onto IDE disks and onto SD and eMMC storage, including the soldered eMMC of a budget laptop. A
live session never opens an installed disk.

**Boot integrity.** The kernel's hash is pinned inside the boot image, which the firmware measures
into the TPM. The kernel checks every boot module against a manifest before it will read it, and
measures itself and the modules into further TPM registers. The volume key is sealed to those
measurements, so a substituted kernel cannot unlock the disk.

**Userspace.** A shell with pipelines and built-in commands. A `make run` build adds eleven GNU
coreutils, `man` pages and TCC, a C compiler that runs on Horus; the install media does not carry
them yet, because shipping them is part of the installed-system work (roadmap 2.11). Those
programs share one copy of newlib: the kernel hands the library only to programs that ask for
it, and each program's references to it are resolved and sealed read-only before `main` runs.

## What it cannot do yet

No networking above Ethernet. No NVMe, no USB, and so no keyboard on a machine without PS/2
emulation; a SATA drive is recognised but not read. An installed disk does not boot by itself:
you start it from Horus boot media. There are no threads, no job control, no wall clock and no
kernel address randomisation. The full list, with the reasons, is in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), and what is being built next, in order, is in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

## How the pieces fit

```
 unprivileged (ring 3)
 ┌──────────────────────────────────────────────────────────────────────┐
 │  shell   coreutils   tcc          programs share libc.so (read-only)  │
 │     │  console client capability       │  file server capability      │
 │  ┌──▼─────────────┐  ┌─────────────────▼┐  ┌──────┐  ┌───────────┐   │
 │  │ console_server │  │    fs_server     │  │ netd │  │ installer │   │
 │  └──┬─────────────┘  └───────┬──────────┘  └──┬───┘  └─────┬─────┘   │
 │     │ one device capability  │ storage         │ one NIC    │ format  │
 │     │ (UART, screen, PS/2)   │ capability      │ capability │ cap     │
 │  init: starts every task above and hands each its capabilities        │
 └─────┼────────────────────────┼─────────────────┼────────────┼─────────┘
 ┌─────▼────────────────────────▼─────────────────▼────────────▼─────────┐
 │ kernel (ring 0): capability tables, IPC, scheduling, paging,           │
 │ untyped memory, the encrypted block store, TPM, IOMMU, disk drivers    │
 │   Rust core: capability algebra, ELF loader, crypto, CSPRNG, audit log │
 └────────────────────────────────────────────────────────────────────────┘
```

Directories, file permissions, terminal handling and which program to run are decided in ring 3.
The kernel keeps what cannot be delegated safely: address spaces, capabilities, the volume key and
the disk drivers. Moving the storage and account code out of ring 0 is on the roadmap (2.7a).
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) explains each subsystem and why it is shaped the
way it is.

## Try it

You need an x86-64 Linux host with `gcc`, `binutils`, `make`, `rustup` (with the
`x86_64-unknown-none` target), `xorriso`, `grub-pc-bin`, `grub-common`, `mtools` and
`qemu-system-x86`. `swtpm` is optional and adds an emulated TPM.

```bash
rustup target add x86_64-unknown-none
make            # builds kernel.elf
make run        # builds horus.iso and boots it in QEMU on this terminal (Ctrl-A X quits)
```

Log in as `root` with password `toor`, then try `ls /bin`, `ps`, `capview`, `dmesg` or
`cat /etc/motd | wc -l`. Those two accounts exist only on a boot with no installed disk; an
installed machine has only the accounts its installer created.

To install onto real hardware, `make install.iso` builds install media with a boot menu (live
session or install); write it to a USB stick with `dd`. The installed disk has no bootloader of
its own yet, and the install media's live session deliberately never opens it, so start the
installed system from a stick holding `horus.iso` (`make horus.iso`), whose single boot entry
finds and opens the volume. The details, every build flag and the troubleshooting notes are in
[`docs/BUILDING.md`](docs/BUILDING.md).

## How it is checked

Every security property Horus claims is a numbered row in [`SECURITY.md`](SECURITY.md), and each
row names the test that would fail if the property broke. A checker in CI refuses a row whose
test does not exist or does not run.

Most tests boot a purpose-built kernel in QEMU and read its serial output. Many are adversarial:
they corrupt a boot module, tamper with the measured boot, or try the refused operation, and
require the refusal. Each such test has a **control arm**, a build that puts the defect back on
purpose, and CI requires the test to go red against it, so a test that cannot fail cannot pass
unnoticed. `.github/workflows/ci.yml` defines 135 jobs; 136 of the 140 status checks they
produce gate a merge, and the four that do not each carry a written reason. Bounded Kani proofs
cover the capability algebra, Miri runs over the Rust core, and `kernel.elf` builds byte for byte
the same twice. [`TESTS.md`](TESTS.md) lists every test and what it proves.

## Where things are

```
src/boot/        entry from GRUB, long mode, the secondary-CPU trampoline
src/kernel/      the kernel: capabilities, IPC, scheduling, paging, storage, TPM, drivers
src/include/     kernel headers
rust/            the no_std security core, its Kani proofs, and fuzz targets
include/         the user-facing ABI: syscall numbers and wrappers, IPC protocols
userspace/       init, the servers, the shell, the installer, libc glue, self-test programs
userspace/ports/ GNU coreutils and TCC, with the changes Horus needs
tools/           build helpers, QEMU drivers for the tests, and the CI checkers
docs/            architecture, syscalls, building, roadmap, limitations, designs, history
site-src/, site/ the website's source and its built pages
```

newlib is not in the tree: `tools/build_newlib.sh` fetches it and refuses it unless its SHA-256
matches the pinned value (`THIRD_PARTY.md`).

## Documents

| Read | For |
|---|---|
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | What is wrong or missing today, and every finding's status |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What is done, and what comes next in what order |
| [`SECURITY.md`](SECURITY.md) | The threat model, every security property with its test, and how to report a vulnerability |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How each subsystem works and why |
| [`docs/SYSCALLS.md`](docs/SYSCALLS.md) | Every system call and the capability it requires |
| [`docs/BUILDING.md`](docs/BUILDING.md) | Building, running, installing, and every build flag |
| [`TESTS.md`](TESTS.md) | Every test target and what it proves |
| [`docs/README.md`](docs/README.md) | Everything else: designs, audits, investigations, history |
| [`CHANGES.md`](CHANGES.md) | What changed, by pull request |

## Contributing and reporting

Contributions are welcome. A change to a security-critical path must say which property it keeps
and add the test that shows it; [`CONTRIBUTING.md`](CONTRIBUTING.md) has the rules. Report
vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

## Licence

MIT; see [`LICENSE`](LICENSE). Third-party code and fonts are listed in
[`THIRD_PARTY.md`](THIRD_PARTY.md).
