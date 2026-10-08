# Horus

**A capability-based x86-64 microkernel in which no code acts on anything it was not explicitly
handed a capability for.**

[![CI](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml)
[![Pages](https://github.com/pharanyx-labs/Horus/actions/workflows/pages.yml/badge.svg)](https://horus.pharanyx.co.uk/)

Horus is a small C kernel with a `no_std` Rust core for the code that must not go wrong:
capability checks, ELF parsing, cryptography and the random number generator. Drivers, the file
server and the console run as ordinary unprivileged tasks. It boots under QEMU and on real
machines, installs itself onto a disk, and gives you a login and a shell in which GNU coreutils and
the Tiny C Compiler run against a shared C library.

The aim is a complete operating system. The kernel is the part everything else has to trust, so
it is built first and kept small.

| | |
|---|---|
| **Status** | Research system. One tagged release, `v0.2.0-alpha` (2026-09-14), for developers; all work lands on `main` |
| **Platform** | x86-64, booted by GRUB under BIOS or UEFI, in QEMU or on real hardware |
| **Languages** | C for the kernel and the ring-3 servers, `no_std` Rust for the security core |
| **Website** | [horus.pharanyx.co.uk](https://horus.pharanyx.co.uk/) |
| **Licence** | MIT ([`LICENSE`](LICENSE)) |

## Contents

- [Before you rely on it](#before-you-rely-on-it)
- [The capability model](#the-capability-model)
- [What it can do](#what-it-can-do)
- [What it cannot do yet](#what-it-cannot-do-yet)
- [What comes next](#what-comes-next)
- [Architecture](#architecture)
- [Getting started](#getting-started)
- [How it is verified](#how-it-is-verified)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Contributing and reporting](#contributing-and-reporting)
- [Licence](#licence)

## Before you rely on it

Horus is a research system, and nobody independent has reviewed it.

- **No human reviews a change before it lands.** Most of the code is written by Claude, an AI
  model, which also merges its own pull requests once every required check passes. The maintainer
  sets direction and decides anything that touches the security model.
- **The checks are extensive, but they are not review.** Every gate is built to fail when the
  defect it guards against is put back; that is evidence, not a second pair of eyes.
- **Some security limitations are open.** An inherited pipe end escapes revocation (1.14), any
  program a person runs can read the command lines they type (2.9b), measured boot is opt-in on a
  machine without a TPM (2.9), and the cryptography is unaudited (5.4).

[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) is the single authoritative status of every known
finding, and the numbers above are its entries. Read it before drawing conclusions.

## The capability model

There is one source of authority in Horus: a **capability**, an unforgeable reference to one
kernel object with a set of rights. A task holds capabilities in its own table and names them by
slot number; it never sees the capability itself.

- **Nothing is granted for who you are.** Being user 0, being the first task, or being spawned by
  the kernel confers nothing. `init` and the shell work because they were handed capabilities.
- **Rights only shrink.** A capability can be copied with fewer rights, never more.
- **Revocation reaches everything derived.** Revoking a capability removes every copy made from
  it, in every task, and leaves unrelated capabilities to the same object alone. A generation
  counter backs this up, so a stale copy the sweep missed still fails.
- **Even memory is paid for.** Creating an endpoint, a shared page or a whole task spends an
  untyped memory budget the creator holds a capability to. A task with no budget cannot create a
  task.
- **Refusal is the default.** Every system call passes a dispatch table that states the
  capability it needs, and an unknown number returns an error rather than reaching a handler.

Two console paths are the deliberate exception: writing to standard output and reading a console
line need no capability, and the read side is refused once `console_server` owns the console
(`docs/LIMITATIONS.md` 1.6).

## What it can do

### Kernel

- Preemptive scheduling on up to eight CPUs, with SMT siblings parked and a microarchitectural
  flush on every switch between tasks.
- Per-task four-level page tables, demand paging, copy-on-write, `fork`, `exec` and signals.
- IPC over bounded queues with one-shot reply capabilities, notifications and pipes; a server can
  tell its clients apart by the capability they call it through.
- SMEP, SMAP, kernel W^X, guard pages and stack canaries; user programs load at a randomised
  address.

### Servers and drivers in ring 3

- `init` starts and supervises every other task and hands each one its capabilities.
- `console_server` owns the serial port, the screen (VGA text or a framebuffer, under BIOS or
  UEFI) and the PS/2 keyboard.
- `fs_server` serves files from the encrypted volume.
- A driver's capability names one device, and the IOMMU confines that device's DMA to the memory
  its driver mapped.
- `netd`, an Intel network driver built the same way, exchanges ARP with its gateway in a test
  build; the shipped system does not start it.

### Storage

- Every block of the volume is encrypted and authenticated under its own derived key, and the key
  never leaves the kernel.
- A Merkle tree catches a block rolled back to an older version, and on a machine with a TPM a
  hardware counter catches the whole volume being swapped for an older copy.
- A journal keeps the filesystem consistent across a power cut.

### Installation

- Install media offers a live session or the installer. A live session never opens an installed
  disk.
- The installer is the only task that can format a disk, and it formats only after a typed
  confirmation word.
- It sets up an administrator and an everyday account, can replace an earlier Horus volume, and
  can leave the volume unencrypted if the operator chooses.
- It installs onto IDE disks and onto SD and eMMC storage, including a laptop's soldered eMMC.

### Boot integrity

- The kernel's hash is pinned inside the boot image, which the firmware measures into the TPM.
- The kernel checks every boot module against a manifest before it reads it, and measures itself
  and the modules into further TPM registers.
- The volume key is sealed to those measurements, so a substituted kernel cannot unlock the disk.

### Userspace

- A shell with pipelines and built-in commands, including `capview`, which draws the capability
  graph.
- Eleven GNU coreutils, `man` pages and TCC, a C compiler that runs on Horus, in a `make run`
  build. The install media does not carry them yet (roadmap 2.11).
- One shared copy of newlib. The kernel hands the library only to programs that ask for it, and
  each program's references to it are resolved and sealed read-only before `main` runs.

## What it cannot do yet

- **No disk that boots by itself.** An installed machine is started from Horus boot media
  (`horus.iso`), which finds and opens the volume.
- **No programs on the disk.** Every shipped program is compiled into the boot image or loaded as
  a measured boot module.
- **No networking above Ethernet.** No IP, TCP, sockets or ARP table.
- **No storage beyond IDE, SD and eMMC.** A SATA drive is identified but not read, and there is no
  NVMe.
- **No USB**, and so no keyboard on a machine without PS/2 emulation.
- **No threads, job control, `/proc`, swap, wall clock or kernel address randomisation.**
- **No architecture but x86-64.**

The full list, with the reasons, is in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## What comes next

In order, from [`docs/ROADMAP.md`](docs/ROADMAP.md):

1. **A disk that boots itself** (2.11), in progress: a GPT disk with an EFI system partition, a
   reserved swap partition and the volume, sized by the operator.
2. **Use all the memory** (3.1): the page pool reaches up to 4 GiB instead of 512 MiB.
3. **Filesystem phase 1b** (2.10): `fs_server`, the path walker and `init` authorise files by
   capability instead of by user id and mode.
4. **Programs on the disk** (2.11): the installer copies the system onto the volume, and the
   loader refuses any file whose hash is not in a manifest pinned in the measured boot image.
5. **Accounts as files** (2.11): `/etc/passwd` and `/etc/shadow` on the volume, owned by a ring-3
   `auth_server`.
6. **Encrypted swap** in the reserved partition, under a key made fresh at every boot.
7. **Filesystem phases 2 to 4** (2.10): the filesystem moves to ring 3 on a copy-on-write format,
   with separate system and home volumes, and gains links, timestamps, snapshots and extended
   attributes.

## Architecture

```text
 ring 3, unprivileged
┌──────────────────────────────────────────────────────────────────────────┐
│  init starts every task here and hands each one its capabilities         │
│  shell, coreutils and tcc share one libc.so, mapped read-only            │
│           │ console cap     │ file cap                                   │
│  ┌────────▼───────┐  ┌──────▼──────┐  ┌───────────┐  ┌──────────┐        │
│  │ console_server │  │  fs_server  │  │ installer │  │  netd *  │        │
│  └────────┬───────┘  └──────┬──────┘  └─────┬─────┘  └─────┬────┘        │
│           │ UART, screen    │ storage cap   │ format cap   │ NIC cap     │
│           │ and PS/2        │               │              │             │
└───────────┼─────────────────┼───────────────┼──────────────┼─────────────┘
┌───────────▼─────────────────▼───────────────▼──────────────▼─────────────┐
│ kernel, ring 0                                                           │
│   capabilities, IPC, scheduling, paging, untyped memory, TPM, IOMMU,     │
│   the encrypted volume, accounts, and the IDE, SD and eMMC drivers       │
│   Rust core: capability algebra, ELF loader, crypto, CSPRNG, audit log   │
└──────────────────────────────────────────────────────────────────────────┘
 * netd runs only in the NET_SELFTEST build; the shipped system does not start it.
```

Directories, file permissions, terminal handling and which program to run are decided in ring 3.
The kernel keeps what cannot yet be delegated safely: address spaces, capabilities, the volume
key, the accounts and the disk drivers. Moving the storage and account code out of ring 0 is
roadmap 2.7a. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) explains each subsystem and why it is
shaped the way it is.

## Getting started

### Requirements

An x86-64 Linux host with:

| Tool | For |
|---|---|
| `gcc`, `binutils`, `make` | The kernel and userspace |
| `rustup` | The Rust core; the first `make` installs the toolchain pinned in `rust-toolchain.toml` |
| `xorriso`, `grub-pc-bin`, `grub-common`, `mtools` | The bootable ISO |
| `qemu-system-x86` | Running and testing |
| `swtpm`, `swtpm-tools` *(optional)* | An emulated TPM, for measured boot and the sealed volume key |
| `python3` *(optional)* | Scripted sessions and PCR recomputation |

### Build and run

```bash
make            # builds kernel.elf
make run        # builds horus.iso and boots it in QEMU on this terminal (Ctrl-A X quits)
```

A boot with no installed disk has two built-in accounts:

| Account | Password | Session |
|---|---|---|
| `root` | `toor` | Administrator |
| `user` | `password` | Unprivileged |

Then try `ls /bin`, `ps`, `capview`, `dmesg`, `man hier`, `tcc -v` or `help`. The built-in
accounts never work on an installed machine, which has only the accounts its installer created.

### Real hardware

| Image | Built by | What it does |
|---|---|---|
| `install.iso` | `make install.iso` | A boot menu: a live session (the default, which opens no disk) or the installer |
| `horus.iso` | `make iso` | One entry: opens the installed volume, runs the installer on a blank disk, or boots in RAM |

```bash
make install.iso
sudo dd if=install.iso of=/dev/sdX bs=4M status=progress conv=fsync   # the device, not a partition
```

The installed disk has no bootloader of its own yet, so start the installed system from a stick
holding `horus.iso`. Every build flag, the persistent-disk targets and the troubleshooting
instruments are in [`docs/BUILDING.md`](docs/BUILDING.md).

## How it is verified

Every security property Horus claims is a numbered row in [`SECURITY.md`](SECURITY.md), and each
row names the test that would fail if the property broke. A checker in CI refuses a row whose
test does not exist or does not run.

| Layer | What it covers |
|---|---|
| Security properties | 116 numbered properties, each bound to a witness by `tools/check_invariants.py` |
| QEMU integration tests | 437 `smoke-*` targets: 207 base gates and 230 control arms |
| Control arms | A build that puts a defect back on purpose; CI requires its gate to go red against it |
| Kani | 33 bounded proofs over revocation, the ELF validator, user-address checks, the RNG seed gate, the login throttle and page reference counts; each gates every pull request, and each proof's recorded mutation is replayed nightly to show it still fails |
| Miri | The security core's tests, interpreted for undefined behaviour on every pull request |
| Fuzzing | The FFI predicates under cargo-fuzz, ten minutes per target, nightly |
| Reproducibility | `kernel.elf` builds byte for byte the same twice; the ISO does not yet |
| Toolchain | The Rust compiler, Kani, the fuzzing toolchain, PyYAML and semgrep are pinned to exact versions |

`.github/workflows/ci.yml` defines 133 jobs; 137 of the 146 status checks the workflows produce
gate a merge. The 9 that do not are the nightly fuzzing, the nightly Kani control arms and the
scheduled ruleset audit, each with its reason in `.github/ci-gating.yml`.
[`TESTS.md`](TESTS.md) lists every test and what it proves.

## Repository layout

```text
src/boot/          entry from GRUB, long mode, the secondary-CPU trampoline
src/kernel/        the kernel: capabilities, IPC, scheduling, paging, storage, TPM, drivers
src/include/       kernel headers
rust/              the no_std security core, its Kani proofs and its fuzz targets
include/           the user-facing ABI: syscall numbers and wrappers, IPC protocols
userspace/         init, the servers, the shell, the installer, libc glue, self-test programs
userspace/ports/   GNU coreutils and TCC, with the changes Horus needs
tools/             build helpers, QEMU drivers for the tests, and the CI checkers
docs/              architecture, syscalls, building, roadmap, limitations, designs, history
site/              the website: plain HTML, edited directly
.github/           CI workflows and the registries the checkers enforce
```

newlib is not in the tree: `tools/build_newlib.sh` fetches it and refuses it unless its SHA-256
matches the pinned value ([`THIRD_PARTY.md`](THIRD_PARTY.md)).

## Documentation

| Document | Read it for |
|---|---|
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | What is wrong or missing today, and every finding's status |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | What is done, and what comes next in what order |
| [`SECURITY.md`](SECURITY.md) | The threat model, every security property with its test, and how to report a vulnerability |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How each subsystem works and why |
| [`docs/SYSCALLS.md`](docs/SYSCALLS.md) | Every system call and the capability it requires |
| [`docs/BUILDING.md`](docs/BUILDING.md) | Building, running, installing, and every build flag |
| [`TESTS.md`](TESTS.md) | Every test target and what it proves |
| [`CHANGES.md`](CHANGES.md) | What changed, one line per entry with its pull request; the full entries to 2026-10-07 are in [`docs/history/CHANGES-2026.md`](docs/history/CHANGES-2026.md) |
| [`docs/README.md`](docs/README.md) | Everything else: designs, audits, investigations and history |

## Contributing and reporting

- **Contributions** are welcome. A change to a security-critical path must say which property it
  keeps and add the test that shows it; [`CONTRIBUTING.md`](CONTRIBUTING.md) has the rules.
- **Vulnerabilities** are reported privately, as described in [`SECURITY.md`](SECURITY.md). Do
  not open a public issue for one.

## Licence

MIT; see [`LICENSE`](LICENSE). Third-party code and fonts, including the GNU coreutils (GPLv3) and
TinyCC (LGPL 2.1) sources under `userspace/ports/`, are listed in
[`THIRD_PARTY.md`](THIRD_PARTY.md).
