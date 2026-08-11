# Horus

**A capability-based secure microkernel for x86-64, and the foundation for a complete
operating system built from the ground up.**

[![CI](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml)
[![Pages](https://github.com/pharanyx-labs/Horus/actions/workflows/pages.yml/badge.svg)](https://horus.pharanyx.co.uk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[![Target: x86-64](https://img.shields.io/badge/target-x86__64-informational)](docs/ARCHITECTURE.md)
[![Security core: no_std Rust](https://img.shields.io/badge/security%20core-no__std%20Rust-orange)](docs/BUILDING.md#rust-core)
[![Build: byte-for-byte reproducible](https://img.shields.io/badge/build-byte--for--byte%20reproducible-brightgreen)](docs/BUILDING.md#reproducible-builds)
[![Boot: TPM 2.0 measured](https://img.shields.io/badge/boot-TPM%202.0%20measured-brightgreen)](docs/ARCHITECTURE.md#12-trusted-boot-and-the-tpm)
[![Status: research-grade](https://img.shields.io/badge/status-research--grade-yellow)](docs/LIMITATIONS.md)

Horus boots on x86-64 hardware and under QEMU, drops to a ring-3 shell, and runs ordinary C
programs — including GNU coreutils and the Tiny C Compiler — on a microkernel whose device
drivers and filesystem live in userspace. The security-critical parsing and validation code
is written in memory-safe `no_std` Rust. The build is byte-for-byte reproducible, the boot
chain is measured into a TPM, and the volume encryption key is sealed against those
measurements.

> ### Assurance status
>
> Horus is **research-grade**, not production-ready, and has not been independently audited.
>
> The 2026-07 audit's critical finding — IPC endpoints were not capability-addressed, so any
> ring-3 task could intercept or forge messages to any userspace server — is **fixed as of
> 2026-07-27** ([C-1]/[C-2] in [`docs/AUDIT-2026-07-27.md`](docs/AUDIT-2026-07-27.md)).
> Open findings are tracked in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) and
> [`docs/ROADMAP.md`](docs/ROADMAP.md). Ambient `uid == 0` authority (**[I-1]**) and
> fixed-size kernel object tables (**[I-7]**) were both retired on 2026-07-27 — cspaces,
> endpoints and notifications are now carved from untyped memory, though `tasks[]` has yet to
> follow. The notable remaining findings are the unconditional `sti` in `spin_unlock` and its
> global IRQ counter (**[C-3]**), an unflushed write-ahead journal (**[I-10]**), and no
> independent review of security-critical changes (**[C-5]**).

---

## Contents

- [Why Horus](#why-horus)
- [The long-term goal](#the-long-term-goal)
- [What exists today](#what-exists-today)
- [Architecture in one page](#architecture-in-one-page)
- [The security model](#the-security-model)
- [Quick start](#quick-start)
- [Repository layout](#repository-layout)
- [Testing](#testing)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Why Horus

Most operating systems place millions of lines of code — filesystems, network stacks,
graphics, every device driver — inside the kernel, where a single bug compromises the whole
machine. A microkernel puts almost none of that in privileged mode. Horus goes further and
asks that *nothing* hold authority it was not explicitly given.

Three principles drive every design decision.

**Least privilege by construction.** Authority is a capability: an unforgeable token naming
one object and one set of rights. There is no `root` bit that opens every door and no
ambient "the caller is trusted" path. A task can only do what it holds a capability for, and
can only delegate a *subset* of what it holds.

**Fail closed.** Every syscall passes through a dispatch table with a declared capability
requirement. An unknown, reserved, or unimplemented syscall number does not fall through to
a handler — it returns `SYS_ERR_NOSYS`. A compile-time assertion makes it impossible to add
a syscall number without adding its table entry.

**Verify, don't assert.** Claims are backed by artifacts. The build is verified reproducible
by building twice and diffing. Boot-module integrity is tested by *corrupting a module* and
asserting rejection. Measured boot is tested by tampering and asserting the PCRs diverge.
Capability revocation carries Kani proofs. Thirty-plus QEMU integration self-tests run in
CI.

---

## The long-term goal

Horus is the high-assurance foundation for a complete operating system. The kernel is not
the destination — it is the smallest thing that must be trusted so that everything above it
need not be.

The path from here is ordered by assurance rather than by demo value:

1. ~~**Make the object model true.**~~ **Done (2026-07-27):** capabilities now mediate
   *which* object, not merely which kind — see **[C-1]**.
2. ~~**Retire ambient `uid == 0` authority**~~ **Done (2026-07-27):** each root-gated syscall
   now demands a distinct capability, so the capability graph is a complete description of
   who can do what — see **[I-1]**.
3. ~~**Kernel objects from untyped memory.**~~ **Done (2026-07-27):** `CAP_UNTYPED` +
   `SYS_RETYPE` replaced the fixed `.bss` tables for cspaces, endpoints and notifications, so
   creating a kernel object is an exercise of authority the graph describes and kernel memory
   is accounted per task — see **[I-7]**. `tasks[]` is the remaining table.
4. **Real virtual-memory objects.** Frame capabilities, shared memory, `mmap`.
5. **Userspace services on top:** a VFS with multiple filesystems, a network stack as a
   ring-3 server, a process and session model, dynamic linking.
6. **Assurance scaffolding throughout:** extend the proofs, publish the threat model, attest
   the artifacts.

[`docs/ROADMAP.md`](docs/ROADMAP.md) has the full plan, with rationale and security impact
per item.

---

## What exists today

| Subsystem | State |
|---|---|
| **Boot** | Multiboot2 via GRUB, higher-half 64-bit kernel at `KERNEL_VMA`, physical pool sized from the E820 map |
| **Memory** | Per-task 4-level page tables, demand paging, copy-on-write, NX stacks, kernel W^X, unmapped stack guard pages, 30-bit userspace ASLR |
| **Capabilities** | 16 object types, rights masking on delegation, system-wide subtree revocation with a serial-keyed generation backstop |
| **Scheduling** | Preemptive (100 Hz PIT / per-CPU LAPIC), full trap-frame context switches, microarchitectural flush on task switch |
| **SMP** | Default on; ACPI MADT enumeration, INIT-SIPI-SIPI bringup, shared runnable pool, acknowledged TLB-shootdown IPIs, SMT siblings parked in software |
| **IPC** | Capability-addressed synchronous send/recv/call/reply over bounded-FIFO endpoints, one-shot reply capabilities, async notifications, per-task private reply endpoints, bounded byte-stream pipes |
| **Filesystem** | `fs_server` in ring 3 over an AEAD-encrypted kernel object store; POSIX rwx against kernel-attested uid/gid; write-ahead journal and mount-time fsck; double-indirect large files |
| **Console** | `console_server` in ring 3 owning the UART and VGA framebuffer; raw terminal mode (termios + winsize) |
| **Storage crypto** | Per-`(inode, block)` AEAD subkeys, hierarchical rollback MAC; key material never leaves the kernel |
| **Boot integrity** | SHA-256 module manifest embedded in the kernel image; TPM 2.0 measurement into PCR 8 and 9; vdisk KEK sealed under `PolicyPCR` |
| **Userspace** | newlib libc, a shell with pipelines, GNU coreutils, TCC |
| **Security core** | `no_std` Rust: ELF parsing and relocation, capability algebra, ChaCha20 CSPRNG, BLAKE2b/SHA-256, AEAD, Argon2 |

**IPC is capability-addressed.** Every IPC syscall takes a cspace slot; the kernel derives
the endpoint or notification from the capability there, checking its type, the right for the
direction, and its lineage generation. A task is born holding exactly one endpoint capability
— its own private reply endpoint — and reaches a service only through a capability something
delegated to it. Clients get WRITE-only capabilities, so a client can send to a server but
can never receive its traffic or forge its replies.

---

## Architecture in one page

```
            ring 3                                        ring 0
 ┌──────────────────────────────────┐        ┌───────────────────────────────┐
 │  shell   coreutils   tcc   init  │        │  Horus microkernel            │
 │                                  │        │                               │
 │  ┌────────────┐  ┌────────────┐  │  IPC   │  capability space per task    │
 │  │ fs_server  │  │  console_  │  │◄──────►│  scheduler + preemption       │
 │  │            │  │  server    │  │        │  paging / demand / COW        │
 │  └─────┬──────┘  └─────┬──────┘  │        │  encrypted object store       │
 └────────┼───────────────┼─────────┘        │  TPM / measured boot          │
          │               │                  │                               │
          │ object-store  │ CAP_IO_DEVICE    │  ┌─────────────────────────┐  │
          │ syscalls      │ MAP_PHYS/IOPORT  │  │ Rust no_std security    │  │
          └───────────────┴─────────────────►│  │ core: ELF, caps, crypto │  │
                                             │  └─────────────────────────┘  │
                                             └───────────────────────────────┘
```

The kernel provides address spaces, threads, capabilities, IPC, and an encrypted block store
whose keys it never releases. Everything else — naming, directories, permissions, terminal
handling, program-loading policy — is userspace.

Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## The security model

**Capabilities.** A capability is `{type, rights, object, badge, serial, generation}`. It
lives in a per-task capability space (cspace) and is named by slot index. Userspace never
sees the struct — only the slot number — so it cannot be forged.

- **Mint** derives a child with `rights & new_rights`: delegation can only ever *reduce*
  authority.
- **Grant** pushes a capability into a child the caller supervises (holds `CAP_TCB` for).
  Never upward.
- **Revoke** is system-wide and *subtree-scoped*: it nulls the target and everything
  transitively derived from it, across every task's cspace, while leaving ancestors,
  siblings, and independent capabilities to the same object intact.
- **Generations** back revocation up. Each capability's serial keys a generation cell that
  is bumped on revoke, so a detached snapshot of a revoked capability fails validation even
  if the structural sweep somehow missed it. Two independent mechanisms; both must hold.

**Zero-trust identity.** A server never trusts what a client says about itself.
`SYS_IPC_SENDER` returns the uid the *kernel* recorded for a message's sender, established
only by a successful login. `fs_server` authorises every file operation against that value.

**Defence in depth in the kernel.** SMEP and SMAP (verified present in CR4 by a self-test),
CR0.WP, EFER.NXE, kernel W^X swept for violations at boot, unmapped kernel-stack guard
pages, stack canaries reseeded from the CSPRNG, `CR4.TSD` denying ring-3 `RDTSC`,
microarchitectural flush on task switch, SMT siblings parked.

**Trusted boot.** GRUB loads the kernel and modules; the kernel verifies each module against
a SHA-256 manifest embedded in its own image and refuses unverified payloads outright. Both
kernel and modules are measured into TPM PCR 8 and 9. The vdisk key-encryption key is sealed
to those PCRs, so a tampered boot cannot unlock the volume.

Full detail, including the threat model and what is explicitly out of scope, in
[`SECURITY.md`](SECURITY.md).

---

## Quick start

**Requirements:** `gcc` (x86-64 host), `binutils`, `make`, `rustup` with the
`x86_64-unknown-none` target, `xorriso`, `grub-pc-bin`, `grub-common`, `mtools`, and
`qemu-system-x86`. Optionally `swtpm` for measured-boot testing.

```bash
rustup target add x86_64-unknown-none
sudo apt-get install -y build-essential binutils make \
    xorriso grub-pc-bin grub-common mtools qemu-system-x86

make            # build kernel.elf
make run        # build the ISO and boot it under QEMU with a serial console
```

Log in as `root` / `horus`. Try `ls /bin`, `dmesg`, `ps`, `cat /etc/motd | wc -l`.

Other useful targets:

```bash
make smoke              # headless boot; asserts the ring-3 shell banner appears
make test               # the full local self-test sweep
make SMP=0              # build without SMP
make DEBUG_SHELL=1      # build with the in-kernel debug shell
make reproducible-build # build twice and diff kernel.elf
make run-tpm            # boot under an emulated TPM (requires swtpm)
```

Complete build documentation, including every configuration flag, in
[`docs/BUILDING.md`](docs/BUILDING.md).

---

## Repository layout

```
src/boot/          multiboot2 entry, long-mode bringup, AP trampoline
src/kernel/        the kernel: caps, paging, sched, IPC, syscalls, storage, TPM, drivers
src/include/       kernel-internal headers
rust/src/          no_std security core (ELF, capabilities, crypto, CSPRNG, audit)
rust/fuzz/         cargo-fuzz targets for the FFI boundary
include/           the userspace ABI: syscall numbers, wrappers, IPC protocols
userspace/         init, fs_server, console_server, shell, self-test programs
userspace/ports/   ported third-party programs (coreutils, tcc)
newlib/            vendored libc
tools/             build helpers, QEMU session drivers, manifest generation
tests/             host-side tests
docs/              architecture, syscalls, roadmap, limitations, audits
site/              the project website published to GitHub Pages
```

---

## Testing

Horus's assurance rests on its tests, so they are treated as first-class. Three layers:

1. **Rust unit tests and Kani proofs** — `cargo test`, plus formal proofs that revocation
   hits exactly the target's derivation subtree.
2. **QEMU integration self-tests** — 30+ targets that boot a purpose-built kernel
   configuration and assert a marker on the serial console. These cover W^X, capability
   refusals, COW, TLB shootdown, preemption, signals, SMEP/SMAP, measured boot, and more.
3. **Scripted sessions** — Python drivers that type into the real ring-3 shell over serial
   and assert on the output.

Several are *adversarial*: `smoke-modules-tamper` corrupts a boot module and asserts it is
refused; `smoke-tpm-tamper` asserts the PCRs diverge. Testing that a control *fires* matters
more than testing that the happy path works.

[`TESTS.md`](TESTS.md) has the complete catalogue and what each test proves.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Subsystem design, invariants, and why each decision was made |
| [`SECURITY.md`](SECURITY.md) | Threat model, security properties, reporting policy |
| [`docs/SYSCALLS.md`](docs/SYSCALLS.md) | The complete syscall ABI with authorisation requirements |
| [`docs/BUILDING.md`](docs/BUILDING.md) | Build, configure, run, reproduce |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Honest accounting of what does not work or is not enforced |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Prioritised plan toward a complete OS |
| [`docs/AUDIT-2026-07-27.md`](docs/AUDIT-2026-07-27.md) | Current full security and engineering audit |
| [`TESTS.md`](TESTS.md) | Test catalogue |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute, and the invariant-preservation rules |
| [`CHANGES.md`](CHANGES.md) | Historical development log |

---

## Contributing

Contributions are welcome, especially to the capability model, formal verification, and
userspace services. Changes to security-critical paths carry an extra obligation: state
which invariant your change preserves, and add the test that witnesses it. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Security

Please report vulnerabilities privately — [`SECURITY.md`](SECURITY.md) has the process and
scope. Known unfixed issues are documented openly in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) and the current audit; Horus does not hide its
weaknesses.

---

## License

MIT — see [`LICENSE`](LICENSE).
