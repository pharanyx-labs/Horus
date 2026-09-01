# Horus

**A capability-based secure microkernel for x86-64, and the foundation for a complete
operating system built from the ground up.**

[![CI](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/ci.yml)
[![CodeQL](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml/badge.svg)](https://github.com/pharanyx-labs/Horus/actions/workflows/codeql.yml)
[![Pages](https://github.com/pharanyx-labs/Horus/actions/workflows/pages.yml/badge.svg)](https://horus.pharanyx.co.uk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[![Target: x86-64](https://img.shields.io/badge/target-x86__64-informational)](docs/ARCHITECTURE.md)
[![Kernel image: byte-for-byte reproducible](https://img.shields.io/badge/kernel.elf-byte--for--byte%20reproducible-brightgreen)](docs/BUILDING.md#reproducible-builds)
[![Boot: TPM 2.0 measured](https://img.shields.io/badge/boot-TPM%202.0%20measured-brightgreen)](docs/ARCHITECTURE.md#12-trusted-boot-and-the-tpm)

Horus boots on x86-64 hardware and under QEMU, drops to a ring-3 shell, and runs ordinary C
programs (including GNU coreutils and the Tiny C Compiler) on a microkernel whose device drivers
and filesystem live in userspace. The security-critical parsing and validation code is written
in memory-safe `no_std` Rust. The kernel image is byte-for-byte reproducible, the boot chain is
measured into a TPM, and the volume encryption key is sealed against those measurements.

> ### Assurance status
>
> Horus is **research-grade**, not production-ready, and has not been independently audited.
> It is the work of a single maintainer, and no security-critical change has had independent
> review (**[C-5]**).
>
> What that means concretely, finding by finding, is in
> [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) (the authoritative status of every one) and
> the analysis is in [`docs/AUDIT.md`](docs/AUDIT.md). The harder investigations are written
> up in [`docs/investigations/`](docs/investigations/), including the ones this project got
> wrong for days before getting right.
>
> Notable open findings: **[C-5]** (no independent review), **[C-6]** (the branch ruleset is
> reconciled to the checked-in gating decision by hand, so it lags a merge). **[G-9]** closed
> on 2026-08-21: its last component was the claim auditor clearing its own exemption before the
> release it exempts, so the checker accused a release that was in flight rather than a leak.

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

Most operating systems place millions of lines of code (filesystems, network stacks, graphics,
every device driver) inside the kernel, where a single bug compromises the whole machine. A
microkernel puts almost none of that in privileged mode. Horus goes further and asks that
*nothing* hold authority it was not explicitly given.

Three principles drive every design decision.

**Least privilege by construction.** Authority is a capability: an unforgeable token naming one
object and one set of rights. There is no `root` bit that opens every door, and since **[H-1]**
landed no kernel path grants authority for *who the caller claims to be*. A task can only do
what it holds a capability for, and can only delegate a *subset* of what it holds. Three
console-adjacent syscalls are still ungated by any capability: `SYS_WRITE` fd 1, `SYS_READ` fd 0
and `SYS_SYSINFO`; they are enumerated in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) §1.6 and
marked *ambient* at each entry in [`docs/SYSCALLS.md`](docs/SYSCALLS.md), because a claim stated
absolutely and enforced partially is worse than no claim. Those three are ungated
*deliberately*: a terminal write, a terminal read and a version string are not authorities this
system rations. Writing to fd 1 no longer carries anything else with it: it once also appended
to the kernel message ring, whose *read* side requires `CAP_KERNEL_LOG`, and that half is gated
now (**[H-2]**, S23).

**Fail closed.** Every syscall passes through a dispatch table with a declared capability
requirement. An unknown, reserved, or unimplemented syscall number does not fall through to a
handler; it returns `SYS_ERR_NOSYS`. A compile-time assertion makes it impossible to add a
syscall number without adding its table entry.

**Verify, don't assert.** Claims are backed by artifacts. `kernel.elf` is verified reproducible
by building twice and diffing; `boot.iso` is not, and `docs/LIMITATIONS.md` §5.3a says why.
Boot-module integrity is tested by *corrupting a module* and asserting rejection. Measured boot
is tested by tampering and asserting the PCRs diverge. Capability revocation carries Kani
proofs. `.github/workflows/ci.yml` runs 103 jobs, most of them QEMU integration self-tests.
Which of them may block a merge is a decision recorded in `.github/ci-gating.yml` and enforced
by the `ci-gating` job: every job must be listed as gating, or exempted with a written reason
(**[C-6]**). The intended set is 105 of its 108 contexts, including every security test; the
ruleset is reconciled to it by hand and lags whenever a gate is added. Read the live count from
`gh api repos/pharanyx-labs/Horus/rulesets/21815299`, not from this sentence; the ruleset is
reconciled by hand, so only the API knows.

---

## The long-term goal

Horus is the high-assurance foundation for a complete operating system. The kernel is not the
destination; it is the smallest thing that must be trusted so that everything above it need not
be.

The path from here is ordered by assurance rather than by demo value:

1. ~~**Make the object model true.**~~ **Done (2026-07-27):** capabilities now mediate
   *which* object, not merely which kind: see **[C-1]**.
2. ~~**Retire ambient `uid == 0` authority**~~ **Done (2026-07-27):** each root-gated syscall
   now demands a distinct capability, so the capability graph is a complete description of
   who can do what, see **[I-1]**.
3. ~~**Kernel objects from untyped memory.**~~ **Done (2026-07-27):** `CAP_UNTYPED` +
   `SYS_RETYPE` replaced the fixed `.bss` tables for cspaces, endpoints and notifications, so
   creating a kernel object is an exercise of authority the graph describes and kernel memory
   is accounted per task, see **[I-7]** (closed 2026-08-30). Since then that includes creating a
   **task**: a spawn carves the child's cspace from the caller's own untyped, so a task holding
   none cannot spawn (**S57**), and `SYS_UNTYPED_SPLIT` hands a delegate a bounded share rather
   than the whole budget (**S58**). The TCB table is carved from untyped too, and how many tasks
   exist is derived at boot from the memory that is there.
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
| **Memory** | Per-task 4-level page tables, demand paging, copy-on-write, NX stacks, kernel W^X, unmapped stack guard pages, 30-bit userspace ASLR, frame capabilities with capability-mediated shared memory, `fork` cloning an address space copy-on-write |
| **Capabilities** | 18 object types, rights masking on delegation, system-wide subtree revocation with a serial-keyed generation backstop; kernel objects (cspaces, endpoints, notifications and memory frames) retyped out of untyped memory a task must hold authority over |
| **Processes** | `spawn` from an embedded or caller-supplied image, exec-in-place, `fork` with a copy-on-write address space and a capability space inherited as *derived* copies, `exec` that replaces the image and touches no capability, `wait` reporting how a task died, signals with handlers and an alternate stack. **No** process groups, job control or `/proc` |
| **Scheduling** | Preemptive (100 Hz PIT / per-CPU LAPIC), full trap-frame context switches, microarchitectural flush on task switch |
| **SMP** | Default on; ACPI MADT enumeration, INIT-SIPI-SIPI bringup, shared runnable pool, acknowledged TLB-shootdown IPIs, SMT siblings parked in software |
| **IPC** | Capability-addressed synchronous send/recv/call/reply over bounded-FIFO endpoints, a blocking receive that sleeps on an empty queue, one-shot reply capabilities, async notifications, per-task private reply endpoints, bounded byte-stream pipes |
| **Filesystem** | `fs_server` in ring 3 over an AEAD-encrypted kernel object store; POSIX rwx against kernel-attested uid/gid; write-ahead journal and mount-time fsck; double-indirect large files; a per-task VFS mount table routing paths to per-mount capabilities |
| **Console** | `console_server` in ring 3 owning the UART and VGA framebuffer; raw terminal mode (termios + winsize) |
| **Devices** | A `CAP_IO_DEVICE` names **one device** in a boot-time table (PCI bus-0 scan plus the non-enumerable legacy platform hardware) and confers only that device's frames, port ranges and interrupt lines. Two ring-3 drivers: `console_server` and `netd`, an Intel e1000 driver proved by a full DMA round trip. It drives e1000 rather than virtio deliberately: a paravirtual device accesses guest memory directly and is not on the far side of the IOMMU at all, so it could not witness DMA confinement. **VT-d DMA remapping**: each device gets an address space that starts **empty**, so it reaches only the frames its driver mapped. An interrupt reaches its ring-3 driver either as an **MSI on a vector the kernel chose** (the driver cannot name one) or through the I/O APIC and masked until acknowledged, so an unserviced device cannot livelock the machine. A device's **MSI-X vector table is unmappable by its driver**, it lives in a BAR, so the vector-choice question had to be answered again there. MSI-X is protected but not yet enabled; no interrupt remapping, no bridge walk |
| **Network** | `netd` drives an e1000 from ring 3 holding one device capability and one untyped region, and its DMA reaches only what it mapped. It is woken by its device's own interrupt and acknowledges it. It transmits; it does **not** receive yet, and there is no ARP table, IP, TCP or socket capability |
| **Storage crypto** | Per-`(inode, block)` AEAD subkeys, Merkle rollback tree, and a TPM NV monotonic counter anchoring the volume against whole-volume rollback; key material never leaves the kernel |
| **Installing** | A ring-3 `installer`, launched by `init` when the machine has a disk carrying no volume. Its whole authority is `CAP_STORAGE_FORMAT` (a capability type of its own — deliberately **not** a rights bit on the storage capability `fs_server` and the shell already hold, since those are granted with every right there is and defining the bit would confer it on both with nothing in the diff to show for it), `CAP_USER` to set the first root password, and a console endpoint. It cannot read the volume it replaces and cannot create a task. **Consent is a typed word, not a menu choice**: a menu whose default is Cancel still becomes a format with two keystrokes. A login still refuses to format a volume it does not recognise. **No partitioning, no bootloader step, one disk**, and installing over an existing volume is refused rather than offered |
| **Boot integrity** | SHA-256 module manifest embedded in the kernel image; TPM 2.0 measurement into PCR 8 and 9; vdisk KEK sealed under `PolicyPCR` |
| **Userspace** | newlib libc, a shell with pipelines, GNU coreutils, TCC |
| **Shared libraries** | A shared object is loaded once into frames and mapped read+exec by many tasks through capabilities that never carry write, so no task can modify code another executes. **Not** yet a dynamic linker: no symbol resolution, and newlib is still statically linked into each program |
| **Assurance** | Every property in `SECURITY.md` is bound by CI to a witness that exists and runs (`tools/check_invariants.py`); every declared count in the docs is derived and compared; every control arm is paired with a base gate |
| **Security core** | `no_std` Rust: ELF parsing and relocation, capability algebra, ChaCha20 CSPRNG, BLAKE2b/SHA-256, AEAD, Argon2 |

**Memory is shared by capability.** A page of shared memory is a `KOBJ_FRAME` retyped out of an
untyped region the creator holds authority over, named by a `CAP_FRAME`, and mapped with
`SYS_MAP_FRAME` into the caller's own address space. Two mutually distrusting tasks reach the
same physical page at two virtual addresses of their own choosing, and the PTE each one gets is
bounded by the rights on the capability it holds, so "you may read this page but not write it"
is expressible, and is what `smoke-frame` asserts on every boot.

**IPC is capability-addressed.** Every IPC syscall takes a cspace slot; the kernel derives the
endpoint or notification from the capability there, checking its type, the right for the
direction, and its lineage generation. A task is born holding exactly one endpoint capability
(its own private reply endpoint) and reaches a service only through a capability something
delegated to it. Clients get WRITE-only capabilities, so a client can send to a server but can
never receive its traffic or forge its replies.

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
whose keys it never releases. Everything else (naming, directories, permissions, terminal
handling, program-loading policy) is userspace.

Full detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## The security model

**Capabilities.** A capability is `{type, rights, object, badge, serial, generation}`. It lives
in a per-task capability space (cspace) and is named by slot index. Userspace never sees the
struct (only the slot number) so it cannot be forged.

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
make test               # cargo test, then a clean rebuild, see the caveat below
make SMP=0              # build without SMP
make DEBUG_SHELL=1      # build with the in-kernel debug shell
make reproducible-build # one SOURCE_DATE_EPOCH build; records both artifacts' hashes
make run-tpm            # boot under an emulated TPM (requires swtpm)
```

Two of those are weaker than their names suggest, and it is better to say so here than to let
someone rely on them.

`make reproducible-build` builds **once** and records `sha256sum` for `kernel.elf` and
`boot.iso` in `.build.sha`. The double-build-and-diff that actually establishes the property
lives only in the `reproducible` CI job, which is a required check; locally, run the target
twice and compare the `kernel.elf` line. Compare that line and not the file: **`boot.iso` is not
byte-reproducible**, because grub-mkrescue stamps a wall-clock UUID into every image it builds.
The ISO's *payload*; the kernel, every boot module, `grub.cfg`, is identical across builds; four
grub-generated objects are not. See `docs/LIMITATIONS.md` §5.3a.

`make test` is the Rust unit tests plus a clean rebuild. It does **not** boot QEMU, so it is not
the full self-test sweep: use the `smoke-*` targets for that.

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
docs/              architecture, syscalls, roadmap, limitations, audit, investigations
site/              the project website published to GitHub Pages
```

---

## Testing

Horus's assurance rests on its tests, so they are treated as first-class. Three layers:

1. **Rust unit tests and Kani proofs**, `cargo test`, plus formal proofs that revocation
   hits exactly the target's derivation subtree.
2. **QEMU integration self-tests**, the bulk of CI's 103 jobs; each boots a purpose-built
   kernel configuration and asserts a marker on the serial console. These cover W^X,
   capability refusals, COW, TLB shootdown, preemption, signals, SMEP/SMAP, measured boot,
   untyped retyping, blocking receive, and more.
3. **Scripted sessions**. Python drivers that type into the real ring-3 shell over serial
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
| [`docs/AUDIT.md`](docs/AUDIT.md) | The current security audit (2026-08-30); predecessors in [`docs/history/`](docs/history/) |
| [`docs/investigations/`](docs/investigations/) | How the harder findings were narrowed, and which hypotheses were wrong |
| [`TESTS.md`](TESTS.md) | Test catalogue |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute, and the invariant-preservation rules |
| [`CHANGES.md`](CHANGES.md) | Changelog |
| [`docs/history/DEVLOG-2026.md`](docs/history/DEVLOG-2026.md) | Development log; the reasoning behind each changelog line |

---

## Contributing

Contributions are welcome, especially to the capability model, formal verification, and
userspace services. Changes to security-critical paths carry an extra obligation: state
which invariant your change preserves, and add the test that witnesses it. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Security

Please report vulnerabilities privately, [`SECURITY.md`](SECURITY.md) has the process and scope.
Known unfixed issues are documented openly in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) and
the current audit; Horus does not hide its weaknesses.

---

## License

MIT, see [`LICENSE`](LICENSE).