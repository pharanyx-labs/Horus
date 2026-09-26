# Horus: known limitations

This is the authoritative list of what Horus does not do, does not enforce, or does badly. It is
written to stop anyone concluding that the system is more ready than it is. Where this document
and the code disagree, the code is right and this document has a defect: please open an issue.

**How to read it.** Sections 1 to 5 hold the entries that are **open** today. Each keeps the
number it was filed under, because code comments and other documents cite those numbers. When an
entry closes it moves to [Closed entries](#closed-entries) as one line: what it was, when it
closed, and the pull request that closed it. The full account of any closed entry is in that pull
request and in the git history of this file.

**Finding IDs.** **[C-n]**, **[I-n]**, **[M-n]** and **[F-n]** come from the 2026-07 audit,
[`history/AUDIT-2026-07.md`](history/AUDIT-2026-07.md). **[G-n]** are architectural gaps
([`ARCHITECTURE.md`](ARCHITECTURE.md) §14). **[H-n]** came from an external audit on
2026-08-15 that is not in the tree. **[HORUS-YYYYMMDD-nn]** are findings filed since, by date,
and "audit F*n*" refers to the 2026-09-19 audit, [`AUDIT.md`](AUDIT.md). A finding has one
status, and it is the one given here.

---

## 1. Security

### 1.6 Two console paths need no capability, by decision

`SYS_WRITE` to fd 1 writes to the console with no capability check, and `SYS_READ` from fd 0
reads a console line with none. Every task has a standard output, and writing to a terminal is not
an authority this system rations. The read side refuses once `console_server` owns the console
hardware, which is from early boot onwards, so in practice console input goes through
`console_server` and its own rules (2.9b). The write side cannot reach the kernel log:
that needs `CAP_KERNEL_LOG` with `WRITE` (**[H-2]**, closed; `SECURITY.md` S23).

This is recorded as a limitation because it is ambient authority, however small, in a system that
otherwise has none. Every other syscall path in the ship kernel is authorised by a capability.

### 1.8 Eleven syscalls have no test that runs their handler

As of the last merge and gated since: **91 of 102** implemented syscalls have their handler body
entered by a tracked workload (the scripted ring-3 session, the conformance suite, and the
boot-modules session). The other 11 are listed in `.github/syscall-coverage.yml`, each with a
written reason. `tools/check_syscall_coverage.py` (required job `syscall-coverage`) fails on drift
in either direction, so the number cannot quietly fall (`SECURITY.md` S25).

The risk is not hypothetical. Four times a probe written to enter an uncovered handler found a
defect on its first run: a kernel hang on a NULL lookup under `cap_lock` (S52), an audit record
declared at two sizes that overran a ring-3 array (S71), block syscalls whose "no such block" and
"permission denied" were the same value, and an ELF loader bounded by the wrong buffer (S84).
So a defect in any of those 11 handlers is invisible in the same way. `captest` cannot find these: it
is a refusal suite, and the capability gate returns before a refused handler runs.

What is left falls into three groups, and the grouping says what each would cost:

- **Gated on a capability `captest` does not hold.** Covering one needs a probe task holding
  exactly that capability, the way `auditprobe` and `blockprobe` were written.
  `SYS_STORAGE_FORMAT` is the exception: entering its body formats the disk the run is using.
- **The call would succeed and replace the caller**: `SYS_FORK` and `SYS_EXEC_NAMED`, each covered
  by its own self-test build rather than a tracked workload.
- **Two `SC_NONE` handlers that cannot usefully be entered**: `SYS_GET_PASS` blocks in the
  `captest` image, and `SYS_SHLIB_INFO`'s interesting body is compiled out of every tracked image.

### 1.12 Rollback protection is anchored only on a machine with a TPM

The Merkle tree catches partial rollback, and since 2026-09-01 a TPM NV monotonic counter bound
into the tree's root catches the whole volume being replaced with an older copy (`SECURITY.md`
S70, `make smoke-rollback`). What remains:

- **Only volumes formatted on a machine with a TPM are anchored.** An unanchored volume has the
  tree and nothing more. No policy flag refuses to mount an unanchored volume.
- **The granularity is one boot.** The counter advances once per unlock, so a rollback to a state
  from a previous boot is refused and a rollback within the current boot is not. Closing that
  would cost a TPM NV write per transaction.
- **Anyone who can talk to the TPM can deny service**, by advancing the counter or undefining the
  index. Neither lets them roll the volume back.
- **An anchored volume is bound to its machine.** Moved to another machine it is refused, and
  there is no export path.

### 1.14 An inherited stdio pipe end escapes revocation **[HORUS-20260911-04]**

A forked child's capabilities are all derived from its parent's (S41), so revoking the parent's
reaches them. `do_spawn`'s stdio wiring does not follow that rule for the one capability it passes
on: `cap_install_child_pipe_end` gives the child's pipe end a fresh serial and `badge = 0`, and
`revoke_subtree` skips `badge == 0`. A revoke of the spawner's end therefore does not reach the
child's. Nothing in the tree revokes a pipe end today, so this contradicts `SECURITY.md` S3 in
principle rather than being a live hole.

**Why the one-field fix cannot land alone.** Setting the badge makes pipe ends reachable by
`revoke_subtree`, which nulls slots without releasing what they owned. A pipe end is two pieces of
state, the capability and a direction count in `pipe.c`, so a revoke that nulls the capability and
leaves the count would leave the peer waiting for an EOF that never comes.

**The design, recorded so the work starts from it.** Recount rather than track deltas: after the
revocation sweep has dropped `cap_lock`, recompute every pipe's `reader_ends` and `writer_ends`
from the cspaces under `pipe_lock` alone. A recount is idempotent and needs no new lock nesting
in `.github/lock-order.yml`. The witness is a new gate (proposed name smoke-pipe-revoke-child,
not yet written) in which a parent revokes its end and the child's must be gone and the peer must
see EOF, with a control arm restoring `badge = 0`. S3 keeps its wording until that arm exists.
This is an authorisation change across `capability.c`, the Rust sweep and `pipe.c`, so it gets its
own pull request.

---

## 2. Correctness

### 2.3 Only retyped kernel objects have a lifecycle

A retyped endpoint, notification or frame (one carved from untyped memory) is destroyed when no
capability names it, found by a mark-and-sweep over the capability graph in
`src/kernel/untyped.c`. The sweep errs towards leaking: a capability whose lineage generation was
bumped still marks its object, because the opposite error is a use-after-free reachable from
ring 3. A frame is also kept while any page table maps it, since a mapping is a second path to the
same bytes.

The **static objects** below `DYN_EP_BASE` and `DYN_NOTIF_BASE` (the well-known service endpoints
and the per-task reply endpoints) are named by the boot protocol rather than by one capability, so
nothing can decide they are dead. They live for the whole boot. Destruction never returns bytes
either: see 2.5.

### 2.5 A destroyed frame's memory is not reused

Kernel objects are bump-allocated from untyped regions, so destroying one frees its **name** and
not its memory. The bytes would come back only if the untyped capability were revoked and the
region's watermark reset, and that reset is not written. A frame's page is therefore consumed for
the life of the boot. This is the seL4 trade taken on purpose: a free list would let a page be
retyped as a different kind of object while a stale capability still names it. The cost is that a
long-running workload that creates and destroys many frames exhausts its region;
`SYS_UNTYPED_INFO` shows it coming.

Three ceilings sit alongside it. `MAX_DYN_FRAMES` (256) bounds how many frames the kernel can name
at once. A frame spans at most `MAX_FRAME_PAGES` (64) pages, 256 KiB, because the user half of
the untyped arena is only 3.5 MiB and a frame that could span it would starve every other object
class. `SYS_MAP_REGION` maps at most 64 frames in one call.

### 2.6b A volume has eight key slots, and only an administrator-set password gets one

Either installed account's password opens the disk (`SECURITY.md` S76). A key slot is granted when
an administrator sets a password; `useradd` alone leaves an account locked and slotless, and a
user changing their own password re-seals the slot they already hold. A volume has
`HORUS_KEYSLOTS` (8) slots, so a machine with more than eight password-holding accounts cannot
give each one. At the ninth, `do_passwd` fails closed with a poor message.

### 2.6c Most gates still read kernel markers from the shared console

The kernel writes a report one byte at a time to a UART that `console_server` also writes from
ring 3, so another task's output can land in the middle of a single kernel message and a gate
matching that message misses it. It has happened in CI. The static rule that gated markers are
written in one piece (`tools/check_split_markers.py`) cannot help here, because the kernel's
message *is* one call.

Since 2026-09-03 the kernel has a channel only it can write: COM3, which no capability names
(`SECURITY.md` S81, `make smoke-kdiag`). **Four gates read it so far**: `smoke-kstack-park`,
`smoke-kstack-reuse` and their control arms. About twenty other gates still match kernel strings
on the shared console and are exposed to the same split.

### 2.6d Only the boot is timestamped, from two clocks

Boot-console lines carry a `[    S.uuuuuu] ` stamp until `init` hands the console to the shell.
After that the console is a terminal and must not be stamped. The kernel stamps from the
calibrated TSC; `console_server` has only the 10 ms monotonic clock (S34), so the two halves
agree only to within a tick and `tools/check_console_timestamps.py` tolerates a small backwards
step. Kernel fault reports bypass the console writer and are unstamped, so a boot with a fault in
it fails that check, which is the intended direction.

### 2.7 A mount point is a name, not a boundary

`userspace/hvfs.c` is a per-task mount table: a path prefix maps to a slot holding a filesystem
server's endpoint capability. A task holding no capability for a mount cannot reach that subtree
(`SECURITY.md` S29). A task that *does* hold a server's capability reaches **all** of that server,
wherever it is mounted: mounting `dev_server` at `/dev` does not confine it to `/dev`.
Confinement is each server's job. The table is per-task, so a child inherits no mounts, and it
holds at most `HVFS_MAX_MOUNTS` (4).

### 2.9 Measured boot is off unless the build asks for it

On a machine with no TPM (and under QEMU without swtpm) boot proceeds: nothing is measured and the
volume key is not sealed, so `SECURITY.md` S11 and S12 do not apply. The boot log says so. A build
with `MEASURED_BOOT_REQUIRED=1` halts when measured boot is unavailable and refuses a persistent
volume that was never sealed (S85, `make smoke-measured-persist`). The default build does not set
it. CI requires swtpm for every TPM gate (`SWTPM_REQUIRED=1`), so those gates cannot pass by
measuring nothing.

### 2.9a Pinning the kernel into the boot image has two costs

The seal binds `PCR[4]`, the firmware's measurement of a boot image that pins the kernel's
SHA-256 (`SECURITY.md` S92). So:

- **A kernel update means resealing.** A new kernel changes the pin, the image and `PCR[4]`, and a
  volume sealed under the old image will not open. A signature scheme would avoid that and was not
  used, because it would make `PCR[4]` the same for every signed kernel.
- **A volume sealed under one firmware does not open under the other.** OVMF and SeaBIOS measure
  different bytes, so a machine that changes firmware mode after an install must reseal.

GRUB's own `tpm` module would let the bootloader measure the kernel instead; it exists only for
`x86_64-efi`, not for the `i386-pc` GRUB the BIOS path uses.

### 2.9b Console input has an owner for passwords only

`CON_OP_GETPASS` is served only to the registered input owner (`SECURITY.md` S93), so a program a
person runs cannot read the password typed at the next `sudo` prompt. `CON_OP_GETLINE` and
`CON_OP_READ_RAW` have no owner, so such a program **can** read command lines as they are typed.
Restricting those needs a foreground-ownership model (one task owns input at a time, and ownership
passes to a child and back), which touches every place the shell spawns a program.

### 2.12 What a device capability does not cover

A `CAP_IO_DEVICE` names one entry in the kernel's device table and reaches only that device's
frames, ports and interrupt lines (`SECURITY.md` S43). It deliberately does not cover:

- **DMA on a machine without an IOMMU.** With VT-d, a device's address space starts empty and holds
  only what its driver mapped (S45). Where there is no DMAR table, `iommu_active()` is 0, the boot
  says so, and a bus-mastering device reaches all of memory.
- **Learning a bus address without a device capability.** `SYS_DMA_ADDR` needs both the frame
  capability and a device capability, on purpose.
- **Discovery.** `SYS_DEVICE_INFO` reports only the device the caller's capability names; there is
  no call to list devices. A driver cannot find a second device it might want: `init` delegates it
  or nothing does.

### 2.14 `netd` receives on one network device model only

`netd` drives an Intel NIC from ring 3. Against QEMU's 82574L (`e1000e`) it sends an ARP request
and receives the reply, and `make smoke-net` gates on that. Against the 82540EM (`e1000`) the reply
almost never reaches the receive ring, and the cause is not known. The address filter, ring
addresses, descriptor layout, device reset, bus mastering and the IOMMU have been ruled out.
`make smoke-net-intx` keeps the 82540EM exercised for its interrupt handling without asserting
reception.

### 2.15 What message-signalled interrupts do not cover

The kernel, not the driver, chooses an MSI vector (`SECURITY.md` S47).

- **MSI-X is protected but not enabled.** Its table lives in device memory a driver could map, so
  that page is refused to the driver (S48). Enabling MSI-X needs per-device work that could not be
  verified here, so a device offering only MSI-X falls back to its legacy interrupt line.
- **A vector is never reclaimed.** A dead driver's route stops delivering, but the vector stays
  allocated. There are sixteen, and the seventeenth request is refused rather than sharing one.
- **Interrupt remapping is off.** What stops a device forging an MSI today is S45: its DMA cannot
  reach the local APIC's message window.

### 2.16 What the shared libc does not do

Shipped programs link against the shared libc by name: the kernel hands its text only to programs
that ask (S106), and crt0's linker resolves each reference, refuses a library it was not built
for, and seals the table read-only (S107, S108). What remains:

- **A task that has bound the library cannot fork.** The library's text is mapped from frames in
  the untyped arena, and `clone_user_aspace` refuses to clone such a mapping. `SYS_FORK` returns an
  error and nothing is shared. None of the shipped programs forks, and the shell is not a libc
  program. This is decision D3 in [`design/shared-libc.md`](design/shared-libc.md).
- **No thread-local storage.** `R_X86_64_TPOFF*` relocations are refused.
- **No wall clock**, so `time()` returns -1 and `gettimeofday` refuses with `ENOSYS`. `tcc`'s
  `__DATE__` and `__TIME__` are the epoch's.
- **The library's address is randomised per boot, not per task.** Shared text must sit at one
  address in every task. The address is drawn at boot from the CSPRNG (S51), but one leak reveals
  it for every task.
- **`hello_shared`, the oldest self-test, still uses the index-based stub archive**, which cannot
  reach library data such as `optarg`. Every shipped program uses the linker instead.

### 2.17 `hello_newlib` is 1.2 MB of real code

It is linked without `--gc-sections`, unlike the coreutils, so it keeps every newlib object it
could call. It is a self-test binary and ships in no default image, so it costs nothing today.

### 2.20 The reply endpoint table is a fixed array

`MAX_ENDPOINTS` is `REPLY_EP_BASE + MAX_TASKS`, so the table always covers every task's reply
endpoint (`SECURITY.md` S95). It is about 336 KiB of `.bss` whether or not a task ever makes a
call. The consistent design is a reply endpoint retyped from the untyped memory that pays for the
task, the way its cspace already is. That touches endpoint resolution, the reachability sweep and
teardown, and the present cost is affordable.

### 2.21 An unencrypted volume is unprotected at rest

The installer can lay down a volume without encryption when the operator chooses it (`SECURITY.md`
S104). Encryption is the default. On an unsealed volume:

- **there is no confidentiality**: `disk_key` is stored in the clear, so anyone with the disk reads
  everything;
- **there is no tamper evidence against someone with the disk**: the tags and the Merkle tree still
  catch accidental corruption, but their keys derive from the same clear key;
- **rollback protection is nominal**, for the same reason;
- **the account passwords still hold**: the shell is behind a login, and a
  `MEASURED_BOOT_REQUIRED` build refuses an unsealed volume.

It does not make installing faster; the metadata region is laid down the same way.

---

## 3. Scale and performance

### 3.1 Compile-time ceilings

| Resource | Limit | Where |
|---|---|---|
| Tasks | 256, provisioned at boot from the kernel's untyped reserve | `MAX_TASKS` sizes the reserve; `g_max_tasks` is what the boot provisioned |
| Capabilities per task | 128 in use, 256 slots | `MAX_CAPS_PER_TASK`, `CNODE_SIZE` |
| CPUs | 8; fewer boot and run on what is present | `MAX_CPUS` (`src/include/cpu_limits.h`) |
| Static endpoints | 320: 64 well-known plus one reply endpoint per task | `MAX_ENDPOINTS` |
| Retyped endpoints, notifications | 256 each | `MAX_DYN_ENDPOINTS`, `MAX_DYN_NOTIFICATIONS` |
| Static notifications | 64 | `MAX_NOTIFICATIONS` |
| Retyped frames | 256, each at most 64 pages | `MAX_DYN_FRAMES`, `MAX_FRAME_PAGES` |
| Untyped arena, user half | 3.5 MiB | `UNTYPED_USER_BYTES` |
| Untyped arena, kernel reserve | 3 MiB: per task, a 10 KiB cspace and 2 KiB of TCB | `UNTYPED_KERNEL_BYTES` |
| Untyped regions nameable at once | 64 | `MAX_UNTYPED` |
| IPC message | 256 bytes | `IPC_MSG_MAX` |
| Boot modules | 48 | `MAX_BOOT_MODULES` |
| Volume | 16 GiB ceiling; the real size comes from the disk | `BLOCKS_PER_DISK` × 4 KiB |
| File | 512 GiB, so in practice the volume is the bound | direct, single, double and triple indirect blocks |
| Inodes | one per 32 blocks | `storage_format_sealed` |
| ATA disk | 128 GiB (LBA28) | `_Static_assert` in `storage.c` |
| Program image | 8 MiB | `LOADER_STAGING_BYTES` |
| Device table | 64 entries | `IODEV_MAX` |

**The kernel image is itself a ceiling.** It must end below `USER_PHYS_BASE` (16 MiB), which the
`linker64.ld` ASSERT enforces. That 16 MiB is the window in which the kernel maps itself with
4 KiB pages, the only place a guard page can exist. GRUB stages boot modules in the same room.
`.bss` is budgeted at **7,532 KiB** (`.github/image-budget.yml`), held exactly by
`tools/check_image_budget.py`, and `argon2_scratch` is 4,096 KiB of it: the Argon2 memory cost,
which must not be cut to buy room. Raising `MAX_CPUS`, `BLOCKS_PER_DISK` or the Argon2 cost spends
that budget; raising `MAX_TASKS` spends pool memory instead.

### 3.3 SMP scheduling is simple

One shared run pool scanned linearly: no affinity, no load balancing, no priorities and no
real-time guarantees. Under TCG emulation more cores are slower than one; the benefit needs KVM or
hardware. Each supported CPU costs about 104 KiB of `.bss` whether present or not, so beyond about
16 the per-CPU blocks would have to be allocated at boot. The scheduler, capability, IPC, spawn,
page and storage locks are each global, so beyond eight to sixteen cores extra CPUs mostly wait.
The SMP race gates run at four CPUs; `smoke-smp-topology` covers bring-up at eight.

### 3.4 One clock, and no timers

`SYS_CLOCK_GETTIME` gives monotonic time since boot at 10 ms resolution, deliberately (S34). There
is no wall clock, no per-task timer, no timeout on IPC, and no libc `clock_gettime`. A blocked task
waits until it is woken or killed. The PIT runs at a fixed 100 Hz.

---

## 4. What does not exist yet

- **A disk that boots itself.** The installer writes the volume over the whole disk, with no
  partition table and no bootloader. An installed machine is started from Horus boot media
  (`horus.iso`), which finds and opens the volume. The install media's menu offers only live boot
  and install, and a live boot opens no disk (S110), so it cannot start an installed system. A GPT
  disk with an EFI system partition is designed in
  [`design/installed-system.md`](design/installed-system.md) and not built.
- **Programs on the disk.** The shipped programs are compiled into the kernel image or loaded as
  measured boot modules; nothing runs from the volume. The manifest-pinned `/bin`, `/sbin` and
  `/lib` of the installed-system design are not built.
- **Networking above Ethernet.** No IP, TCP, sockets or ARP table. `netd` completes one ARP
  exchange (2.14).
- **Storage beyond ATA and SD/eMMC.** Legacy IDE and SD/eMMC are readable, writable and
  installable. AHCI identifies a SATA drive and stops: no reads or writes, so a SATA SSD cannot be
  installed onto. NVMe is not addressed at all.
- **USB.** A machine with no PS/2 controller emulation has no keyboard. On eMMC, write durability
  across a power cut rests on the driver's flush and the laptop's register reading; no emulated
  gate can witness it.
- **Graphics.** A text grid only. The framebuffer console draws an 8x16 font; after the console
  handover, `console_server` draws no cursor on a framebuffer (the kernel's console does). The
  8x8 font used for 80x50 VGA text mode has an ASCII half of unrecorded provenance
  (`THIRD_PARTY.md`).
- **Processes beyond fork and exec.** No process groups, job control, `SIGCHLD` or `/proc`. A child
  of `fork` carries everything its parent held into an `exec`, with no way for the parent to narrow
  it first. One thread per address space.
- **More than one filesystem.** One volume and one `fs_server`, plus `dev_server` in self-test
  builds. The capability filesystem of [`design/filesystem.md`](design/filesystem.md) has its
  kernel half (phase 1a, IPC tokens, S105); the server half is not built.
- **Swap.** Running out of the page pool is a hard failure.
- **Kernel ASLR.** User programs get 30 bits of address randomisation; the kernel loads at a fixed
  address.
- **Other architectures.** x86-64 only, booted by GRUB under BIOS or UEFI.

---

## 5. Process and assurance

### 5.1 No independent review **[C-5]**

Claude writes most of the code and merges its own pull requests once the gates are green; the
maintainer sets direction and decides the questions `CLAUDE.md` reserves for them. The ruleset
requires a pull request and no approving review, so **no human reads a change before it lands.**
The automated verification is extensive; human review is absent. **[C-1]** showed what that
produces: a defect that passed every gate because the suite tested the property the author had in
mind rather than the one the documentation claimed. The honest claim is "thoroughly automatically
verified", not "independently reviewed".

### 5.2i The format trusts its checked writes instead of reading the metadata back

A format used to read its whole metadata region back and hash what it found. It now hashes the one
all-zero block every metadata block was written from, which is sound because every write in the
format is checked. The trade, which was the maintainer's decision on 2026-09-24: a device that
acknowledges a write and does not store it leaves a leaf whose hash disagrees with the disk. That
metadata block is then refused on first use, so the 128 data blocks it describes are unusable
until a reformat. Nothing wrong is ever accepted. `smoke-installer-emmc` fell from about 90 s to
51.5 s; on a real card the saving is projected, not timed.

### 5.3 No release provenance **[I-9]**

There are no tags, no releases, no signed artifacts and no SLSA provenance, so nobody can check that
a `horus.iso` they were given came from this repository's CI. The one network input to the build,
the newlib tarball, is pinned by SHA-256 and checked before unpacking (`make smoke-newlib-tamper`),
so inbound verification is in place; outbound is not.

### 5.3a `horus.iso` is not byte-reproducible; `kernel.elf` is

Two clean builds of the same source give an identical `kernel.elf` and every identical boot
module, and two different ISOs: `grub-mkrescue` writes a file named for the wall-clock second and
embeds a UUID in the EFI loaders it generates. The `reproducible` CI job compares `kernel.elf` and
requires the build record to name both artifacts; it does not compare the ISO. Closing this means
assembling the image with `xorriso` directly or deriving that UUID from `SOURCE_DATE_EPOCH`.
`SECURITY.md` S17 names the kernel image for that reason.

### 5.3b The `RUST_ENABLED=0` build cannot link

`src/kernel/rust_shims.c` reads as a C fallback for the Rust core. It provides a handful of symbols
and the kernel calls forty-nine, so 43 stay unresolved, among them the capability engine, the page
refcounts and the hashes. CI never builds this configuration. Whether a no-Rust build is a goal at
all is undecided; `SECURITY.md` S86's checker refuses a new shim with no subject.

### 5.3e A stale scheduler claim still reproduces under injection

`smoke-switch-commit`'s configuration (`PROC_SELFTEST=1 SCHED_INVARIANTS=1 KSP_GUARD_INJECT=1`)
reported `stale scheduler claim` once in 200 boots under `tools/stress_boot.sh`'s deliberate
contention (four guest CPUs pinned to two host cores). That is an upper bound under a widener, not
the gate's own rate. It is filed as a limitation rather than a finding because it is neither
attributed nor witnessed by a gate that can fail. A campaign without the pinning, or a captured
reproduction (the stress harness now keeps every failure), would settle it.

### 5.4 Cryptography is unaudited and not verified constant-time **[HORUS-20260920-03]**

ChaCha20, SHA-256, BLAKE2b, Argon2id and the AEAD are from-scratch `no_std` Rust with no external
dependency. None has been independently audited and none is verified constant-time. They protect
the measured-boot chain and the sealed volume key (SHA-256), every block of the encrypted store and
the `disk_key` unwrap (the AEAD), every password at rest (Argon2id), and the CSPRNG (ChaCha20). The
tests witness how the primitives are used, not the primitives. The two places a timing leak would
matter most are the password path behind the login prompt and the AEAD over attacker-chosen block
contents. Closing this means an independent audit, or replacing them with an audited `no_std`
implementation, vendored and hash-pinned; both are the maintainer's decision, because the crate's
zero-dependency property is itself part of the supply-chain argument. Writing new primitives is not
the fix.

### 5.5 Formal verification is narrow

Kani proves properties of capability revocation, the ELF validator and the page-pool refcount
arithmetic: **23** harnesses, **21** of them gating in the required `kani-bounded` job. That is the
whole of the formal methods here. The kernel as a whole is not verified, no refinement proof links
a specification to the code, and no TLA+ specification exists (two unsound ones were removed on
2026-09-10).

### 5.7 CI workflows GitHub injects are outside the tree

`tools/check_ci_gating.py` sees the three workflows in `.github/workflows/`. GitHub can also inject
**dynamic** workflows that no commit contains. One did: a GitHub Advanced Security reviewer backed
by Copilot, which failed on every run from 2026-09-19 because the account has no Copilot licence,
could not read any C, header or Rust file, and made network requests to a third party from an
unpinned runtime. The project decided on 2026-09-20 not to use it. It has not run since
2026-09-20 11:34Z; which setting stopped it was not isolated. Nothing in the tree would notice if
another appeared.

### 5.8 The full `kani` job cannot fail, and has never run

The `kani` job in `ci.yml` runs only on manual dispatch, has never been dispatched, and carries
`continue-on-error: true` on both steps, so it could not fail if it ran. Run as written it would
also time out: the two harnesses excused from gating (`.github/kani-harnesses.yml`) were measured
not to finish in 1500 s. The proofs that matter gate through `kani-bounded`. The fix is to point
the job at the two excused harnesses by name, drop `continue-on-error` and give it a matching
timeout, or delete it. Either is a CI classification change for the maintainer.

---

## 6. Completeness estimate

Against "a complete, self-hosting operating system":

| Area | Estimate |
|---|---|
| Boot and low-level x86-64 | 85% |
| Memory management | 70% |
| Capability model, design | 80% |
| Capability model, enforcement | 80% (two console paths stay ambient by decision, 1.6; the pipe-end lineage gap, 1.14) |
| Scheduling | 55% |
| SMP | 50% |
| IPC | 55% |
| Filesystem | 65% |
| Userspace and libc | 65% |
| Drivers | 25% (IDE, SD/eMMC, one NIC, PS/2; no AHCI I/O, NVMe or USB) |
| Networking | 10% (a driver and one ARP exchange; nothing above Ethernet) |
| Formal verification | 10% |
| Build and supply chain | 80% |
| Governance and review | 35% |

**Overall: an early research kernel with unusually thorough instrumentation.** The machinery
around it (measured boot, adversarial CI with control arms, bounded proofs) is more mature than
the operating system it checks. The largest remaining risk is not technical: no second person
reviews the capability paths (5.1).

---

## Closed entries

One line each. The number is kept so that citations resolve; the pull request has the account.

| § | Finding | What it was | Closed |
|---|---|---|---|
| 1.1 | [C-1], [C-2] | IPC was addressed by a global integer, not a capability | 2026-07-27, #108 |
| 1.2 | [I-1], [H-1] | `uid == 0` was a kernel authority beside the capabilities | 2026-07-27, #109; last gate 2026-08-15, #155 |
| 1.3 | [I-4] | `SYS_GET_TASK_INFO` disclosed another task's instruction pointer | 2026-07-27, #109 |
| 1.4 | [C-4] | User copies truncated silently and reported success | 2026-08-13, #141 |
| 1.5 | [I-3] | An unprivileged task could force a broad revocation | 2026-08-16, #160 |
| 1.6a | [H-3] | Four ramfs paths were gated on the slot-3 decoy capability | 2026-08-22, #194 |
| 1.6b | | Task-creating syscalls were gated on the slot-3 decoy | 2026-08-30, #256 |
| 1.6c | | Two ship-build syscalls were gated on the slot-3 decoy (S79) | 2026-09-03, #307 |
| 1.7 | | Two syscall wrappers truncated a buffer pointer to 32 bits | 2026-08-20, #177 |
| 1.9 | | S16 had no witness | 2026-08-28, #222 |
| 1.10 | | A gate was classified as a control arm by its name | 2026-08-30, #251 |
| 1.11 | | The property table's `enforced by` column was parsed and discarded | 2026-08-30, #251 |
| 1.13 | [HORUS-20260911-03b] | `create_task` building a cspace unlocked: withdrawn, not a defect | 2026-09-12, #390 |
| 1.15 | [HORUS-20260919-02] | A verified boot module could change after its hash was taken (S96) | 2026-09-19, #402 |
| 1.16 | [HORUS-20260920-01] | A kernel fault wrote a kernel text address into a ring-3 exit record (S97) | 2026-09-21, #412 |
| 1.17 | [HORUS-20260920-02] | A reused task slot kept its predecessor's wait record (S98) | 2026-09-21, #413 |
| 1.18 | [HORUS-20260921-01] | Any task could wait on any task (S99) | 2026-09-21, #414 |
| 1.19 | [HORUS-20260921-02] | A capability for a dead task named whatever reused its slot (S100) | 2026-09-21, #417 |
| 1.20 | [HORUS-20260921-03] | A spawn could reuse a slot whose kernel stack a CPU was still on (S20) | 2026-09-21, #421 |
| 1.21 | [HORUS-20260921-04] | A task killed while running on another CPU kept running (S56) | 2026-09-22, #423 |
| 2.0 | [C-3] | Spinlock interrupt state was global | 2026-08-13, #135 |
| 2.1 | [I-2] | Heap syscalls truncated 64-bit arithmetic | 2026-08-13, #145 |
| 2.2 | [I-5] | Endpoints were single-slot mailboxes | 2026-08-10, #120 |
| 2.25 | [I-10] | The write-ahead journal was not durable on real hardware | 2026-08-16, #158 |
| 2.4 | | Copy-on-write had one producer; `fork` is now the second (S39, S40) | 2026-08-28, #225 |
| 2.5a | [HORUS-20260919-01] | The physical free path was safe by its callers, not by construction (S102) | 2026-09-22, #425 |
| 2.6 | | User accounts did not survive a reboot (S62) | 2026-08-31, #267 |
| 2.6a | | Self-test markers written in pieces could be split; now refused by `tools/check_split_markers.py` (kernel markers are 2.6c) | 2026-09-01, #268, #284 |
| 2.8 | | The CSPRNG was safe by boot ordering, not by construction (S30) | 2026-08-23, #200 |
| 2.10 | | Four live syscalls had no caller | 2026-08-23, #204 |
| 2.10a | | Two more uncalled syscalls, retired with 1.6c (S79) | 2026-09-03, #307 |
| 2.11 | | A forked child did not inherit its parent's cspace (S41) | 2026-08-28, #221 |
| 2.13 | | A PCI interrupt line could not be delivered to ring 3 (S46) | 2026-08-28, #232 |
| 2.18 | | The `.bin` container was declared four times and parsed in eleven places (S80) | 2026-09-03, #308 |
| 2.19 | | The end of a directory and its absence were the same answer | 2026-09-06, #318 |
| 3.2 | [I-6] | `this_cpu()` read LAPIC MMIO on every call | 2026-07-31, #116 |
| 3.5 | | The block allocator rescanned the bitmap from the start | 2026-09-01, #277 |
| 5.2 | [C-6] | Which checks gate a merge was reconciled by hand | 2026-09-21, #415 |
| 5.2b | [I-11] | A required check was nondeterministic by construction | 2026-08-16, #161 |
| 5.2c | [G-8] | The SMP session soak: a task was claimable while its old CPU was still on its stack | 2026-08-17, #162 |
| 5.2d | [G-9] | Claims leaked and kernel stacks collided on the spawn and reap path | 2026-08-21, #188 |
| 5.2e | [G-10] | The spawn and exec path was unserialised process-wide state | 2026-08-18, #168, #170 |
| 5.2f | [G-11] | The armed image was ambient state that `sudo` would elevate | 2026-08-18, #170 |
| 5.2g | [G-12] | Two CPUs current on one task through the user-entry path | 2026-09-03, #305 |
| 5.2h | [G-13] | The installer gate's format bound was a total, not a stall | 2026-09-03, #306 |
| 5.3c | | Horus could not be reinstalled over an existing Horus volume (S90) | 2026-09-11, #381 |
| 5.3d | | Six checkers examined nothing and passed when their parser went silent | 2026-09-10, #368, #369, #375 |
| 5.6 | [M-3] | Governance files were in the wrong place | 2026-07-27, #107 |
