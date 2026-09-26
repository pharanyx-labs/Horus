# Horus roadmap

**Objective: a complete operating system on a kernel small enough to verify and a capability
model strong enough to rely on.**

The roadmap is ordered by assurance value, not by demo value. A feature built on an unenforced
foundation adds surface without adding capability, so the order has been: make the object model
true, make kernel objects allocatable, then grow the system on top. Tracks 0 and 1 did the first
two. Track 2 is the operating system; Tracks 3 and 4 run beside it.

Items keep their numbers, because code and other documents cite them. A finished item is one line
in its track's table, naming the pull requests that delivered it; the account is in those pull
requests. What is still wrong, as opposed to still unbuilt, is in
[`LIMITATIONS.md`](LIMITATIONS.md). Finding IDs are explained there.

| Mark | Meaning |
|---|---|
| ✅ | Done and gated in CI |
| ◧ | The item's own goal is met; a named remainder is listed |
| 🚧 | In progress |
| ⬜ | Not started |

---

## What happens next

In order. Each step is its own set of pull requests with its own gates and control arms.

1. **Filesystem phase 1b** (2.10): `fs_server` authorises by capability instead of by uid and
   mode, `hvfs` walks with capabilities, and `init` mints the root capability from a policy file.
   It removes `perm_ok`, the root check on `chown`, `SYS_FS_SET_META`, the uid path of
   `SYS_IPC_SENDER` in the filesystem, and `SYS_CONNECT_FS_SERVER`. Phase 1a, the kernel half,
   is done.
2. **Programs on the disk** (2.11 step 1): the installer copies the system onto the volume
   (`/bin`, `/sbin`, `/lib`, `/tmp`, `/var`, man pages), and the loader refuses any file whose
   hash is not in a manifest pinned inside the measured boot image. The two land together:
   running from the disk must never exist without the check. One question is still open: how
   programs compiled on the machine by `tcc` relate to a manifest-only rule.
3. **A disk that boots itself** (2.11 step 2): a GPT disk with an EFI system partition holding
   GRUB, the kernel and its pinned hash, and the volume as partition 2.
4. **Accounts as files** (2.11 step 3): `/etc/passwd` and `/etc/shadow` on the volume, owned by a
   ring-3 `auth_server`; the kernel keeps only the key-slot unlock.
5. **Filesystem phases 2 to 4** (2.10): the kernel shrinks to a sealed-block service and the
   filesystem moves to ring 3 with a copy-on-write format, then symbolic links, timestamps and
   sparse files, then snapshots, reflinks and extended attributes.

Steps 1 and 4 meet at `/etc/passwd`; whichever lands second adapts to the first.

---

## Track 0: make the object model true ✅

The difference between "a capability-based microkernel" and "a microkernel that has
capabilities in it". Complete.

| Item | Delivered |
|---|---|
| 0.1 ✅ Capability-addressed IPC [C-1], [C-2] | Every IPC syscall takes a cspace slot and the kernel derives the endpoint from the capability there. 2026-07-27, #108 |
| 0.2 ✅ Retire ambient `uid == 0` authority [I-1] | Every uid gate replaced by a held capability. 2026-07-27, #109; the last gate 2026-08-15, #155 |
| 0.3 ✅ Kernel objects from untyped memory [I-7] | `CAP_UNTYPED` and `SYS_RETYPE` carve cspaces, endpoints, notifications, frames and task control blocks; creating a task is paid for (S57) and the budget can be split (S58). 2026-07-27, #111; completed 2026-08-30, #253, #257 |

---

## Track 1: correctness and performance foundations

| Item | Delivered |
|---|---|
| 1.1 ✅ Explicit boot interrupt policy, then a per-CPU spinlock [C-3] | 2026-08-10 to 2026-08-13, #124 to #127, #135 |
| 1.2 ◧ `%gs`-based per-CPU data [I-6] | The performance goal is met another way: `this_cpu()` reads the TSS selector instead of the LAPIC. 2026-07-31, #116 |
| 1.3 ✅ Endpoint queues, reply capabilities, a blocking receive [I-5] | 2026-08-10 to 2026-08-11, #120, #121, #133 |
| 1.4 ✅ Fail-closed user copies [C-4] | 2026-08-13, #141 |
| 1.5 ✅ 64-bit-clean heap arithmetic [I-2] | 2026-08-13, #145 |
| 1.55 ✅ A durable write-ahead journal [I-10], [I-11] | 2026-08-16, #158, #161 |
| 1.6 ✅ Unbounded revocation closure [I-3] | 2026-08-16, #160 |
| 1.7 ✅ Serialise the spawn and exec path [G-10], [G-9] | 2026-08-17 to 2026-08-21, #164, #168, #170, #188 |

### 1.2 ◧ Remainder: a per-CPU block

A per-CPU data block reached through `%gs`, holding a current-task pointer and the per-CPU state
that now lives in `MAX_CPUS`-indexed arrays. It needs `swapgs` on every interrupt entry and exit,
because the ring-3 return paths load a user selector into `%gs` and that zeroes the base. That is
a large change to the most safety-critical assembly in the tree, and nothing is blocked on it.

---

## Track 2: toward a complete operating system

| Item | Status |
|---|---|
| 2.1 ◧ Frames, shared memory and sized regions [F-2.1] | Frame capabilities, all-or-nothing region maps, sized frames, and copy-on-write refused over a frame (S26, S27, S35 to S38). 2026-08-22 to 2026-08-27 |
| 2.2 ◧ Time and timers [F-2.6] | A monotonic clock at 10 ms, deliberately coarse (S34). 2026-08-24, #208 |
| 2.3 ◧ Process and session model [F-2.4] | `fork` with copy-on-write (S39, S40), derived capabilities for the child (S41), and `fork` then `exec` keeping lineage (S42). 2026-08-28 |
| 2.4 ◧ A VFS layer [F-2.2] | A per-task mount table and one path walker in a library, not a server (S29); `init` provisions a server's endpoint from its own budget (S59). 2026-08-22 to 2026-08-30 |
| 2.5 ✅ Dynamic linking and a shared libc [F-2.5] | `libhorus` for the servers (#184); a shared libc handed out by capability, linked by name and sealed, and the shipped programs moved onto it (S106 to S108). 2026-08-21 to 2026-09-26, #465, #467, #468, #470 |
| 2.6 ◧ A network stack in ring 3 [F-2.3] | `netd`, an Intel NIC driver holding one device capability and one untyped region, confined by the IOMMU (S44, S45). 2026-08-28, #227, #228 |
| 2.7a ⬜ Evict the in-kernel services [F-2.7a] | Not started |
| 2.7 ◧ Device drivers in ring 3 | A device capability names one device and reaches only its frames, ports and interrupt lines (S43); interrupts and MSI reach ring 3 with the kernel choosing the vector (S46 to S48). 2026-08-28 to 2026-08-29, #226, #232 |
| 2.8 ✅ A volume large enough to install onto | 4 KiB blocks, no in-RAM metadata mirror, a Merkle rollback tree, a 16 GiB ceiling sized from the disk (S65, S66, S68), and a TPM anchor for whole-volume rollback (S70). 2026-08-31 to 2026-09-01, #270, #273, #274, #276, #279 |
| 2.9 ✅ An installer | A format capability only the installer holds (S72), consent by a typed word after every answer is shown back (S73), a choice of target disk (S82, S83), replacing an existing volume from install media (S90), two accounts that each open the disk (S76), and an optional unencrypted volume (S104). 2026-09-01 to 2026-09-24 |
| 2.10 🚧 A capability-addressed filesystem | Phase 1a, the kernel's endpoint tokens and reply-mint (S105). 2026-09-25, #455 |
| 2.11 ⬜ An installed system | Designed ([`design/installed-system.md`](design/installed-system.md)); a live boot never opens an installed disk (S110, #472) |

### 2.1 ◧ Remainder

- **Reclaiming a frame's memory.** Kernel objects are bump-allocated, so a destroyed frame's page
  is not reusable until its untyped region is revoked and reset, and the reset is not written
  (`LIMITATIONS.md` 2.5).
- `MAX_DYN_FRAMES` (256) bounds how many frames the kernel can name at once, which a real
  workload will meet before it meets its untyped budget.

### 2.2 ◧ Remainder

- **Per-task timers delivered as notifications**, and with them `SYS_IPC_CALL` with a timeout.
  That is a scheduler change.
- **Tickless operation.** The PIT runs at 100 Hz whether or not anything needs it.
- **A libc `clock_gettime`**, and a wall clock, which needs an RTC and a way to trust it.

### 2.3 ◧ Remainder

- **Process groups, job control and `/proc`.** `/proc` would be a filesystem server behind 2.4.
- **Narrowing what a child carries into `exec`.** Today it carries everything its parent held;
  the only subtraction is the child revoking its own slots first.
- **Namespace inheritance**: a spawned or forked child starts with no mounts.

### 2.4 ◧ Remainder

Mount and unmount as syscalls, `/proc`, and namespace inheritance (2.3). `dev_server` runs only in
the `VFS_SELFTEST` build. How files themselves are authorised is being replaced by 2.10.

### 2.6 ◧ Remainder

Everything above Ethernet: an ARP table, IP, TCP and per-application socket capabilities. `netd`
speaks enough Ethernet to prove the device is driven, and receives on the 82574L only
(`LIMITATIONS.md` 2.14).

### 2.7a ⬜ Evict the in-kernel services [F-2.7a]

`.github/ring0-classification.yml` (S87) measures the ring-0 `service` class at about 6,000 code
lines beside a 10,843-line core: `storage.c` (the encrypted store and the on-disk filesystem),
`kusers.c` (accounts and password hashing), the loader and spawn path, `crypto.c` and
`syscall_fs.c`. Neither big move is mechanical. `storage.c` holds the volume key, so moving it
means deciding what a ring-3 storage server may hold; 2.10's phase 2 is that decision for the
filesystem half, and 2.11's `auth_server` for the accounts half. S87 deliberately sets no line
target for the whole kernel: the classification is the property.

### 2.7 ◧ Remainder

Every driver beyond the ones that exist: AHCI reads and writes (the controller is identified and
the drive answers IDENTIFY), NVMe, USB (and with it a keyboard on machines with no PS/2
emulation), and a framebuffer server. Legacy IDE, SD and eMMC are driven in the kernel today.

### 2.10 🚧 A capability-addressed filesystem

The specification is [`design/filesystem.md`](design/filesystem.md), and every load-bearing
question in it has been answered by the maintainer. The disk holds no authority: capabilities are
derived fresh each boot from a policy inside the encrypted, Merkle-verified volume. The kernel
keeps only sealing and opening blocks, and chooses every nonce. The POSIX view is truthful:
`stat` reports what the caller's capability allows, and `chmod` succeeds only when it asks for what
is already true.

| Phase | What lands |
|---|---|
| 1a ✅ | Endpoint tokens, reply-mint and carry-one in the kernel, with Kani proofs (S105) |
| 1b | Capability authorisation in `fs_server`, `hvfs` and `init`, on the existing format |
| 2 | The kernel's sealed-block service; the copy-on-write v12 format in `fs_server` |
| 3 | Symbolic links, timestamps and a time service, cross-directory rename, sparse files |
| 4 | Snapshots, reflinks, extended attributes, quotas, locks, open-unlinked files |

### 2.11 ⬜ An installed system

The specification is [`design/installed-system.md`](design/installed-system.md). Decided on
2026-09-24: programs on the disk are trusted by a manifest of hashes pinned in the measured boot
image, with no signing key; GNU coreutils and TCC ship with their licences; accounts move to
`/etc/passwd` and `/etc/shadow` under a ring-3 `auth_server`; the disk is GPT with an EFI system
partition and no Secure Boot. `init`, `fs_server` and `console_server` stay in the boot image,
because they run before the volume can be read. The three steps are items 2 to 4 of
[What happens next](#what-happens-next).

---

## Track 3: assurance and observability

| Item | Status |
|---|---|
| 3.1 ◧ Reproducible builds | `kernel.elf` is byte-reproducible and gated; `horus.iso` is not (`LIMITATIONS.md` 5.3a) |
| 3.2 ✅ Measured boot and a sealed volume key | TPM PCR measurement, a key sealed to the measurements (S11, S12), the kernel pinned in the boot image (S92), and a policy build that refuses to run unmeasured (S85) |
| 3.3 ✅ Boot-module integrity manifest | A module that fails its hash check cannot be read or run (S10) |
| 3.4 ✅ Kani proofs on revocation | Revocation reaches exactly the target's derivation subtree |
| 3.5 ◧ Proofs over the capability algebra [F-3.1] | Lookup and grant proved, and the bounded proofs gate a merge (`kani-bounded`). 2026-08-23, #205 |
| 3.6 ◧ A debug capability [F-3.2] | `CAP_DEBUG`, read-only, gates cross-task introspection and `SYS_CAP_ENUMERATE`; the shell's `capview` draws the capability graph (S32). 2026-08-23 to 2026-08-24, #206, #209 |
| 3.7 ⬜ Deterministic replay [F-3.3] | Not started |
| 3.8 ◧ KASLR, CFI and sanitisers [F-3.5] | Miri over the Rust core on every pull request (S33). 2026-08-24, #207 |
| 3.9 ⬜ Virtualisation (VT-x) [F-3.4] | Not started |

### 3.5 ◧ Remainder

- **A type check inside `rust_cap_lookup`.** The C `cap_lookup` takes the expected type (S60); the
  Rust side resolves without one, so "lookup refuses a mistyped capability" cannot yet be proved.
  The control arm `CAP_LOOKUP_TYPE_UNCHECKED` reaches only the C build, so the work is three
  parts: pass the type through the FFI, thread the arm into the Rust build so one switch disarms
  both halves, and re-measure that the base gate goes red under it.
- **IPC authority implies a held endpoint capability**, which needs a Rust model of
  `ipc_ep_from_slot`.
- **A sound TLA+ specification.** None exists; the two removed on 2026-09-10 were unsound.

### 3.6 ◧ Remainder

A queryable stream of capability operations (mint, grant and revoke are audited but not
readable as a stream), and `capview` as a program rather than a shell builtin.

### 3.7 ⬜ Deterministic replay [F-3.3]

Record syscall and IPC traces under QEMU and replay them, so an SMP race becomes an artifact.

### 3.8 ◧ Remainder

- **Kernel ASLR.** User programs get 30 bits. The kernel is built `-mcmodel=kernel`, so a slide
  would buy about 9 bits at 2 MiB alignment, and even that needs relocation records packed into
  the image, a relocator that runs before any absolute reference, and early paging aware of the
  slide, all inside the trusted base. The disclosure paths that had to close first are closed
  ([`investigations/kernel-pointer-disclosure.md`](investigations/kernel-pointer-disclosure.md));
  two decisions remain: what to do without UMIP, and whether the kernel log keeps printing raw
  addresses to a `CAP_KERNEL_LOG` holder. It sits behind 2.7a.
- **CFI on indirect calls in the C kernel.** gcc's `-fcf-protection` gives CET/IBT;
  `-fsanitize=cfi` needs clang and LTO.
- **ASan or UBSan over the C kernel**, which needs a freestanding runtime.

### 3.9 ⬜ Virtualisation (VT-x) [F-3.4]

A `CAP_VCPU` object and an EPT-backed guest address space, so a ring-3 monitor holding only its
guest's capabilities can host another operating system.

---

## Track 4: repository, governance and secure development

| Item | Status |
|---|---|
| 4.1 ⬜ Require reviewer approval [C-5] | Needs a second person (below) |
| 4.2 ✅ Gate the security tests [C-6] | Every job is classified as gating or exempt with a written reason in `.github/ci-gating.yml`; the ruleset requires the `gates` aggregator and CodeQL, and `gates` needs every gating job. 2026-08-16 to 2026-09-21, #159, #165, #415 |
| 4.3 ✅ `gitleaks` and `cargo-audit` fail the build | 2026-08-30 |
| 4.4 ⬜ Build provenance and signed artifacts [I-9] | Not started |
| 4.5 ◧ Tagged releases | One so far, `v0.2.0-alpha` (2026-09-14): an install ISO and its SHA-256, for developers. Not yet carrying an SBOM, provenance or the expected PCR values |
| 4.6 ✅ `horus.py` under `tools/` [M-2] | 2026-09-09 |
| 4.7 ✅ Governance files [M-3] | 2026-07-27, #107 |
| 4.8 ⬜ Secret scanning for non-provider patterns [M-4] | Not started |
| 4.9 ✅ One author identity [M-9] | 2026-08-29, #241 |
| 4.10 ✅ Third-party material declared | `THIRD_PARTY.md`, 2026-09-08; the provenance of the 8x8 font's ASCII half is still open |
| 4.11 ⬜ `verify-release.sh` | Not started |
| 4.12 ✅ A security-invariant registry [F-4.1] | `tools/check_invariants.py` binds every `SECURITY.md` property to a witness that runs. 2026-08-28 |
| 4.13 ⬜ Publish the threat model [F-4.3] | The threat model is a section of `SECURITY.md`, not a versioned document |
| 4.14 ⬜ Nightly fuzzing and full Kani | Not started |

**4.1.** The `CODEOWNERS` paths are correct and cover the capability and IPC files. What is left
is a second person to review them. Turning on required approval with one maintainer either blocks
every merge or needs a bypass actor, which would undo 4.2. `SECURITY.md` therefore claims
"thoroughly automatically verified", not "independently reviewed".

**4.2.** The gating set is **136 required, 4 exempted** (137 jobs, 140 contexts; re-derive with
`tools/check_ci_gating.py`). The four exemptions are properties of the test, not open defects:
`fuzz` (a 30-second search is evidence of effort, not absence), `kani` (manual only;
`LIMITATIONS.md` 5.8), `ruleset-audit` (runs on a schedule, never on a pull request) and
`smoke-smp-kvm` (a second run of required gates under KVM, until its pass rate is measured).

**4.4, 4.5 and 4.11** belong together: SLSA provenance and signatures on `kernel.elf` and the ISO,
releases that carry them with the SBOM and the expected PCR values (the one release so far carries
only the ISO and its checksum, from an unsigned tag), and a script a third party runs to rebuild
from a tag and compare. They wait on 3.1, since an ISO that does not rebuild to the
same bytes cannot be verified by rebuilding.

**4.12.** The exemption list in `.github/invariants.yml` is currently
**empty**: all 112 properties name a witness that resolves.

---

## What exists

| | |
|---|---|
| ✅ | 64-bit long mode, a higher-half kernel, booted by GRUB under BIOS or UEFI |
| ✅ | Per-task four-level page tables, demand paging, copy-on-write, NX stacks, kernel W^X |
| ✅ | Capabilities with rights that only narrow, derivation lineage and system-wide subtree revocation |
| ✅ | Kernel objects, tasks included, allocated from untyped memory a task holds a capability to |
| ✅ | Preemptive SMP scheduling on up to eight CPUs, with flush-on-switch barriers |
| ✅ | Ring-3 servers: `init`, `console_server`, `fs_server`, `netd`; one path walker in a library |
| ✅ | An encrypted, Merkle-verified volume with a journal and TPM-anchored rollback protection |
| ✅ | An installer, on IDE disks and SD or eMMC storage, including a laptop's soldered eMMC |
| ✅ | A shell with pipelines, a shared libc, GNU coreutils and TCC |
| ✅ | Measured boot, the kernel pinned in the boot image, and a PCR-sealed volume key |
| ✅ | An IOMMU confining device DMA, and device capabilities that name one device each |
| ◧ | Reproducible `kernel.elf` (not yet the ISO), an SBOM, CodeQL, Dependabot, signed commits, a protected `main` |
| ✅ | 430 `smoke-*` targets, nearly all QEMU integration tests, and 226 of them control arms that must reproduce a defect |
| ✅ | Bounded Kani proofs, Miri over the Rust core, and fuzzing at the FFI boundary |
