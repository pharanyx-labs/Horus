# Horus roadmap

**Objective: a complete operating system on a kernel small enough to verify and a capability
model strong enough to rely on.**

This document holds only open work, in the order that finishes all of it soonest. Rewritten on
2026-10-12. A finished item leaves it for [`history/ROADMAP-DONE-2026.md`](history/ROADMAP-DONE-2026.md),
one line with its pull requests; numbers are never reused, so a citation of a finished item
resolves there. What is wrong, as opposed to unbuilt, is in [`LIMITATIONS.md`](LIMITATIONS.md),
which is the authoritative status of every finding.

| Mark | Meaning |
|---|---|
| 🚧 | In progress |
| ⬜ | Not started |
| ⏸ | Waits on a decision below |

---

## 1. Decisions that unblock the route

Each blocks only the work named. Answering them in one sitting removes every wait from the route.
The recommendation is the one the route is written around; it is not the decision.

| | Question | Recommendation | Blocks |
|---|---|---|---|
| D3 | Measured boot mandatory whenever a TPM is present | Yes, failing closed; a machine without a TPM boots with a visible warning | 5.6 |
| D4 | Refuse an unanchored volume on a TPM machine; advance the rollback counter at a bounded interval; eMMC RPMB as a second anchor | Yes to the first two; RPMB opt-in only, since programming its key is irreversible | 5.7 |
| D5 | Kernel updates by predicted PCR values and a staged second seal | Yes, over signed kernels, which would make `PCR[4]` the same for every signed kernel | 5.8 |
| D7 | `SYS_SPAWN_IMAGE` needs a capability no session holds; exec goes through a file capability | Yes | 5.4 |
| D8 | One capability per grant, bounded by the kernel, instead of one root carrying the union | Yes | 5.10 |
| D9 | TLA+, and its Java toolchain, as a new verification dependency | Yes, nightly first; a full Isabelle model of the kernel is not recommended at this size of team | 5.11 |
| D10 | How releases are signed: key type and custody | Sigstore keyless signing from the release workflow with SLSA provenance, actions pinned by SHA, and tags signed by the maintainer's key | 4.4 |
| D11 | A second reviewer for the capability and IPC paths | The maintainer's to find; the ruleset change follows | 4.1 |
| D12 | Whether to build virtualisation at all | Defer until there is a hosting need | 3.9 |
| D13 | A syscall operation by which a task marks pages that hold secrets as never swapped | Yes, as an operation on the task's own pages only, refusing shared and lent frames | 2.12 remainder |
| D15 | CI throughput: a merge queue, and a fast path that skips the QEMU gates for a change touching only documentation | Yes to both; the fast path decided by a checked allowlist of paths, never by a label | The pace of everything |

---

## 2. The route

**How it stays fast.** CI time is the bottleneck, so the route minimises full CI runs:

- **One pull request per milestone**, not per step. A milestone is the row of a lane below; its
  documentation, counts and arms travel in the same pull request.
- **Local gates first.** Every touched gate and its control arms run locally before the first push,
  the SMP ones under KVM as well as TCG. A push is never a way to find out.
- **Lanes in parallel**, each in its own worktree. Lanes in one wave touch different subsystems, so
  they merge in a train without conflicts beyond the derived counts.
- **One merge of `main` per pull request**, immediately before it is merged, with the counts synced
  by the checker rather than by hand.
- **Decisions answered up front** (section 1), so no lane stops part-way.

### Wave 1: close the holes, build the enablers

| Lane | Milestone | Items | Closes | Needs |
|---|---|---|---|---|
| Filesystem | A policy on every installed system, then the uid path removed | 2.10 steps 3(c), 6 | 1.31 | |

### Wave 2: authority completes, the boot chain tightens

| Lane | Milestone | Items | Closes | Needs |
|---|---|---|---|---|
| Filesystem | Accounts as files, then exec by capability | 2.11 step 3, 5.4 | 1.23 | Wave 1 filesystem, D7 |
| Console | Job control: stopping and resuming the foreground program | 2.3 job control | | |
| Boot | Measured boot by default, rollback anchoring | 5.6, 5.7 | 2.9, 1.12 | D3, D4 |
| Supply chain | Verifiable releases, then updates without a lockout | 4.5, 4.4, 4.11, then 5.8 | 5.3, 2.9a | D10, D5 |
| SMP | Per-CPU run queues, one-shot timers, timers as notifications | 1.8 steps 2 and 3, 2.2 | | |
| Memory | Reclaimable kernel memory | 5.9, 2.1 | 2.5, 2.3 | |
| Proofs | Typed lookup proved, IPC authority modelled, concurrent protocols modelled | 3.5, 5.11 | narrows 5.5 | D9 |
| Swap | Secrets kept out of swap | 2.12 | | D13 |

### Wave 3: shrink ring 0

| Lane | Milestone | Items | Closes | Needs |
|---|---|---|---|---|
| Filesystem | The kernel a sealed-block service, v12 in `fs_server` | 2.10 phase 2, the storage half of 2.7a | | Wave 2 filesystem |
| Filesystem | A session's grants bounded by the kernel | 5.10 | 1.24 | phase 2, D8 |
| Kernel | The loader and spawn path out of ring 0, and no disk I/O in ring 0: the IDE, SD and eMMC drivers replaced by ring-3 ones | 2.7a, 2.7 | | phase 2 |
| SMP | Scheduling contexts, passive servers, affinity, more than eight CPUs, then the `%gs` block | 1.8 steps 4 to 8, 1.2 | | Wave 2 SMP |
| Hardening | Indirect-branch tracking, then kernel ASLR | 3.8 | | 2.7a |
| Observability | The audit stream, then deterministic replay | 3.6, 3.7 | | |

### Wave 4: grow outward

| Lane | Milestone | Items | Needs |
|---|---|---|---|
| Filesystem | Links, timestamps, sparse files; then snapshots, reflinks, extended attributes | 2.10 phases 3 and 4 | phase 2 |
| Drivers | NVMe installable by the ring-3 storage route, then AHCI, then xHCI with USB keyboards | 2.7 | Wave 3 kernel |
| Network | IP, UDP, TCP and socket capabilities | 2.6 | |
| Processes | `/proc`, mounts as syscalls, namespace inheritance, narrowing what `exec` carries | 2.3, 2.4 | |
| Time | A wall clock and `clock_gettime` | 2.2 | Wave 2 SMP |
| Virtualisation | `CAP_VCPU` and EPT | 3.9 | D12 |

### Beside every wave

Independent review (4.1, D11), the published threat model (4.13), secret scanning beyond
provider patterns (4.8), and the font's provenance (4.10). An external audit at each release, its
findings recorded in `LIMITATIONS.md` and each closed by a gate, until a second reviewer exists.

---

## 3. The open items

Grouped by track; the numbers are the ones the code cites.

### Track 1: correctness and performance foundations

**1.2 ⬜ The `%gs` per-CPU block.** A per-CPU data block reached through `%gs`, holding a
current-task pointer and the per-CPU state that now lives in `MAX_CPUS`-indexed arrays. It needs
`swapgs` on every interrupt entry and exit, with the speculative-`swapgs` barriers, because the
ring-3 return paths load a user selector into `%gs` and that zeroes the base. A large change to
the most safety-critical assembly in the tree; nothing is blocked on it, so it comes last in SMP.

**1.8 🚧 Per-CPU scheduling, with CPU time as a capability.** Designed in
[`design/scheduler.md`](design/scheduler.md); steps 0, 1, 1b and 2a are done. Next, step 2: per-CPU
run queues, the reschedule interrupt and stealing, with no policy change. Then step 3, per-CPU
one-shot timers and tickless idle; then scheduling contexts and budgets (4), passive servers (5),
affinity (6), more than eight CPUs (7) and targeted shootdown (8).

### Track 2: toward a complete operating system

**2.1 ⬜ Reclaiming a frame's memory.** Part of 5.9. `MAX_DYN_FRAMES` (256) bounds how many frames
the kernel can name at once, which a real workload meets before its untyped budget; it becomes a
table sized from the budget.

**2.2 ⬜ Timers and a wall clock.** Per-task timers delivered as notifications, and with them
`SYS_IPC_CALL` with a timeout, following the one-shot timers of 1.8 step 3 (which also end the
fixed 100 Hz tick). Then a libc `clock_gettime`, and a wall clock, which needs an RTC and a way to
trust it.

**2.3 ⬜ Processes.** Process groups and job control, built on the input capability the shell
already lends to the foreground program and takes back when it ends (S93), so stopping a program
takes it back and resuming lends it again; `/proc` as a filesystem server behind 2.4; narrowing
what a child carries into `exec` (today it carries everything its parent held); and namespace
inheritance.

**2.4 ⬜ Mounts.** Mount and unmount as syscalls, `/proc`, and namespace inheritance: a spawned or
forked child starts with no mounts. `dev_server` runs only in the `VFS_SELFTEST` build.

**2.6 ⬜ Networking above Ethernet.** An ARP table, IP, UDP and TCP in `netd`, a socket as a tokened
endpoint capability per connection, and DHCP. `netd` receives on the 82574L only (LIMITATIONS
2.14) and runs only in the `NET_SELFTEST` build; shipping it is part of this item.

**2.7 🚧 Drivers in ring 3.** Each under one device capability and the IOMMU. Three storage
drivers run in ring 3 in self-test builds, each proved by a write checked on the host: `nvmed`
drives an NVMe controller (`make smoke-nvme`), `sdhcid` an SD card or eMMC device
(`make smoke-sdhcid`) and `atad` an IDE disk (`make smoke-atad`), the last two with no memory to
give their controllers, since they move data by PIO. All three serve the block-driver protocol
(`make smoke-blkproto`, S136), which holds each client to the extent of the disk its token was
bound to. The IDE controller's ports are declared for ring 3 only in `atad`'s self-test build,
so no task can be granted them while `ata.c` drives the controller (S137). The kernel never waits
on a ring-3 task mid-call, so none of them can serve the kernel's storage; they become disks the
system stores to when the kernel stops doing disk I/O, and the ring-0 drivers are then deleted
([`design/ring3-storage.md`](design/ring3-storage.md)): filesystem phase 2 (2.10) next, then swap
through a ring-3 driver, then the cutover. NVMe then installs by the
same path as eMMC. After that, interrupts once MSI-X is enabled, AHCI reads and writes (the
controller is identified and the drive answers IDENTIFY), USB through xHCI (and with it a keyboard
on machines with no PS/2 emulation), and a framebuffer server.

**2.7a ⬜ Evict the in-kernel services [F-2.7a].** `.github/ring0-classification.yml` (S87) measures
the ring-0 `service` class at about 6,000 code lines beside a 11,856-line core: `storage.c` (the
encrypted store and the on-disk filesystem), `kusers.c` (accounts and password hashing), the loader
and spawn path, `crypto.c` and `syscall_fs.c`, and the IDE, SD and eMMC drivers sit in ring 0 too.
The drivers leave by [`design/ring3-storage.md`](design/ring3-storage.md), storage with 2.10 phase
2, accounts with 2.11 step 3's `auth_server`, and the loader as a ring-3 spawn server that builds a
task's address space through frame and untyped capabilities, the ELF validator staying in the Rust
core. S87 sets no line target for the whole kernel: the classification is the property.

**2.10 🚧 A capability-addressed filesystem.** Specified in [`design/filesystem.md`](design/filesystem.md),
every load-bearing question answered. The disk holds no authority: capabilities are derived fresh
each boot from a policy inside the encrypted, Merkle-verified volume, and the POSIX view is
truthful. Phase 1b's steps 1, 2, 4 and 5 and steps 3(a) and 3(b) are done. Open:

| Step | What lands |
|---|---|
| 3(c) | The installer writes `/etc/fs.policy`, with read grants on `/etc/shell.conf` and `/etc/login.conf` for every account (`design/configuration.md`) |
| 6 | The identity path removed: `perm_ok`, the root check on `chown`, the uid half of `SYS_IPC_SENDER` in the filesystem, `SYS_FS_SET_META` and `SYS_CONNECT_FS_SERVER`. Closes LIMITATIONS 1.31 |
| Phase 2 | The kernel's sealed-block service, its calls taking and returning ciphertext so that `fs_server` moves the blocks through a ring-3 driver ([`design/ring3-storage.md`](design/ring3-storage.md)), and the copy-on-write v12 format in `fs_server`, whose pointer tree is the Merkle tree, so all metadata is authenticated; separate system and home volumes |
| Phase 3 | Symbolic links, timestamps and a time service, cross-directory rename, sparse files |
| Phase 4 | Snapshots, reflinks, extended attributes, quotas, locks, open-unlinked files |

**2.11 🚧 An installed system, step 3: accounts as files.** `/etc/passwd` and `/etc/shadow` on the
volume under a ring-3 `auth_server`; the kernel keeps only the key-slot unlock
([`design/installed-system.md`](design/installed-system.md)). Steps 1 and 2 are done.

**2.12 ⏸ Secrets kept out of swap.** A request by which a task marks pages that hold secrets as
never swapped ([`design/swap.md`](design/swap.md) step 3); a new syscall operation, so D13 first.
Compressed memory stays deferred: if it comes, it is a cache in front of swap that compresses one
task's pages only, never a page marked secret, and charges each task for its own.

### Track 3: assurance and observability

**3.5 ⬜ Proofs over the capability algebra.** A type check inside `rust_cap_lookup` and its proof,
with the `CAP_LOOKUP_TYPE_UNCHECKED` arm reaching the Rust build too, so one switch disarms both
halves; a Rust model of `ipc_ep_from_slot` and a proof that IPC authority implies a held endpoint
capability; and a checker that every `rust_cap_*` export has a Kani harness.

**3.6 ⬜ The audit stream.** Mint, grant and revoke are audited but not readable as a stream; make
them a stream readable through `CAP_DEBUG`, and `capview` a program rather than a shell builtin.

**3.7 ⬜ Deterministic replay [F-3.3].** Record syscall and IPC traces under QEMU and replay them,
so an SMP race becomes an artefact rather than a rate.

**3.8 ⬜ Kernel ASLR, CFI and sanitisers [F-3.5].** Indirect-branch tracking first, with gcc's
`-fcf-protection=branch`, since it needs no new toolchain. Kernel ASLR after 2.7a: the kernel is
built `-mcmodel=kernel`, so a slide buys about 9 bits at 2 MiB alignment and needs relocation
records in the image, a relocator before any absolute reference, and early paging aware of the
slide. The disclosure paths that had to close first are closed
([`investigations/kernel-pointer-disclosure.md`](investigations/kernel-pointer-disclosure.md)); two
decisions remain, taken when the work starts: what to do without UMIP, and whether the kernel log
keeps raw addresses for a `CAP_KERNEL_LOG` holder. ASan or UBSan over the C kernel needs a
freestanding runtime.

**3.9 ⏸ Virtualisation (VT-x) [F-3.4].** A `CAP_VCPU` object and an EPT-backed guest address space,
so a ring-3 monitor holding only its guest's capabilities can host another operating system. A
large addition to ring 0, which everything else here shrinks; D12 first.

### Track 4: repository, governance and secure development

**4.1 ⏸ Require reviewer approval [C-5].** `CODEOWNERS` covers the capability and IPC paths. What is
missing is a second person (D11); required approval with one maintainer would block every merge or
need a bypass actor, which would undo the gating. Until then `SECURITY.md` claims "thoroughly
automatically verified", not "independently reviewed".

**4.4 ⏸ Build provenance and signed artefacts [I-9].** SLSA provenance and signatures on `kernel.elf`
and the ISO, in the form D10 picks.

**4.5 ⬜ Releases that carry their evidence.** The four releases so far carry an ISO and its checksum
from an unsigned tag. Each release also carries the SBOM, the provenance of 4.4 and the expected PCR
values.

**4.8 ⬜ Secret scanning for non-provider patterns [M-4].**

**4.10 ⬜ The 8x8 font's provenance.** `THIRD_PARTY.md` declares everything else; the origin of the
font's ASCII half is still open.

**4.11 ⬜ `verify-release.sh`.** A script a third party runs to rebuild from a tag and compare with
the release, including the PCR values. Needs 4.5.

**4.13 ⬜ Publish the threat model [F-4.3].** It is a section of `SECURITY.md`, not a versioned
document.

### Track 5: closing the known limitations


**5.4 ⏸ Exec only from a file capability** (1.23). A spawn call that takes a file capability carrying
`EXEC`, with `fs_server` supplying the bytes through it; `SYS_SPAWN_IMAGE` then needs a capability no
session holds (D7). A compiler's output still runs, from a home the policy grants `EXEC`. Witness: a
session holding a readable, non-`EXEC` file cannot run it by either route.

**5.6 ⏸ Measured boot whenever a TPM is present** (2.9). A machine with a TPM fails closed when
measurement or sealing fails; one without boots, says so at install and at every login, and the
installer records it. The `MEASURED_BOOT_REQUIRED=1` build stays, for deployments that refuse
TPM-less machines.

**5.7 ⏸ Rollback anchoring** (1.12). Refuse an unanchored volume on a machine with a TPM unless the
installer recorded it as deliberate; advance the counter at clean shutdown and at a bounded interval
of writes, shrinking the window from one boot to that interval; later, opt-in, eMMC RPMB as a second
anchor; and an export path for a volume moved between machines.

**5.8 ⏸ Kernel updates without a lockout** (2.9a). Compute the PCR values a new boot image will
produce, seal a second copy of the volume key to them before rebooting, and drop the old seal only
after the new image has unlocked once. Needs D5; the reproducible ISO it relied on is done (#557).

**5.9 ⬜ Reclaimable kernel memory** (2.5, then 2.3). The untyped reset: revoking an untyped
capability destroys everything carved from it, and the watermark is reset and the pins cleared only
when nothing names or maps any of it. Then a ring-3 allocator in `init` recycles regions, and the
static objects become retyped ones: a task's reply endpoint carved at creation and destroyed at
teardown, the service endpoints carved by `init`. Witness: a workload that creates and destroys
frames for longer than its region could hold without reuse.

**5.10 ⏸ A session's grants bounded by the kernel** (1.24). One capability per grant instead of one
root carrying the union; the walker starts from the capability with the longest matching grant, so
the kernel's rights intersection bounds each grant and `fs_server` is trusted only for contents.
After 2.10 phase 2, whose back-references also let the server tell a grant's object from a name
swapped in under it. D8 first.

**5.11 ⏸ A model of the concurrent protocols** (5.5). The protocols where races have happened,
specified and model-checked: spawn, wait and teardown (S125), the kernel-stack claim and park (S20),
the TLB shootdown (S124), and revocation against lookup. Each model ships with a seeded defect it
must catch, as every gate has an arm. Nightly first. D9 first.
