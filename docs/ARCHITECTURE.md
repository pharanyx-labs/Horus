# Horus architecture

How Horus is built, why, and which invariants each subsystem is responsible for. Written for
contributors who need to understand the system before changing it, and for reviewers judging the
design. Where this document and the code disagree, the code is right; please open an issue.

## Contents

1. [Design philosophy](#1-design-philosophy)
2. [Boot and memory layout](#2-boot-and-memory-layout)
3. [The C / Rust split](#3-the-c--rust-split)
4. [Capabilities](#4-capabilities)
5. [Address spaces and paging](#5-address-spaces-and-paging)
6. [Tasks and scheduling](#6-tasks-and-scheduling)
7. [SMP](#7-smp)
8. [IPC and notifications](#8-ipc-and-notifications)
9. [The syscall layer](#9-the-syscall-layer)
10. [Userspace servers](#10-userspace-servers)
11. [Storage and the encrypted object store](#11-storage-and-the-encrypted-object-store)
12. [Trusted boot and the TPM](#12-trusted-boot-and-the-tpm)
13. [Side-channel posture](#13-side-channel-posture)
14. [Known architectural gaps](#14-known-architectural-gaps)

---

## 1. Design philosophy

Horus is a microkernel in the seL4 tradition, with three commitments.

**The kernel does the minimum.** It owns address spaces, tasks, capabilities, IPC, and an
encrypted block store whose keys it never releases. Filenames, directories, permissions, terminal
behaviour and program-loading policy live in ring-3 servers that hold only the capabilities they
need. Some policy is still in ring 0 (the on-disk filesystem, accounts, ELF loading), and moving
it out is tracked as gap G-14.

**Authority is explicit and only narrows.** Everything a task can do traces to a capability it
holds. Capabilities are delegated downwards, never acquired upwards, delegation can only reduce
rights, and revocation reaches everything derived.

**Every claim has a witness.** Each security property in `SECURITY.md` names the test or proof
that would fail if it broke, and each such test has a control arm that puts the defect back and
must turn it red.

### What is in the trusted computing base

- The kernel: `src/kernel/`, `src/boot/` and the Rust core in `rust/src/`.
  `.github/ring0-classification.yml` classifies every object linked into it (S87).
- `init` (`userspace/init.c`), the delegation root for every server.
- `fs_server`, the reference monitor for files.
- `console_server`, which owns the console hardware and so sees all terminal traffic.
- GRUB and the platform firmware, up to where measured boot takes over.

The shell, the coreutils, `tcc` and user programs are outside it by design.

---

## 2. Boot and memory layout

### The boot sequence

1. **GRUB**, under BIOS or UEFI, checks `kernel.elf` against the SHA-256 pinned in the boot image
   (S92), loads it with Multiboot2 at physical 1 MiB, and loads the `module2` payloads above it.
   The command line carries the boot mode chosen at the menu (`horus.live` or `horus.install`).
2. **`src/boot/multiboot.S`** runs in 32-bit protected mode: enables PAE, builds the initial page
   tables, sets `EFER.LME` and `EFER.NXE`, enters long mode and jumps to the higher half.
3. **`kernel_main`** (`src/kernel/main.c`) reads the multiboot2 tags (memory map, modules,
   framebuffer, command line), sizes the physical pool and places its reserves clear of every
   module (S96), verifies each module against the embedded manifest, measures the command line,
   manifest and modules into the TPM, initialises paging, capabilities, the scheduler, the IOMMU,
   devices and storage, hashes the verified modules again (S96), and starts `init` in ring 3.

### Virtual memory layout

```
0xFFFFFFFF_80100000   kernel image (.text r-x, .rodata r--, .data/.bss rw-)  = KERNEL_VMA + 1 MiB
high_pdpt[511]        per-task kernel stacks, each above an unmapped guard page
high_pdpt[509]        the framebuffer window, when there is one
0xFFFFFF80_80000000   PHYS_KVA window: physical [0, 1 GiB), then the RAM in [1, 4 GiB)
0x00000000_xxxxxxxx   userspace: image, heap, stack (per task, randomised)
```

`KERNEL_VMA` is fixed by `linker64.ld` and shared with the boot assembly through
`src/include/kernel_vma.h`. Two translations exist and must not be confused: `virt_to_phys` and
`phys_to_virt` are for kernel image symbols only, and `PHYS_KVA(p)` is for arbitrary physical
addresses such as fresh frames and page tables. The kernel half, including the `PHYS_KVA`
window, is copied into every task's PML4 (`pml4[256..511]`), so it resolves on any CR3; the
demand pager must use it, because faulting inside the fault handler while holding `page_lock`
with interrupts off wedges the machine.

### Physical memory

The page pool starts at `USER_PHYS_BASE` (16 MiB, above the kernel image) and spans every region
the firmware memory map calls available, up to 4 GiB (a frame address is 32 bits). What lies
between regions is never handed out, and above 1 GiB only whole 2 MiB chunks of RAM count, because
the `PHYS_KVA` window maps that range with 2 MiB pages over RAM and nothing else (S117). The pool's
per-frame tables (free stack, refcounts, loan bits) are sized for the span at boot and placed at
the top of RAM, clear of modules and the reserves. Three regions are held back from it as one reserved window: the 8 MiB loader
staging buffer, the RAM volume's backing store and the untyped arena (§4). The window moves clear
of any boot module GRUB placed there and of holes in the map, and every frame a module occupies
is held back too (S96).
Modules below 1 MiB are kept, since UEFI GRUB puts small ones in conventional memory there, and a
module over the AP trampoline page, which the kernel writes when it starts the other CPUs, halts
the boot as one over the kernel image does.
The kernel stacks are mapped from ordinary pool frames on first use. The kernel image itself must
end below `USER_PHYS_BASE`, and `.bss` has an exact budget (`.github/image-budget.yml`).

The untyped arena has two halves: a **kernel reserve** sized from `MAX_TASKS` (one cspace and
task control block per task, never nameable by a capability) and a fixed **3.5 MiB user half**
(`UNTYPED_ROOT`), which `init` delegates onwards.

---

## 3. The C / Rust split

The kernel is C; the security core is `no_std` Rust compiled to a static library and linked with
`--whole-archive`. The split is drawn by attack surface: code that parses bytes an attacker or
firmware controls, or that enforces an algebraic security property, belongs in Rust.

| Module | Responsibility |
|---|---|
| `capability.rs` | The capability algebra: lookup, mint, grant, transfer, reply-mint, subtree revocation, serial allocation |
| `lib.rs` | ELF header and program-header validation, load planning, i386 and x86-64 relocation |
| `crypto.rs`, `aead.rs`, `sha256.rs`, `blake2b.rs`, `argon2.rs` | Cryptographic primitives, including HKDF |
| `rng.rs` | The ChaCha20 CSPRNG, which refuses output until seeded (S30) |
| `memory.rs` | Pointer and range predicates, and the page-pool reference counts |
| `audit.rs` | The forward-secure audit log |
| `auth.rs`, `ps.rs` | Authentication and process-listing helpers |

Moving the ELF loader to Rust found two out-of-bounds bugs in the C original.

### The FFI contract

`capability_t` in C and `Capability` in Rust are the same memory, and layout drift is a compile
error on both sides: each asserts every field offset. **Every Rust FFI function checks its own
inputs**; none assumes the C side did. Every `unsafe` carries a `# Safety` section stating what
the caller must uphold (S54, checked by `unsafe-safety`), and every exported symbol must have a
live caller (S86, checked by `ffi-deadsurface`), because the core is linked whole and an unused
export would ship anyway. `rust/fuzz/` fuzzes the pure predicates at this boundary.

---

## 4. Capabilities

### Structure

```c
typedef struct capability {
    uint32_t type;        /* CAP_TCB, CAP_ENDPOINT, CAP_FRAME, ... */
    uint32_t rights;      /* READ | WRITE | EXEC | GRANT | MINT | REVOKE | ... */
    uint64_t object;      /* which instance: task (slot + generation), endpoint index, frame index, ... */
    uint64_t badge;       /* the parent's serial: the derivation-tree link */
    uint64_t serial;      /* issued once, never reissued; 64 bits so it cannot wrap */
    uint64_t token;       /* an endpoint's server-defined identity; 0 = none (S105) */
} capability_t;
```

Each task has a 256-slot cspace. Userspace names a capability by slot and never sees the
structure, so a capability cannot be forged or guessed.

The types are `CAP_TCB`, `CAP_NOTIFICATION`, `CAP_ENDPOINT`, `CAP_FRAME`, `CAP_USER`, `CAP_AUDIT`,
`CAP_CONSOLE`, `CAP_ENCRYPTED_STORAGE`, `CAP_REVOCATION`, `CAP_BLOCK_DEV`, `CAP_IO_DEVICE`,
`CAP_PIPE`, `CAP_KERNEL_LOG`, `CAP_BOOT_MODULE`, `CAP_UNTYPED`, `CAP_REPLY`, `CAP_DEBUG` and
`CAP_STORAGE_FORMAT`. Two are splits rather than additions: `CAP_DEBUG` exists so that `ps`
does not need the capability that rotates the audit keys, and `CAP_STORAGE_FORMAT` exists because
a format right on `CAP_ENCRYPTED_STORAGE` would have been conferred at once on every holder of
that capability's full rights. A new type fails closed where a new rights bit fails open.

**The token** makes an endpoint capability a handle on one thing a server serves, such as a file.
The kernel never interprets it: every message records the token and rights of the capability it
was sent through, and the receiver reads them with `SYS_IPC_INVOKER`, so a server authorises on
what a client holds rather than on who it is. Only `SYS_CAP_MINT_TOKEN` (from an untokened
endpoint capability holding MINT) and the reply-mint `SYS_IPC_REPLY_CAP` (a child of the invoking
capability, never with more rights) set a token; every other derivation copies it, and the
receive right is stripped wherever one is set. Proved in Kani and witnessed by
`make smoke-captoken` (S105). It is the kernel half of the capability filesystem
(`docs/design/filesystem.md`).

### Untyped memory

Kernel objects are carved from memory a task holds a capability to. A `CAP_UNTYPED` names a region,
and `SYS_RETYPE(untyped_slot, kobj_type, count, dest_slot[, pages])` carves endpoints,
notifications and frames out of it, installing a capability for each. Creating a task spends the
creator's untyped too (S57), and `SYS_UNTYPED_SPLIT` hands a delegate a bounded share of a budget
rather than the whole of it (S58). So "this task may consume at most this much kernel memory" is
expressible, and a task holding no untyped cannot create anything.

Allocation within a region is a **monotonic bump pointer**, following seL4. Destroying an object
returns its name, not its bytes: a free list would let an object's bytes be retyped as a different
class while a stale capability still names the old address. The cost is in `docs/LIMITATIONS.md`
2.5.

**Object lifetime is capability-governed**: an object exists as long as some capability names it,
computed by a mark-and-sweep over the capability graph (`kobj_gc_locked`, run from revocation and
teardown) rather than by reference counts spread across every mint, grant and revoke site. A frame
is also kept while any page table maps it. An object is born pinned and becomes collectable only
when a capability names it: the install that writes that capability clears the pin under the same
`cap_lock`, so a sweep on another CPU can never take an object between its creation and its
naming, and no creator has to remember to. The sweep always holds `cap_lock`, so it never reads a
capability halfway through being written, and it halts by name if it is entered any other way
(S151). The well-known service endpoints and the per-task reply
endpoints below `DYN_EP_BASE` are named by the boot protocol, not by a capability, and live for the
whole boot (gap G-5). `endpoint_by_index` and `notification_by_index` are the single resolvers,
and both return `NULL` for a destroyed object.

**Frames** are indices into a table `SYS_RETYPE` fills, never physical addresses, so the legacy
`CAP_FRAME` every task is born holding in slot 3 maps nothing (S26). A frame carries its length
(up to `MAX_FRAME_PAGES` contiguous pages) and is mapped and withdrawn whole (S36);
`SYS_MAP_FRAME` builds the PTE from the capability's rights (S27); `SYS_MAP_REGION` maps a run of
frames all or nothing (S35); a frame's size is readable only through a capability that names it
(S37); and a kernel object's page is never copied on write (S38) nor cloned by `fork` (S40).

### Serials, badges and the derivation tree

Every capability gets a fresh, increasing `serial`; a derived capability records its parent's
serial in `badge`. The `(serial, badge)` pairs form a forest, and a capability's descendants are
the transitive closure of "badge points at a reached serial". Primordial capabilities carry the
reserved `0xC0DE****` serial tag and are not revocable.

### Delegation

- **`cap_mint(dest, src, rights)`** derives into the caller's own cspace with `rights &
  src->rights`.
- **`cap_transfer(dest, src)`** does the same, keeping the source's rights.
- **`cap_grant_into(target, dest, src, rights)`** derives into another task's cspace, authorised
  by a `CAP_TCB` naming that task. `SYS_CAP_GRANT` reaches it as `cap_grant_from_user`.
- **`cap_clone_cspace`** gives a forked child a derived copy of every capability its parent holds
  (S41), and `pipe_count_forked_ends`, before the clone releases `cap_lock`, counts each pipe end
  the child holds, since a pipe is freed when no counted end is left.

A pipe end's holders are counted in the pipe table, not in the capability, so only the kernel's
own copies (creating the pipe, a fork, the stdio wiring at spawn) may make one, and each counts
the end it makes inside the `cap_lock` section that installs it. A pipe's count is therefore never
below the ends that exist, which is what keeps a pipe from being freed while an end still names it
(S134). Ring 3 cannot copy a pipe end: `cap_grant_from_user` and `cap_mint` (and so
`cap_transfer`) refuse one by type in the Rust core (S133). Behind the counts, a pipe end names
one use of its pipe slot, not the slot: its object carries the slot's generation beside the
index, and every pipe operation compares it, so an end left over from a freed pipe, should the
counts ever be wrong, reaches nothing rather than the next pipe in the slot (S139).

Every write to a capability slot takes `cap_lock` and goes through the accounted cap-write path
(S94): `tools/check_cap_writes.py` holds the list of writers, declared in
`.github/cap-write-sites.yml`. This matters beyond the slot being written: revocation reads every
cspace, and a capability is several fields a C store writes one at a time, so an unlocked writer
could show the sweep a half-written slot. One declared exemption, `create_task` building a cspace
for a task already published, is safe by a stated argument that the manifest pins.
`cap_install_child_pipe_end`, the spawn path's stdio wiring, derives the child's pipe end from the
spawner's, so a revoke of the spawner's end reaches it like any other derived capability (S3).

### Revocation

`cap_revoke(slot)` is **system-wide** and **subtree-scoped**. It hands every live cspace plus the
root cnode to `rust_cap_revoke_global`, which nulls the target and computes and nulls the whole
descendant closure across all cspaces. Afterwards no cspace holds the target or anything derived
from it, and ancestors, siblings and independent capabilities to the same object are untouched
(S3, S4, proved in Kani). The closure marks in place and iterates to a fixpoint, so it is exact at
any subtree size and needs no allocation.

A death keeps the tree whole. A derived capability names its parent by serial, so emptying a dying
task's cspace would cut every edge another task's copy names into it, and a revocation above could
no longer reach that copy. So before the cspace is emptied, `rust_cap_reparent_dying` gives every
capability derived from one of the dying task's its grandparent instead, following chains inside
the dying cspace to the first ancestor outside it; a child of a dying root becomes a root, which
nothing above could revoke before either. Only edges move, never rights or objects (S3, proved in
Kani).

A pipe end is a capability and a count in the pipe table, so the sweep counts every pipe end it
removes, by pipe and direction with the generation the ends named, and `cap_revoke` releases
those ends from the table (`pipe_release_revoked_ends`) before it drops `cap_lock`, only from the
pipe that generation names. A peer whose last opposite end was
revoked sees EOF or EPIPE on its next call (S134, proved in Kani).

### One serial, one slot

A serial is issued once, by `assign_fresh_serial` in `rust/src/capability.rs`, and never again:
it is 64 bits wide, derived serials start at 2^32 (above the primordial `0xC0DE....` range), and
the allocator refuses rather than wrap. Every way a capability comes into a slot gives it a fresh
serial, and `tools/check_cap_writes.py` (rule 7) refuses a C store that gives a slot any other
serial, or copies a whole capability into one. So a serial names one capability in one slot.

That is what revocation rests on. The revoke empties, under `cap_lock`, every slot holding the
revoked serial or a descendant, so a capability still in its slot has not been revoked and lookup
consults no other record (S5). Until 2026-10-11 a second record did exist: a generation per serial
in a 4096-cell table indexed by a hash of the serial. Different serials share a cell, so revoking
one capability made unrelated live ones unusable (LIMITATIONS 2.23), and with 32-bit serials that
wrapped it was also the only thing telling a reissued serial from the old one (2.24). Both are gone.

### Snapshot and revalidate

A looked-up capability can go stale if anything between lookup and use yields or drops
`cap_lock`. Such paths take a `cap_snapshot` and call `cap_revalidate` afterwards, which confirms
the slot still holds the same serial and object with the required rights. A revoke empties the
slot, and whatever is installed there afterwards has a serial of its own. IPC send and receive
use it.

### Devices

`CAP_IO_DEVICE` names one entry in the I/O-device table (`src/kernel/pci.c`), built once at boot:
a breadth-first walk of the PCI bus tree through every bridge (each bus scanned once, bridges
followed only downwards, so a cyclic topology costs nothing), plus one non-enumerable
**platform** entry for the legacy console hardware (PIT, PS/2 controller, COM1, the VGA registers
and framebuffer). Each entry declares its frames, port ranges and interrupt lines, and the device
syscalls check every request against the entry the caller's capability names (S43). A register
page is checked whole, because it is mapped whole: a page that a BAR smaller than a page shares
with another device's registers, or that lies in the chipset window (I/O APIC, HPET, TPM, VT-d,
local APIC), is refused. Ring 3 never
names a bus address and never reaches configuration space. The table holds `IODEV_MAX` (64)
entries; a device the walk misses or that does not fit is absent, so nothing can grant it. Index 0
names nothing, so a zeroed field fails closed.

**What the table does not declare is load-bearing too.** COM3 (`0x3E8`) and COM4 (`0x2E8`) are in
no entry, so no capability or port grant can reach them. COM3 is the kernel's own diagnostic
channel (S81): the kernel writes every report there first, where no ring-3 output can interleave
with it. COM4 is the kernel console's own copy (S144): everything the kernel prints, whole, written
inside the console lock, and nothing else, so a gate that waits for a kernel line reads it there
rather than off COM1, where after the handover it arrives through `console_server` among ring 3's
writes. The handover itself happens between lines: the owner changes under the console lock, so a
kernel line already being written finishes first (S145).

**Interrupts.** Interrupts route through the I/O APIC when the MADT describes one; the 8259 is the
fallback, kept buildable with `IRQ_FORCE_PIC=1`. Every delegatable line starts masked and goes live
only when `SYS_IRQ_REGISTER` accepts a capability for it; a level-triggered line is masked when it
fires and stays masked until the driver's `SYS_IRQ_ACK` (S46). With MSI the kernel allocates the
vector (48 to 63) and programs the device; the ABI has no field for a driver to name one (S47).
MSI-X tables live in a BAR, so the page holding one is refused to the driver (S48); MSI-X itself
is not enabled yet (`docs/LIMITATIONS.md` 2.15).

**DMA.** `src/kernel/iommu.c` brings up Intel VT-d before any ring-3 task exists. Every device has
its own address space, starting empty, and `SYS_DMA_ADDR` maps only frames the driver holds a
capability for, carrying that capability's write right (S45). A device's mapping goes when the
frame or the driver does (S53). `SYS_DEVICE_ENABLE` sets only a device's three PCI decode bits
(S44). Without a DMAR table `iommu_active()` is 0, the boot says so, and devices reach all memory.

**`netd`** (`userspace/netd.c`) is the demonstration driver: an Intel NIC driven from ring 3 with
one device capability and one untyped region, woken by MSI or by its masked legacy line, and
confined by the IOMMU. It drives e1000 rather than virtio on purpose, because a paravirtual device
reads guest memory directly and could not witness DMA confinement. It runs in the `NET_SELFTEST`
build, not in the shipped system, and speaks only enough Ethernet to exchange ARP.

**`nvmed`** (`userspace/nvmed.c`) is the first storage driver outside ring 0: an NVMe controller
driven with one device capability and one untyped region, confined by the IOMMU. It resets the
controller, identifies it and its first namespace, builds one I/O queue pair and polls its
completions (NVMe interrupts are MSI-X, which is not enabled). It writes only a disk whose block 0
carries the test signature. It runs in the `NVME_SELFTEST` build; the kernel's storage does not
read through it yet.

**`sdhcid`** (`userspace/sdhcid.c`) is the SD/eMMC driver in ring 3, the first step of moving the
storage drivers out of ring 0 ([`design/ring3-storage.md`](design/ring3-storage.md)). Its whole
authority is one device capability: it moves data by PIO, so it holds no untyped memory and
enables the controller's memory decode without bus mastering, and the controller can start no DMA
at all. It brings up an SD card or an eMMC device, reads, and writes only a card whose block 0
carries the test signature. It runs in the `SDHCID_SELFTEST` build, where the ring-0 probe is
compiled out; elsewhere `sdhci.c` still serves the kernel's storage.

**`atad`** (`userspace/atad.c`) is the IDE driver in ring 3, built the same way: one device
capability, PIO, I/O decode without bus mastering. It drives the primary channel's master. A
controller in compatibility mode has no BAR for its command block, so its legacy ports are
declared on the controller's device entry only in the `ATAD_SELFTEST` build, which also compiles
the ring-0 probe out; every other build declares no ATA port, so no ring-3 task can be granted the
ports `ata.c` is using (S137). The kernel never waits on a
ring-3 task mid-call, so the drivers leave ring 0 when the kernel stops doing disk I/O: the
sealed-block calls of filesystem phase 2 take and return ciphertext, and `fs_server` moves it.

**The block-driver protocol** (`include/blkproto.h`) is how a client reads and writes through
any of the three storage drivers, and its server half (`userspace/blkserve.c`) is one file linked
into each.
A supervisor (in the installed system, `init`) makes the driver's endpoint and one frame per
client, grants the driver the endpoint's receive right and the frames, and binds each client's
token to an extent of the disk. A client's sectors are relative to its extent and cannot leave
it; a token nobody bound, and the supervisor's own capability, reach nothing; only the untokened
capability binds (S136). Nothing consumes it yet: filesystem phase 2 will.

### The shared library

`src/kernel/shlib.c` loads the shared libc (`lib/libc.so`, a verified boot module) once, relocates
it at a base drawn from the CSPRNG at boot (S51), and keeps its frames as roots of the object
collector. Its text is mapped through `CAP_FRAME`s carrying READ and EXEC and never WRITE, so many
tasks execute it and none can modify it (S49). Its writable segment is a template no task maps:
each task gets its own copy (S50).

The kernel endows `init` with the text capabilities; `init` grants them to the shell; a spawned
child inherits derived copies only if its own image asks for the library (`DT_NEEDED "libc.so"`)
and its spawner holds all of them (S106). At spawn and exec the kernel copies the data template
into fresh pages of the task's own address space. Before `main`, crt0's linker maps the text,
refuses a library whose export-table hash differs from the one the program was built against,
resolves each import by name or refuses the program, and seals the resolved table read-only with
`SYS_MEM_SEAL` (S107, S108). No relocation parsing was added to ring 0.

---

## 5. Address spaces and paging

Each task has its own PML4. `create_user_pagedir` builds it, copies the kernel half, premaps the
image window and binds the task's kernel stack above its guard page.

**Demand paging.** Heap and stack pages are allocated on fault, on the faulting task's CR3,
through `PHYS_KVA`.

**Copy-on-write.** Fresh anonymous pages alias a shared read-only zero frame; the first write
allocates a private frame. Frame reference counts are checked in Rust and proved not to wrap. A
kernel `copy_to_user` into a copy-on-write page breaks it the same way.

**`fork`.** `clone_user_aspace` points the child's tables at the parent's frames and marks
**both** sides copy-on-write (S39); a task with a kernel object's page mapped cannot fork (S40),
and neither can a task that has bound the shared libc. Supervisor leaves (the LAPIC and TPM
windows) are re-established by the child rather than cloned.

**Protection.** User stacks are NX. The kernel image is W^X, enforced by `CR0.WP` and swept at boot
(S8). SMEP and SMAP are enabled where the CPU has them and checked by a test. A program can make
pages of its own image read-only for good with `SYS_MEM_SEAL` (S107).

**Crossing the ring boundary.** `copy_to_user` and `copy_from_user` walk the target address space
in software and require `PAGE_PRESENT | PAGE_USER` (and `PAGE_WRITE` for writes) on every page, so
a user pointer at kernel memory cannot be satisfied even without SMAP (S7). A failed copy refuses
rather than shortening (S24). The physical free path accepts only frames it lent out (S102).

**ASLR.** Image, heap and stack bases are randomised with 30 bits from the CSPRNG,
rejection-sampled; a draw from an unseeded pool halts rather than returning predictable bits.

---

## 6. Tasks and scheduling

A `tcb_t` holds register state, CR3, the cspace pointer, the kernel stack, heap bounds, uid and
gid, signal and FPU state, and IPC blocking state. The table of them is carved from the kernel's
untyped reserve, and `g_max_tasks` is derived at boot from the reserve that exists.

**Preemption.** The timer ISR calls `preempt_on_tick` with the interrupted task's trap frame. A
switch happens **only when the tick interrupted ring 3**, where the task holds no spinlock and its
whole state is in the frame; a tick in ring 0 only advances the clock and charges the running
task's time (below). The kernel is therefore not preemptible, which removes a whole class of
reentrancy hazard. Every return to ring 3 passes one epilogue, which checks that the loaded CR3
is the returning task's own and loads it if not (S156), so no kernel path that leaves the wrong
page tables loaded can run one task's code in another's memory.

**CPU time is a capability** ([`design/scheduler.md`](design/scheduler.md) §3.1). Every task is
bound to a scheduling context, a share of one CPU spent as a budget every period, and is chosen
only on the time it grants: a CPU runs its own budgeted work first and slack work (a context with
the slack right, out of budget or on another CPU) after it. The time a task runs is measured with
the TSC between one choice and the next and charged by the context's own CPU, before it chooses
again, and a run across its period's end is charged to both periods. At each choice the CPU arms
its timer for the moment the chosen budget runs out (§3.4, step 3b) or a refill lets a more
urgent task run (step 3c), whichever is first; the timer is the TSC-deadline mode where the CPU
offers it with an invariant TSC, a LAPIC one-shot otherwise. The interrupt, or the tick, that finds
the running task out of budget switches it away, or, if it landed in a system call, marks it to be
switched away on its way back to ring 3. `init` holds the per-CPU roots, `SYS_SCHED_SPLIT`
divides a context and `SYS_SCHED_BIND` binds a task to one (S152, S153). Until something binds a
task elsewhere every task runs on the BSP's root, budgeted on the BSP and slack on every AP.

**Priority is capped by authority** (§3.2 of the design). Among the budgeted work a CPU may run it
chooses the highest priority, round robin within a level, and the task it is running keeps it over
anything it outranks and over slack work. A task's maximum bounds every priority and maximum it can
set, through a `CAP_TCB` with `CAP_RIGHT_PRIORITY` (S154, S155). Every shipped task is at 255, so
the choice is the round robin it was before.

**One switch mechanism, four entry points.** Timer preemption, blocking IPC, voluntary yield and
first entry (`sched_enter_user`) all resume a saved trap frame; first entry fabricates the frame a
preemption would have left, with `rsp` biased by 8 to satisfy the System V ABI's alignment at
function entry.

**Spawn is suspended.** A spawned child is not schedulable until its supervisor has endowed it and
called `SYS_TASK_RESUME`, so no child can observe a half-populated cspace. The spawn path builds the
child's first frame without publishing it (`sched_fabricate_user_frame`), so there is no moment at
which another CPU could choose it (S150). The supervisor's
`CAP_TCB` to the child carries READ, WRITE and MINT: MINT so it can hand on less than it holds, as
`init` gives the shell's watcher a copy that can only wait (decision D1; S140).

**A dead task stays dead.** `task_teardown` empties the cspace before the object sweep (S56),
sends the kill IPI to any CPU still running the task and waits until none is, and a torn-down task
is never resumed or dispatched again. So when `SYS_KILL` returns the task has stopped: an IPI
relayed by a hypervisor can take milliseconds, and the task used to run on through them. A reused slot starts with no death record (S98), and a `CAP_TCB` records the
slot's generation, so a capability for a dead task never names its successor (S100).

**FPU.** `fxsave` and `fxrstor` bracket every ring transition (S16). New tasks start from a
template with `MXCSR = 0x1F80`.

**Signals.** `SYS_SIGACTION` registers a handler that must lie inside the task's own image
(checked in Rust), `SYS_SIGMASK` blocks and unblocks, and `SYS_SIGALTSTACK` sets an alternate
stack. `SIG_KILL` cannot be caught or blocked.

### Interrupt policy

Every row is asserted by `make smoke-irq-policy`, which records `RFLAGS.IF` at five named points.

| Context | `IF` | Established by |
|---|---|---|
| Boot, up to `kernel-ready` | **0** | long mode is entered masked and nothing enables |
| Ring 0: syscall or ISR body | **0** | `int 0x80` and every IDT gate are interrupt gates |
| Ring 3 | **1** | `sched_prepare_user_context` builds the frame with `RFLAGS = 0x202` |
| A parked CPU's idle loop | **1** | `enter_cpu_idle` builds its frame with `RFLAGS = 0x202` |
| Inside a spinlock | **0** | `spin_lock` issues `cli` |
| After the outermost `spin_unlock` | **the caller's own** | `spin_unlock` restores, never imposes |

The nesting depth and saved flag are per CPU, so one CPU's release cannot unmask another's
critical section. The one window that needs interrupts on, the TLB-shootdown wait, enables them
deliberately, restores the previous state, and panics if the caller holds a spinlock. Code inside
an interrupt gate uses raw test-and-set helpers (`sched_raw_lock`, `ipc_lock`) that never touch
`IF`.

---

## 7. SMP

SMP is on by default; `SMP=0` compiles it out.

- **Up to eight CPUs** (`MAX_CPUS`, `src/include/cpu_limits.h`), from the ACPI MADT, started with
  INIT-SIPI-SIPI through a real-mode trampoline linked at 0x8000 by its own script and bounded
  three times against the cells above it (`make smoke-ap-trampoline`). The BSP waits for them for
  at most 2 s of the calibrated clock and then closes bring-up: a CPU that checks in later is
  parked with interrupts off, never counted and never run, so the count printed is the boot's
  (S138).
- **A CPU's index is not its LAPIC id.** The BSP builds `apic_to_cpu[]` from the MADT (itself,
  then primary threads, then SMT siblings) so sparse ids work, and a core past the ceiling parks.
- **SMT siblings are parked** in `ap_entry64`, identified by LAPIC id (S101), so no task shares a
  core's L1 and L2 with another. A parked sibling keeps interrupts on to answer shootdowns, so
  `preempt_on_tick` also refuses to schedule on one, whatever interrupts it.
- **Each AP takes its own one-shot LAPIC timer tick** while it has a task, and an idle AP stops
  ticking until another CPU's tick wakes it for waiting work; one AP, the watcher, always ticks.
  The BSP's tick is the PIT's. Where the TSC is invariant the clock (`system_ticks`) is derived
  from it in whole ticks, so it keeps time while the BSP holds interrupts off; elsewhere it counts
  PIT interrupts. Each CPU chooses from its own run list first. Every live
  task is homed on one CPU's list; a CPU with nothing of its own takes another's waiting task, and
  the tasks waiting on a CPU stuck in the kernel go to the others ([`design/scheduler.md`](design/scheduler.md) §3.5).
- **TLB shootdown** is an acknowledged IPI, and a wait that runs out with a CPU unacknowledged
  halts the kernel rather than returning (S124). The ship kernel never needs one: an address space
  is live on one CPU at a time, there are no global pages, and `switch_cr3` flushes. Only the SMP
  selftest calls it, until threads or PCID ([`design/scheduler.md`](design/scheduler.md) §3.8).

### The claim invariant

```
task_running_cpu[t] == c   <=>   percpu_current_task[c] == t     (t > 0)
```

A CPU claims only a task whose entry is `-1`, so one task's kernel stack and trap frame are never
touched by two CPUs. A claim held by a CPU not running the task makes that task unschedulable by
every CPU; a task run without a claim can be taken by a second CPU. A stale claim is therefore a
symptom to diagnose and never a value to clear, and `SCHED_INVARIANTS=1` checks the invariant and
panics naming the task, the CPU and the observer.

**The claim is held until the CPU has left the stack** (S20). Every switch runs on the outgoing
task's kernel stack, so the claim is released by `sched_release_deferred()`, which
`isr_common_stub64` calls just after it has moved `%rsp` onto the incoming frame. Until then a
second CPU could have resumed the task and re-entered the ISR on the same stack (gap G-8). The
property is checked, not argued: `g_kstack_inflight` marks each task whose stack a CPU is still
leaving and halts the machine on a collision. A CPU whose last task dies parks on its own ring-0
stack, not a shared one, and those idle stacks have guard pages. A spawn never reuses a slot whose
kernel stack a CPU is still on, and the first entry to ring 3 re-checks its claim under the
scheduler lock.

### Lock order

Ten locks, with their order declared once in `.github/lock-order.yml` and enforced by
`tools/check_lock_order.py` (S88), which fails on any nesting not declared and on the reverse of
one that is.

| Lock | Owns |
|---|---|
| `spawn_stage_lock` | The spawn and exec staging state, and every task teardown, so that a `SYS_WAIT` waiter and the death it waits for are ordered (S125). The outermost lock: taken by syscall entry points and the fault paths holding nothing, and by `task_teardown` unless its caller already holds it |
| `storage_lock` | The encrypted object store and on-disk filesystem |
| `ata_lock` | The ATA driver; always inside `storage_lock` |
| `sdhci_lock` | The SD/eMMC controller, for a whole block operation. Innermost |
| `endpoint_lock` | Endpoints and notifications, through `ipc_lock()` |
| `cap_lock` | Every cspace |
| `page_lock` | The pager's structures |
| `untyped_lock` | The untyped regions; `cap_lock -> untyped_lock` |
| `pipe_lock` | Pipe objects; a leaf, and `cap_lock -> pipe_lock` |
| `scheduler_lock` | The per-CPU run lists, the claim invariant and the scheduling contexts; `untyped_lock -> scheduler_lock` |

The nestings that exist on purpose are declared, each with its reason, in
`.github/lock-order.yml`: `endpoint_lock -> cap_lock` (the reply capability is minted before the
receiver wakes, which a receiver already running on another CPU would otherwise race),
`endpoint_lock -> page_lock` (delivering a reply body can fault the destination in),
`page_lock -> swap_lock` and `endpoint_lock -> swap_lock` (a swapped page is freed or brought back
under the swap slot table), `cap_lock -> untyped_lock` (the object collector reads every cspace
and must see none mid-write, S151), `untyped_lock -> scheduler_lock` (a collected scheduling context
gives its share back and unbinds its tasks), and `cap_lock -> pipe_lock` (a pipe end and its count change together
under `cap_lock`, S134). None is a cycle while its reverse stays absent, and
`tools/check_lock_order.py` keeps it so. There is no runtime lock-order check: `spin_lock` records
no lock identity.

**Two operation locks sit outside all of these** (S146). `g_storage_op` makes each exported storage
call one operation, and `g_argon2_op` lets one password hash at a time use the 4 MiB Argon2 scratch
buffer. Both are `oplock_t`: held for the whole operation (seconds, for a format or a hash), taken
again by the CPU that holds it, owned by a CPU rather than a task (sound because ring 0 is not
preemptible and nothing under them blocks), and waited for with interrupts on so that a waiter
still acknowledges TLB shootdowns. The only nesting between them is `g_storage_op -> g_argon2_op`
(a key slot's key is derived inside a storage call). Every spinlock, `storage_lock` included, is
taken inside them, never around them: `oplock_enter` halts by name if this CPU holds a spinlock,
because its waiter turns interrupts on. `tools/check_lock_order.py` reads only `spin_lock`, so
these two are held to that rule at run time instead.

---

## 8. IPC and notifications

### Endpoints

Each endpoint is a **bounded FIFO** of `EP_QUEUE_SLOTS` (default 4) messages of up to
`IPC_MSG_MAX` (256) bytes. The depth is fixed, so a sender cannot make the kernel allocate. Each
queued message carries its own kernel-recorded sender and invoking capability. The static table
holds the well-known endpoints and one private reply endpoint per task (`MAX_ENDPOINTS` is
`REPLY_EP_BASE + MAX_TASKS`, so the table always covers every task, S95); retyped endpoints live
above `DYN_EP_BASE`.

- **`SYS_IPC_SEND` and `SYS_IPC_RECV`** do not block: they return `IPC_AGAIN` on a full or empty
  queue and the caller retries from ring 3, where preemption guarantees progress.
  `ipc_call_retry` in `libhorus` retries only a transient result, and boundedly.
- **`SYS_IPC_RECV_BLOCK`** sleeps on an empty queue instead. The sender's syscall completes the
  receive, so the one-shot `CAP_REPLY` is minted into the receiver's cspace under `ipc_lock`,
  before the wake.
- **`SYS_IPC_CALL`** sends and waits for the reply on the caller's private reply endpoint.
- **`SYS_IPC_REPLY_TO`** delivers the reply through the one-shot `CAP_REPLY` the receive minted,
  so replying twice, or to a client never received from, is unrepresentable. The capability names
  the client by slot and slot generation, recorded with the message when it was sent, so a reply
  to a client that died never reaches the task that reused its slot; `SYS_IPC_SENDER` answers
  only while the slot holds the sender that sent (S13, S13b).

**Publish after save.** A caller's block is made visible to wakers only after its trap frame is
saved, with a full barrier between, so a cross-CPU reply never patches a stale frame. Delivering a
reply into another address space makes the waiter the current task for the duration of the copy,
with interrupts masked, because the user-copy path translates through the current task's CR3.

### Notifications

Badge accumulators: `SYS_NOTIFY` ORs a badge in and wakes a blocked waiter; `SYS_POLL_NOTIFY`
reads without blocking. `SYS_IRQ_REGISTER` routes an interrupt to a notification, which is how a
ring-3 driver sleeps until its device needs it.

### Pipes

Bounded in-kernel byte streams with a `CAP_PIPE` for each end, back-pressure, and EOF or EPIPE when
the peer closes. `task_teardown` releases a dying task's ends so a pipeline cannot wedge.
`SYS_PIPE` gives both ends `CAP_RIGHT_REVOKE`, so the creator can take back every copy of an end
it handed on to a forked or spawned child; a spawned stage gets `READ` or `WRITE` alone. A read or
write resolves its end and moves the bytes under one `cap_lock`, so a revoke cannot free the pipe
between the two (S134).

### Capability addressing

Every IPC syscall names its object by a cspace slot. `ipc_ep_from_slot` and `ipc_notif_from_slot`
(`src/kernel/syscall_ipc.c`) are the single choke point: the slot must hold a live capability of
the right type, with `READ` to receive or `WRITE` to send, passing the lineage check. A server's
listen capability is `READ|WRITE`; a client's is `WRITE` only, so it can send but never receive
the server's traffic or forge its replies (S13a, S13b). A task is born with exactly one endpoint
capability, its private reply endpoint, which no other task can hold a capability for.

---

## 9. The syscall layer

Entry is `int 0x80`, through `interrupt_handler64` to `syscall_handler`, dispatching on a table:

```c
typedef struct {
    void   (*fn)(struct interrupt_frame64 *r);
    uint16_t slot;     /* authorising cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;
```

Where a syscall's authority is one fixed capability, the check happens once, centrally, before the
handler runs. `SC_NONE` means the authority depends on the arguments (a `CAP_TCB` for the target
task, a capability the caller names) and the handler resolves it through `cap_lookup`, which
resolves only in the caller's own cspace and refuses a mistyped capability (S55, S60). No ship row
is gated on slot 3, whose capability every task holds (S79, checked by
`tools/check_dispatch_gates.py`).

**It fails closed.** A number with no entry returns `SYS_ERR_NOSYS`; retired numbers stay reserved
so no new syscall inherits an old caller; and a compile-time assertion ties the table's size to
the highest syscall number, so a syscall cannot be added without its entry. The complete ABI is in
[`SYSCALLS.md`](SYSCALLS.md).

---

## 10. Userspace servers

### `init`

The first task and the **delegation root**. The kernel endows it from the root cnode with what it
must use or delegate: the console, storage and user capabilities, the service endpoints, the
console's input minter (the one capability the keyboard's input capability can be minted from,
S93), the platform device, the kernel log, the boot modules, `CAP_STORAGE_FORMAT`, the shared libc's text,
and `CAP_UNTYPED` over `UNTYPED_ROOT`. It surveys the machine's storage, then starts `fs_server`,
`console_server`, and either the installer (on a blank disk, or when the boot menu asked) or the
shell, each suspended, granting each exactly its subset and resuming it last. The shell's subset
holds nothing of administration until an administrator logs in (S149). The installer and
the shell are lent the keyboard's input capability while init waits for them, and init takes it
back when each has ended. The installer is the only task given `CAP_STORAGE_FORMAT`; nothing a login
reaches holds one.

**Adding a program** is one line in the Makefile, `$(eval $(call USERPROG,name))`, and a
deliberate hand-written launch in `init.c`. There is no macro for delegation: which authority a
program receives is the decision this system exists to make explicit. Grant the narrowest rights
that work.

### `fs_server`

The filesystem and its **reference monitor**. It holds `CAP_ENCRYPTED_STORAGE` and implements
names, directories and permissions over the kernel's `(inode, logical block)` object store. A
request through a tokened capability is authorised by that capability: its object is the inode the
token names and its rights are the capability's, both attested by the kernel (`SYS_IPC_INVOKER`),
and lookup, create and mkdir hand back the child's capability, narrowed and revocable with its
parent (S120). A walk of several names below a directory hands back one capability, to the last,
derived from the one invoked, so a client holds one per path and not one per component. A rename
or link that would cross directories is refused (S121). No request is decided by who sent it: an
untokened capability, which only `init` holds, opens and ends sessions and is refused everything
else, and no task can be handed one any more (S14). A file's mode and owner are never stored
(S77), and every account gets a home directory, which the policy's `@self` line grants it (S78).
It rebuilds the system trees (`/bin`, `/sbin`, `/lib`, `/usr` and below) from the verified boot
modules once the volume is open: a file that matches its module byte for byte stays, any other is
rewritten, and anything no module names is removed. Every request that would change a file or an
entry in those trees is refused before its permission check, for every client, root included
(S116), so an update is new install media.
The POSIX layer and the shell walk with capabilities when they hold a root (S126, S127). A login's
session is one root capability whose token names a grant set: `fs_server` compiles the account's
grants from the policy (`userspace/fs_policy.h`; the compiled-in default on a live boot, the
volume's `/etc/fs.policy` otherwise, chosen by the store's kind as `SYS_FS_STORE_KIND` reports
it), answers `FS_OP_SESSION` only through init's untokened capability, and at every directory on
the way to a grant allows only what the policy gives there (S128). Each session's `/tmp` is a
directory of its own, kept in a store no session can see and removed when the session ends
(S129). A stat through a session's capability is synthesised, never read from the disk: owner bits
are the capability's rights, other bits a bound on every other account's grants at or above the
policy node the token names, which the session's compiled tree also holds (S130), and a chmod or
chown through it succeeds only when it asks for what is already true (S131). After each login the
shell asks `init` for its session; `init` names the account by `SYS_IPC_SENDER`, never by the
request, grants the shell the session's root and working directory, and revokes and ends the
session at logout or when the shell dies, and a login given no session reaches no file, so the
shell ends it (S141, S14). The shell walks by the root in its slot only while a session is open, and drops its root
and working directory at logout whatever `init` did, so no login holds an earlier one's
filesystem (S147). The administrator's session, and no other, is also lent what administration
needs: when the kernel attests a login as uid 0, `init` grants the shell `CAP_USER`, the kernel
log and `CAP_DEBUG`, each minted from a copy `init` keeps and revokes at logout, so the kernel's
capability test is what refuses `dmesg`, `capview`, `useradd` and the rest to a standard account,
and the shell asks no uid (S149). `fs_server` writes `/etc/fs.policy` into a new installed volume when it first
provisions it, the live default with read on `/etc/shell.conf` and `/etc/login.conf` for every
account, and never writes it again, so a deleted policy leaves the administrator alone (S148)
(`docs/design/filesystem.md`, roadmap 2.10).

### `console_server`

Owns the UART, the screen (VGA text or a linear framebuffer) and the PS/2 keyboard, through one
`CAP_IO_DEVICE` naming the platform device: `SYS_MAP_PHYS` for the framebuffer, `SYS_IOPORT_GRANT`
for native port I/O, and `SYS_IRQ_REGISTER` for the keyboard and the tick. It sleeps on a
notification until a key or the tick arrives. The kernel stops reading the keyboard and stops
drawing at the same moment the server takes the hardware (`console_hw_owned()`, S89), and both
share one scancode table, `include/ps2_scancode.h`.

It is the single writer to the console. It implements raw terminal mode (termios and window
size), scrollback of the last 512 lines (Shift+PgUp and PgDn), cells for full-screen programs
alongside their escape sequences on the serial line, and the rule that keyboard input is a
capability (S93): it serves `GETLINE`, `GETPASS` and `READ_RAW` only to a request sent through the
console endpoint tokened `CON_TOKEN_INPUT`, as the kernel attests it (`SYS_IPC_INVOKER`), and
refuses every other without reading. `init` alone can mint that capability, from the one console
capability carrying `MINT`; it lends it to the installer and the shell, and the shell lends a
derived copy to the program it runs in the foreground and revokes it once that program has been
waited for (`console_lend` in `libhorus`). The kernel's own console paths, `SYS_WRITE` fd 1,
`SYS_READ` fd 0, `SYS_GET_LINE` and `SYS_GET_PASS`, ask for the console's capabilities too (S135).
Every boot-log line is timestamped by whichever writer
emits it, the kernel from the TSC and the server from the 10 ms clock, on one epoch, until the
session starts. `task_teardown` hands the hardware back to the kernel if the server dies.

### `libhorus`

The shared freestanding runtime every server links (`include/libhorus.h`, `userspace/libhorus.a`):
memory and string helpers, console output, a bounded busy-wait, the TUI library the installer is
built from, the per-task mount table and path walker (`hvfs`, which walks by capability through a
mount backed by a directory capability, one capability per object from a pool of slots it alone
fills, S126), lending the console's input to a child and taking it back (`conlend`, S93), and
`ipc_call_retry`, which makes the IPC retry contract a library guarantee. It declares nothing that needs authority: anything that
would belongs behind a capability, not a function call.

---

## 11. Storage and the encrypted object store

The kernel exposes an **object store**, not a filesystem: allocate and free inodes, read and write
`(inode, logical block)`, stat, set size and metadata. The AEAD stays in the kernel; `fs_server`
never sees a key. Authority is one capability, `CAP_ENCRYPTED_STORAGE` with `READ|WRITE`, checked
by the dispatch table, and the store answers only an **unlocked** volume, not merely a mounted one
(S74).

- **Encryption.** Every block of file data, directories, indirect pointer blocks, the inode
  table and the allocation bitmaps is sealed with an AEAD under a per-`(inode, block)` subkey
  derived with HKDF from the volume key, with a fresh nonce per write. A pointer block is sealed
  under an identity no data block can have, and a metadata block under `SPAN_INO` and its own
  block number. A metadata block the format wrote and nothing has rewritten (the empty root, the
  root's bitmap bit, zeros) is the one kind left in the clear, vouched for by its leaf.
- **One operation at a time.** Each exported call is one operation under `g_storage_op` (S146),
  because the journal's open transaction, the metadata and Merkle caches and the superblock in
  memory have one copy each, and an install on two CPUs has the installer and `fs_server` in the
  store together. The block reads and writes refuse to run outside an operation.
- **Key slots.** The volume key is wrapped in up to eight key slots, each under a KEK derived with
  Argon2id from one password, and sealed to the TPM's PCRs where there is one (S61, S12). An
  installer may instead write the volume **unsealed**, the key in the clear, when its operator
  chooses (S104).
- **Integrity.** A Merkle tree (fanout 128) whose leaves are the nonce and tag blocks and every
  block of the inode bitmap, block bitmap and inode table, with its root in the superblock. The
  root also binds the superblock's layout and its anchor, sealing and TPM flags, so a moved region
  or a cleared flag fails at unlock. Unlock verifies one node; everything else is verified on the
  path from the root when first read, and each node is checked against its parent, so a block
  rewound to an older valid version fails (S66). The check sits in the block layer every read and
  write of the inode table and bitmaps goes through, and a write carries its leaf up to the root
  in the same journal transaction (S143). A volume of an older format is refused, never mounted.
- **Rollback.** The tree's root lives in the superblock it protects, so a whole volume swapped for
  an older copy would pass. `sb.rollback_gen` is a TPM NV monotonic counter value bound into the
  root, and unlock refuses a volume behind the counter (S70).
- **Size.** A volume is sized from its disk, up to a 16 GiB ceiling (S68); files use direct,
  single-, double- and triple-indirect blocks.
- **Crash safety.** A write-ahead journal with three `FLUSH CACHE` barriers around the commit
  record, so atomicity is an ordering on the medium rather than on issue order; the metadata cache
  writes dirty lines back inside the committing transaction (S65); `fsck` runs after a replay or
  when flagged, and never frees a live file's blocks (S67).
- **Devices.** Backing store is a RAM volume reserved in the pool, a legacy IDE disk, or an SD or
  eMMC card; every disk is a block device of its own, and a format names the disk it erases (S82,
  S83). A block device accepts only blocks it has memory for (S64).
- **Accounts.** The account table lives on the volume, sealed under a key derived from the volume
  key and written through the journal (S62). The compiled-in accounts exist only on a boot with no
  installed disk (S103), no compiled-in password is ever written to a disk (S109), and a live boot
  mounts no persistent disk at all (S110).
- **Swap.** An unlock on an installed boot turns on the swap partition the verified table places
  beside the volume, never over it (`src/kernel/swap.c`, S118). It is an array of 4 KiB slots,
  each page sealed with the AEAD under a key drawn at that boot and never written anywhere, with
  the slot and a per-slot generation in the nonce. The generation and the tag stay in RAM (24
  bytes a slot, from the pool), so the partition holds ciphertext and nothing else, and a changed,
  moved or replayed block fails. Under memory pressure idle private pages go there, chosen by a
  clock over each task's accessed bits: first those of tasks no CPU is running, each held off
  every CPU while its page tables change (S123), then the faulting task's own; they come back on
  touch (S119); a swapped page is a non-present PTE with `PAGE_SWAPPED` and its slot, and every walker
  knows it ([`design/swap.md`](design/swap.md)).

---

## 12. Trusted boot and the TPM

Three layers, each tested adversarially.

**1. The kernel is pinned.** `tools/mkbootimg.sh` puts the kernel's expected SHA-256 inside the
El Torito boot image; GRUB refuses a kernel that does not match, and the firmware measures that
image into `PCR[4]` (S92). This is the layer the kernel does not vouch for itself.

**2. Modules are verified and measured.** `tools/gen_module_manifest.sh` hashes every boot module
at build time into a manifest compiled into the kernel. At boot each module is hashed and compared;
an unverified module reads as an empty slot and its payload cannot be read, so it can never be
provisioned (S10). The kernel extends a token over its command line and manifest into `PCR[8]`
(S91) and each module's digest into `PCR[9]`; `tools/tpm_expected_pcr.py` recomputes them on the
host and CI compares.

**3. The volume key is sealed** to PCRs 4, 8 and 9 under a `PolicyPCR` session, so a changed
kernel, boot image, command line or module leaves the volume locked (S12). The in-RAM volume's key
is random and derived with HKDF rather than Argon2id, because there is no password to harden.

A build with `MEASURED_BOOT_REQUIRED=1` halts when measured boot is unavailable and refuses a
persistent volume that was never sealed (S85); by default a machine without a TPM boots and says
so. The tests: `smoke-modules-tamper`, `smoke-tpm-tamper`, `smoke-tpm-seal`, `smoke-boot-pin`,
`smoke-tpm-bootimg` and `smoke-tpm-cmdline`, each against an arm that restores the attack.

---

## 13. Side-channel posture

**Flush on switch.** `set_current_task` is the single point at which a CPU is about to resume a
task, so every switch path passes it. When the incoming ring-3 task differs from the outgoing one,
the CPU evicts indirect-branch predictor state, L1D and the store, fill and load buffers, gated on
CPUID. The policy is a pure function (`sched_domain_switch_would_flush`) tested on its own.

**SMT parking.** Secondary threads never run tasks (S101).

**`CR4.TSD`.** Ring-3 `RDTSC` faults, and the clock ring 3 can read ticks at 10 ms (S34), so no
syscall gives the fine timer back.

**Not covered.** Channels through the shared L2 and L3, and DMA on a machine without an IOMMU
(`docs/LIMITATIONS.md` 2.12).

---

## 14. Known architectural gaps

Design-level gaps, numbered G-*n*. Their authoritative status is in
[`LIMITATIONS.md`](LIMITATIONS.md); the ones that led to long investigations are written up in
[`investigations/`](investigations/).

| Gap | What it was | Status |
|---|---|---|
| G-2 | `uid == 0` was a kernel authority beside the capabilities | Closed 2026-08-15: every gate is a typed capability (S18) |
| G-3 | Kernel objects were fixed `.bss` tables, and the task count a compile-time ceiling | Closed 2026-08-30: everything, task control blocks included, comes from untyped memory (S57, S58) |
| G-4 | Endpoints were single-slot mailboxes | Closed 2026-08-11: bounded queues, reply capabilities, a blocking receive |
| G-5 | No kernel object lifecycle | Closed for retyped objects; the well-known service endpoints and the per-task reply endpoints still live for the whole boot (`LIMITATIONS.md` 2.3) |
| G-6 | `this_cpu()` read LAPIC MMIO on every call | Closed differently: the id comes from the TSS selector; a `%gs` per-CPU block remains roadmap 1.2 |
| G-7 | A blocked task could be left holding a scheduler claim | Closed 2026-08-09 |
| G-8 | A task's kernel stack could be run by two CPUs | Closed 2026-08-17 (S20) |
| G-9 | Claims leaked and kernel stacks collided on the spawn and reap path | Closed 2026-08-21 |
| G-10 | The spawn and exec path was unserialised process-wide state | Closed 2026-08-18 |
| G-11 | The armed program image was ambient state | Closed 2026-08-18 (S21) |
| G-12 | Two CPUs current on one task through the user-entry path | Closed 2026-09-03 |
| G-13 | The installer's format was bounded by a total time, not a stall | Closed 2026-09-03 |
| G-14 | Ring 0 carries more evictable policy than verifiable machinery | **Open** |

**G-14.** `.github/ring0-classification.yml` classifies every object linked into the kernel as
`core`, `driver`, `service` or `selftest` (S87), and `tools/check_ring0_budget.py` holds `core` to
its measured size, so ring 0 cannot grow by accident. What the classification exposes is the
company the core keeps: the `service` class (the on-disk filesystem and object store, accounts and
Argon2id, ELF loading and spawn staging, the CSPRNG's seeding) is about 6,000 code lines of policy
at the same privilege as the capability engine, and a defect in any of it is a defect in ring 0.
Evicting it is roadmap 2.7a, and the two large moves are design decisions rather than mechanisms:
`storage.c` holds the volume key, and `kusers.c` holds the accounts and their password
hashes. The capability filesystem's phase 2 (roadmap 2.10) and the installed system's
`auth_server` (roadmap 2.11) are those decisions.
