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
0xFFFFFF80_80000000   PHYS_KVA window: higher-half alias of physical [0, 1 GiB)
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

The page pool starts at `USER_PHYS_BASE` (16 MiB, above the kernel image) and is sized from the
firmware memory map. Three regions are held back from it as one reserved window: the 8 MiB loader
staging buffer, the RAM volume's backing store and the untyped arena (§4). The window moves clear
of any boot module GRUB placed there, and every frame a module occupies is held back too (S96).
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
| `capability.rs` | The capability algebra: lookup, mint, grant, transfer, reply-mint, subtree revocation, lineage generations |
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
    uint32_t badge;       /* the parent's serial: the derivation-tree link */
    uint32_t serial;      /* globally unique, monotonic */
    uint32_t generation;  /* lineage generation at creation */
    uint32_t reserved;    /* always 0 */
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
computed by a mark-and-sweep over the capability graph (`kobj_gc`, run from revocation and
teardown) rather than by reference counts spread across every mint, grant and revoke site. A frame
is also kept while any page table maps it. The well-known service endpoints and the per-task reply
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
  by a `CAP_TCB` naming that task.
- **`cap_clone_cspace`** gives a forked child a derived copy of every capability its parent holds
  (S41).

Every write to a capability slot takes `cap_lock` and goes through the accounted cap-write path
(S94): `tools/check_cap_writes.py` holds the list of writers, declared in
`.github/cap-write-sites.yml`. This matters beyond the slot being written: revocation reads every
cspace, and a capability is several fields a C store writes one at a time, so an unlocked writer
could show the sweep a half-written slot. One declared exemption, `create_task` building a cspace
for a task already published, is safe by a stated argument that the manifest pins. One known gap:
`cap_install_child_pipe_end` gives a spawned child's stdio pipe end no parent link
(`docs/LIMITATIONS.md` 1.14).

### Revocation

`cap_revoke(slot)` is **system-wide** and **subtree-scoped**. It hands every live cspace plus the
root cnode to `rust_cap_revoke_global`, which nulls the target, bumps its serial's generation, and
computes and nulls the whole descendant closure across all cspaces. Afterwards no cspace holds the
target or anything derived from it, and ancestors, siblings and independent capabilities to the
same object are untouched (S3, S4, proved in Kani). The closure marks in place and iterates to a
fixpoint, so it is exact at any subtree size and needs no allocation.

### The generation backstop

Revocation nulls slots structurally; generations are the independent second mechanism. Each
serial hashes to a cell in a 4096-entry atomic table (`LINEAGE_GEN`), and a capability is valid
only if its recorded `generation` equals its cell's current value. Revocation bumps the cell, so a
detached copy fails validation even if the sweep never reached it (S5). Creation stamps the
current value, so a new serial that hashes onto a bumped cell is born valid.

### Snapshot and revalidate

A looked-up capability can go stale if anything between lookup and use yields or drops
`cap_lock`. Such paths take a `cap_snapshot` and call `cap_revalidate` afterwards, which confirms
the slot still holds the same serial, generation and object with the required rights. IPC send
and receive use it.

### Devices

`CAP_IO_DEVICE` names one entry in the I/O-device table (`src/kernel/pci.c`), built once at boot:
a breadth-first walk of the PCI bus tree through every bridge (each bus scanned once, bridges
followed only downwards, so a cyclic topology costs nothing), plus one non-enumerable
**platform** entry for the legacy console hardware (PIT, PS/2 controller, COM1, the VGA registers
and framebuffer). Each entry declares its frames, port ranges and interrupt lines, and the device
syscalls check every request against the entry the caller's capability names (S43). Ring 3 never
names a bus address and never reaches configuration space. The table holds `IODEV_MAX` (64)
entries; a device the walk misses or that does not fit is absent, so nothing can grant it. Index 0
names nothing, so a zeroed field fails closed.

**What the table does not declare is load-bearing too.** COM3 (`0x3E8`) is in no entry, so no
capability or port grant can reach it, and that is the kernel's own diagnostic channel (S81): the
kernel writes every report there first, where no ring-3 output can interleave with it.

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
whole state is in the frame; a tick in ring 0 only advances the clock. The kernel is therefore not
preemptible, which removes a whole class of reentrancy hazard.

**One switch mechanism, four entry points.** Timer preemption, blocking IPC, voluntary yield and
first entry (`sched_enter_user`) all resume a saved trap frame; first entry fabricates the frame a
preemption would have left, with `rsp` biased by 8 to satisfy the System V ABI's alignment at
function entry.

**Spawn is suspended.** A spawned child is not schedulable until its supervisor has endowed it and
called `SYS_TASK_RESUME`, so no child can observe a half-populated cspace.

**A dead task stays dead.** `task_teardown` empties the cspace before the object sweep (S56),
sends the kill IPI to any CPU still running the task, and a torn-down task is never resumed or
dispatched again. A reused slot starts with no death record (S98), and a `CAP_TCB` records the
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
  three times against the cells above it (`make smoke-ap-trampoline`).
- **A CPU's index is not its LAPIC id.** The BSP builds `apic_to_cpu[]` from the MADT (itself,
  then primary threads, then SMT siblings) so sparse ids work, and a core past the ceiling parks.
- **SMT siblings are parked** in `ap_entry64`, identified by LAPIC id (S101), so no task shares a
  core's L1 and L2 with another.
- **Each CPU takes its own LAPIC timer tick** and pulls from a shared run pool.
- **TLB shootdown** is an acknowledged IPI.

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
| `spawn_stage_lock` | The spawn and exec staging state. The outermost lock: taken by syscall entry points holding nothing |
| `storage_lock` | The encrypted object store and on-disk filesystem |
| `ata_lock` | The ATA driver; always inside `storage_lock` |
| `sdhci_lock` | The SD/eMMC controller, for a whole block operation. Innermost |
| `endpoint_lock` | Endpoints and notifications, through `ipc_lock()` |
| `cap_lock` | Every cspace |
| `page_lock` | The pager's structures |
| `untyped_lock` | The untyped regions; `cap_lock -> untyped_lock` |
| `pipe_lock` | Pipe objects |
| `scheduler_lock` | The run pool and the claim invariant |

Two nestings exist on purpose: `endpoint_lock -> cap_lock` (the reply capability is minted before
the receiver wakes, which a receiver already running on another CPU would otherwise race) and
`endpoint_lock -> page_lock` (delivering a reply body can fault the destination in). Neither is a
cycle while no `cap_lock` or `page_lock` holder enters IPC, and the checker keeps it so. There is
no runtime lock-order check: `spin_lock` records no lock identity.

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
  so replying twice, or to a client never received from, is unrepresentable.

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
platform device, the kernel log, the boot modules, `CAP_STORAGE_FORMAT`, the shared libc's text,
and `CAP_UNTYPED` over `UNTYPED_ROOT`. It surveys the machine's storage, then starts `fs_server`,
`console_server`, and either the installer (on a blank disk, or when the boot menu asked) or the
shell, each suspended, granting each exactly its subset and resuming it last. The installer is the
only task given `CAP_STORAGE_FORMAT`; nothing a login reaches holds one.

**Adding a program** is one line in the Makefile, `$(eval $(call USERPROG,name))`, and a
deliberate hand-written launch in `init.c`. There is no macro for delegation: which authority a
program receives is the decision this system exists to make explicit. Grant the narrowest rights
that work.

### `fs_server`

The filesystem and its **reference monitor**. It holds `CAP_ENCRYPTED_STORAGE` and implements
names, directories and permissions over the kernel's `(inode, logical block)` object store. Every
request is authorised against the uid the kernel recorded for the sender at login
(`SYS_IPC_SENDER`), never a claim from the client (S13, S14). A file's mode may be set by its owner
or root, its owner by root alone (S77), and every account gets a home directory it owns (S78). It
provisions `/bin` and `/usr/share/man` from verified boot modules once the volume is unlocked.
The capability filesystem of `docs/design/filesystem.md` will replace uid authorisation with
capabilities (roadmap 2.10).

### `console_server`

Owns the UART, the screen (VGA text or a linear framebuffer) and the PS/2 keyboard, through one
`CAP_IO_DEVICE` naming the platform device: `SYS_MAP_PHYS` for the framebuffer, `SYS_IOPORT_GRANT`
for native port I/O, and `SYS_IRQ_REGISTER` for the keyboard and the tick. It sleeps on a
notification until a key or the tick arrives. The kernel stops reading the keyboard and stops
drawing at the same moment the server takes the hardware (`console_hw_owned()`, S89), and both
share one scancode table, `include/ps2_scancode.h`.

It is the single writer to the console. It implements raw terminal mode (termios and window
size), scrollback of the last 512 lines (Shift+PgUp and PgDn), cells for full-screen programs
alongside their escape sequences on the serial line, and the input-owner rule that only the
registered owner may read a password (S93). Every boot-log line is timestamped by whichever writer
emits it, the kernel from the TSC and the server from the 10 ms clock, on one epoch, until the
session starts. `task_teardown` hands the hardware back to the kernel if the server dies.

### `libhorus`

The shared freestanding runtime every server links (`include/libhorus.h`, `userspace/libhorus.a`):
memory and string helpers, console output, a bounded busy-wait, the TUI library the installer is
built from, the per-task mount table and path walker (`hvfs`), and `ipc_call_retry`, which makes
the IPC retry contract a library guarantee. It declares nothing that needs authority: anything that
would belongs behind a capability, not a function call.

---

## 11. Storage and the encrypted object store

The kernel exposes an **object store**, not a filesystem: allocate and free inodes, read and write
`(inode, logical block)`, stat, set size and metadata. The AEAD stays in the kernel; `fs_server`
never sees a key. Authority is one capability, `CAP_ENCRYPTED_STORAGE` with `READ|WRITE`, checked
by the dispatch table, and the store answers only an **unlocked** volume, not merely a mounted one
(S74).

- **Encryption.** Every block is sealed with an AEAD under a per-`(inode, block)` subkey derived
  with HKDF from the volume key, with a fresh nonce per write.
- **Key slots.** The volume key is wrapped in up to eight key slots, each under a KEK derived with
  Argon2id from one password, and sealed to the TPM's PCRs where there is one (S61, S12). An
  installer may instead write the volume **unsealed**, the key in the clear, when its operator
  chooses (S104).
- **Integrity.** A Merkle tree over the block metadata (fanout 128) whose root is in the
  superblock. Unlock verifies one node; everything else is verified on the path from the root
  when first loaded, and each node is checked against its parent, so a block rewound to an older
  valid version fails (S66).
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
`storage.c` holds the volume key, and `kusers.c` is reached from the capability-minting
`SYS_SUDO`. The capability filesystem's phase 2 (roadmap 2.10) and the installed system's
`auth_server` (roadmap 2.11) are those decisions.
