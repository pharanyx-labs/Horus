# Horus Architecture

This document describes the design and internals of the Horus microkernel — for contributors who want to understand the system before working on it, and for anyone evaluating the design. Where this document and the code disagree, the code is authoritative; please open an issue.

---

## Design philosophy

Horus is built around one principle: **no ambient authority**. A task cannot access any resource — files, other tasks, devices, memory — unless it holds an explicit capability token granting that access. The kernel enforces this at every system-call boundary.

The secondary goal is **verifiability**: the most security-sensitive operations (capability manipulation, memory reference counting, the cryptographic primitives, the W^X policy, the attacker-facing ELF parse) are implemented in safe Rust, where the type system statically rules out whole classes of memory-safety bugs.

Horus is a microkernel. The kernel handles only what must run in Ring 0: memory management, capability enforcement, task scheduling, interrupt handling, and a thin encrypted block/inode store. Filesystem *semantics*, the console driver, and device policy live in ring-3 servers communicating over IPC.

---

## Target hardware

Horus targets **x86-64** exclusively.

- The kernel runs in 64-bit long mode: PML4 paging, 48-bit virtual addresses, `-mcmodel=kernel`.
- Bootloader: **Multiboot2** (GRUB2).
- CPU features detected at runtime: SMEP, SMAP, UMIP, AES-NI, SSE2/SSE4.2, TSC, RDRAND, plus the microarchitectural-flush controls (IBPB / L1D_FLUSH / MD_CLEAR) and SMT topology.
- Multi-core: application processors are brought up via the LAPIC (INIT-SIPI-SIPI), each with its own LAPIC-timer preemption tick. SMP is **default-on** (CPU count from the ACPI MADT); `SMP=0` compiles the subsystem out and boots single-core on the PIT path.
- An optional **TPM 2.0** (TIS/FIFO MMIO) is used for measured boot and disk-key sealing when present; absence is handled gracefully.

Ring-3 userspace is 64-bit too: tasks run under the GDT's 64-bit user code segment (`cs = 0x23`, DPL 3) as static-PIE `EM_X86_64` images, relocated at load.

The only 32-bit code left is the boot on-ramp that cannot go: an x86 CPU starts in real mode, GRUB enters `_start` in 32-bit protected mode, and an application processor comes out of SIPI in real mode. The `.code32` multiboot stage and the `.code16`/`.code32` AP trampoline are how long mode is reached at all. One deliberate exception in the test tree: `userspace/elftest.o` is still built 32-bit so `smoke-elf` keeps exercising the loader's ELFCLASS32 path.

---

## Memory layout

### 64-bit virtual address space

| Region | Virtual address | Notes |
|---|---|---|
| Kernel image | `0xFFFFFFFF80100000` | `.text`/`.rodata`/`.data`/`.bss`, linked at `KERNEL_VMA` + 1 MiB, **loaded at physical 1 MiB** |
| Physical alias (`PHYS_KVA`) | `0xFFFFFF8080000000` | Physical `[0, 1 GiB)` aliased r/w; present in **every** address space |
| LAPIC | `0x00000000FEE00000` | Identity-mapped MMIO, replicated into every address space |
| Boot stage (`.boot`) | `0x0000000000100000` | VA == PA; the 32-bit entry code and its GDT/stack; unmapped after long mode |
| User image (PIE base) | `0x0000000400000000` + random | PIE image relocated to `USER_IMAGE_ASLR_BASE` (16 GiB) + a random page offset in a 4 TiB window (**30 bits**) |
| User heap | `0x0000000001000000` | Grows upward via `sbrk`/`brk`; demand-paged |

**The kernel runs at −2 GiB** (`KERNEL_VMA = 0xFFFFFFFF80000000`), so no kernel address is a user address. That base is *forced*, not chosen: `-mcmodel=kernel` lets GCC emit 32-bit sign-extended symbol references (`R_X86_64_32S`), valid only in `[−2 GiB, +2 GiB)`, and this is the top half of that range. A canonical higher-half base such as `0xFFFF800000000000` would break every one of them and force `-mcmodel=large`.

`0xFFFFFFFF80000000` decodes to PML4[511], PDPT[510] — one more entry in the same `high_pdpt` that already held the `PHYS_KVA` window at PDPT[2]. Each high section carries `AT(vma − KERNEL_VMA)`, so `p_paddr` stays low and GRUB loads the kernel at 1 MiB.

**`.boot` is linked VA == PA** because GRUB enters `_start` in 32-bit protected mode: a 32-bit `movl $sym, %edi` cannot encode a high address, and the far jump that activates long mode is absolute and executes *after* `CR0.PG`. The boot stage names kernel symbols as `sym − KERNEL_VMA`, and escapes to the linked addresses via `movabs` + `jmp *%rax`.

**The low identity map is gone from user address spaces.** `create_user_pagedir` builds `pml4[0]` → PDPT → PD holding nothing but the image premap and the low stack; every other entry is not-present. The kernel half (`pml4[256..511]`) is copied from the kernel PML4 with `PAGE_USER` stripped, so the kernel — and `PHYS_KVA` — remain addressable on a user CR3 while ring 3 cannot reach any of it. **A user mapping cannot shadow kernel state by construction**, rather than because ASLR is bounded away from it.

**Physical access from the fault handler.** The user page pool starts at `USER_PHYS_BASE` (16 MiB) and a user address space maps none of it directly. The demand pager runs on the faulting task's CR3 and reaches freshly allocated frames through the higher-half alias (`PHYS_KVA`) that every task replicates. Using a low identity address instead faulted *inside* the fault handler and re-entered the `page_lock` — a hard hang; the pager gates every mapping on `rust_validate_page_fault`, which approves only the faulting task's own image, heap, and stack regions.

### Physical memory

| Region | Physical address | Purpose |
|---|---|---|
| Loader staging + RAM vdisk | base of the pool | Off-`.bss`, reached through `PHYS_KVA` |
| User page pool | `0x01000000` (16 MiB) | 4 KiB frames for user images/heaps/stacks |
| Kernel stacks | allocated at init | one guarded 32 KiB stack per task slot |

### Kernel address translation

A kernel symbol's virtual address is `KERNEL_VMA` above its physical address, so writing `(uint64_t)&sym` into CR3 or a PTE is a bug (it sets bits above 51 → reserved-bit fault). `virt_to_phys()` / `phys_to_virt()` (`kernel.h`) are the conversions for kernel image addresses; `PHYS_KVA` reaches an arbitrary physical page. Neither applies to `.boot` (VA == PA).

`KERNEL_VMA` is defined in `linker64.ld` (the placement authority) and `src/include/kernel_vma.h` (shared by C and boot assembly). They are cross-checked, not trusted: the linker exports `__kernel_vma_from_linker` and `kernel_main` asserts the two agree, that it is executing above `KERNEL_VMA`, and that a `virt_to_phys`/`phys_to_virt` round-trips — printing `HIGHHALF: PASS` or halting. A botched relocation is loud, not a mystery fault later.

### Paging, W^X, and copy-on-write

**W^X.** `EFER.NXE` is enabled and the kernel sets the PTE NX bit so a writable page is never executable. User stacks are non-executable; the ELF loader honours each `PT_LOAD` segment's `p_flags` (`rust_user_page_is_noexec`, unit-tested). The kernel's own image is `.text` r-x, `.rodata` r--, `.data`/`.bss` rw-NX, with `CR0.WP` set — mandatory, because with WP clear a supervisor write ignores the PTE read-only bit and ring 0 is the only ring that can reach those pages. `make smoke-wx` asserts the per-section bits *and* sweeps **every present leaf** for a simultaneously-writable-and-executable mapping (both permissions accumulated across page-table levels) — the sweep, not a per-section check, because every W^X hole this kernel had was an *alias* (a second mapping of the same frames), and it found the last one itself (the LAPIC MMIO, mapped W+X outside the image).

**Stack guard pages.** Every task kernel stack (all `MAX_TASKS` slots, task 0 included), the BSP boot stack, the three boot IST fault stacks, and every AP's IST stacks sit above an unmapped guard page, so an overflow faults on the guard. `smoke-wx` / `smoke-wx-smp` assert each guard is absent while the stack just above it stays present.

**Copy-on-write.** Shared pages are marked `PAGE_COW` and mapped read-only; the first write faults `present|write`, and the pager hands out a private frame, clears `PAGE_COW`, and preserves the NX bit. Physical pages carry refcounts maintained in Rust (`rust_page_ref_inc/_dec`). The main producer of COW mappings is the **shared zero page**: a demand-zero *read* installs one immortal read-only zero frame (allocated once in `paging_init`), so reading a sparse heap costs one physical page total. Breaking it on write is a special case, not a copy — duplicating an all-zero frame just means handing out a zeroed page, so the pager allocates one and returns without touching the zero frame's refcount (`free_user_physical_page` refuses that frame by address). The **generic non-zero** break path — decrement the shared frame's refcount, then either copy (refcount ≥ 2) or upgrade the PTE in place (sole owner) — is factored into `cow_break_pte` and driven by `make smoke-nzcow`; it is reached by no runtime caller (`fork` is a non-goal) and carried two latent bugs until it was tested (a sole-owner infinite fault loop and a per-break refcount leak), both fixed. Two subtleties: the pager derives the old frame with `PTE_ADDR_MASK` (not `& ~0xFFF`, which would leave NX set and compare unequal to the zero frame), and `user_copy` breaks COW itself before writing so a `copy_to_user` into a read-only shared page does not fault on a page the kernel is about to fill. `make smoke-cow` gates the user-visible contract.

Address-space reclaim is deferred: `task_teardown` runs before `task_exit_switch`, so a dead task's CR3 may still be the one a CPU is walking; its ~284 KiB is freed when its slot is reused, bounding the pool at `MAX_TASKS` × the per-task footprint.

**ASLR.** Per-spawn stack top, heap gap, and image load base are drawn from the CSPRNG. Userspace is built static-PIE (`ET_DYN`); `do_spawn` picks a random page-aligned base and `try_elf_load` relocates there, failing closed on any relocation type it does not implement (`R_386_RELATIVE` REL and `R_X86_64_RELATIVE` RELA). Image-base entropy is **2³⁰ page-aligned positions (30 bits)**, a 4 TiB window above `USER_IMAGE_ASLR_BASE` (16 GiB); the image sits clear of the fixed stack/heap regions so the window can be that wide. `make smoke-aslr` asserts 8 spawns land at 8 distinct high bases spanning > 1 GiB.

---

## Capability system

The capability system is the core security mechanism; all other security properties derive from it.

### What a capability is

A capability is an unforgeable token in a task's **capability node (CNode)** of 256 slots. Low slots are reserved for kernel-assigned capabilities; higher slots are free for userspace. **All 256 slots are zeroed to `CAP_NULL` when a task slot is allocated** (`create_task`), so a reused slot cannot inherit the dead task's capabilities.

```c
typedef struct capability {
    uint32_t type;     /* CAP_TCB, CAP_FRAME, CAP_ENDPOINT, CAP_IO_DEVICE, CAP_PIPE, ... */
    uint32_t rights;   /* bitmask: READ | WRITE | EXEC | GRANT | MINT | REVOKE | ... */
    uint64_t object;   /* identifies the governed object */
    uint32_t badge;    /* parent serial, used for derivation/revocation tracking */
    uint32_t serial;   /* unique per capability instance */
} capability_t;
```

### Capability types

| Type | Value | Governs |
|---|---|---|
| `CAP_NULL` | 0 | empty slot |
| `CAP_TCB` | 1 | a task (kill / signal / grant-into) |
| `CAP_NOTIFICATION` | 2 | a notification object |
| `CAP_ENDPOINT` | 3 | an IPC endpoint |
| `CAP_FRAME` | 4 | a physical frame |
| `CAP_USER` | 6 | admin authority over the user database |
| `CAP_AUDIT` | 7 | the audit log |
| `CAP_CONSOLE` | 8 | the console |
| `CAP_ENCRYPTED_STORAGE` | 9 | the file master key |
| `CAP_REVOCATION` | 10 | a revocation object |
| `CAP_BLOCK_DEV` | 11 | the raw block / encrypted object store |
| `CAP_IO_DEVICE` | 12 | device delegation (map-phys / port-I/O / IRQ bridge) — held by `console_server` |
| `CAP_PIPE` | 13 | one end of a bounded in-kernel pipe |

> The values 12/13 were formerly `CAP_DIR`/`CAP_FILE` for the removed in-memory capfs; those types no longer govern any object and the values are now reused by `CAP_IO_DEVICE`/`CAP_PIPE`.

### Rights bitmask

| Right | Bit | Meaning |
|---|---|---|
| `CAP_RIGHT_READ` | `0x001` | Read the object |
| `CAP_RIGHT_WRITE` | `0x002` | Write to the object |
| `CAP_RIGHT_EXEC` | `0x004` | Execute or invoke |
| `CAP_RIGHT_GRANT` | `0x008` | Transfer a copy to another task |
| `CAP_RIGHT_MINT` | `0x010` | Derive a capability with a subset of rights |
| `CAP_RIGHT_REVOKE` | `0x020` | Revoke this and all derived capabilities |
| `CAP_RIGHT_AUDIT_WRITE` | `0x040` | Append to the audit log |

### Operations

All capability operations live in `rust/src/capability.rs` (safe Rust), called from C over FFI.

| Operation | Effect |
|---|---|
| **Mint** | Derived capability with a subset of the parent's rights; records the parent's serial as its badge. |
| **Transfer** | Copies a capability into another task's CNode with the same rights. |
| **Move** | Transfer, then nullify the source slot. |
| **Grant** (`SYS_CAP_GRANT`) | A supervisor holding a child's `CAP_TCB` copies one of its own slots into a chosen slot of that child's cspace — least-privilege delegation. Routed through the locked, `caps_in_use`-accounted, rights-masked `cap_grant_into` (audit A2, fixed). |
| **Revoke** | System-wide, **descendant-only**. `rust_cap_revoke_global` nullifies the target, then sweeps every live CNode plus the kernel root cnode for the target's **derivation subtree**, nullifying exactly those — not ancestors, siblings, or same-object peers (audit A1) — and bumps the per-serial lineage generation once. |

### Revocation and lineage

Revocation is **complete, not caller-local**: the C wrapper `cap_revoke` (under `cap_lock`) collects every live cspace and passes them to `rust_cap_revoke_global`, which does the whole sweep in one Rust call — so a derived copy in another task is revoked together with its parent. The sweep is **descendant-only** (`revoke_subtree`): a bounded worklist seeded with the target's serial, closed under "child (`badge`) of an already-revoked serial". If a subtree ever exceeds `MAX_REVOKE_LINEAGE` (never in practice), a fail-safe object-sweep fallback nulls every same-`object` cap — a complete superset — so no descendant can survive.

A second, independent mechanism prevents **use-after-revoke**: a **lineage table** (`LINEAGE_SLOTS` = 4,096 generation counters). Each capability is created stamping `generation = rust_lineage_current(serial)` — keyed by the globally-unique **serial** (finding 3.3; previously `object`) — and `rust_cap_lookup` re-checks strict equality at use time. A revoke bumps its serial's cell, so a stale snapshot fails the generation check even if its bit pattern escaped the structural sweep. The residual imprecision is the hash: distinct serials can collide into one cell, so a bump can spuriously invalidate a colliding live cap — an availability-only, fail-safe effect (Roadmap Track 1). Proved over the whole `u32` space by two Kani harnesses.

**Primordial capabilities** — root capabilities assigned at boot, identified by the `0xC0DE` serial prefix — cannot be revoked (a serial-range check in the Rust path enforces it).

---

## Task model

Horus supports up to `MAX_TASKS` concurrent tasks. Each has a **TCB** (saved trap frame / register state, `cr3`, `saved_ksp`), a **256-slot CNode**, a dedicated guarded **32 KiB kernel stack**, a 512-byte **FXSAVE image** for its x87/SSE file, a demand-paged **heap** (`heap_start`/`_current`/`_end`), a **UID/GID login identity** the kernel attests to servers, and a **signal handler** + `pending_sig` slot. A task's state is one of `TASK_DEAD`, `TASK_RUNNABLE`, `TASK_BLOCKED_IPC`, `TASK_BLOCKED_NOTIF`, or `TASK_BLOCKED_WAIT`.

### Scheduling

The scheduler is preemptive round-robin. The PIT fires at 100 Hz on the BSP; under SMP each AP runs its own LAPIC-timer tick. A tick that interrupted **ring 3** switches to the next runnable task by swapping the per-task kernel stack holding its full trap frame (`preempt_on_tick` returns the `%rsp` to resume on; the ISR epilogue `iretq`s into it). A tick that lands in **ring 0** never switches — the kernel is effectively non-preemptible, sidestepping lock/reentrancy hazards.

There is a **single context-switch path**: every task enters and resumes via a full interrupt trap frame on its kernel stack (`sched_prepare_user_context` at spawn, `sched_enter_user` for first entry / `init`, timer preemption, `ipc_block_switch` for blocking syscalls, `sched_yield_switch` for `SYS_YIELD`). The legacy cooperative `yield()`/`schedule()` switch has been deleted. Multi-core scheduling shares a single runnable pool with a per-CPU pull under a raw scheduler lock; per-CPU run queues and priorities are future work (Roadmap Track 3).

**Flush-on-switch (side-channel).** The switch chokepoint is `set_current_task`, so no path bypasses it. On a switch to a *different* ring-3 task the kernel evicts the microarchitectural state the incoming task could snoop the outgoing one with — the indirect-branch predictor (**IBPB**, `IA32_PRED_CMD`), the L1 data cache (**L1D_FLUSH**, `IA32_FLUSH_CMD`), and the store/fill/load buffers (**MDS**, `VERW`) — each gated on a CPUID-detected capability (`cpu_flush_microarch_state`), a safe no-op otherwise; same-task resumes and switches to the kernel idle task are skipped. Gated by `make smoke-flush` (detection + policy; the barriers engage on hardware/KVM, which TCG does not emulate).

### x87/SSE context

The trap frame saves general-purpose registers only. Each task carries a 512-byte FXSAVE image; `interrupt_handler64` saves on entry from ring 3 and restores on return, keyed on the *current* task at each moment (the dispatcher may have switched). A ring-0 → ring-0 interrupt skips both. The kernel is built `-mno-sse -mno-mmx -mno-80387` and holds no FPU state of its own — which makes the save cheap and stops the leak in the other direction (GCC auto-vectorising an integer loop would otherwise leave a live `xmm` value another ring-3 task could read). This was latent while userspace was i386 (SSE2 not in that baseline); under `-m64` it became real data corruption once, and `smoke-fs-conc` is the regression test.

### Process control (ring-3)

Tasks are first-class from ring 3. A task can `SYS_SPAWN` a named embedded binary or `SYS_SPAWN_IMAGE` a caller-supplied image loaded over the `fs_server` (receiving the child's `CAP_TCB`), replace its own image in place (`SYS_EXEC_NAMED` / `SYS_EXEC_IMAGE`, same pid and cspace), delegate a capability into a supervised child (`SYS_CAP_GRANT`), terminate itself (`SYS_EXIT`) or a task it holds a `CAP_TCB` for (`SYS_KILL`), and block until another exits (`SYS_WAIT`). Spawn/exec take a full `argv`, marshalled onto the child's initial stack and read back with `SYS_GET_ARGV`.

A ring-3 **`init` (PID 1)** launches at boot, endowed with `CAP_AUDIT` plus the caps it hands the console server and shell. It spawns `console_server` and the shell, delegates their capabilities with `SYS_CAP_GRANT`, and then **blocks in `SYS_WAIT`** — consuming no CPU — relaunching a child that exits or faults.

### Signals

A task registers its own handler with `SYS_SIGACTION`. Two delivery paths share it:

- **Fault signals.** A ring-3 fault (page fault → `SIG_SEGV`, `#UD` → `SIG_ILL`) is delivered to the handler instead of killing the task: `try_deliver_fault_signal` saves the trap frame and rewrites the live frame to enter the handler (signal # in `rbx`, fault addr in `rcx`); `SYS_SIGRETURN` restores the exact context.
- **Async task-to-task** (`SYS_SIGNAL`, gated on a `CAP_TCB` to the target — same authority as `SYS_KILL`). The sender queues `pending_sig`; the target is redirected into its handler on its next return to ring 3.

The pending set is a full 1..31 bitmask; `SYS_SIGMASK` blocks/unblocks (`SIG_KILL` excepted, lowest unmasked delivered first); a signal to a `SYS_WAIT`-blocked target interrupts the wait (`SYS_ERR_INTR`). The handler entry is validated in safe Rust to *that task's own* `[image_base, image_end)` (`rust_signal_handler_addr_ok`), a fault inside a handler is not re-delivered (the `in_signal` guard), and `SYS_SIGALTSTACK` runs a handler on a registered alternate stack so a corrupt primary stack cannot stop it. Signals grant no new authority — the handler runs at ring 3 with unchanged privileges.

---

## IPC and pipes

IPC is endpoint-based; the kernel maintains 64 endpoints. Each is a **single-slot mailbox**. `SYS_IPC_SEND`/`RECV` are **non-blocking** (return a would-block code rather than spinning), so a userspace peer polls from ring 3 where the timer interleaves it. `SYS_IPC_CALL` may block the caller (`TASK_BLOCKED_IPC`) on the full-context block/switch path and resumes when the reply arrives. Requests serialise one at a time through an endpoint's single slot, but replies do not: `SYS_IPC_REPLY_TO` routes a reply straight into the requesting client's blocked call by kernel-recorded sender identity — which is what lets one server hold several clients at once. Per-endpoint multi-slot queueing remains future work. A snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window across the send/recv paths.

**Block/wake publish order (SMP-safe):** the syscall handler only records a `pending_block` intent; `ipc_block_switch` then (1) stores the live trap frame in `saved_ksp`, (2) issues a full memory barrier, and (3) publishes the waiter under the IPC lock. A notifier on another core therefore never patches a null or stale frame; if the event already arrived, publish completes the wait immediately.

**Notifications** (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) complement endpoints with an async, badge-carrying signal: `SYS_NOTIFY` ORs a 32-bit badge into a slot and wakes any task blocked on it (patching the accumulated badge into the waiter's saved `rbx`), else the badge accumulates. Proven by `make smoke-notify`.

**Pipes** (`SYS_PIPE`/`_READ`/`_WRITE`/`_CLOSE`) are bounded in-kernel byte buffers, the substrate for shell pipelines. `SYS_PIPE` installs a read and a write `CAP_PIPE` in the caller's cspace and returns their slots. Reads and writes apply back-pressure: `SYS_PIPE_READ` returns `SYS_ERR_AGAIN` when empty but writers remain open (0 = EOF once all writers close), and `SYS_PIPE_WRITE` returns `SYS_ERR_AGAIN` when full but a reader is open (`SYS_ERR_PIPE` once no reader remains), letting the shell interleave stages by yielding. At spawn the shell wires a child's stdin/stdout to pipe ends; `SYS_STDIO_INFO` lets `posix_init` learn which of fd 0/1 is a pipe. Gated by `make smoke-pipe`.

### Userspace filesystem server

Filesystem *semantics* run in the ring-3 `fs_server` — the system's **single** filesystem and its reference monitor. The kernel provides only a **persistent, encrypted object store**: inode allocation and per-(inode, block) AEAD I/O (syscalls 56–61), owner/mode persistence (`SYS_FS_SET_META`, 74), and hard-link counts (`SYS_FS_INODE_LINK`, 76), all gated on `CAP_BLOCK_DEV` + uid 0. Encryption keys never leave the kernel TCB. The server builds directories (as inode data; root = inode 0), path resolution, and file sizes on top, answering clients over IPC (`include/fs_proto.h`; requests on endpoint 4, each client's reply-wait on 5).

It enforces **per-file POSIX owner/group/other rwx** against the caller's *kernel-attested* identity — `SYS_IPC_SENDER` returns the sending task's login uid/gid from `tasks[]`, unforgeable by the client — with root (uid 0) the only ambient authority (`chmod` owner-or-root, `chown` root-only). It serves **multiple clients concurrently** via `SYS_IPC_REPLY_TO`. Every multi-block update is **crash-atomic** via a write-ahead redo journal (HMAC-authenticated header) replayed at the next mount, and a mount-time `fsck` reclaims orphaned inodes and leaked blocks. Files map through direct + single- + double-indirect blocks (up to 12 + 64 + 64×64 blocks). The volume is **16 MiB** (32768 blocks): the data allocator uses a **multi-block bitmap** and the metadata rollback-HMAC is **hierarchical** (a top MAC over per-meta-block MACs) so a single write refreshes one block's MAC plus the top and the per-write cost stays flat. Proven by `smoke-fs`, `-perms`, `-conc`, `-wal`, `-large`.

The earlier parallel **in-memory capfs** (syscalls 38–45) has been **removed** — its engine and objects are gone and the numbers fail closed and are reserved.

**Programs load from this filesystem, not the kernel image.** At startup the `fs_server` builds a directory skeleton (`/bin`, `/etc`, `/home`, `/lib`, `/usr`, `/usr/share/man`). Only the binaries that must run before any filesystem exists (`init`, `shell`, `fs_server`, `console_server`, `hello`, `captest`) are embedded in the kernel; the ported GNU coreutils and their man pages ship as **GRUB multiboot2 modules** loaded into RAM outside the image. The kernel exposes each module read-only over `SYS_BOOT_MODULE_INFO`/`_READ` (77/78, same `CAP_BLOCK_DEV` + uid 0 authority as the store); each module's cmdline is its destination path (`bin/<name>` or `usr/share/man/<name>`), and the `fs_server` writes a root-owned file there (executables `0755`, data `0644`).

**Modules are integrity-checked before exposure (audit A4).** The kernel embeds a **SHA-256 manifest** of exactly the modules the build shipped (generated into `src/kernel/boot_module_manifest.h` from the same `BOOT_MODULES` list the ISO is assembled from). At boot, before userspace exists, `boot_module_verify_all` hashes each module where GRUB left it (through `PHYS_KVA`) and requires an exact (path, size, digest) match; anything else is refused at the syscall choke point and can never be provisioned. No key is involved — the manifest ships inside the reproducible kernel image, which is the root of trust. The `fs_server` independently constrains the destination to `/bin` or `/usr/share/man` (`module_dest_ok`). Gated by `make smoke-modules-tamper`.

### Ring-3 console server

The console (VGA text framebuffer + serial) is driven by a ring-3 server, `console_server`, not by the kernel — the first driver carved out of the kernel's flat trust domain. At boot `init` launches it and delegates a `CAP_ENDPOINT` for IPC and a `CAP_IO_DEVICE` that gates the three device-delegation mechanisms: mapping the framebuffer into its own address space (`SYS_MAP_PHYS`, restricted to a device-frame allowlist), native `in`/`out` on the console ports via a per-task TSS I/O-permission bitmap (`SYS_IOPORT_GRANT`), and routing a hardware IRQ to a notification (`SYS_IRQ_REGISTER`). The shell sends output and reads input (with the server doing line editing, echo, and password masking) over the same reply-by-identity IPC the filesystem server uses; `SYS_CONSOLE_OWNED` tells a program whether fd-1 output must route through the server. The kernel retains only a minimal serial writer for panic and early-boot output, plus an in-kernel fallback. A console-driver bug is contained as an ordinary ring-3 fault (`make smoke-console-isolation`). See `docs/proposals/console-server.md`.

---

## Symmetric multiprocessing

Horus brings up the application processors and runs scheduled tasks across cores; SMP is **default-on** (`SMP=0` compiles it out):

- **AP bringup** via LAPIC INIT-SIPI-SIPI; each AP sets up long mode, its GDT/TSS/IDT, and enters the scheduler.
- **Per-CPU preemption** from the LAPIC timer over a shared runnable pool with a per-CPU pull under a raw scheduler lock.
- **IPC + notification locking** so cross-CPU sends/receives serialise correctly.
- **TLB-shootdown IPIs** with acknowledgement (ack count = online + parked), so a CPU that changes a shared mapping flushes the others' TLBs first.

**SMT is disabled in software.** Flush-on-switch (above) covers time-sliced co-tenancy, but a sibling hyperthread sharing L1/L2 *concurrently* cannot be flushed away, so at AP bringup a secondary thread (non-zero SMT bits in its APIC id, per CPUID leaf 0x0B) is **parked**: it stays TLB-coherent and services shootdown IPIs but never starts its scheduler timer and never runs a task, so no untrusted work co-resides on a core. Boot logs `smp: N cores online, K SMT siblings parked`; gated by `make smoke-smt`. Per-CPU run queues, priorities, and cache partitioning are the remaining SMP-maturity work (Roadmap Track 3).

---

## Syscall interface

Syscalls use `int 0x80`: number in `rax`; arguments in `rbx, rcx, rdx, rsi, rdi` (a sixth in `r8`). Arguments and the return value are 64-bit — they carry user pointers, and `SYS_BRK`/`SYS_SBRK` return an *address*. Numbers run **0 (`SYS_YIELD`) through 88 (`SYS_DMESG`)**; the newest are the pipe family (83–86), `SYS_STDIO_INFO` (87), `SYS_CONSOLE_OWNED` (82), and `SYS_DMESG` (88). See [SYSCALLS.md](SYSCALLS.md).

Dispatch is **table-driven**: `syscall_handler` indexes a `syscall_table[]` of descriptors `{ handler, slot, rights, type }`, validates the number, and — for syscalls whose authority is a single fixed capability — enforces it in one central place before calling the handler. A number with no entry fails closed. A `_Static_assert` pins the table size to the highest syscall number + 1. Syscalls with dynamic or self-authorising policy (the capability ops, FS ops, auth/sudo, user management, kill/signal/grant, pipes) authorise inside their handler.

---

## User authentication and audit

### User database

Up to 32 users are stored in a kernel-managed table serialised to the filesystem, authenticated with an HMAC-SHA256 tag keyed by the per-boot pepper. Each entry holds username, UID, GID, home/shell paths, a random per-user salt, a password hash, and a failure counter. Defaults are `root`/`rootpass` and `user`/`password`; changes persist across reboots.

Password hashing is **Argon2id** (RFC 9106) — the memory-hard KDF — implemented from scratch in safe Rust (`argon2.rs`) on the crate's own BLAKE2b (`blake2b.rs`) and validated against `argon2-cffi` vectors. It folds in the per-user salt and a per-boot pepper; the raw 32-byte tag is stored. Multi-lane capable (validated at p=2/p=4); the kernel runs 4 MiB / 3 passes / 1 lane. Verification is constant-time and equalised so a missing username is timing-indistinguishable; lockout and a global anti-spray throttle live in `auth.rs`.

### Forward-secure audit log

The kernel maintains a 256-entry circular buffer recording event type, timestamp, subject UID, object identifier, and result. The log is **forward-secure** (forward integrity, Bellare–Yee / Schneier–Kelsey). Each entry's MAC and the running chain head are keyed by an evolving key `K_i` that is **ratcheted one-way** (`K_{i+1} = SHA256(domain ‖ K_i)`) and **erased in place** the instant the next entry is recorded (`rust_audit_fs_record`); the genesis key derives from the per-boot pepper without touching it. Because the ratchet is one-way and old keys are erased, **a kernel compromised at time _t_ cannot recompute or forge the MAC or head of any entry committed before _t_** — pre-compromise history is cryptographically unforgeable, verified by an external monitor that records the chain head via `SYS_AUDIT_DIGEST`. A separate **unkeyed** sliding-window hash lets the kernel still self-check the retained ring for accidental corruption after the keys are gone. Entries written *after* a compromise, and whole-machine rollback, still need an external append-only anchor (a TPM NV counter / remote WORM) — the honest ceiling for a self-hosting kernel. The keyed-hash and ratchet logic lives in safe Rust (`audit.rs`); the C side owns the ring storage.

---

## Measured boot and TPM sealing

A minimal **TPM 2.0** TIS/FIFO MMIO driver records the reproducible boot hash chain into the TPM's PCRs: a kernel-identity token into `PCR[8]` and each **verified** boot module into `PCR[9]`. The boot state is therefore attested at runtime, not only checked at build time (the SHA-256 module manifest above).

A persistent volume formatted with a TPM present is sealed in **TPM mode**: its `disk_key` KEK becomes two-factor, `HKDF(password-KEK, tpm_secret)`, where `tpm_secret` is TPM2-sealed under a `PolicyPCR(PCR[8], PCR[9])` and released only by a measured-good boot. A tampered module changes `PCR[9]`, the TPM refuses the unseal (TPM-enforced, not an in-kernel check), and the volume stays locked. A machine with no TPM (and the release `boot.iso`) is unaffected — a password-mode volume with `tpm_mode = 0`. Gated by `make smoke-tpm{,-tamper,-seal,-seal-roundtrip}` under an emulated TPM (swtpm). Residual: local sealing, not remote attestation (no `TPM2_Quote` yet), and no bus parameter-encryption (the emulated bus does not need it).

---

## Rust integration

The crate at `rust/` compiles to a static library linked into the kernel — a `no_std` crate, no allocator, no OS dependencies. Data crosses the C/Rust boundary as raw pointers/integers via FFI shims.

| Module | Role |
|---|---|
| `capability.rs` | Capability mint/transfer/move/grant/revoke + lineage |
| `memory.rs` | Physical page reference counting and validation |
| `lib.rs` | Page-fault validation, demand-paging + W^X page policy, signal-handler window, ELF parse, command-token parsing |
| `sha256.rs` | SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2 |
| `blake2b.rs` | BLAKE2b (RFC 7693) — the hash under Argon2id |
| `argon2.rs` | Argon2id (RFC 9106) memory-hard password hashing |
| `rng.rs` | ChaCha20 fast-key-erasure CSPRNG; RDRAND + timing-jitter seeding |
| `aead.rs` | ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (encryption-at-rest) |
| `audit.rs` | Forward-secure audit log: ratcheted per-entry MAC + chain head |
| `auth.rs` | Auth/sudo lockout + anti-spray throttle; least-privilege sudo frame |
| `ps.rs` | Task state-name labels for the `ps` renderers |

The crate contains no `unsafe` in its logic. The unavoidable `unsafe` is the FFI boundary — the `rust_*` entry points are `unsafe extern "C"` because they dereference C-supplied pointers. Each carries a documented `# Safety` contract, validates its arguments (null/length, fail-closed), and copies through fixed-size local buffers. The *surface* is the whole FFI API, but the *risk* is confined to those thin, contract-checked shims; all computation behind them is safe Rust. Parts carry machine-checked proofs (Kani) and coverage-guided fuzzers (`cargo-fuzz`), run as advisory CI jobs.

---

## Reproducible builds

The build sets `SOURCE_DATE_EPOCH=1609459200` and `-frandom-seed=horus`, links with `--build-id=none`, and builds the Rust with `--locked`, `opt-level=z`, `lto=true`, `codegen-units=1`. The result is a byte-for-byte identical `kernel.elf` across clean builds on the same toolchain. `make reproducible-build` builds twice and diffs; reference checksums are in `.build.sha`.

---

## Security properties

**What the design provides:** no ambient authority; transitive descendant-only revocation with use-after-revoke prevention; least-privilege delegation (`CAP_TCB`-gated kill/signal/grant); primordial-capability protection; hardware user/kernel isolation (SMEP/SMAP/UMIP); W^X for user memory and the kernel image; kernel state unaddressable from ring 3 by construction; register-file isolation; side-channel flush-on-switch + SMT-off + `CR4.TSD`; a forward-secure audit log; measured boot + TPM-sealed storage; centralised fail-closed syscall authorisation; signals that grant no new authority.

**What it does not yet provide** — see [LIMITATIONS.md](LIMITATIONS.md). Key gaps: IPC endpoints are single-slot mailboxes (multi-client *replies* routed by identity, but no multi-slot queueing); the multi-core scheduler shares one runnable pool with no per-CPU queues, priorities, or affinity; cache *partitioning* is not done; the audit log's post-compromise/rollback ceiling needs an external anchor; and the build's provenance (independent review, pinned/attested toolchain) is the open high-priority item (Roadmap Track 0).
