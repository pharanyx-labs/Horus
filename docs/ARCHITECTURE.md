# Horus Architecture

This document describes the design and internals of the Horus microkernel. It is intended for contributors wanting to understand the system before working on it, and for anyone evaluating the design.

---

## Design philosophy

Horus is built around one principle: **no ambient authority**. A task cannot access any resource — files, other tasks, devices, memory — unless it holds an explicit capability token granting that access. The kernel enforces this at every system call boundary.

The secondary goal is **verifiability**: the most security-sensitive operations (capability manipulation, memory reference counting, the cryptographic primitives, the W^X policy) are implemented in safe Rust, where the type system statically rules out whole classes of memory safety bugs.

Horus is a microkernel. The kernel handles only what must run in Ring 0: memory management, capability enforcement, task scheduling, interrupt handling, and a thin encrypted block/inode store. Filesystem *semantics* and device policy live in userspace, communicating via IPC — the filesystem is a ring-3 server (`userspace/fs_server.c`).

---

## Target hardware

Horus targets **x86-64** exclusively.

- The kernel runs in 64-bit long mode: PML4 paging, 48-bit virtual addresses, `mcmodel=kernel`.
- Bootloader: **Multiboot2** compatible (GRUB2).
- CPU features detected at runtime: SMEP, SMAP, AES-NI, SSE2/SSE4.2, TSC, RDRAND.
- Multi-core: application processors are brought up via the LAPIC (INIT-SIPI-SIPI), each with its own LAPIC-timer preemption tick. SMP is **default-on** (the CPU count comes from the ACPI MADT); `SMP=0` compiles the whole subsystem out and boots single-core on the PIT path.

Ring-3 userspace is 64-bit too: tasks run under the GDT's 64-bit user code segment (`cs = 0x23`, L=1/D=0/DPL=3) as static-PIE `EM_X86_64` images, relocated at load. Userspace was `EM_386` in compatibility mode until the 64-bit ABI landed.

The only 32-bit code left is the boot on-ramp, and it cannot go: an x86 CPU starts in real mode, GRUB enters `_start` in 32-bit protected mode, and an application processor comes out of SIPI in real mode. The `.code32` multiboot stage and the `.code16`/`.code32` AP trampoline are how long mode is reached at all. One deliberate exception in the test tree: `userspace/elftest.o` is still built 32-bit so `smoke-elf` keeps exercising the loader's ELFCLASS32 path, which remains supported.

---

## Memory layout

### 64-bit virtual address space

| Region | Virtual address | Notes |
|---|---|---|
| Kernel image | `0xFFFFFFFF80100000` | `.text`/`.rodata`/`.data`/`.bss`, linked at `KERNEL_VMA` + 1 MiB, **loaded at physical 1 MiB** |
| Physical alias (`PHYS_KVA`) | `0xFFFFFF8080000000` | Physical `[0, 1 GiB)` aliased read/write; present in **every** address space |
| Low identity map | `0x0000000000000000` | Physical `[0, 1 GiB)` as 2 MiB supervisor pages. Retained: see below |
| LAPIC | `0x00000000FEE00000` | Identity-mapped MMIO, replicated into every address space |
| Boot stage (`.boot`) | `0x0000000000100000` | VA == PA. The 32-bit entry code and its GDT/stack; dead after long mode |
| User text (PIE base) | `0x0000000400000000` + random | PIE image relocated to `USER_IMAGE_ASLR_BASE` (16 GiB) + a random page offset in a 4 TiB window (**30 bits**). `0x400000` (4 MiB) is only the flat/non-PIE fallback base and the loader floor |
| User heap | `0x0000000001000000` | Grows upward via `sbrk`/`brk` |

**The kernel runs at `-2 GiB`** (`KERNEL_VMA = 0xFFFFFFFF80000000`), so no kernel address is
a user address. That base is forced, not chosen: `-mcmodel=kernel` lets GCC emit 32-bit
*sign-extended* symbol references (`R_X86_64_32S`), valid only in `[-2 GiB, +2 GiB)`, and
this is the top half of that range. A "canonical higher-half" base such as
`0xFFFF800000000000` would break every one of them and force `-mcmodel=large`. (The old
1 MiB link satisfied `-mcmodel=kernel` only by accident — the signed-32 range is symmetric
about zero, so the *low* 2 GiB fits too.)

`0xFFFFFFFF80000000` decodes to PML4[511], PDPT[510] — the same `high_pdpt` that already
held the `PHYS_KVA` window at PDPT[2]. The kernel's mapping is therefore one more entry in
an existing table, aliasing the same `pd`. Physical placement is unchanged: each high
section carries `AT(vma - KERNEL_VMA)`, so `p_paddr` stays low and GRUB (which honours
`p_paddr`) loads the kernel at 1 MiB as before.

**`.boot` is linked VA == PA** because GRUB enters `_start` in 32-bit protected mode: a
32-bit `movl $sym, %edi` cannot encode a high address, and the far jump that activates long
mode is absolute and executes *after* `CR0.PG`. It therefore lands in a low 64-bit stub,
which escapes to the kernel's linked addresses via `movabs` + `jmp *%rax`. The boot stage
names kernel symbols as `sym - KERNEL_VMA`.

**The low identity map can never be dropped**, even though the kernel no longer lives
there: the SMP trampoline far-jumps to ~`0x8000` after enabling paging on the kernel's own
CR3, and the LAPIC/VGA MMIO are reached at their physical addresses.

**A user page directory contains only the task's own mappings.** `create_user_pagedir`
builds `pml4[0]` → PDPT → PD with nothing in it but the image premap and the low stack;
every other entry is not-present. The kernel half (`pml4[256..511]`) is copied from the
kernel PML4 with `PAGE_USER` stripped, which is how the kernel — and `PHYS_KVA` — remain
addressable on a user CR3 while ring 3 cannot reach any of it.

This is the property the whole exercise was for: a user mapping cannot shadow kernel state
**by construction**, rather than because ASLR is bounded away from it. It used to
identity-fill PD[0..7] — physical `[0, 16 MiB)` as supervisor huge pages — because the
kernel was linked low and had to reach `tasks[]` and its own `.bss` while on a user CR3.

Removing that fill also un-broke demand paging in the low window: a fault there now finds a
not-present page and reaches the pager, instead of finding an identity-supervisor page and
being declined with "already present". The pager gates every mapping on
`rust_validate_page_fault`, which approves only the faulting task's own image, heap and
stack regions.

**Physical access from the fault handler.** The user page pool starts at `USER_PHYS_BASE`
(16 MiB) and a user address space maps none of it directly. The demand pager runs on the
faulting task's CR3 and must read page tables and zero/copy freshly allocated frames, so it
reaches them through the higher-half alias (`PHYS_KVA`, `VA(pml4=511, pdpt=2)` → physical
`[0, 1 GiB)`) that `create_user_pagedir` replicates into every task via `pml4[256..511]`.
Using a low identity address instead faulted *inside* the fault handler, which then
re-entered the `page_lock` it already held with interrupts disabled — a hard hang.

**Image size is capped at the premap**, not by the address space: `try_elf_load` writes
segments with `copy_to_user`, which walks the page tables and requires a present `PAGE_USER`
page — it does not fault, so it cannot demand-page. Only the `USER_ASPACE_PREMAP_PAGES`
(32 → 128 KiB) premapped pages are writable at load time. A task can now fault in the rest
of its own image region at runtime, but growing the loadable image needs the premap to grow
or `user_copy` to demand-page.

### Physical memory

| Region | Physical address | Purpose |
|---|---|---|
| User page pool | `0x01000000` | 16,384 × 4 KB pages (64 MB) |
| Kernel stacks | allocated at init | 64 × 32 KB, one per task slot |

### Paging

The kernel reaches page tables through the **higher-half physical alias** (`PHYS_KVA`, see
Memory layout above), not through the slot-510 self-map — the self-map is installed and
kept current, but no code reads through it.

**Kernel address translation.** A kernel symbol's virtual address is `KERNEL_VMA` above its
physical address, so a `(uint64_t)&sym` written into CR3 or a page-table entry is a bug: it
sets bits above 51 and takes a reserved-bit fault. `virt_to_phys()` / `phys_to_virt()`
(`kernel.h`) are the conversion — use them for kernel image addresses, and `PHYS_KVA` to
reach an arbitrary physical page. They do **not** apply to `.boot`, which is linked VA == PA.

`KERNEL_VMA` is defined twice, in `linker64.ld` (the authority on placement) and
`src/include/kernel_vma.h` (shared by C and the boot assembly), because a linker script
cannot include a header. They are cross-checked rather than trusted: the linker exports its
value as `__kernel_vma_from_linker` and `kernel_main` asserts the two agree at boot, along
with "am I executing above `KERNEL_VMA`" and a `virt_to_phys`/`phys_to_virt` round-trip.
That check prints `HIGHHALF: PASS` on the serial console and halts on failure — a botched
relocation is loud rather than a mystery fault later.

**Copy-on-write** is implemented at the page level. Shared pages are marked `PAGE_COW` and mapped read-only; the first write faults `present|write`, and the pager gives the faulting address a private frame, clears `PAGE_COW`, and preserves the page's NX bit. Physical pages carry reference counts maintained in Rust (`rust_page_ref_inc`, `rust_page_ref_dec`), and the COW-copy-vs-demand-zero decision logic is unit-tested.

The pager's main producer of `PAGE_COW` mappings is the **shared zero page**. A demand-zero *read* installs one immortal, read-only zero frame (allocated once in `paging_init`) rather than a fresh page per fault, so reading a sparse heap costs one physical page in total. Breaking it on write is a special case rather than a copy: duplicating an all-zero frame just means handing out a zeroed page, so the pager allocates one and returns without touching the zero frame's refcount — correct precisely because that frame is aliased by many PTEs and must never be moved or freed (`free_user_physical_page` refuses it by address). Only a shared **non-zero** page reaches the generic copy path, and nothing in the tree creates one today, as `fork` is a non-goal.

Two subtleties bind this together. The pager derives the old frame with `PTE_ADDR_MASK`, not `& ~0xFFF`: the latter leaves NX (bit 63) set, so a no-execute page's "frame address" would not compare equal to the zero frame and the pager would dereference a wild address while holding `page_lock`. And `user_copy` breaks COW itself before writing — a `copy_to_user` into a read-only shared zero page is a *kernel* write that must not fault on a page the kernel is about to fill.

**W^X**: `EFER.NXE` is enabled at boot and the kernel uses the PTE NX bit (63) to keep writable pages non-executable. User stacks (low and high ASLR) are mapped no-execute. The ELF loader honours each `PT_LOAD` segment's `p_flags`, mapping code read+execute and data/rodata read[+write]+NX; the policy decision (`rust_user_page_is_noexec`) lives in Rust and is unit-tested. The shipped userspace binaries are static-PIE ELFs and take this path; a flat-binary fallback remains for non-ELF images (loaded at the fixed base, image left executable).

**ASLR**: per-spawn stack top, heap gap, **and image load base** are randomised from the CSPRNG. Userspace is built static-PIE (`ET_DYN`); `do_spawn` picks a random page-aligned base and `try_elf_load` relocates there, failing closed on any relocation type it does not implement. Both forms are handled: `R_386_RELATIVE` (i386 REL — 8-byte entries, read-modify-write, type in `r_info & 0xFF`) and `R_X86_64_RELATIVE` (RELA — 24-byte entries, `*(u64*)(r_offset+slide) = slide + r_addend`, type in `r_info & 0xFFFFFFFF`). The two agree for ld-linked images because GNU ld pre-applies the addend into the field; they diverge only for a linker that does not (lld's `--no-apply-dynamic-relocs`).

Image-base entropy is **2³⁰ page-aligned positions = 30 bits**, a 4 TiB window above `USER_IMAGE_ASLR_BASE` (16 GiB) — set by `ASLR_MAX_LOAD_RANDOM_PAGES` (`1 << 30`). The image sits in its own base region, clear of the fixed low regions (the ~8 MiB stack and the 16 MiB heap), so the window can be this wide without colliding with them. The earlier ~8.91-bit figure (`log2(512 − 32)`) was not a policy choice but the shape of the old single-PD-entry premap; the multi-level page-table walk removed that constraint, and the entropy is a genuine choice now.

---

## Capability system

The capability system is the core security mechanism. All other security properties derive from it.

### What a capability is

A capability is an unforgeable token residing in a task's **capability node (CNode)**. Each CNode has 256 slots. Low slots are reserved for kernel-assigned capabilities (see the endowment table below); higher slots are available to userspace. All 256 slots are **zeroed to `CAP_NULL` when a task slot is allocated** (`create_task` in `scheduler.c`), so a reused slot cannot inherit the dead task's capabilities.

```c
typedef struct capability {
    uint32_t type;     /* CAP_TCB, CAP_FRAME, CAP_FILE, CAP_ENDPOINT, ... */
    uint32_t rights;   /* bitmask: READ | WRITE | EXEC | GRANT | MINT | REVOKE | ... */
    uint64_t object;   /* identifies the governed object */
    uint32_t badge;    /* parent serial, used for revocation tracking */
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
| `CAP_DIR` / `CAP_FILE` | 12 / 13 | *reserved* — the legacy capfs directory / file objects they governed have been removed |

### Rights bitmask

| Right | Bit | Meaning |
|---|---|---|
| `CAP_RIGHT_READ` | `0x001` | Read the object |
| `CAP_RIGHT_WRITE` | `0x002` | Write to the object |
| `CAP_RIGHT_EXEC` | `0x004` | Execute or invoke |
| `CAP_RIGHT_GRANT` | `0x008` | Transfer a copy to another task |
| `CAP_RIGHT_MINT` | `0x010` | Derive a new capability with a subset of rights |
| `CAP_RIGHT_REVOKE` | `0x020` | Revoke this and all derived capabilities |
| `CAP_RIGHT_AUDIT_WRITE` | `0x040` | Append to the audit log |
| `CAP_RIGHT_FS_*` | `0x400+` | *reserved* — the legacy capfs rights (`LOOKUP`, `CREATE`, `DELETE`, `READ`, `WRITE`); no longer used now that capfs is removed |

### Capability operations

All capability operations live in `rust/src/capability.rs` (safe Rust) and are called from the C kernel over FFI.

| Operation | Effect |
|---|---|
| **Mint** | Creates a derived capability with a subset of the parent's rights. The new capability records the parent's serial as its badge. |
| **Transfer** | Copies a capability into another task's CNode with the same rights. |
| **Move** | Transfer, then immediately nullify the source slot. |
| **Grant** (`SYS_CAP_GRANT`) | A supervisor that holds a child's `CAP_TCB` copies one of its own cap slots into a chosen slot of that child's cspace — least-privilege delegation at spawn time. |
| **Revoke** | System-wide. `rust_cap_revoke_global` nullifies the target capability, then sweeps **every live task's CNode plus the kernel root cnode**, nullifying any capability whose serial/badge/object matches the revoked lineage, and bumps the lineage generation counter exactly once. |

### Revocation and lineage

Revocation is **complete, not caller-local**: the C wrapper `cap_revoke` (under `cap_lock`) builds the list of all live cspaces and passes it to `rust_cap_revoke_global`, which performs the entire sweep inside one Rust call. A derived capability copied into another task's CNode is therefore revoked together with its parent — there is no window in which another task retains access after revocation.

The system additionally prevents use-after-revoke via a **lineage table** (`LINEAGE_SLOTS` = 4,096 entries). Each entry is a generation counter, and the Rust table is the single source of truth. When a capability is minted it records the current generation for its lineage slot; at use time `rust_cap_lookup` checks whether the stored generation still matches. A revocation bumps the counter, so even a stale bit pattern that escaped the structural sweep fails the generation check immediately. The structural sweep and the generation bump are defence-in-depth for the same invariant.

**Primordial capabilities** — root capabilities assigned at boot, identified by the `0xC0DE` serial prefix — cannot be revoked. A serial-range check in the Rust revocation path enforces this.

> **Audit note (2026-07, finding A1 — being reworked).** The sweep currently
> matches a capability's `serial`, its `badge` (which records the *parent's*
> serial), **or** its `object`. That matches descendants, but also **ancestors,
> siblings, and any unrelated capability to the same object** — so revocation is an
> equivalence-class operation, not a derivation-subtree operation. Revoking a
> *granted* capability can therefore also null the grantor's original. This
> **fails safe** (it over-revokes; it never leaves stale authority live), but it is
> broader than the least-privilege-delegation model intends. The planned fix is an
> explicit capability derivation tree (CDT) so `revoke(T)` deletes exactly `T`'s
> subtree. Related: the lineage-generation table is a lossy 4096-slot hash keyed by
> `object` (finding A3), and `SYS_CAP_GRANT` copies full rights and skips the
> locked reserved-slot/`caps_in_use` discipline (finding A2). See
> [AUDIT-2026-07.md](AUDIT-2026-07.md) and [ROADMAP.md](ROADMAP.md) Track 1.

---

## Task model

Horus supports up to 64 concurrent tasks. Each task has:

- A **Task Control Block (TCB)** with a saved trap frame / register state (`rip`, `rsp`, `cr3`, `saved_ksp`)
- A **capability node** (256 slots)
- A dedicated **kernel stack** (32 KB) used during syscall and interrupt handling
- A 512-byte **FXSAVE image** (`fpu_state`) holding its x87/SSE register file across kernel entries
- A **user heap** tracked by `heap_start`, `heap_current`, `heap_end`
- A **UID and GID** login identity establishing its authentication context, which the kernel attests to servers (via `SYS_IPC_SENDER`) so a ring-3 filesystem can enforce ownership a client cannot forge
- A **signal handler** (`SYS_SIGACTION`) and a `pending_sig` slot for async delivery

A task's state is one of `TASK_DEAD` (0), `TASK_RUNNABLE` (1), `TASK_BLOCKED_IPC` (2), `TASK_BLOCKED_NOTIF` (3), or `TASK_BLOCKED_WAIT` (4).

### Scheduling

The scheduler is preemptive round-robin. The PIT fires at 100 Hz (BSP); under `SMP=1` each application processor runs its own LAPIC-timer tick. On a tick that interrupted **ring 3**, the timer ISR switches to the next runnable task by swapping the per-task kernel stack that holds its full interrupt trap frame — `preempt_on_tick` returns the kernel `%rsp` to resume on, and the ISR epilogue `iretq`s into it. A freshly spawned task gets a fabricated initial frame (`sched_prepare_user_context`) so the timer (or a block/switch) can `iretq` into it at its entry point. A tick that lands in **ring 0** (mid syscall or handler) never switches — the kernel is effectively non-preemptible, which sidesteps lock/reentrancy hazards.

**Blocking** (a blocking `SYS_IPC_CALL`, `SYS_WAIT_NOTIFY`, or `SYS_WAIT`) uses the *same* full-context mechanism: the handler marks the task blocked and returns, and the `int 0x80` epilogue saves its trap frame and switches to the next runnable task via `ipc_block_switch`. When the blocking condition clears (a reply arrives, or a target task's `task_teardown` wakes a `SYS_WAIT` waiter — on a clean exit **or** a fault), the task is made runnable again and resumes via its saved frame.

There is a single context-switch path: every task enters and resumes via a full interrupt trap frame on its kernel stack (`sched_prepare_user_context` at spawn, `sched_enter_user` for first entry / boot of `init`, timer preemption, `ipc_block_switch` for blocking syscalls, `sched_yield_switch` for `SYS_YIELD`). The legacy cooperative `yield()`/`schedule()` switch (which swapped CR3/current but returned on the caller's own kernel stack) has been deleted. Multi-core scheduling shares a single runnable pool with a per-CPU pull under a raw scheduler lock; per-CPU run queues and priorities are future work.

### x87/SSE context

The trap frame saves general-purpose registers only, so the x87/SSE register file needs its
own handling. Each task carries a 512-byte FXSAVE image in its TCB: `interrupt_handler64`
saves on entry from ring 3 and restores on return to ring 3, keyed on the *current* task at
each moment — the dispatcher may have switched, so the restore loads the task actually being
`iretq`'d into. A ring-0 → ring-0 interrupt skips both.

The kernel is built `-mno-sse -mno-mmx -mno-80387` and holds no FPU state of its own. That
is what makes the above cheap (nothing to save on a kernel-internal interrupt) and what stops
the leak in the other direction: left to itself GCC auto-vectorises ordinary integer loops,
and anything the kernel leaves in `xmm` would be readable by the next ring-3 task. `crypto.c`
is not an exception — its `-msse2 -maes` was vestigial, naming an AES-NI cipher that no longer
exists (encryption-at-rest is ChaCha20 + HMAC-SHA256 in safe Rust).

This was latent for as long as userspace was i386: SSE2 is not in that baseline, so generated
code never held a live `xmm` across a syscall. Under `-m64` SSE2 *is* the baseline, and the
bug became data corruption — GCC compiled a 16-byte fill in the fs client into a broadcast
plus one `movups`, hoisted the broadcast out of the loop, and left it live in `xmm0` across
`sys_ipc_call`; the fs_server's leftover `xmm0` was stored as file data and written to disk
with every checksum agreeing. `smoke-fs-conc` is the regression test.

### Process control (ring-3, Phase 1)

Tasks are first-class from ring 3. A task can `SYS_SPAWN` a named embedded binary (the load runs in the kernel address space; the caller receives the child's `CAP_TCB`), replace its own image in place with `SYS_EXEC_NAMED` (same pid and cspace), delegate a capability into a supervised child with `SYS_CAP_GRANT`, terminate itself (`SYS_EXIT`) or a task it holds a `CAP_TCB` for (`SYS_KILL`), and block until another task exits (`SYS_WAIT`). Both spawn and exec take a full `argv`: the kernel copies the vector out of the caller's address space and lays the strings + a NULL-terminated pointer array on the child's initial stack, which the child reads back with `SYS_GET_ARGV`.

A ring-3 **`init` (PID 1)** launches at boot. The kernel endows it with `CAP_AUDIT` plus the `CAP_CONSOLE` and `CAP_ENCRYPTED_STORAGE` it hands to the shell. `init` spawns the shell, delegates those two caps with `SYS_CAP_GRANT` (authorised by the shell's `CAP_TCB` it holds from the spawn), and then **blocks in `SYS_WAIT`** on the shell — consuming no CPU while the shell runs — relaunching it if it ever exits or faults.

### Signals

A task registers its own handler with `SYS_SIGACTION`. Two delivery paths share it:

- **Fault signals.** When the task faults in ring 3 (a page fault or a CPU exception such as `#UD`), `try_deliver_fault_signal` (`idt.c`) — instead of killing it — saves the full trap frame in the TCB and rewrites the live frame to enter the handler at ring 3, passing the signal number in `rbx` and the faulting address in `rcx`. `SYS_SIGRETURN` (serviced directly in `interrupt_handler64`) restores the saved context for an exact resume.
- **Async task-to-task signals** (`SYS_SIGNAL`, gated on a `CAP_TCB` to the target — same authority as `SYS_KILL`). The sender queues `pending_sig`; the target is redirected into its handler on its next return to ring 3 (reusing the fault-signal path). An unhandled signal, or the uncatchable `SIG_KILL`, takes the default terminate action.

Pending signals are held in a full 1..31 bitmask, and `SYS_SIGMASK` blocks/unblocks signals (`SIG_KILL` excepted); `deliver_pending_signal` delivers the lowest-numbered *unmasked* pending signal, and a masked one stays queued until unblocked. A signal to a task parked in `SYS_WAIT` interrupts the wait (it returns `SYS_ERR_INTR`) and is delivered promptly rather than waiting on the awaited task.

The handler entry is validated to the user code window in safe Rust (`rust_signal_handler_addr_ok`), a fault *inside* a handler is not re-delivered (the `in_signal` guard prevents loops), and the handler runs at ring 3 with unchanged privileges — so signals add recovery/notification without granting any new authority. `SYS_SIGALTSTACK` registers an alternate signal stack: a signal delivered while the task is not already on it enters the handler on `[ss_sp, ss_sp+ss_size)` (`SS_ONSTACK`), so a corrupt or overflowed primary stack cannot stop the handler running; the alternate stack is cleared on `SYS_SIGRETURN`.

---

## IPC

IPC is endpoint-based. The kernel maintains 64 endpoints. A sending task writes a message to an endpoint; a task waiting on that endpoint receives it. Messages carry a small payload (up to 256 bytes) and a sender badge.

Each endpoint is a **single-slot mailbox**. `SYS_IPC_SEND`/`SYS_IPC_RECV` are **non-blocking** (they return a would-block code rather than spinning), so a userspace peer polls from ring 3 where the timer interleaves it with the other party. `SYS_IPC_CALL` may block the caller (`TASK_BLOCKED_IPC`) on the full-context block/switch path and is resumed when the reply arrives. Requests still serialise one at a time through an endpoint's single slot, but replies do **not** have to: `SYS_IPC_REPLY_TO` routes a reply straight into the requesting client's blocked call by kernel-recorded sender identity, which is what lets one server hold several clients at once (see the filesystem server below). Per-endpoint multi-slot queueing remains future work. A snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window across the send/recv paths.

**Block/wake publish order (SMP-safe):** the syscall handler only records a `pending_block` intent. `ipc_block_switch` then (1) stores the live trap frame in `saved_ksp`, (2) issues a full memory barrier, and (3) publishes the waiter under the IPC lock (`blocked_waiter` / `SYS_WAIT` link / notif waiter + `TASK_BLOCKED_*`). A notifier on another core therefore never patches a null or stale frame. If the event already arrived (reply in the mailbox, target already dead, badge pending), publish completes the wait immediately and resumes the same task.

**Notifications** (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) complement endpoints with an async, badge-carrying signal. `SYS_NOTIFY` ORs a 32-bit badge into one of `MAX_NOTIFICATIONS` slots and, if a task is blocked waiting on that slot, wakes it — patching the accumulated badge into the waiter's saved trap frame (`rbx`) so no cross-address-space copy is needed; otherwise the badge accumulates until the next wait. `SYS_WAIT_NOTIFY` returns a pending badge immediately, or blocks via the same full-context path as IPC/`SYS_WAIT` (the badge comes back in `ebx`). Proven end-to-end by `make smoke-notify`.

### Userspace filesystem server

Filesystem *semantics* run in a ring-3 server (`userspace/fs_server.c`), which is the system's **single** filesystem and its reference monitor. The kernel provides only a **persistent, encrypted object store** — inode allocation and per-(inode, block) AEAD I/O via syscalls 56–61 (`SYS_FS_INODE_ALLOC`/`_FREE`, `SYS_FBLOCK_READ`/`_WRITE`, `SYS_FS_STAT`, `SYS_FS_SET_SIZE`) plus owner/mode persistence (`SYS_FS_SET_META`, 74), gated on `CAP_BLOCK_DEV` + uid 0. Encryption keys never leave the kernel TCB. The server builds directories (as inode data; root = inode 0), path resolution, and file sizes on top, and answers clients over IPC using the protocol in `include/fs_proto.h` (requests on endpoint 4, each client's reply-wait on 5). The block store (`storage.c`) probes for an ATA disk at boot and uses the encrypted ATA backend when one is present (files and per-block crypto metadata survive reboot; the volume is sealed until login), falling back to an ephemeral RAM vdisk when none is attached.

The server enforces **per-file POSIX owner/group/other rwx and ownership** against the caller's *kernel-attested* identity — `SYS_IPC_SENDER` returns the sending task's login uid/gid, which a client cannot forge or place in the request — with root (uid 0) the only ambient authority (`chmod` is owner-or-root, `chown` is root-only). It serves **multiple clients concurrently**: it replies with `SYS_IPC_REPLY_TO`, which routes each reply directly into the requesting client's blocked `SYS_IPC_CALL` by kernel-recorded sender, never via a shared reply endpoint another client could observe (requests still serialise one at a time). Every multi-block update is **crash-atomic** via a write-ahead redo journal (v5 on-disk format) with an HMAC-authenticated header, replayed at the next mount, and a mount-time `fsck` reclaims orphaned inodes and leaked blocks. Files map through direct + single-indirect + double-indirect blocks (up to 12 + 64 + 64×64 = 4172 blocks). The volume is **16 MiB** (32768 blocks, ~14 MiB usable): the data allocator uses a **multi-block bitmap** (the inode allocator stays single-block), and the metadata rollback-HMAC (`sb.meta_hmac`, which detects a physical attacker rolling back per-block nonce/tag metadata) is **hierarchical** — a top MAC over per-meta-block MACs — so a single block write refreshes one block's MAC plus the top, and the per-write cost does not scale with the volume. Proven end-to-end by `make smoke-fs`, `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, and `smoke-fs-large`.

The earlier parallel **in-memory capfs** (`SYS_FS_*`, syscalls 38–45) has been **removed** — its engine and objects are gone, the syscall numbers fail closed and are reserved — leaving the encrypted `fs_server` as the one capability-mediated, permission-enforcing filesystem.

**Programs and their man pages load from this filesystem, not the kernel image.** At startup the `fs_server` builds a directory skeleton — `/bin`, `/etc`, `/home`, `/lib`, `/usr`, `/usr/share/man` — so a fresh `ls` shows a real layout rather than an empty root (`provision_boot_modules`, idempotent). Only the core binaries that must run before any filesystem exists (`init`, `shell`, `fs_server`, `hello`, `captest`) are embedded in the kernel image; other content — the ported GNU coreutils and their man pages — ships as **GRUB multiboot2 modules** that GRUB loads into RAM outside the image (so the 16 MiB image budget stops applying). The kernel records each module from the boot tags and exposes it read-only over `SYS_BOOT_MODULE_INFO`/`SYS_BOOT_MODULE_READ` (77/78, gated on the same `CAP_BLOCK_DEV` + uid 0 authority as the store, since a module is a TCB-supplied image at that trust tier). Each module's cmdline is its **destination path** in the store (`bin/<name>` for a binary, `usr/share/man/<name>` for a man page); the `fs_server` creates any missing parent directories and writes a root-owned file there (executables `0755`, data `0644`). The shell runs a binary by resolving `/bin/<name>`, loading the image over the `fs_server`, and handing it to `SYS_SPAWN_IMAGE`; `man <name>` reads `/usr/share/man/<name>` from the store (falling back to a built-in page table for shell builtins and module-free kernels). `init` blocks on a notification until the `fs_server` signals provisioning is done before launching the shell, so the block-by-block copy into the store runs with the CPU to itself and `/bin` is populated before the first command. The 16 MiB store volume holds every ported coreutils binary in `/bin` plus its man page at once; provisioning is ordered and skips anything that would not fit, but on this volume nothing is dropped.

### Ring-3 console server

The console (VGA text framebuffer + serial) is driven by a ring-3 server, `console_server`, not by the kernel — the first driver moved out of the kernel's flat trust domain (Phase 6). At boot `init` launches it and delegates it two capabilities: a `CAP_ENDPOINT` for IPC and a `CAP_IO_DEVICE` that gates the three device-delegation mechanisms it needs — mapping the framebuffer into its own address space (`SYS_MAP_PHYS`, restricted to a fixed device-frame allowlist), native `in`/`out` on the console ports via a per-task TSS I/O-permission bitmap (`SYS_IOPORT_GRANT`), and routing a hardware IRQ to a notification (`SYS_IRQ_REGISTER`). The shell sends output (`CON_OP_WRITE`) and reads input (`CON_OP_GETLINE`/`GETPASS`, with the server doing line editing, echo, and password masking) over the same reply-by-identity IPC the filesystem server uses; it falls back to the in-kernel console if the server is ever unreachable. The kernel retains only a minimal serial writer for panic and early-boot output. Because it is a ring-3 task, a bug in the console driver is contained as an ordinary ring-3 fault (`make smoke-console-isolation`) rather than reaching kernel state. See `docs/proposals/console-server.md`.

---

## Symmetric multiprocessing

Horus brings up the application processors and runs scheduled tasks across cores. SMP is **default-on** (`SMP=0` compiles it out and boots single-core):

- **AP bringup** via the LAPIC INIT-SIPI-SIPI sequence; each AP sets up long mode, its GDT/TSS/IDT, and enters the scheduler.
- **Per-CPU preemption** from the LAPIC timer (the legacy PIC IRQ0 only reaches the BSP); a shared runnable pool with a per-CPU pull under a raw scheduler lock is the load-balancing mechanism.
- **IPC + notification locking** so cross-CPU sends/receives serialise correctly.
- **TLB-shootdown IPIs** with acknowledgement, so a CPU that changes a shared mapping flushes the others' TLBs before proceeding.

The BSP is never pulled out of its ring-0 idle/kernel context by the timer, preserving the exact single-CPU boot flow; the APs do the multi-core work. Proven by `make smoke-smp`. Per-CPU run queues, priorities, and flush-on-switch between time-sliced tasks are the remaining SMP-maturity work (Roadmap Track 3).

---

## Syscall interface

Syscalls use `int 0x80`. The syscall number is in `rax`; arguments in `rbx, rcx, rdx, rsi, rdi`. Arguments and the return value are 64-bit — they carry user pointers, and `SYS_BRK`/`SYS_SBRK` return an *address*, so a 32-bit return would truncate the program break. Numbers run `SYS_YIELD` = 0 through `SYS_IPC_REPLY_TO` = 75. See [SYSCALLS.md](SYSCALLS.md) for the per-syscall reference.

Dispatch is **table-driven**: `syscall_handler` indexes a `syscall_table[]` of descriptors `{ handler, slot, rights, type }`, validates the number, and — for syscalls whose authority is a single fixed capability — enforces that capability in one central place before calling the handler. A number with no entry fails closed. A `_Static_assert` pins the table size to the highest syscall number + 1, so a syscall cannot be added without a table slot. Syscalls with dynamic or self-authorising policy (the capability ops, the FS ops, auth/sudo, user management, kill/signal/grant) carry no fixed slot and authorise inside their handler.

Broad categories: **core/process** (yield, exit, get_line, sbrk/brk, read/write/open, wait, get_task_info, exec); **process control** (spawn, exec_named, spawn_image/exec_image, kill, cap_grant, signal, spawn_arg/get_argv); **IPC** (send/recv/call/reply, sender, reply_to; notify/wait_notify deliver async badges); **auth & audit** (getuid, auth, sudo, passwd, useradd/del, read_audit, audit_digest); **signals** (sigaction, sigreturn, sigmask, sigaltstack); **capabilities** (mint/transfer/move raw-numbered, revoke); **filesystem** (encrypted object store 56–61 + set_meta 74; capfs 38–45 removed/fail-closed); **block storage & server registration** (47–50; 46 removed/fails-closed). Numbers 1/`SYS_PRINT` and 20/`SYS_GETPID` are defined but not dispatched.

---

## User authentication and audit

### User database

Up to 32 users are stored in a kernel-managed table, serialised to the RAM filesystem as a `passwd` file. Each entry holds: username, UID, GID, home directory path, shell path, a random per-user salt, a password hash, and an authentication failure counter. The serialised table is authenticated with an HMAC-SHA256 tag keyed by the per-boot pepper. The default accounts are `root`/`rootpass` and `user`/`password`; password changes persist across reboots.

Password hashing is **Argon2id** (RFC 9106) — the memory-hard KDF — implemented from scratch in safe Rust (`rust/src/argon2.rs`) on the crate's own BLAKE2b (`rust/src/blake2b.rs`) and validated against the `argon2-cffi` reference vectors. It hashes the password with the per-user random salt and a per-boot secret pepper folded in; the raw 32-byte tag is stored. The implementation is multi-lane (`p ≥ 1`, validated against p=2/p=4 vectors); the cost profile (`m`, `t`, `p`) is set by `ARGON2_M_COST_KIB` / `ARGON2_T_COST` / `ARGON2_P_COST` in `kernel.h`, and the kernel runs 4 MiB / 3 passes / 1 lane. The fill buffer is a kernel static (no allocator); hashing runs non-preemptibly inside the syscall, so one shared buffer is safe. Verification runs in constant time and is equalised so a missing username cannot be distinguished by timing. Lockout arithmetic and a global anti-spray throttle live in `rust/src/auth.rs`.

### Audit log

The kernel maintains a 256-entry circular buffer. Each event records: event type, TSC timestamp, subject UID, object identifier, and result code. Types include authentication, sudo, user management, capability operations, file access, IPC, and filesystem events. The log is readable via `SYS_READ_AUDIT`.

The log is **tamper-evident**. Each entry is bound by `mac = HMAC(pepper, LE64(seq) || event)` (the sequence number defeats slot swaps and replays) and a running chain head advances as `head = HMAC(pepper, head || mac)`, committing to the whole ordered history — including entries the ring has already overwritten. The keyed-hash logic lives in safe Rust (`rust/src/audit.rs`); the C side owns the ring storage and seeds the chain in `users_init` as soon as the pepper exists. `SYS_AUDIT_DIGEST` returns the total event count, the current chain-head MAC, and a constant-time verify status of the retained window. This is an integrity detector keyed to a secret the log's readers do not hold — not a guarantee against an attacker who has already compromised the kernel and can read the pepper.

---

## Rust integration

The Rust crate at `rust/` compiles to a static library (`libhorus_shell.a`) linked into the kernel. It is a `no_std` crate — no allocator, no OS dependencies. Data crosses the C/Rust boundary as raw pointers and integers via the FFI shims in `src/kernel/rust_memory_stubs.c`.

| Module | Role |
|---|---|
| `capability.rs` | Capability mint, transfer, move, revoke, and lineage management |
| `memory.rs` | Physical page reference counting and validation |
| `lib.rs` | Page-fault validation, demand-paging decisions, W^X page policy (`rust_user_page_is_noexec`), signal-handler-address window, command token parsing |
| `sha256.rs` | SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA256 |
| `blake2b.rs` | BLAKE2b (RFC 7693) — the hash primitive under Argon2id |
| `argon2.rs` | Argon2id (RFC 9106) memory-hard password hashing |
| `rng.rs` | ChaCha20 fast-key-erasure CSPRNG; RDRAND + timing-jitter seeding |
| `aead.rs` | ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (used by the block-storage layer for encryption-at-rest) |
| `audit.rs` | Tamper-evident audit log: per-entry HMAC (sequence-bound) + running hash-chain head |
| `auth.rs` | Auth/sudo lockout + anti-spray throttle; least-privilege sudo frame rights |
| `ps.rs` | Task state-name labels for the `ps` renderers |
| `crypto.rs` | Intentionally empty — the primitives live in the modules above |

The Rust code is safe Rust internally: the crate contains no `unsafe` blocks in its logic. The one unavoidable `unsafe` is the FFI boundary itself — the `rust_*` entry points the C kernel calls are `unsafe extern "C"` functions because they dereference C-supplied raw pointers. Each carries a documented `# Safety` contract, validates its arguments (null and length checks, fail-closed on bad input), and copies through fixed-size local buffers rather than trusting caller bounds. So the *surface* is the whole FFI API, but the *risk* is confined to those thin, contract-checked shims; all computation behind them is safe Rust.

---

## Reproducible builds

The build system sets `SOURCE_DATE_EPOCH=1609459200` (2021-01-01 UTC) and passes `-frandom-seed=horus` to GCC. The linker is invoked with `--build-id=none`. The Rust build uses `--locked`, `opt-level=z`, `lto=true`, and `codegen-units=1`. The result is a byte-for-byte identical `kernel.elf` across clean builds on the same toolchain version. `make reproducible-build` builds twice and diffs; reference checksums are recorded in `.build.sha` (and the historical `.build1.sha`/`.build2.sha`).

---

## Security properties

### What the design provides

- **No ambient authority** — a task cannot access a resource it does not hold a capability for, regardless of UID
- **Transitive revocation** — revoking a capability immediately invalidates all capabilities derived from it, across all tasks
- **Use-after-revoke prevention** — lineage generations make a revoked capability slot invalid even if its bit pattern is retained
- **Least-privilege delegation** — a supervisor grants a child exactly the caps it needs (`SYS_CAP_GRANT`); kill/signal are gated on holding the child's `CAP_TCB`
- **Primordial capability protection** — system-critical root capabilities cannot be revoked by any userspace path
- **Hardware user/kernel isolation** — Ring 0 / Ring 3 boundary; SMEP/SMAP enabled when advertised
- **W^X for user memory** — stacks are non-executable and ELF segments honour their `p_flags`
- **Kernel state is unaddressable from ring 3** — the kernel lives in the higher half, so a user mapping cannot share a virtual address with kernel data by construction rather than by bounding ASLR away from it
- **Register-file isolation** — a task's x87/SSE registers are saved/restored across the ring-3 boundary, so neither another task's values nor kernel leftovers are observable in `xmm`
- **Centralised syscall authorisation** — one table-driven choke point; an unlisted syscall number fails closed
- **Signals grant no new authority** — a handler runs at ring 3 with unchanged privileges; async signalling requires a `CAP_TCB` on the target

### What the design does not yet provide

See [LIMITATIONS.md](LIMITATIONS.md) for detail. Key gaps: IPC endpoints are single-slot mailboxes, so requests serialise one at a time — multi-client *replies* are routed by kernel-recorded identity (`SYS_IPC_REPLY_TO`), but multi-slot queueing is not implemented; and SMP is default-on but the multi-core scheduler still shares one runnable pool with no per-CPU run queues, priorities, or flush-on-switch between time-sliced tasks. Image-base ASLR is 30 bits (a 4 TiB window at 16 GiB). (The filesystem is now persistent, multi-client, permission-enforcing, and crash-atomic — see the LIMITATIONS filesystem note for the residual operational limits.)
