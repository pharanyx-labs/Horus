# Horus Architecture

How Horus is built, why it is built that way, and which invariants each subsystem is
responsible for. Written for contributors who need to understand the system before changing
it, and for reviewers evaluating the design.

**Where this document and the code disagree, the code is authoritative — please open an
issue.**

---

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

**The kernel does the minimum.** It owns address spaces, threads, capabilities, IPC, and an
encrypted block store whose keys it never releases. It does not own filenames, directories,
permissions, terminal semantics, or program-loading policy. Those live in ring-3 servers
that hold only the capabilities they need.

**Authority is explicit and reducible.** Everything a task can do traces to a capability it
holds. Capabilities are delegated downward, never acquired upward, and delegation can only
narrow rights. Revocation is transitive over the derivation tree.

**Every claim has a witness.** A security property that is not tested is a hope. Horus
therefore ships an unusually large integration self-test suite, formal proofs over the
capability algebra, and a reproducible build verified by double-building in CI.

### What is in the trusted computing base

- The kernel (`src/kernel/`, `src/boot/`, `rust/src/`) — approximately 20 kLOC.
- `init` (`userspace/init.c`) — the delegation root for every userspace server.
- `fs_server` — the reference monitor for filesystem permissions.
- `console_server` — owns the console hardware and therefore sees all terminal traffic.
- GRUB and the platform firmware, up to the point where measured boot takes over.

Everything else — the shell, coreutils, tcc, user programs — is outside the TCB by design.

---

## 2. Boot and memory layout

### The boot sequence

1. **GRUB** loads `kernel.elf` (Multiboot2) at physical 1 MiB and any `module2` payloads
   into RAM above it.
2. **`src/boot/multiboot.S`** runs in 32-bit protected mode: sets `CR4.PAE`, builds the
   initial page tables, enables `EFER.LME` and `EFER.NXE`, enters long mode, and jumps to
   the higher-half kernel.
3. **`kernel_main`** (`src/kernel/main.c`) scans the multiboot2 tags for the E820 memory map
   and boot modules, sizes the physical pool, verifies module hashes against the embedded
   manifest, measures kernel and modules into the TPM, initialises paging, capabilities, the
   scheduler, storage, and launches `init` in ring 3.

### Virtual memory layout

```
0xFFFFFFFF_80100000   kernel image (.text r-x, .rodata r--, .data/.bss rw-)  = KERNEL_VMA + 1 MiB
0xFFFFFF80_80000000   PHYS_KVA window: higher-half alias of physical [0, 1 GiB)
0x00000000_xxxxxxxx   userspace: image, heap, stack (per-task, ASLR-randomised)
```

`KERNEL_VMA` is fixed by `linker64.ld` and shared with the boot assembly through
`src/include/kernel_vma.h`. Two translations exist and must not be confused:

- `virt_to_phys` / `phys_to_virt` — for **kernel image symbols only**, where the fixed
  `± KERNEL_VMA` relation holds.
- `PHYS_KVA(p)` — for **arbitrary physical addresses** (freshly allocated frames, page
  tables). This window is copied into every task's PML4 (`pml4[256..511]`), so it resolves
  on a user CR3 too. The demand pager must use it: the low identity map does not cover the
  user page pool, and faulting inside the fault handler while holding `page_lock` with
  interrupts off wedges the machine.

### Physical memory

The pool starts at `USER_PHYS_BASE` (16 MiB, above the kernel image) and is sized at boot
from the E820 map, falling back to 64 MiB. Three regions are reserved at the base before the
free list begins: the 8 MiB loader staging buffer, the RAM vdisk backing store, and the 4 MiB
untyped arena (§4). All three used to be `.bss` arrays, which capped them against the
`__bss_end <= USER_PHYS_BASE` linker assertion; moving them into the pool decoupled their
size from that ceiling entirely.

Boot-module frames are also held back from the free list — GRUB places modules wherever it
likes, typically inside the pool, and handing one out as an anonymous user page would
corrupt the image before `init` reads it.

---

## 3. The C / Rust split

The kernel is C; the security core is `no_std` Rust compiled to a static library and linked
with `--whole-archive`. The split is drawn by **attack surface**, not by convenience: code
that parses attacker- or firmware-controlled bytes, or that enforces an algebraic security
property, belongs in Rust.

**In Rust today** (`rust/src/`):

| Module | Responsibility |
|---|---|
| `capability.rs` | The capability algebra: lookup, mint, grant, transfer, subtree revocation, lineage generations |
| `lib.rs` | ELF header/phdr validation, load planning, i386 and x86-64 relocation |
| `crypto.rs`, `aead.rs`, `sha256.rs`, `blake2b.rs`, `argon2.rs` | Cryptographic primitives |
| `rng.rs` | ChaCha20 fast-key-erasure CSPRNG with RDRAND health checking |
| `memory.rs` | Pointer and range validation predicates |
| `audit.rs` | Forward-secure audit log |
| `auth.rs`, `ps.rs` | Authentication and process-listing helpers |

Moving the ELF loader to Rust found two real out-of-bounds bugs in the C original. That is
the argument for the split, stated empirically.

### The FFI contract

`capability_t` (C) and `Capability` (Rust) are the same memory passed across the boundary.
Layout drift is a **compile error on both sides**:

```c
/* src/kernel/capability.c */
_Static_assert(__builtin_offsetof(capability_t, object) == 8, "cap.object offset");
```
```rust
// rust/src/capability.rs
const _: () = { assert!(core::mem::offset_of!(Capability, object) == 8); };
```

Field offsets are asserted rather than `size_of`, because only trailing padding differs
between the 32- and 64-bit targets.

`rust/fuzz/` runs cargo-fuzz over the pointer and scalar predicates at this boundary.

---

## 4. Capabilities

### Structure

```c
typedef struct capability {
    uint32_t type;        /* CAP_TCB, CAP_ENDPOINT, CAP_FRAME, ... */
    uint32_t rights;      /* READ | WRITE | EXEC | GRANT | MINT | REVOKE | ... */
    uint64_t object;      /* which instance: task id, endpoint index, address, ... */
    uint32_t badge;       /* the parent's serial — the derivation-tree link */
    uint32_t serial;      /* globally unique, monotonic */
    uint32_t generation;  /* lineage generation at creation */
} capability_t;
```

Sixteen object types, besides the empty `CAP_NULL`: `CAP_TCB`, `CAP_NOTIFICATION`,
`CAP_ENDPOINT`, `CAP_FRAME`, `CAP_USER`, `CAP_AUDIT`, `CAP_CONSOLE`,
`CAP_ENCRYPTED_STORAGE`, `CAP_REVOCATION`, `CAP_BLOCK_DEV`, `CAP_IO_DEVICE`, `CAP_PIPE`,
`CAP_KERNEL_LOG`, `CAP_BOOT_MODULE`, `CAP_UNTYPED`, `CAP_REPLY`.

Each task has a 256-slot cspace. Userspace names a capability by slot index and never sees
the struct, so capabilities cannot be forged or guessed.

### Untyped memory

Kernel objects are not entries in fixed arrays. A `CAP_UNTYPED` names a region of physical
memory, and `SYS_RETYPE(untyped_slot, kobj_type, count, dest_slot)` carves typed objects out
of it, installing a capability for each into the caller's cspace. A task holding no
`CAP_UNTYPED` cannot create a kernel object at all, and the region a task does hold is a hard
bound on the kernel memory it can ever consume — which is what makes kernel-memory
consumption attributable and exhaustion preventable.

The arena is split once at boot:

| Region | Backs | Reachable from ring 3 |
|---|---|---|
| `UNTYPED_KERNEL` | per-task cspaces (`KOBJ_CNODE`) | never — no capability is ever minted for it |
| `UNTYPED_ROOT` | everything userspace allocates | `init` holds the primordial capability and delegates onward |

The split is deliberate. With one shared region, "userspace exhausted kernel memory" and "the
system can no longer create a task" would be the same event.

Allocation within a region is a **monotonic bump pointer**, following seL4. Destroying an
object does not return its bytes; reclaiming a region means revoking the untyped capability
itself. This is a safety property, not a simplification: with a free list, an object's bytes
can be handed straight back out and retyped as a different class while a stale capability
still names the old address. A watermark that never moves backwards makes bytes reusable only
after every capability into the region has been revoked — the same event that invalidates the
stale reference.

Retyped endpoints and notifications live in an index range above the static tables, which
remain as a compatibility shim for the well-known service objects the boot protocol names by
index; `endpoint_by_index` / `notification_by_index` are the single resolvers, and both return
`NULL` for a destroyed object so IPC fails closed on a stale capability.

`tasks[]` is not yet migrated: a TCB is reachable from the scheduler's hot path and from every
trap frame. `KOBJ_CNODE` is allocatable by the kernel but refused to ring 3 — no capability
type names a CNode and no syscall installs one as a task's cspace, so minting one would be
authority with no defined meaning.

**Object lifetime is capability-governed.** An object exists exactly as long as some
capability names it. This is computed by a mark-and-sweep over the capability graph
(`kobj_gc`, run from `cap_revoke` and `task_teardown`), not by a refcount — a refcount would
have to be maintained at every mint, transfer, move, grant, revoke, null and teardown site
across both the C and safe-Rust halves of the implementation, where one missed site is a leak
and one double-decrement is a use-after-free reachable from ring 3. Reachability is computed
from the same graph the security argument is already stated over, so the two cannot disagree.

### Serials, badges, and the derivation tree

Every capability gets a fresh, monotonically increasing `serial` at creation. A derived
capability records its parent's serial in `badge`. The set of all `(serial, badge)` pairs is
therefore a forest, and the descendants of a capability are exactly the transitive closure
under "badge points at an already-reached serial".

Primordial root capabilities carry the reserved `0xC0DE****` serial tag, live in the
kernel-reserved slots `0..3`, and are non-revocable.

### Delegation

- **`cap_mint(dest, src, rights)`** — derive into the caller's own cspace with
  `rights & src->rights`. Rights can only narrow.
- **`cap_transfer(dest, src)`** — mint preserving full source rights.
- **`cap_grant_into(target_pid, dest, src, rights)`** — push a derived capability into a
  child's cspace. Authorised by holding `CAP_TCB` for the target, or `CAP_USER` admin.
  Deliberately has no kernel-reserved-slot floor: endowing a child's low slots is exactly
  what grant is for.

All four hold `cap_lock` across the read-modify-write, count newly-occupied slots against
`MAX_CAPS_PER_TASK`, and refuse a cspace-less caller (the no-ambient-authority guard).

### Revocation

`cap_revoke(slot)` is **system-wide** and **subtree-scoped**. It collects every live task's
cspace plus the kernel root cnode into a `cspace_desc_t` array and hands the whole set to
`rust_cap_revoke_global`, which:

1. Nulls the target and decrements its owner's `caps_in_use`.
2. Bumps the target serial's lineage generation.
3. Computes the transitive descendant closure by BFS over `badge → serial` links across all
   supplied cspaces.
4. Nulls each descendant and bumps its serial's generation.

**Invariant.** After this returns true, no live cspace retains the target or any capability
derived from it — and capabilities that are *not* descendants (the grantor, unrelated
siblings, independent capabilities to the same object) are left intact. Revocation is
therefore both *complete* and *least-privilege-correct*.

Kani proofs in the Rust crate verify the subtree property.

**Fail-safe overflow.** The descendant worklist is bounded at 256 entries. On overflow the
sweep falls back to nulling every capability sharing the root's `object` — a *superset* of
the descendant set, since mint/grant/transfer all preserve `object`. A descendant can never
survive; the fallback can only over-approximate. See `docs/LIMITATIONS.md` for the
denial-of-service consequence of that over-approximation.

### The generation backstop

Revocation nulls slots structurally. Generations are the independent second mechanism.

Each capability's `serial` hashes to a cell in a 4096-entry atomic table (`LINEAGE_GEN`).
A capability is valid iff its recorded `generation` **exactly equals** its serial's current
cell value. Revocation bumps the cell, so any detached snapshot or copy carrying the old
value fails validation even if the structural sweep never reached it.

Creation sites stamp `generation = rust_lineage_current(serial)` so a fresh serial that
happens to hash onto a previously-bumped cell is born *valid*, not stale. Empty (`0`) and
primordial (`0xC0DE****`) serials are exempt.

The table is keyed by **serial**, not by object. Object-keying was the historical design and
was effectively dormant: two independent capabilities to the same object shared a cell, so
the only way to keep them independent was to treat generation 0 as always-valid — and every
capability in the running kernel was created with generation 0. Serial-keying plus strict
equality made the backstop active and precise.

### Snapshot and revalidate

A looked-up `struct capability *` can go stale if anything between lookup and use yields or
drops `cap_lock`. The pattern for such paths is:

```c
cap_snapshot_t auth = cap_snapshot(cap_lookup(slot, rights));
/* ... something that may yield ... */
if (auth.valid && !cap_revalidate(slot, rights, &auth)) return -1;
```

`cap_revalidate` re-looks-up and confirms the slot still holds the *same identity* (serial,
generation, object) with the required rights. This is wired into the IPC send and receive
paths.

---

## 5. Address spaces and paging

Each task has its own PML4. `create_user_pagedir` builds it, copies `pml4[256..511]` (the
kernel half and the `PHYS_KVA` window) so kernel mappings resolve on every CR3, premaps the
image window, and binds the task's kernel stack above an unmapped guard page.

**Demand paging.** Heap and stack pages are allocated on fault. The pager runs on the
faulting task's CR3 and reaches page tables and fresh frames through `PHYS_KVA`.

**Copy-on-write.** Fresh anonymous pages alias a shared read-only zero frame. The first
write faults, allocates a private frame, copies, and remaps writable. Refcounts are
maintained per frame. `user_copy` drives the same COW break when the kernel writes into a
present-but-read-only COW page, so a `copy_to_user` cannot corrupt the shared zero frame.

**Protection.** User stacks are NX. The kernel image is W^X: `.text` r-x, `.rodata` r--,
`.data`/`.bss` rw-, enforced by `CR0.WP` and swept at boot by a self-test that walks every
leaf PTE looking for a writable-and-executable page. SMEP and SMAP are enabled when the CPU
advertises them, and a gated self-test asserts they are actually set in CR4.

**Crossing the ring boundary.** `copy_to_user` / `copy_from_user` do a **software page-table
walk** of the target address space and require `PAGE_PRESENT | PAGE_USER` (plus `PAGE_WRITE`
for writes) on every page touched. This is stronger than relying on SMAP: it works on CPUs
without SMAP, and it makes a user pointer aimed at kernel memory structurally impossible to
satisfy rather than merely trapped.

**ASLR.** Image base, heap base, and stack top are randomised with 30 bits of entropy from
the kernel CSPRNG, rejection-sampled rather than reduced modulo.

---

## 6. Tasks and scheduling

A `tcb_t` holds register state, CR3, cspace pointer, kernel stack, heap bounds, uid/gid,
signal state, FPU state, and IPC blocking state.

**Preemption.** The timer ISR calls `preempt_on_tick` with the interrupted task's full trap
frame. A switch happens **only when the tick interrupted ring 3**. At that instant the task
holds no kernel spinlock (spinlocks mask interrupts) and its entire state is in the trap
frame. A tick that lands in ring 0 just advances the clock. This keeps the kernel
effectively non-preemptible and removes an entire class of reentrancy hazard.

### Interrupt policy

Stated, rather than emergent. Until roadmap 1.1 this section could not be written: interrupt
enablement was a *consequence* of a locking defect (**[C-3.1]**), not of any rule. Every
statement below is asserted by `make smoke-irq-policy`, which records `RFLAGS.IF` at each
named point and fails on a mismatch.

| Context | `IF` | Established by |
|---|---|---|
| Boot, `_start` → `kernel-ready` | **0** | the CPU enters long mode masked and nothing enables |
| Ring 0: syscall or ISR body | **0** | `int 0x80` and every IDT gate are *interrupt* gates |
| Ring 3 | **1** | `sched_prepare_user_context` builds the frame with `RFLAGS = 0x202` |
| A parked CPU's idle loop | **1** | `enter_cpu_idle` builds its frame with `RFLAGS = 0x202` |
| Inside a spinlock | **0** | `spin_lock` issues `cli` |
| After the outermost `spin_unlock` | **the caller's own** | `spin_unlock` *restores*, never imposes |

Two consequences are worth stating explicitly, because both have been got wrong here.

**The kernel is not preemptible, and interrupts staying masked through a syscall is what
makes that true rather than merely intended.** A syscall handler runs from entry to return
with `IF = 0`. It was not always so: the old `spin_unlock` ended in an unconditional `sti`
once its global nesting depth hit zero, so the first lock any syscall took and released turned
interrupts on for the remainder. `preempt_on_tick`'s ring-0 guard exists because of that — it
was widened from "CPU 0" to every CPU after a ring-0 tick mid-syscall abandoned a task and
produced an intermittent SMP deadlock.

**A critical section returns the interrupt state it was given.** `spin_lock` saves the
caller's `IF` at the outermost acquire and `spin_unlock` restores exactly that; the nesting
depth is per-CPU, so one CPU's release cannot unmask another's critical section
(**[C-3]**). A window that genuinely *needs* interrupts on must therefore ask for them, and
exactly one does: the TLB-shootdown wait (`smp_maybe_shootdown`) spins for acknowledgements
that arrive as IPIs, so it enables interrupts deliberately, restores the previous state
afterwards, and **panics if the caller holds a spinlock** — the precondition its comment had
always stated but nothing had ever checked.

Switching is a kernel-`%rsp` swap: save the outgoing frame pointer, install the incoming
task's CR3 and TSS RSP0, and hand its saved frame to the ISR epilogue, which pops and
`iretq`s into it.

**Spawn is suspended.** `do_spawn` returns a child that is *not* schedulable; the supervisor
endows it (`SYS_CAP_GRANT`) and then calls `SYS_TASK_RESUME`. This is structural, not
advisory: a child cannot observe a partially-populated cspace because it cannot run at all
until its supervisor says so. Three separate SMP races were traced to the old
publish-immediately behaviour before the pattern was recognised (finding **[I-13]**).

**One mechanism, four entry points.** Timer preemption, blocking IPC (`ipc_block_switch`),
voluntary yield (`sched_yield_switch`), and first entry (`sched_enter_user`) all go through
the same saved-trap-frame path. First entry works by *fabricating* the frame a preemption
would have left (`sched_prepare_user_context`), so entry and resume are identical.

**Stack alignment.** The fabricated frame biases `rsp` by 8, because the System V AMD64 ABI
guarantees `rsp % 16 == 8` at a function's first instruction (a `call` just pushed a return
address). `iretq` pushes nothing, so handing over a 16-byte-aligned `rsp` puts every
compiler-computed stack slot 8 bytes out and the first `movaps` faults. Flat test binaries
never noticed; newlib faulted inside the first `puts()`.

**FPU.** `fxsave`/`fxrstor` bracket ring transitions, so one task's XMM register file cannot
leak into another's. New tasks start from a template with `MXCSR = 0x1F80` — a zeroed FXSAVE
image would unmask every SIMD exception.

**Signals.** POSIX-style: `SYS_SIGACTION` registers a handler (validated to lie inside the
task's own image, in safe Rust), `SYS_SIGMASK` blocks and unblocks, `SYS_SIGALTSTACK`
registers an alternate stack. Delivery rewrites the trap frame to enter the handler and
saves the pre-signal frame for `SYS_SIGRETURN`. `SIG_KILL` is uncatchable and unblockable.

---

## 7. SMP

SMP is **on by default**. `SMP=0` compiles it out.

- CPU count comes from the ACPI MADT; APs are started with INIT-SIPI-SIPI via a real-mode
  trampoline (`src/boot/ap_trampoline.S`).
- Each CPU takes its own LAPIC timer tick and pulls from a **shared runnable pool**.
- `task_running_cpu[]` is the mutual-exclusion guard: a CPU only claims a task whose entry is
  `-1`, so a task's single kernel stack and saved trap frame are never touched by two CPUs.

### The claim invariant

```
task_running_cpu[t] == c   <=>   percpu_current_task[c] == t     (t > 0)
```

Both directions carry weight, and they fail differently:

- **A claim held by a CPU not running the task** makes that task unschedulable by *every* CPU,
  including the holder — every selection loop skips a claimed candidate. The task stays
  `RUNNABLE` with a valid context and simply never runs again: a silent livelock, not a crash.
- **A task run without a claim** can be selected by a second CPU, so two cores execute one
  task's kernel stack and trap frame concurrently.

The asymmetry to watch for is a path that **claims unconditionally but releases
conditionally**; that is exactly the shape of the deadlock fixed on 2026-07-28, where a ring-0
timer tick leaked a claim because the release was gated on `ring3`.

**A CPU is only ever switched away from a ring-3 context or an idle loop.** The tick path can
save a ring-3 trap frame and nothing else — it cannot preserve an in-flight kernel context or
a lock that context holds — so a ring-0 tick on a CPU with a live task returns without
switching (`percpu_idle` distinguishes a genuinely parked CPU, which has nothing to save).

Consequently **a stale claim must never simply be cleared.** A claim is stale precisely when
its task was abandoned mid-kernel, so freeing it lets the task resume from a stale trap frame,
discarding kernel work that may include a held lock. Treat a stale claim as a symptom to
diagnose, never a value to correct; `SCHED_INVARIANTS=1` machine-checks the invariant and
panics with the offending task, CPU and observer.
- TLB shootdown is an acknowledged IPI.
- **SMT siblings are parked in software** — a disable-SMT-in-software measure that closes
  same-core co-residency, the strongest available mitigation against cross-thread
  microarchitectural attacks without hardware support.

**Locking.** `spin_lock` masks interrupts and takes a test-and-set lock. Its nesting depth and
the caller's saved `RFLAGS.IF` are **per-CPU**, and the outermost `spin_unlock` restores that
saved value rather than asserting one — see §6, "Interrupt policy", which is the authoritative
statement.

> **Resolved — [C-3] / [C-3.1], fixed 2026-08-11.** *This callout said "Known defect … open"
> for four days after the fix landed, while §6 of this same document described the corrected
> behaviour. It is left here, rewritten, because the shape of the defect explains three
> subsystems that still route around it.*
>
> The nesting depth used to be a single **global** counter shared by all CPUs with non-atomic
> increments, and `spin_unlock` did an **unconditional** `sti` when it reached zero. Under SMP
> one CPU's release could unmask another's critical section; and any lock taken where `IF` was
> already clear enabled interrupts as a side effect — including inside `user_copy`'s
> hand-rolled `cli`/CR3 window.
>
> The second behaviour was **load-bearing**, which is why the obvious fix failed once. A
> correct per-CPU lock written on 2026-07-27 passed every local gate and stalled the `init` →
> `fs_server` → `console_server` → shell handshake in CI, and was reverted; the handshake
> depended on preemption the defect produced. What made the second attempt safe was
> `preempt_on_tick`'s ring-0 guard, widened from "CPU 0" to every CPU in the interim, so a
> ring-0 tick is no longer a switch point and the `sti` creates nothing anything depends on.
> `IRQ_LEGACY_GLOBAL_LOCK=1` rebuilds the defect exactly and `make smoke-irq-policy` gates the
> policy at five named boot milestones. See [`ROADMAP.md`](ROADMAP.md) item 1.1.

Code that runs inside an interrupt gate (where `IF` is already clear by hardware) uses raw
test-and-set helpers instead — `sched_raw_lock`, `ipc_lock` — which must not touch `IF` at
all.

---

## 8. IPC and notifications

### Endpoints

`MAX_ENDPOINTS = 128` static endpoints, plus `MAX_DYN_ENDPOINTS = 256` retyped ones above
`DYN_EP_BASE` (see §4). Each endpoint is a **bounded FIFO**, not a single mailbox slot: a ring
of `EP_QUEUE_SLOTS` (default 4, overridable at compile time) messages of up to
`IPC_MSG_MAX = 256` bytes, a head/count pair, one `last_sender`, and one blocked-waiter field.
Each queued slot carries its *own* sender id, because the reply path authorises by
kernel-recorded sender identity and a shared field would be overwritten by the next sender;
`last_sender` is the sender of the most recently **dequeued** message. The depth is fixed at
compile time, so a sender cannot make the kernel allocate and a server that stops receiving
cannot be used to grow kernel memory without bound. `EP_QUEUE_SLOTS=1` degenerates the ring
back to the old single-slot mailbox, which is how the queue's benefit was measured rather than
asserted (roadmap 1.3, finding **[I-5]**).

- **`SYS_IPC_SEND` / `SYS_IPC_RECV`** are non-blocking: they return `-2` when the queue is
  genuinely full (`count == EP_QUEUE_SLOTS`) or empty (`count == 0`) and the caller polls from
  ring 3, where timer preemption guarantees progress. Spinning in-kernel would not, because
  the kernel is not preemptible. With a queue, concurrent clients enqueue instead of
  colliding, so the retry path is reached only under real back-pressure.
- **`SYS_IPC_RECV_BLOCK`** is the same receive under the same capability gate, but **sleeps**
  on an empty queue instead of returning `-2`. It never returns `IPC_AGAIN`, so a negative
  return is permanent and a server that loops on it is wedging rather than applying
  back-pressure. Its subtlety is authority, not sleep: the receive is completed by the
  *sender's* syscall running in the sender's cspace, so `cap_install_reply_for` mints the
  one-shot `CAP_REPLY` into the **receiver's** cspace, under `ipc_lock` and before the wake —
  a receiver holds its reply right before it is schedulable. The first version minted after the
  wake and lost the race on 8 of 25 loaded SMP boots while every single-CPU gate passed.
- **`SYS_IPC_CALL`** is the blocking send-then-await-reply. It deposits the message and
  records a *pending* block; the actual publish happens later.
- **`SYS_IPC_REPLY_TO`** delivers a reply directly into the recorded sender's blocked reply
  buffer. The target comes from a **one-shot `CAP_REPLY`** minted by `SYS_IPC_RECV` into
  `CAPSLOT_REPLY` and consumed by the reply, *not* from the endpoint's mutable `last_sender`.
  Replying twice, or to a client this task never received from, is therefore unrepresentable
  rather than merely refused — which is what makes one server safe for concurrent clients.

**The publish-after-save protocol.** A cross-CPU reply must never patch a stale or null
saved frame. The ordering is therefore:

1. The syscall handler sets `pending_block` only — not yet wake-visible.
2. `ipc_block_switch` writes `saved_ksp` (the live trap frame).
3. A full barrier.
4. `ipc_publish_pending_block` publishes the waiter under `ipc_lock` — or completes
   immediately if the event already arrived.
5. Only then does the CPU switch away.

Wakers therefore always patch a valid frame.

**Cross-address-space reply delivery.** `copy_to_user` translates through
`tasks[get_current_task()].cr3`, so delivering into a waiter's buffer requires the waiter to
*be* the current task across the copy — merely switching CR3 is not enough. The sender
briefly sets current-task to the waiter with interrupts masked, copies, and restores.

### Notifications

`MAX_NOTIFICATIONS = 64` badge accumulators. `SYS_NOTIFY` ORs a badge in and wakes any
blocked waiter by patching its saved frame directly (no cross-address-space pointer copy
needed). `SYS_IRQ_REGISTER` routes a hardware IRQ to a notification slot, which is how a
ring-3 driver receives interrupts.

### Pipes

Bounded in-kernel byte streams with `CAP_PIPE` capabilities for each end, `EAGAIN`
back-pressure, and EOF/EPIPE on peer close. `task_teardown` releases a dying task's ends so a
pipeline stage cannot wedge its peer.

### Capability addressing

Every IPC syscall names its object by a **cspace slot**, never by an object index. The
kernel resolves it through `ipc_ep_from_slot` / `ipc_notif_from_slot`
(`src/kernel/syscall_ipc.c`), which are the single choke point and enforce, in one place:

- the slot holds a live capability (non-null, serial != 0);
- of the right **type** — `CAP_ENDPOINT` or `CAP_NOTIFICATION`, so a `CAP_FRAME` cannot
  authorise IPC;
- carrying the **right for the direction** — `READ` to receive, `WRITE` to send;
- that passes the serial-keyed **lineage** check, so a revoked capability fails here exactly
  as everywhere else.

Only then is `object` trusted, and it is re-bounds-checked.

**The read/write split is the isolation boundary.** `READ` is the receive right. A *listen*
capability (`READ|WRITE`) belongs to the server: it may dequeue requests and answer them with
`SYS_IPC_REPLY_TO`, which also requires `READ` because it writes straight into the recorded
sender's blocked reply buffer. A *client* capability is `WRITE` only — it may send and
nothing else. `SYS_CONNECT_FS_SERVER` mints WRITE-only, and `do_spawn` propagates the console
capability to children masked to WRITE, so the receive right cannot escape the one task meant
to hold it.

**A task is born with exactly one endpoint capability:** its own private reply endpoint
(`reply_ep_for_task`, slot `CAPSLOT_REPLY_EP`). It is what `SYS_IPC_CALL` parks on, no other
task holds a capability for it, and the caller cannot name a different one — so replies
cannot be intercepted and a blocked caller cannot be woken spuriously. This also retires the
shared `FS_EP_REP` on which concurrent clients used to collide.

Until 2026-07-27 none of this held: indices came straight from a register and the dispatch
table gated IPC on slot 3, which holds a `CAP_FRAME` in every task. See finding **[C-1]**.

---

## 9. The syscall layer

Entry is `int 0x80` → `interrupt_handler64` → `syscall_handler`, dispatching through a
descriptor table:

```c
typedef struct {
    void   (*fn)(struct interrupt_frame64 *r);
    uint16_t slot;     /* authorizing cspace slot, or SC_NONE */
    uint32_t rights;   /* rights required at `slot` */
    int      ctype;    /* required capability type, or SC_ANYTYPE */
} syscall_desc_t;
```

Where a syscall's authority is a single fixed capability, the check happens **once,
centrally**, before the handler runs — so a syscall physically cannot execute without it.
`SC_NONE` means the authority is argument-dependent (e.g. `SYS_KILL` needs a `CAP_TCB` for a
*dynamic* target) and the handler performs it, with the reason noted per entry.

**Fail-closed properties:**

- A number with no table entry, or a `NULL` handler, returns `SYS_ERR_NOSYS`.
- Numbers 38–45 (the removed legacy capfs) are deliberately left reserved and unreused, so
  no future syscall silently inherits an old ring-3 caller.
- A compile-time assertion ties the table size to the highest syscall number:

```c
_Static_assert(SYSCALL_TABLE_SIZE == SYS_UNTYPED_INFO + 1,
               "syscall_table size must equal (highest syscall number + 1)");
```

Adding a syscall without a table entry is a build failure, not a runtime surprise.

The complete ABI is in [`SYSCALLS.md`](SYSCALLS.md).

---

## 10. Userspace servers

### `init`

PID 1, uid 0, and the **delegation root**. `kshell` endows it from the primordial root cnode
with exactly what it must wield or delegate: `CAP_AUDIT`, `CAP_CONSOLE`,
`CAP_ENCRYPTED_STORAGE`, `CAP_USER` (admin), the service `CAP_ENDPOINT`s, `CAP_IO_DEVICE`,
`CAP_KERNEL_LOG`, `CAP_BOOT_MODULE`, and `CAP_UNTYPED` over `UNTYPED_ROOT`. It launches
`fs_server` and `console_server` and hands each only its own subset via `SYS_CAP_GRANT` —
including, in principle, a bounded share of kernel-object memory, which is what makes "this
server may consume at most this much of the kernel" expressible.

### `fs_server`

The system's only filesystem and its **reference monitor**. It holds `CAP_BLOCK_DEV` for the
encrypted object store and implements all filesystem semantics — names, directories,
permissions — on top of `(inode, logical block)` addressing.

Every request is authorised against `SYS_IPC_SENDER`: the uid the *kernel* recorded for the
sender, established only by a successful login. A client cannot claim to be another user
because it never supplies its own identity.

Features: POSIX rwx, a write-ahead journal with mount-time fsck for crash atomicity,
double-indirect blocks for large files, and concurrent multi-client service via
`SYS_IPC_REPLY_TO`.

The journal's crash atomicity is an ordering property over what is on *stable media*, not
over the order writes were issued, so `journal_commit()` places three `FLUSH CACHE` barriers:
after the staged data and **before** the commit record (the write-ahead rule — without it
recovery can redo a validly-committed transaction from data sectors that never landed), after
the commit record, and after the home apply. `journal_recover()` carries the same barrier
before clearing a replayed header. Until 2026-08-16 there were none, and the ATA driver had no
`FLUSH CACHE` opcode at all (**[I-10]**), so the guarantee held only under an emulator that
persisted every write regardless.

### `console_server`

Owns the serial UART and the VGA framebuffer in ring 3. It receives `CAP_IO_DEVICE` from
`init`, which gates `SYS_MAP_PHYS` (map the framebuffer), `SYS_IOPORT_GRANT` (native ring-3
`in`/`out` on the console ports via the TSS I/O bitmap), and `SYS_IRQ_REGISTER` (keyboard
IRQ → notification).

It is the **single writer** to the console. The kernel keeps a minimal serial writer for
panics and early boot, and fails closed on the in-kernel read path while a server owns the
hardware (`console_hw_owned()`) so the kernel never becomes a second reader stealing bytes
from a typed line.

Raw terminal mode (termios, winsize) is implemented here — the foundation for curses
applications.

`task_teardown` calls `console_clear_owner`, so a crashed console server releases the
hardware back to the kernel fallback.

---

## 11. Storage and the encrypted object store

The kernel exposes an **object store**, not a filesystem: allocate/free inodes, read/write
`(inode, logical block)`, stat, set size, set metadata. The AEAD stays entirely in the
kernel — the ring-3 FS server never sees a key.

- Per-`(inode, block)` AEAD subkeys derived from the volume key, with a fresh nonce per
  write.
- A hierarchical rollback MAC over block metadata, so the per-write cost does not scale with
  volume size.
- 16 MiB volume (32768 × 512 B blocks), multi-block data allocation bitmap.
- Backing store is either an ATA disk or a RAM vdisk reserved in the physical pool.

Authority is one capability, checked in one place: the dispatch table requires a
`CAP_ENCRYPTED_STORAGE` carrying `READ|WRITE` at `CAPSLOT_AUDIT` (slot 7) before the handler
runs. The ambient `uid == 0` check that used to sit alongside it in each handler is gone
(finding **[I-1]**) — authority is the capability, not the identity — so the store API is
reachable only by the task `init` endows with that capability.

---

## 12. Trusted boot and the TPM

Three layers, each independently tested:

**1. Module integrity.** `tools/gen_module_manifest.sh` computes a SHA-256 for every boot
module at build time and generates `src/kernel/boot_module_manifest.h`, which is compiled
*into the kernel image*. At boot, each module is hashed and compared. A module that does not
match is flagged unverified: `SYS_BOOT_MODULE_INFO` reports it as an empty slot and
`SYS_BOOT_MODULE_READ` refuses its payload outright. Since provisioning into `/bin` goes
through that read path, an unverified module can never become a root-owned executable.

**2. Measured boot.** The kernel image and each module are extended into **TPM PCR 8 and 9**
over the TIS interface. `tools/tpm_expected_pcr.py` recomputes the expected values on the
host, and CI asserts they match.

**3. Sealed volume key.** The vdisk key-encryption key is sealed to PCR 8 and 9 under a
`PolicyPCR` session. A measured-good boot unseals it; any change to the kernel or modules
changes the PCRs and the volume stays locked. The KEK derivation uses HKDF rather than
Argon2, which cut `ramfs_init` from 1.5 s to 0.25 s without weakening the seal — the
security comes from the TPM policy, not from KDF hardness.

**Adversarial tests.** `smoke-modules-tamper` corrupts a module payload in the ISO and
asserts the kernel refuses it. `smoke-tpm-tamper` asserts the PCRs additionally *diverge*.
`smoke-tpm-seal` asserts a changed PCR leaves the volume locked. These test that the control
fires, not merely that the happy path works.

---

## 13. Side-channel posture

**Flush on switch.** `set_current_task(v)` is the single chokepoint at which a CPU is about
to resume task `v`. Hooking there covers every switch path — timer preemption, IPC block,
yield, first entry — with none able to bypass it. When the incoming ring-3 task differs from
the outgoing one, the CPU evicts indirect-branch predictor state, L1D, and store/fill/load
buffers. The policy predicate is factored out as a pure function
(`sched_domain_switch_would_flush`) so it can be tested independently of the barriers, and
the barriers themselves are gated on CPUID feature detection.

**SMT parking.** Sibling threads are parked in software, closing same-core co-residency.

**`CR4.TSD`.** Ring-3 `RDTSC` faults, removing the cheapest high-resolution timer an attacker
would use to build a cache side channel.

**What is not covered.** A concurrent sibling on the same physical core when SMT parking is
disabled; DMA-capable devices (no IOMMU); and any channel through the shared L2/L3. See
`docs/LIMITATIONS.md`.

---

## 14. Known architectural gaps

These are design-level, not bugs to be patched in place. Each is tracked in
[`ROADMAP.md`](ROADMAP.md) and analysed in [`AUDIT-2026-07-27.md`](AUDIT-2026-07-27.md).

**G-2 — Ambient `uid == 0` authority runs parallel to the capability system.** *Closed*
(roadmap 0.2, finding **[I-1]**). Nine syscall handlers used to gate on the caller's uid
rather than on a capability, so the capability graph was not a complete description of who
could do what. Each of those gates is now a distinct capability type — `CAP_KERNEL_LOG`
(dmesg), `CAP_BOOT_MODULE` (the module read surface), `CAP_ENCRYPTED_STORAGE` (the object
store, §11) — minted once in the primordial root cnode and delegated by `init` to exactly the
task that needs it. `SYS_GET_TASK_INFO`'s root promotion is gone with them: cross-task
introspection now needs a `CAP_USER` (slot 6) or `CAP_AUDIT` (slot 7), and `info.eip` is
zeroed for any task but the caller (finding **[I-4]**).

*Closed properly only on 2026-08-15* (finding **[H-1]**). Roadmap 0.2's sweep covered
`syscall.c` and `syscall_fs.c` and missed `kusers.c`, whose `current_user_is_admin()` kept a
`uid == 0` fallback — the sole gate on `SYS_USERADD` / `SYS_USERDEL` / `SYS_PASSWD`, which are
`SC_NONE` in the dispatch table. This paragraph claimed "*Closed*" for nineteen days while it
was not. Administrative authority over the user database is now possession of `CAP_USER` and
nothing else. See `LIMITATIONS.md` §1.2 for why the conformance suite could not have caught it.

**G-3 — Kernel objects are fixed-size `.bss` tables.** *Largely closed* (roadmap 0.3, finding
**[I-7]**). `CAP_UNTYPED` + `SYS_RETYPE` are in: cspaces, endpoints and notifications are
carved from untyped memory (§4), which removed 504 KiB of `.bss` and made object creation an
exercise of authority the capability graph describes. What remains is `tasks[]` — a TCB is
reachable from the scheduler's hot path and from every trap frame, so migrating it is its own
change — and reclaiming a dead task's cspace, which needs `cap_lookup`'s NULL-cspace →
root-cnode fallback removed first.

**G-4 — Endpoints are single-slot with no queue.** *Closed 2026-08-11* (roadmap 1.3, finding
**[I-5]**). Endpoints are bounded FIFOs of `EP_QUEUE_SLOTS` (§8), so concurrent senders enqueue
instead of colliding, and the one-shot `CAP_REPLY` landed with them — reply forgery is
structurally impossible rather than right-gated. The shared global reply endpoint that used to
compound this is also gone; every task has a private one.

*This paragraph continued "**What remains is a blocking receive:** an empty queue still returns
`-2` and the server polls" for four days after that stopped being true.* `SYS_IPC_RECV_BLOCK`
(syscall 94, `syscall.c:1032`) sleeps on an empty queue, and both ring-3 servers use it —
`console_server.c:229` unconditionally, `fs_server.c:644` once the volume is provisioned, since
before that it must keep polling the root inode for a login to unlock it. Session time on one
core fell 15.18 s → 6.25 s with non-overlapping ranges. `smoke-recvblock` and
`smoke-recvblock-smp` gate it, and `EP_QUEUE_SLOTS=1` rebuilds the single-slot endpoint as the
control arm. What is still inexpressible is **priority inheritance**, which needs priorities the
scheduler stores but does not use (§7), and IPC **timeouts**, which need the clock roadmap 2.2
adds — a blocked task blocks until woken or killed.

**G-5 — No kernel object lifecycle.** *Closed for retyped objects* (roadmap 0.3). A retyped
endpoint or notification is destroyed when no capability names it any more, computed by
mark-and-sweep over the capability graph (§4). The statically-allocated well-known service
objects are still immortal by construction — they are named by the boot protocol rather than
by any single capability — and will stop being so as they migrate to retyped objects.

**G-6 — `this_cpu()` reads LAPIC MMIO on every call.** *Closed, differently* (roadmap 1.2,
finding **[I-6]**). The MMIO read is off the hot path: `this_cpu()` derives the CPU id from
the TSS selector in `TR` rather than reading the LAPIC, verified per-core against the LAPIC at
bringup (`percpu_id_verify_self`, `make smoke-percpu`). `%gs`-based per-CPU data was *not*
adopted — the ring-3 return paths load `0x33` into `%gs`, which zeroes the GS base in long
mode, so doing it properly needs a CS-conditional `swapgs` on every ISR entry and exit plus
the NMI/IST re-entrancy hazard. **[C-3]** did not wait for it: the per-CPU lock landed on
2026-08-11 with its nesting depth and saved `RFLAGS.IF` in `MAX_CPUS`-indexed arrays that
`this_cpu()` indexes directly (§6). A per-CPU *block* is still wanted — for a current-TCB
pointer, and to stop paying a `MAX_CPUS`-wide array per datum — but nothing is blocked on it.

**G-7 — a blocked task can be left holding a scheduler claim.** *Closed 2026-08-09 — the
checker was wrong, not the scheduler.* The `SCHED_INVARIANTS=1` reports were not `init`
blocked in `sys_wait()`; they were `init` mid-`do_spawn`, where `load_staged_image_into`
deliberately installs the *child* as the CPU's current task for the whole ELF load so the
loader's `copy_to_user` resolves through the child's address space. The claim was live, not
stale, and the auditor was reading an undeclared impersonation as a leak.
`sched_impersonate_enter/exit` now record the task the CPU is *really* running
(`percpu_real_task[]`) and the audit is stated over that, with the bracket depth itself
checked. 20 pinned boots before: 10 failures; 30 after: 0. See `TESTS.md`,
`make smoke-sched-invariants`.
