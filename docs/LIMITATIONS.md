# Horus — Current Limitations

This document is an honest account of what Horus does and does not do. The goal is to prevent anyone from drawing incorrect conclusions about its readiness or security properties.

Horus is a research and learning project. It is not a production operating system and makes no claim to be one. Where this document and the code disagree, the code is the source of truth — please open an issue.

---

## What actually works

These subsystems are functional in the current codebase:

- **Boot sequence** — Multiboot2 boot via GRUB2 into x86-64 long mode, with the kernel linked into the higher half at `0xFFFFFFFF80000000`; a ring-3 `init` (PID 1) launches the shell. A boot-time assertion checks the kernel really is executing above `KERNEL_VMA` and that `virt_to_phys`/`phys_to_virt` round-trip (`HIGHHALF: PASS`), so a botched relocation is loud rather than a mystery fault later.
- **VGA terminal** — text mode, colour output, kernel log buffer, serial mirror; PS/2 keyboard input.
- **Hardware isolation** — Ring 0/Ring 3 separation, per-task page tables, user/kernel memory split. SMEP, SMAP and UMIP are enabled when the CPU advertises them (ring 0 cannot execute or casually read user pages, and ring 3 cannot read out the GDT/IDT/LDT/TSS addresses via `SGDT`/`SIDT`/`SLDT`/`STR`/`SMSW`), brought up after feature detection. `make smoke-cpu` gates this: it boots under a CPU that advertises all three and asserts each is both detected *and* present in CR4. That gate exists because they were **silently off for the project's entire history** — the CPUID leaf-7 query inherited a stale ECX and read back zeros, so the kernel believed the features were absent. Nothing in the source looked wrong, and asking the kernel what it had detected would have agreed with it. With the kernel in the higher half, a user page directory holds *only* the task's own mappings, so a user mapping cannot shadow kernel state by construction rather than because ASLR is bounded away from it.
- **Per-task x87/SSE context** — each task's register file is saved and restored around every ring-3 kernel entry (`FXSAVE`/`FXRSTOR` into the TCB), so one task cannot read what another left in `xmm`. The kernel is built `-mno-sse -mno-mmx -mno-80387` and holds no FPU state of its own to leak. Regression-tested by `make smoke-fs-conc`.
- **W^X for user memory** — `EFER.NXE` is on and the kernel sets the PTE NX bit so writable pages are never executable: user stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags`. The policy decision lives in Rust and is unit-tested; the shipped static-PIE binaries take the ELF path and are covered by the smoke-boot, `smoke-elf` (ELFCLASS32) and `smoke-elf64` (ELFCLASS64) tests.
- **W^X for the kernel's own image** — `.text` is mapped read-only + executable, `.rodata` read-only + NX, `.data`/`.bss` writable + NX, and the low megabyte, the dead `.boot` stage and the slack above `.bss` are absent outright. `CR0.WP` is set, without which the read-only half would be advisory: a supervisor write ignores the PTE write bit when WP is clear, and ring 0 is the only ring that can reach those pages. Gated by `make smoke-wx`, which asserts the per-section bits, checks `CR0.WP`/`EFER.NXE` are actually engaged, and then **sweeps every present leaf in the address space** asserting none is simultaneously writable and executable (~8,800 leaves; both permissions accumulated across page-table levels).

  The sweep, rather than a per-section check, because every hole this kernel had was an **alias** — a second mapping of the same frames with different bits — and `.text`'s own PTE was correct throughout. `multiboot.S` built one page directory of 2 MiB `P|W` pages with no NX and hung it off three entries at once (the identity map, the PHYS_KVA window, and the kernel's own mapping), so tightening any view tightened all three and none could be. Each of the four holes was found by hand, by guessing where to look; the sweep found the fifth on its own (the LAPIC's MMIO registers were mapped writable *and* executable, outside the image where no per-section check would have looked).
- **Capability mint, transfer, grant, and revoke** — the core operations work, including transitive revocation across every task's cspace and the kernel root cnode. Revocation requires `CAP_RIGHT_REVOKE`; mint/transfer require `CAP_RIGHT_MINT`; a "no ambient authority" guard refuses cap operations from any non-kernel task lacking its own cspace. `SYS_CAP_GRANT` delegates one slot from a supervisor into a child it spawned.
- **Lineage tracking** — use-after-revoke is prevented via per-lineage generation counters; a looked-up capability can be snapshotted and re-validated at point of use (wired into the IPC paths to close a lookup/use TOCTOU window).
- **Capability/FFI integrity** — the C `capability_t` and Rust `Capability` layouts are pinned by mirrored compile-time assertions; the refcount table is registered once and every later inc/dec must present the exact (pointer, length) or is refused.
- **User authentication** — login, lockout after failed attempts + anti-spray throttle, per-user UID assignment, Argon2id memory-hard hashing; password changes persist across reboots.
- **Audit log** — kernel-side circular buffer of security events. **Tamper-evident**: each entry is HMAC'd (binding its sequence number) and a running hash-chain head commits to the whole ordered history, keyed by the per-boot pepper (`rust/src/audit.rs`); `SYS_AUDIT_DIGEST` returns the digest + constant-time verify status. Detector, not tamper-proof (see below).
- **Preemptive round-robin scheduling** — the timer (PIT at 100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch, so CPU-bound tasks time-share without cooperating. A tick in ring 0 never switches (the kernel stays effectively non-preemptible). Proven by `make smoke-preempt`. Blocking (`SYS_IPC_CALL`, `SYS_WAIT`), voluntary `SYS_YIELD`, first entry into a task (`sched_enter_user`), and boot of `init` all use the same full-context trap-frame path; the legacy cooperative `yield()`/`schedule()` switch has been removed.
- **Ring-3 process control** — a task can `SYS_SPAWN` a named child (receiving its `CAP_TCB`), replace its own image in place (`SYS_EXEC_NAMED`), delegate caps to a child (`SYS_CAP_GRANT`), terminate itself (`SYS_EXIT`) or a task it holds a `CAP_TCB` for (`SYS_KILL`), and block until a task exits (`SYS_WAIT`). Proven by `make smoke-proc`.
- **`init` supervision** — a ring-3 PID 1 spawns, capability-endows, and blocking-supervises the shell, relaunching it on exit or fault.
- **Fault signals** — a task registers its own handler (`SYS_SIGACTION`); a ring-3 fault (page fault → `SIG_SEGV`, `#UD` → `SIG_ILL`) is delivered to it (signal # in `rbx`, fault addr in `rcx`) instead of killing it, and `SYS_SIGRETURN` resumes the exact pre-signal context. The handler address is validated in safe Rust (fail-closed); a fault *inside* a handler is not re-delivered; the handler runs at ring 3 with unchanged privileges. Proven by `make smoke-signal`.
- **Async task-to-task signals** — `SYS_SIGNAL` (gated on a `CAP_TCB` to the target, same authority as `SYS_KILL`) queues a signal, redirected into the target's handler on its next return to ring 3, or taking the default terminate action when unhandled or for the uncatchable `SIG_KILL`. The pending set is a full 1..31 bitmask; `SYS_SIGMASK` blocks/unblocks signals (lowest unmasked delivered first, `SIG_KILL` never maskable); a signal to a `SYS_WAIT`-blocked target interrupts the wait (`SYS_ERR_INTR`) so it lands promptly; and `SYS_SIGALTSTACK` runs a handler on a registered alternate stack (`SS_ONSTACK` guard, so a corrupt or overflowed primary stack cannot stop the handler running). Proven by `make smoke-proc`.
- **Symmetric multiprocessing (behind `SMP=1`)** — application processors are brought up (LAPIC INIT-SIPI-SIPI), each runs its own LAPIC-timer preemption tick over a shared runnable pool, IPC/notification paths lock for cross-CPU safety, and TLB-shootdown IPIs are acknowledged. Proven by `make smoke-smp`. Off by default; see the SMP note below.
- **Filesystem server** — a ring-3 `fs_server` over the kernel's encrypted object store, reached over IPC; real `ls`/`cat`/`mkdir`/`rm`/`touch`/redirection from the shell, and the system's single filesystem (the legacy in-memory capfs is removed). It is the filesystem reference monitor: it enforces per-file POSIX owner/group/other rwx against the caller's *kernel-attested* uid/gid (`SYS_IPC_SENDER`, unforgeable by the client), serves multiple clients concurrently with replies routed to each caller by identity (`SYS_IPC_REPLY_TO`), makes every multi-block update crash-atomic through a write-ahead redo journal replayed by a mount-time `fsck`, and supports large files via double-indirect blocks. Proven by `make smoke-fs`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, and `smoke-fs-large`.
- **Persistent encrypted storage (by default when a disk is present)** — at boot the kernel probes for an ATA disk (bounded probe; no hang on a diskless bus) and uses the encrypted store when one is present. Per-block crypto metadata (nonces/tags) is flushed on write and reloaded + HMAC-verified at mount, so files survive a reboot; the volume comes up mounted-but-locked and is unwrapped at login (Argon2id-derived KEK). With no disk attached the kernel falls back to an ephemeral in-RAM vdisk (auto-unlocked). Proven by `make smoke-fs-persist` (write on boot 1, verify on boot 2 against the same disk image).
- **Userspace runtime** — ring-3 tasks are 64-bit (`EM_X86_64` static-PIE, relocated at load via `R_X86_64_RELATIVE`), with a demand-paged heap via `sbrk`/`brk`, a userspace `malloc`, and an `x86_64-elf` newlib libc port over a per-process POSIX fd layer (`make smoke-newlib`).
- **Reproducible builds** — `make reproducible-build` yields a byte-for-byte identical `kernel.elf` across clean builds (verified in CI).

---

## Partial implementations

These subsystems compile and run but are incomplete:

### Userspace shell

The shell accepts input and dispatches commands. Several are implemented end-to-end; others parse their arguments but return errors or do little. Coverage is uneven.

### IPC

The endpoint-based `send`/`recv` cycle works (256-byte messages, capability-gated). `SYS_IPC_SEND`/`RECV` are **non-blocking** (return a would-block code `-2`; the caller polls from ring 3 where preemption interleaves it); `SYS_IPC_CALL` can block on the full-context path. Each endpoint is a **single-slot mailbox**, so it serves **one in-flight request at a time**. Concurrent multiple-client service is achieved above this primitive by `SYS_IPC_REPLY_TO`, which routes a server's reply to the request's kernel-recorded sender (used by `fs_server`); a richer multi-slot / parallel-worker IPC is still a follow-up. **Async notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) work**: `SYS_NOTIFY` ORs a 32-bit badge into a notification slot and wakes any task blocked on it (accumulating the badge otherwise); `SYS_WAIT_NOTIFY` consumes a pending badge or blocks via the same full-context path as IPC. Proven by `make smoke-notify`.

### Copy-on-write paging

The `PAGE_COW` flag and refcount infrastructure are in place, and the page-fault handler calls into Rust to decide demand-zero vs. COW-copy. The demand-zero path now genuinely works — until recently it did not, and could not: the pager reached freshly allocated frames through a virtual address that a user CR3 does not map, so it faulted inside itself and deadlocked on the `page_lock` it already held, and separately the heap sat in a window that is identity-mapped supervisor and therefore cannot be demand-paged at all. Both are fixed (see CHANGES.md), and a probe walking 640 KiB of heap now completes.

Demand-zero reads now resolve to a **single shared, read-only zero frame** marked `PAGE_COW`, so a task that reads a large sparse heap consumes one physical page rather than one per page touched. The first *write* breaks the sharing: the pager hands out a private zeroed frame, clears `PAGE_COW`, and preserves the address's NX bit. `make smoke-cow` exercises this from ring 3, asserting that fresh heap pages read as zero, that writing one page keeps its sibling zero, and that the two are mutually isolated afterwards. Note what that gates and what it does not: those assertions hold equally if the pager ignored the shared zero page and gave every fault a private frame, so `smoke-cow` gates the **user-visible contract**, not the sharing itself. That the sharing engages was confirmed by tracing the pager during development (one zero-page→private break per written page, and no more); gating it in CI would need kernel introspection the test deliberately does without.

One branch remains untested end-to-end. Breaking the *zero* page needs no copy (the copy of an all-zero frame is zeros), so it takes a special case and returns early — the generic COW path that decrements the refcount and duplicates real page content is still reached by nothing, because `fork` is a deliberate non-goal (see ROADMAP Phase 1) and nothing else in the tree shares a **non-zero** page. That branch is unit-tested in Rust only; treat it as untested code.

The shared zero frame is never freed: `free_user_physical_page` refuses it explicitly, and it is aliased by many PTEs whose refcounts are deliberately not tracked against it.

### Disk-backed storage (volume geometry)

`storage.c` implements encrypted block storage — a ChaCha20 + HMAC-SHA256 AEAD with per-block HKDF keys, fresh per-write nonce, `(ino, block)` as AAD — over a real superblock/inode/bitmap layout, exercised end-to-end by `fs_server` via the encrypted object-store syscalls. The live backend is selected at boot: a real ATA disk (`ata.c`, 28-bit-LBA PIO) when one is present, otherwise the ephemeral RAM vdisk. Cross-reboot persistence of files *and* their per-block crypto metadata is in place on ATA, multi-block updates are crash-atomic through a write-ahead redo journal replayed by a mount-time `fsck`, and files map through direct + single- + double-indirect blocks. The remaining limit is volume *scale*: a single 512-byte bitmap block caps a volume at 4096 data blocks (2 MiB). Growing that cap needs multi-block bitmaps, which is a pure capacity feature with no security value and is a deliberate non-goal for now (the allocator already enforces the cap safely).

---

## What does not work / is not yet present

### SMP as default

Multi-core works behind `SMP=1`, but the shipped kernel is single-core. The multi-core scheduler shares one runnable pool with a per-CPU pull; there are no per-CPU run queues, no priorities or fairness, and no flush-on-switch. Retiring the gate and hardening the scheduler is Phase 3.

### ASLR entropy ceiling (page-table geometry)

Per-spawn stack top, heap gap, and image load base are all randomised from the CSPRNG (userspace is static-PIE and relocated at load). The remaining limitation is *entropy*, not mechanism: the image base has 8.91 bits (480 pages).

Note the reason has changed, even though the number has not. This used to be a consequence of the ABI — userspace ran in 32-bit compatibility mode — and the figure was lower still, clamped away from kernel low memory. Userspace is now 64-bit and the kernel is in the higher half, so neither bound applies; 8.91 bits is the *structural* ceiling of the current design, where `create_user_pagedir` premaps the image window into a single 2 MiB PD entry and `ASLR_MAX_LOAD_RANDOM_PAGES` (`512 - 32`) is exactly what fits. The user image window itself is still `[4 MiB, 8 MiB)`. Reaching the tens of bits a 64-bit address space allows is no longer an ABI question — it needs the premap and the user window to be restructured.

---

## Security limitations

These matter specifically for anyone evaluating Horus as a security system:

### Encrypted storage is persistent, but still early

The block cipher is sound (ChaCha20 + HMAC-SHA256 AEAD, per-block HKDF subkeys, fresh per-write nonce), and on an attached ATA disk the store is the live backend with crypto metadata persisted across reboots (volume sealed until login), multi-block updates crash-atomic via a write-ahead redo journal, and per-file POSIX ownership/permissions enforced by the `fs_server` against the caller's kernel-attested identity. Residual limitations are operational rather than cryptographic: a diskless boot still uses the ephemeral RAM vdisk, and volume size is capped at 2 MiB by single-bitmap geometry (a deliberate non-goal to grow). Fuller ACLs (beyond POSIX owner/group/other + a uid-0 superuser) are also a deliberate non-goal.

### Bounded load-base ASLR entropy

The load base has 8.91 bits of entropy — bounded by page-table geometry rather than the ABI (see above) — so a determined attacker with a memory-disclosure primitive faces a smaller search space than a full 64-bit randomisation would impose.

### Audit log is tamper-evident, not tamper-proof

Edits, ring-slot swaps, replays, drops, and rollbacks are all *detectable* (including by an external monitor recording the chain head via `SYS_AUDIT_DIGEST`). The residual limitation is that this is a **detector**: an attacker who fully compromises the kernel and reads the per-boot pepper can recompute a self-consistent chain — the same accepted trust boundary as the user-database tag.

### No covert / cache side-channel mitigation

The timer preempts and switches between mutually distrusting ring-3 tasks (and, under `SMP=1`, across cores), but there is no flush-on-switch or cache partitioning to limit microarchitectural leakage. Tracked in `SECURITY.md`.

### No privilege separation within the kernel

All kernel code runs at the same privilege level with access to all kernel data; a bug in the terminal driver has the same blast radius as one in the capability system.

### Only ring-3 tasks' kernel stacks are guarded

Each task's kernel stack now sits above an unmapped guard page, so an overflow faults on the guard instead of running into the previous task's stack. This is gated by `make smoke-wx`, which checks the guard is absent *and* that the stack above it is still present — unmapping one page too many would take the stack with it.

It covers slots 1..63, i.e. every task that runs ring-3 code. **Task 0 — the kernel's own boot/idle task — is not guarded**: it keeps the `kernel_stacks[]` entry `create_task` gives it (`create_user_pagedir` returns early for task 0 and never rebinds the stack), and that array is only 16-byte aligned with no guard slot, so guarding it needs a layout change rather than an unmap. Also unguarded: the BSP boot stack, the three 4 KiB IST stacks (thin for a double-fault handler), and the early-handler stack.

There are two per-task kernel stack arrays, which is one more than the design needs: `create_task` binds `kernel_stack_top` to `kernel_stacks[id]` (2 MiB, `scheduler.c`) and then `create_user_pagedir` immediately rebinds it to `per_task_kstacks[id]` (4 MiB, `paging.c`) for every task but 0. So `kernel_stacks[1..63]` is written once and never used, and `per_task_kstacks[0]` is never used — close to 2 MiB of `.bss` that exists to be overwritten. That matters more than it looks: `.bss` ends ~600 KiB below `USER_PHYS_BASE`, and the link-time `ASSERT` guarding that collision is the only thing standing between a routine `MAX_TASKS` bump and the allocator handing out live kernel memory.

### No KASLR

The kernel image is linked at a fixed `KERNEL_VMA` (`0xFFFFFFFF80000000`) and loaded at a fixed physical 1 MiB, so its addresses are identical on every boot — the ASLR that exists is user-side only. This is not a small change and it is not merely undone work: `-mcmodel=kernel` lets GCC materialise symbol addresses as 32-bit sign-extended immediates, which is only valid in `[-2 GiB, +2 GiB)`, and `linker64.ld` explains at length why that pins the base. Real KASLR needs a relocatable kernel, or randomisation confined to whatever slack exists inside the -2 GiB window.

---

## Code quality notes

- Compilation success is not evidence of correct runtime behaviour; some paths are partial.
- Error codes are a shared, descriptive, errno-aligned `SYS_ERR_*` set (`include/errno.h`) used by both kernel and userspace, with `sys_strerror()`. The dispatcher and the auth / user-copy paths return specific codes; some deeper helpers still use ad-hoc small negatives.
- The Rust crate is named `horus_shell` for historical reasons; it is the security core (capabilities, memory refcounting, the SHA-2/BLAKE2b/Argon2id/KDF/AEAD/RNG primitives, FFI validation).
- `src/kernel/minimal_secure_stubs.c` supplies the stubs for the `MINIMAL_SECURE=1` build; it is build configuration, not security logic.
- **Tests:** 57 Rust unit tests (capability engine, memory/refcount trust boundary, RNG and SHA-2 family vs. published vectors, the ChaCha20+HMAC AEAD, the tamper-evident audit MAC/chain, BLAKE2b + Argon2id vs. RFC 7693 / `argon2-cffi` vectors, the W^X page policy, the signal-handler-address window, FFI validation). CI runs **26 jobs** (twenty-five gating; the `security` SAST/SBOM scan is advisory and never blocks a merge) (`cargo test` + `clippy -D warnings`; kernel/ISO build; alt-config matrix; twenty-one headless QEMU self-tests — smoke-boot, the kernel W^X leaf sweep, the CR4 protections actually being set in CR4, ELF/W^X for both ELFCLASS32 and ELFCLASS64 images, preemption, signals, process-control, copy-on-write, image-base ASLR, async notifications, SMP, a scripted `smoke-session` integration test that drives the real ring-3 shell over serial, and the filesystem/libc suite: fs, fs-perms, fs-conc, fs-persist, fs-wal, fs-large, init-fs, newlib; a reproducible-build check; and a security scan + SBOM). The scripted-session harness (`tools/session_test.py`) is a first, deliberately small integration test — broader scenarios (W^X violations, IPC/FS round-trips) and fuzzing are still ahead, as is automatic checking of the TLA+ specs in `docs/`.

---

## Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part of the project.

| Area | Estimate |
|---|---|
| Capability model (design and core implementation) | ~85% |
| Boot and hardware initialisation | ~85% |
| Process model (spawn/exec/kill/wait/signal, init) | ~85% (Phase 1 complete; mask + altstack + image exec) |
| Memory management | ~55% |
| Task scheduling | ~60% (preemptive; SMP behind a gate; no priorities) |
| IPC | ~45% (send/recv + blocking call + async notifications; single-slot) |
| Filesystem | ~75% (ring-3 server over encrypted store; persistent on ATA; per-file permissions, multi-client, crash-atomic journal, large files) |
| Cryptography (Argon2id/BLAKE2b + KDF/MAC/RNG + ChaCha20/HMAC AEAD) | ~80% |
| Storage / disk I/O | ~75% (ATA probe + persisted crypto metadata + crash-atomic journal; volume-size cap remains) |
| SMP | ~55% (works behind `SMP=1`; not default, shared run queue, no priorities) |
| Testing | ~45% (57 unit tests + 26 CI jobs + twenty-one QEMU self-tests; no deeper integration/fuzz) |
