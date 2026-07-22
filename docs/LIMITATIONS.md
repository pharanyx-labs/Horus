# Horus — Current Limitations

This document is an honest account of what Horus does and does not do. The goal is to prevent anyone from drawing incorrect conclusions about its readiness or security properties.

Horus is a research and learning project. It is not a production operating system and makes no claim to be one. Where this document and the code disagree, the code is the source of truth — please open an issue.

---

## What actually works

These subsystems are functional in the current codebase:

- **Boot sequence** — Multiboot2 boot via GRUB2 into x86-64 long mode, with the kernel linked into the higher half at `0xFFFFFFFF80000000`; a ring-3 `init` (PID 1) launches the shell. A boot-time assertion checks the kernel really is executing above `KERNEL_VMA` and that `virt_to_phys`/`phys_to_virt` round-trip (`HIGHHALF: PASS`), so a botched relocation is loud rather than a mystery fault later.
- **Console** — an 80×50 VGA text grid mirrored to serial, with a kernel log buffer and PS/2 keyboard input. The driver now runs as a **ring-3 server** (`console_server`): the shell's output and its line input (including echo and masked password entry) go through it over IPC, and it drives the framebuffer and serial/VGA ports itself. The kernel keeps a minimal serial writer for panic and early-boot output, and an in-kernel reader as a fallback.
- **Hardware isolation** — Ring 0/Ring 3 separation, per-task page tables, user/kernel memory split. SMEP, SMAP and UMIP are enabled when the CPU advertises them (ring 0 cannot execute or casually read user pages, and ring 3 cannot read out the GDT/IDT/LDT/TSS addresses via `SGDT`/`SIDT`/`SLDT`/`STR`/`SMSW`), brought up after feature detection. `make smoke-cpu` gates this: it boots under a CPU that advertises all three and asserts each is both detected *and* present in CR4. That gate exists because they were **silently off for the project's entire history** — the CPUID leaf-7 query inherited a stale ECX and read back zeros, so the kernel believed the features were absent. Nothing in the source looked wrong, and asking the kernel what it had detected would have agreed with it. With the kernel in the higher half, a user page directory holds *only* the task's own mappings, so a user mapping cannot shadow kernel state by construction rather than because ASLR is bounded away from it.
- **Per-task x87/SSE context** — each task's register file is saved and restored around every ring-3 kernel entry (`FXSAVE`/`FXRSTOR` into the TCB), so one task cannot read what another left in `xmm`. The kernel is built `-mno-sse -mno-mmx -mno-80387` and holds no FPU state of its own to leak. Regression-tested by `make smoke-fs-conc`.
- **W^X for user memory** — `EFER.NXE` is on and the kernel sets the PTE NX bit so writable pages are never executable: user stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags`. The policy decision lives in Rust and is unit-tested; the shipped static-PIE binaries take the ELF path and are covered by the smoke-boot, `smoke-elf` (ELFCLASS32) and `smoke-elf64` (ELFCLASS64) tests.
- **W^X for the kernel's own image** — `.text` is mapped read-only + executable, `.rodata` read-only + NX, `.data`/`.bss` writable + NX, and the low megabyte, the dead `.boot` stage and the slack above `.bss` are absent outright. `CR0.WP` is set, without which the read-only half would be advisory: a supervisor write ignores the PTE write bit when WP is clear, and ring 0 is the only ring that can reach those pages. Gated by `make smoke-wx`, which asserts the per-section bits, checks `CR0.WP`/`EFER.NXE` are actually engaged, and then **sweeps every present leaf in the address space** asserting none is simultaneously writable and executable (~8,800 leaves; both permissions accumulated across page-table levels).

  The sweep, rather than a per-section check, because every hole this kernel had was an **alias** — a second mapping of the same frames with different bits — and `.text`'s own PTE was correct throughout. `multiboot.S` built one page directory of 2 MiB `P|W` pages with no NX and hung it off three entries at once (the identity map, the PHYS_KVA window, and the kernel's own mapping), so tightening any view tightened all three and none could be. Each of the four holes was found by hand, by guessing where to look; the sweep found the fifth on its own (the LAPIC's MMIO registers were mapped writable *and* executable, outside the image where no per-section check would have looked).
- **Image-base ASLR** — a PIE image's load base is drawn from the CSPRNG across a 4 TiB window above 16 GiB: 30 bits of entropy (2^30 page-aligned positions), up from the 8.91 bits the old single-page-table premap allowed. That old ceiling was the page-table shape, not a policy — `ASLR_MAX_LOAD_RANDOM_PAGES` was literally the slots left in one 2 MiB PD entry. The multi-level page-table walk lifted it; the image, stack and heap sit in separate regions so the window can be wide. Per-spawn stack top and heap gap are randomised too. `make smoke-aslr` asserts 8 spawns land at 8 distinct high bases spanning more than 1 GiB.
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
- **Symmetric multiprocessing (default-on)** — application processors are brought up (LAPIC INIT-SIPI-SIPI, CPU count from the ACPI MADT), each runs its own LAPIC-timer preemption tick over a shared runnable pool, IPC/notification paths lock for cross-CPU safety, and TLB-shootdown IPIs are acknowledged. Proven by `make smoke-smp`. `SMP=0` compiles it out and boots single-core; the scheduler-maturity gaps are in the SMP note below.
- **Filesystem server** — a ring-3 `fs_server` over the kernel's encrypted object store, reached over IPC; real `ls`/`cat`/`mkdir`/`rm`/`touch`/redirection from the shell, and the system's single filesystem (the legacy in-memory capfs is removed). It is the filesystem reference monitor: it enforces per-file POSIX owner/group/other rwx against the caller's *kernel-attested* uid/gid (`SYS_IPC_SENDER`, unforgeable by the client), serves multiple clients concurrently with replies routed to each caller by identity (`SYS_IPC_REPLY_TO`), makes every multi-block update crash-atomic through a write-ahead redo journal replayed by a mount-time `fsck`, and supports large files via double-indirect blocks. Proven by `make smoke-fs`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, and `smoke-fs-large`.
- **Persistent encrypted storage (by default when a disk is present)** — at boot the kernel probes for an ATA disk (bounded probe; no hang on a diskless bus) and uses the encrypted store when one is present. Per-block crypto metadata (nonces/tags) is flushed on write and reloaded + HMAC-verified at mount, so files survive a reboot; the volume comes up mounted-but-locked and is unwrapped at login (Argon2id-derived KEK). With no disk attached the kernel falls back to an ephemeral in-RAM vdisk (auto-unlocked). Proven by `make smoke-fs-persist` (write on boot 1, verify on boot 2 against the same disk image).
- **Userspace runtime** — ring-3 tasks are 64-bit (`EM_X86_64` static-PIE, relocated at load via `R_X86_64_RELATIVE`), with a demand-paged heap via `sbrk`/`brk`, a userspace `malloc`, and an `x86_64-elf` newlib libc port over a per-process POSIX fd layer (`make smoke-newlib`). The libc surface covers `open`/`read`/`write`/`close`/`lseek`, `stat`/`fstat` (reporting the file's real mode/uid/gid), `unlink`/`rename`/`ftruncate`, directory iteration (`opendir`/`readdir`/`closedir` over the permission-checked `FS_OP_READDIR`), a per-process working directory (`chdir`/`getcwd` with relative-path resolution), an empty `environ` (so `getenv` links and returns "not found"), `fcntl` (fd-validating flag-word no-ops), `mkstemp`, and `kill()` (wired onto `SYS_SIGNAL` under the capability model: it reaches your own descendants and yourself, `EPERM` otherwise — the "descendants-only" resolution, no ambient pid namespace), `link()` (real store-level hard links: a new `FS_OP_LINK`/`SYS_FS_INODE_LINK` increments an inode's on-disk link count, `unlink` decrements it and frees the inode only when the last name goes, and `stat` reports the real `st_nlink`), and `tmpfile()` (a named temp file removed when its fd is closed) — all gated by `make smoke-newlib`. The libc surface for a coreutils/binutils port is now complete; the remaining constraint is program *size*, not the C library. Both former program-size caps are lifted. The image-window premap is sized to the staged image's actual loaded span (`staged_image_span_pages()`), so a loaded image is no longer capped at the old fixed 128 KiB premap; and the staged-image buffer (`loader_staging`) moved off `.bss` — it is now a fixed region reserved at the base of the physical pool and reached through the `PHYS_KVA` window, so `MAX_PROGRAM_SIZE` is 8 MiB (trivially raisable, costing pool frames not `.bss`) instead of ~1 MiB against the tight `.bss` ceiling. `make smoke-newlib` loads a ~1.5 MiB image (a ~1.06 MiB `const` array past the old 1 MiB cap, plus a ~160 KiB `.bss` array taking the loaded span to ~69 pages past the old 32-page premap); forcing either cap back to its old value makes the image fail to load and the test fail. Programs now reach the system as **GRUB multiboot2 modules** the `fs_server` provisions into `/bin` (they no longer live in the kernel image at all — see the coreutils note below), so the kernel-image budget no longer bounds them. The store volume was grown from 2 MiB to **16 MiB** (a multi-block data-allocation bitmap, an off-`.bss` RAM vdisk, and a hierarchical metadata rollback-MAC so the per-write cost stays flat), so all eleven ported coreutils binaries live in `/bin` at once.
- **Reproducible builds** — `make reproducible-build` yields a byte-for-byte identical `kernel.elf` across clean builds (verified in CI).

---

## Partial implementations

These subsystems compile and run but are incomplete:

### Userspace shell

The shell accepts input and dispatches commands. Several are implemented end-to-end; others parse their arguments but return errors or do little. Coverage is uneven.

The presentation layer is deliberate rather than incidental. `ls` sorts its entries, packs them into columns sized to the console, and marks directories (`/`) and executables (`*`); `ls -l`, `stat` and `ps` print aligned tables behind a header row, with human-readable sizes. **No ANSI colour is used anywhere**: the console is a VGA text grid mirrored to serial and the terminal driver does not interpret escape sequences, so colour codes would render as literal garbage on the VGA side — alignment and column discipline carry the whole visual weight instead.

The shell also carries its own manual: `man <command>` renders a full reference page (NAME / SYNOPSIS / DESCRIPTION / OPTIONS / EXIT STATUS / SEE ALSO), `whatis` gives the one-line summary and `apropos` searches names and summaries by keyword. The pages live in the shell binary — there is no `/usr/share/man` to read and nothing to load from disk — so the manual works before any filesystem is mounted, and the text describes what is actually true on Horus (which operations are capability-gated, which are checked against a kernel-attested uid) rather than repeating Unix folklore. `make smoke-session` asserts the page sections render and that an unknown page is reported rather than silently ignored. When the ported GNU coreutils utilities are shipped as GRUB boot modules (`COREUTILS_MODULES=1`) and provisioned into `/bin`, the shell runs them by name with arguments -- `head file`, `wc -w file`, `seq 1 5`, `printf %s=%d\n foo 7`, `tail -c 3 file` -- resolving `/bin/<name>`, loading the image over the fs_server, and spawning each as a child that reaches the fs_server over its own connection; a `/bin/<name>` shadows the shell's lighter builtin of the same name.

### IPC

The endpoint-based `send`/`recv` cycle works (256-byte messages, capability-gated). `SYS_IPC_SEND`/`RECV` are **non-blocking** (return a would-block code `-2`; the caller polls from ring 3 where preemption interleaves it); `SYS_IPC_CALL` can block on the full-context path. Each endpoint is a **single-slot mailbox**, so it serves **one in-flight request at a time**. Concurrent multiple-client service is achieved above this primitive by `SYS_IPC_REPLY_TO`, which routes a server's reply to the request's kernel-recorded sender (used by `fs_server`); a richer multi-slot / parallel-worker IPC is still a follow-up. **Async notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) work**: `SYS_NOTIFY` ORs a 32-bit badge into a notification slot and wakes any task blocked on it (accumulating the badge otherwise); `SYS_WAIT_NOTIFY` consumes a pending badge or blocks via the same full-context path as IPC. Proven by `make smoke-notify`.

### Copy-on-write paging

The `PAGE_COW` flag and refcount infrastructure are in place, and the page-fault handler calls into Rust to decide demand-zero vs. COW-copy. The demand-zero path now genuinely works — until recently it did not, and could not: the pager reached freshly allocated frames through a virtual address that a user CR3 does not map, so it faulted inside itself and deadlocked on the `page_lock` it already held, and separately the heap sat in a window that is identity-mapped supervisor and therefore cannot be demand-paged at all. Both are fixed (see CHANGES.md), and a probe walking 640 KiB of heap now completes.

Demand-zero reads now resolve to a **single shared, read-only zero frame** marked `PAGE_COW`, so a task that reads a large sparse heap consumes one physical page rather than one per page touched. The first *write* breaks the sharing: the pager hands out a private zeroed frame, clears `PAGE_COW`, and preserves the address's NX bit. `make smoke-cow` exercises this from ring 3, asserting that fresh heap pages read as zero, that writing one page keeps its sibling zero, and that the two are mutually isolated afterwards. Note what that gates and what it does not: those assertions hold equally if the pager ignored the shared zero page and gave every fault a private frame, so `smoke-cow` gates the **user-visible contract**, not the sharing itself. That the sharing engages was confirmed by tracing the pager during development (one zero-page→private break per written page, and no more); gating it in CI would need kernel introspection the test deliberately does without.

One branch remains untested end-to-end. Breaking the *zero* page needs no copy (the copy of an all-zero frame is zeros), so it takes a special case and returns early — the generic COW path that decrements the refcount and duplicates real page content is still reached by nothing, because `fork` is a deliberate non-goal (see ROADMAP Phase 1) and nothing else in the tree shares a **non-zero** page. That branch is unit-tested in Rust only; treat it as untested code.

A dead task's address space is reclaimed when its slot is reused, not when it dies: `task_teardown` runs *before* `task_exit_switch`, so at teardown the dying task's CR3 may still be the one a CPU is walking, and freeing there would be a use-after-free of live page tables. The consequence is that a dead task's ~284 KiB is held until something spawns into its slot, which bounds the pool at `MAX_TASKS` x the per-task footprint (~18 MiB of 64) rather than releasing eagerly. Before this existed nothing was reclaimed at all — `free_user_physical_page` had no callers — and ~230 spawns exhausted the pool.

The shared zero frame is never freed: `free_user_physical_page` refuses it explicitly, and it is aliased by many PTEs whose refcounts are deliberately not tracked against it.

### Disk-backed storage (volume geometry)

`storage.c` implements encrypted block storage — a ChaCha20 + HMAC-SHA256 AEAD with per-block HKDF keys, fresh per-write nonce, `(ino, block)` as AAD — over a real superblock/inode/bitmap layout, exercised end-to-end by `fs_server` via the encrypted object-store syscalls. The live backend is selected at boot: a real ATA disk (`ata.c`, 28-bit-LBA PIO) when one is present, otherwise the ephemeral RAM vdisk. Cross-reboot persistence of files *and* their per-block crypto metadata is in place on ATA, multi-block updates are crash-atomic through a write-ahead redo journal replayed by a mount-time `fsck`, and files map through direct + single- + double-indirect blocks. The volume is **16 MiB** (32768 blocks): the data allocator uses a multi-block bitmap and the metadata rollback-HMAC is hierarchical so its per-write cost does not grow with the volume, and the RAM vdisk's backing store lives in the physical pool rather than `.bss`. Scaling much further (multi-GiB) would want the inode allocator made multi-block too and the crypto-metadata array bootstrapped from the pool rather than sized in `.bss`.

---

## What does not work / is not yet present

### SMP scheduler maturity

Multi-core is default-on (the shipped kernel runs across every core; `SMP=0` compiles it out). What is not yet done is *scheduler maturity*: the multi-core scheduler shares one runnable pool with a per-CPU pull, with no per-CPU run queues, no priorities or fairness, and no flush-on-switch between mutually distrusting tasks. Hardening the scheduler is Roadmap Track 3 (the flush-on-switch item is the security-relevant one — see the side-channel note below).

---

## Security limitations

These matter specifically for anyone evaluating Horus as a security system. The
July 2026 audit ([AUDIT-2026-07.md](AUDIT-2026-07.md)) added the first four items
below; remediation is tracked in [ROADMAP.md](ROADMAP.md) (Tracks 0–2).

### Capability revocation is descendant-only (audit A1 — fixed)

Revocation is transitive *downward*: revoking a capability nulls it and its derived
descendants. Previously the sweep matched an **object/badge/serial equivalence
set** — because a derived cap records its parent's serial in its `badge`, and the
sweep also matched shared `object`, revoking a delegated capability could
additionally null **the grantor's original** and **any same-object peer**. It failed
safe (removed access, never granted it) but broke the least-privilege-delegation
contract.

It now computes the target's exact **derivation subtree** (`revoke_subtree`): a
bounded worklist seeded with the target's serial, closed under "child (`badge`) of
an already-revoked serial", nulling exactly those. Ancestors, siblings, and
independent same-object capabilities survive. If a subtree ever exceeds the
worklist (`MAX_REVOKE_LINEAGE`, never in practice), a fail-safe fallback also nulls
every same-`object` cap — a complete superset — so no descendant can survive.
Regression-tested in `rust/src/capability.rs` and on real hardware by
`smoke-captest`.

### Capability grant now uses the locked write discipline (audit A2 — fixed)

`SYS_CAP_GRANT` previously performed a raw cspace store: the source was looked up
outside `cap_lock` and then written under it (an SMP race with a concurrent
revoke), the write was not accounted against the target's `caps_in_use` /
`MAX_CAPS_PER_TASK` ceiling, and it left a malformed lineage badge. It now routes
through `cap_grant_into`/`rust_cap_grant_into`, which does the source lookup and
destination store together under `cap_lock`, counts the write, masks rights to the
source's, and records a well-formed derivation-tree parent. (The audit's original
"reserved-slot floor" sub-point was withdrawn — grant legitimately endows a
dominated child's low slots, e.g. a server's IPC gate at slot 3.) A residual
follow-up is exposing the rights-reduction mask through the syscall ABI so grant
can drop `CAP_RIGHT_REVOKE` on delegation by default.

### Lineage-generation table is a lossy hash (audit A3)

Use-after-revoke is backed by a 4096-slot generation table keyed by a hash of the
capability's `object`. Distinct objects can collide into one slot, so bumping one
lineage can **spuriously invalidate a colliding object's live capabilities** at next
use. This is an availability effect (it fails safe) and undermines the precision the
"single source of truth" framing claims; the fix is per-object exact generation
storage (Roadmap Track 1).

### Boot modules are unsigned (audit A4 — content unverified; destination now constrained)

Programs and man pages that ship as GRUB multiboot2 modules are written into the
encrypted store as **root-owned executables** and run by the shell, trusted purely
by boot-chain provenance. There is still no per-module signature or hash manifest,
and the reproducible-build hash covers only the *embedded* binaries (`init`,
`shell`, `fs_server`, …), **not** the modules — so anyone able to alter the
ISO/GRUB config can inject an arbitrary root-owned binary into `/bin`. Verifying
module *content* in-kernel is planned (Roadmap Track 2.1, which records the
embedded-hash vs signed-manifest trade-off) as the precursor to measured boot.

The *destination* half is now closed: `module_dest_ok` (`fs_server.c`) constrains
where a module may land — only a bare name (→ `/bin`), a path under `bin/`, or one
under `usr/share/man/`; absolute paths and any empty, `.` or `..` component are
refused and the module is skipped with a log line. So a stray or tampered module
list can no longer plant a root-owned file outside the two intended trees, even
though its contents remain unverified.

### Development process is not yet high-assurance (audit P1–P5)

The audit's central finding was about the *process*, not the code. Much of it is
now closed: `main` **is** branch-protected (the four hard-gate checks are required,
the rule is enforced for administrators, force-push and deletion are blocked),
Dependabot alerts + security updates are on, and CodeQL scans the C kernel. What
remains: every PR is still **self-merged by a single maintainer** (no independent
review — required CODEOWNERS review is deliberately off, since with one maintainer
it would deadlock every merge), and the reproducible build is deterministic on one
runner image but the toolchain is unpinned and artifacts are unsigned. For a kernel
whose value is *verifiable* isolation, the build's integrity still rests on the
maintainer's workstation and an unattested toolchain. Remediation is
[Roadmap Track 0](ROADMAP.md) and is the highest priority. See
[../SECURITY.md](../SECURITY.md) → "Development process & governance."

### Encrypted storage is persistent, but still early

The block cipher is sound (ChaCha20 + HMAC-SHA256 AEAD, per-block HKDF subkeys, fresh per-write nonce), and on an attached ATA disk the store is the live backend with crypto metadata persisted across reboots (volume sealed until login), multi-block updates crash-atomic via a write-ahead redo journal, and per-file POSIX ownership/permissions enforced by the `fs_server` against the caller's kernel-attested identity. Residual limitations are operational rather than cryptographic: a diskless boot still uses the ephemeral RAM vdisk, and scaling the 16 MiB volume much further (multi-GiB) would want a multi-block inode allocator and the crypto-metadata array bootstrapped from the pool rather than sized in `.bss`. Fuller ACLs (beyond POSIX owner/group/other + a uid-0 superuser) are a deliberate non-goal.

### Audit log is tamper-evident, not tamper-proof

Edits, ring-slot swaps, replays, drops, and rollbacks are all *detectable* (including by an external monitor recording the chain head via `SYS_AUDIT_DIGEST`). The residual limitation is that this is a **detector**: an attacker who fully compromises the kernel and reads the per-boot pepper can recompute a self-consistent chain — the same accepted trust boundary as the user-database tag.

### Cache side-channel mitigation is partial

The timer preempts and switches between mutually distrusting ring-3 tasks (and, with SMP default-on, across cores), but there is no flush-on-switch or cache partitioning to limit microarchitectural leakage. What *is* mitigated: `CR4.TSD` is set (`cpu_enable_protections`, `crypto.c`), so a ring-3 `RDTSC`/`RDTSCP` — the highest-resolution timer a cache/covert-channel attack leans on — raises `#GP` and is delivered as a fault signal rather than returning a cycle count (ring 0 keeps `RDTSC`; TSD gates CPL>0 only, so the kernel's own jitter entropy is unaffected). This is deliberately *partial*: coarser timers and a counting-thread construction remain, and it does nothing about the cache state itself. `make smoke-tsd` gates that a ring-3 `RDTSC` faults into its handler. Flush-on-switch / partitioning is still open; tracked in `SECURITY.md`.

### Privilege separation is partial

The kernel is still largely one flat trust domain: most kernel code runs at the same privilege level with access to all kernel data, so a bug in an in-kernel driver has the same blast radius as one in the capability system.

The one exception — and the first to be carved out — is the **console**. The VGA/serial console driver now runs as a ring-3 server (`console_server`), holding only its own capabilities: it maps the framebuffer into its own address space, runs port I/O through a per-task TSS I/O-permission bitmap, and serves the shell's line input, echo, and password entry over IPC. A fault in it is contained as an ordinary ring-3 fault — proven by `make smoke-console-isolation` — so a console-driver bug can no longer reach kernel memory or the capability system. The remaining in-kernel drivers (block/ATA, the keyboard IRQ path) have not yet been separated, and a minimal in-kernel serial writer is deliberately retained for panic and early-boot output.

### Task kernel stacks and every IST fault stack are guarded

Each task's kernel stack sits above an unmapped guard page, so an overflow faults on the guard instead of running into the previous task's stack. This is gated by `make smoke-wx`, which checks the guard is absent *and* that the stack above it is still present — unmapping one page too many would take the stack with it.

It now covers **all `MAX_TASKS` task slots (task 0 included), plus the fixed BSP boot stack and the three boot IST fault stacks**. Task 0 — the kernel's own boot/idle/reaper task — was previously the exception: it kept a separate, 16-byte-aligned, unguarded `task0_kernel_stack`, while `per_task_kstacks[0]` sat allocated and unused. Task 0 now runs on that `per_task_kstacks[0]` (bound by `create_user_pagedir(0)`), so its stack has the same guard page every other task's does — the array lives in the 4 KiB-mapped kernel window, so slot 0's guard is unmappable like the rest.

The BSP boot stack (`stack_top`, the stack `kernel_main` and all early init run on) and the three IST fault stacks (`ist1`/`ist2`/`ist3` in `multiboot.S` — IST1 takes `#DF`/`#GP`/`#PF`, so it is on the path of every demand page fault and every ring-3 fault-signal delivery) are now each laid out above a page-aligned guard page that `kern_fixed_stack_guards_init()` unmaps at boot. `smoke-wx` asserts `MAX_TASKS` per-task guards, the four fixed-stack guards, and — for each — that the guard is absent while the stack just above it stays present.

The per-CPU **AP** IST fault stacks (`ap_ist` in `gdt.c`, SMP-only) are now guarded too: each of the three IST stacks per AP is laid out as a `[guard][stack]` two-page block, and `ap_ist_guards_init()` unmaps the guard at boot via the same `kern_arm_guard_page()` kernel-window clear the per-task and fixed guards use — armed before `smp_bringup()`, so each AP inherits the absent guard in its CR3 with no shootdown. `make smoke-wx-smp` (a `WX_SELFTEST=1 SMP=1` multi-core boot) asserts, for all `(MAX_CPUS-1) × 3` AP IST guards, that the guard is absent while the stack page above it is present. IST1 (#DF/#GP/#PF) is on the path of every demand page fault an AP-run task takes, so this is exercised, not just latent.

Still unguarded: only the dead early 32-bit boot stack (in the `.boot` stage, which is unmapped outright after boot). Every always-active stack — the BSP boot stack, the boot IST stacks, every task's kernel stack, and every AP's IST stacks — is now covered.

### No KASLR

The kernel image is linked at a fixed `KERNEL_VMA` (`0xFFFFFFFF80000000`) and loaded at a fixed physical 1 MiB, so its addresses are identical on every boot — the ASLR that exists is user-side only. This is not a small change and it is not merely undone work: `-mcmodel=kernel` lets GCC materialise symbol addresses as 32-bit sign-extended immediates, which is only valid in `[-2 GiB, +2 GiB)`, and `linker64.ld` explains at length why that pins the base. Real KASLR needs a relocatable kernel, or randomisation confined to whatever slack exists inside the -2 GiB window.

---

## Code quality notes

- Compilation success is not evidence of correct runtime behaviour; some paths are partial.
- Error codes are a shared, descriptive, errno-aligned `SYS_ERR_*` set (`include/errno.h`) used by both kernel and userspace, with `sys_strerror()`. The dispatcher and the auth / user-copy paths return specific codes; some deeper helpers still use ad-hoc small negatives.
- The Rust crate is named `horus_shell` for historical reasons; it is the security core (capabilities, memory refcounting, the SHA-2/BLAKE2b/Argon2id/KDF/AEAD/RNG primitives, FFI validation).
- `src/kernel/minimal_secure_stubs.c` supplies the stubs for the `MINIMAL_SECURE=1` build; it is build configuration, not security logic.
- **Tests:** 78 Rust unit tests (capability engine, memory/refcount trust boundary, RNG and SHA-2 family vs. published vectors, the ChaCha20+HMAC AEAD, the tamper-evident audit MAC/chain, BLAKE2b + Argon2id vs. RFC 7693 / `argon2-cffi` vectors, the W^X page policy, the signal-handler-address window, FFI validation). CI runs **41 jobs** (thirty-eight gating; the `security` SAST/SBOM scan is advisory and never blocks a merge) (`cargo test` + `clippy -D warnings`; kernel/ISO build; alt-config matrix; the headless QEMU self-tests — smoke-boot, the kernel W^X leaf sweep, the CR4 protections actually being set in CR4, the E820 pool sizing, ELF/W^X for both ELFCLASS32 and ELFCLASS64 images, preemption, signals, TSD, process-control, copy-on-write, image-base ASLR, async notifications, SMP, a scripted `smoke-session` integration test that drives the real ring-3 shell over serial, the filesystem/libc suite (fs, fs-perms, fs-conc, fs-persist, fs-wal, fs-large, init-fs, newlib), a capability/syscall conformance test asserting mostly on refusals (`smoke-captest`), and two GNU coreutils-via-the-filesystem tests -- `smoke-modules` ships `printf`/`tail` as GRUB boot modules, provisions them into `/bin`, and runs them from the store through the ring-3 shell, and `smoke-coreutils-shell` does the same for real `head`/`wc`/`seq` on real files; a reproducible-build check; and a security scan + SBOM). The scripted-session harness (`tools/session_test.py`) is a first, deliberately small integration test — broader scenarios (W^X violations, IPC/FS round-trips) and fuzzing are still ahead, as is automatic checking of the TLA+ specs in `docs/`.

---

## Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part of the project.

| Area | Estimate |
|---|---|
| Capability model (design and core implementation) | ~85% |
| Boot and hardware initialisation | ~85% |
| Process model (spawn/exec/kill/wait/signal, init) | ~85% (Phase 1 complete; mask + altstack + image exec) |
| Memory management | ~55% |
| Task scheduling | ~60% (preemptive; SMP default-on; shared run queue, no priorities) |
| IPC | ~45% (send/recv + blocking call + async notifications; single-slot) |
| Filesystem | ~75% (ring-3 server over encrypted store; persistent on ATA; per-file permissions, multi-client, crash-atomic journal, large files) |
| Cryptography (Argon2id/BLAKE2b + KDF/MAC/RNG + ChaCha20/HMAC AEAD) | ~80% |
| Storage / disk I/O | ~75% (ATA probe + persisted crypto metadata + crash-atomic journal; volume-size cap remains) |
| SMP | ~60% (default-on; shared run queue, no per-CPU queues/priorities, no flush-on-switch) |
| Testing | ~45% (78 unit tests + 41 CI jobs + 31 QEMU self-tests; no deeper integration/fuzz) |
