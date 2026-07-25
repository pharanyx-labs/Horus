# Horus — Current Limitations

An honest account of what Horus does and does not do, so no one draws incorrect conclusions about its readiness or security. This is a research and learning project, not a production OS. Where this document and the code disagree, the code is the source of truth — please open an issue.

---

## What actually works

- **Boot** — Multiboot2 via GRUB2 into x86-64 long mode, kernel linked into the higher half at `0xFFFFFFFF80000000`, ring-3 `init` (PID 1) launching the shell. A boot-time assertion checks it really is executing above `KERNEL_VMA` and that `virt_to_phys`/`phys_to_virt` round-trip (`HIGHHALF: PASS`).
- **Console + boot log** — an 80×50 VGA text grid mirrored to serial, PS/2 keyboard input, and a kernel message ring with Linux-style `[    S.mmm]` TSC-timestamped messages readable by root via the `dmesg` command / `SYS_DMESG` (uid 0 only). The driver runs as a **ring-3 server** (`console_server`): the shell's output and its line input (echo, masked password entry) go through it over IPC. The kernel keeps a minimal serial writer for panic/early boot and an in-kernel fallback reader.
- **Hardware isolation** — Ring 0/3 separation, per-task page tables, user/kernel split. SMEP/SMAP/UMIP enabled when advertised; `make smoke-cpu` boots under a CPU advertising all three and asserts each is in CR4 (they were silently off for the project's whole history — a stale CPUID leaf read zeros). With the kernel in the higher half, a user page directory holds only the task's own mappings, so a user mapping cannot shadow kernel state by construction.
- **Per-task x87/SSE context** — saved/restored around every ring-3 kernel entry; the kernel is `-mno-sse -mno-mmx -mno-80387` with no FPU state to leak. `make smoke-fs-conc`.
- **W^X for user memory and the kernel image** — `EFER.NXE` + PTE NX; user stacks non-executable, ELF `p_flags` honoured; kernel `.text` r-x, `.rodata` r-- NX, `.data`/`.bss` rw- NX, `CR0.WP` set. Gated by `make smoke-wx`, which asserts the per-section bits, checks `CR0.WP`/`EFER.NXE`, and sweeps every present leaf (~8,800) for a W+X mapping — the sweep, because every hole this kernel had was an alias, and it found the last one itself (LAPIC MMIO mapped W+X).
- **Stack guard pages** — every task kernel stack (task 0 included), the BSP boot stack, the boot IST fault stacks, and every AP's IST stacks sit above an unmapped guard page. `smoke-wx`/`smoke-wx-smp` assert the guard is absent and the stack above it present. Only the dead early 32-bit boot stack is uncovered.
- **Image-base ASLR (30 bits)** — a PIE image's load base is drawn from the CSPRNG across a 4 TiB window above 16 GiB (2³⁰ page-aligned positions), up from the old ~8.91 bits (which was the single-PD-entry premap shape, not a policy). Per-spawn stack top and heap gap randomised too. `make smoke-aslr` asserts 8 distinct high bases spanning > 1 GiB.
- **Capability mint / transfer / grant / revoke** — including transitive, **descendant-only** revocation across every cspace and the kernel root cnode, Kani-proved (audit A1). `SYS_CAP_GRANT` delegates one slot from a supervisor into a child, through the locked/accounted/rights-masked path (audit A2).
- **Lineage tracking** — use-after-revoke prevented via per-serial generation counters (finding 3.3), snapshot + revalidate-at-use wired into the IPC paths.
- **FFI integrity** — C `capability_t` and Rust `Capability` layouts pinned by mirrored compile-time assertions; the refcount table registered once, every later inc/dec must present the exact (pointer, length).
- **User authentication** — login, lockout + anti-spray throttle, per-user UID, Argon2id hashing; password changes persist across reboots.
- **Forward-secure audit log** — each entry HMAC'd (binding its sequence) under a per-entry key ratcheted one-way and erased, so pre-compromise history is unforgeable; a chain head commits to the whole ordered history (`audit.rs`); `SYS_AUDIT_DIGEST` returns the digest + a key-free retained-window self-check.
- **Preemptive scheduling** — PIT at 100 Hz preempts ring-3 tasks via a full-context kernel-stack switch; a tick in ring 0 never switches. `make smoke-preempt`. Blocking (`SYS_IPC_CALL`, `SYS_WAIT`), `SYS_YIELD`, first entry, and boot of `init` all use the same trap-frame path; the legacy cooperative switch is removed.
- **Flush-on-switch** — on a switch to a different ring-3 task the scheduler evicts IBPB / L1D / MDS state, each CPUID-gated (`cpu_flush_microarch_state`). `make smoke-flush`.
- **Ring-3 process control** — `SYS_SPAWN` (+ `CAP_TCB`), `SYS_EXEC_NAMED`/`_IMAGE`, `SYS_CAP_GRANT`, `SYS_EXIT`/`SYS_KILL`, `SYS_WAIT`. `make smoke-proc`.
- **`init` supervision** — a ring-3 PID 1 spawns, endows, and blocking-supervises the console server and the shell, relaunching on exit or fault.
- **Fault + async signals** — a task registers its own handler (`SYS_SIGACTION`); a ring-3 fault is delivered to it (`SYS_SIGRETURN` resumes exactly), and `SYS_SIGNAL` (`CAP_TCB`-gated) queues an async signal. Full 1..31 pending bitmask, `SYS_SIGMASK`, `SYS_SIGALTSTACK`. `make smoke-signal` / `smoke-proc`.
- **SMP (default-on)** — AP bringup (LAPIC INIT-SIPI-SIPI, count from the ACPI MADT), per-CPU LAPIC-timer ticks over a shared runnable pool, IPC/notification locking, acknowledged TLB-shootdown IPIs, and **SMT parked in software**. `make smoke-smp` / `smoke-smt`. `SMP=0` compiles it out.
- **Filesystem server** — a ring-3 `fs_server` over the kernel's encrypted object store, the system's single filesystem and its reference monitor: per-file POSIX rwx against the caller's kernel-attested uid/gid (`SYS_IPC_SENDER`), multi-client concurrency (`SYS_IPC_REPLY_TO`), crash-atomic via a write-ahead journal + mount-time `fsck`, large files via double-indirect blocks. `smoke-fs`, `-perms`, `-conc`, `-wal`, `-large`.
- **Persistent encrypted storage** — boot probes for an ATA disk (bounded probe) and uses the encrypted store when present (per-block nonces/tags flushed on write, reloaded + HMAC-verified at mount, volume mounted-but-locked until login, Argon2id-derived KEK; TPM-sealed KEK on a TPM-formatted volume). Diskless boots fall back to an ephemeral RAM vdisk. `smoke-fs-persist`.
- **Measured boot + TPM sealing** — a TPM 2.0 TIS driver extends the reproducible boot hash chain (`PCR[8]` kernel identity, `PCR[9]` each verified module); a TPM-formatted volume's disk KEK is sealed under `PolicyPCR` and released only by a measured-good boot. `smoke-tpm{,-tamper,-seal,-seal-roundtrip}`.
- **Userspace runtime + libc** — ring-3 tasks are 64-bit static-PIE, demand-paged heap (`sbrk`/`brk`), userspace `malloc`, an `x86_64-elf` newlib port over a per-process POSIX fd layer (`smoke-newlib`). The libc surface (open/read/write/close/lseek, stat/fstat, unlink/rename/ftruncate, opendir/readdir, chdir/getcwd, fcntl, mkstemp, kill(), link(), tmpfile()) is complete enough for a coreutils/binutils port; the constraint is now program *size*, not the C library, and both former size caps are lifted (`staged_image_span_pages()` sizes the premap; `loader_staging` moved off `.bss` into the pool, so `MAX_PROGRAM_SIZE` is 8 MiB). `smoke-newlib` loads a ~1.5 MiB image.
- **Shell pipelines** — bounded in-kernel pipes (`SYS_PIPE*`) with EAGAIN + yield back-pressure; the shell wires a child's stdin/stdout to pipe ends at spawn, `SYS_STDIO_INFO` lets `posix_init` learn which fd is a pipe. `make smoke-pipe`.
- **Reproducible builds** — `make reproducible-build` yields a byte-for-byte identical `kernel.elf` across clean builds.

---

## Partial implementations

### Userspace shell

Accepts input and dispatches commands; several are end-to-end, others parse arguments but do little — coverage is uneven. The presentation layer is deliberate: `ls` sorts and columns entries and marks directories/executables; `ls -l`/`stat`/`ps` print aligned tables. **No ANSI colour is used** — the console is a VGA text grid mirrored to serial and the driver does not interpret escapes. The shell carries its own manual (`man`/`whatis`/`apropos`) whose pages live in the binary, so it works before any filesystem is mounted; when coreutils ship as GRUB modules (`COREUTILS_MODULES=1`) the shell runs them by name from `/bin`, and a `/bin/<name>` shadows the lighter builtin. Pipelines connect stages over in-kernel pipes.

### IPC

The endpoint `send`/`recv` cycle works (256-byte messages, capability-gated). `SYS_IPC_SEND`/`RECV` are **non-blocking** (return −2; the caller polls); `SYS_IPC_CALL` can block on the full-context path. Each endpoint is a **single-slot mailbox**, so it serves one in-flight request at a time; concurrent multi-client service is achieved above it by `SYS_IPC_REPLY_TO` (used by `fs_server`), but a richer multi-slot / parallel-worker IPC is still a follow-up. Async notifications work (`smoke-notify`). Pipes (above) are a separate bounded-byte-stream primitive.

### Copy-on-write paging

`PAGE_COW` + refcounts are in place and the pager decides demand-zero vs COW-copy in Rust. Demand-zero reads resolve to a **single shared read-only zero frame**, so a large sparse heap costs one physical page; the first write breaks sharing (private zeroed frame, `PAGE_COW` cleared, NX preserved). `make smoke-cow` exercises the user-visible contract from ring 3 (note: those assertions hold even if the pager gave every fault a private frame, so `smoke-cow` gates the contract, not the sharing — the sharing was confirmed by tracing during development). The **generic non-zero** break path (copy on refcount ≥ 2, upgrade in place when sole owner) is factored into `cow_break_pte` and driven end-to-end by `make smoke-nzcow`; it is reached by no runtime caller (`fork` is a non-goal), was therefore previously untested, and carried two latent bugs — a sole-owner infinite fault loop and a per-break refcount leak — both fixed. A dead task's address space is reclaimed when its slot is reused (teardown runs before the exit switch, so freeing eagerly would be a use-after-free of live page tables); the shared zero frame is never freed.

### Disk-backed storage (volume geometry)

`storage.c` implements encrypted block storage (ChaCha20 + HMAC-SHA256 AEAD, per-block HKDF keys, fresh per-write nonce, `(ino, block)` AAD) over a real superblock/inode/bitmap layout, with the live backend selected at boot (ATA when present, else the RAM vdisk). Cross-reboot persistence of files *and* crypto metadata, crash-atomic multi-block updates, and direct + single- + double-indirect blocks are all in place. The volume is **16 MiB** (32768 blocks): a multi-block data bitmap and a hierarchical metadata rollback-HMAC keep the per-write cost flat, and the vdisk's backing store lives in the pool rather than `.bss`. Scaling much further (multi-GiB) wants the inode allocator made multi-block and the crypto-metadata array bootstrapped from the pool.

---

## What is not yet present

### SMP scheduler performance maturity

Multi-core is default-on. The two **security**-relevant items are done — **flush-on-switch** (IBPB / L1D / MDS between distrusting tasks) and **SMT co-residency** (sibling threads parked at AP bringup: TLB-coherent, service shootdown IPIs, never run a task; `smp: N cores online, K SMT siblings parked`; `make smoke-smt`). What remains is *performance/quality*: the multi-core scheduler still shares one runnable pool with a per-CPU pull under a single raw lock (no per-CPU run queues), and has no priorities, fairness, or affinity. That is Roadmap Track 3.

### No KASLR

The kernel is linked at a fixed `KERNEL_VMA` and loaded at a fixed physical 1 MiB, so its addresses are identical every boot — the ASLR that exists is user-side only. This is not merely undone work: `-mcmodel=kernel` materialises symbol addresses as 32-bit sign-extended immediates, valid only in `[−2 GiB, +2 GiB)`, which pins the base. Real KASLR needs a relocatable kernel or randomisation confined to the slack in the −2 GiB window.

---

## Security limitations (for anyone evaluating Horus as a security system)

The July 2026 audit ([AUDIT-2026-07.md](AUDIT-2026-07.md)) drove the first four; remediation is tracked in [ROADMAP.md](ROADMAP.md).

- **Capability revocation is descendant-only (A1 — fixed).** Nulls the target's exact derivation subtree, not ancestors/siblings/same-object peers; a fail-safe object-sweep fallback preserves completeness for the never-in-practice oversized subtree. Regression-tested in `capability.rs` and by `smoke-captest`; Kani-proved.
- **Capability grant uses the locked write discipline (A2 — fixed).** `cap_grant_into` does source lookup + store under `cap_lock`, counts the write, masks rights, records a well-formed parent. Residual: expose rights-reduction through the ABI so grant can drop `CAP_RIGHT_REVOKE` by default.
- **Lineage-generation table is a lossy hash (A3; keyed by `serial` per finding 3.3).** Now active and precise (serial-keyed, strict-equality, no gen-0 escape). Residual: distinct serials can collide into one 4096-slot cell, so bumping one lineage can spuriously invalidate a colliding serial's live caps at next use — availability-only, fails safe. Fix: exact per-serial storage (Track 1). Proved over the whole `u32` space by two Kani harnesses.
- **Boot modules: content verified, manifest in the kernel image (A4 — fixed).** A SHA-256 manifest of the shipped modules is embedded and each is hashed at boot; a mismatch is refused at the syscall choke point (`SYS_ERR_PERM`), with a `/bin`+`/usr/share/man` destination allowlist. `make smoke-modules-tamper`. Residual: this protects the module *payload*, not the *kernel image* itself — closing that needs the pinned, attested, signed build of Track 0.4 and measured boot (already present for the boot chain, Track 2.2).
- **Development process is not yet high-assurance (P1–P5).** `main` is branch-protected (four hard-gate checks required, enforced for admins, force-push/deletion blocked), Dependabot + CodeQL are on. Open: every PR is still **self-merged by a single maintainer** (no independent review; required CODEOWNERS review is deliberately off since with one maintainer it would deadlock), and the reproducible build is deterministic on one runner image but the toolchain is unpinned and artifacts unsigned. Highest priority — Track 0. See [../SECURITY.md](../SECURITY.md).
- **Encrypted storage is persistent but early.** Cryptographically sound; residual limits are operational (diskless boots use the RAM vdisk; scaling the 16 MiB volume much further wants a multi-block inode allocator). Fuller ACLs beyond POSIX + a uid-0 superuser are a deliberate non-goal.
- **Audit log is forward-secure (tamper-proof for pre-compromise history).** A kernel compromised at time _t_ cannot forge any entry committed before _t_; the external monitor verifies via the chain head. Residual — the honest ceiling for a self-hosting kernel: entries logged *after* the compromise, and whole-machine rollback, need an **external append-only anchor** (a TPM NV monotonic counter / periodic PCR-extend of the head — the TPM is already present — or a remote WORM sink). "Completely tamper-proof" is not achievable inside the same trust domain as the attacker.
- **Cache side-channel mitigation is partial.** `CR4.TSD` disables ring-3 `RDTSC` (`smoke-tsd`); flush-on-switch evicts IBPB / L1D / MDS on the time-slice boundary (`smoke-flush`); SMT parking closes concurrent co-residency (`smoke-smt`). Residual: **cache partitioning** is not done (the primary thread's own successive tasks share a warmed cache between the flush and the next eviction), and coarser timers / counting-thread constructions remain.
- **Privilege separation is partial.** The kernel is still largely one flat trust domain. The one exception carved out is the **console** (`console_server`, ring-3, contained fault — `smoke-console-isolation`); the block/ATA and keyboard-IRQ paths have not yet followed, and a minimal in-kernel serial writer is deliberately retained for panic/early boot.

---

## Code quality notes

- Compilation success is not evidence of correct runtime behaviour; some paths are partial.
- Error codes are a shared, errno-aligned `SYS_ERR_*` set (`include/errno.h`) with `sys_strerror()`; some deeper helpers still use ad-hoc small negatives.
- The Rust crate is named `horus_shell` for historical reasons; it is the security core.
- `src/kernel/minimal_secure_stubs.c` supplies the `MINIMAL_SECURE=1` stubs — build configuration, not security logic.
- **Tests:** 91 Rust unit tests (capability engine, memory/refcount trust boundary, RNG/SHA-2 vs vectors, the ChaCha20+HMAC AEAD, the forward-secure audit MAC/chain, BLAKE2b + Argon2id vs RFC 7693 / `argon2-cffi` vectors, the W^X page policy, the signal-handler window, FFI validation) + machine-checked Kani proofs. CI runs **52 jobs** (three advisory: `security` SAST/SBOM, `fuzz`, `kani`), including ~45 headless QEMU self-tests. Deeper integration scenarios and broader fuzzing are still ahead, as is automatic checking of the TLA+ specs in `docs/`.

---

## Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part.

| Area | Estimate |
|---|---|
| Capability model | ~85% (design + core impl; A1/A2/A3 addressed) |
| Boot and hardware init | ~85% |
| Process model (spawn/exec/kill/wait/signal, init) | ~85% |
| Memory management | ~55% |
| Task scheduling | ~65% (preemptive; SMP default-on; flush-on-switch + SMT done; shared run queue, no priorities) |
| IPC | ~50% (send/recv + blocking call + notifications + pipes; single-slot endpoints) |
| Filesystem | ~75% (ring-3 server; persistent on ATA; per-file permissions, multi-client, crash-atomic, large files) |
| Cryptography | ~80% |
| Storage / disk I/O | ~75% (ATA probe + persisted crypto metadata + journal; volume-size cap remains) |
| SMP | ~65% (default-on; flush-on-switch + SMT parking done; shared run queue, no per-CPU queues/priorities) |
| Measured boot / TPM | ~70% (measured boot + sealed KEK; no remote attestation) |
| Testing | ~50% (91 unit tests + 52 CI jobs + ~45 QEMU self-tests; no deep integration/fuzz) |
