# Horus security and efficiency audit, 2026-09-19

**Scope.** The whole tree, prompted by a build that failed on the maintainer's machine while CI
stayed green. The build defect is fixed; the review then widened to the security and efficiency
questions the failure raised. This audit is deep on the paths a hostile ring-3 task or a hostile
program image reaches first, and mechanical (grep, checker, one measurement) on the rest. Section
2 states the coverage honestly, subsystem by subsystem, so a reader knows what was read closely
and what was only swept.

**Method.** Read against the local checkout at `dfb57ec` as the source of truth, never against the
documentation. Every behavioural finding demonstrated on a boot or a build with `DEFECT FLAGS`
read off the wire, or by a checker that reproduces it. Every number re-derived by running the tool
that derives it. `gcc -fanalyzer` was run over every `src/kernel/*.c` under the kernel's own
flags, after confirming it reports a planted null-dereference and use-of-uninitialised value in
that same configuration, so its empty result is evidence and not a silenced analyser.

**Baseline.** `dfb57ec`, the branch tip carrying the build fix (PR #400). The predecessor is
[`docs/history/AUDIT-2026-08-30.md`](history/AUDIT-2026-08-30.md), which this supersedes in status,
not in findings: the IDs it established keep their meaning and their current status is in
[`LIMITATIONS.md`](LIMITATIONS.md), which stays authoritative.

---

## 1. Why this audit exists

`make` failed on the maintainer's Void Linux machine at the final kernel link, with
`linker64.ld`'s assertion that `.bss` had overrun `USER_PHYS_BASE`. `.bss` was innocent. The
overrun was in `.rodata`, and it was 128 MiB of it, in a single embedded blob that should have
been 270 bytes. Every required check on CI was green at the same commit.

That gap, a defect that is total on one toolchain and invisible on another, is the kind an audit
exists to close, so the review took it as the thread to pull. The finding is F1 below. What it
opened onto, a copy into low physical memory bounded by nothing but a symbol difference, is the
reason it is rated Critical rather than a build annoyance.

---

## 2. What was covered, and how closely

| Area | Depth | Result |
|---|---|---|
| AP trampoline link and SMP bring-up copy | close read | **F1**, fixed |
| User-copy boundary (`user_copy`, `copy_{from,to}_user`, `paging.c`) | close read | robust |
| User address-space construction (`create_user_pagedir`) | close read | robust |
| Physical allocator and refcounted free (`paging.c`, `untyped.c`) | close read | **F3** (hardening, closed 2026-09-21), else robust |
| Capability core and FFI (`rust/src/capability.rs`, `capability.c`) | close read | robust |
| Revocation subtree, and the §1.14 stdio-pipe root | close read | §1.14 confirmed still accurate |
| Syscall ABI and dispatch (`syscall.c`, `include/syscall.h`) | close read | robust |
| ELF loader and load-plan validation (`rust/src/lib.rs`) | close read | robust |
| Build and CI TCB (action pinning, token scopes, deps, newlib pin) | mechanical | robust |
| Memory footprint (`.bss`/`.rodata` top objects, headroom) | measured | **F2**, closed |
| Syscall-dispatch efficiency | static | O(1) table, robust |
| IPC/endpoints/notifications, storage-at-rest, crypto, TPM, measured boot, MSI/IOAPIC, `ahci`/`sdhci`, the ring-3 servers | swept, not close-read | no finding; **not cleared** |

The audit's own tally, gated with the rest:

| Tally | Count |
|---|---|
| Candidates investigated and **rejected** | **4** |

The last row is the honest limit of this pass: those subsystems were swept for the shapes this
audit was chasing and nothing surfaced, but they did not get the line-by-line read the rows above
did. They are not asserted clean. This differs from the 2026-08-30 audit, which read the whole
tree; naming the difference is the point of the table.

---

## 3. Findings

### 3.1 The kernel image depended on the host assembler's defaults, *Critical*, **fixed in PR #400**, **[F1]**

`src/boot/ap_trampoline.bin` was linked with `ld -m elf_i386 -Ttext=0x8000 --oformat binary`.
`-Ttext` places `.text` and leaves every other allocated section to the default i386 script. Void's
binutils 2.44 assembler emits a `.note.gnu.property` by default; the default script placed it at
0x080480d4, and `--oformat binary` wrote a flat image spanning everything from 0x8000 to the note,
134,479,912 bytes. `multiboot.S` embeds that in `.rodata`, and only `linker64.ld`'s unrelated
`.bss` assertion stopped the build. Ubuntu's binutils emits no note, so CI never saw it.

Behind the build failure was the memory-safety half: `smp_start_aps` copies
`ap_trampoline_end - ap_trampoline_start` bytes to physical 0x8000, bounded by nothing, and the
blob shares its page with the cells the BSP writes from 0x8FD8. A blob a few KiB too large, rather
than 128 MiB, would have linked and been copied over its own cells and on into low memory at
bring-up.

Fixed by a dedicated `src/boot/ap_trampoline.ld` (everything at 0x8000, notes discarded, end
asserted below 0x8FD8), an assemble-time bound in `src/boot/ap_trampoline_embed.S` on the bytes
actually embedded, a runtime bound in `smp_start_aps`, and note-stripping on the flat self-test
payloads, which had the same latent dependence. Witness `make smoke-ap-trampoline`, which forces
the note on so CI tests the case its own toolchain never produces; falsified by
`make smoke-ap-trampoline-control`.

### 3.2 The kernel `.bss` headroom is one buffer deep, *Low*, **closed 2026-09-19**, **[F2]**

After the fix, `.bss` ends 0x74a000 (7.29 MiB) below `USER_PHYS_BASE`. The single largest static
is `argon2_scratch` at 4 MiB, over half the remaining room. That 4 MiB is a deliberate
memory-hardness parameter (`ARGON2_M_COST_KIB = 4096`) and must not be trimmed to buy headroom,
that would weaken password hashing. The observation is that the linker assertion F1 relied on is
closer to firing than the numbers suggest: a routine bump to `MAX_TASKS`, `BLOCKS_PER_DISK`, or the
argon2 cost collides the image with the page pool. Recommended: declare the headroom as a
doc-claim so the next bump is caught in review, and note in `LIMITATIONS.md` §3.1 that the argon2
buffer is the dominant `.bss` term. No code change.

**Closed, with a checker rather than a doc-claim alone.** `tools/check_doc_claims.py` derives every
value statically and never builds, so it cannot read a figure that exists only in the linked ELF.
The budget therefore lives in `.github/image-budget.yml`, and `tools/check_image_budget.py` holds
the default build's `.bss` to it exactly, in both directions, in CI's `kernel` job; the doc-claim
the recommendation asked for then reads the budget file. The budget is on `.bss` and not on the end
of the image because the end is not a property of the source: the same tree ended at 0x8B4000 on CI
and at 0x8B7000 on Void, while `.bss` was 0x6E3000 on both. The checker also ties `linker64.ld`'s
16 MiB literal to `USER_PHYS_BASE`, which the two files had kept in step only by a comment. Working
this finding also turned up **HORUS-20260919-02**, a verified boot module that could change after
its hash was taken, fixed in PR #402 (`LIMITATIONS.md` 1.15).

### 3.3 The physical free path is safe only by its callers' discipline, *Low*, closed 2026-09-22, **[F3]**

**Closed** as **S102** (`LIMITATIONS.md` 2.5a): the free path now refuses any frame that is not out on
loan, tracked by a separate bitmap, because the refcount check recommended below cannot tell a
first free from a second (tables are freed at count one, leaves at zero).

`free_user_physical_page` bounds the refcount index it clears, but pushes the frame onto
`free_page_stack` guarded only by the stack not being full: no range check on the value, no
double-free check. It is safe today because every caller frees a leaf only through
`user_leaf_release`, which frees on an exact refcount of zero, and frees table pages that are never
aliased. That is the "by remembering" pattern the project prefers to replace with "by
construction" (`§1` of `CLAUDE.md`). Recommended: a cheap in-function guard (index in range, and
the frame not already at count zero) so the function fails closed if a future caller reaches it
without the refcount. No live defect: the refcount prevents the double-free upstream.

---

## 4. Confirmations

Recorded so the coverage is honest, not to claim more than was read.

- **The user-copy boundary carries S7 and S24 as documented.** The software page-walk requires
  `PAGE_USER` per page, refuses an absent page rather than paging it in (the #176 lesson), breaks
  COW before a kernel write, and refuses a length above `USER_MEM_MAX_COPY` rather than clamping
  it (the [C-4] lesson). Canonical-address and wrap checks are present.
- **The capability FFI validates its own inputs.** Every `unsafe extern "C"` in
  `rust/src/capability.rs` null-checks and bounds-checks, keys validity on strict generation
  equality (the 3.3 backstop), and carries a `# Safety` clause the `unsafe-safety` job enforces.
  Revocation sweeps the derivation subtree only, leaving ancestors and same-object peers intact.
- **`§1.14` is still accurate.** `cap_install_child_pipe_end` sets the child pipe end's
  `badge = 0`, and `revoke_subtree` skips `badge == 0`, exactly as the limitation records. The
  path is otherwise careful: the source is looked up under `cap_lock` with a lineage check.
- **The build and CI TCB is hardened.** All 134 external action references are pinned by commit
  SHA; `ci.yml` is read-only at the top level with no per-job write override; only `pages.yml`
  (`id-token`) and `codeql.yml` (`security-events`) carry the one write each needs. The Rust
  security core has zero external dependencies, and newlib is SHA256-pinned and verified on every
  invocation.
- **The ELF loader is safe-Rust.** Header and program-header validation compute offsets in u64,
  read through bounds-checked slices, and reject each malformation with its own code. The privileged
  `copy_to_user` runs only from the validated plan.
- **Syscall dispatch is O(1) and gated declaratively.** The dispatch is a designated-initialiser
  array `[SYS_X] = { handler, cap_slot, rights, type }`, so the capability gate is data, not a
  per-handler check to remember.

---

## 5. Candidates rejected

An audit that reports only what it confirmed is not showing its work. **4 leads were investigated and rejected**, each recorded so the next audit does not re-raise it. The count is derived from the table below, not typed, and kept on one line because `tools/check_doc_claims.py` matches line by line.

| Candidate | Why it is not a finding |
|---|---|
| `argon2_scratch` is 4 MiB of static `.bss`, half the pool headroom | It is the argon2 `m_cost` (4096 KiB), a memory-hardness parameter. Shrinking it to buy headroom would weaken offline-dictionary resistance. The footprint is real (F2), the buffer is not waste. |
| Syscall wrappers cast a length argument to `uint32_t`, the same shape as the #176 pointer truncation | A length, not a pointer. `check_syscall_abi.py` proves no pointer narrows. The kernel re-bounds every length by a scratch buffer or `USER_MEM_MAX_COPY`, so a truncated length can only shorten a copy, never overrun. |
| `free_user_physical_page` pushes to the free stack with no double-free guard | Every caller frees a leaf only through the exact-zero refcount, and table pages are never aliased, so the double-free is not reachable. Recorded as a hardening note (F3), not a live defect. |
| `user_copy` switches to the kernel CR3 and back inside the copy | The save and restore are correct, bracketed by `cli` with the interrupt flag preserved and restored, so there is no window in which a user address is walked on the wrong CR3. |

---

## 6. What was measured

**The kernel `.bss` and `.rodata` top objects, and the headroom under `USER_PHYS_BASE`.** Read
from the built `kernel.elf` with `nm -S --size-sort`: `argon2_scratch` 4096 KiB, `referenced.2`
and `free_page_stack` 512 KiB each, `endpoints` 335 KiB, `ap_idle_stacks` 272 KiB,
`page_refcounts` 256 KiB. `__bss_end` sits 0x74a000 below `USER_PHYS_BASE`. This is F2's evidence,
and the argon2-heavy shape is why F2 recommends a doc-claim on the figure.

**The base-gate reddening sweep, for the one gate this audit added.**
`tools/check_base_gate_reddens.sh AP_TRAMPOLINE_FLAT_LINK` reports the base gate goes red under the
flag (RED, 1 of 1), the direction a control arm alone does not establish.

Efficiency measurement stopped there. The hot-path timings the plan named (syscall entry, IPC
round trip, page alloc under contention) were not taken this pass; the dispatch and allocator were
reviewed statically and found O(1) and refcounted respectively, but a TSC measurement under load is
outstanding.

---

## 7. Process findings, unchanged

**[C-5] No independent review.** *Critical (process)*, open. Every security-critical path here has
been modified by one person, and this audit was performed by a tool the same person directed. It
is not a substitute for outside review.

**[C-6] Ruleset reconciliation lags a merge.** *High (process)*, open at this audit and **fixed
2026-09-21** (`LIMITATIONS.md` 5.2): the ruleset now requires one aggregated check from `ci.yml`,
whose `needs:` is proved equal to the gating classification in the PR itself, so a new gate no
longer waits on a hand sync. F1's CI witness was added as two steps inside the existing
`reproducible` job, before that, precisely so it needed no ruleset change.

---

## 8. Assurance statement

This audit found one Critical defect and fixed it, made two low-severity hardening
recommendations, and confirmed that the boundaries it read closely enforce the properties they
claim.

- The Critical defect was not in the capability model. It was in the build, where the kernel image
  had come to depend on a host toolchain default, with a latent low-memory copy behind it. It is
  fixed, gated, and the gate is falsified in both directions.
- Every security boundary read closely, the user-copy path, the capability core, revocation, the
  ELF loader, held to the standard the rest of the tree sets. F2 and F3 are both closed; F3 was
  defence-in-depth, not a hole.
- The build and CI TCB is in good order: actions pinned, tokens minimal, no external Rust
  dependency, newlib hash-anchored.
- The coverage is partial and section 2 says where. IPC internals, storage-at-rest, measured boot,
  the interrupt path and the ring-3 servers were swept, not cleared, and a hot-path measurement is
  outstanding. A second pass should close those before this audit is read as tree-wide.

Nothing here is a reason to trust the system more than `README.md` already says. The property
claims that were checked are, as far as this pass could determine, true; the build no longer keeps
a secret from CI; and the areas not yet read closely are named rather than implied.
