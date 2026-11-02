# Horus security assessment, 2 November 2026

**Assessed tree.** `e3aa595` on `main` (`ci(deps): bump the github-actions group with 2 updates`, pull request 608).

**Classification.** Research-system assessment. This is not an independent review, not a penetration test, and not a production clearance. Horus has had no independent human audit. The honest claim the project already makes is thorough automatic verification.

**Author.** A reading of the local clone, directed by the maintainer's session. The same limit as every previous self-audit applies: one maintainer, and the model that writes most of the code, reading the tree that model produced. [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) 5.1 remains the status of that fact.

**Status of findings.** [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) is the single status of every known finding. This report does not open a second status. New observations are recommendations. They do not close, reopen, or rename an entry.

---

## 1. Executive summary

Horus at this commit is an early research microkernel with a capability check on the shipped syscall path and a verification harness that is further along than the operating system. It boots under QEMU and on the hardware the register names. It installs onto IDE and onto SD or eMMC. It is not something to trust with data that cannot be lost.

The risk that should decide use is not a newly missed decoy slot. It is the set the register already publishes:

| ID | Why it still dominates |
|---|---|
| 5.1 [C-5] | No human reads a change before it merges. |
| 5.4 [HORUS-20260920-03] | The cryptography is from-scratch `no_std` Rust. It is unaudited, and it is not verified constant-time. |
| 1.23 | `SYS_SPAWN_IMAGE` runs bytes the caller already holds. `EXEC` does not stop that. |
| 1.24 and 1.26 | Below a session root, `fs_server` is the reference monitor. The kernel bounds the union of the grants. |
| 2.9, 2.9a, 1.12 | Measured boot and rollback anchoring fail open unless the build, or a TPM, says otherwise. |
| 2.12 | Without an IOMMU, a bus-mastering device is not confined. The boot says so. |
| 2.3 and 2.5 | Destroying a retyped object frees the name. The bytes are not reused. A long run exhausts the region. |
| 5.3 [I-9] | Releases are unsigned and carry no provenance. |
| 5.5 | Proofs cover the Rust core's algebraic checks. They do not cover the kernel. |
| G-14 | The filesystem, the accounts and the loader still run in ring 0. See section 5. |

This pass found no new way for an unprivileged ring-3 task to mint authority the ship kernel does not already refuse. `tools/check_dispatch_gates.py`, run on this commit, reports that every slot-3 gate in the dispatch table is compiled in only under a defect flag. That is the property S79.

Three defects in the record were found. None of them changes what the ship kernel does. Each one can make a later reader, or a later edit, trust the wrong sentence.

| ID | Severity | Where | What is wrong |
|---|---|---|---|
| R1 | Medium (assurance) | `site/limitations.html` | The page says every gate has a control arm. Ten property rows do not. S1, the central dispatch claim, is one of them. |
| R2 | Low (audit trail) | `syscall.c`, `syscall_ipc.c`, `syscall_fs.c`, `loader.c` | Comments still describe the withdrawn slot-3 decoy as the live gate, and one still says the task table is a `.bss` array waiting on a closed roadmap item. |
| R3 | Low (status) | `docs/LIMITATIONS.md` | Architectural gap G-14 is open in `docs/ARCHITECTURE.md` and was not an entry in the register. The register is the status of a finding. |

A wholesale rewrite of `SECURITY.md`, `docs/LIMITATIONS.md` and the site was considered and refused. Those texts were rewritten on 1 November 2026 (pull request 601). On this commit the doc-claim checker, the prose checker, the invariant checker and the positive-boot census all pass. Replacing a machine-checked table with a paraphrase would either drop a witness binding or invent a claim. The corrections that the code supports are small, and they are prepared beside this report rather than folded into it.

What this pass did not do: boot QEMU, run `make smoke` or `make smoke-captest`, or re-prove the Kani harnesses. A reading of a gate is not the gate. Section 3 says exactly what was run.

## 2. Scope

In scope:

- The capability model and the shipped syscall dispatch table (`src/kernel/syscall.c`).
- The trusted computing base as the project defines it: the kernel (`src/kernel/`, `src/boot/`, `rust/src/`), `init`, `fs_server` and `console_server`.
- Boot measurement and the fail-open path (`tpm_measured_boot`, `measured_boot_unavailable`).
- The cryptographic use the register names: the AEAD tag compare and the password compare.
- Isolation claims already witnessed: per-task page tables, user copies, W^X, the flush on switch, SMT parking, the IOMMU where firmware provides one.
- Process security: review, provenance, action pinning, and the gating classification.
- The public documents and `site/`, against the code and against the register.
- Dead or misleading comments on the dispatch path.

Out of scope for this pass:

- A line-by-line re-read of every driver, which the 19 September 2026 audit (`docs/AUDIT.md`) already marked as swept and not cleared. That limit still holds. This pass did not clear `ahci`, the SD host, or the ring-3 storage servers beyond the properties the register and the dispatch table state.
- Exploit development, proof-of-concept code, and reproduction steps. Findings are names, impacts and dispositions.
- New roadmap items. The order of work stays [`docs/ROADMAP.md`](docs/ROADMAP.md). This report does not start 4.17, 5.6, 5.7, 5.9 or 5.15.
- History under `docs/history/` and `docs/investigations/`. Those files are a record of what was true on the day they were written. Their current status is the register.

## 3. Method

1. Read the register, `SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/AUDIT.md`, the site, and the dispatch table, against commit `e3aa595`.
2. Re-derived the census rather than trusting the prose. On this commit:

   - `tools/check_doc_claims.py` passes (58 numeric occurrences, 93 forbidden phrasings).
   - `tools/check_prose_style.py` passes.
   - `tools/check_invariants.py` passes: 158 properties, none exempted.
   - `tools/check_positive_boot.py` passes: 10 rows, and the census matches the table.
   - `tools/check_dispatch_gates.py` passes: 122 dispatch rows, 7 slot-3 rows, each restored only under `LEGACY_SYSCALLS_PRESENT` or `RAMFS_SLOT3_GATE`.

3. Read the symbols the open limits name: `syscall_table` in `src/kernel/syscall.c`, `measured_boot_unavailable` in `src/kernel/tpm.c`, `tags_equal` and `open` in `rust/src/aead.rs`, `rust_ct_eq` in `rust/src/lib.rs`, `spawn_untyped_region` in `src/kernel/kspawn.c`, and `h_sudo` in `src/kernel/kusers.c`.
4. Counted `#[kani::proof]` harnesses in `rust/src/`. The count is 44, which is what `SECURITY.md` S31 states, and what the doc-claim checker derives.
5. Did not boot a guest. Did not treat a previous session's green CI as a result of this pass.

An instrument that finds nothing has to say so. The dispatch-gate checker found the slot-3 rows and showed each one is behind a defect flag. That is a finding of absence in the ship build, and it is reported as such.

## 4. Threat model

The model in `SECURITY.md` matches the code that was read. It is not repeated here in full. The alignment that matters:

| Adversary | What holds at this commit | What does not |
|---|---|---|
| A1, unprivileged ring 3 | Ship syscalls that need a capability ask for one the caller holds, or they act only on the caller. Unknown numbers return `SYS_ERR_NOSYS` (S6). | Denial of service. No shipped task is bound to a budget smaller than a whole CPU (S152, S153). Kernel memory of destroyed frames is not reused (2.5). |
| A1b, uid 0 with an empty table | Identity is not kernel authority (S18), and `fs_server` does not decide a request by who sent it (S14). `SYS_SUDO` answers `SYS_ERR_NOSYS` (`h_sudo`). | A session whose policy grants the union can still do what the union allows. `fs_server` enforces the split inside that union (1.24). |
| A2, a compromised server | The loss is bounded by the capabilities that server holds. | `fs_server` is the reference monitor for file contents. `console_server` sees terminal traffic. Both are in the trusted computing base on purpose. |
| A3, offline, with the disk | On a sealed volume, block contents, the inode table, the bitmaps and indirect pointers are sealed, and the Merkle root binds the superblock layout (S143, S66, S70). | An unsealed volume, which the installer can write if the operator chooses it, has none of that (2.21). Rollback of a whole volume is refused only when a TPM anchor exists (1.12). |
| A4, boot tamper | Modules are checked against a manifest in the kernel (S10). The kernel hash is pinned in the boot image the firmware measures (S92). | A machine with no TPM boots and says so (`tpm: no TPM present, measured boot skipped`). `MEASURED_BOOT_REQUIRED` is what turns that into a halt (`measured_boot_unavailable`). The default build does not set it (2.9). Anyone who can boot their own media can erase the disk. |
| A5, local timing | Flush on switch, SMT siblings parked (S101), `RDTSC` denied, clock at 10 ms (S34). The password compare and the AEAD tag compare are xor accumulates, watched by `tools/check_ct_compare.py` (roadmap 4.20, landed). | The primitives themselves are not shown constant-time (5.4). Shared L2 and L3 are out of scope. |
| A6, a malicious change | Signed commits, no bypass on `main`, actions pinned, secret scanning, reproducible images (S17). | No approving review (5.1). No signed release and no SLSA provenance (5.3). |

Physical access, firmware, and a hypervisor above the guest are out of scope in `SECURITY.md`. This pass does not widen that.

## 5. Findings

### R1. The public limitations page overclaims the control arms

**Severity.** Medium, assurance and public record. Not a kernel defect.

**Evidence.** `site/limitations.html` says each gate has an arm. `SECURITY.md` says the opposite in the introduction to the property table: rows whose witness is only a positive boot are named in `.github/positive-boot.yml`. `tools/check_positive_boot.py` on this commit reports 10 rows and a match. The rows are S1, S6, S7, S8, S9, S10, S11, S12, S15 and S18.

S1 is the claim that a task cannot exercise authority it holds no capability for. Its witness is `make smoke-captest`. The cell names no arm. The suite is large and the dispatch table is data, which is real evidence. It is not the same thing as a build that puts the missing check back and is required to go red. The project recorded that distinction on purpose (roadmap 4.21, pull request 603). The website then stated the stronger sentence.

`site/testing.html` describes the rule and the arm count derived from `.github/gate-pairs.yml`. It does not mention the census. A reader of that page can leave thinking every property row has an arm.

**Disposition.** Correct the sentence. Name the census. Do not invent arms in this change: adding an arm for S1 is a verification change with its own witness, and roadmap 4.21 says the census does not add the arms.

**Prepared separately.** Branch `docs/public-status`, not contained in this report's commit, so this file remains a reading of `e3aa595`.

### R2. Dispatch comments still describe a gate the table does not use

**Severity.** Low. The ship rows are `SC_NONE`. The behaviour is the handler's lookup, not the comment. The risk is the next edit.

**Evidence.** In `src/kernel/syscall.c` the rows are:

- `SYS_SPAWN_IMAGE` is `{ h_spawn_image, SC_NONE, ... }`. The comment above it says the gate is slot-3 `WRITE|EXEC`, the same gate as `SYS_SPAWN`.
- `SYS_FORK` is `{ h_fork, SC_NONE, ... }`. The comment says the row is deliberately not `SC_NONE`, that the authority does not exist yet, and that `tasks[]` is still `.bss` waiting on roadmap 0.3. Roadmap 0.3 is closed. `spawn_untyped_region` resolves `CAPSLOT_UNTYPED` as `CAP_UNTYPED` with `WRITE` (S57).
- `SYS_IPC_SENDER` is `SC_NONE`. The comment says slot-3 `READ`. The handler resolves the endpoint the caller names (S13).
- `SYS_IPC_REPLY_TO` is `SC_NONE`. The comment says slot-3 `WRITE`.

`src/kernel/syscall_ipc.c` says slot-3 `READ` is enforced by the table for `SYS_WAIT_NOTIFY`. The table row is `SC_NONE`, and `h_wait_notify` calls `ipc_notif_from_slot`.

`src/kernel/syscall_fs.c` says slot-3 `WRITE|EXEC` is enforced by the table for `SYS_SPAWN`. The handler is in `kspawn.c` and the row is `SC_NONE`. The same file's banner still lists `SYS_SUDO` as a self-authorising check. `h_sudo` returns `SYS_ERR_NOSYS` and does nothing else.

`src/kernel/loader.c` describes `SYS_SUDO` re-authenticating the caller and spawning the armed image as uid 0, in the present tense, in the comment that justifies the owner stamp. The call is withdrawn. The owner stamp is still the mechanism for S21, and that part of the comment is the reason to keep it. The tense is what is false.

The table comment a few hundred lines earlier already says a sweep cannot certify itself and that `tools/check_dispatch_gates.py` reads the table. That checker passed. The false sentences survived it because it does not read comments. The 2026-08-29 lesson, recorded in `tools/check_doc_claims.py`, is that a retired claim lives on in the comment beside the check. These sentences are that shape. They are not on the forbidden-phrasing list, so the ratchet did not see them.

**Why it matters.** The last time the slot-3 decoy shipped, the comment said the sweep was finished. A later editor who "repairs" a row to match the comment would put the decoy back. The checker would then fail, which is why this is low and not high. The comment is still part of the audit, and it currently contradicts the row.

**Disposition.** Rewrite the comments so they state the row that is there, the property it keeps, and the closed history in the past tense. Do not change a handler. Witness remains `tools/check_dispatch_gates.py`, because the table is the gate.

**Prepared separately.** Branch `harden/dispatch-comment-truth`. Handlers were not edited. The dispatch-gate checker was run on that branch and passed.

### R3. G-14 has no entry in the register

**Severity.** Low, status hygiene. The gap is real. The omission is the finding.

**Evidence.** `docs/ARCHITECTURE.md` section 14 lists G-14 as open: ring 0 still holds evictable policy. The introduction of `docs/LIMITATIONS.md` says a G-number's status is that file. G-8 through G-13 appear in the closed table. G-14 does not appear in the open sections. Roadmap 2.7a describes the same gap and is not started. `.github/ring0-classification.yml` is what measures the split (S87). The core budget the checker derives on this commit is 13,354 code lines. The service class is the company that core keeps: `storage.c`, `kusers.c`, the loader and spawn path, `crypto.c`, `syscall_fs.c`, and the in-kernel disk drivers.

A defect in the volume key, the password hash, or the ELF loader is a kernel defect. That is the trusted-computing-base fact. It is not a new vulnerability, and this pass does not propose to move the code. Moving it is a design decision the roadmap already sequences behind filesystem phase 2.

**Disposition.** Add one open entry, 1.42, pointing at G-14 and at roadmap 2.7a. Do not evict the service class in that change.

**Prepared separately.** The same docs branch as R1, because both are the public status of an existing fact.

### Carried findings, confirmed still open

These are not new. Each was checked against the symbol the register names. None is closed by this pass.

| Register | Confirmed by | Residual |
|---|---|---|
| 1.12 | S70 and the register's own limits | Anchor only if the volume was formatted on a machine with a TPM. One step per boot. No export. |
| 1.23 | `SYS_SPAWN_IMAGE` takes the caller's bytes. The row does not consult a file mode. | System trees are rebuilt from verified modules (S116). A readable file outside them can be run. Roadmap 5.4. |
| 1.24, 1.26 | S128. The kernel intersects rights at the root. The server applies the policy below it. | A bug in `fs_server` is a bug in the policy. A grant names a path. Roadmap 5.10 waits on decision D8. |
| 2.3, 2.5 | The register and roadmap 5.9 | Retyped objects leak rather than use-after-free. Static endpoints live for the boot. Frame bytes are not recycled. |
| 2.9, 2.9a | `measured_boot_unavailable` prints and returns in the default build, and halts under `MEASURED_BOOT_REQUIRED`. The seal binds `PCR[4]`. | Fail open without a TPM. A kernel update locks a sealed volume until it is resealed. Roadmap 5.6, 5.7, 5.8. |
| 2.12 | S45 when VT-d is present. `iommu_active()` is 0 when there is no DMAR table, and the boot says so. | DMA is not confined on that machine. Roadmap 5.14 is a build flag, not the default. |
| 2.21 | S104 | An operator can format an unsealed volume. The boot says which kind it found. |
| 5.1 | `SECURITY.md` process section. The ruleset requires no approving review. | Critical as a process finding. Not fixable by a patch in this tree. |
| 5.3 | Release text in `SECURITY.md` | Four alpha ISOs, unsigned tags, no provenance. Rebuild reproducibility is S17, which is a different property. |
| 5.4 | `tags_equal` and `rust_ct_eq`, both xor loops. `tags_equal` keeps the accumulator opaque with `black_box`. `rust_ct_eq` does not. | The compares are in the shape roadmap 4.20 watches. That does not audit ChaCha20, SHA-256, BLAKE2b, Argon2id or the AEAD, and it does not prove the compiler keeps the loop. The finding stays open. Roadmap 5.15 waits on a maintainer decision. Do not write new primitives. |
| 5.5 | 44 harnesses, all listed, the `kani-bounded` job required. | No refinement proof. No TLA+ model. Concurrent protocols are roadmap 5.11 and wait on decision D9. |

`rust_ct_eq` returns 0 on a null pointer or a zero length. That is fail-closed. It is not a timing proof.

The AEAD is ChaCha20 with HMAC-SHA256, encrypt-then-MAC, and the tag stored is 16 bytes (`AEAD_TAG_LEN` in `rust/src/aead.rs`). Truncation is a design parameter of an unaudited construction. It is recorded here so a reader does not have to discover it. It is not a new finding and it is not a recipe.

## 6. What is holding

Recorded so the coverage is honest, not to claim more than was read.

- **The ship dispatch table is data.** `syscall_handler` refuses a number past the table or a null entry. `_Static_assert` ties `SYSCALL_TABLE_SIZE` to `SYS_SCHED_GET_PRIORITY + 1`. Authority that depends on which capability the caller names is `SC_NONE` on purpose, with the lookup in the handler. A fixed slot would repeat the decoy (the comment on the IPC rows says this, and it is the one that is still true).
- **Slot 3 is a decoy in the ship build.** The seven rows that still name it are under `LEGACY_SYSCALLS_PRESENT` or `RAMFS_SLOT3_GATE`. S79's checker reads the table.
- **Task creation spends untyped memory.** `spawn_untyped_region` looks up `CAP_UNTYPED` with `WRITE` in the caller's slot. A task with no such capability cannot spawn (S57). The fork comment that denies this is R2. The code does not.
- **`SYS_SUDO` is gone.** `h_sudo` returns `SYS_ERR_NOSYS`. Administration is a login that is lent `CAP_USER`, the kernel log and `CAP_DEBUG` for that session and has them revoked at logout (S149).
- **Measured boot tells the truth in the default build.** The log line is explicit. The policy build halts. CI sets `SWTPM_REQUIRED` so a TPM gate cannot pass by skipping the measurement. That is 2.9 as designed, not a silent success.
- **The password compare and the AEAD tag compare are the xor accumulates**, and a `memcmp`, an early return or a slice equality on either path fails the build (roadmap 4.20). Limitation 5.4 stays open, and the changelog says so.
- **The invariant registry has no exemptions.** `.github/invariants.yml` is empty of exemptions. 158 properties resolve to a target or a job that exists.
- **The public documents after pull request 601 are mostly the tree.** The doc-claim checker passes on this commit. The site's open limits match 5.1, 1.23, 1.24, 2.9, 5.4, 2.12, 5.3 and 5.5. The false sentence is R1, not the whole site.
- **Scanners of the trusted userspace can fail** (roadmap 4.16, pull request 602). CodeQL is no longer described as advisory. That closed a process gap the previous session queue was written around. It does not review a change.

## 7. Staleness, duplication, and what was not deleted

Dead code that is still a control arm is not dead. `h_open` and `h_ramfs_create` exist so `RAMFS_SLOT3_GATE` can put the defect back. Removing them would delete the witness. They stay.

`src/kernel/rust_shims.c` is the unfinished C fallback. Limitation 5.3b says the `RUST_ENABLED=0` build cannot link and that whether a no-Rust build is a goal is undecided. Deleting the shims would decide that. This pass does not.

`DEBUG_SHELL` and the `*_SELFTEST` syscalls are absent from the default kernel. The boot names every extra switch in `DEFECT FLAGS:`. That is the right shape. No flag was turned on to make a reading easier.

Ring-0 comments that explain a failed approach stay. The standard is the block in `src/kernel/scheduler.c` headed as a record of what did not work. R2 deletes nothing of that kind. It corrects sentences that state a present fact which is no longer true.

No third-party crate was added. The Rust core stays dependency-free. Roadmap 5.15 is the decision about replacing the primitives, and it is not taken here.

G-14 was not used as a reason to start moving `storage.c`. That would be a security-model change bundled with a document, which the operating rules forbid.

## 8. Documentation

### What was checked

`README.md`, `SECURITY.md`, `docs/LIMITATIONS.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/BUILDING.md` (by the checkers, not by a full re-read), `TESTS.md` (the invariant job line), `CONTRIBUTING.md`, `AGENTS.md`, `CHANGES.md`, `docs/AUDIT.md`, and the eight HTML pages.

`docs/AUDIT.md` remains the 19 September 2026 audit. It says the areas it swept were not cleared. This report does not replace that file, because `tools/check_doc_claims.py` parses its rejected-candidate table. A second audit beside it is the right shape. `docs/README.md` is updated in this change so a reader can find both.

### What was wrong

R1 and R3, above. Also, `docs/ARCHITECTURE.md` said the status of G-14 "stays this section and `LIMITATIONS.md`" while the register had no entry. That sentence is how R3 hid.

### What was already right, and was left alone

- The threat model, the adversary list, and the out-of-scope list.
- The property table. 158 rows, witnesses resolved, census matched. Paraphrasing it would break `tools/check_invariants.py` or silently drop an arm.
- The register's open entries and the closed table. Counts in section 3 of the register are derived or cited from symbols (`MAX_TASKS`, `CNODE_SIZE`, the image budget). The completeness percentages in section 6 are estimates, not measurements. They are labelled as an estimate against a complete operating system. This pass does not invent new percentages.
- The site's home page, which already says the system is not independently reviewed and not something to trust with data that cannot be lost.
- History and investigations. They stay as written.

### Rewrites that were not done

A complete rewrite of every Markdown file was the request. Doing it would have manufactured drift in a tree whose checkers pass, and it would have bundled a status change, a comment change and a new document into one pull request. The operating rules say one concern, and they say a document that disagrees with the code is the thing to fix. The disagreements found are R1, R2 and R3. The rest of the public record was read against the code and left.

## 9. Residual risk and the next work

In the order the roadmap already gives, not a new queue:

1. **Keep 5.1 visible.** A second reviewer (decision D11, roadmap 4.1) is the largest reduction in risk. No patch in this repository creates that person.
2. **Do not start new primitives.** Limitation 5.4 closes by an audit or by a vendored, hash-pinned replacement. That is decision 5.15. The compare watcher is not that audit.
3. **Measured boot and rollback.** Roadmap 5.6 and 5.7. Fail closed when a TPM is present. The default research build can keep booting without one, and it must keep saying so.
4. **Exec from a file capability.** Roadmap 5.4, which closes 1.23. `SYS_SPAWN_IMAGE` then needs a capability no session holds.
5. **Reclaim, then the service class.** Roadmap 5.9 closes the exhaustion in 2.5 and 2.3. G-14 leaves ring 0 with filesystem phase 2 (2.10) and `auth_server` (2.11), not before.
6. **Arms for the positive-boot rows, S1 first.** The census is done. The arms are not. An arm for the central dispatch claim is worth more than another document.
7. **One stamped kernel image** (roadmap 4.17) before any new scanner. A shared image without a stamp is a gate that can pass on the wrong kernel.
8. **Provenance** (4.4, 4.5, 4.11) so a release can be checked by someone who did not rebuild it by hand.

This assessment does not lower any of those. It does not raise the system above the register.

## 10. Appendix

### A. Commands run on `e3aa595`

| Command | Result |
|---|---|
| `tools/check_doc_claims.py` | Pass |
| `tools/check_prose_style.py` | Pass |
| `tools/check_invariants.py` | Pass, 158 properties, 0 exemptions |
| `tools/check_positive_boot.py` | Pass, 10 rows |
| `tools/check_dispatch_gates.py` | Pass, no ship row gated on slot 3 |

Not run: `make`, `make smoke`, `make smoke-captest`, `cargo test`, `cargo kani`, any QEMU boot. Those remain the witnesses in `SECURITY.md`. This pass did not re-execute them.

### B. Positive-boot rows

S1, S6, S7, S8, S9, S10, S11, S12, S15, S18. Source: `.github/positive-boot.yml`, confirmed by `tools/check_positive_boot.py`.

### C. Documents relied on

| Document | Role |
|---|---|
| `docs/LIMITATIONS.md` | Status of every finding |
| `SECURITY.md` | Threat model and the property table |
| `docs/ARCHITECTURE.md` | Trusted computing base and G-14 |
| `docs/ROADMAP.md` | Order of the open work |
| `docs/AUDIT.md` | Previous self-audit, 19 September 2026, not superseded as a status |
| `.github/positive-boot.yml` | Witnesses with no arm |
| `.github/ring0-classification.yml` | What is linked into the kernel |

### D. Relationship to earlier audits

| Record | What it still contributes |
|---|---|
| `docs/history/AUDIT-2026-07.md` | The C, I, M and F identifiers. Status is the register. |
| `docs/history/AUDIT-2026-08-30.md` | Whole-tree pass of that date. Status is the register. |
| `docs/AUDIT.md` | F1 to F3, all closed. IPC, storage, measured boot and the ring-3 servers were swept, not cleared. This pass read dispatch, measurement and the compares. It does not clear the rest. |
| `docs/history/AUDIT-EXTERNAL-2026-09-20.md` | An outside reading, reconciled. It sets no statuses. |

### E. Prepared corrections, not in this commit

| Branch | Concern |
|---|---|
| `docs/public-status` | R1 and R3: the page, the testing census, register entry 1.42 |
| `harden/dispatch-comment-truth` | R2: comments only. Properties kept: S79, S57, S13, S21. Witness: `tools/check_dispatch_gates.py` |

If those branches are not on `main`, the sentences this report quotes are still in the tree at `e3aa595`.
