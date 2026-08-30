# Horus security audit, 2026-08-30

**Scope.** The whole tree: C kernel, `no_std` Rust security core, x86-64 assembly, build system,
userspace, tests, the assurance machinery itself, documentation, and repository metadata.

**Method.** Read against the local checkout as the source of truth, never against the
documentation. Every finding re-derived from the code; every behavioural finding demonstrated on
a boot with `DEFECT FLAGS` read off the wire. Every number produced by running the tool that
derives it.

**Baseline.** `d78aa04`, 477 commits. The predecessor audit is
[`docs/history/AUDIT-2026-07.md`](history/AUDIT-2026-07.md), dated 2026-07-27 and itself carrying
the July 2026 audit as its Appendix A. This audit supersedes its status, not its findings: the
finding IDs it established (`[C-n]`, `[I-n]`, `[M-n]`) remain in use and their current status is
in [`LIMITATIONS.md`](LIMITATIONS.md), which is authoritative.

---

## 1. Why this audit exists, and what it was looking for

Between 2026-08-22 and 2026-08-29, **seventeen of the fifty-six security properties** in
`SECURITY.md` were written: sized frames and the region map (S35 to S38), fork and exec (S39 to
S42), device capabilities (S43, S44), the VT-d IOMMU (S45), interrupt routing (S46), MSI and
MSI-X (S47, S48), and the shared library (S49 to S51). A third of the claim surface, in eight
days.

Every one of those arrived with a gate, and every gate was falsified by its author against the
defect its author had in mind. That is the house rule working. It is also the blind spot: a
falsification finds the defect you thought of. This audit went looking for the ones nobody
thought of, and for the places where the machinery that checks the claims does not check what it
appears to.

**The prior for this tree is that documentation drifts faster than code.** The 2026-07-27 audit
found claims wrong in both directions, and `[H-1]` survived nineteen days because three documents
asserted a property while one gate contradicted it. So no finding here rests on a document.

---

## 2. Summary

| | Count |
|---|---|
| Defects found and fixed | **4** |
| Coherence defects found and fixed | **25** |
| Findings recorded as limitations, not fixed | **3** |
| Candidates investigated and **rejected** | **9** |
| New security properties | **S52**, **S53**, **S54** |
| New gating checks | 2, plus one harness deliberately outside CI |

**Overall posture: unchanged, and that is the finding.** Nothing here moves the project's risk
rating. The capability model held everywhere it was probed, and the new device, IOMMU, fork and
shared-library surfaces are, with one exception, built the way the rest of the kernel is built.

The result worth noting is where the serious defect was. This audit was commissioned because a
third of the security properties had landed in eight days, and the critical finding turned out to
be in `cap_mint`, which predates all of it. The new code was sound; the old code had a helper that
turned a refusal into a halt, and the reason nobody had found it is that nothing ever called the
three syscalls that reach it.

**The dominant residual risk is still governance.** No security-critical change in this project
has ever been reviewed by a second person (**[C-5]**), and ruleset reconciliation still lags a
merge (**[C-6]**). Neither is technically fixable by a single maintainer, and neither moved.

---

## 3. Defects found and fixed

### 3.1 A refused capability operation halted the CPU instead of returning, *Critical*, **fixed in #242**

`cap_mint()` and `cap_transfer()` resolved the caller's **source** slot through `kcap_lookup()`,
which was `cap_lookup()` followed by `kassert_cap()`, an unconditional `for(;;){}` on NULL. Both
ran holding `cap_lock`, with interrupts masked by `spin_lock`'s own `cli`.

Every input that makes `cap_lookup()` return NULL is chosen by the caller: a slot past
`CNODE_SIZE`, an empty slot, or a slot without `CAP_RIGHT_MINT`. `h_cap_mint` passed
`rbx`/`rcx`/`rdx` through untouched, and `SYS_CAP_MINT`, `SYS_CAP_TRANSFER` and `SYS_CAP_MOVE`
are `SC_NONE` entries whose table comment delegates authority to the primitives.

So `syscall(SYS_CAP_MINT, 203, 200, 0)` from **any unprivileged ring-3 task** spun that CPU
forever inside a global critical section, and the next CPU to want `cap_lock` stopped behind it.
One syscall, no capability, whole machine.

**This is not the documented local-denial-of-service exemption.** That exemption covers a task
spending its own share: spinning, allocating, forcing a broad revocation. This ends the machine
for every task and consumes no quota to do it.

**Why it lasted.** All three syscalls sat on `.github/syscall-coverage.yml`'s `uncovered` list,
carrying *"not entered by any tracked workload, and by no build known in this tree"* since
2026-08-22. Nothing ran the handlers, so nothing found it. `LIMITATIONS.md` §1.8 described
exactly this risk and said *"nothing here is known to be broken"*; it has been rewritten.

Fixed by letting the existing `if (!src …) return false` be reachable. Property **S52**, falsified by `CAP_LOOKUP_ASSERT_HANG=1`.

### 3.2 A device's IOMMU translation outlived the frame that authorised it, *High*, **fixed in #243**

`SYS_DMA_ADDR` installs a VT-d entry for the frame a driver names, and nothing removed it.
`frame_map_refcount` counts CPU mappings only, so a device mapping neither kept the frame alive
nor was torn down when it died: `destroy_dyn_frame` scrubbed the run, released the pages to the
untyped arena, and left the translation installed. The arena then handed those bytes to a fresh
object while a bus-mastering device could still read and write them.

A device-side use-after-free, and the third capability-free path to a page in a function whose
own comments reason carefully about the second. `iommu_unmap()` and `iommu_reset_device()`
existed, were prototyped, and were **called by nothing**; their own comment said they run *"when
a frame capability is revoked or a driver dies"*.

Property **S53**. Falsified by `IOMMU_NO_FRAME_TEARDOWN=1`. The `task_teardown` half has no arm
and that is stated rather than implied: reproducing it needs a driver holding a device capability
to die under `SMOKE_IOMMU` while a peer still holds the frame, and no workload here does that
yet.

### 3.3 Comments across the kernel asserted a system that had been retired, *Medium*, **fixed in #244**

Three families, none of which broke a build or a test:

- **Seven handlers claimed a `uid == 0` gate their bodies do not contain**, and five header lines
  said the same. Ambient uid 0 was retired by **[I-1]** and **[H-1]**; the comments were never
  swept. `SYS_DMESG`'s said *"ROOT ONLY … gated to uid 0, enforced here"*, and it is gated on
  `CAP_KERNEL_LOG` in the dispatch table.
- **Twelve comments named `CAP_BLOCK_DEV` as the gate on the object store.** That type is defined
  and **enforced by nothing**: no dispatch entry and no check in the tree uses it. Someone
  auditing that authority would have looked for the wrong capability.
- **Four comments still said "there is no IOMMU"**, two of them stating the security argument for
  disclosing a physical address from `SYS_DMA_ADDR`, resting on a premise VT-d had retired.

**The mechanism mattered more than the instances.** The `forbidden:` ratchet scanned `*.md`,
`*.html` and `*.yml` only, so all of these were invisible to it, and #243 had added *"there is no
IOMMU"* to that ratchet on the same day four copies stayed live in `.c` and `.h` files. It now
scans source, which immediately found eight further instances nobody had gone looking for.

### 3.4 The security core's `unsafe` FFI stated no obligations, *Medium*, **fixed in #245**

`CLAUDE.md` §7 required a `# Safety` clause on every `unsafe` and nothing enforced it. **30 of
49** production sites had none, worst in the two modules the kernel trusts most:
`rust/src/capability.rs` (10 of 14) and `rust/src/memory.rs` (6 of 6, the string appearing
nowhere in the file).

This matters more here than in ordinary Rust because every one of these is called from C, and **C
cannot be made to uphold an obligation nobody wrote down.** Neither of these is visible from a
signature: `rust_cap_revoke_global` needs *every* cspace in the system in its `spaces` array or a
revocation silently misses a derived copy, and `rust_page_ref_inc` needs `page_lock` held because
it is a non-atomic read-modify-write on the refcount that decides when a page is freed.

Property **S54**, gated by `unsafe-safety`. **The checker found its own defect**: a fixed 30-line
lookback let an undocumented item inherit its neighbour's clause, which is how a thirtieth
undocumented site had been missed by hand.

---

## 4. Findings recorded, not fixed

Each of these is a real gap whose repair is a judgement the maintainer should make.

### 4.1 The task-creating syscalls are gated on the `[C-1]` decoy (`LIMITATIONS.md` §1.6b)

`SYS_SPAWN`, `SPAWN_IMAGE`, `EXEC_NAMED`, `EXEC_IMAGE` and `FORK` authorise on cspace slot 3 with
`SC_ANYTYPE`, and `create_task` installs a `CAP_FRAME` there in **every** task with exactly
`READ|WRITE|EXEC`. By **S28** that is not a gate. It is **[H-3]**'s shape, one table over.

**Not an escalation.** Unlike [H-3], where the decoy bought reach into the in-kernel ramfs, these
confer nothing the caller already lacked: a fork copies the caller's own address space and
cspace, and a spawn endows a child from what the spawner holds (**S41**, **S42**). The entries
were left in place because the shape is right and the authority that belongs there would have to
name a task object, which does not exist while `tasks[]` is `.bss` (**[I-7]**). The two comments
that described it as a gate, in disagreement with each other, were corrected.

### 4.2 A gate is classified as a control arm by its name (`LIMITATIONS.md` §1.10)

`check_gate_pairs.py` tests whether the string `control` appears in the target name. Four
falsification arms are named otherwise and count as base gates. Both resulting figures are
**published and gated**: 69 arms and 97 gates, against a true 73 and 93.

The obvious fix is worse: classifying by what a target *builds* finds 87, because `DEFECT_FLAGS`
holds instruments and policy opt-ins as well as defects, four of which `CLAUDE.md` explicitly
calls *"not a defect"*. That trades being wrong about four targets for being wrong about
eighteen. The real fix is a manifest naming each pair, the way `ci-gating.yml` names every job.

### 4.3 The `enforced by` column is parsed and discarded (`LIMITATIONS.md` §1.11)

`check_invariants.py` reads each row as `(statement, enforced_by, witness)` and binds only the
witness. So the column naming the code that makes a property true can name a function that does
not exist. The other direction is unchecked too: **21 of 56 S-numbers appear nowhere in the code
they describe**, of which five are properties of the build with no kernel site to cite from and
sixteen have a specific enforcing site that does not name what it carries.

A **traceability** gap, not an enforcement one: every property is enforced by code that exists
and witnessed by a gate that runs.

---

## 5. Candidates rejected

An audit that reports only what it confirmed is not showing its work. Eight leads were
investigated and rejected; each is recorded because the reasoning is what stops the next audit
re-raising it.

| Candidate | Why it is not a finding |
|---|---|
| `SYS_SUDO` mints capabilities with `badge = 0`, so no revocation can sweep them | `badge` is documented as *"its parent's serial (a graph edge), **0 at a root**"*. These are capabilities over new objects, not copies of existing authority, so root is the correct encoding, the same one `create_task` uses. Contrast `FORK_CSPACE_ORPHAN_COPY`, whose defect is an orphan copy of authority that already existed. |
| IPC gates on the slot-3 decoy | The `cap_snapshot(cap_lookup(3, …))` in `sys_ipc_send` is an additive TOCTOU guard that deliberately does not newly reject. The actual gate is `ipc_ep_from_slot`, which resolves the endpoint from the capability's own object. |
| `SYS_ROTATE_KEYS` is gated on `CAP_CONSOLE` | The dispatch entry is one of two checks; `do_rotate_keys` requires `CAP_ENCRYPTED_STORAGE` before doing anything. |
| `msi_dispatch` calls `sys_notify` from interrupt context, racing `ipc_lock` | Vector `0x80` is an **interrupt** gate (`0xEE`), so syscalls run with `IF=0` and cannot be interrupted by the MSI that would take the lock. |
| `ipc_unlock` bypasses the `irq_lock_depth` accounting | Same reason: with `IF=0` throughout, the accounting the other unlocks maintain has nothing to restore here. |
| `ensure_identity_mmio_page` allocates without `page_lock` | Based on a misreading of which functions take the lock; `user_map_fresh_page`, the comparison drawn, takes no lock either. |
| `endpoint_lock` → `page_lock` is an undeclared nest | Checked in the direction that matters: no `page_lock` holder enters IPC. |
| The lineage generation table is a lossy hash, so a collision can over-revoke | Documented in the code, stated as an assumption in the Kani harness, and rated as a fail-safe residual in the predecessor audit's **A3**. Known and accepted, not undiscovered. |
| The required `security` job masks its scanners | Deliberate, documented in place at length, and compensated by a step that fails the job if any scanner is missing. It can go green having found problems; it cannot go green having run nothing. |

---

## 6. What was measured

**Thirty-one claims that a gate reddens, and nothing had ever checked one.**
`docs/BUILDING.md` says *"`make smoke-X` must go red under it"* thirty-one times. No target, job
or checker tested it. It is not implied by the control arm: an arm builds *with* the flag and
asserts its own FAIL marker, the gate builds *without* it and asserts PASS, and nobody built the
gate with the flag. Those come apart whenever the two watch different markers.

Measured 2026-08-30 with `tools/check_base_gate_reddens.sh`: **30 of 30 pairs go red.** The
thirty-first drives a `cargo` feature rather than a `-D` flag and is exercised separately.

**The control arms themselves were not separately re-run, and the reason is worth stating.** CI
runs 164 of the 166 smoke targets on every pull request, so the five green runs this audit
produced measured every arm on the current tree. The two exemptions are verified non-stale by
`check_gate_pairs.py` and each names the stronger form that CI does run. Re-running them locally
would have added hours and no evidence.

---

## 7. Process findings, unchanged

**[C-5] No independent review.** *Critical (process)*, open. Every security-critical path in
this project has been modified by one person. This audit is not a substitute: it was performed by
a tool the same person directed.

**[C-6] Ruleset reconciliation lags a merge.** *High (process)*, open and narrowing. The
scheduled `ruleset-audit` job verifies the live ruleset daily as a GitHub App with
`Administration: read`. What remains is that `--sync-ruleset` needs an admin token, so a pull
request adding a gating job leaves the ruleset one context behind until it is run.

---

## 8. Assurance statement

Horus is a research microkernel and this audit does not change that. What it establishes is
narrower and worth saying precisely:

- The capability model held everywhere it was probed. The one critical defect was not a failure
  of the model but of a helper that turned a refusal into a halt, in code older than every
  subsystem this audit set out to review.
- The newest surfaces (device capabilities, VT-d, fork, the shared library) are built to the
  same standard as the rest. The one defect among them was an absence rather than a mistake: a
  teardown path that existed and was never called.
- The assurance machinery is good and was itself unaudited. Three of its checkers gained a rule
  or a scope they should have had; two more gaps are recorded rather than closed.
- Documentation drift remains this project's most reliable defect class. Twenty-five coherence
  defects in one pass, including a falsification record naming the wrong marker, and a checker
  that remembered a retired claim in prose while four copies lived on in the code beside the
  check.

Nothing here is a reason to trust the system more than `README.md` already says. The honest
summary is that the property claims are, as far as this audit could determine, true; that rather
more of them are now checked than asserted; and that the gap between what this project claims and
what it proves is smaller than it was on 2026-08-29, in a way that is measurable rather than
argued.
