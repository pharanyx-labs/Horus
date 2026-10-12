# The long-term plan: closing the known gaps

**A plan, not a design; nothing in it is built beyond what each item says.** Written on
2026-10-12 at the maintainer's request, from two lists of findings and proposals they supplied
that day. Every finding was checked against the code on that date. Where a step changes the
security model it waits on a decision that is the maintainer's (section 7); the recommendation
given there is a recommendation, not the decision.

[`ROADMAP.md`](../ROADMAP.md) Track 5 holds the new items this plan adds, one line each. Existing
roadmap items keep their numbers and their own status; this document only says when they come.
[`LIMITATIONS.md`](../LIMITATIONS.md) stays the authoritative status of every finding.

## 1. How the order was chosen

1. **Holes before features.** A finding that contradicts a property `SECURITY.md` claims comes
   before anything that adds surface.
2. **Enablers early.** A cheap step that several later ones need goes first: a reproducible ISO is
   what makes a release verifiable and a PCR value predictable.
3. **Authority before mechanism.** The filesystem and accounts finish moving to capabilities before
   the kernel's services leave ring 0, so each service leaves with its authority already explicit.
4. **Ring 3 by default.** Every new mechanism is placed outside ring 0 unless it cannot be, and the
   ring-0 budget (S87) is raised only with a reason.
5. **Each step is its own pull request** with a gate, a control arm that reddens the base gate, and
   its documentation, as every change is.

## 2. Where each finding stands

Checked on 2026-10-12. "Closes with" names the step in this plan; the phases are sections 3 to 5.

| Finding | Today | Closes with |
|---|---|---|
| LIMITATIONS 1.29, pipe ends copied uncounted | The `fork` half fixed (#553); ring 3 refused any copy (#555, in review) | #555 |
| 1.14, a stdio pipe end escapes revocation | Design recorded (recount after the sweep); not built | 5.1 |
| 1.31, the uid path reaches a file by inode number | The uid path is still how every login reads files | ROADMAP 2.10 step 3(b), then step 6 |
| 1.30, inode table and bitmaps unauthenticated | Data blocks sealed; metadata in the clear, outside the Merkle tree | 5.2 now, or ROADMAP 2.10 phase 2 |
| 1.23, `EXEC` advisory against a reader | `SYS_SPAWN_IMAGE` runs any image its caller holds in memory | 5.4 |
| 1.24, session policy below the root enforced by `fs_server` | The kernel bounds a session only by the union of its grants | 5.10 |
| 1.12, rollback anchored only with a TPM, one-boot granularity | As stated; no policy refuses an unanchored volume | 5.7 |
| 2.9, measured boot optional | `MEASURED_BOOT_REQUIRED` defaults to 0 | 5.6 |
| 2.9a, a kernel update needs a reseal | As stated | 5.8, after ROADMAP 3.1 |
| 2.9b and 1.6, console input has an owner for passwords only | Any program a person runs can read the lines they type | 5.5 |
| 2.3 and 2.5, static objects permanent, destroyed frames not reclaimed | No untyped reset exists (`untyped.c` says so where the pins are set) | 5.9 |
| 2.6c, kernel markers read off the shared console | Four gates read COM3. A string search of the gate definitions against the kernel sources finds 55 base gates whose required marker only the kernel prints; how many of those print after `console_server` owns the UART, and so are exposed, is not measured | 5.3 |
| SMP and per-CPU data | Scheduler steps 0, 1, 1b and 2a done; one global run pool and lock; no `%gs` block | ROADMAP 1.8 steps 2 to 8, then 1.2 |
| 5.5, formal verification narrow | Bounded Kani harnesses over a handful of properties; no model of the concurrent protocols; no typed-lookup proof | ROADMAP 3.5 remainder, and 5.11 |
| 5.3a, 5.3, the ISO not reproducible, no provenance | `kernel.elf` reproducible; the ISO is not; releases carry an ISO and its checksum from an unsigned tag | ROADMAP 3.1, 4.5, 4.4, 4.11 |
| 5.1, no independent review | No human reads a change before it lands | 5.12 (ROADMAP 4.1) |

## 3. Phase A: close the holes, build the enablers

In order. Each is small enough to finish in days, and none waits on the others except where said.

1. **Merge #555** (1.29): ring 3 may no longer copy a pipe end (S133).
2. **5.1 Revocable pipe ends** (1.14). Give the child's stdio end the spawner's end as its parent
   (`badge = serial`), and after every revocation sweep has dropped `cap_lock`, recount each pipe's
   `reader_ends` and `writer_ends` from the cspaces under `pipe_lock` alone. Since #555, every
   holder of a pipe end is one the kernel made, which keeps the recount's inputs to three
   producers. Witness: a new gate (proposed name smoke-pipe-revoke-child) in which a parent revokes its end, the child's
   must be gone and the peer must see EOF; arm restores `badge = 0`. `SECURITY.md` S3 then holds
   for pipe ends without a footnote.
3. **ROADMAP 2.10 step 3(b), 3(c) and step 6** (1.31). Step 3(b) waits on decision D1 below, the
   one question already outstanding: how `init` hands its login watcher a read-only `CAP_TCB`.
   Step 6 removes the uid path, which closes 1.31 by deletion rather than by a check.
4. **5.3 Kernel reports off the shared console** (2.6c). First a checker that classifies every
   base gate's required markers by who prints them and when (before or after the console handover),
   with a ratchet list that can only shrink, so the exposed number is measured, not estimated. Then
   move the exposed gates to COM3 in batches by subsystem, each batch with its arms rerun, until the
   ratchet is empty. The COM1 split at the console handover that reddened `kdiag` and
   `installer-sd-smp` is part of this work, not a separate flake.
5. **ROADMAP 3.1 A reproducible ISO** (5.3a). Assemble the image with `xorriso` directly, or derive
   GRUB's embedded UUID and file names from `SOURCE_DATE_EPOCH`, and extend the `reproducible` job
   to build the ISO twice, in two directories as two users, and compare. Phase B's release work and
   5.8 both depend on it.
6. **5.2 Authenticated metadata on the current format** (1.30), if decision D2 takes it. Make the
   inode-table and bitmap blocks leaves of the existing Merkle tree, so a changed owner, mode, size
   or bitmap is refused at first use, as a changed data block is. It is a format version bump: a
   volume made before it is refused with a message, not mounted unverified. Witness: a gate that
   edits an inode's mode on the disk image and must see the mount or the read refused; arm skips
   the leaf check. Without D2's yes, 1.30 waits for phase 2 of the filesystem (section 5), which
   authenticates all metadata by construction.

## 4. Phase B: authority completes, the boot chain tightens

Roughly in this order; the SMP and proof strands run beside the others.

1. **ROADMAP 2.11 step 3, accounts as files.** `/etc/passwd` and `/etc/shadow` under a ring-3
   `auth_server`; the kernel keeps only the key-slot unlock. This is also the accounts half of
   ROADMAP 2.7a.
2. **5.4 Exec only from a file capability** (1.23), shape set by decision D7. A new spawn call
   takes a file capability that carries `EXEC` and has `fs_server` supply the bytes through it;
   `SYS_SPAWN_IMAGE` then needs a capability of its own that no session is given. TCC's output
   still runs: the compiler writes the file in the user's home, which the default policy grants
   `EXEC`. Witness: a session holding a readable, non-`EXEC` file cannot run it by either route;
   arm lets `SYS_SPAWN_IMAGE` run unauthorised.
3. **5.5 Console input as a capability** (2.9b, and 1.6's read half), if decision D6 takes it.
   `console_server` serves input only through a foreground capability; the shell holds it, grants
   a derived copy to the child it runs in the foreground, and revokes it when the child ends or is
   stopped. The watcher of 2.10 step 3(b) is where the hand-back happens, which is why this follows
   it. Writing to the console stays ambient. Witness: a background program's read is refused while
   another task owns input; arm serves every reader.
4. **5.6 Measured boot whenever a TPM is present** (2.9), if decision D3 takes it. A machine that
   has a TPM fails closed when measurement or sealing fails; a machine without one boots, says so on
   screen at install and at every login, and the installer records the choice. The
   `MEASURED_BOOT_REQUIRED=1` build stays, for a deployment that refuses TPM-less machines.
5. **5.7 Rollback anchoring** (1.12), in three parts set by decision D4: refuse to mount an
   unanchored volume on a machine that has a TPM unless the installer recorded that the volume was
   made unanchored on purpose; advance the counter at clean shutdown and at a bounded interval of
   writes, so the window shrinks from one boot to that interval; and, later and opt-in, eMMC RPMB
   as a second anchor on machines without a TPM. An export path for a volume moved between
   machines comes with the second part.
6. **The release chain**: ROADMAP 4.5 then 4.4 then 4.11. Each release carries the SBOM, the ISO
   built reproducibly, and the expected PCR values; then signatures and SLSA provenance, in the form
   decision D10 picks; then `verify-release.sh`, which rebuilds from the tag and compares.
7. **5.8 Updates without lockout** (2.9a), after the reproducible ISO. Compute the PCR values the
   new boot image will produce, seal a second copy of the volume key to them before rebooting, and
   remove the old seal only after the new image has unlocked once. Decision D5 confirms this over a
   signature scheme, which was rejected because it makes `PCR[4]` the same for every signed kernel.
8. **SMP: ROADMAP 1.8 steps 2 and 3, then the 2.2 remainder.** Per-CPU run queues with a reschedule
   interrupt and stealing, then per-CPU one-shot timers and tickless idle, then per-task timers
   delivered as notifications and `SYS_IPC_CALL` with a timeout. Each step runs the SMP gates under
   KVM as well as TCG; KVM is available locally since 2026-10-12.
9. **5.9 Reclaimable kernel memory** (2.5, then 2.3). Write the untyped reset: revoking an untyped
   capability destroys everything carved from it, and only when nothing names or maps any of it is
   the watermark reset and the pins cleared. Then a ring-3 allocator in `init` recycles regions by
   splitting and resetting them. Then turn the static objects into retyped ones: a task's reply
   endpoint carved from its budget at creation and destroyed at teardown, the service endpoints
   carved by `init`. `MAX_DYN_FRAMES` becomes a table sized from the untyped budget. Witness: a
   workload that creates and destroys frames for longer than its region could hold without reuse;
   arm skips the reset.
10. **Proofs: the ROADMAP 3.5 remainder.** Pass the expected type through `rust_cap_lookup` and prove
    a mistyped capability is refused, with `CAP_LOOKUP_TYPE_UNCHECKED` reaching both builds; model
    `ipc_ep_from_slot` and prove IPC authority implies a held endpoint capability; and add a checker
    that every `rust_cap_*` export has a Kani harness.
11. **5.11 A model of the concurrent protocols** (5.5), if decision D9 takes TLA+. The protocols
    where races have actually happened, specified and model-checked: spawn, wait and teardown
    (S125), the kernel-stack claim and park (S20), the TLB shootdown (S124), and revocation against
    lookup under `cap_lock`. A model is a test, so it is held to the control-arm rule: each one ships
    with a seeded defect it must catch. Runs nightly first, gating once it is fast enough.

## 5. Phase C: shrink ring 0, then grow outward

1. **ROADMAP 2.10 phase 2.** The kernel becomes a sealed-block service and the copy-on-write v12
   format lives in `fs_server`. The pointer tree is the Merkle tree, so all metadata is
   authenticated by construction (1.30 closes for good) and the storage half of 2.7a is done.
2. **5.10 The session's grants bounded by the kernel** (1.24), shape set by decision D8. Instead of
   one root carrying the union of a session's rights, `init` gives a session one capability per
   grant, and the path walker starts each walk from the capability with the longest matching
   grant. The kernel's rights intersection then bounds every grant, and `fs_server` is trusted only
   for what it already is: the contents. v12's back-references (phase 3) let the server tell a
   grant's object from a name someone swapped in.
3. **The rest of ROADMAP 2.7a.** The loader and spawn path to ring 3: a spawn server that builds a
   task's address space through frame and untyped capabilities, with the ELF validator staying in
   the Rust core. Then the IDE, SD and eMMC drivers out of the kernel under device capabilities.
4. **ROADMAP 1.8 steps 4 to 8, then 1.2.** Scheduling contexts and budgets, passive servers,
   affinity, more than eight CPUs, targeted shootdown; then the `%gs` per-CPU block, with `swapgs`
   on every entry and exit and the speculative-`swapgs` barriers that go with it.
5. **ROADMAP 3.8.** Kernel ASLR once its two open decisions are taken (behaviour without UMIP, and
   whether the kernel log keeps raw addresses for a `CAP_KERNEL_LOG` holder), and it sits after
   2.7a so there is less ring 0 to relocate. Indirect-branch tracking with gcc's
   `-fcf-protection=branch` first, since it needs no new toolchain.
6. **ROADMAP 3.6 and 3.7.** The audit stream readable through `CAP_DEBUG`, then deterministic
   replay of syscall and IPC traces under QEMU, so an SMP race becomes an artefact rather than a
   rate.
7. **ROADMAP 2.7 drivers**, each in ring 3 under one device capability and the IOMMU: AHCI reads and
   writes, then NVMe, then xHCI with USB keyboards (machines with no PS/2 emulation need it).
8. **ROADMAP 2.6 networking.** IP, UDP and TCP in `netd`, a socket as a tokened endpoint capability
   per connection, DHCP, and `netd` shipped rather than confined to its test build.
9. **ROADMAP 3.9 virtualisation**, last and only if decision D12 wants it: a `CAP_VCPU` object and
   an EPT-backed guest space is a large addition to ring 0, which this plan otherwise shrinks.

## 6. Review, beside everything

**5.12 Independent review** (LIMITATIONS 5.1, ROADMAP 4.1) is the largest remaining risk and the one
item no amount of code closes. What the tree can do is make a reviewer's job small: `CODEOWNERS`
already names the capability and IPC paths. What it needs is decision D11: a second person for
those paths, after which the ruleset requires their approval there only, so the rest of the
pipeline keeps its pace. Until then, an external audit at each release (as the source review of
2026-10-12 was), its findings recorded in `LIMITATIONS.md` and each closed by a gate, and ROADMAP
4.13, the threat model published as a versioned document.

## 7. Decisions the maintainer is asked for

Each blocks only the step named. The recommendation is the one this plan is written around.

| | Question | Recommendation | Blocks |
|---|---|---|---|
| D1 | How `init` narrows the spawner's `CAP_TCB` to READ for the login watcher | Give the spawner's `CAP_TCB` the `MINT` right, so a supervisor can hand out narrowed copies (only ever reduces; S2 already proved) | 2.10 step 3(b) |
| D2 | Authenticate the inode table and bitmaps on the current format now, or wait for phase 2 | Now: a format bump costs a reformat; phase 2 is far off | 5.2 |
| D3 | Measured boot mandatory whenever a TPM is present | Yes, failing closed; TPM-less machines boot with a visible warning | 5.6 |
| D4 | Refuse unanchored volumes on TPM machines; a bounded counter interval; RPMB later | Yes to the first two; RPMB opt-in only, since programming its key is irreversible | 5.7 |
| D5 | Predicted PCRs and a staged second seal for updates | Yes, over signed kernels | 5.8 |
| D6 | Console input becomes a capability, retiring 1.6's ambient read | Yes; console writes stay ambient | 5.5 |
| D7 | `SYS_SPAWN_IMAGE` needs a capability no session holds; exec goes through a file capability | Yes | 5.4 |
| D8 | One capability per grant, bounded by the kernel, instead of a union root | Yes | 5.10 |
| D9 | TLA+ (and its Java toolchain) as a new verification dependency | Yes, nightly first; a full Isabelle model of the kernel is not recommended at this size of team | 5.11 |
| D10 | How releases are signed: key type and custody | Sigstore keyless signing from the release workflow with SLSA provenance, actions pinned by SHA, and tags signed by the maintainer's key | ROADMAP 4.4 |
| D11 | A second reviewer for the capability and IPC paths | The maintainer's to find; the ruleset change follows | 5.12 |
| D12 | Whether to build virtualisation at all | Defer until there is a hosting need | ROADMAP 3.9 |
