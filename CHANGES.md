# Changelog

All notable changes to Horus are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project intends to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a public ABI to break.

**The reasoning behind these lines is in [`docs/history/DEVLOG-2026.md`](docs/history/DEVLOG-2026.md)** —
117 entries recording what was tried, what failed, and how each measurement was taken. In a
security project that record is evidence, not commentary, so it is kept in full rather than
compressed away. Entries here cite finding IDs; their **current** status is in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), never in this file.

---

## [Unreleased]

### Changed

- **Measured boot can be required, and then an unmeasured boot does not proceed
  (`MEASURED_BOOT_REQUIRED=1`).** #197 fixed the CI half — `SWTPM_REQUIRED=1` stopped four gates
  passing without measuring — but the kernel still booted happily with no TPM: PCRs unextended,
  volume key never sealed, S11/S12 simply not applying rather than failing closed. The flag makes
  every unavailable measured boot fatal (no TPM, locality, transport, PCR readback) and refuses
  to unlock a **persistent volume that was never sealed**. That second half is where the real
  downgrade lived: the sealed path already fails closed when the TPM denies (S12), but nothing
  checked the reverse, so a re-formatted password-only disk made the requirement evaporate —
  `tpm_mode == 0` turns `apply_tpm_kek_binding` into a no-op.
  **Default behaviour is unchanged** and deliberately so; this kernel is expected to boot on
  TPM-less machines. The ephemeral RAM vdisk is exempt, because its key is generated this boot
  and discarded at power-off — there is nothing for a measurement to protect — and that exemption
  is named rather than implicit, since it makes the refusal branch unreachable on an ordinary
  boot. `MEASURED_VOLUME_EXEMPT_NONE=1` removes it so the branch can be falsified.
  **Three arms**: with a TPM the machine still boots and measures (a refusal-only gate is passed
  by a kernel that halts always); without one it halts; with an unsealed volume it refuses.
  `tools/run_with_swtpm.sh` gained `EXPECT_FAULT`, matching `smoke_test.sh` — it tested its fault
  regex before the required marker, so on a build whose success condition IS a halt no marker
  could ever be reached. Falsified by naming a fault that never occurs: the arm times out and
  fails rather than accepting the halt that did happen.
  **Still not gated**: a persistent disk under the policy. The arm proves the refusal fires, not
  that a real on-disk volume reaches it — stated in `docs/LIMITATIONS.md` §2.9.

- **`hvfs` has users: the libc and the shell walk paths through it (roadmap 2.4).** `posix.c`
  and `shell.c` carried private copies of the walker the namespace library was written to
  replace, and the copies had drifted — the shell resolved `.` and `..` only because it rewrote
  the *string* first, which no libc program goes through, so `open("/a/../a/f")` from any
  newlib program failed with `ENOENT`. Both now call `hvfs_walk` / `hvfs_walk_parent`, and
  `libhorus.a` is linked into the newlib programs to make that possible: the Makefile note
  refusing that link feared "a second memcpy under a different name", and nothing in
  `libhorus.o` is named `memcpy` (the symbols are `u`- and `k`-prefixed). ~200 bytes per binary,
  one walker instead of two. The reversed decision is recorded where the old note stood.

  **`fsclient.c` was never one of the three walkers**, and three documents said it was. It has
  no walker: flat single-name lookups over a private `rpc()` whose bounded retry and selftest
  markers `hvfs_rpc` deliberately lacks. Corrected rather than migrated — changing working code
  to make a sentence true is the wrong direction.

  **And `..` did not work below a mount root in any client.** `hvfs` resolved it by asking the
  server to look up a `..` **entry**; `fs_server` creates none, so the branch returned `NOENT`
  every time. Dead from the day it landed in #195, invisible because the only test touching
  `..` used the *pinned* case, which returns before the lookup. It now pops the walker's own
  descent stack — no round trip, and not something a server can lie about.
  **Falsified two ways**, each aimed at one defect: `POSIX_LEGACY_WALK=1` (the private walker)
  reddens `smoke-newlib` at `FAIL dot-here`, and `HVFS_DOTDOT_SERVER=1` (the shipped `..`
  branch) reddens it at `FAIL dotdot-back` — specifically that marker, since `.` still resolves
  under it and only the descending `..` does not.

- **The syscall-coverage deriver described a kernel that has never booted, in both directions.**
  It read the dispatch table as flat text, so `SYS_OPEN`, `SYS_PREEMPT_TRACE` and
  `SYS_IRQ_POLICY_INFO` — compiled only under a defect arm or a selftest flag — counted as
  shipped; and it matched only `[SYS_NAME]`, so **seven entries written as bare numbers were
  invisible**, five of them live in the ship build. The count was 81; the ship build has 83.
  `scan_table` evaluates the preprocessor now, guarded entries are declared under a new
  `conditional:` section **with the flag that guards each** (so a syscall silently re-entering
  the shipped surface fails the build), and a bare numeric index is refused outright. The seven
  entries are named — `SYS_YIELD` kept a name the table did not use; `SYS_CLEAR`, `SYS_SYSINFO`,
  `SYS_DEBUG_EXEC`, `SYS_EXEC_LEGACY`, `SYS_RAMFS_CREATE`, `SYS_RAMFS_LIST` are new symbols for
  unchanged numbers. `check_doc_claims.py` imports the deriver instead of keeping a second copy
  of the regex, which had inherited both blind spots.
  **Falsified seven ways, one arm per new rule** — and the seventh arm did not fire on its first
  attempt, because it mutated an `#ifdef` earlier in the file than the table and so tested
  nothing. It was rerun against the table region, where it does.
  **What the newly-visible entries turned out to be**: four live handlers with **no userspace
  wrapper anywhere in the tree**, reachable only by issuing the raw number — recorded in
  `docs/LIMITATIONS.md` §2.10 rather than deleted, because removing a syscall is an ABI decision
  and this commit is about being able to see them.
  The blind spot had been written down in prose beside `SYS_OPEN` since 2026-08-22 — **naming the
  wrong three**, since two of the three it named were bare numerics the regex never matched. An
  unenforced note is worth exactly that much.

- **The CSPRNG was safe by boot ordering, not by construction; now it refuses (S30).**
  `RngState::fill` never consulted `seeded`. Asked for output before `entropy_init()` it would
  have run ChaCha20 under the hardcoded startup key in `RngState::new()` — a **published**
  constant, because the build is reproducible — and returned it as randomness. Nothing reached
  it: `entropy_init()` runs before the first consumer and halts if the pool did not take. That
  is an ordering fact about one call site, not a property of the RNG, and it is what a refactor
  moves; the same shape as the frame refcount in #192. `fill` now returns false and zeroes the
  caller's buffer while unseeded, and `rust_rng_u64()` — which returned a `uint64_t` and so had
  **nowhere to put a refusal** — became `rust_rng_u64_checked(uint64_t *)`, wrapped by
  `secure_random_u64()`. Both C wrappers halt on a refusal, the way `entropy_init` already did.
  **No live defect and no finding ID**; the point is that the claim is now the RNG's own.
  **Falsified three ways**: `smoke-rng-seed-control` (`RNG_UNSEEDED_LEGACY=1`, the check
  compiled out) serves keystream to a probe placed before the seed, 3 boots in 3, and reddens
  the base gate; `cargo test --features rng_unseeded_legacy` fails `rng_refuses_before_seeding`
  and only that test; and an `if true` mutation making `fill` refuse *everything* reddens the
  base gate on its boot half, which is also the only execution of the C halt path.

- **The Rust staticlib named five of its fifteen source files as prerequisites.** Editing
  `rng.rs`, `aead.rs`, `ps.rs` or nine others rebuilt nothing and the kernel linked the previous
  `libhorus_shell.a` — a measurement taken against source the binary does not contain, the same
  family as the `-D` flags that survived a flagless rebuild. It is `$(wildcard rust/src/*.rs)`
  now, plus `.build-flags`, so a cargo *feature* change re-runs cargo too. Found while adding
  the arm above, whose control build would otherwise have been measured on a stale library.

- **`smoke-kstack-park` was a required check that could not fail, and it was failing.** The job
  carried job-level `continue-on-error: true` from its advisory days. #190 promoted it by editing
  `.github/ci-gating.yml` and the ruleset and touched no workflow; #191 then rewrote the job
  *name* one line above the mask to delete the word ADVISORY from the published context, and left
  the mask. GitHub publishes a `continue-on-error` job's check run as SUCCESS however its steps
  exited, so for that whole window the ruleset required a context that could only ever be green.
  It was not idle: the job **failed on `main` at 9476799**, and on `a59667ab` before it, inside
  runs GitHub reported green — and `ruleset-audit` could not notice, because it compares context
  *names* and a masked job publishes the right name with the wrong verdict. The mask is gone, and
  `tools/check_ci_gating.py` now **refuses any `required:` job carrying job-level
  `continue-on-error`**, so the combination cannot be reassembled. Step-level `continue-on-error`
  is untouched and still allowed — that is how the `security` job keeps its scanners advisory
  without becoming unfailable itself. **Falsified both ways**: against the tree as it stood the
  new rule names `smoke-kstack-park` and exits 1; with the mask removed it exits 0, and the
  `security` job's four step-level exemptions pass unremarked.

- **The control arm's misses were the instrument, not the schedule — and `KSTACK0_PARK_TRACE`
  turns out to cost ~40% of boots.** `smoke-kstack-park-control` failed on `main` at 9476799 with
  8 misses in 8 boots. #193 had set that budget on the reading that a miss meant one park in the
  whole boot, so `the collision was impossible there` — and from that treated boots as independent
  draws. They are not: those boots ended in `KERNEL FATAL EXCEPTION` and `PROC_SELFTEST: FAIL` —
  the workload **died** before a second CPU could park. Measured on the *fixed* kernel, same
  workload and host, `-smp 4`, 20 boots each: **8 of 20 died with `KSTACK0_PARK_TRACE=1` and 0 of
  20 without it** (Fisher one-sided p = 0.0016). The trace writes through `kfault_*` straight to
  COM1 from interrupt context 5–10 times a boot, and that is enough to kill the run. So the ~40%
  "pre-existing scheduler claim leak" the job's own comment cited as the reason it could not be
  required (9/20 at `-smp 4`) was a measurement of the **instrumented** build all along, and
  [G-9]'s closure is not in question — the uninstrumented build is 0 for 20 here, consistent with
  the 0-in-200 that promoted the gate.
  - The arm now treats a boot the workload died in as **inconclusive**: named, tallied, and
    re-booted rather than counted. `KSTACK_PARK_CONTROL_BOOTS` (8) counts boots that *ran to
    completion*; `KSTACK_PARK_CONTROL_ATTEMPTS` (24) caps the total. Exhausting the attempts is a
    red with **different wording**, because a run that could not measure must not read like one
    that measured and found nothing. Nothing is weakened: the assertion is still that the defect
    MUST reproduce, and of the boots that complete it reproduced **10 out of 10**.
  - **A wrong fix was tried first and is recorded because it nearly shipped.** Counting "parked,
    then the kernel died" as a third witness looks sound — the base arm requires the fixed build
    to complete the same workload, so the pair appears to differ by exactly that. Falsifying it
    against the fixed build produced boots of 6, 10 and 8 parks and then one park and a
    `KERNEL FATAL EXCEPTION`: the identical shape, with no shared park anywhere in the build. A
    witness that fires on the fixed build is not a witness.
  - **Falsified in the other direction, in the target's exact form**: with `KSTACK0_SHARED_PARK=1`
    removed from `smoke-kstack-park-control` and nothing else changed, the arm ran 8 conclusive
    boots (6 parks each, no shared stack) and went red on the "did NOT reproduce" branch rather
    than the "could not measure" one.
  - `docs/ROADMAP.md` listed **four** exemptions beside a count that said three: `smoke-kstack-park`
    stayed in that list for eleven days after #190 promoted it. A count and a list that disagree are
    two claims, and `doc-claims` can only check the one that is a number.

- **An external security audit was checked against the tree, and two residuals it surfaced are
  now documented** (`docs/LIMITATIONS.md` §2.8, §2.9). Ten of its twelve findings duplicate
  existing `[C-5]`, `[C-6]`, `[I-7]` or §5.4 entries and are left where they are rather than
  filed twice.
  - **§2.8** — `RngState::fill()` did not test `seeded`, so the CSPRNG was safe by the order of
    two calls in `kernel_main` rather than by the function that could enforce it. **The audit
    overstated this**: its recommended fix ("panic or refuse output until `seeded=true`")
    already existed in `entropy_init()`, which halts if unseeded and runs before the first
    consumer — so the claimed weak ASLR/canaries/nonces were not reachable. What remained was
    the same shape as #192's frame refcount: a safety property held up by a fact nobody
    enforces. **Closed 2026-08-23 (S30) — see the entry at the top of this section.** Recorded
    in the past tense the day it closed, because §2.8 open here and closed in
    `docs/LIMITATIONS.md` is one finding carrying two statuses, which is the drift these
    entries exist to prevent.
  - **§2.9** — the kernel proceeds without a TPM, so S11/S12 do not apply rather than failing
    closed. The CI half closed in #197; the kernel half is a design question and is recorded as
    one.
- **§2.6's fix design is corrected.** It described TPM-sealing the password pepper; that was
  superseded on 2026-08-22 in favour of putting the user table inside the AEAD object store,
  where the already-sealed volume key protects the hashes and **the pepper stops needing to
  survive the reboot at all**. Smaller, stronger, and it works without a TPM — which the sealed
  pepper did not, on the common case.


- **`smoke-kstack-park` promoted from advisory to merge-gating**, one merge after [G-9] closed —
  the shape its own exemption asked for ("promote it in the same commit that closes [G-9], and
  quote a rate"). The rate: the `PROC_SELFTEST -smp 4` workload it boots ran **0 failures in 200
  boots** after the fix (95% upper bound 1.49%), against ~45% before [G-9]'s exec and page-table
  components and ~7% after them; the gate itself passed 5 of 5 in its exact form, which at a 7%
  rate is ~70% power and is corroboration rather than evidence. **No CI exemption now stands for
  an open defect** — the three that remain (`fuzz`, `kani`, `ruleset-audit`) are properties of
  those tests, not of the tree.

### Fixed

- **Four TPM gates could report success while measuring nothing.** `tools/smoke_tpm.sh` and
  `tools/run_with_swtpm.sh` both `exit 0` when `swtpm` is absent — so `smoke-tpm`,
  `smoke-tpm-tamper`, `smoke-tpm-seal-roundtrip` and `smoke-tpm-seal` (a **required**
  merge-gating job carrying **S11** and **S12**) printed `SKIP` and passed. `SWTPM_REQUIRED=1`
  now makes that an error, and CI sets it on all four. Locally the skip stays, because blocking
  a developer without swtpm buys nothing. **CI had in fact been installing swtpm all along** —
  verified against a real run's log, where the measured PCRs are present and match the
  host-computed manifest — so this was latent rather than live; a renamed package or a changed
  runner image would have been enough. Falsified in a genuinely swtpm-less environment (a
  `PATH` stripped of it): skip and exit 0 without the flag, hard failure with it. **The
  end-to-end arm is what caught the first fix being incomplete** — `smoke_tpm.sh`'s own inline
  guard swallowed the flag before the shared code ever saw it.

### Added

- **`tools/swtpm_lib.sh`** — the swtpm lifecycle in one place (state dir, daemon, socket wait,
  teardown), shared by `run_with_swtpm.sh`, `smoke_tpm.sh` and `smoke_test.sh`'s new `TPM=1`
  mode. Any gate can now boot under an emulated TPM without a second copy of the QEMU command
  line; `KEEP_TPMSTATE` carries one TPM across two boots for sealing tests.
- **`make run` boots with a TPM when `swtpm` is present**, so the system you actually run is the
  measured-boot one the security properties are stated over. `NO_TPM=1` or `make run-plain`
  forces the fallback, which should stay easy to reach deliberately rather than by accident.


- **The user-database persistence path had never run, and is deleted.** ~90 lines in
  `src/kernel/kusers.c` — `users_save_to_ramfs`, `users_load_from_ramfs`, `users_persist` and
  its four call sites, plus the integrity tag over them — removed as code that could not have
  worked, for three independent reasons any one of which was fatal: `ramfs_write` took no
  offset so only the last of four writes survived; nothing persisted the ramfs and the load ran
  at boot against a zeroed `.bss` table, so it opened nothing every boot since it was written;
  and **password hashes are boot-local by construction** — `kernel_pepper` is fresh random every
  boot and feeds both the set and the verify, so a stored hash can never verify in the next
  boot whatever it is stored in. The honest state is now written down: accounts are seeded from
  constants each boot and last until reboot (`docs/LIMITATIONS.md` §2.6).
- **The in-kernel ramfs left the ship build with it.** Its ring-3 surface went with **[H-3]**
  and the user database was its last real consumer, so it is now compiled only under
  `RAMFS_SLOT3_GATE` — the control arm that restores those four gates and needs something
  behind them. Measured: **`.bss` −36,864 bytes, `.text` −4,096**. `main.c` calls
  `storage_init()` directly rather than `ramfs_init()`, which was a misnamed wrapper around it
  plus two demo files.
- **A required gate would have quietly stopped measuring.** `smoke-passwd-probe-control`
  asserted on the probe opening the *user database* file; with that path deleted nothing writes
  it and the check would have passed **trivially in both arms**. Retargeted to a seeded file.
  Separately, restoring the four slot-3 gates onto an *empty* store reproduced only **2 of 4**
  doors — open and read had nothing to find — so the control build now rebuilds `ramfs_init()`
  with its seeding. Both were caught by running the arm rather than by reasoning about it.
  **S28 is unchanged**: the property was never about what sat behind the gates.


- **[H-3] Four paths into the in-kernel ramfs were gated on the [C-1] decoy, and one of them
  is where the user database lives.** `SYS_OPEN`, syscall 15 (ramfs create), syscall 16 (ramfs
  list) and `SYS_READ`'s `fd >= 3` branch all authorised on cspace slot 3 with `SC_ANYTYPE` —
  and slot 3 holds the legacy `CAP_FRAME` that `create_task` installs in every task, with
  `READ|WRITE|EXEC`, asked for by nobody. A gate every task passes is not a gate. These were
  the last four still wearing the shape that made **[C-1]** reachable, and they survived
  **[I-1]** and **[H-1]** because those swept for authority derived from *identity*, and
  survived §1.6's own sweep because that looked for gates that were *absent*. A gate that is
  present and vacuous matches neither search. Demonstrated from ring 3 as the ordinary uid-1000
  account holding no delegated capability: opened the user-database file, read bytes out of
  three ramfs files, created a file, listed the store. **Retired rather than re-gated**,
  following syscalls 38–45 — the ramfs is a toy superseded by `fs_server`, nothing in ring 3
  calls any of them, and an ABI kept alive for nobody is surface with no owner. `SECURITY.md`
  **S28**; witness `make smoke-passwd-probe`, falsified by `RAMFS_SLOT3_GATE=1`.
- **`docs/LIMITATIONS.md` §1.6's "complete residual list" was not complete.** It named the four
  paths gated on *nothing* and missed the four gated on a capability *equivalent to* nothing.
  Corrected, with the generalisation written down: "ungated" and "gated on something every task
  holds" are the same security property and were being counted differently.


- **`smoke-kstack-park-control` asserted a probabilistic event from a single boot**, and had
  been merge-gating for one day when it reddened an unrelated PR. A *shared* park needs two
  CPUs to reach the park path in the same boot, which is a property of the schedule rather than
  of the build: measured 2026-08-22 it reproduces **9 boots in 12** on a feature branch and
  **10 in 12** on unmodified `main`. (This entry originally added "and every miss recorded
  exactly one park in the whole boot — `the collision was impossible there`, not merely
  unobserved". That reading was wrong, and the entry below corrects it.) So a one-boot assertion is
  about 25% red. It now boots up to `KSTACK_PARK_CONTROL_BOOTS` (8) times and stops at the
  first reproduction, which is the shape `smoke-kstack-race-control` has carried since
  2026-08-19 for exactly this reason ("never assert a probabilistic event from one boot"); the
  arm next door simply never got it. Nothing is weakened — the assertion is still that the
  defect MUST reproduce, drawn from a sample large enough to mean it. (It also claimed
  "at 75%/boot a clean sweep of 8 is `~1 run in 65000`" — an independence argument the entry
  below withdraws.) **Falsified in the other direction**: against the *fixed* park path
  with tracing on, 8 boots produced 32 parks and no shared stack, so the loop still goes red
  when the defect is absent rather than being a way to pass.
- **That arm also scored its own strongest reproductions as misses.** It gated on duplicated
  `PARKTRACE` lines and deliberately excluded the kernel's collision PANIC, on the grounds that
  the PANIC needs both CPUs parked at the same instant. But `sched_note_park` *halts* the
  machine on detecting the second CPU, so on precisely those boots the second `PARKTRACE` line
  is never printed and the duplicate test sees one. Observed on 2026-08-22: a boot whose log
  carried `PANIC: two CPUs parking on one kernel stack` was scored as no reproduction. Either
  signal now counts; the PANIC cannot be a false positive, because it is the kernel observing
  the exact event asserted.

- **`smoke-kstack-race` went red on `main` after the [G-9] fix, and it was a real
  regression rather than a flake.** That fix needed one property — the claim auditor's
  exemption must outlive the claim release — but it also moved the `g_kstack_inflight`
  clear inside the scheduler lock, which the property never required. Under
  `KSTACK_RACE_WIDEN` the wider critical section pushed the session past its 90-second
  budget and it never reached the login prompt. The bit now clears outside the lock as it
  always did; the control arm still reproduces on boot 1, so the narrower lock did not
  weaken the fix.
- **The legacy `CAP_FRAME` in slot 3 was a decoy waiting to become a defect.** Every task is
  born holding one — `READ|WRITE|EXEC`, object `USER_AREA_BASE`, identical in every task — and
  it is the capability that made **[C-1]** reachable when the dispatch table gated IPC on slot
  3. Giving `CAP_FRAME` a meaning put it back in play: under the obvious design, where
  `capability_t.object` holds a physical address, `SYS_MAP_FRAME(3, ...)` maps physical
  `0x400000` into ring 3 on the first boot from a capability the kernel hands out itself. A
  frame capability therefore names an **index** into a table the kernel populates, so the
  decoy is refused by a bound rather than by an allowlist. `FRAME_INDEX_UNCHECKED=1` is that
  kernel, and it reproduces on every boot. The decoy is kept rather than deleted: `captest`
  needs it for six C-1 regression checks, and it is now the negative test vector for the map
  path as well.
- **A mapped frame could have been returned to the free page stack, and was not, by luck.** An
  untyped-arena page sits inside `[USER_PHYS_BASE, pool ceiling)` and so has a refcount slot,
  and `free_user_table` releases every present leaf of a dying task's page tables. Nothing
  stopped a mapped frame's bytes being handed out as an anonymous page while the untyped region
  still owned them, except that a never-allocated arena page sits at count 0 and
  `rust_page_ref_dec` fails closed on an already-zero frame — a value nobody set on purpose
  holding up a safety property. The untyped region now takes a permanent reference of its own,
  every mapping adds one, and the count can never reach 0. It also gives the object GC its
  liveness test: above 1 means a live PTE somewhere, and a frame with one is not collectable.
- **`untyped_bump` aligned the region-relative watermark, not the address it returned.** Correct
  only while every region base happened to be a multiple of `KOBJ_ALIGN` (64), which nothing
  requires; at `KOBJ_FRAME`'s `PAGE_SIZE` alignment it stops being true the moment a region
  starts anywhere but a page boundary, and a misaligned "frame" would be truncated down onto
  whatever object shares its page — cross-object aliasing that reads as data corruption rather
  than as a permission error. It now pads the absolute arena address, and alignment is per
  object class.
- **A stale ABI comment claimed `SYS_DMESG` was root-only.** `include/syscall.h` documented it
  as `ROOT ONLY (uid==0)` while the dispatch table has gated it on `CAP_KERNEL_LOG` + READ
  since **[I-1]**; `docs/SYSCALLS.md` already said so correctly. It was the last surviving
  ambient-uid-0 claim in the tree, in the header every userspace program includes, contradicting
  **S18**.

### Added

- **A VFS mount table and one path walker** (roadmap 2.4, finding **[F-2.2]**).
  `userspace/hvfs.c` maps a path prefix to the cspace slot holding that filesystem server's
  endpoint capability, so crossing a mount point is choosing a different slot. **It is a
  library, not a server, and that is the security decision**: a VFS server would have to hold a
  capability to every backing filesystem, making it the most privileged task in ring 3 and a
  single point whose compromise is a compromise of every mount — the monolithic trust 2.4
  exists to avoid. `SECURITY.md` **S29**. Longest-prefix match, `..` pinned at the mount root,
  and a mount refused unless the slot holds a usable capability.
- **`dev_server`**, a second filesystem server serving `/dev/null` and `/dev/zero` over the
  existing `fs_proto`. What matters is what it does **not** hold: one capability, the listen end
  of its own endpoint — no `CAP_ENCRYPTED_STORAGE`, no `CAP_BOOT_MODULE`, no `CAP_USER`. A
  filesystem server that structurally cannot touch the encrypted store, mounted in the same
  namespace as one that can. A single server owning both necessarily holds both sets.
- **`smoke-vfs`** (required job `vfs`), 14 checks, with control arms `VFS_FIRST_MATCH=1` and
  `VFS_MOUNT_UNGATED=1`. Routing is asserted by **which server answered**: under first-match
  `/dev/zero` reaches the root filesystem, which has an inode 0 of its own and so answers about
  a different object rather than failing.


- **Frame capabilities and capability-mediated shared memory** (roadmap 2.1, finding
  **[F-2.1]**). `KOBJ_FRAME` is retyped out of a `CAP_UNTYPED` by the existing `SYS_RETYPE`,
  so a page of shared memory is paid for by untyped authority somebody holds rather than
  conjured by a syscall. `SYS_MAP_FRAME(frame_slot, vaddr, rights)` and `SYS_UNMAP_FRAME` map
  it into the caller's own address space; the PTE is built from `cap->rights & requested`, so
  a mapping can never carry authority the capability does not. Two mutually distrusting tasks
  share one physical page at two virtual addresses, and a `READ`-only delegate can see the
  bytes and not write them. `SECURITY.md` **S26** and **S27**.
- **`SYS_CAP_MINT` is reachable from ring 3.** Syscall 4 has been in the dispatch table since
  the beginning as an unnamed numeric literal, and nothing in userspace could call it: it was
  absent from `include/syscall.h` entirely. That mattered more than it looked, because
  `SYS_CAP_GRANT` passes `CAP_RIGHT_ALL` unconditionally — so **ring 3 had no way to reduce
  rights at all**, and "delegation may only ever reduce" was a property of the kernel's
  internals that no userspace program could exercise or witness. Sharing a page read-only is
  now mint-then-grant. Syscalls 4/8/9 are named constants in both headers now rather than
  literals in the table.
- **`smoke-frame`** (required job `frame`), with control arms `FRAME_INDEX_UNCHECKED=1` and
  `FRAME_RIGHTS_UNCHECKED=1`. Two ring-3 tasks, 22 checks, 3 boots in 3 on every arm.

- **`libhorus`, the shared runtime for freestanding userspace** (`include/libhorus.h`,
  `userspace/libhorus.a`). Replaces 22 hand-copied definitions across 7 files. Linked as an
  archive so a program that uses none of it pays nothing — `captest`'s `.text` is
  byte-identical to before it existed.
- **`ipc_call_retry`** makes the IPC retry contract a library guarantee: retry only while
  `ipc_transient()`, bound even that, and return a permanent refusal unretried. The
  pre-libhorus loop spun on `SYS_ERR_PERM` forever, turning a capability denial into an
  indistinguishable hang (**[G-8]** signature C). Two programs had independently re-derived
  the correct loop; it is now written once.
- **`smoke-libhorus`** (required job `libhorus`), with control arms `LIBHORUS_RETRY_ANY=1`
  and `LIBHORUS_STRNCPY_UNTERMINATED=1`. The first executable witness that a permanent IPC
  refusal is not retried — the property had been asserted by comments and tested by nothing.
- **`$(call USERPROG,name)`**, so adding a freestanding program is one line. Capability
  delegation stays hand-written in `init.c` on purpose: a macro that guessed would be a macro
  that granted.

### Changed

- **[G-9] is reproducible now** — 2–4% of boots on `PROC_SELFTEST` at `-smp 4`, captured
  per-boot (2/60, 3/80, 1/80). It previously took "eighteen boots across three builds, by hand".
- **[G-9]'s recorded signature was wrong.** Every document described a claim held by a CPU that
  had *gone idle*. All five 2026-08-21 captures show the holder **running another live task**,
  owing no deferred release and not impersonating — so the leak is **not** in the
  deferred-release machinery, which is where the two previous fixes went.
- Four leads killed with instruments rather than arguments (`CLAIM_TRACE=1`, zero hits in 220
  boots): deferred-slot overwrite, `sched_enter_user` owing a release, a declined release in
  `sched_release_deferred`, and the SYSCALL fast path (unreachable — `EFER.SCE` is never set).
- **[G-9]'s scope is wider than recorded.** The scheduler claim leak was documented against
  `PROC_SELFTEST` at `-smp 4` (~40% of boots, always task 3). On 2026-08-21 the same shape
  appeared in the **default boot** — `init` spawning the shell, task 4, on an idled CPU — at
  1 boot in 120. A control on the preceding commit was 0 in 270; the difference is not
  significant (Fisher p ≈ 0.31) and is recorded rather than concluded.
- **`smoke-sched-invariants-stress`'s green runs never established what they were read as.**
  Thirty boots has ~26% power against a 1%-per-boot event. `TESTS.md` now states the power
  beside the sample size. The gate stays **required**: unlike `smoke-kstack-park`, which is
  advisory because it reddens for a defect it does not test, this gate tests the claim
  invariant and what it caught was a claim leak. A red here is a [G-9] reproduction to
  capture, not a flake to re-run.

### Fixed

- **[G-9] root cause found: a switch was committed before its resume value was validated.**
  `task_exit_switch()` returns `0` both for "nothing runnable, caller parks" and — via
  `ksp_refuse()` — for "I already claimed `next`, but its resume value is bogus". Its three
  callers cannot tell those apart, so they park the CPU and the claimed task is orphaned
  forever. The resume guard added *for* [G-9] is what created this. All four switch paths now
  validate before committing. Deterministically gated by `smoke-switch-commit` /
  `smoke-switch-commit-control` (`SWITCH_COMMIT_EARLY=1` + `KSP_GUARD_INJECT=1`).
  This was one of three components; see below.

- **[G-9] is CLOSED.** Its last and largest component was not a scheduler defect at all: the
  claim auditor's own exemption, `percpu_deferred_release[]`, was cleared *before* the lock that
  drops the claim, so an audit landing in that window accused a release that was in flight. The
  checker's second false positive — 2026-08-09 was the first, reading a deliberate impersonation
  as a leak. Fixed by clearing the exemption last, under the same lock. Natural rate **9 in 200
  boots → 0 in 200** (Fisher p = 0.0036); mechanism proven deterministically, **8/10 against
  0/10** with `DEFER_WINDOW_WIDEN=1` set in both arms (p ≈ 0.0007). Gated by
  `smoke-defer-exemption` / `-control` (required job `defer-exemption`).

- **`sched_enter_user()` reached ring 3 without paying its deferred release.** It carried a
  second hand-written copy of the ISR epilogue that omitted `call sched_release_deferred`, so a
  CPU arriving there while owing a release orphaned that task's claim — and its
  `g_kstack_inflight` bit, which makes the **[G-8]** detector report a collision that is not
  happening. Latent in current workloads; fixed because it is wrong, not because it explains
  the observed leak.

### Added

- **The invariant that makes the class non-recurrable:** *a CPU in ring 3 owes no deferred
  release*, asserted in `preempt_on_tick` under `SCHED_INVARIANTS`. The periodic claim audit
  **cannot** catch an unpaid debt — it exempts exactly that state as a legitimate mid-handover —
  so an orphaned release hides inside the exemption that keeps the auditor honest. Gated by
  `make smoke-claim-release` (required job `claim-release`), falsified by `CLAIM_RELEASE_SKIP=1`.
- `CLAIM_TRACE=1`, an instrument recording claim provenance and reporting two orphaning events
  as they happen.

### Fixed

- `fsclient.c`'s `put_int` negated a signed `int` (`(unsigned)(-v)`), which is undefined for
  `INT_MIN` and reachable, since the value printed is an IPC rc a server chooses. libhorus's
  `kput_int` accumulates in unsigned.

- `tools/check_defect_flags.py` and the required `defect-flags-documented` job. The
  defect-flag table in `docs/BUILDING.md` claimed to be the complete list and was not:
  `RESUME_RSP_INJECT`, `RESUME_RSP_INJECT_PRECLAIM` and `WAL_CRASHTEST` had no row, and one
  appeared nowhere in the file. The claim is now derived from the Makefile rather than asserted.

### Changed

- The changelog is versioned. The 117 narrative entries that were this file moved to
  [`docs/history/DEVLOG-2026.md`](docs/history/DEVLOG-2026.md), which is exempt from the
  documentation ratchet because a historical record reports a past state rather than
  asserting a present one.
- The G-8/G-9/G-10/G-11 investigations moved out of `TESTS.md` into
  [`docs/investigations/`](docs/investigations/) and are cited from the three documents that
  used to retell them. `TESTS.md` 2327 → ~1180 lines.
- The two audit documents merged into `docs/AUDIT.md`, the July 2026 one as Appendix A.
  `docs/proposals/console-server.md` moved to `docs/design/`, since it records what was built.
- The README's assurance banner states the standing position instead of narrating every
  finding's history, which the linked documents already do authoritatively.

### Removed

- `src/kernel/shell.c` and `userspace/include/captest.c` — 1396 lines of byte-identical,
  never-built source superseded by `src/kernel/kshell.c` and `userspace/shell.c`.
- Three prototypes in `src/include/kernel.h` with no definition and no caller anywhere:
  `console_putc`, `console_puts`, `untyped_selftest`.
- `tests/`. Its one file defined its own `struct capability` and its own `cap_lookup` and
  tested those; the real `capability_t` has a `uint64_t object` and a `generation` field —
  the use-after-revoke backstop — and the copy had neither, so no kernel regression could
  have failed it. `tests/README.md` also claimed `make test` ran it, which nothing did. The
  binding coverage it pointed to is now listed in `TESTS.md`.
- `.build1.sha` / `.build2.sha`, tracked since the initial commit and holding the same stale
  `kernel.elf` hash.

### Fixed

- Four stale citations, each pointing at unrelated code: `docs/BUILDING.md` sent readers
  ~1,980 lines from `smoke-irq-policy`, `docs/ARCHITECTURE.md` cited the wrong *file* for
  `SYS_IPC_RECV_BLOCK`, and `kspawn.c:188` had drifted ~156 lines in three documents. Where a
  line number will drift again, the symbol is named instead.

---

## [0.1.0] — 2026-08-21

The first tagged state of Horus: a capability-based x86-64 microkernel that boots on hardware
and under QEMU, drops to a ring-3 shell, and runs ordinary C programs — including GNU
coreutils and TCC — with its filesystem and console drivers in userspace.

**This release is research-grade.** It has not been independently audited, and
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) is the honest accounting of what it does not do.
Version `0.1.0` marks a coherent starting point for versioned change, not a readiness claim.

### Added

**Capabilities and the object model**

- A capability is `{type, rights, object, badge, serial, generation}`, held in a per-task
  cspace and named only by slot index, so ring 3 can never see or forge the struct.
- Mint derives a child with `rights & new_rights`: delegation can only ever *reduce* authority.
  Grant pushes a capability into a supervised child, never upward.
- Revocation is system-wide and subtree-scoped, backed by serial-keyed generation counters as
  an independent second mechanism. Both must hold. Machine-checked by Kani proofs.
- Kernel objects — cspaces, endpoints, notifications — are carved from untyped memory via
  `CAP_UNTYPED` and `SYS_RETYPE`, replacing fixed `.bss` tables (**[I-7]**). `tasks[]` remains.
- IPC is capability-addressed: every IPC syscall names a cspace slot, and the kernel derives
  the endpoint from the capability there (**[C-1]**, **[C-2]**).
- One-shot reply capabilities and per-task private reply endpoints, making reply forgery
  unrepresentable rather than merely refused.
- Endpoints are a bounded FIFO with a blocking receive that sleeps on an empty queue
  (**[I-5]**), plus async notifications and bounded byte-stream pipes.

**Memory and scheduling**

- Per-task 4-level page tables, demand paging, copy-on-write, NX stacks, kernel W^X swept
  rather than asserted, unmapped stack guard pages, 30-bit userspace ASLR.
- Preemptive scheduling at 100 Hz (PIT, or per-CPU LAPIC under SMP) with full trap-frame
  context switches and a microarchitectural flush between distrusting tasks.
- SMP on by default: ACPI MADT enumeration, INIT-SIPI-SIPI bringup, a shared runnable pool,
  acknowledged TLB-shootdown IPIs, and SMT siblings parked in software to close the
  co-residency side channel.

**Storage and boot integrity**

- `fs_server` in ring 3 over an AEAD-encrypted kernel object store, enforcing POSIX rwx
  against a **kernel-attested** uid (`SYS_IPC_SENDER`) that a client cannot forge.
- A write-ahead journal with mount-time fsck, and double-indirect block mapping for large files.
- Per-`(inode, block)` AEAD subkeys under a hierarchical rollback MAC; key material never
  leaves the kernel.
- SHA-256 boot-module manifest embedded in the kernel image; TPM 2.0 measurement into PCR 8
  and 9; the vdisk KEK sealed under `PolicyPCR`.

**Userspace**

- Ring-3 `init` (PID 1) that delegates every capability its children hold and supervises the
  shell with a blocking `SYS_WAIT`.
- `console_server` in ring 3 owning the UART and VGA framebuffer, with raw terminal mode.
- A shell with pipelines and redirection, a newlib libc port, GNU coreutils, and TCC.

**Assurance**

- `kernel.elf` is byte-for-byte reproducible, verified by building twice and diffing in CI.
  `boot.iso` is not; see [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) §5.3a for why.
- Every boot prints `DEFECT FLAGS: <list>`, so a serial transcript records the configuration
  that produced it, and a flag change forces a rebuild.
- Fifteen defect-reproducing control arms, each rebuilding a specific closed defect on demand
  so its gate can be falsified rather than trusted.
- Which CI jobs may block a merge is a checked-in decision in `.github/ci-gating.yml`,
  enforced by the `ci-gating` job (**[C-6]**, mechanism half).
- Documented counts are derived and gated by `tools/check_doc_claims.py` (**S22**), control-arm
  structure by `tools/check_gate_pairs.py`, and the defect-flag table by
  `tools/check_defect_flags.py`.

### Fixed

Security-relevant defects closed before this release. Each has a falsified witness; the
control arm is named in [`docs/BUILDING.md`](docs/BUILDING.md).

- **[C-1]**, **[C-2]** — IPC endpoints were not capability-addressed, so any ring-3 task could
  intercept or forge messages to any userspace server.
- **[C-3]**, **[C-3.1]** — one global IRQ nesting counter shared by every CPU, incremented
  non-atomically, with an unconditional `sti` on release. The lock is per-CPU and restores the
  caller's own `RFLAGS.IF`.
- **[C-4]** — user copies truncated instead of refusing.
- **[H-1]** — the user database still granted authority for ambient `uid == 0`, for nineteen
  days after three documents said that authority had been retired. It now tests `CAP_USER`.
- **[H-2]** — a ring-3 write to fd 1 was appended to the kernel message ring with no authority
  tested, though the *read* side had required `CAP_KERNEL_LOG` since **[I-1]**.
- **[I-1]** — ambient `uid == 0` authority across the root-gated syscalls.
- **[I-2]** — 32-bit truncation in the heap syscalls and the pager's region gate.
- **[I-3]** — a revocation closure an unprivileged task could force to over-approximate,
  destroying unrelated peers' authority. Now exact.
- **[I-5]** — a single-slot endpoint, replaced by a bounded queue.
- **[I-6]** — `this_cpu()` read LAPIC MMIO on every call.
- **[I-10]** — the write-ahead journal had no `FLUSH CACHE` barriers and was not durable on
  real hardware.
- **[I-11]** — the journal recovery test ended on a signal rather than a process exit.
- **[G-8]** — a switch path handed a task to another CPU while the CPU making the switch was
  still executing on that task's kernel stack. Measured over 1600 alternating boots: the
  pre-fix release site fails 31/800, the shipped one 0/800. A second path — every CPU whose
  last task died parking on `tasks[0]`'s stack — was closed with it.
- **[G-10]** — a page-table use-after-free giving a cross-address-space read/write primitive
  reachable from ring 3, plus the unserialised spawn staging around it.
- **[G-11]** — the armed program image was ambient state, so `SYS_SUDO` would elevate whatever
  was armed to uid 0 whether or not the authenticating task had staged it.

### Known open

- **[C-5]** — no independent review of security-critical changes. Single maintainer.
- **[C-6]** — reconciling the branch ruleset to `.github/ci-gating.yml` is still a manual step
  that lags a merge.
- **[G-9]** — a scheduler claim leaks and kernel stacks collide on the spawn/reap path under
  SMP. Two components fixed, taking it from ~45% of boots to roughly 1–2%; the rest is open.

The full list, with what each means for a reader, is in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

---

[Unreleased]: https://github.com/pharanyx-labs/Horus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pharanyx-labs/Horus/releases/tag/v0.1.0
