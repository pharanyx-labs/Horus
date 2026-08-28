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

### Added

- **S16 has a witness (`make smoke-fpu`).** `SECURITY.md` claimed "a task cannot read another's
  XMM register file" with a literal em-dash in its witness column, for the life of the project.
  `fpu_save` / `fpu_restore` were real code, called from `interrupt_handler64` on every ring
  transition, and **nothing exercised them** — the **[C-1]** shape exactly: a documented property
  with no test binding it to the code. Found while surveying `SECURITY.md` for roadmap 4.12's
  invariant registry, which exists to make that unrepeatable; this is the first thing it catches.

  The witness is two ring-3 tasks sharing one CPU. `fputest` loads a sentinel into all sixteen
  xmm registers and requires it intact after 64 switches away and back; `fpupeer` never writes an
  xmm register and requires that none of them ever holds that sentinel. `-smp 1` is load-bearing:
  the disclosure needs both tasks on **one physical register file**.

  **The load, yields and read-back are one `asm volatile` block.** Userspace is compiled with
  SSE2 as the baseline, so the compiler may use xmm registers at any point; split across
  statements this would test whatever GCC left behind, and pass or fail on optimisation settings.

  **The arm caught the test before it caught the kernel.** The first version released both tasks
  together and the leak arm reproduced on **2 boots in 3** — because `fpupeer` samples a bounded
  number of times, so scheduled early it could spend its whole window while `fputest` was still
  filling its sentinel buffer, reporting "no leak" having never looked at a moment when there was
  one. Raising the sample count would have hidden the race and left the arm's rate a property of
  the host's timing; that is the `smoke-kstack-park` mistake. The peer is now spawned suspended
  and released by `fputest` itself, from inside the asm block, after the sentinel is loaded and
  before the first yield — its first sample is ordered after the load by construction.

  **Two arms, one per half, and they are separable** — which is the part worth recording.
  `FPU_NO_RESTORE=1` drops the `fxrstor`, so a task inherits the previous task's physical
  registers: the peer reads the sentinel, and the integrity check **still passes**, because
  nothing overwrote it. `FPU_NO_SAVE=1` drops the `fxsave`, so a task is handed a stale image:
  the integrity check fails and the leak check **still passes**, because a stale image discloses
  nothing. One loses state, the other leaks it. A single `FPU_BROKEN` flag would have reddened
  both markers at once and shown neither check could fail on its own.


- **A forked child inherits its parent's capabilities as DERIVED copies (roadmap 2.3, S41).**
  `cap_clone_cspace` gives the child a copy of every capability the parent holds, in the same
  slot, each with its **own fresh serial** and a `badge` naming the parent capability's serial —
  the edge `revoke_subtree` walks. The child's authority is therefore a *subtree* of the
  parent's: fork adds no new **root** to the capability graph, and every revocation that would
  have swept the parent's capability sweeps the child's with it. Closes
  `docs/LIMITATIONS.md` §2.11, open since #220 landed the memory half the day before.

  **A cspace is an array of `capability_t`, so this looks like a `memcpy`,** and that is wrong
  in two independent directions — which is why each is a control arm rather than a sentence:

  **Identical serials** (`FORK_CSPACE_FLAT_COPY=1`). `rust_cap_revoke_global`'s sweep nulls
  every capability whose serial matches the revoked root's, in *every* cspace, because a serial
  is supposed to name exactly one capability. Duplicate one and the child revoking its **own**
  slot destroys the parent's — a cross-task revocation primitive available to any task that can
  fork, which is every task. Revocation is meant to flow down the derivation tree; this makes it
  flow sideways.

  **No parent edge** (`FORK_CSPACE_ORPHAN_COPY=1`). A fresh serial with `badge` left alone is
  not derived from anything: a second **root** of the capability graph holding the parent's
  authority. `mark_children_of` never marks it and its serial matches no revocation root, so
  revoking the parent's capability leaves the child's working. This is finding **3.3**'s shape —
  a capability keyed to a serial no sweep reaches — applied to a whole cspace at once, and it is
  the hole `docs/LIMITATIONS.md` §2.11 was opened to record.

  **Neither is avoided by getting the copy right; both are avoided by not writing the copy.**
  The loop calls `rust_cap_grant_into`, which is what `SYS_CAP_GRANT` uses, so a forked
  capability and a delegated one are the same object by construction rather than by two
  implementations agreeing. **[H-3]** is what happens when they stop agreeing.

  **Four things are not inherited, and each would be impersonation rather than delegation.**
  Slots 0–3 and slot 4 are the child's own identity — the parent's slot 0 names the **parent**,
  so copying it would mint a `CAP_TCB` over the parent that the parent never held in a
  delegatable form, and slot 4 is the private reply endpoint whose entire value is that nobody
  else has it (finding **C-1**). `CAP_REPLY` is skipped **by type** wherever it sits: one-shot,
  and two holders is reply forgery. Hitting `MAX_CAPS_PER_TASK` fails the whole fork rather than
  handing over a slot-order-dependent prefix of the parent's authority — the same all-or-nothing
  argument **S35** makes about a partly-installed mapping.

  **Rights are not narrowed**, unlike the console capability `SYS_SPAWN` masks to `WRITE`, and
  that is a decision rather than an omission. Spawn hands authority to a *different program*;
  fork's child is the same program at the same instruction. A silently reduced copy would break
  `if (fork() == 0) serve();` with nothing to report it, and the program would have the parent
  grant the rights back — achieving nothing but a less legible graph. `rust_cap_grant_into`
  still intersects with the source's rights, so a copy never carries more than the parent held.

  **Witness `make smoke-fork`**, which reads the derivation graph directly with
  `SYS_CAP_ENUMERATE` — `serial` and `badge` are the graph's nodes and edges, so the invariant is
  checked structurally, with no rendezvous between parent and child and no timing assumption.
  Falsified one arm per rule by `smoke-fork-cspace-flat-control` and
  `smoke-fork-cspace-orphan-control`, both of which also redden the base gate. The four S41
  checks deliberately do not short-circuit: an early exit on the first would leave the later ones
  unreachable from any arm, which is a check that cannot fail.


- **`SYS_FORK` (101): a child that gets its own copy of its parent's memory, lazily
  (roadmap 2.3, S39 and S40).** `clone_user_aspace` (`src/kernel/paging.c`) builds the child's
  address space as a copy-on-write clone of the caller's — both trees point at the same physical
  frames with `PAGE_WRITE` cleared and `PAGE_COW` set, refcounts raised — and leaves the break
  itself to `cow_break_pte`, which was written in the previous change for a caller that did not
  yet exist. Fork adds no copying path of its own.

  **The parent's leaf is downgraded too, and that is the property.** Downgrading only the
  child's is what this looks like from outside — "the child gets copy-on-write" — and it leaves
  the parent writing through a writable mapping of a page the child reads. That is not a copy:
  it is one process with two schedulable contexts, sharing one stack. `FORK_SHARE_WRITABLE=1`
  is that kernel, and the witness catches it from both sides.

  **A mapped kernel object refuses the fork outright (S40).** S38 already refuses the *break* of
  an arena page, and leaning on it would have been leaning on a fault-time refusal: the fork
  succeeds, two tasks exist, and whichever writes first is killed at an unpredictable later
  instruction on a page it was entitled to write a moment before. Refusing the clone reports the
  same policy while the caller can still act on it. The alternative that reads most reasonably —
  clone the frame *writable-shared*, since a frame **is** shared memory — is worse: the child
  would hold a live mapping of a kernel object that no capability of its own names, so revoking
  the parent's `CAP_FRAME` would sweep the parent's PTE and leave the child's behind.

  **Gated on the same capability as `SYS_SPAWN`** (slot 3, `WRITE|EXEC`), and deliberately not
  `SC_NONE`. Fork names no object and a task copying itself reaches nothing new, both of which
  are true and neither of which is the point: an ungated `SYS_FORK` would be a second way to
  create a task standing beside a gated one, so revoking slot 3 would stop a task spawning and
  not stop it forking — and "this task can create no more tasks" would quietly stop being true.

  **The child does not inherit its parent's cspace**, and that is recorded as a limitation
  (`docs/LIMITATIONS.md` §2.11) rather than done quietly. Copying capabilities as they stand
  would leave the child's keyed to a serial no revocation sweeps — finding 3.3's shape applied
  to a whole cspace, and a revocation hole reachable from ring 3 by anything that can fork. It
  gets its own commit. Also not inherited: the port-I/O grant, the file master key, and every
  in-flight kernel rendezvous. The child **is** born runnable, unlike a spawned one, because
  fork performs the child's whole endowment inside the syscall — there is no window for a
  supervisor to lose, which is the only reason spawn suspends.

  **Witness `make smoke-fork`**, falsified by `smoke-fork-share-control` and
  `smoke-fork-arena-control`, both of which also redden the base gate. **The witness had to be
  falsified before the kernel was:** its first version had a failing child report and exit, so
  under `FORK_SHARE_WRITABLE=1` the run printed a `FAIL` and then a `PASS` — the child had died
  before writing the page the parent's own check reads. A failing child now dies through a null
  write and the parent reads `TASK_EXIT_PAGEFAULT` back with `SYS_TASK_EXIT_INFO`; the manner of
  its death is the one channel a forked child still has to its parent.

### Changed

- **A page belonging to a kernel object is never copied out from under it (roadmap 2.1, S38).**
  `cow_break_pte` refuses any physical page inside the untyped arena. Roadmap 2.1 posed this as
  *"what does a COW break mean for a capability two tasks hold"*, and the answer is that it must
  not happen — it would be **two** holes at once.

  **Resource authority.** The shared branch calls `alloc_user_physical_page()`, the *anonymous*
  pool. A task holding a frame capability would obtain a private writable page that **no untyped
  region ever paid for**. Roadmap 0.3's whole premise is that creating a memory-backed object is
  an exercise of authority the capability graph describes; a COW break conjures one outside that
  graph, which is ambient resource — and this kernel does not have ambient anything.

  **Identity.** The PTE would be repointed at a page no capability names. The mapping silently
  stops being the object, and the frame's `1 + mappings` pin arithmetic stops describing reality
  — which is precisely what `destroy_dyn_frame` reads to decide a run is collectable. A task
  that wants a private copy retypes its own frame from its own untyped and copies the bytes:
  explicit, budgeted, visible in the graph.

  **The guard covers the whole arena, not just frames.** A cnode or an endpoint has even less
  business being copied out from under its object, and a predicate answering only about frames
  would be a narrower guarantee than the caller needs. The arena sits inside
  `[USER_PHYS_BASE, pool ceiling)` and so shares `page_refcounts[]` with the anonymous
  allocator, which is exactly why the generic page machinery would have operated on it happily.

  **NOTHING IN THE TREE REACHES THIS PATH, and that is the reason to guard it now rather than an
  argument against.** Two things prevent it and neither is a statement about frames:
  `user_map_frame_page` sets `PRESENT|USER[|WRITE][|NX]` and never `PAGE_COW`, and
  `rust_validate_page_fault` admits only image, heap and stack. Both are facts about *other
  functions* — the shape **S28** and **S30** turned out to have when someone finally looked, and
  the shape [G-2] had for nineteen days. Roadmap 2.3's `fork` is the function that changes it,
  and a frame mapped inside the heap window already passes the region gate today. Guarding
  before the caller exists is the cheapest this will ever be.

  **The arm is aimed at the half that matters.** `COW_ARENA_UNGUARDED=1`, witnessed by a third
  case in `nzcow_selftest` driven with a **real** `KOBJ_FRAME` at refcount **2**. A freshly
  retyped frame sits at 1 — its permanent pin — and at 1 an unguarded break takes the
  *sole-owner* path: it upgrades the PTE in place and allocates nothing. That would have shown a
  read-only mapping turning writable but not a page appearing outside the untyped budget, which
  is the half that breaks the object model. `NZCOW_SELFTEST: FAIL arena-cow-broken`, 3 boots in
  3, and `smoke-nzcow` goes red under the same flag.

- **[G-9]'s open remainder measured: load-independent, ~2 boots in 20, and invisible to the
  gate that runs the exact build.** A CI failure looked load-induced. It is not. A 2×2 on
  `origin/main` — `{KSP_GUARD_INJECT, not}` × `{12 busy cores, idle}`, n=10 per cell, each boot
  observed for a **uniform 25 s window** — gives 1/10 idle and 1/10 loaded on the clean build,
  4/10 and 4/10 with the injection. **CPU contention changes nothing about the rate**; it
  changes whether a gate is still observing when the violation happens.

  No new finding: this is the remainder of **[G-9]**, which `docs/LIMITATIONS.md` §5.2d has
  carried as open since 2026-08-17, and the rate agrees with the "2 in 30 of these boots" the
  `smoke-exec-reenter` target already records. The measurement adds the load result, the
  injection's contribution (≈4×, expected — that arm parks a CPU mid-switch, which is the shape
  that strands a claim), and the signature on a build carrying **no defect flag at all**: a CPU
  holding a claim on one task *while running another*, at `preempt_on_tick` and
  `enter_cpu_idle`, persisting across two audits.

  **The methodological point is the observation window.** Every one of these gates stops at its
  `REQUIRE_MARKER` and quits QEMU, so a violation later in the same boot is invisible *by
  construction* rather than rarely. A first attempt at this measurement used a different marker
  and returned 6/10 for the same cell — the instrument was moving the window, which is the
  [G-8] trace lesson in a new place. `smoke-exec-reenter` additionally discards its per-boot
  verdict on purpose while the finding is open, and says so inline; when the remainder closes,
  that `rc` becomes assertable and picking it up is part of closing it.

- **The smoke harness threw away the diagnosis at the point of detection.** `FAIL_MARKER` is the
  specific string a gate declares as its forbidden condition; `FAULT_RE` is a blanket
  `PAGE FAULT|Exception! Vector|PANIC|Rejected by validator` every gate inherits. The blanket was
  checked **first**, and its branch printed `SMOKE FAIL: kernel fault/panic on serial` and exited
  — no matching line, no context, log discarded.

  Both halves bit one investigation. `smoke-switch-commit` forbids `stale scheduler claim`; run
  on `origin/main` with every core busy, six boots produced one
  `PANIC: stale scheduler claim at preempt_on_tick` — **its own marker** — and one
  `PANIC: unclaimed running task`. CI reported all of it identically as a generic fault, so a
  gate catching the exact condition it exists to catch was indistinguishable from the workload's
  deliberate page fault.

  **A named detection now outranks the generic backstop**, and both failure paths print the
  matching lines. **No verdict changes**: both statuses exit 1, so only the message differs, and
  the one place a fault is a *success* signal — `EXPECT_FAULT` — keeps its original ordering.
  Making the order depend on which role the fault plays is what keeps that true without
  forbidding the combination outright.

  Demonstrated against the log that caused the confusion: old ordering scores it
  `fault (generic)`, new ordering `marker_fail (named detection)`. Under load,
  `smoke-switch-commit` now names the invariant it tripped instead of saying nothing.

- **`EXPECT_FAULT` did not require the fault, so five control arms could not fail.**
  `tools/smoke_test.sh`'s own header has always said the run *"FAILS if none does"*. The code
  never implemented it: a build that booted cleanly to the login prompt fell through to the
  success paths and exited 0 with the named fault nowhere on the wire. `EXPECT_FAULT`
  **inverted** the verdict for a fault that happened; it never **required** one to happen.

  Every user of it is a control arm whose whole purpose is that a reintroduced defect kills the
  kernel before the login prompt — `smoke-claim-release-control`,
  `smoke-switch-commit-control`, `smoke-resume-guard-negative-control` and the two
  measured-boot-required arms. **All five passed whether or not their defect reproduced**, and
  the only thing that could redden them was a boot too slow to reach the banner: failing on runs
  that prove nothing and passing on runs that *disprove* the defect.

  **Measured, not argued.** `smoke-claim-release-control`'s kernel rebuilt with no defect flag —
  `DEFECT FLAGS: none` on the wire — booted to `horus login:` with the guard string absent from
  the log entirely, and the harness printed `SMOKE PASS`.

  *"A test that cannot fail is not a test"*, and this is the third time the shape has appeared:
  `smoke-ksp-guard` shipped a control arm with no positive counterpart, the resume guard shipped
  a bound rejecting the IST stacks, and now this. Checked over the **complete** log at the end,
  for the same reason `ABSENT_MARKER` is.

  **It was found by chasing a flake**, which is the part worth keeping. A required gate went red
  on a PR whose kernel diff could not reach the code; measuring the arm on both branches settled
  nothing (neither reproduced); and looking at *why the arm could go red at all* turned up an
  arm that could not go red for the right reason.

  **The three outcomes are now distinguished** for the two arms asserting a scheduling-dependent
  fault at `SMP_CPUS=4`: the fault appearing is a PASS; a run that **completes** without it is a
  real miss and fails **at once, never retried** — retrying a miss is how an N-try loop becomes
  a way of passing; a boot reaching neither is INCONCLUSIVE and retried up to
  `*_CONTROL_BOOTS` (3). The other three arms keep their single boot: deterministic defects, not
  timing-bound. Falsified all three ways.

- **`smoke-kstack-race` scored a died-in boot as a broken property.** The base arm ran one
  session and treated two very different outcomes identically: the detector firing — *two CPUs
  shared a kernel stack*, the property broken — and the session failing to complete, which at
  `-smp 4` under a window this build **deliberately widens** so it is entered on every switch
  says nothing about whether two CPUs shared anything. The second is the absence of evidence,
  and it was being scored as evidence against.

  **This is the third time this lesson has had to be learned in one file.**
  `smoke-kstack-park`'s control arm scored its own strongest reproductions as misses, and the
  repair was to call a died-in boot *inconclusive* and boot again. `KSTACK_RACE_CONTROL_BOOTS`,
  forty lines below this target, has carried the sample-size half since 2026-08-19. The arm next
  door got neither — and reddened a PR whose entire kernel diff was an early return in a
  function no live session calls.

  Up to `KSTACK_RACE_BOOTS` (4) attempts now, stopping at the first **completed** session.
  **The property assertion is unchanged and is not weakened**: the detector fails the build on
  sight, on every attempt, and no number of retries can turn a detected race into a pass.

  **The fence that makes the retry honest is that all-inconclusive FAILS.** A kernel that never
  boots must not satisfy the gate by exhausting the loop — the obvious way for a retry to become
  a way of not testing. Inconclusive attempts are named and tallied as they go.

  Falsified in all three directions, because a loop that only ever goes green is not a gate: a
  healthy build passes on the first attempt; `KSTACK_RACE_TIMEOUT=1 KSTACK_RACE_BOOTS=2` makes
  every attempt inconclusive and the gate **fails**; and `KSTACK_RELEASE_EARLY=1` fails on
  **attempt 1** with *"two CPUs shared a kernel stack with the fix in place"*, never retried
  past.

- **A frame capability now describes its own object (S37).** `SYS_FRAME_PAGES(frame_slot)`
  returns how many contiguous pages the `CAP_FRAME` at that slot names. This closes the gap the
  *previous* change opened and recorded: giving a frame a length meant only the task that
  retyped one knew what that length was, so a delegate had to be told out of band or discover it
  by trial-mapping page after page — O(n) syscalls polluting an address space to learn a number
  the kernel already had. **A capability that does not describe its own object needs a side
  channel.**

  **The interesting decision is where the answer did NOT go.** `SYS_CAP_ENUMERATE` already
  reports a capability's type, rights, serial and generation, and a length would have been one
  more field. It lost on authority grounds: that call is gated on `CAP_DEBUG` at
  `CAPSLOT_DEBUG`, a **cross-task observability** capability — so an ordinary task would have
  needed a debug capability to learn about its **own** object, and `CAP_DEBUG` would have begun
  revealing other tasks' object extents in the same change. The capability discipline answers it
  directly: the entitlement to know how big the object is comes from holding a capability that
  names it.

  **It takes a cspace slot and never a frame index**, which is the security property rather than
  a calling convention. The handler needs an index and the caller could just pass one — the
  shortcut `syscall_vm.c` exists to refuse. That would be **[C-1]**'s shape, and something worse
  besides: an **object-existence oracle**. A task holding no frame capability at all could walk
  indices and learn which frames are live, and how large, across every task in the system — a
  side channel on other tasks' allocation behaviour, out of a syscall that looks like it returns
  a number. `FRAME_INFO_BY_INDEX=1` is that kernel; `FRAMETEST: FAIL
  peer-frame-pages-not-an-index`, 3 boots in 3, `smoke-frame` red under it.

  **The arm's marker is the DELEGATE's, and it has to be.** Asked from `frametest`, which holds
  every frame in play, an index and a slot are hard to tell apart. Asked from `framepeer`, which
  holds exactly one delegated `CAP_FRAME` and nothing else, they separate cleanly: slots 1 and 2
  are unassigned in the canonical cspace map and empty in that task, while frame indices 1 and 2
  are live because `frametest` retyped several before resuming it.

  **It is not "a syscall that reads a capability"**, which `userspace/framepeer.c` argues
  against and is right to. It reports the *object's* extent and nothing about the capability —
  not rights, not lineage, not badge — so a holder still cannot discover what authority it has
  without exercising it. It discloses nothing `SYS_MAP_FRAME` withholds from the same holder,
  which could learn the same number by trial-mapping forward.

  It returns a **scalar rather than filling a caller's struct**: no user pointer means no
  pointer to truncate, and issue #176 was a wrapper that truncated one to 32 bits. No rights
  floor (`cap_lookup(slot, 0)`, like `SYS_UNMAP_FRAME`) — the size is not the contents, and
  requiring `READ` would refuse a `WRITE`-only sharer the ability to learn how much it may
  write.

- **A frame capability names a run of pages, not a page (roadmap 2.1's region object, S36).**
  `SYS_RETYPE(untyped, KOBJ_FRAME, count, dest, pages)` carves `pages` contiguous pages as **one
  object**, named by **one** `CAP_FRAME`, mapped and withdrawn whole. This is the other half of
  2.1's virtual-memory objects: yesterday's `SYS_MAP_REGION` maps a run of *capabilities*, and
  this makes the run *one capability*.

  **It is a sized frame, not a `KOBJ_REGION`.** seL4 sizes frames for the same reason, and the
  alternative was worse on maintenance grounds rather than on vocabulary: a new object class
  meant a second capability type, a second index table, a second destroy path and a second GC
  mark, four things that would then have to be kept in step with the four that already exist.
  **[H-3]** is what happens when parallel copies of one idea drift apart.

  **The length is the fifth argument to `SYS_RETYPE`, not a new syscall**, so one authority gate
  covers both shapes. `pages == 0` means one page — which is what every retype written before
  frames had a length passes — so **not one existing call site changed**. A non-zero length on a
  class that has none is **refused, not ignored**: a caller asking for an 8-page endpoint has a
  wrong model, and quietly handing it one endpoint leaves that model uncorrected until it
  matters.

  **Three things the length made newly possible to get wrong**, each now enforced and the first
  falsified. The pages must be **distinct** physical pages rather than `pages` aliases of the
  first. The **span** must be bounded including its last byte, because an address legal for a
  one-page frame can put a four-page run past the user half. And every page must be **pinned and
  scrubbed** — a run pinned only at its head puts page 1 on the free page stack when the task
  dies, and a run scrubbed only at its head leaves the rest of a buffer readable by whoever the
  arena hands those bytes to next.

  **`FRAME_PAGES_SAME_PHYS=1` is the arm, and it aims at the failure that does not announce
  itself.** Advance the virtual cursor and forget the physical one — one of two cursors in a loop
  that reads correctly — and nothing crashes: the caller gets exactly the pages it asked for,
  present, writable, correctly righted, all aliasing page 0. The only way to see it is to write a
  distinct word to each page and read them all back. `FRAMETEST: FAIL sized-pages-distinct`,
  3 boots in 3, and `smoke-frame` goes red under it. It reddens the unmap checks too, which is
  the defect showing rather than the test leaking: `unmap_run` withdraws page *k* by naming
  `base + k`, and under aliasing the PTE does not hold it.

  **The unwind is shared with `SYS_MAP_REGION`**, so a failure part-way *inside* one sized frame
  and a failure part-way *across* a run of slots are the same code — and `FRAME_REGION_NO_ROLLBACK=1`
  now reddens checks at both levels from one flag. **The 64-page ceiling stops being about the
  rollback**: a run is contiguous, so page *k* is `base + k` and the unwind needs no per-page
  state at all. `MAX_FRAME_PAGES` is 64 because `UNTYPED_ARENA_BYTES` is 4 MiB *total*.

  **Giving a frame a length silently disarmed an existing control arm**, which CI caught and the
  local run did not. There are now two functions turning `CAP_FRAME.object` into a fact about an
  object, and `FRAME_INDEX_UNCHECKED=1` was written when there was one: under the arm the address
  resolver behaved as intended and the new *length* resolver applied the bound the arm exists to
  remove, so the legacy slot-3 capability was refused at the length check and
  `FRAMETEST: FAIL legacy-cap-mapped` stopped appearing. The arm went red for want of a failure.
  The property was never wrong and the base gate passed all 48 checks throughout — what broke was
  the measurement. **When you split a function a defect flag mutates, the flag has to follow every
  piece**, and a green base arm says nothing about whether its control arm still fires.

  **Known gap, recorded rather than papered over:** a delegate cannot ask how large a frame is.
  `SYS_CAP_ENUMERATE` reports the capability, not the object behind it, so a sharer has to be
  told the size out of band. Nothing is unsafe — mapping fails closed on an occupied or
  out-of-span range — but a delegated buffer is less self-describing than it should be. Roadmap
  2.1 carries it.

- **A multi-page map that reports failure now installs no page (roadmap 2.1, S35).**
  `SYS_MAP_REGION(first_slot, count, vaddr, rights)` maps `count` `CAP_FRAME`s from consecutive
  cspace slots at consecutive pages — the dual of `SYS_RETYPE(untyped, KOBJ_FRAME, count, dest)`,
  which fills the run it maps. The roadmap had this item blocked on one question: *"a length
  wants a policy for partial failure part-way through a run."* This settles it as
  **all-or-nothing**, and enforces it.

  **The answer is the opposite of the one already in the tree, and that is the interesting
  part.** `untyped_retype` stops at the first failure, keeps what it made, and returns the
  count. Copying that here was the obvious move and is wrong, because the asymmetry is in the
  primitives rather than in taste. Retype's partial result is *complete information* — n
  objects, each named by a capability at a slot the caller computed, all enumerable and
  destroyable. A partial **map** is a hole in a range whose entire purpose is to be addressed as
  a range: the caller does not learn about it at the call, it learns at some later instruction,
  as a fault, with nothing left to say which call left it. And a PTE is authority, so a partial
  map after a reported error hands ring 3 authority it was just told it did not get — fail-open,
  in a syscall whose failure path is the whole point. Rollback is also exactly bounded here and
  is not in retype: this call knows which PTEs it installed, while unwinding a retype would mean
  destroying objects whose bytes the untyped watermark cannot reclaim.

  **It returns 0 or an error, never "3 of 5".** Prefix semantics would put the cleanup on a
  caller that has just been told it failed, and a caller applying the convention every other
  syscall here uses — treat `< 0` as the failure — would silently keep pages it believes it does
  not have.

  **The unwind withdraws only the pages this call installed.** The pre-existing mapping that
  caused the refusal is not one of them and survives. An unwind over the whole *requested* range
  would answer a refused request by destroying the mapping that refused it, which any task could
  aim at a mapping it disliked by asking to map a region across it.

  **FALSIFIED IN BOTH DIRECTIONS, one arm per rule**, because a policy with one arm is half
  measured. `FRAME_REGION_NO_ROLLBACK=1` (`make smoke-frame-region-control`) drops the unwind:
  pages 0 and 1 of the four-page run stay mapped, `FRAMETEST: FAIL region-rollback-page0`, 3
  boots in 3. `FRAME_REGION_ROLLBACK_WIDE=1` (`make smoke-frame-region-wide-control`) unwinds
  too much: `FRAMETEST: FAIL region-rollback-ate-blocker`, 3 boots in 3. Each arm fails **only**
  its own checks, and `smoke-frame` goes red under both.

  **Two details the arms forced.** `frametest` blocks the **middle** of the run, so it fails at
  page 2 of 4 — an unwind that handled only the first page, or only the last, would pass a run
  that failed at either end. And the blocker is the run's **own** page-2 frame, because against
  an unrelated frame `user_unmap_frame_page`'s `expect_phys` test would refuse the wide unmap by
  itself: the check would pass under the arm and the arm would measure nothing. Aim at the range
  logic, not at the guard underneath it. The rollback is then probed *without touching the
  pages* — mapping over a present page is refused, so a single-page map that succeeds proves the
  address is free, where a read would prove it by faulting and killing the task.

  **The per-page decision is now one function**, shared with `SYS_MAP_FRAME`. A region map that
  validated one step less than a single map would be another door of the **[H-3]** shape, and
  two hand-maintained copies of a nine-step check is exactly how one opens.

- **`frametest`'s check count is derived, and it had already gone stale.** `TESTS.md` said 17
  parent checks; the wire says 31. `frametest_checks` joins `captest_checks` in
  `.github/doc-claims.yml`, anchored to a line that *starts* with the call so the `static void
  check(...)` definition is not counted — a deriver that includes its own definition is off by
  one in a way nobody notices until the number decides something. It is quoted in `SECURITY.md`
  as S35's witness, so both occurrences are declared.

- **A sixth door of [H-3]'s shape, on console input (S28).** `SYS_GET_LINE`'s dispatch entry
  declares `SC_NONE`, so its handler is the only gate — and that gate read
  `cap_lookup(8, READ)` with a fallback to `cap_lookup(3, READ)`, **neither type-tested**. Slot 3
  is the legacy `CAP_FRAME` `create_task` installs in every task. Measured before the change:
  `captest`, holding that decoy and no `CAP_CONSOLE`, passed the check and **blocked inside the
  console read** — not merely eligible, actually reading what the user types.

  It survived because a ring-3 console server owns the UART in any live boot and
  `console_hw_owned()` refuses first. That is a *circumstance* — the server being alive — not a
  gate, and it is the same shape as the CSPRNG's boot ordering in #200. The `console_hw_owned()`
  check stays: it answers "do not race the owner", and a question about racing is not an answer
  about authority. `CAP_CONSOLE`, type-tested, no fallback.

  **Found by looking for the class rather than the instance.** `cap_lookup` does not test type —
  by design — so every caller must, and five call sites in this tree did not: two in the
  `DEBUG_SHELL`-only kernel shell, one inside the retired `RAMFS_SLOT3_GATE` arm, and two in
  `h_get_line`. Only the last were live.

  **The arm asserts a STALL**, which the harness could not express: a task admitted to a console
  read prints nothing, so there is no FAIL line to require, and a timeout was unconditionally a
  failure. `tools/smoke_test.sh` gained `EXPECT_STALL`, fenced three ways — a progress marker that
  must appear (or a kernel that never booted would satisfy it), a forbidden marker that must not,
  and no fault. Falsified in all three directions, including that `EXPECT_STALL` without
  `ABSENT_MARKER` is refused outright.

  **The reconciliation that entry needed and did not get.** Moving `SYS_GET_LINE`'s gate changed
  what a test enters, and the manifest saying so — `.github/syscall-coverage.yml` — was written
  and never committed, so the required `syscall-coverage` job held the PR red for three days on
  exactly the drift it exists to catch: *"declared uncovered but its handler DID run"*. It is
  `covered` now, and the reason records the distinction the whole file rests on — captest's check
  is that a task holding no `CAP_CONSOLE` is **refused**, and a refusal decided inside the handler
  still runs the handler. **A syscall can be covered by a test that proves it says no.**

  `docs/SYSCALLS.md` was the more serious half, because it is the ABI reference and nothing
  pointed at it. Its `SYS_GET_LINE` row still read `slot 8 READ, else slot 3 READ` — the retired
  authority, published as current for three days after the handler stopped honouring it. Two rows
  beside it had been stale since 2026-08-22: `SYS_READ` still documented the `fd >= 3` slot-3 path
  and `SYS_OPEN` was still listed as available, when **[H-3]** removed both and the same file says
  so seventy lines higher. A reference that contradicts itself is read at the row, not the essay.

- **A gated numerator does not gate its own remainder (S25).** Four documents state syscall
  handler-entry coverage as *"55 of 81"*, and `doc-claims` has checked both of those numbers since
  2026-08-19. Three of them go on to say how many are left — and that number was written by hand,
  read **25** in two files and **33** in a third, and was **27** in the tree. Three figures for one
  quantity, all wrong, sitting one sentence away from a number no one could get wrong.

  `site/index.html` failed the same way in prose: it credited the measurement to *"the two
  workloads this project tracks"* when it has run over three since the boot-modules session was
  added — on the one page a reader outside this repository ever sees. **A checked number lends its
  credibility to the unchecked sentence beside it**, which is the mechanism, not the excuse.

  `syscalls_uncovered` is now derived from the manifest and declared at all four occurrences, and
  both retired phrasings are in `forbidden:`. Falsified four ways against the live tree: a wrong
  number in a newly-declared occurrence fails; rewording one so its pattern matches nothing fails
  as *"declared here but its pattern matches nothing"*; and each retired phrasing fails on
  reintroduction, in the file it was retired from.

- **Cross-task introspection required "do you hold the audit log's keys" (roadmap 3.6, S32).**
  `SYS_GET_TASK_INFO` accepted `CAP_USER` or `CAP_AUDIT` as well as `CAP_DEBUG` — so
  "do you administer users" and "do you hold the audit keys" were both answers to "may I see the
  process list". Those gates were real (finding I-1 put them there in place of an ambient uid-0
  test), which is exactly why two ambient-authority sweeps walked past them: the failure is
  **bundling**, not ambience. `CAP_DEBUG` alone now.

  **The blast radius was real and is the interesting part.** `proctest` and `fsclient` had been
  endowed with a real `CAP_AUDIT` *for this syscall*, so both were re-pointed at `CAP_DEBUG`. That
  broke `PROC_SELFTEST: FAIL grant-rc` on the first build — `proctest`'s **delegation** test hands
  a child a capability and watches it work through `SYS_READ_AUDIT`, so it genuinely needs a
  `CAP_AUDIT` to delegate. Swapping it would have been least privilege applied to the wrong thing.
  It holds both now, for two stated reasons.

  **Witnessed by the one task that can tell the acceptance sets apart**: `grantee` holds a granted
  `CAP_AUDIT` and no `CAP_DEBUG`. It proves that capability is live via `SYS_READ_AUDIT` first —
  so the refusal cannot be "it holds nothing" — and reads its own info successfully, so it cannot
  be a blanket refusal either. Falsified by `TASKINFO_WIDE_AUTHORITY=1`, under which it reads
  another task's info again.

  **captest's check ORDER turned out to be load-bearing**, and nothing said so. `fail()` calls
  `sys_exit()`, so the suite stops at its first failing check and a control arm sees exactly one
  marker. The cross-check added here fires under `CAP_ENUMERATE_UNGATED` as well — both halves of
  "observing needs `CAP_DEBUG`" fail there — so sitting early in the file it pre-empted
  `cap-enumerate-without-cap-debug`, the marker `smoke-captest-capenum-control` names, and that
  arm timed out waiting for a line captest had exited before reaching. It sits last now, with the
  constraint written beside it: invisible unless you already know `fail()` exits.

- **A monotonic clock, at the resolution `CR4.TSD` allows (roadmap 2.2, S34).**
  `SYS_CLOCK_GETTIME` reports time since boot from the PIT tick counter — 10 ms — rather than
  from the TSC. That is a security decision, not a hardware limit: `CR4.TSD` is set precisely to
  deny ring 3 the cycle-accurate timer that cache and covert-channel attacks between mutually
  distrusting tasks lean on, and a nanosecond clock behind a syscall would hand it back through
  the front door. It is not a claim of side-channel safety — the TSD comment already says the
  mitigation is partial, and a counting loop still builds a finer timer — only a refusal to
  supply one.

  **The control arm's "defect" is that it is better.** `CLOCK_TSC_RESOLUTION=1` reports real
  microseconds off the calibrated TSC: more accurate, more useful, and it undoes TSD. That is the
  arm worth having, because the tempting mistake here does not look like one.

  No wall clock: every id but `HORUS_CLOCK_MONOTONIC` is refused rather than approximated, since
  nothing here reads an RTC and answering `CLOCK_REALTIME` with uptime would be a number shaped
  like a date with nothing behind it. Ambient by design — a coarse count of time since boot is not
  authority over an object.

  **The control arm caught my own mistake, and one checker could not.** The clock's dispatch
  entry first landed inside the `#else` branch of `CAP_ENUMERATE_UNGATED`, so that build had no
  clock at all and captest failed on `clock-monotonic-refused` rather than on the door the arm
  aims at. `smoke-captest-capenum-control` went red, which is exactly its job. What did *not*
  catch it is the syscall-coverage deriver: it models the **ship** build, where the entry is
  present and correct, so a syscall accidentally scoped to a defect arm's `#else` is invisible
  to it. Recorded next to the entry.

  `system_ticks` is 64-bit now. At 100 Hz a `uint32_t` wraps after ~497 days, which was
  irrelevant while nothing read it as a clock and a defect the moment something did: a monotonic
  clock that goes backwards makes every timeout built on it fire early or never. One counter, not
  two, so they cannot drift; `get_system_ticks()` still returns the low 32 bits for the callers
  that only compare small deltas. `PIT_TICK_HZ` moved to `kernel.h` for the same reason — the
  clock converts ticks to seconds with it, and the same constant in two files is a clock that
  silently lies when one of them changes.

- **Miri over the security core, and it found UB in the tests (roadmap 3.8, S33).** 80 `unsafe`
  blocks live in `rust/src`, every one at the boundary where the C kernel hands in a pointer, and
  nothing had ever checked them for undefined behaviour. `cargo miri test` now runs on every pull
  request — 77 tests, ~2 minutes, required, no `continue-on-error`.

  **Three UB sites on the first run, all of them in the harness rather than the library.** A test
  would take `x.as_mut_ptr()`, store it in a `CSpaceDesc`, then reach the same array a second way
  — another `as_mut_ptr()`, or a direct `table[6] = ...` — and the second access retags the array,
  invalidating the pointer the first had already handed to the code under test. The next write
  through it is UB. Sixteen tests in `capability.rs` had that shape, plus
  `memory::refcount_trust_boundary`. Fixed by hoisting one pointer per array and using it
  throughout, which is what the C caller actually does: it holds ONE `struct capability *` and
  passes it twice — one provenance used twice, not two Rust borrows.

  **The library was not at fault, and that was established rather than assumed.** The first fix
  written was a library change: `rust_cap_revoke_global` rewritten to avoid `&mut`, with a
  confident comment about why the aliasing made it necessary. Reverting **only** that change and
  re-running Miri left it clean — so the change fixed nothing, its comment asserted something the
  measurement disproved, and it is not in this commit. Ablate before believing your own fix.

  `.github/miri-scope.yml` classifies every test module as run-or-excused, the job derives its
  `--skip` flags from that file (one list, not two), and `tools/check_miri_scope.py` is falsified
  three ways: a rotted skip entry, an excuse under eight words, and a new module — which defaults
  to RUN, the safe direction, so nothing can be silently skipped.

- **Two Kani proofs were excused from gating for a reason nobody had measured.** #205 put the
  two ELF validators in `manual` on the grounds that they are "corroboration, not the only
  witness" and that one was "the more expensive of the two". Measured the same day: **2 seconds
  each**. Both gate now, and the excuses that stood in for a measurement are recorded as such.
  The two revocation lineage proofs beside them were measured properly and **do not finish in
  1500 s**, so they stay manual.

  **The end-to-end figure in #205 was also misleading, in an interesting direction.** It said
  319 s for eleven harnesses; thirteen harnesses now take **196 s**. More proofs, less time —
  what dominates is the rebuild each `cargo kani --harness` invocation may need, not the solving.
  Both numbers are recorded rather than one, because either alone would mislead whoever budgets
  the job next.

- **`ps` required the capability that rotates the audit chain's keys (roadmap 3.6, S32).** The
  ad-hoc root introspection was already gone — finding I-1 replaced it with a real capability
  check — but the capability init handed the shell for `ps` was **`CAP_AUDIT`**, which also reads
  the audit log and rotates its keys. That is a *bundling* mistake rather than an ambient one:
  the gate was real, it just named far more authority than the caller needed, which is why two
  ambient-authority sweeps walked past it. `CAP_DEBUG` is observation and nothing else, minted
  **READ-only** at the root so no delegation can widen it, and the shell now holds that instead.
  The change **narrows** the shell.

  **The capability graph is observable now**, which is the part of 3.6 that matters: the security
  argument of this system is that graph, and until now it could be read in the source but not
  asked of a running machine. `SYS_CAP_ENUMERATE` (97) reports one cspace slot's type, rights,
  serial, badge and generation; the shell's `capview` walks it and prints the tree. `object` is
  deliberately withheld — `serial` and `badge` **are** the edges, so derivation is fully visible
  without naming what each node points at.

  **Falsified** by `CAP_ENUMERATE_UNGATED=1`, which removes the declared capability so the central
  gate admits everyone; captest — holding no `CAP_DEBUG` — then reads another task's cspace. The
  arm is aimed at the gate rather than the handler because the handler contains no authority check
  at all, by design. Positive half: `smoke-session` runs `capview` and requires the shell's own
  `debug r-----` entry, since "no capabilities anywhere" is what a broken readout looks like.

- **The cspace slot map was written down twice and nothing compared them.** `CAPSLOT_DEBUG` was
  first added as **18**, which `CAPSLOT_UNTYPED` already was, so init's delegation wrote a
  `CAP_DEBUG` into the slot it keeps its `CAP_UNTYPED` in. It presented as "the capability did not
  arrive" — the friendly version; the unfriendly one is a capability arriving where something else
  was expected and being used as it. `tools/check_capslots.py` refuses a duplicate number within a
  header and a disagreement between `kernel.h` and `syscall.h`, and is falsified by both.

  The syscall-coverage deriver also needed a fix this exposed: an entry written into **both** arms
  of an `#ifdef`/`#else` — the shape a control arm takes when it changes a syscall's declared
  capability rather than removing it — was reported as guarded *and* unclassified at once. Active
  wins now, because the question that map answers is whether this build dispatches it.

- **Seven new proofs of the capability algebra, and the first Kani job that can fail
  (roadmap 3.5, S31).** `rust_cap_lookup` and `rust_cap_grant_into` had no harnesses at all.
  Proved now, for every input: lookup succeeds **exactly when** the capability holds every
  requested right — an equivalence, so a lookup that refused too much fails it too, which is the
  mutation a one-directional property misses — and never resolves an empty or out-of-range slot;
  grant yields exactly `requested & source`, records its grantor as the grantee's parent with a
  fresh derived serial, refuses an invalid source **without writing anything**, and is bounded by
  the destination cspace.

  **The proofs did not gate anything, and had not since they were written.** The `kani` job is
  `workflow_dispatch`-only *and* carries `continue-on-error: true` on both of its steps: it never
  ran on a pull request and could not have failed one. Thirteen proofs of the capability algebra,
  none load-bearing — the `smoke-kstack-park` shape (required and unfailable at once) applied to
  formal verification. `.github/kani-harnesses.yml` now classifies every harness, the new required
  `kani-bounded` job runs the eleven that finish (**319 s**, measured end to end — the per-harness
  solver times sum to about three minutes, and the gap is one rebuild per invocation), and
  `tools/check_kani_harnesses.py` fails the build on a proof in neither list. Four are excused with
  reasons: the serial-keyed lineage pair and the two ELF validators, which is what pushed a full
  `cargo kani` past GitHub's 6-hour ceiling.

  **Every new proof was falsified by mutation** — weakening lookup's rights test to "any overlap",
  dropping grant's `& src.rights`, zeroing the recorded parent, removing a bound — and confirmed to
  report `VERIFICATION:- FAILED`. One mutation looked uncaught and **the mutation was wrong**: a
  first-occurrence string replace hit `rust_cap_mint`, 77 lines above the intended
  `rust_cap_grant_into`. That is the second time in one day that trap produced a falsely reassuring
  arm; aimed correctly, the proof failed as it should. The checker itself was falsified four ways,
  one per rule.

- **A fifth door of [H-3]'s shape: syscall 14 created a task for any caller.** `SYS_EXEC_LEGACY`
  read `{ h_exec, 3, CAP_RIGHT_WRITE|CAP_RIGHT_EXEC, SC_ANYTYPE }` — cspace slot 3, the legacy
  `CAP_FRAME` `create_task` installs in *every* task, any type — on a syscall that **creates a
  task**. Measured before removal: `passwdprobe`, running as uid 1000 and holding no delegated
  capability, called it and was handed task id 2. The task it made had no identity of its own —
  `create_task` assigns `state` and never `uid`/`gid`, so a new task carried whatever the slot
  held: 0 on a never-used slot, the previous occupant's uid on a reused one. Since **S18** uid 0
  confers no kernel authority, but `fs_server` enforces file permissions against the
  kernel-attested uid (**S13**/**S14**).

  **It survived the [H-3] sweep because it was invisible to it.** The dispatch entry was written
  `[14]`, a bare number, matching none of the `[SYS_NAME]` patterns that sweep, the coverage
  manifest and every audit grep are built on — and it sat *directly beneath* the comment block
  explaining that a slot-3 gate is not a gate. Naming it in #201 is what made it findable; this
  commit removes it, along with `SYS_CLEAR` (5) and `SYS_SYSINFO` (6), which had no caller
  anywhere in the tree either. `SYS_DEBUG_EXEC` (7) survives only in a `DEBUG_SHELL=1` build —
  before this its *entry* was unconditional and only the handler body was guarded, so the ship
  kernel dispatched it, copied 127 bytes from the caller, and returned −1.

  Numbers reserved as 38–45 are. Witness `make smoke-passwd-probe` (8 checks), falsified by
  `make smoke-passwd-probe-legacy-control` (`LEGACY_SYSCALLS_PRESENT=1`), where the probe is
  handed a task id again. Ship-build dispatch entries: 83 → 79.

  **The coverage checker refused this commit's own first draft**, which is what it is for:
  `#if defined(DEBUG_SHELL) || defined(LEGACY_SYSCALLS_PRESENT)` is a form `scan_table` could not
  evaluate, so it failed closed rather than guessing. It now evaluates `||` and `&&` over
  `defined()` terms, records the whole condition in the manifest (so a guard that gains or loses a
  term fails the build), and **refuses a mixed `||`/`&&` expression** rather than assuming a
  precedence. Falsified both ways.

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
