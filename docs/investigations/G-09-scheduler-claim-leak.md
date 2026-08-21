# G-9: a scheduler claim leaks on the spawn/reap path under SMP

*Extracted from [`../../TESTS.md`](../../TESTS.md), where it was one section of a test
catalogue. The narrative is kept in full: in this project the reasoning is the evidence, and
the record of which hypotheses were wrong is the part worth reusing.*

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md); the gates that
witness it are listed in [`../../TESTS.md`](../../TESTS.md).*

---

**Status: CLOSED 2026-08-21.** Natural rate 9 in 200 boots → 0 in 200 (Fisher p = 0.0036),
with the mechanism proven by a deterministic control pair rather than by that rate. See the
final section below.

**Found 2026-08-17 by `smoke-kstack-park`, and pre-existing.** `PROC_SELFTEST` at `-smp 4`
violates the claim invariant on ~40% of boots. Nothing had run that workload at more than one
CPU before: `smoke-proc` boots it uniprocessor, where it is clean 20/20.

```
PANIC: stale scheduler claim at preempt_on_tick: task 3 claimed by cpu 2
       but that cpu was running 0 (persisted across two audits; observed by cpu 1)
```

Always task 3 — the driver that spawns and reaps — and, *in the 2026-08-17 captures*, a CPU that
had gone idle while still holding the claim. **That last clause did not generalise**: the
2026-08-21 captures below all show the holder running another live task, not idling, which is
what moved the search off the deferred-release machinery. Read it as one observed shape rather
than the finding's definition. "Persisted across two audits" is the two-strike guard, so it is a leak
and not a mid-flight snapshot.

> ### Scope, widened 2026-08-21: this is not confined to `PROC_SELFTEST`
>
> Everything below was measured against `PROC_SELFTEST` at `-smp 4`, and the finding was
> written as though that workload were the whole of it. It is not. On 2026-08-21 the same
> shape appeared in the **default boot** — no selftest workload at all, just `init` spawning
> the shell — under `SCHED_INVARIANTS=1`:
>
> ```
> PANIC: stale scheduler claim at preempt_on_tick: task 4 claimed by cpu 1
>        but that cpu was running 0 (persisted across two audits; observed by cpu 3)
> ```
>
> Task 4 is the shell; the claiming CPU is idle. It is the same leak — a claim left behind by
> a CPU that then went idle — at a far lower rate: **1 boot in 120**, against ~40% for
> `PROC_SELFTEST`. A control measurement on the immediately preceding commit was 0 in 270,
> but the difference is not significant (Fisher exact, p ≈ 0.31) and one event does not
> support a rate estimate worth quoting. See `TESTS.md`, "the claim invariant fired again".
>
> **Two consequences.** The blast radius is wider than this document said — the leak is
> reachable from the ordinary boot path, not only from a spawn-and-reap stress driver. And
> `smoke-sched-invariants-stress`, a required gate at 30 boots, has roughly a **26% chance**
> of catching a 1%-per-boot event, so its green runs have never established absence at this
> rate. Neither fact changes the mechanism below; both change what its absence is worth.

| Configuration | Boots | Failed | Stale claim reported |
|---|---|---|---|
| `-smp 1` | 20 | **0** | 0 |
| `-smp 4` | 20 | 9 | 8 |
| `-smp 4`, `KSTACK_RELEASE_EARLY=1` (pre-#162 release timing) | 20 | 10 | 9 |

**The third row is the load-bearing one:** 10/20 against 9/20 is no difference (Fisher p ≈ 1.0),
so this is not [G-8]'s deferred release misfiring. The leak predates both G-8 fixes. What they
changed is that it is now *visible* — before them this workload failed **20/20** on the shared
park, and a defect that kills every boot hides every other defect behind it.

**Both directions of the invariant break, and the second one does damage.** A boot showed
`claim: task 1 running_cpu=-1  percpu_current=[0,0,1,0]` — a task running with no claim, which
makes it selectable by a second CPU. The consequence was observed, not inferred: two CPUs on one
kernel stack, caught by the stack canary in `h_write`.

**How it was found is the useful part.** Without `SCHED_INVARIANTS` the failures present as a
mix — over 25 boots: 10 pass, 7 supervisor `#PF` (instruction fetch at `rip=0x2/0x12/0x82`, a
return through a corrupted pointer), 5 stalls with no marker, 3 canary trips. Three shapes, one
cause, and no way to tell from any single one. Two wrong diagnoses were published before the
right instrument was used:

1. **"The park trace corrupts the marker."** `KSTACK0_PARK_TRACE` does write straight to COM1
   and does interleave with ring-3 output — that is real, and is why the trace is now barred from
   any gate matching an exact string. But it was **not the cause**: with the trace removed the
   failure rate was 10/25, identical to 10/25 with it. The statistic first offered as proof —
   "gate failure and corrupted marker correlate 10 for 10" — was a *tautology*, since the gate's
   assertion **is** that marker. It could not distinguish any hypothesis from any other.
2. **"The 4 KiB I took off the idle stack."** Enlarging it to `PAGE_SIZE + KERNEL_STACK_SIZE`
   gave 12 passes in 25 against 12 KiB's 10 in 25, with canary trips going **up**, 3 → 5. The
   enlargement was kept because the park path having the room it had before the move is right on
   its own merits, but it fixed nothing here.

What actually resolved it was making `__stack_chk_fail` say where it fired. It had printed
`PANIC: stack smashing detected` and nothing else — no function, no CPU, no task — and through
`print()`, which is klog-only once a ring-3 console server owns the console, so a smash during a
live session emitted **nothing on the wire at all**. That is #140's defect, still sitting in the
canary handler because nobody had looked. It now reports `__builtin_return_address(0)` — which
*is* the faulting function, since the canary is checked in that function's epilogue — plus the
CPU, the task and the claim dump. The first run with it said `h_write`, `task=1`, every time,
which is what turned the search from the write path to the scheduler.

**Next step:** find which path leaves a CPU idle holding a claim. `sched_enter_user()` is worth
looking at first — it has its own inline `iretq` epilogue and so bypasses `isr_common_stub64`,
and with it `sched_release_deferred()`. Offered as a lead with its check named, not a diagnosis.

#### 2026-08-21 (final): the last component was the checker, not the scheduler

**The defect.** `percpu_deferred_release[]` is not merely a CPU's note of work owed. It is the
**claim auditor's exemption**: `sched_assert_claims()` skips a claim while the holder's deferred
slot names it, on the correct reasoning that such a claim is mid-handover.
`sched_release_deferred()` cleared that slot *before* taking the lock that drops the claim:

```c
percpu_deferred_release[cpu] = -1;   /* exemption gone */
__sync_fetch_and_and(&g_kstack_inflight, ~(1ULL << t));
sched_raw_lock();                    /* another CPU can audit throughout here */
task_running_cpu[t] = -1;            /* claim dropped only now */
```

For the width of a lock acquisition the task is claimed, un-exempt and mid-release. A CPU
auditing in that window sees exactly what a leak looks like. **It is not one** — the auditor is
reading a torn intermediate state of its own exemption protocol.

**This is the auditor's second false positive**, the same family as 2026-08-09, where it read a
deliberate spawn-time impersonation as a leak. Both times it observed its own exemption machinery
mid-update. *A checker that exempts a state must hold the exemption for the whole of that state.*

**The fix.** Clear the slot last, under the same lock that drops the claim. The
`g_kstack_inflight` bit still clears *before* the claim, for the reason recorded at its
declaration — the other order leaves a task claimable with its bit still set, which makes the
**[G-8]** detector report a collision that has already ended.

**How it was found, after four wrong hypotheses.** Last-write provenance was not enough: it said
"claimed by `preempt_on_tick/next`, never released" while the chokepoint watching for a CPU
abandoning a claimed task stayed silent — two things that cannot both be true of one history. So
the code was made to record the history itself: a ring of every write to `task_running_cpu[t]`
plus the deferred lifecycle. Every healthy cycle logs `defer-CONSUME → consume-SAW → release`;
every panicking one stops between the first two, i.e. inside the lock acquisition. That is not a
leak — it is a CPU part-way through the release.

**Falsification, and why it had to be deterministic.** The natural event is ~4.5% with variance
wide enough that 200-boot arms cannot separate 4.5% from 6.5%: the baseline itself ran 2/50 and
then 9/200, and an intermediate measurement of 13/200 was briefly read as a regression before a
significance test showed p = 0.39. `DEFER_WINDOW_WIDEN=1` stretches the window and is set in
**both** arms:

| Arm | Boots | Panics |
|---|---|---|
| widened, exemption held to the end (shipped) | 10 | **0** |
| widened, `DEFER_CLEAR_EARLY=1` (pre-fix) | 10 | **8** |

Fisher p ≈ 0.0007. Gated by `make smoke-defer-exemption` / `smoke-defer-exemption-control`
(required job `defer-exemption`).

**What 0 in 200 does and does not establish.** It bounds the residual natural rate at **under
1.49%** at 95% confidence. It is not proof of zero, and this document was burned once today by
reading a clean run as absence — the "30 runs, 0 failures" row corrected earlier had only 26%
power against a 1% event. The deterministic pair, not the clean run, is the evidence.

#### 2026-08-21 (later): a root cause, found, fixed and deterministically gated

**One real cause is closed. The finding is not.** The natural rate went from ~2–4% to
**2 in 130 boots (1.5%)** — an improvement that is *not* statistically distinguishable from
the old rate, and a second path is still leaking. Read this section as one cause removed, not
as a fix for the whole finding.

**The cause: a sentinel collision in `task_exit_switch()`.** It returns `0` for two
incompatible things:

```c
if (next < 0) { ...; return 0; }             /* nothing runnable -- NO claim taken */
...
task_running_cpu[next] = cpu;                /* claim taken */
set_current_task(next);                      /* CPU committed to it */
if (ksp_is_bogus(ksp)) return ksp_refuse();  /* ALSO 0 -- claim already taken */
```

All three callers in `idt.c` read it identically — `if (rsp) return rsp;` and otherwise park
the CPU at `resume_shell_after_fault`. So a refusal is indistinguishable from an empty run
queue: the CPU parks, and `next` stays claimed **forever**, skipped by every selection loop,
unschedulable by every CPU including the holder.

**The resume guard added *for* [G-9] is what commits the switch before validating it.** The
instrument installed to catch this leak was creating one.

**Why four days of investigation walked past it.** The audit reports the corpse ~10ms later at
`preempt_on_tick`, a site with nothing to do with it, because that is simply where the next
tick ran. The claim invariant structurally cannot name the culprit — which is why the search
kept returning to the deferred-release machinery.

**Deterministic reproduction.** `KSP_GUARD_INJECT=1` forges the bogus value and
`SWITCH_COMMIT_EARLY=1` restores the old ordering. Every boot:

```
DEFECT FLAGS: KSP_GUARD_INJECT SWITCH_COMMIT_EARLY
SCHED BOGUS KSP from task_exit_switch task=2 ... refusing, parking this CPU instead
PANIC: stale scheduler claim: task 2 claimed by cpu 0 but that cpu was running 0
```

Note `running 0` — the **idle** variant this document originally described. The later captures
showed "running another live task" only because the parked CPU had picked up new work before
the audit ran. **Both recorded signatures are the same bug**, which is worth knowing: the
"corrected" signature above and the original are not two findings.

**Fix: validate before committing.** All four switch paths now check the resume value before
claiming `next`, installing its address space, or naming it current — so a refusal has no state
to unwind. Releasing the claim on the refusal path was considered and rejected: it publishes a
task whose saved frame is known bogus.

**A residual behaviour, stated rather than discovered later.** With the fix, a genuinely bogus
resume value is refused by each CPU in turn instead of being locked away behind a leaked claim.
That is a loud stall rather than silent corruption of the claim invariant — a deliberate trade,
and the better of the two.

**Gated:** `make smoke-switch-commit` / `smoke-switch-commit-control` (required job
`switch-commit`).

**What is still open, and the next lead is specific.** 2 in 130 boots post-fix (5 captures in
total across 220), every one `last claimed by task_exit_switch/next`, and the
`set_current_task` chokepoint probe does **not** fire for any of them.

That absence is evidence rather than a dead end. The chokepoint only reports a CPU moving *off a
live claimed task*; it cannot see a CPU diverted **between** claiming `next` and reaching
`set_current_task(next)`. In `task_exit_switch` that gap is five statements wide:

```c
task_running_cpu[next] = cpu;          /* claimed here */
sched_mark_kstack_inflight(cpu, dead);
switch_cr3(tasks[next].cr3);           /* <-- faults here and the claim stands */
uint64_t kstop = task_kstack_top(next);
set_tss_kernel_stack(kstop);
set_current_task(next);                /* only now is the CPU "on" next */
```

If anything in that gap faults or diverts, `percpu_current_task[cpu]` still names the **dead**
task — state 0, and therefore exempt from the audit — so the chokepoint is silent, the claim on
`next` stands, and the CPU is later seen running something else entirely. That matches all five
captures exactly.

**Next step:** bracket that gap. Record entry and exit around it per CPU, and report any CPU
that enters and does not leave. `switch_cr3()` is the first suspect — a stale or freed `cr3` is
[G-10] territory, and [G-10]'s page-table use-after-free was closed on evidence gathered before
the `percpu_cr3` tracking existed.

#### 2026-08-21: a reproduction, a corrected signature, and four leads killed

**Still open.** What changed is that it is now cheap to reproduce and the recorded signature was
wrong in a way that had been sending the search to the wrong machinery.

**A reproduction, at last.** `PROC_SELFTEST` at `-smp 4` reproduces on **2–4% of boots**, captured
per-boot rather than by hand. Three campaigns: 2/60, 3/80, 1/80. Earlier work put this at
"eighteen boots across three builds, by hand"; it is now one loop.

**The signature is not what every document says.** Everything above — and `LIMITATIONS.md`,
and `TESTS.md` — describes a claim held by a CPU that has *gone idle*. Every capture shows the
holder **running another live task**:

```
PANIC: stale scheduler claim at preempt_on_tick: task 3 claimed by cpu 3
       but that cpu was running 1 (persisted across two audits; observed by cpu 2)
  last claimed by: preempt_on_tick/next on cpu 3
  task state=1 runnable_ctx=1 deferred_on_holder=-1 impersonating=0
```

Three facts follow, and together they move the search:

1. the claim was taken as an **incoming** task by `preempt_on_tick`, which is legitimate;
2. the holder owes **no deferred release** (`deferred_on_holder=-1`), so the epilogue ran and
   paid its debt;
3. **no impersonation** is involved, so the 2026-08-09 `percpu_real_task[]` machinery is not it.

So the leak is **not in the deferred-release path** — which is where the two previous fixes went.
Something moves a CPU off a claimed task without any release running.

**Four leads killed by instruments, not arguments** (`CLAIM_TRACE=1`, zero hits across 220 boots):

| Lead | Instrument | Result |
|---|---|---|
| `percpu_deferred_release[]` is one slot, overwritten unconditionally | report the overwrite | **never fired** |
| `sched_enter_user()` reached owing a release | report a pending debt there | **never fired** |
| `sched_release_deferred()` declines when the claim names another CPU | report the decline | **never fired** |
| The SYSCALL fast path skips the epilogue | read `EFER.SCE` | unreachable by design — `SCE` is never set |

Also verified rather than assumed: `get_current_task()` is per-CPU, so `ipc_caller` always names
the CPU's own task; both AP park sites leave `percpu_current_task` zero; and `ksp_refuse()` halts
loudly rather than leaking.

**One real defect found and fixed, and it is not this leak.** `sched_enter_user()` carried a
second hand-written copy of the ISR epilogue that omitted `call sched_release_deferred`. Any CPU
reaching ring 3 through it while owing a release orphaned that claim *and* leaked the task's
`g_kstack_inflight` bit — which is worse than the claim, because a stuck bit makes the **[G-8]**
detector report a collision that is not happening. The probes prove the path is not taken in this
workload, so this is latent rather than the observed leak; it is fixed because it is wrong, not
because it explains anything.

**The structural half, which is the durable part.** A new invariant — *a CPU in ring 3 owes no
deferred release* — is asserted in `preempt_on_tick` under `SCHED_INVARIANTS`. It exists because
`sched_assert_claims()` **structurally cannot** catch an unpaid debt: it deliberately exempts a
task whose holder's deferred slot names it, on the correct reasoning that such a claim is
mid-handover. An orphaned debt therefore hides inside the exemption that keeps the auditor
honest, and surfaces ~10ms later at a site that had nothing to do with it — which is why every
report for this finding has named `preempt_on_tick`. Gated by `make smoke-claim-release`,
falsified by `CLAIM_RELEASE_SKIP=1` (fires, naming the owed task; silent 0 in 30 without it).

**What the next session should do first.** Give the *release* side the provenance the claim side
now has: record which site last dropped each claim. The claim side alone cannot distinguish
"never released" from "released, then re-taken by a path that should not have" — and that
distinction is the remaining question.

#### Narrowed 2026-08-17: the exec hand-off component, fixed and falsified

**The lead above was wrong, and so were the two that followed it.** Kept, because the pattern is
the point: each was a real shape in the code, and each was killed by an instrument rather than
by an argument.

1. **`sched_enter_user()` bypasses the stub.** True, and irrelevant: every caller is a boot-time
   path on the BSP, where no deferred release is ever pending. It cannot leak.
2. **The unguarded "defensive claim" in `preempt_on_tick`** (`scheduler.c:1459`) claims without
   testing `tasks[cur].state` while its release is gated on `ring3`. A genuine asymmetry — and a
   probe recording the site of every claim found it wrote **none** of the leaked ones.
3. **`create_task()` inheriting a stale claim through slot reuse.** It really does not reset
   `task_running_cpu[id]`, and a probe at the reuse point fired **zero times in 20 boots**.

What resolved it was asking a question that did not presuppose a path: *did anything leak, and
what last touched it?* A probe at the point where a CPU installs a task without an ISR epilogue
behind it caught the defect in the act on the first instrumented run:

```
CLAIMORPHAN: cpu 0 entering task 1 at exec_reenter_switch while still claiming live task 3
  percpu_current=3  deferred=-1  state=1
```

`percpu_current=3` while entering task **1**: a CPU consuming an exec re-entry for a task it was
not running. `g_exec_reenter_task` was a single global, consumed by `idt.c` on the exit of every
syscall on every CPU with no test of ownership. The thief claims the exec'ing task, installs its
CR3 and resumes the frame the exec tail just fabricated — while the core that ran the exec is
still executing on that frame. One race, all three signatures above.

**Fix:** per-CPU storage behind `exec_reenter_arm()` / `exec_reenter_take()` (`kspawn.c`), so the
sharing is removed rather than guarded, plus a one-comparison assertion in `exec_reenter_switch`
under `SCHED_INVARIANTS` as the standing witness.

**Falsification.** Control arm `EXEC_REENTER_GLOBAL=1` restores the shared slot. Pinned to two
host cores, `-smp 4`:

| Arm | Boots | Pass | exec-steal | stale claim | CPL-0 fault | stall |
|---|---|---|---|---|---|---|
| fixed | 30 | 22 | **0** | 2 | 6 | 0 |
| `EXEC_REENTER_GLOBAL=1` | 20 | 10 | **5** | 0 | 4 | 1 |

0 in 30 against 5 in 20 is Fisher p ≈ 0.008. Gates: `make smoke-exec-reenter` (the wrong-CPU
report must be **absent** over `EXEC_REENTER_RUNS` boots) and `make smoke-exec-reenter-control`
(it must be **present** in at least one). Both assert on the marker, not on the boot's exit
status, because the workload still fails 2 boots in 30 (~7%) on the rest of **[G-9]** — the
bogus resume `%rsp` — and gating on completion would turn this pair into a detector for that
instead of a witness for this property. (This paragraph read "~27% of the time on **[G-10]**"
until 2026-08-18: that was the rate before [G-10]'s page-table half landed, and [G-10] itself
closed that day.)

**A measurement that lied, recorded because it nearly shipped.** An earlier run of the fix
reported **0 claim panics in 20 boots** and looked like a clean close. It was built with the
diagnostic scaffolding still in — a scan of every task slot on every ISR exit — and that
perturbation hid both residues below. The unscaffolded table above is the real one. The rule this
re-earns: *the arm you measure must be the arm you ship.*

**G-9 stays OPEN.** Two residues remain, neither of them the exec race:

- a stale claim in the **boot/spawn phase, before any exec runs** — 2 in 30, e.g. `task 1 claimed
  by cpu 3 but that cpu was running 0` immediately after `PROC_SELFTEST: begin`;
- a CPL-0 fault in **6 of 30 boots**, `vec=14 errc=0x2` (supervisor *write* to a non-present
  page), resolving via `addr2line` to `lapic_eoi` and `interrupt_handler64` — a CPU taking an
  interrupt on a CR3 that does not map the LAPIC. That is an address space reachable before its
  kernel half was built, which points at **[G-10]**, not at the scheduler.

`smoke-kstack-park` therefore **stays advisory**. Promoting it on a partial fix would restore a
required gate that still reddens on 2 boots in 30 (~7%) for something it does not test.

---
