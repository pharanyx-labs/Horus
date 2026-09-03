# G-12: two CPUs current on one task, through the user-entry path

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md) §5.2g; the gates
that witness it are `make smoke-enter-user-claim` and its two control arms.*

---

**Status: ATTRIBUTED and FIXED, 2026-09-03.** `sched_enter_user()` claimed its task
unconditionally, and the one live launch site published that task as schedulable *before*
calling it -- so an AP's timer tick landing in the window between took the task, and the
entering CPU took it as well. Two CPUs then held one task's single kernel stack.

**Filed 2026-09-02 at 10 marker failures in 3250 boots (0.31% per boot), with two failure
modes and no mechanism.** Everything below is kept in the order it happened: the rate, the two
candidate mechanisms this document positively excluded, the three checker false positives that
were counted as the defect, and finally the mechanism. The exclusions are what made the
attribution findable, and the arithmetic behind each is the part worth reusing.

This is **not** [G-9] reopened. Every mechanism [G-9] names is fixed and falsified, and this
document does not disturb that. What is filed here is the residue that [G-9]'s own record
predicted would remain -- *"a stale claim in the boot/spawn phase, before any exec runs, 2 in
30"* -- measured, still reproducing after the closure, and now with one candidate mechanism
positively **excluded**.

It gets its own number because it has its own evidence and no attribution: calling it [G-9]
would say the mechanism [G-9] describes explains it, and that is exactly what the measurement
below shows is not established.

## What it looks like

`smoke-sched-invariants-stress` boots `SCHED_INVARIANTS=1` at `-smp 4` and fails on a
`PANIC:` marker. Four signatures observed, all within a few hundred milliseconds of
`kernel ready, starting init`:

```
PANIC: dispatcher returned a bogus resume rsp=0x1 task=1 'prog1' state=1 pending_block=0
  vec=32 cs=0x23 cpu=2
  claim: task 1 running_cpu=0  percpu_current=[1,0,1,0]  imp=[0,0,0,0]
```

```
PANIC: stack smashing detected in function at 0xffffffff801131c6 cpu=2 task=2
  claim: task 2 running_cpu=-1  percpu_current=[0,0,2,0]  imp=[0,0,1,0]
```

```
PANIC: unclaimed running task at preempt_on_tick: task 1 claimed by cpu 1 ...
PAGE FAULT ... err=0x11 (present, instruction-fetch, supervisor) task=1 'prog1'
  rip=0xffffffffc0030f40 cs=0x8  rsp=0xffffffffc0030d60 cpu=0
  claim: task 1 running_cpu=0  percpu_current=[1,1,0,0]  imp=[1,0,0,0]
```

```
PANIC: unclaimed running task at enter_cpu_idle: task 1 claimed by cpu 2 ...
  holder cpu 2: commit_gap=-1 deferred=-1 idle=0 current=2 impersonating=1
  task 1: state=3 runnable_ctx=0 inflight=1
```

**Three of those four are memory corruption, not audit reports**: a resume `%rsp` that is a
small integer rather than an address, the kernel's own `-fstack-protector-strong` canary, and an
instruction fetch into a kernel stack address hitting NX (`rip == rsp + 0x1e0`, which is what
executing a clobbered return address looks like). That is the consequence `scheduler.c` states
for a broken `<-` claim direction: *"a second CPU may select the same task and two cores execute
one task's single kernel stack and trap frame concurrently -- memory corruption."* So the bogus
resume value is a **symptom**; the guard that reports it is working.

## The rate, measured rather than inherited

`docs/LIMITATIONS.md` §5.2d records 1 boot in 120 for the default-boot shape, measured
2026-08-21. That figure was not re-derived before this campaign, and it is not what the tree
does now.

| Environment | Boots | Marker failures | Rate |
|---|---|---|---|
| CI `main`, 25 runs mined from the job's own `STRESS RESULT` lines | 750 | 2 | 0.27% |
| Local, unwidened, no instrument | 500 | 1 | 0.20% |
| Local, unwidened, `CLAIM_TRACE=1` | 1000 | 4 | 0.40% |
| **Pooled** | **2250** | **7** | **0.31%** |

The CI figure is **not** conditioned on the job passing: `tools/stress_boot.sh` runs all N boots
regardless of failures and prints the count either way, so a green run contributes its 30 boots
and its zero hits. Runs that reddened for *other* jobs contribute normally too.

**An early cluster that was not real.** The first local run measured **2 failures in 30 boots**
and, taken alone, would have supported a 6.7% rate -- 25x the truth. Both hits fell on boots 28
and 30, which invited a host-state explanation; the 500-boot run then failed on boot 104 and
killed that idea too. At the pooled rate, 2-or-more hits in 30 boots has probability ≈ 0.2%.
It was a coincidence, it is recorded because it nearly became the number this investigation was
sized against, and it is the reason nothing here is quoted from fewer than several hundred boots.

**What a green gate is worth.** `smoke-sched-invariants-stress` runs 30 boots and permits zero
marker failures. At 0.31% per boot it reddens on 1 - 0.9969^30 ≈ **8.9%** of runs, and observed
2 of 25 on `main` (8%). So a green run establishes very little about absence at this rate --
which [G-9]'s own record already said in different numbers, and which stays true.

## The deferred-release machinery is EXCLUDED

`CLAIM_TRACE=1` (`docs/BUILDING.md`: *"used for measurement; not a gate"*) instruments the only
two ways the deferred-release path can orphan a claim, and halts naming both tasks the instant
either happens:

- `claim_trace_defer` -- a CPU defers a second release while its first is still outstanding, so
  the first task's claim is never paid.
- the *declined release* -- a CPU reaches the point where it is provably off task `t`'s stack,
  but `task_running_cpu[t]` names a different CPU, so `== cpu` declines and the release is
  silently dropped.

| Arm | Boots | Marker failures | `CLAIMTRACE` hits |
|---|---|---|---|
| `CLAIM_TRACE=1` | 1000 | **4** | **0** |
| `CLAIM_TRACE=1 KSTACK_RACE_WIDEN=1` | 100 | 0 | **0** |

**Four reproductions with the instrument armed, and it was silent on every one.** That is the
load-bearing row: the widened arm on its own would only say the events are rare, but the
unwidened arm caught the failure four times and the instrument still said nothing. The
deferred-release machinery -- the [G-8]/[G-9] hand-over path -- does not explain this residue.

Two limits on that, stated because they bound the claim rather than decorate it:

- The widened arm reproduced **no** failures (0 in 100), so its silence is unanchored on its own.
  `KSTACK_RACE_WIDEN` also costs **3x boot time** (7.5 s/boot against 2.35 s) and killed one boot
  in 100, so it perturbs the timing it is stretching. It is corroboration, not the evidence.
- `CLAIM_TRACE` itself costs nothing measurable: 4/1000 with it against 1/500 without is Fisher
  p ≈ 0.67. That check exists because §5.2d records an instrument whose cost was misread as the
  system's failure rate, and the same mistake here would have made the exclusion worthless.

## The candidate is DEAD, and the auditor is accusing states that do not hold

`CLAIM_IMP_TRACE=1` (added 2026-09-02) re-reads the accused CPU at the instant of the
accusation and prints the impersonation depth either side of the reads, what each branch of
`sched_running_on()` would have returned, and a fresh evaluation. 1000 boots, unwidened:

| | Boots | Marker failures | Rate |
|---|---|---|---|
| `CLAIM_IMP_TRACE=1` | 1000 | 3 | 0.30% |

0.30% against the 0.31% baseline, so the instrument costs nothing measurable -- checked before
anything it reported was believed.

**The impersonation-tear hypothesis is falsified by its own instrument.** `torn=0` in every
capture. It was the leading candidate when this document was filed, and it is wrong:

```
imp-probe: d1=1 d2=1 torn=0 cur=1 real=1  seen2=1  -- MISMATCH GONE ON RE-READ
imp-probe: d1=0 d2=0 torn=0 cur=1 real=-1 seen2=1  -- MISMATCH GONE ON RE-READ
```

**Every audit accusation captured is false at the instant it is made.** The auditor reports
`task 1 claimed by cpu N but that cpu was running 0`; a fresh `sched_running_on(N)` microseconds
later returns 1. The claim and the runner agree. Three captures, three times.

**The two-strike guard does not establish persistence.** It reads *"persisted across two
audits"*, and it is a single file-scope `(sched_susp_task, sched_susp_cpu)` pair with **no time
component**: audit A arms it, audit B -- which may be microseconds later on another CPU, and both
audits run under `sched_raw_lock` so they serialise rather than exclude the window -- sees the
same in-flight switch and panics. "Seen twice" is not "persisted", and for a window every switch
enters, the difference is the whole claim.

`percpu_commit_gap[]` exists to describe exactly that window -- the gap between
`task_running_cpu[next] = cpu` and `set_current_task(next)` -- and it is **printed in the panic
and never exempted by the audit loops**. `sched_enter_user()`, the first-entry path that runs a
few hundred milliseconds after `kernel ready` (which is when these failures land), does not set
it at all.

## There are TWO failure modes, not one

This is the part that stops the checker story explaining everything.

| Capture | Auditor fired? | Corruption |
|---|---|---|
| `fail-34` | **no** | stack canary, alone |
| `fail-696` | yes, first | `PANIC: two CPUs on one kernel stack task=1 entering-cpu=3 unwinding-cpu=0` |
| `fail-842` | yes, first | page fault at `0x0`, task killed by the validator |
| CI, PR #299 | yes, **second** | stack canary, **printed first** |

`fail-34` corrupts memory with **no audit panic at all**, so the auditor is not the only thing
wrong. And the ordering settles a confound: in `fail-696` the audit fired first and halts a CPU
while holding `sched_raw_lock`, so the two-CPU report could have been fallout from that halt --
but in the PR #299 capture **the canary tripped BEFORE the audit panic**, which no halt can
explain. The corruption is independent of the claim auditor.

### The `two CPUs on one kernel stack` report in `fail-696` was a FALSE POSITIVE

*Corrects this document, 2026-09-02.* It was filed here as an independent detector reporting the
same underlying condition. It was not. The entering CPU in that capture has `imp=[0,0,0,1]` -- it
was **impersonating** -- and the G-8 detector took its identity from `get_current_task()`, i.e.
`percpu_current_task[]`, which is deliberately lying for the whole of an impersonation window. A
CPU impersonating a peer that blocked on another core, and had not been unwound off its stack
yet, asked "is anyone else on that task's stack", got yes, and reported a collision while neither
CPU was on the other's.

Fixed and witnessed by `make smoke-kstack-imp` / `smoke-kstack-imp-control`
(`KSTACK_COLLIDE_IMPERSONATED=1`). That is the **third** false positive in this family --
the claim auditor's impersonation blind spot in August, its two-strike guard above, and now the
collision detector -- all of them one question asked of the wrong variable.

**What survives as evidence of real corruption is the stack canary**, which is independent of
both detectors: `fail-34` tripped it with no audit panic at all, and the CI capture on PR #299
printed it *before* the audit panic. That remains unattributed.

## The auditor's persistence test is fixed (2026-09-02), the corruption not yet

*2026-09-02.* `claim_still_mismatched()` now asks, immediately before accusing, whether the
mismatch is **still there**. It was not, on every capture ever taken.

**This costs no detection, and that is asserted rather than argued.** A leaked claim is
permanent -- that is what makes it a leak, and why the livelock it causes is silent and forever
-- so it cannot resolve between the sighting and the re-read. What can resolve is a switch in
flight, which is not a violation. `make smoke-claim-reread` requires **both**: a live leak is
still reported, and a resolved mismatch is not. Either half alone admits a wrong predicate --
"never accuses" passes the second, and the pre-fix "always accuses" passes the first. Arm:
`CLAIM_AUDIT_NO_REREAD=1`; base gate RED under it.

## The corruption is in the kernel stacks, and the address says so

`0xffffffffc0030f40` has appeared in two independent captures as the target of an **instruction
fetch** (`err=0x11`: present, exec) from ring 0, with `%rsp` 0x1e0 below it. That address is
inside `KSTACK_REGION_VMA` (`0xFFFFFFFFC0000000`, `paging.c`) -- **the per-task kernel stack
region**. A CPU `ret`d to an address that lives in a kernel stack.

That unifies all three surviving symptoms as one thing, *kernel stack contents being
overwritten*: a resume `%rsp` that is a small integer, a stack canary that fails, and a return
address that points into the stack it came off. It is the condition S20 exists to prevent, and
**the S20 detector did not fire on these boots** -- it reports only when the inflight bit is set
*and* a foreign holder exists, so this is happening outside that window.

## The load "lever" did NOT survive retesting

*Corrects this document, 2026-09-03.* It was recorded here as an established effect with
Fisher p = 0.010, from a campaign where 2 failures fell in the first 1000 boots (0.20%) and 9 in
the next 700 (1.29%) while concurrent `make -j12` builds ran on the same host. That contamination
is real and that campaign stays discarded -- `tools/stress_boot.sh` refuses to run beside another
QEMU and has no defence against a compiler.

**But the lever does not reproduce.** Retested deliberately with 12 CPU burners against an
otherwise identical build: **1 failure in 600 loaded boots against 0 in 2500 idle, Fisher
p = 0.194.** So "CPU contention raises the rate" is not established, and the earlier figure
should not be used to size a campaign.

What differs is what `make -j12` actually does -- memory pressure, I/O, page-cache churn and page
faults, not merely burning cores -- so a build-shaped load may still be the lever while a
spin-loop is not. Recorded as an open question rather than a tool, because a lever nobody has
made work twice is a story.

## The rate at HEAD is lower, and this is now established

| | Boots | Marker failures | Rate |
|---|---|---|---|
| Pre-fix baseline | 2250 | 7 | 0.311% |
| HEAD, clean idle boots (2500 + 1000) | **3500** | **0** | **0%** |

**Fisher exact p = 0.0014.** The 95% upper bound on the current rate is 0.086% (rule of three).

**What that means, stated carefully.** The two fixes it follows are both *checker* fixes -- the
collision detector's identity (S20, 2026-09-02) and the auditor's persistence test (above). So
the honest reading is that **the majority of what this finding was counting were the checkers'
own false positives**, and removing them removed the failures. It is not evidence that any
hardware-level defect was repaired, and nothing here claims it was.

An earlier 0-in-1000 was reported here as suggestive-not-significant at p = 0.11; it was right to
hold. 3500 boots is what it took.

## THE SURVIVOR, and it now has a function name

One failure in the 600 loaded boots, and it is not a checker artifact:

```
PANIC: unclaimed running task at preempt_on_tick: task 1 claimed by cpu 1
       but that cpu was running 0 (persisted across two audits; observed by cpu 3)
  holder cpu 1: commit_gap=-1 deferred=-1 idle=0 current=1 impersonating=0
  task 1: state=1 runnable_ctx=1 inflight=0
PANIC: stack smashing detected in function at 0xffffffff80116e34 cpu=0 task=1 'prog1'
  claim: task 1 running_cpu=0  percpu_current=[1,1,0,0]  imp=[0,0,0,0]
```

Four things make this the real one:

- **`percpu_current=[1,1,0,0]` with `imp=[0,0,0,0]`.** Two CPUs are current on task 1 and no
  impersonation exists to explain it away. That is the claim invariant's `<-` direction broken,
  whose documented consequence is two cores executing one kernel stack.
- **The audit panic survived the re-read** added by the persistence fix above, so the mismatch
  persisted. Post-fix, an audit panic is evidence rather than noise.
- **`0xffffffff80116e34` symbolises to `do_spawn_charged`** (`src/kernel/kspawn.c:518`) -- the
  spawn path, and the corruption is its stack frame's canary.
- **`inflight=0`**, so the S20 collision detector could not have fired: it reports only when the
  inflight bit is set *and* a foreign holder exists. This collision is outside that window.

So the surviving defect is: **two CPUs become current on one task with no impersonation
involved, and the shared kernel stack corrupts the spawn path's frame.** How the second CPU comes
to be current on a task it has not claimed was the open question; the section below answers it,
and the answer is not [G-10] -- the spawn path's singleton state was the strongest lead at the
time of writing and had nothing to do with it. The second CPU arrives through the *entry* path,
not the spawn path, and the canary in `do_spawn_charged` is a frame that happened to be on the
shared stack rather than the thing that shared it.

## THE MECHANISM, and it is one line of ordering

*Attributed and fixed 2026-09-03. This is the answer to the section above.*

`sched_enter_user()` is the first-entry path: it takes a task with a fabricated trap frame,
claims it, installs its address space and kernel stack, and `iretq`s into ring 3. Under SMP its
claim was **unconditional**:

```c
    sched_raw_lock();
    int cpu = this_cpu();
    task_running_cpu[tid] = cpu;        /* whoever else may hold it */
```

The one live launch site, `spawn_initial_userspace_init()` (`src/kernel/kshell.c`), published
the task and then called it:

```c
    tasks[pid].runnable_ctx = 1;        /* PUBLISH */
    sched_enable_preemption();
    sched_enter_user(pid);              /* CLAIM, a call later */
```

Between those two statements init satisfies **every** condition of `preempt_on_tick()`'s
selection loop -- `state == TASK_RUNNABLE`, a `cr3`, a `runnable_ctx`, a `saved_ksp`, and
`task_running_cpu[] == -1` -- on a machine where `smp_sched_enabled` has been 1 since bringup
and preemption has just been armed. An AP's timer tick landing there selects it, claims it and
becomes current on it. The BSP then arrives and claims it too.

Two CPUs, both current on one task, neither impersonating, both `iretq`ing onto the same kernel
stack with the same TSS `RSP0`. That is the `<-` claim direction broken, and it is the
consequence `scheduler.c`'s own header names for it. Every surviving symptom in this document
follows from it: a resume `%rsp` that is a small integer, the stack-protector canary, and a
return address that points into `KSTACK_REGION_VMA`.

### It reproduces on the first boot

`ENTER_USER_STEAL_WIDEN=1` holds the entry open until another CPU claims the task, or a spin
budget expires. It is set in **both** arms; that is what makes the pair a measurement. With the
pre-fix ordering and the guard removed:

```
ENTERUSER: steal-widen tid=1 cpu=0 holder=1 runnable_ctx=1 spins=22431
PANIC: dispatcher returned a bogus resume rsp=0xfee000b0 task=1 'prog1' state=1
  vec=32 errc=0x0 rip=0x18fbb9bccb2 cs=0x23 rsp=0x7fed10 cpu=1
  claim: task 1 running_cpu=0  percpu_current=[1,1,0,0]  imp=[0,0,0,0]
```

`percpu_current=[1,1,0,0]` with `imp=[0,0,0,0]` -- **the survivor's signature above, verbatim**,
on the first boot rather than one boot in three hundred. **6 boots in 6.**

The AP takes the task within **912 to 45245 spins** across nine measured boots, i.e. almost
immediately once the window is open: an AP is normally already inside `preempt_on_tick` or
queued for the scheduler lock. The window in the unwidened tree is a few instructions, which is
why the natural event ran at 0.31% per boot rather than at 100%.

### The second failure on the same path

The first widen was a fixed 60 ms rather than a poll, and it found something else:

```
ENTERUSER-WIDEN: tid=1 cpu=0 holder=-1 state=4 runnable_ctx=0 ap_ticks_delta=63
```

`state=4` is `TASK_BLOCKED_WAIT`, `runnable_ctx=0`. The AP had taken init, run it all the way to
`SYS_WAIT`, and *released* it -- so by the time the BSP looked, the claim was free again and the
task was not runnable. The BSP entered it anyway, because `sched_enter_user` tested
`runnable_ctx`, `saved_ksp` and `cr3` **before** queueing for the scheduler lock and never looked
again. Same root cause -- a decision made outside the lock that another CPU can invalidate --
and a separate failure: resuming a blocked task from a frame that is no longer its own.

This is also why the instrument polls rather than sleeping a fixed time. A fixed widen
reproduces the *wrong one* of the two defects, and an arm that reproduces the wrong defect is an
arm reporting the wrong thing.

### The fix, and why not the other one

Two halves, and they are separate rules:

1. **`enter_user_impl()` re-validates under the lock** and fails closed. If the task is claimed
   by another CPU, or is no longer schedulable, this CPU does not enter it -- it parks. That is
   the correct outcome and not a degradation: the task *is* running, on the CPU that
   legitimately holds it, and this CPU has nothing to do. It is general, so it covers every
   caller, including the selftest launchers that still publish the whole task table with
   `selftest_resume_all()` before entering one of them. It reports, because a refusal means some
   launch site still has the window, and a window nobody can see is how this one survived the
   [G-9] closure.
2. **`sched_publish_and_enter_user()` removes the window** at the launch site by doing the
   publish, the claim and `set_current_task()` in **one** acquisition of the scheduler lock.
   There is no instant at which the task is schedulable and unclaimed.

The obvious alternative -- claim in one critical section, then publish and enter in a second --
was written and rejected. It leaves the CPU holding a claim it is not yet current on, which is
the **commit gap**, and the claim auditor does not exempt that. The repair would then have been
to widen an exemption in the auditor in order to fix a defect in a launch path, and the auditor
is the thing that catches this whole class. Note that this also answers the open question three
sections up: exempting the commit gap was listed as "the obvious repair" for the auditor's
persistence test, and it is now unnecessary -- there is no commit gap on this path to exempt.

### Witnesses

| Gate | Asserts |
|---|---|
| `make smoke-enter-user-claim` | The window is held open for the full spin budget and **no other CPU takes the task** (`holder=-1`), no refusal fires, and the boot still reaches its login prompt. All three, because `holder=-1` alone is also what a boot that never reached `sched_enter_user` would print |
| `make smoke-enter-user-claim-control` (`ENTER_USER_PUBLISH_EARLY=1`) | The pre-fix ordering with the guard left standing: the AP takes init and the guard refuses, `ENTERUSER: refused entry to task 1 ... already claimed by cpu N`, **3 boots in 3** -- and the boot still completes, which is the fail-closed outcome being correct rather than merely safe |
| `make smoke-enter-user-collide-control` (`+ ENTER_USER_CLAIM_UNCHECKED=1`) | The guard removed as well -- the pre-fix kernel -- and the two-CPU collision reproduces, **6 boots in 6**. Asserts a *fault* attributed to task 1 rather than a flavour: the three shapes seen are the claim auditor, the resume-`%rsp` floor guard and the stack canary, and which fires depends on which of two CPUs sharing a stack corrupts what first |

Falsified in the other direction too: `make smoke-enter-user-claim` goes **red** under
`ENTER_USER_PUBLISH_EARLY=1`, and so does `make smoke-sched-invariants` under the full arm.

### The marker was splittable, and the defect proved it

*Added 2026-09-03, after the first CI run.* The refusal report was written as a `kfault_str`
sequence, passed 3 boots in 3 locally, and went red on the CI runner -- shredded byte-by-byte by
the ring-3 task whose theft it was reporting:

```
ENTERUSER: refused entIry to task NIT_STORAGE: no persistent volume; this boot r1uns
on the on cpu  ephemeral store
```

The defect had reproduced perfectly and the gate reported *a timeout without its marker*. The
`kfault` and `panic` writers bypass the console lock deliberately -- right for a halt, where
there is no owner left to be polite to -- and wrong for a **survivable** report that by
construction races a ring-3 task on another CPU. `print_core()` already holds that lock for the
whole string, "so a line is emitted whole to one sink"; the report is now formatted into a buffer
and emitted with one `print()`.

Fixed at the source rather than by shortening the marker. Shortening lowers the odds of the same
failure and does not remove it, and **a marker must not be splittable by the condition it
asserts**. The collision arm cannot be repaired the same way -- a panic cannot politely take a
lock held by a CPU it is about to halt -- so it gets a bounded retry instead
(`ENTER_USER_COLLIDE_CONTROL_BOOTS` = 5), falsified against the fixed build, where the loop still
goes red.

### What this does NOT claim

That the 0.31% figure was all this defect. It was not: the campaign that produced it was
counting the three checker false positives recorded above as well, which is why the rate at HEAD
was already 0 in 3500 boots *before* this fix. What the arms establish is that the mechanism is
real, reachable from a normal boot, and now impossible -- not that it accounted for any
particular share of the historical rate. That share is not recoverable, because the captures
that would settle it were overwritten by `tools/stress_boot.sh`'s keep-the-first-failure policy.

## What this does NOT justify

Re-sizing or relaxing `smoke-sched-invariants-stress`. It permits zero marker failures, and
throughout this investigation it was catching real memory corruption at a real rate; the gate
was never the problem. Raising its tolerance would have converted a detector into a silence,
which is precisely the trade `CLAUDE.md` refuses. The 8.9% red rate it ran at on `main` was a
fact about the defect, not about the gate -- which is the argument that held while the defect
was open, and the reason it was still there to catch the next one.

## Evidence

Serial captures are inline above. `tools/stress_boot.sh` keeps only the **first** failure's log
per campaign, so three of the four reproductions in the 1000-boot run were not recoverable --
the same shape as the evidence-destruction lesson `CLAUDE.md` records for `smoke-exec-reenter`,
in a script that gates nothing and therefore never got the repair.
