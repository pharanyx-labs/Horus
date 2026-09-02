# G-12: the claim invariant still fires in the boot phase, mechanism unattributed

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md) §5.2g; the gate
that observes it is `make smoke-sched-invariants-stress`.*

---

**Status: OPEN, filed 2026-09-02. Rate 7 marker failures in 2250 boots (0.31% per boot).**

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

## Candidate, NOT established

`sched_running_on()` reads `percpu_impersonating[c]`, and on the `d == 0` branch reads
`percpu_current_task[c]` afterwards. `sched_impersonate_enter()` takes no scheduler lock, so a
CPU can begin impersonating between those two reads -- and the auditor then reads the
**impersonated** task believing it is the real one, which would report a mismatch that is not
one. That is the same class as [G-9]'s final component, which was a checker false positive.

**The evidence does not support it as the whole story**, and it is written down as a lead rather
than a finding for one specific reason: the first capture above has `imp=[0,0,0,0]` -- no
impersonation anywhere -- and still produced a bogus resume `%rsp`. Either there is more than one
mechanism here, or impersonation is not necessary to it. Fitting the story to two captures out of
three is how the earlier residues in this family were mis-attributed twice.

## What would settle it

An instrument on `sched_running_on` recording whether a reported mismatch coincides with an
impersonation transition. That distinguishes "the auditor is lying" from "the scheduler is
leaking", and those need different fixes -- the first is a checker bug and the second is not.

## What this does NOT justify

Re-sizing or relaxing `smoke-sched-invariants-stress`. It permits zero marker failures and it is
catching real memory corruption at a real rate; the gate is not the problem. Raising its
tolerance would convert a detector into a silence, which is precisely the trade `CLAUDE.md`
refuses. Its 8.9% red rate on `main` is a fact about the defect, not about the gate.

## Evidence

Serial captures are inline above. `tools/stress_boot.sh` keeps only the **first** failure's log
per campaign, so three of the four reproductions in the 1000-boot run were not recoverable --
the same shape as the evidence-destruction lesson `CLAUDE.md` records for `smoke-exec-reenter`,
in a script that gates nothing and therefore never got the repair.
