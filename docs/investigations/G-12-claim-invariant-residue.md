# G-12: the claim invariant still fires in the boot phase, mechanism unattributed

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md) §5.2g; the gate
that observes it is `make smoke-sched-invariants-stress`.*

---

**Status: OPEN, filed 2026-09-02. Rate 10 marker failures in 3250 boots (0.31% per boot).**
**Two failure modes, one of them independent of the claim auditor. The impersonation
hypothesis this document was filed with has since been falsified by its own instrument.**

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

## What would settle it

Two things, and they are separate work:

1. **The auditor's persistence test.** Make "persisted" mean it, rather than "seen twice by
   whichever CPUs happened to audit". The obvious repair -- exempt the commit gap, as the
   deferred release is already exempted -- must not reduce what the gate detects: `fail-34`
   shows corruption arriving with the auditor silent, so a quieter auditor is a gate that
   catches less. **Re-sizing or relaxing the gate is not on the table** (see below).
2. **The corruption itself**, which is not the auditor's doing and is not yet attributed.

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
