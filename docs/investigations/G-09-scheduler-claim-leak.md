# G-9: a scheduler claim leaks on the spawn/reap path under SMP

*Extracted from [`../../TESTS.md`](../../TESTS.md), where it was one section of a test
catalogue. The narrative is kept in full: in this project the reasoning is the evidence, and
the record of which hypotheses were wrong is the part worth reusing.*

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md); the gates that
witness it are listed in [`../../TESTS.md`](../../TESTS.md).*

---

**Found 2026-08-17 by `smoke-kstack-park`, and pre-existing.** `PROC_SELFTEST` at `-smp 4`
violates the claim invariant on ~40% of boots. Nothing had run that workload at more than one
CPU before: `smoke-proc` boots it uniprocessor, where it is clean 20/20.

```
PANIC: stale scheduler claim at preempt_on_tick: task 3 claimed by cpu 2
       but that cpu was running 0 (persisted across two audits; observed by cpu 1)
```

Always task 3 — the driver that spawns and reaps — and always a CPU that has gone idle while
still holding the claim. "Persisted across two audits" is the two-strike guard, so it is a leak
and not a mid-flight snapshot.

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
