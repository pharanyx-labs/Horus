# Changelog

All notable changes to Horus are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Horus has not yet reached a versioned release. Changes below reflect the state of the `main` branch. See the git history for the individual commits behind each item.

---

## Unreleased

### Found — a scheduler claim leaks on the spawn/reap path under SMP (**[G-9]**, pre-existing)

`smoke-kstack-park` turned `main` red. The gate's property is sound and the kernel fix it guards
is sound; what it exposed is a **different, pre-existing defect** that nothing had ever
exercised. `PROC_SELFTEST` at `-smp 4` violates the claim invariant on ~40% of boots, and
`smoke-proc` has only ever booted that workload uniprocessor, where it is clean 20/20.

```
PANIC: stale scheduler claim at preempt_on_tick: task 3 claimed by cpu 2
       but that cpu was running 0 (persisted across two audits; observed by cpu 1)
```

| Configuration | Boots | Failed | Stale claim |
|---|---|---|---|
| `-smp 1` | 20 | **0** | 0 |
| `-smp 4` | 20 | 9 | 8 |
| `-smp 4`, `KSTACK_RELEASE_EARLY=1` (pre-#162 timing) | 20 | 10 | 9 |

The third row is why this is not the **[G-8]** fixes misfiring: 10/20 against 9/20 is no
difference (Fisher p ≈ 1.0). The leak predates them. What they changed is that it is *visible* —
before them the same workload failed **20/20** on the shared park, and a defect that kills every
boot hides every other defect behind it. Both directions of the invariant break; the second
(`task 1 running_cpu=-1` while a CPU runs it) was observed doing damage, as two CPUs on one
kernel stack caught by the canary in `h_write`.

`smoke-kstack-park` is **demoted to advisory** with a written reason naming [G-9] — the same
treatment `smoke-session-smp-soak` had while G-8 was open, and for the same reason: a required
check that reddens for a defect it does not test teaches the re-run reflex. Required contexts
71 → 70. Promote it in the same commit that closes [G-9], and quote a rate.

### Fixed — `__stack_chk_fail` said neither where it fired nor, in a live session, anything at all

It printed `PANIC: stack smashing detected; halting` — no function, no CPU, no task — and
through `print()`, which only appends to the klog once a ring-3 console server owns the console.
**So a stack smash during a live session emitted nothing on the wire.** That is the defect #140
fixed for the trap reports and #143 for the resume guard, still sitting in the canary handler
because nobody had looked; the only reason it was legible on 2026-08-17 is that `PROC_SELFTEST`
never starts `console_server`.

It now reports `__builtin_return_address(0)` — which *is* the faulting function, since the canary
is checked in that function's epilogue — plus the CPU, the task and the claim dump, through
`kfault_*` under the bounded claim. The first run with it printed `h_write`, `task=1`, every
time, which is what turned the search from the write path to the scheduler. Two wrong diagnoses
had been published before it existed; see `TESTS.md` on G-9 for both, kept.

### Changed — the per-CPU idle stacks get a full `KERNEL_STACK_SIZE`, and the constant is pinned

Placing the guard page inside a 16 KiB slot left 12 KiB usable while the **[G-8]** park fix
simultaneously routed a new path onto it. The slot is now `PAGE_SIZE + KERNEL_STACK_SIZE`, so a
parked CPU has exactly the room it had on task 0's stack before the move.

*This was not the fix for the canary trips it was reached for* — 32 KiB gave 12 passes in 25
against 12 KiB's 10, with trips going up, 3 → 5. It is kept because the park path having the
space it previously had is right on its own merits, and because reaching for it turned up a
real trap: `AP_IDLE_STACK_SIZE` is duplicated in `src/boot/ap_trampoline.S`, which cannot include
the header, and **nothing pinned the two**. Diverge them and every AP silently gets a stack
overlapping its neighbour's, at bringup, before anything can report. Now `_Static_assert`ed in
the same shape as the `MAX_CPUS` assert beside it, and falsified: diverging the constants fails
the build with `AP_IDLE_STACK_SIZE changed: update the literal in src/boot/ap_trampoline.S`.

### Changed — `KSTACK0_PARK_TRACE` is barred from any gate that matches a string on serial

It emits through `kfault_*`, which writes bytes straight to COM1 and bypasses console ownership.
That is correct for a panic and wrong during a live session, where it is a second concurrent
writer (finding #126's hazard) and corrupts whatever ring-3 is printing:

```
PARKTRACE cpu=3 rsp=0xffffffff806ff0PROC_SELFTEST: PASS exit+kill+spawn
```

`smoke-kstack-park` built it and its fixed arm now does not. Only the control arm may, because
its assertion is the trace itself rather than a marker the trace can break — which also moves
reachability to the control arm, where `smoke-resume-guard` already puts it.

**This was first published as the cause of the red CI, and it was not.** With the trace removed
the failure rate was 10/25, identical to 10/25 with it. The statistic offered as proof —
"gate failure and corrupted marker correlate 10 for 10" — was a tautology: the gate's assertion
*is* that marker, so every failure lacks it by construction, and the number could not
distinguish one hypothesis from another. Recorded because inventing a confident-sounding
correlation is a worse habit than having no number at all.

### Changed — the ruleset audit's log now says what it compared (**[C-6]**)

`--check-ruleset` printed the classification summary and nothing about the ruleset, so a green
run was silent on whether the comparison had happened at all. The first live run of
`ruleset-audit` could only be shown to have really read the ruleset by *falsifying* it
afterwards with a bad token — which is the wrong way round for a job whose entire purpose is to
be believed when it is green.

It now prints one line, and the state is set only where the corresponding thing actually
happened:

```
live ruleset 19007209      : 71 required contexts, matches
live ruleset 19007209      : 70 required contexts, DIVERGED (1 missing, 0 unexpected)
live ruleset 19007209      : NOT READ
```

`NOT READ` is the default and survives any path that does not complete a comparison, so a run
that failed to reach the API cannot look, at a glance, like one that read it and found it
correct. The exit status was already right in every case; this is about what the log says.

Falsified in all four states before being believed: matching (exit 0), a live ruleset short one
context (`DIVERGED`, exit 1), an unreadable ruleset (`NOT READ`, exit 1), and the line correctly
absent without `--check-ruleset`.

### Added — a scheduled job that checks the live ruleset against the checked-in classification (**[C-6]**)

The half of **[C-6]** that CI could not reach. `.github/ci-gating.yml` is the decision record
and the `ci-gating` job proves it is *complete*; nothing proved the ruleset *matched* it,
because reading a ruleset needs the `Administration` permission and `Administration` is not
among the scopes a workflow `GITHUB_TOKEN` can be granted. A change in the GitHub UI could
diverge the two silently.

`.github/workflows/ruleset-audit.yml` runs `tools/check_ci_gating.py --check-ruleset` daily,
authenticating as a **GitHub App scoped to this repository with `Administration: read` and
nothing else** — minted per run, expiring within the hour, unable to modify what it inspects.
It calls the same tool the maintainer runs by hand rather than reimplementing the comparison,
because a second copy of it is one more thing that can drift from the classification it
polices.

**The trade is stated in the workflow header rather than left implicit:** a credential that can
read repository administration now lives in Actions secrets, in order to detect drift that
requires administration access to cause. Read-only, one repository, revocable by uninstalling
the App. The alternative is a check nobody runs, which is what left the required set at 22 of
66 with no security gate among them.

**[C-6] stays open until the App exists.** The job fails loudly on every scheduled run until
`RULESET_AUDIT_APP_ID` and `RULESET_AUDIT_PRIVATE_KEY` are set — deliberately, because an audit
that skips when unconfigured is a check that cannot fail. Setup is in the workflow header.

The job is classified `advisory` (schedule-only, so it never runs on a pull request), and it is
listed in `.github/ci-gating.yml` rather than excluded from the checker the way `pages.yml` is:
listing it means **deleting it trips `ci-gating`**, since an entry naming a job that no longer
exists is an error. A security control that can be removed without anything noticing is the
shape of [C-6] itself. Required contexts are unchanged at **71**.

### Documentation — the roadmap said things that had stopped being true

Swept end to end on 2026-08-17, prompted by 4.1 and 4.2 both being stale:

- **4.1 asked for work 4.7 had already done.** It required repairing "the stale `CODEOWNERS`
  paths (seven files listed do not exist; the files containing **[C-1]** are uncovered)" —
  corrected on 2026-07-27 by 4.7, two tracks away in the same document. Re-derived: **0 of 57
  patterns** name a missing path, and both **[C-1]** files are covered. What remains on
  **[C-5]** is a second person, and the item now says only that.
- **0.3 was `✅` while `SECURITY.md` listed [I-7] as open** — one finding with two statuses in
  two files, which is exactly what the finding-ID rule forbids. Now `◧`, with the `tasks[]`
  remainder named.
- **`◧` was in use on 1.2 but absent from the status legend.** Added.
- **"The shape of the next year" described 1.1 as the next blocking item.** 1.1 landed
  2026-08-11, followed by 1.3, 1.4, 1.5, 1.55 and 1.6.
- **A promise in that section had not been kept, and saying so is the point.** It read *"Each
  one is another place that has to be revisited when 1.1 lands."* Checked: the three C-3.1
  route-arounds are **still in place**, and `src/kernel/untyped.c` still calls C-3.1 "the defect
  roadmap 1.1 has to fix" six days after 1.1 fixed it. Neither is a defect today — they are
  conservative — but they rest on a premise that no longer holds. Recorded as work with its own
  falsification rather than corrected opportunistically in a PR about something else.
- **"30+ QEMU integration self-tests"** re-derived to **68**, with the count's derivation
  written beside it.

### Fixed — a dying task's CPU parked on a kernel stack every other CPU also parked on (**[G-8]**, second path)

**[G-8]**'s remaining path, recorded the same day as an unwitnessed lead and closed with one.

When a task died and `task_exit_switch()` found nothing else runnable, all three fallbacks in
`idt.c` resumed the CPU at `resume_shell_after_fault()` with
`frame->rsp = tasks[0].kernel_stack_top` — **one stack, shared by every CPU that took the
path**. Two CPUs parked there both run `sti; hlt` on it and both push a trap frame at the same
address on the next tick, which is S20 in the one place `g_kstack_inflight` cannot see it: that
mask is keyed on task ids and skips task 0, legitimately the current task on several CPUs at
once as the idle sentinel.

**The measurement that mattered was choosing the right workload.** With `KSTACK0_PARK_TRACE=1`:

| Workload, `-smp 4` | Parks per boot | Two CPUs on one park stack |
|---|---|---|
| healthy scripted session | **0** (3 boots) | — |
| `PROC_SELFTEST`, which kills tasks on purpose | **5–8** | **2–3 per boot, 3 boots of 3** |

Three healthy sessions say the path is never entered, and that reading would have retired the
lead. A path a test never enters is not a path that cannot be entered.

```
PANIC: two CPUs parking on one kernel stack rsp=0xffffffff80202ff0 this-cpu=1 already-cpu=2 task=1 'exectest'
```

That also explains the capture this finding could not account for: `task=0`,
`percpu_current=[0,0,0,0]`, `PANIC: dispatcher returned a bogus resume rsp=0xfee000b0`. The
LAPIC EOI register address is a word out of the other CPU's `lapic_eoi` frame on the shared
stack.

**The fix.** Each CPU parks on its own ring-0 stack — the one `enter_cpu_idle()` already uses —
so the fault path joins the kernel's single park mechanism instead of keeping a worse second
one. `sched_note_park()` records the choice and halts if two CPUs ever pick the same stack.

**Falsified, both arms, 3 of 3**, and both gate on the same deterministic property — whether any
one park stack was used by more than one CPU:

| Target | Build | Required |
|---|---|---|
| `smoke-kstack-park` | `PROC_SELFTEST=1`, `-smp 4` | ≥2 CPUs parked, none sharing a stack, detector silent |
| `smoke-kstack-park-control` | + `KSTACK0_SHARED_PARK=1` | at least one park stack used by more than one CPU |

Two corrections the gates needed, both found by running them rather than by reading them. The
control arm first gated on the collision **PANIC**, which requires two CPUs parked at the *same
instant* — a property of the schedule, not of the code — and reproduced 2 boots in 3. And the
fixed arm asserts that at least two CPUs actually parked, because without it "no park stack was
shared" is vacuously true on a kernel that never parks, which is precisely what a healthy
session produces. A third: the fixed arm failed 3/3 on the default 40 s budget the `-smp 4`
self-test cannot meet — a timeout, not a fault.

### Fixed — the per-CPU idle stacks had no guard page, so S9 was overclaimed

Found while fixing the above, and true independently of it: `enter_cpu_idle()` has always parked
CPUs on `ap_idle_stacks[]`, and those had **no guard page**. `SECURITY.md` S9 — "an unmapped
guard page below every kernel stack" — was therefore false for every CPU sitting in the ring-0
idle loop, whose neighbour is another CPU's idle stack.

The guard is the **first page of each slot**, not a page prepended to it. Both `ap_idle_stack_top()`
and `ap_trampoline.S` compute the stack *top* as `base + (cpu+1) * AP_IDLE_STACK_SIZE`, so
putting the guard inside the slot leaves the top where it was and needs no change to the
trampoline or to its duplicated `AP_IDLE_STACK_SIZE` — a constant that exists in assembly
precisely because it cannot include the header. The usable stack goes from 16 KiB to 12 KiB.

`smoke-wx` and `smoke-wx-smp` enumerate the new family beside the per-task, fixed and AP IST
guards. Falsified by disabling the arming: `WX_SELFTEST: FAIL armed 0 AP idle-stack guards,
expected 4`, exit 2.

Invariant preserved: **S9** and **S20**.

### Fixed — a task was handed to another CPU before this one had left its kernel stack (**[G-8]**)

**G-8 is diagnosed and closed.** The origin of the bogus resume `%rsp` is a window between
*giving a task up* and *leaving its kernel stack*, and the two are not the same instant.

Every switch path in `scheduler.c` — `preempt_on_tick`, `ipc_block_switch`,
`sched_yield_switch` — is called from `interrupt_handler64`, which is executing on the
outgoing task's kernel stack: the C frames sit immediately below the trap frame the CPU
pushed on entry. Those paths released `task_running_cpu[cur]` and dropped the scheduler lock
while this CPU still had to pop six callee-saved registers off that stack, `ret` through a
return address on it, run the floor guard and `fpu_restore`, read its stack-protector canary
from it, pop four more registers, `ret` again, and only *then* reach
`isr_common_stub64`'s `movq %rax,%rsp`.

A second CPU that claimed the task inside that window resumed it to ring 3 from its saved
frame, and its very next trap re-entered the ISR **on the same stack, at the same depth,
running the same functions** — rewriting exactly the words the first CPU had not finished
reading.

That exactness is why it took so long to see. The return addresses and the stack canary land
back at their own slots holding their own values, so every frame validates and every `ret`
goes where it should. Only the *data* differs — and the first datum out is the resume `%rsp`
on its way to the ISR epilogue. That is G-8's entire recorded signature: a resume value that
is a plausible word from the wrong context (a `.text` return address in one capture, `4` in
another), a canary that passed, and a claim invariant that read perfectly consistent.

**The claim invariant was never evidence against this, and the fix's own control arm shows
why.** A reproduced collision reports `claim: task 4 running_cpu=3 percpu_current=[0,0,0,4]`
— the invariant *holds*, bit-for-bit the observation that retired the shared-stack hypothesis
in `TESTS.md` on 2026-08-13. It holds because it is true: the task really is running on
exactly one CPU. The other one is merely still leaving. `TESTS.md`'s statement that "nothing
observed supports it" is withdrawn; the instrument could not see this and never could.

**The fix** holds the claim until the CPU has physically left the stack. `isr_common_stub64`
calls `sched_release_deferred()` immediately after `movq %rax,%rsp` — the first instruction at
which the CPU is provably reading a different stack — and that is where the hand-over
completes. Interrupts are off there, so it cannot re-enter, and its frame lands in the same
unused region of the incoming task's stack the ISR's own C frames occupied on entry. The delay
is a few tens of instructions; a CPU that wanted the task takes it on the next tick.

**And the property is now checked rather than asserted** (`SECURITY.md` **S20**).
`g_kstack_inflight` carries bit *t* while a CPU is inside that window on task *t*'s stack, and
`interrupt_handler64` tests it on entry: a CPU arriving in an ISR for a task another CPU has
not finished leaving means two CPUs on one kernel stack, and the kernel says so and halts
rather than corrupting itself quietly. One load and a bit test on the common path — `MAX_TASKS`
is 64, so one word covers every task exactly.

**Measured, paired, adjacent-boot alternating on one host — 1600 boots, `-smp 4`:**

| Arm | Failures | Rate |
|---|---|---|
| `KSTACK_RELEASE_EARLY=1` (the pre-fix release site) | **31 / 800** | 3.9% |
| shipped (deferred release) | **0 / 800** | 0% (95% upper bound 0.38%) |

Fisher exact, two-sided: **p = 6.9 × 10⁻¹⁰**. Both ISOs were built from the committed tree and
sha256-pinned, nothing was rebuilt during the run, and the kernel binaries were checked
byte-identical to a fresh build afterwards.

The 3.9% decomposes exactly onto what was already documented. 13 of the 31 were caught *at the
collision* by the new detector; the other 18 — 2.25% — ran on and became a downstream failure
(a stall with no marker, a supervisor `#PF`, or the floor guard's bogus resume `%rsp`), which is
G-8's documented **2–3% per boot**, reproduced. The pre-fix arm is therefore not a worse kernel
than `main`; it is `main`'s defect with an instrument attached that names it before it does
damage.

An earlier 1600-boot run of the same design gave **44/800 against 0/800** (p = 6.2 × 10⁻¹⁴).
Its binaries predated the detector's report deduplication, so it is quoted as a second run
rather than merged. What did not move between them is the part that matters: the
downstream-failure subset was **18/800 = 2.25% in both**, to the boot. The totals differ because
the detector's hit rate tracks how contended the host is — the first run shared the machine with
a stray QEMU — and contention is what opens the window in the first place, which is why this
finding was first seen on a CI runner and on pinned cores rather than on an idle workstation.

**Falsified, both arms, in seconds rather than at 1 boot in 150.** `KSTACK_RACE_WIDEN=1`
stretches the window with a spin so it is entered on essentially every switch, and is set in
*both* arms — the same widened window must be harmless with the fix and fatal without it:

| Target | Build | Required |
|---|---|---|
| `smoke-kstack-race` | widened window, deferred release | session completes, marker **absent** |
| `smoke-kstack-race-control` | widened window, `KSTACK_RELEASE_EARLY=1` | marker **present** and the session must **not** pass |

The control arm is the load-bearing one: without it, the first proves only that a kernel with a
spin in it still boots.

Three details recorded because each would have made the gate lie.

**The obvious widener does not work, and only measurement said so.** Spinning after every
switch is self-defeating: the CPU that must *take* the released task reaches the same spin on
its own switch, so it is always a full spin behind and its own delay prevents the collision it
was meant to cause. Widening every switch reproduced on **2 boots in 7**; thinning it to one
switch in eight, on **0 in 3**. The CPUs are therefore split —
`KSTACK_RACE_WIDEN_CPUMASK ?= 0x5` lingers on cpu 0 and cpu 2 and takes at full speed on cpu 1
and cpu 3 — which reproduces on **12 boots in 12** and, as a side effect, runs about twice as
fast. A control arm that reproduces two times in seven is not a control arm; it is a coin the
next person would have re-flipped.

**The spin count is the value that was measured** (`KSTACK_RACE_WIDEN_SPINS ?= 200000`), not a
round number left in the Makefile. A first draft defaulted to ten times that while every
hand-run had used the smaller one, and the gate then ran the widened session so slowly it
*timed out rather than concluding* — the "verify in the exact form it runs" trap costing a
cycle again.

**The detector reports once per boot.** Both parties to a collision see it and would print the
same task and the same pair of CPUs, and the first control run garbled them together into
`task= entering-cpu=3-2145272000`. That deduplication is deliberately *not* the muteness #143
fixed — there the claim was taken by an unrelated fatal fault on another CPU and the event went
unreported; here it is taken by this same detector reporting this same collision under the
bounded bracket that always emits.

**`smoke-session-smp-soak` is restored to gating** in this commit, as `TESTS.md`, the Makefile
and `ci.yml` have each required since 2026-08-09, and the rate above is the number that
restores it.

*One thing this does not close, recorded rather than fixed.* The `#PF`/exit fallback in
`idt.c` resumes a CPU with `frame->rsp = tasks[0].kernel_stack_top` when nothing else is
runnable, and that stack is shared by every CPU that takes the fallback — a second instance of
the same family. It is not covered by the detector, which is keyed on task ids and excludes
task 0 (the idle sentinel, legitimately "current" on several CPUs at once). No witness for it
exists, so no fix is claimed for it; `docs/LIMITATIONS.md` §5.2c carries the lead and the one
capture that suggested it.

Invariant preserved: **S20** — a task's kernel stack is executed by at most one CPU at a time.

### Fixed — the journal recovery test ends on a process exit, not a signal (**[I-11]**, roadmap 1.55)

`smoke-fs-wal` ended boot 1 by killing QEMU the instant `WAL_CRASHTEST: crashed-after-commit`
appeared on serial. That made "the guest finished" a string match rather than a process exit,
so a genuine WAL regression and a harness that shot QEMU a moment early produced byte-identical
output — a required check that could not distinguish the defect it existed to catch from its
own flakiness.

**Half the finding was already closed and nobody had noticed.** Barrier B is a real
`FLUSH CACHE` and it runs *before* the marker is printed, so since the [I-10] work landed the
journal write has been on stable media by the time the harness sees the marker. The physical
race described in the finding was gone; what remained was the diagnostic ambiguity.

Boot 1 now ends by asking QEMU to quit over its QMP monitor (`tools/qmp_quit.py`, driven by
`WAIT_FOR_EXIT=1`) and **waiting for the process to exit**. A guest that reaches the marker and
then fails to leave is a timeout, not a pass. The harness fails **closed**: no `python3`, a
non-executable helper, or an undeliverable quit each fail the run rather than reverting to
signalling — a silent fallback would be this finding wearing the fix's name.

Roadmap 1.55 had prescribed `isa-debug-exit`. It does not work, and the measurements are kept
at the crash hook so nobody repeats them: on QEMU 10.0.11 a byte write to port `0x604` does not
terminate the process, with or without `-no-shutdown`, and the `lidt 0x0; int $0x0` fallback
faults while *reading* its own descriptor at address 0 and is caught by the kernel's page-fault
handler. QMP `quit` closes the block backends cleanly and exits 0.

**Falsified four ways**, each confirmed to exit non-zero. The decisive one: with `qmp_quit.py`
stubbed to refuse, a serial log containing `WAL_CRASHTEST: crashed-after-commit` **fails** —
the old harness scored that identical log a pass. The others cover a missing `python3`, a
non-executable helper, and an unreachable socket.

**Rate: 20/20 two-boot runs passed**, one fresh 32768-block image each. That is corroboration,
not proof: the pre-fix flakiness was load-dependent and did not reproduce locally, so it is not
a before/after comparison. The substantive argument is structural.

Two harness bugs fell out. An exit the harness had *asked for* was reported as
`QEMU exited before the banner (triple fault?)`, because QEMU could die between the inner and
outer liveness checks. And a contradiction left in `src/kernel/storage.c` by an earlier revert —
one comment claiming the guest exits via `isa-debug-exit`, the next explaining that it halts
because that does not work — is reconciled.

`smoke-fs-wal` is **promoted back to a required check**; [I-11] was the entire reason for its
exemption, and a stale exemption reason is precisely the drift **[C-6]**'s mechanism exists to
prevent. The intended required set goes 67 → 68, exemptions 4 → 3.

### Fixed — revoking a large subtree no longer destroys a peer's capability (**[I-3]**, roadmap 1.6)

`revoke_subtree` accumulated the revoked-serial closure in a fixed 256-entry array. A subtree
larger than that set `overflow`, and the null pass then also nulled **every capability sharing
the root `object`**. That was safe in the direction that matters — mint, transfer and grant all
preserve `object`, so the object set is a superset of the descendant set and no descendant
could survive — but it was reachable from ring 3. An unprivileged task could derive more than
256 capabilities, revoke the root, and make the kernel destroy an *unrelated* task's
independent capability naming the same object: a denial of service against a peer, and an
over-broad revocation the capability graph does not describe.

The closure now marks in place and iterates to a fixpoint, so it is **exact at any subtree
size**. The mark lives in the capability's own `typ` field in two states — `CAP_MARK_NEW` (in
the subtree, children not yet expanded) and `CAP_MARK_DONE` (expanded) — while `serial` and
`badge` are left intact so the derivation tree stays readable mid-sweep. No side array and no
allocation, which is the point: the old bound existed precisely because a `no_std` kernel has
nowhere to grow one. Each capability is marked at most once and promoted at most once, so the
loop terminates without a depth bound or a cycle check, at a cost proportional to the subtree
the revoker actually derived rather than to the whole system.

Revoke-*by-object* (`root_serial == 0`) still sweeps by object. That is not a fallback: with no
lineage seed it is the only complete answer, and it is exact for a shared-object lineage.

Two regression tests witness it — one for breadth (a subtree past the old bound, three levels
deep), one for depth (a 300-link chain across two cspaces) — and both assert that an
independent peer sharing the same object *survives*. Both are falsified by
`--features=revoke_legacy_bounded`, which compiles the old bounded closure back in:

```
test test_revoke_large_subtree_is_exact_and_spares_independent_peers ... FAILED
  assertion `left == right` failed: an independent same-object cap must survive
test test_revoke_deep_chain_is_fully_closed ... FAILED
  assertion `left == right` failed: the unrelated chain's root must survive
```

The `rust` CI job runs that control arm and fails if the tests pass against it, so the
falsification is executed on every push rather than trusted from this entry. `smoke-captest`
still reports 100 checks.

### Changed — which CI jobs gate a merge is now a checked-in decision (**[C-6]**, roadmap 4.2)

The required-status-check list lived only in branch ruleset `19007209`, which no commit
touches. So every job added to `ci.yml` landed in the advisory set **by default**, and nothing
asked whether it should have — which is how the ratio drifted from 21-of-30 to 22-of-66 without
a decision ever being taken, twice at the cost of a security gate: `smoke-captest` sat advisory
until 2026-08-15, and the two [I-10] durability gates landed advisory on 2026-08-16, in the
very commit that fixed the defect they witness.

`.github/ci-gating.yml` now lists every job in `ci.yml` and `codeql.yml` under `required:` or
under `advisory:` **with a written reason**. The `ci-gating` job — and `make check-gating` —
fails the build when a job is in neither, in both, or names a job that no longer exists. There
is deliberately no default, because defaulting is the defect. It caught the CodeQL `analyze`
job unclassified on its first run.

The intended set at the time was **67 required contexts and 4 exemptions**: `smoke-fs-wal` (**[I-11]**),
`smoke-session-smp-soak` (**[G-8]**), `fuzz` (a fixed 30-second search is evidence of effort,
not of absence) and `kani` (manual-only, so it has no conclusion to gate on). Everything
roadmap 4.2 listed as "still to promote" — `smoke-wx`/`-wx-smp`, `smoke-cpu`,
`smoke-modules-tamper`, `smoke-tpm*`, `smoke-flush`, `smoke-stackguard`, `smoke-heap64`,
`smoke-irq-policy`, `smoke-percpu`, `smoke-resume-guard`, `smoke-newlib-tamper`, CodeQL — is
promoted, along with the two new journal gates.

**The promotions are measured, not assumed.** Across 18 CI runs sampled on 2026-08-16, 64 of
66 jobs had zero failures over 1152 job-executions; the only two that failed were `security`
(2/18, both deliberate, during #154) and `smoke-session-smp-soak` (1/18, consistent with
[G-8]'s documented 2–3% per boot). `smoke-fs-wal` is *demoted* from required: a flaky gate that
blocks merges spuriously teaches the maintainer to re-run red checks, and the durability claim
it used to carry now belongs to the deterministic `smoke-fs-wal-flush` / `smoke-fs-wal-order`.

**The ruleset was synced on 2026-08-16**: `tools/check_ci_gating.py --sync-ruleset` took it
from **22 required contexts toward 67**, preserving `strict_required_status_checks_policy` and
the (empty) bypass-actor list, and re-read the ruleset to confirm the write took. Run from a
feature branch, it also required three contexts `main` could not yet produce — the `ci-gating`
job and the two [I-10] gates — and a required context the base branch cannot produce never
reports, so every PR was blocked on it. `tools/prune_unsatisfiable_checks.py` dropped those
three (67 → 64) and now encodes the rule: **never require a context the base branch cannot
produce**; promotion lags the job landing by one merge. `smoke-fs-wal`
was the single demotion. Every security gate the finding named now blocks a merge.

**This narrows [C-6] rather than closing it.** Reading a ruleset needs Administration
permissions the workflow `GITHUB_TOKEN` does not have and cannot be granted, so CI enforces
that the classification is *complete* but cannot enforce that the ruleset *matches* it — the
two could diverge again through a change made in the web UI and nothing in CI would notice.
`--check-ruleset` is the check, and it has to be run deliberately.

Falsified three ways, each confirmed to exit non-zero against a passing baseline: a new job
classified nowhere; an advisory entry naming a job that no longer exists; an advisory entry
whose reason is a placeholder. Recorded in `TESTS.md`.

### Fixed — the write-ahead journal is durable on real hardware (**[I-10]**, roadmap 1.55)

`src/kernel/ata.c` issued three commands — `READ SECTORS`, `WRITE SECTORS`, `IDENTIFY` — and
no `FLUSH CACHE` (0xE7). `WRITE SECTORS` completes once the data reaches the drive's volatile
write cache, so on real hardware a power failure could lose the journal's commit record and
leave recovery in exactly the state the WAL exists to prevent.

The driver implements the command, with its own BSY budget: ATA-8 permits a flush to take up
to 30 seconds, and the sector path's ~2-second cap would have timed out mid-flush — a
timed-out flush read as success is the same silent hole in a new place. `journal_commit()`
now places **three** barriers, where roadmap 1.55 specified two:

| Barrier | Position | Prevents |
|---|---|---|
| **A** | after the journal data, *before* the commit header | Recovery redoing a valid, correctly-HMAC'd transaction from data sectors that never reached the medium. This is the write-ahead rule itself, and it is the one the roadmap did not ask for. |
| **B** | after the commit header, before applying home | A crash mid-apply with no durable record to replay. |
| **C** | after applying home, before clearing the header | Retiring the only copy that could replay the update. |

`journal_recover()` carries the same barrier before clearing a replayed header. Failure is not
advisory: A and B abort with home untouched; C leaves the header in place for the next mount
and returns *success*, because the transaction genuinely is committed and reporting failure
would be a lie in the more dangerous direction — userspace would be told the write did not
happen and would see it happen anyway.

**The test specified for this would not have worked, which is the more useful finding.** The
plan was a `cache=writeback` variant of `smoke-fs-wal`. Under writeback QEMU writes guest
blocks into the *host page cache*; killing QEMU does not lose them, because the host kernel
still holds the pages. A kernel that never flushes and one that flushes correctly produce
identical results, and there is no QEMU cache mode where a two-boot outcome depends on whether
the guest flushed. Switching the cache mode would have built a second vacuous gate beside the
one it was meant to repair.

Two gates that do work, both falsified against the new `WAL_NO_FLUSH=1` control arm:

- **`smoke-fs-wal-flush`** — `blkdebug` returns `EIO` for every `flush_to_disk`, making the
  command's presence observable through the kernel's reaction to its failure. Fixed kernel:
  `WAL: FLUSH FAILED before commit header - transaction aborted`, nothing committed. Control
  arm: no flush issued, `blkdebug` never fires, the refusal is **absent** and the transaction
  commits.
- **`smoke-fs-wal-order`** — traces the IDE command register and asserts the commit tail is
  `0x30 0xe7 0x30 0xe7`. Presence alone is insufficient: a barrier placed *after* the commit
  header would satisfy error injection identically while losing the write-ahead rule. Control
  arm: `WAL_ORDER: FAIL no FLUSH CACHE (0xe7) was ever issued`.

Deterministic, not a rate — the barriers are either compiled in or they are not. Both control
arms run in CI rather than being trusted from this entry.

### Changed — a harness liveness check that could never observe an exit

`tools/smoke_test.sh` tested whether QEMU was still running with a bare `kill -0`. QEMU is an
unreaped background child, so between its exit and the harness's `wait` it is a **zombie whose
PID still answers `kill -0`** — meaning the `SMOKE FAIL: QEMU exited before the banner (triple
fault?)` branch was unreachable, and every such case was reported as a plain timeout instead.
`qemu_alive()` now also checks the process state. Found while implementing `WAIT_FOR_EXIT`,
which hung against a guest that had already exited cleanly.

**[I-11] was not fixed here** (it was, later the same day — see the entry above), **and its
prescribed remedy is now known not to work.** Roadmap 1.55
called for boot 1 to end itself via `isa-debug-exit`. Measured against QEMU 10.0.11: the port
write at `0x604` does not terminate the process, with or without `-no-shutdown`; and the
`lidt 0x0; int $0x0` triple-fault fallback that `src/kernel/kshell.c:99` pairs with it faults
while *reading* the descriptor at address 0, so the kernel's own handler catches it and prints
a `PAGE FAULT` the harness correctly fails on. Both were tried and reverted, and the comment
at the crash hook records it so the next attempt starts from this rather than repeating it.
QMP `quit` over a monitor socket is the obvious next candidate.

### Fixed — four documents still said no security test gates a merge (**[C-6]**)

The commit that promoted `smoke-captest` updated six files and missed four more, so the tree
spent a day asserting both halves of a contradiction. `README.md` still gave the ratio as
**21** of 64 — a number that was simply wrong, not merely stale — and its assurance banner,
`SECURITY.md`'s research-grade banner, and `docs/LIMITATIONS.md` §5.2's heading all still said
the security tests do not gate merges, without qualification.

The one that could have caused harm is `.github/pull_request_template.md`. It told the author
of every pull request that the security `smoke-*` jobs are **not** merge-gating and that CI
will not stop them — advice that is now false for `smoke-captest` and, read as reassurance,
invites treating a red capability-conformance run as noise. It now names `smoke-captest` as
gating and lists the eleven jobs plus CodeQL that genuinely are still advisory, so the note
says which is which instead of asserting one blanket answer.

This is **[C-6]**'s own mechanism turned on the documentation: a fact maintained by hand in
nine places drifts in whichever ones a commit forgets to open. The count in `README.md` now
carries the same "read it from `gh api repos/pharanyx-labs/Horus/rulesets/19007209`, not from
this sentence" pointer the other documents were given. No status marker changed and **[C-6]**
stays open — the required set is still 22 of 64, verified live, with `smoke-captest` the only
security gate among them.

### Changed — the capability conformance suite can now block a merge (**[C-6]**, partial)

`smoke-captest` is a required status check as of 2026-08-15. Ruleset `19007209` now requires
**22** of `ci.yml`'s **64** jobs; until this change not one of the 22 was a security gate.

That mattered more than the count suggests. `SECURITY.md` names `smoke-captest` as the witness
for eight of its S-numbered properties — S1, S5, S6, S7, S13, S13a, S13b and S18 — so the suite
establishing most of the security argument could fail while a pull request merged green. It is
the same shape as **[C-1]** itself: a control that reads as coverage and provides none.

**This does not close [C-6], and the remaining half is the more interesting one.** Every other
security gate is still advisory — `smoke-wx`, `smoke-cpu`, `smoke-modules-tamper`,
`smoke-tpm*`, `smoke-flush`, `smoke-stackguard`, `smoke-heap64`, `smoke-irq-policy`,
`smoke-percpu`, `smoke-resume-guard`, `smoke-newlib-tamper`, CodeQL. Promoting them one at a
time would not fix the mechanism: the required list is maintained by hand in a ruleset that no
commit touches, so a job added to `ci.yml` lands in the advisory set by default and nothing
asks whether it should have. That is how the ratio drifted from 21-of-30 to 21-of-64 without a
decision ever being taken. Roadmap 4.2 now specifies generating the list from `ci.yml` and
failing CI on any job that is in neither it nor an explicit, reasoned advisory list.

Also corrected: this repository has been citing **nine** S-properties for `smoke-captest`, in
`LIMITATIONS.md` and in the audit that prompted the change. Counted off the witness column in
`SECURITY.md`, it is **eight**. Every document that quotes a required-check count now also says
to read the live number from `gh api repos/pharanyx-labs/Horus/rulesets/19007209` rather than
trust the prose, because a hand-maintained number in a document about a hand-maintained list is
the drift this project keeps rediscovering.

### Fixed — the last ambient `uid == 0` gate, nineteen days after [I-1] was declared closed (**[H-1]**)

`current_user_is_admin()` (`src/kernel/kusers.c`) ended `return tasks[get_current_task()].uid
== 0;`. Roadmap 0.2 retired the ambient uid gates in `syscall.c` and `syscall_fs.c` and never
reached `kusers.c` — and because `SYS_USERADD`, `SYS_USERDEL` and `SYS_PASSWD` are `SC_NONE`
in the dispatch table, that function *was* their gate. A ring-3 task at uid 0 holding no
capability could create an account with an arbitrary uid/gid and reset any other user's
password; since uid is the identity `fs_server` authorises file access against, that is
authority over the whole subject namespace. `SECURITY.md` S18, `LIMITATIONS.md` §1.2 and
`ARCHITECTURE.md` §G-2 all recorded the finding as closed throughout.

Administrative authority is now possession of `CAP_USER` and nothing else.

**The fallback was load-bearing, which was not the expectation.** `launch_shell`
(`userspace/init.c`) delegated console, storage, the console client endpoint, `CAP_KERNEL_LOG`
and `CAP_AUDIT` — but never `CAP_USER`. The shell's `useradd` had therefore been running on
the ambient gate alone, and deleting it turned `smoke-session` red at
`[ok] useradd allowed for root`. So `init` now delegates `CAP_USER` to the shell and the shell
refuses `useradd`/`userdel` to a non-root session itself: the kernel asks whether the task
holds the authority, the session manager asks whether this user may exercise it. That is the
same split `CAP_KERNEL_LOG` uses, and for the same reason — the shell is one long-lived task
serving successive logins, so its capability cannot express "only while root is logged in".
`passwd` needs neither half: the shell always targets the caller's own uid.

**Witnesses.** `make smoke-captest`, **96 → 100 checks**: four new refusals (`useradd`,
`userdel`, `passwd` of another user, cross-task `get_task_info`) asserted as exactly
`SYS_ERR_PERM`, run as uid 0. `make smoke-session` asserts both directions through the real
ring-3 shell — root may add a user, a standard user gets
`useradd: permission denied (root only)`.

**Falsified.** With the fallback reintroduced and nothing else changed, `make smoke-captest`
reports `CAPTEST: FAIL useradd-allowed-by-uid0-without-CAP_USER`.

**Withdrawn, recorded so it is not re-derived.** A first draft assumed `captest` had been
holding `CAP_USER` via `do_spawn_inner`'s propagation and added a harness step to clear slot 6.
It had not; the step was removed. The propagation calls `cap_lookup(6, …)` *after*
`load_staged_image_into` has made the child the current task, so it reads the child's own empty
cspace and never fires (`kspawn.c:188-197`). It is dead, and dead in the fail-closed direction
— repairing it would silently widen authority to every spawned child, so it is not a tidy-up.

### Fixed — the resume-`%rsp` floor guard was mute on exactly the boots it existed to explain (**[G-8]**)

`interrupt_handler64`'s guard against a bogus resume `%rsp` (#123) reported inside
`kfault_begin(1)`/`kfault_end(1)`. `kfault_begin(1)` is `panic_begin()`, whose claim
is **permanent**: the first CPU to report a fatal fault takes it and never releases
it, and every later CPU that asks for it halts *inside* `panic_begin` **without
emitting a byte**. So once any CPU had died fatally — for the same underlying reason,
a bogus resume value a moment earlier — the guard was silent for the rest of the boot.

That is not hypothetical. In the 2026-08-13 two-event capture, cpu 3's fatal `#GP`
printed first and kept the claim; the only report that got out afterwards was cpu 0's
`#PF`, which uses the **bounded** bracket. The guard could not have been heard on that
boot whether or not it fired. #140 moved this report off `println()` and onto the UART
but left it behind a claim the failure itself takes away.

The guard now reports under the bounded claim, releases it, and only then halts.
Halting is unchanged behaviour (`kfault_end(1)` already did it) and is the fail-closed
answer: `iretq`-ing onto a value just rejected is the one thing that must not happen.
As a side effect the dead fall-through into the `out->cs` read is gone — that read is
what turns `rsp == 4` into a fault at `0x94`, and it cost a symbolisation cycle once.

**Every "the floor guard did not catch it" statement about G-8 is withdrawn.** The
absence of the line was never evidence about the guard. `TESTS.md` and
`docs/LIMITATIONS.md` §5.2c are corrected rather than quietly amended.

### Added — `make smoke-resume-guard{,-preclaim,-legacy,-nofloor}`, a four-arm gate for that guard

The natural event is ~1 boot in 150, so the gate does not wait for it.
`RESUME_RSP_INJECT=1` forces the dispatcher to return a bogus resume `%rsp` of `4` —
G-8's own recorded value, for the same reason `smoke-kfault` injects at `0x94` — once,
after the console handover, and the harness requires the `PANIC:` line after the login
prompt. `-preclaim` takes the permanent panic claim first, reproducing another CPU's
fatal exception. `-legacy` restores the pre-fix bracket and requires **silence**;
`-nofloor` compiles the guard out and requires silence. The two control arms are what
make the first two a measurement rather than an assertion.

The injected value is read through a `volatile`: as a literal, GCC folds the comparison
at compile time and the arm would prove the reporting works while never executing the
`cmp`/`jae` a real occurrence goes through. The gate reuses `tools/kfault_test.sh` via
a `REPORT_RE` override rather than copying it — it asks the same question of a
different reporter, and the after-the-handover ordering is the whole test.

**G-8 remains open** and the soak job stays advisory; the origin of the bad value is
still unknown. What is closed is the instrument. *(As at that entry's date; closed 2026-08-17 — see the top of this section.)* One new narrowing came out of the
control arm and is recorded in `TESTS.md` as an inference with its check named: an
`rsp` of `4` reaching `out->cs` faults at `0x94`, but the capture faulted at `0x4` in
the stub, so on that boot the value became `4` *after* the guard — in the epilogue
window, with the frame's stack canary intact, which points at a register rather than a
smeared stack.

### Fixed — 64-bit-clean heap arithmetic, and a heap can now be paged above 4 GiB (**[I-2]**, roadmap 1.5)

`SYS_SBRK`/`SYS_BRK` computed the new break in 32 bits while `heap_start`,
`heap_current` and `heap_end` are all `uint64_t` in the TCB. Seven narrowing points
between them; the sharpest were the three that truncated a value *after* it had
been range-checked at full width, so the check passed on the real address and the
break was then stored wrapped. Both handlers are now `uint64_t` end to end with the
overflow test before the range test, and `sbrk` still shrinks correctly (negation
via `-(x+1)+1`, so `INT64_MIN` has no undefined step).

**The finding was scoped too narrowly, and the missing part was not latent.** The
same truncation appeared a third time in the **pager**:
`handle_demand_page_fault`'s region gate cast the heap bounds to `uint32_t` when
calling `rust_validate_page_fault`, which declares them `u64`. For a heap above
4 GiB the effect was not a wrong break value but **no demand paging at all** — the
gate compared a 64-bit fault address against a truncated window, decided it was out
of region, and refused to map a page the task was entitled to. A heap outside the
premapped low window could never be paged, and it failed **silently**, because a
ring-3 fault prints nothing.

The tell was that two call sites of one validator disagreed: `page_fault_handler`
passed the same values untruncated and admitted the fault, then the pager rejected
it. So `[I-2]` was in part a functional ceiling on the address space rather than
arithmetic hygiene — which matters for roadmap 2.1, whose point is placing regions
freely.

**This one has a real witness**, unlike **[C-4]**. `make smoke-heap64` builds
`USER_HEAP_HIGH_BASE=1` (every heap at 8 GiB — above 2^32, below
`USER_IMAGE_ASLR_BASE`, inside PML4[0] so no new top-level paging is needed) and
runs `captest`, which calls `sbrk`/`brk` and then writes to the page it is given.
Built without the fix, the same target reports `CAPTEST: FAIL (sbrk-grow-failed)`.
Both arms were run by hand before the target was written.

Worth recording for anyone extending this: the reason the pager bug went unnoticed
is that the *image* already lives at 16 GiB and works — but it is **premapped** by
`create_user_pagedir`, so it never exercises the demand path at that address. A
premapped high region is not evidence that demand paging works there.

Tests: `smoke` · `smoke-captest` · `smoke-heap64` · `smoke-cow` · `smoke-nzcow` ·
`smoke-wx` · `smoke-aspace` · `smoke-newlib` · `smoke-elf` · `smoke-session` ·
`smoke-fs` — **11/11**.

### Documentation — a second G-8 capture retires the shared-stack hypothesis and one bad search

A dual-arm soak (150 boots per arm on one host) caught the fault again on `main` at `e9aebdd`,
this time in a boot carrying **two** corrupted resume values on two CPUs: a `.text` return
address consumed at the `iretq`, and **`4`** consumed at the stub's first `pop`. Both symbolise
exactly against the binary that produced them.

Three corrections to what was recorded on 2026-08-13 earlier in the day:

**The two-CPUs-on-one-kernel-stack hypothesis is not supported.** The second event is the first
`t > 0` capture, and there `task_running_cpu[4] == 0` and `percpu_current_task[0] == 4` — the
claim invariant **holds** at fault time. One capture does not disprove it, but nothing observed
now supports it, and a one-word value/pointer confusion needs no second CPU to explain.

**"Find the write that puts a return address into `saved_ksp`" was the wrong search.** Two
different garbage values in a single boot put the cause upstream of any one assignment. No
`saved_ksp` write produces `4`.

**The floor guard did not fire on `rsp = 4`.** That value is below its threshold and is named
verbatim in its own comment, yet no `bogus resume rsp` line appears in the log. Until that is
explained, the guard's behaviour is unverified — and every "the guard did not catch it"
statement about this fault, including the one written earlier today, is an inference rather
than an observation.

The same run served as the control for **PR #135** (per-CPU IRQ lock, `[C-3]`/`[C-3.1]`):
`main` 1/150 against #135 rebased **0/150**. Not a significant difference (Fisher p = 1.0) and
no improvement is claimed — but it establishes the fault is `main`'s, not #135's, which is why
#135 was no longer held for it and merged the same day.

**[G-8] remains open.** No code changed here. *(As at that entry's date; closed 2026-08-17 — see the top of this section.)*

### Fixed — the SMP soak stops destroying the evidence it exists to collect (**[G-8]**)

`smoke-session-smp-soak` reused a single `mktemp` log, overwrote it on every
iteration, deleted it at the end, and printed `tail -20` of a failing run. G-8 is
rare, so that discarded almost everything it caught. Not hypothetically: on PR #142
— a docs-only change — CI hit an occurrence at run 34/45 and retained exactly

```
PAGE FAULT at 0x525c71a094 err=
```

stopping mid-assignment. The error code, `rip`, `rsp`, `rbp` and the `claim:` line —
the entire payload the previous entry added — were thrown away by the harness that
observed them. **Every G-8 occurrence CI has ever seen was lost this way**, including
any `t > 0` capture, which is the one that would settle whether two CPUs are sharing
a kernel stack.

Two causes, both fixed:

**`session_test.py` stopped draining too early.** On a fault marker it waited for the
rest of the dump with `for _ in range(6): if not self._pump(0.25): break`, which gives
up at the *first* quarter-second with no bytes. A fault report is not a continuous
stream — the kernel formats each field, and under SMP may be doing so while another
CPU is wedged, so a gap mid-dump is ordinary. It now tolerates gaps and stops on
sustained silence, bounded by `FAULT_DRAIN_SECS` so a wedged guest cannot hang a run.

**The soak kept nothing.** `session_test.py` has always supported
`SESSION_SERIAL_LOG`, which writes the complete serial buffer; nothing ever set it.
Each boot now writes one into `$(SOAK_EVIDENCE_DIR)` (default `soak-evidence/`,
gitignored); passing runs are deleted, failing and vacuous ones are kept with their
stdout beside them, and a clean run removes the directory. CI uploads it as an
artifact — together with the exact `kernel.elf`, because symbolising against a
rebuilt tree has already produced a wrong reading of this fault twice.

Verified in both directions rather than assumed. With `KFAULT_INJECT=1
KFAULT_INJECT_TICKS=40` firing a deliberate supervisor fault mid-session, the retained
log holds the report whole — `PAGE FAULT` line, `vec`/`errc`, `rip`/`cs`/`rflags`,
`rsp`/`rbp`/`cpu` and `claim:` — where #142's CI capture had one truncated line. A
forced-failure arm (`SOAK_MIN_CHECKS=99`) retains full 80-line transcripts; a clean
arm leaves no directory at all.

This changes no kernel code and fixes no kernel defect. **[G-8] remains open** and the
job remains advisory; what changes is that the next occurrence produces evidence
instead of a rate. *(As at that entry's date; closed 2026-08-17 — see the top of this section.)*

Tests: `smoke` · `smoke-session` · `smoke-session-smp` · `smoke-kfault` ·
`smoke-kfault-legacy`, plus both soak arms above.

### Fixed — user copies refuse instead of truncating (roadmap 1.4, **[C-4]**)

`copy_from_user`/`copy_to_user` clamped `n` to `USER_MEM_MAX_COPY` (64 KiB) and then
returned 0 — success. A caller that believed it had moved `n` bytes was left with
whatever the destination already held past the clamp: on a copy out, stale
kernel-stack bytes in the tail of a user buffer, handed over as if they were data.
Both helpers now refuse the request. The ceiling was never the defect; reporting a
short copy as a complete one was.

Auditing all ~89 call sites found that none can reach the refusal: each either bounds
`n` by the kernel scratch buffer it stages through (`h_write` 255, `h_dmesg` 1024,
`pipe_read`/`pipe_write` `PIPE_IO_CHUNK`, the block syscalls `BLOCK_SIZE`, the rest a
`sizeof`), or chunks explicitly to `USER_MEM_MAX_COPY` before calling
(`arm_image_from_user`, `try_elf_load`, `load_staged_image_into`). The change is
therefore behaviour-preserving, which is what the sweep below measures.

**`h_boot_module_read` was the exception, and was live rather than latent.** It has no
staging buffer — it copies straight out of the `PHYS_KVA` window — and returned the
*unclamped* `len`, so a request above 64 KiB reported bytes it had never written. It
now clamps to the ceiling itself and returns the count actually copied: a short read,
which is what its ABI already promises ("bytes copied from a boot module's payload")
and what `fs_server`'s provisioning loop already handles by advancing on the return
value. In-tree it has only ever been called in `BLK`-sized chunks, which is why this
stayed latent in practice.

Worth stating plainly, because it bounds the claim: with every syscall clamping to its
own buffer first, the refusal is **not reachable from ring 3**. This closes a latent
kernel-memory disclosure against the next caller added, not one that was open to
userspace. A falsification test for the reachable half — the boot-module short read —
still needs writing, and needs a caller holding `CAP_BOOT_MODULE`.

Tests: `smoke` · `smoke-captest` · `smoke-wx` · `smoke-cow` · `smoke-nzcow` ·
`smoke-aspace` · `smoke-fs` · `smoke-fs-large` · `smoke-modules` ·
`smoke-modules-tamper` · `smoke-session` — **11/11**.

### Added — the interrupt-policy audit is read out in band (roadmap 1.1 step 2b)

The entry below removed the audit's ability to corrupt the session it measured, but
left it unable to say anything once a shell was up: quiet mode counted correctly
and printed nothing, and the boot-window gate printed at tick 40 and never reached
a prompt. Neither produced the session-scale total roadmap 1.1 step 3 needs.

**`SYS_IRQ_POLICY_INFO` (92)** returns the counters to userspace on request, and
the shell's **`irqpolicy`** builtin prints them through `console_server` like any
other program. The kernel is no longer a second writer at all, so there is nothing
to interleave with — and because the readout is on demand it can be taken *after* a
representative workload instead of at a fixed tick, which is the entire difference
between a session-scale figure and a boot-scale one. `IRQ_POLICY_QUIET` now
defaults **on**; `make smoke-irq-policy` passes `IRQ_POLICY_QUIET=0` because it is a
boot-window gate that exits on its marker and never reaches a prompt.

`make measure-irq-policy` is the supported way to take the measurement — fourteen
commands, every one a `console_server` round trip:

```
irq-policy: accidental_sti=1439 benign_sti=720 sites=7 @tick=693
```

| Site | Hits |
|---|---|
| `cap_install_object` | 685 |
| `cap_consume_slot` | 684 |
| `storage_decrypt_block` | 41 |
| `cap_grant_into` | 12 |
| `storage_encrypt_block` | 11 |
| `create_task` | 4 |
| `user_map_device_page` | 2 |

**This is the table step 3 should be designed against.** It says something the
withdrawn one did not: the two IPC capability sites are **95%** of all accidental
`sti`s and scale with message traffic, while the other five are fixed boot-time
costs. Making the windows explicit is therefore mostly a question about *two*
functions on the IPC path — the same path the startup handshake runs on, and so
precisely where the reverted July attempt broke.

Gated like `SYS_DMESG` (`CAP_KERNEL_LOG`, READ) rather than on fresh authority, and
absent from the dispatch table outside `IRQ_POLICY_AUDIT` builds so the ship kernel
answers `SYS_ERR_NOSYS`. Verified end to end in both directions: a standard user is
refused at the shell, and root on a ship kernel gets `not an IRQ_POLICY_AUDIT build`.

`captest` **88 → 89 checks**, falsified in both directions:

| Break | Check that fired |
|---|---|
| capability gate removed (`SC_NONE`) | `irq-policy-info-allowed-without-kernel-log-cap` |
| kernel built with the audit, userspace without | `irq-policy-info-present-in-ship-kernel` |

The second was not contrived — it is how the check first failed. Userspace compiles
with its own flags, so `#ifdef IRQ_POLICY_AUDIT` in `captest.c` was never true and
the test disagreed with the kernel about which kernel it was in. It failed loudly
instead of passing against the wrong expectation, which is the only reason it was
caught; `USERSPACE_CFLAGS` now propagates the flag. An exact-errno assertion catches
this and a `< 0` assertion would have passed in both configurations.

The measurement tool also asserts prompt integrity as a net against measuring a
corrupted session. **That guard has not been shown to fire on a genuine split** — the
corruption is deterministic for a particular prompt timing rather than a general
race, and this tool's prompts land after the async reports finish. `session_test.py`
remains the instrument that detects a split reliably. Recorded rather than presented
as falsified.

### Fixed — roadmap 1.1's own instrument was corrupting the session it measured, and its published numbers came from it

`IRQ_POLICY_AUDIT=1` (roadmap 1.1 step 1) reported through `panic_str`, straight at the
UART, deliberately bypassing the runtime suppression of `print()`. That suppression
is not an inconvenience to route around: ring-3 `console_server` owns the serial
line, and a second writer interleaves. The tick-41 report lands on the login prompt
and cuts it in half:

```
root@horus\n[irq-policy] handshake-early @tick=41: accidental_sti=96 benign_sti=65 sites=7
```

`root@horus#` then appears **nowhere** in the transcript, so `tools/session_test.py`
waits 180 s for a prompt that was never written contiguously. This is the
`PA[NIC: console_server] ready` interleaving bug one level up — the same defect the
single-writer console was introduced to fix, reintroduced by an instrument that
opted out of it.

**Measured interleaved** — adjacent boots, alternating builds, so no amount of host
drift can explain the gap — with the unmodified audit build kept in as a positive
control:

| Build | `session_test.py` failures |
|---|---|
| ship kernel (no audit) | **0 of 8** |
| audit, `IRQ_POLICY_QUIET=1` | **0 of 8** |
| audit, exactly as shipped | **8 of 8** |

`IRQ_POLICY_QUIET=1` suppresses every timer-driven report and touches nothing else.
That is not an assertion: `spin_lock` and `spin_unlock` disassemble to **82
identical instruction lines** under both settings, referencing the same five counter
symbols the same number of times. The counting was never the problem.

**The numbers step 1 published are withdrawn.** When the prompt is split the harness
stops issuing commands, so the guest correctly runs nothing more and the counters
stop climbing. `docs/ROADMAP.md` and `TESTS.md` reported **99 accidental / 67 benign
over seven sites** as a measurement "across a scripted shell session"; it is the boot
window of a session that never executed a command. A session the harness can drive
reads **420 / 224 at tick 201**, and the distribution is materially different — the
two IPC capability sites are ~90% of accidental `sti`s rather than roughly comparable
to the rest. The seven *sites* reproduce in both populations and are unchanged.

Reports now carry `@tick=`, because these counters are cumulative and still climbing:
a figure quoted without its sample point is not a measurement, which is precisely how
a boot-window snapshot came to be recorded as a session total.

**`make smoke-irq-policy` is unaffected and stays gating** — `MARKER_ONLY=1` means the
marker alone signals success, so the gate exits at tick 40 and never reaches a prompt.
Verified as a rate, 8 boots in 8, not a single green run.

Two wrong diagnoses were recorded and corrected along the way, both caught by controls
rather than by re-reading code: that the periodic reports added while investigating had
caused the failures (the control failed too), and that the frozen counters beside a live
timer meant a wedged kernel, possibly **G-8** (they mean an idle one — the guest was
healthy throughout). An early comparison was also run as time-separated blocks, which
confounds build with host state; its *p*-value was withdrawn and the experiment redone
interleaved.

**Roadmap 1.1 step 3 is not unblocked by this.** Quiet mode counts correctly and says
nothing; the gate prints but never reaches a prompt. Neither yields an honest
session-scale total, which is the number step 3 needs — the windows it must reason
about are dominated by IPC sites that only appear under load. A readout through the
single-writer console, or at guest exit, is the remaining prerequisite.

### Fixed — the scheduler's claim auditor was reading a deliberate impersonation as a leak

`SCHED_INVARIANTS=1` had been reporting, in about 1 boot in 5 — **10 in 20** once
the boots were pinned to two host cores:

```
PANIC: stale scheduler claim at preempt_on_tick: task 1 claimed by cpu N
       but that cpu was running 4 (persisted across two audits)
```

It was recorded as a real, un-root-caused SMP scheduling defect: `init` blocked in
`sys_wait()` on the shell, left claimed by a CPU that had moved on. `TESTS.md`,
`docs/ROADMAP.md` and the `Makefile` all said so, and roadmap item **1.1** was
blocked behind root-causing it.

**There was no scheduling defect.** The claim invariant

```
task_running_cpu[t] == c  <=>  percpu_current_task[c] == t
```

was never violated. What was wrong was the auditor's notion of what
`percpu_current_task[]` means.

`copy_to_user` resolves through `tasks[get_current_task()].cr3`, so writing into
another task's address space requires briefly making that task current. Three
places do it, for the same reason:

| site | impersonates | duration |
|---|---|---|
| `sys_ipc_send`, `h_ipc_reply_to` | the blocked peer | ≤256-byte copy, IF masked |
| `do_spawn` → `load_staged_image_into` | **the child** | the entire ELF load |

The IPC pair had been declared to the checker (a `percpu_in_user_copy` flag, added
when it false-positived on exactly this). **The spawn window had not** — and it is
the long one: a ~450 KiB copy plus page-table construction and relocation
processing, which under TCG spans many timer ticks and so comfortably outlives the
two audits the checker requires before it accuses.

So `task 1 claimed by cpu N but that cpu was running 4` was `init` (task 1) midway
through spawning the shell (task 4), correctly claimed by the CPU executing its
`SYS_SPAWN` in ring 0, while `percpu_current_task[]` deliberately named the child.
The serial log had been saying so all along: the panic lands two lines after
`init: console_server launched`, before the shell exists.

**The fix does not switch the checker off for those windows.**
`sched_impersonate_enter/exit` record the task the CPU is *really* running
(`percpu_real_task[]`), and the audit is stated over that — so coverage stays
continuous across the longest operation in the system, which is precisely where a
genuine leak would be easiest to hide. The bracket is a nesting depth rather than a
flag, and is itself checked: a CPU that reaches **ring 3** at non-zero depth has an
`enter()` that lost its `exit()`, and panics saying so. An exemption mechanism with
no balance check is a hole in the shape of the thing being checked.

| Build | Runs (pinned, 2 host cores) | Failures |
|---|---|---|
| before | 20 | **10** |
| after | 30 | **0** |

Falsified in both directions rather than merely observed green: deleting the claim
release in `preempt_on_tick` (a genuine leak) still panics 3 boots in 3, and
deleting `sched_impersonate_exit()` fails 3 in 3, once via the new balance panic.

`make smoke-sched-invariants-stress` — 30 pinned boots reported as a **rate**, not
a single run — is now a CI check, which is what the finding had been blocking.

Also fixed: two CPUs tripping the checker on the same tick interleaved their output
byte-by-byte into an unreadable `PANICPANIC: : unbalanced impersostale scheduler
claim…`. A first-CPU-wins latch now gives the reporter the UART alone. Same failure
as the earlier `PA[NIC: console_server] ready` episode, one level up.
### Added — one-shot reply capabilities: reply forgery is now unrepresentable (roadmap 1.3)

`SYS_IPC_RECV` mints a **`CAP_REPLY`** into `CAPSLOT_REPLY` of the receiving task,
naming the sender of the message it just dequeued. `SYS_IPC_REPLY_TO` requires that
capability and **consumes** it.

The reply used to be routed by `endpoints[ep].last_sender` — a mutable field
overwritten by the next receive. Replying to the correct client was therefore a
**convention** the server had to honour ("must precede the next recv, which would
overwrite last_sender"), not a property the kernel enforced. The bounded queue in
the entry below sharpened that: a server can now hold several dequeued requests
while only the newest was nameable.

Three properties that convention could not provide:

| Attempt | Before | Now |
|---|---|---|
| reply to a client you never received from | routed by whatever `last_sender` held | no capability → `SYS_ERR_PERM` |
| reply twice to one request | permitted | first reply consumed the right |
| reply to the wrong client | a discipline the server had to keep | the right names the client and cannot be retargeted |

**Two subtleties that were bugs first.**

A *dropped* reply still spends the right. The first draft returned success without
consuming when the client was no longer blocked — which preserved exactly the
hazard the capability exists to remove: a retained right outlives its request, so
if that client later made a **new** call and blocked, a reply issued now would land
on an unrelated request. Issuing a reply spends the right whether or not anyone was
still listening. A `-2` retry, by contrast, must *keep* it — the server is being
asked to repeat that reply.

And `cap_consume_slot()` is new, because `cap_install_object` had no counterpart:
`caps_in_use` was incremented on NULL → occupied and decremented **nowhere in the
tree**. Clearing the slot by installing a `CAP_NULL` would have leaked one count
per receive and wedged every long-running server at `MAX_CAPS_PER_TASK` — the
failure arriving as a hang thousands of messages after the cause, invisible to every
short test. It is explicitly *not* a revoke: it forgets one slot in the caller's own
cspace and touches no derived capability.

**`captest` 84 → 88 checks, falsified in two directions:** removing the drop-path
consume fails `reply-twice-to-one-request-allowed`, and reverting to `last_sender`
routing fails it too. One of the four checks was also *renamed* after falsification
showed it did not test what its name claimed — `CAPSLOT_REPLY` is per-task, not
per-endpoint, so it witnesses one-shot consumption rather than the independence of
endpoint and reply authority.

### Changed — endpoints are a bounded FIFO, not a single mailbox slot (roadmap 1.3, **[I-5]**)

An endpoint used to hold exactly ONE in-flight message. Every additional sender
got `-2` and polled from ring 3, so N clients on one server spent their slices
colliding rather than working — contention was a busy-wait, and fair service could
not be expressed at all, because the queue that would order requests did not exist.

Each endpoint now owns a bounded ring of `EP_QUEUE_SLOTS` (4) messages. `-2` means
the ring is genuinely **full**, which under normal service it is not, so the common
contention case stops being a retry loop and becomes an enqueue. Bounded is the
point: the depth is fixed at compile time, so a sender cannot make the kernel
allocate, and a server that stops receiving cannot be used to grow kernel memory
without limit.

**Measured, not asserted.** `EP_QUEUE_SLOTS=1` rebuilds the previous single-slot
behaviour exactly, which is the A/B. On the 4-client concurrency test under
single-core starvation, 12 boots each:

| Depth | Mean | Spread |
|---|---|---|
| 1 | 7042 ms | 6648–7694 ms, in **three discrete clusters ~520 ms apart** |
| 4 | **5162 ms** | 11 of 12 within **15 ms** |

The clustering matters more than the 27%: single-slot completion times quantised
into steps, each step one more collision-and-retry round. The queue removes the
quantisation, which is contention disappearing rather than work merely going
faster.

Three details are security properties rather than conveniences:

- **Each slot carries its own sender id.** The reply path authorises by
  kernel-recorded sender identity, so a queued message must remember who sent it;
  one shared `sender_task` field would be overwritten by the next sender, which
  with a queue becomes cross-client reply misrouting.
- **Slots are scrubbed on dequeue.** A slot outlives the message in it and the
  next sender may be a mutually distrusting task — without scrubbing the ring is a
  residue channel between them.
- **Both copies go through a kernel buffer.** `copy_from_user` before a slot is
  taken (a fault must not publish a half-filled message), and dequeue before
  `copy_to_user` (a faulting copy must not consume a request whose sender is
  blocked awaiting its reply).

Regression: 16 targets including `captest` (84 checks), `fs-conc`, `fs-perms`,
`console-isolation`, `session-smp`. **Not** the whole of 1.3 — the receive side
still polls an empty queue, and the one-shot reply capability that would make reply
forgery structurally impossible is still to come.

### Fixed — a permanent IPC refusal was retried forever, hanging the FS tests (G-8 signature C)

`smoke-fs-conc` and `smoke-fs-persist` — both *gating* — hung intermittently on a
**uniprocessor** boot: the serial log stopped at `[fs_server] filesystem
provisioned` and nothing followed. Reproduced at **3 in 30** under single-core
starvation, and bimodal: 17 boots in 6–8 seconds, 3 unfinished after **600**.

**The mechanism.** `SYS_CONNECT_FS_SERVER` returns `-1` until `fs_server` has
completed `SYS_REGISTER_FS_SERVER`, and the clients become runnable at the same
instant as the server, so losing that race is ordinary. The client called connect
**once and discarded the result**, then issued requests through an empty
capability slot — and every one returned `SYS_ERR_PERM` (**-1**) into

```c
while ((r = sys_ipc_call(...)) < 0) spin_delay();   /* retries -1 forever */
```

`SYS_ERR_PERM` is -1 and the only retryable code is -2. They were always
distinguishable; nothing distinguished them. Four separate userspace loops had the
same shape.

**Why this is a security bug, not only a robustness one.** Fail-closed has to mean
*stop, loudly, where authority was refused*. A refusal retried forever is
indistinguishable from a hang, so the one event the capability system exists to
make visible becomes the one nobody can see — revoke a capability out from under
any of these loops and the task wedges silently instead of reporting denial.

**The fix.** `syscall.h` now states the retry contract explicitly (`IPC_AGAIN` is
the only retryable code; `ipc_transient()` is the predicate). All four loops —
`fsclient`, `fs_server`, `console_server`, `consoletest` — retry transient-only and
bounded, and report permanent refusals. `fs_connect_retry()` retries the connect,
the same discipline `fs_server` already applied to its own registration on the
other side of the same race.

| Build | Starved single-core boots | Result |
|---|---|---|
| before | 30 / 30 | **3 and 5 hangs** |
| after | 40 | **0** |
| race restored, retry discipline kept | 30 | **2 hit the race, 0 silent hangs** — each reported `FAIL ipc-refused rc=-1` |

The third row proves the halves independently: the connect retry removes the
failure, and the retry discipline converts a silent unkillable hang into a
diagnosable message.

**A published diagnosis was wrong, and is corrected.** This was first recorded as a
livelock caused by single-slot endpoint contention (**[I-5]**), and roadmap 1.3 was
promoted to a correctness item on that basis. It was neither. A hung boot showed
**not one byte of IPC traffic on any endpoint** — contention produces traffic and
then stalls; zero traffic means the clients never had a capability. `TESTS.md`,
`docs/LIMITATIONS.md` §2.2 and `docs/ROADMAP.md` 1.3 are corrected; 1.3 returns to
its original standing as a real limitation with no witness of it hanging anything.

### Added — `HANG_WATCHDOG`, because the hang left no log to read

The clients in `smoke-fs-conc` print nothing on the happy path, so a wedged boot
and a slow one produced byte-identical serial output: 120 seconds of silence. The
watchdog dumps every task's scheduler state, each task's parked instruction
pointer, and every endpoint carrying traffic, then **lets the boot continue** —
halting would stop a merely-slow boot from going on to pass, which was the
hypothesis under test. Three dumps 1200 ticks apart showed byte-identical
instruction pointers and no endpoint traffic at all, which is what identified the
mechanism. Off in the ship kernel; falsified by firing it deliberately on a healthy
boot.

### Changed — the SMP session soak is advisory until finding G-8 is diagnosed

*(2026-08-09. It was diagnosed on 2026-08-17 and the job gates again — see the top of
this section. The condition this entry set, "restore it in the same commit that
resolves G-8 and quote a rate", was met rather than quietly dropped.)*

The soak is reporting a reproducible intermittent failure on `main` at **2–3% per
boot** — 1 in 45 pinned to two host cores, 1 in 45 on a runner. **Two distinct
signatures** have been captured: one stalling mid-output after 9 of 12 checks, and
one where boot never reaches the login prompt at all, its serial log ending at
`[console_server] ready`.

That second signature is the `smoke-console-smp` deadlock's, verbatim — fixed in
PRs #112–#115, stress-green 24/24, 24/24 and 30/30 since. So the open question is
whether that fix is incomplete or a second defect presents identically. It is
**not** the IPC lost-reply race below (`#116` is in every tree measured), and the
claim-invariant checker's 30/30 does not exclude a leaked claim — 30 boots witness
a 2% event less than half the time.

**A rate is not a mechanism**, and neither is one capture. This repo has erred in
both directions already — `smoke-console-smp` was a real deadlock called flaky, and
the `SCHED_INVARIANTS` report was a correct kernel called broken — and this
finding's own first draft guessed "slow `apropos`" from a single capture, which the
very next capture falsified. Signatures recorded; mechanism not claimed.

So the job runs on every PR and reports, but no longer blocks, and `SOAK_RUNS`
rises to 45 in CI so an advisory job actually witnesses what it reports (~75% of
runs, against ~37% at 15). Gating on a check that reddens a third of the time
teaches everyone to press re-run, which is the reflex that hid the console-smp
deadlock for months. Restore it to gating in the same commit that resolves G-8 —
either way — and quote a rate, not a green run. See `TESTS.md` and
`docs/LIMITATIONS.md` §5.2c.

### Changed — verify the build's own inputs and gates, not just the kernel's

Three follow-ups from the **[I-6]** / IPC-race work, all the same shape: something
was being trusted that had never been checked.

**The newlib fetch retried the wrong error class.** `tools/build_newlib.sh`
downloads a 9 MiB tarball and passed `--retry 3` — but curl's plain `--retry`
covers only what it calls *transient*: a timeout, an FTP 4xx, or HTTP
408/429/500/502/503/504. A connection that dies mid-body is `CURLE_RECV_ERROR`
(exit 56), which is **not** in that set, so the retry never fired for it. One
dropped read reddened CI on PR #116 with a failure that had nothing to do with
the tree. Now `--retry-all-errors --retry-delay 3 --retry 5` with `-C -` to resume
the partial transfer instead of restarting from zero.

Resuming into a partial file is safe only *because* the checksum is
unconditional, and it is: verification runs on every invocation, not just after a
fetch, so a tarball that arrived by any route — resumed, cached, or dropped in by
hand — is checked before it is trusted.

**A rejected artifact used to wedge the tree.** The fetch is skipped whenever the
tarball exists, so a tarball that failed verification was re-read and re-rejected
by every subsequent build, with no way out but a manual `rm`. It is now
quarantined to `.rejected`: the next run re-fetches cleanly, the evidence is kept,
and the current build still refuses. Failing closed should not also mean failing
*stuck*.

**The pin itself was never exercised** — `make smoke-newlib-tamper`. That
SHA-256 is the only thing between a compromised upstream and the libc every
userspace binary links against, and an unexercised pin is an assumption, not a
control; a gate that has quietly stopped checking looks exactly like one with
nothing to reject. The test asserts tampered bytes are refused **before
unpacking** (tar has had path-traversal bugs; don't touch the payload until it is
trusted) and that the artifact is quarantined — *and* that the genuine tarball
still passes, because a gate that refused everything would sail through the
negative control alone. Falsified by disabling the checksum: 3 controls fail. No
network or QEMU needed; it runs in seconds.

**The soak gate could have gone green on nothing.** As first written it sent each
run to `/dev/null` and trusted the exit status, so a `session_test.py` that
degraded into a no-op would have reported 15/15 green over 15 boots that tested
air — the same "a test that cannot fail is not evidence" trap the soak exists to
close, reintroduced by the soak itself. Each run must now emit `SESSION_TEST:
PASS` **and** clear `SOAK_MIN_CHECKS` (default 8) `[ok]` steps; a run that exits 0
with too few is reported `VACUOUS` and fails the gate. Passing runs print their
check count, and failing runs print their output instead of discarding it.
Falsified by raising the floor above what the test can produce.

**`smoke-fs-conc` was failing as a timeout, not a defect.** It waits on several
concurrent clients and was using the 40s default sized for single-client tests;
on a loaded host it ran out of budget with **zero** `CONC_SELFTEST: FAIL` — it
never reached a verdict at all. Given its own `CONC_TIMEOUT` (default 120s),
following the existing `PERSIST_TIMEOUT` precedent. This is a max-wait, not a
sleep: healthy runs still finish in seconds, and a genuine failure or hang still
fails — just after a wait long enough to tell "hung" from "slow".

### Fixed — an IPC lost-reply race that wedged the shell mid-print under SMP

A client blocking in `SYS_IPC_CALL` could have its reply **silently discarded and
the discard reported to the server as a successful delivery**. The client then
parked forever on a reply that could never arrive. It reproduced as an
intermittent console hang under `-smp 4` — the shell stopped partway through a
line with the console server idle and the system otherwise alive — on roughly
**1 boot in 5**.

**The bug.** `h_ipc_reply_to` classifies the client three ways:

| client shows | meaning | action |
|---|---|---|
| `state == TASK_BLOCKED_IPC` | blocked and waiting | deliver |
| `pending_block == TASK_BLOCKED_IPC` | committed, not yet published | return `-2`, server retries |
| neither | not waiting on us | return `0`, drop the reply |

That third case is correct only if "neither" genuinely means *not waiting*. There
were two intervals where a client that was very much waiting showed neither:

1. **`h_ipc_call` published the request before the intent.** `sys_ipc_send()`
   made the request visible under `ipc_lock`, and only afterwards was
   `pending_block` set. A server on another CPU could receive, service and reply
   inside that gap — landing in case 3.

2. **`ipc_publish_pending_block` cleared `pending_block` outside the lock**, then
   set `state` inside it. For the instructions in between, the task again
   advertised neither.

Both `console_server` and `fs_server` reply with `SYS_IPC_REPLY_TO`, so both were
exposed. The mailbox path (`sys_ipc_reply` → `sys_ipc_send`) was never affected:
`ipc_publish_pending_block` re-checks `has_message`, which is the same
double-check discipline the reply-to path was missing.

**The fix.** Make the declaration cover the whole interval. `h_ipc_call` now sets
`pending_block` *before* the request becomes visible (and withdraws it if the
send fails), and `ipc_publish_pending_block` clears it **under `ipc_lock`,
atomically with the state write** — the same lock `h_ipc_reply_to` takes, so from
another CPU the transition is indivisible. A client is now always either
`BLOCKED_IPC` or `pending_block`-committed from the moment its request can be
seen until it is genuinely done waiting.

**Why it hit the login-failure path.** That path issues several `print`s
back-to-back with no intervening read, so the server is already parked in `recv`
and answers at its fastest — which is precisely when it can reply inside the
window. The hang always appeared mid-`"Login incorrect ("`.

| Kernel | Interleaved boots | Hangs |
|---|---|---|
| before | 45 | **9** (20%) |
| after  | 25 | **0** |

Measured by alternating both ISOs in one loop so host load hit each arm equally;
an earlier non-interleaved comparison produced a misleading 3-vs-0 in the other
direction and was discarded. Fisher's exact on the interleaved data, p ≈ 0.014.

**Witness.** `make smoke-session-smp-soak` (`SOAK_RUNS`, default 15). A single
boot cannot witness a 1-in-5 defect — it passes four times in five, which is
exactly how this survived every green smoke job — so the gate requires N
consecutive clean sessions and treats one hang as a failure, never a retry. It
was falsified against the pre-fix kernel: 2/10 boots hung, gate red.

### Changed — `this_cpu()` no longer reads LAPIC MMIO on every call (**[I-6]**)

`get_current_task()` is the kernel's "who is the subject" accessor: ~110 call
sites across `capability.c`, `syscall*.c`, `paging.c`, `kaudit.c`, `storage.c`
and the fault handlers, hit several times per syscall. Every one of those calls
went through `this_cpu()`, which read the LAPIC ID register at `0xFEE00020` — an
uncacheable mapping, hundreds of cycles per read. It was, by a wide margin, the
dominant avoidable cost in the syscall path.

**The fix.** The CPU already carries its own identity in a register. Every CPU
`ltr`s a *different* TSS — it has to, because RSP0 and the IST stacks are loaded
from the running CPU's TSS on a ring-3 → ring-0 transition — and those selectors
are laid out linearly: `0x38` for the BSP (`setup_tss64`, `src/boot/multiboot.S`)
and `0x48/0x58/0x68` for APs 1..3 (`ap_tss_selector`, `src/kernel/gdt.c`). So

```
cpu = (str() - 0x38) / 0x10
```

`str` is a register read: no memory reference, no serialisation, legal at CPL 0
(UMIP blocks it at CPL 3 only). TR is written once per CPU at bringup and never
again, so the answer cannot go stale mid-syscall. In the non-SMP build the
function compiles to `return 0` — the read was answering a question that had a
compile-time answer.

**Why not the `%gs`-based per-CPU block** that roadmap 1.2 / **F-1.1** sketches:
making a per-CPU base survive a ring transition requires `swapgs` in every ISR
entry and exit. The ring-3 return paths (`scheduler.c`'s iretq epilogue and
`drop_to_ring3`) load `0x33` into `%gs`, and loading a selector into `%gs` zeroes
the GS base in long mode — so a base installed without `swapgs` does not survive
the first return to ring 3. Doing it properly means a CS-conditional swap on
every entry (exceptions arrive from ring 0 too), matching swaps on every exit
including the epilogue that `iretq`s into a *different* task's frame, and the
NMI/IST re-entrancy hazard that has produced a long line of CVEs in kernels with
more reviewers than this one. `str` gets essentially the same win for none of
that risk, and does not preclude doing `%gs` later — roadmap 1.2's other half
(per-CPU IRQ-nesting state for **[C-3]**) still wants it.

**The witness.** The derivation is a claim about a GDT layout owned by two other
files, tied to this one by nothing the compiler checks. If either moves,
`this_cpu()` starts returning another CPU's index and every `get_current_task()`
on that core silently names the wrong task — one core reading and writing
another's current-task slot, the claim invariant violated from a direction no
scheduler assertion watches. So `percpu_id_verify_self()` runs **on each core**,
at the moment that core's TSS is loaded, and compares the `str` derivation
against the LAPIC — the independent oracle it replaced. Disagreement panics
there, naming both answers, before any task has run. This is not gated behind a
self-test flag: it costs one MMIO read once per CPU at bringup.

`PERCPU_SELFTEST` (`make smoke-percpu`) then asserts the witness bitmask shows
the comparison actually *happened* on every online CPU, so a core that skipped it
fails rather than passing by absence. It requires ≥2 cores: on one CPU the
mapping yields 0 for the only right answer, so a UP run cannot fail and the test
refuses to pass vacuously.

Both halves were falsified before landing — a deliberately wrong stride panicked
at AP bringup (`TR=0x48 str-derived=2 lapic=1`), and setting `EFER.SCE` tripped
the `FAIL` marker.

### Fixed — a one-sided `swapgs` in the staged SYSCALL entry path

Found while tracing the above. `syscall_entry` (`src/kernel/lowlevel64.S`)
executed `swapgs` on entry with no matching swap before `sysretq`. It is
currently unreachable — `init_syscall_instruction_path()` programs
STAR/LSTAR/SFMASK but nothing sets `EFER.SCE`, so `SYSCALL` raises #UD and ring 3
reaches the kernel exclusively via `int $0x80` — and inert, because the kernel
keeps no per-CPU GS base for the swap to move. But it is armed: whoever enables
`SCE` or introduces a GS base inherits a swap that hands the kernel's per-CPU
pointer to ring 3 on the first syscall.

The pair is now balanced, and the stub documents the three preconditions that
still make enabling `SCE` unsafe — chiefly that `current_kernel_stack_top` is a
single global the SMP scheduler updates only for CPU 0, so an AP entering there
would load CPU 0's kernel stack and two cores would execute on one stack.
`PERCPU_SELFTEST` asserts `EFER.SCE` stays clear, turning a plausible one-line
"optimisation" into a red CI run rather than cross-CPU stack corruption.

### Fixed — an intermittent SMP scheduling deadlock that had been dismissed as a flaky test

`smoke-console-smp` failed roughly a third of the time and had been treated as
flaky. It was not flaky. It was correctly reporting an intermittent **kernel
deadlock**, and every retry was a real defect going unlogged.

**The bug.** `preempt_on_tick` claimed the incoming task unconditionally but
released the outgoing one only on a ring-3 tick:

```c
if (cur > 0 && cur < MAX_TASKS && ring3) {   /* release: gated on ring3   */
    task_running_cpu[cur] = -1;
}
task_running_cpu[next] = cpu;                /* claim:   unconditional    */
```

A ring-0 tick therefore switched the CPU to `next` while leaving `cur` claimed
forever. Every selection loop skips a claimed candidate, so the victim stayed
`RUNNABLE`, kept a valid resumable context, and became unschedulable **by every
CPU in the system, including the one holding the claim**. The result was a
livelock: timer ticking, surviving tasks spin-yielding, one task stranded.

The guard that should have prevented it was scoped to the BSP, on the reasoning
that "syscalls run with interrupts cleared, so a ring-0 tick never lands
mid-syscall". That reasoning does not hold: `spin_unlock` ends with an
unconditional `sti` (**[C-3.1]**), so the first lock a syscall takes and releases
re-enables interrupts for the rest of that syscall.

**The fix.** Never switch a CPU away from a live ring-0 context — the tick path
can save a ring-3 trap frame and nothing else, so a CPU may only be switched away
when it is in ring 3 or parked in an idle loop. This applies the BSP's existing
guard to every CPU, *removing* a special case rather than adding one. APs now
mark themselves idle when they park, without which they would have declined every
tick and SMP would have silently degraded to one CPU.

| Build | Runs | Failures |
|---|---|---|
| before | 12 | **6** |
| after | 24 + 24 + 30 | **0** |

**Why it looked like flakiness.** Under TCG each guest vCPU is a host thread. On
an idle many-core workstation a 4-vCPU guest gets a core each, the window never
opens, and the *broken* kernel scores 10/10 green. It fails only where vCPUs
outnumber host cores — which is what CI runners are. The environment that made it
look like noise was the developer workstation.

**Why the leaked claim mattered more than the hang.** Underneath it, a syscall had
been abandoned mid-flight with its kernel stack discarded while `saved_ksp` still
held a stale ring-3 frame. So "repairing" the stale claim would have been strictly
worse: the task becomes schedulable again and resumes from that frame, discarding
the syscall's work — including, if it was abandoned inside a critical section, a
lock it will never release. `cap_lock` is taken by every capability mutation, so a
task abandoned holding it deadlocks every capability operation in the system,
reachable from ring 3 with no capability required. Two such "defensive" repairs
were written during this work and measured: they took the stress harness from
**24/24 to 13/20**. Both sites now carry a "do not do this" comment with the
numbers.

As a security property this was an availability failure reachable with **no
capability at all** — ordinary scheduling could render another task permanently
unschedulable, entirely outside the capability model that is meant to describe all
authority. Same shape as **[I-3]**.

**Also in this series.**

- `make smoke-console-smp-stress` — builds once, boots N times with QEMU pinned to
  a small host CPU set, reports a *rate*. Validated against the bug it measures
  (6/12 before, 0/30 after). Refuses to run when another QEMU competes for the
  same cores, which had silently contaminated a 20-boot measurement.
- `SCHED_INVARIANTS=1` — machine-checks
  `task_running_cpu[t] == c <=> percpu_current_task[c] == t` at every tick,
  panicking with the task, CPU and observer. **Not wired into CI**: it reports a
  real, not-yet-root-caused violation in which `init`, blocked in `sys_wait()`,
  stays claimed by a CPU that has moved on (~1 boot in 5). Latent — a blocked task
  is not selectable — but it must be root-caused before roadmap 1.1 touches this
  path.
- `scheduler_init` now initialises `blocked_waiter` to `-1` instead of leaving the
  `.bss` zero, which claimed task 0 was blocked on every static endpoint. Benign
  only because every consumer happened to test `> 0` rather than `>= 0`.
- The comment on `smp_sched_enabled` claimed "normal SMP boot leaves it 0".
  `smp_bringup()` sets it on every SMP boot; the stale comment sent an
  investigation of this very hang down a blind alley before gdb showed it set.

### Added — kernel objects are carved from untyped memory (`CAP_UNTYPED`, roadmap 0.3, finding **[I-7]**)

Every kernel object used to be an entry in a fixed `.bss` array — `tasks[64]`,
`endpoints[128]`, `notifications[64]`, `cspace_pool[64][256]`. The problem was
never that the numbers were small. It was that the capability graph could not
answer *"who may create a kernel object?"*, because the answer was "everyone, and
the storage already exists". Object creation sat outside the model the entire
security argument is stated over.

Following seL4, a **`CAP_UNTYPED`** capability now names a region of physical
memory, and **`SYS_RETYPE`** carves typed objects out of it:

- **Attributable.** A task can only create objects in a region it holds a
  capability for, so "which authority paid for this kernel memory" is answerable
  by inspecting the capability graph.
- **Preventable.** Delegating a small region to a task is a hard bound on the
  kernel memory it can ever consume — the first confinement property the system
  can state without an asterisk.
- **Capability-governed lifetime.** An object exists exactly as long as some
  capability names it, instead of forever because an array slot is never
  reclaimed.

**The arena and the split.** 4 MiB is reserved from the physical pool at boot —
the same pattern the loader staging buffer and the RAM vdisk already use, and for
the same reason: a kernel object table in `.bss` is charged against the
`__bss_end <= USER_PHYS_BASE` linker assertion whether or not it is used. It is
split once into `UNTYPED_KERNEL`, which backs per-task cspaces and for which **no
capability is ever minted**, and `UNTYPED_ROOT`, which `init` holds and delegates
onward. With a single shared region, "userspace exhausted kernel memory" and "the
system can no longer create a task" would be the same event.

**Bump allocation, deliberately.** Within a region the watermark never moves
backwards; destroying an object does not return its bytes. This is a safety
property, not a simplification. With a free list, an object's bytes can be handed
straight back out and retyped as a *different* class while a stale capability
still names the old address — type confusion through reuse. A monotonic watermark
makes bytes reusable only after every capability into the region has been
revoked, which is the same event that invalidates the stale reference.

**What moved.** Per-task cspaces are now `KOBJ_CNODE`s from untyped memory,
removing **516,096 bytes (504 KiB) of `.bss`**. Endpoints and notifications are
retypable from ring 3 into an index range above the static tables, which remain
as a compatibility shim for the well-known service objects the boot protocol
names by index; `endpoint_by_index` / `notification_by_index` are the single
resolvers and return `NULL` for a destroyed object, so IPC fails closed on a
stale capability at the same choke point that enforces the capability.

**Destruction by reachability, not refcounts.** `kobj_gc` mark-and-sweeps the
capability graph from `cap_revoke` and `task_teardown`. A refcount would have to
be maintained at every mint, transfer, move, grant, revoke, null and teardown site
across *both* the C and safe-Rust halves of the capability implementation, where
one missed site is a leak and one double-decrement is a use-after-free reachable
from ring 3. Reachability is computed from the same graph the security argument
is already stated over, so the two cannot disagree.

**Capability-addressed, like IPC.** `SYS_RETYPE` (90) and `SYS_UNTYPED_INFO` (91)
are `SC_NONE` in the dispatch table and resolve their region from the caller's
slot argument. A fixed table slot would repeat finding **[C-1]** exactly: gating
on a capability every task happens to hold while never consulting the one that
names the resource.

**Witnesses.** `captest` 41 → 84 checks, covering both directions — a held
`CAP_UNTYPED` really does create usable, distinct, destroyable endpoints, and
every malformed request is refused *without spending any of the region*, since a
refusal that consumes what it refused is a denial-of-service primitive. Four
independent gates were falsified against the patched kernel to prove the suite
detects their removal: the reserved-slot floor, the cspace range checks, the
capability-type check together with the kernel-reserve guard, and `kobj_gc`
itself. (An earlier falsification attempt on the type check *alone* was **not**
caught — the range check masked it — which is why the wrong-type probe now uses a
`CAP_NOTIFICATION` whose `object` is a valid untyped index.)

**Not migrated.** `tasks[]` — a TCB is reachable from the scheduler's hot path
and from every trap frame. Retyping a `KOBJ_CNODE` from ring 3 is refused: no
capability type names a CNode and no syscall installs one as a task's cspace.
Reclaiming a dead task's cspace needs `cap_lookup`'s NULL-cspace → root-cnode
fallback removed first, or freeing one would be an authority *escalation* rather
than a crash.

**Note for roadmap 1.1 — C-3.1 bit during this change, and was measured.**
`create_task` now calls `kobj_alloc`, which made task creation take a spinlock
for the first time; `task_teardown` likewise, via `kobj_gc`. Both run on paths
that keep interrupts masked deliberately — task teardown is reached from the
page-fault handler, and spawn runs inside the ring-3 startup handshake — and
`spin_unlock` ends with an unconditional `sti` (finding **[C-3.1]**).

The symptom was `smoke-console-smp` failing: the shell banner never arrived
within the timeout, the same signature the reverted per-CPU-lock attempt produced
(roadmap 1.1) and for the same underlying reason.

The fix makes the untyped critical section **IF-transparent**: `ut_lock` /
`ut_unlock` save and restore `RFLAGS` around the region, so `spin_unlock`'s `sti`
is a no-op for every caller whatever state it was in. Done once in the helper
rather than as a `pushfq`/`popfq` bracket at each call site, since the number of
call sites will only grow. It becomes redundant — not wrong — once 1.1 makes
`spin_unlock` IF-preserving.

Measured, because `smoke-console-smp` was failing on `main` too and a small sample
would have concluded almost anything:

| Build | Runs | Failures |
|---|---|---|
| `main` | 6 | 2 |
| this branch, before the IF fix | 3 | 2 |
| this branch, after the IF fix | 6 | 1 |

So the regression was real — the pre-fix branch was materially worse than `main`
— and the fix restored parity.

*Postscript (2026-07-28):* the residual failures on `main` above were called a
"flake" here. They were not. They were an intermittent SMP scheduling deadlock,
diagnosed and fixed the next day — see the entry at the top of this file. The
IF-transparency fix in this entry remains correct and necessary; only the
characterisation of the background failures was wrong.

`untyped.c` also defers *arming* that lock until the end of `scheduler_init`, so
no lock is taken during early boot at all. Between the deferral and the
IF-transparency, this is the third subsystem to work *around* C-3.1 rather than
fix it.

This completes **Track 0** of the roadmap.

### Added — SMT sibling threads are parked (disable-SMT in software; closes the co-residency side channel)

Flush-on-switch (previous entry) closes the *time-sliced* cache/predictor side
channel, but a sibling **hyperthread** shares its core's L1/L2 *concurrently*, so a
spy on the sibling can snoop the primary thread's live state — which a time-slice
flush cannot cover. Horus now **disables SMT in software** by parking sibling
threads:

- **Topology detection.** `cpu_detect_features` reads CPUID leaf 0x0B subleaf 0 to
  learn how many low APIC-id bits identify the SMT thread within a core
  (`platform.smt_shift`). A logical processor whose those bits are non-zero is a
  secondary (sibling) thread; the primary of each core (and the BSP) has them zero.
- **Parking.** At AP bringup (`ap_entry64`), a sibling does the full early
  setup — GDT/IDT/CR4/TSS and `lapic_enable` — then **parks** (`sti; hlt` forever)
  *before* starting its scheduler timer. It never enters the scheduler, so no
  ring-3 task ever runs on it and no untrusted work co-resides on a core; its
  core-partner (the primary) does all the work. It keeps interrupts on so it stays
  TLB-coherent and services TLB-shootdown IPIs.
- **Shootdown accounting.** Parked siblings still receive the all-excluding-self
  shootdown broadcast and ack it, so the ack total is now `present = online +
  parked` (not just the schedulable `online`) — under-counting would let an
  initiator return before a parked sibling flushed.
- Boot logs `smp: N cores online, K SMT siblings parked (co-residency avoided)`.

Verified: new gated **`make smoke-smt`** boots a 2-core × 2-thread topology and
asserts the two siblings are parked *and* the system still boots to the shell
(parked siblings + shootdown do not wedge); `make smoke-smp` (default `-smp 4`,
no SMT — `smt_shift == 0`, nothing parked) is unchanged and passes; default boot
unaffected; clean build. `docs/LIMITATIONS.md` + `SECURITY.md` updated (SMT
co-residency moves from residual to handled; the cost is the siblings' compute, and
core-scheduling to reclaim it for same-domain work is future work).

### Added — flush-on-switch between distrusting tasks (SMP scheduler maturity #1, side-channel hardening)

The scheduler preempts and time-slices mutually distrusting ring-3 tasks on a
core, but left the **microarchitectural** state (branch predictor, L1D cache,
store/fill/load buffers) untouched across the switch, so an incoming task could
snoop the outgoing one's residue. The only prior mitigation was `CR4.TSD` (deny
ring-3 `RDTSC`), which raises the bar on the *timer*, not the *channel*.

On a scheduler switch to a **different** ring-3 task, the kernel now evicts that
state — **IBPB** (`IA32_PRED_CMD`), **L1D flush** (`IA32_FLUSH_CMD`), and **MDS**
via `VERW` — in `cpu_flush_microarch_state`. Robustly and securely:

- **Detected, never assumed.** Each barrier is gated on a CPUID-detected
  capability (`CPUID.7.0:EDX` bits 26/28/10), so an issued `wrmsr` can never `#GP`
  on a CPU that lacks the feature. Boot logs the real coverage
  (`sched: flush-on-switch IBPB L1D MDS`, or `none-available`).
- **No bypass.** The flush hooks the single switch chokepoint (`set_current_task`,
  which is called exactly when a CPU is about to resume a task), so every switch
  path — timer preemption, IPC block, yield, first entry — is covered, present and
  future. Same-task resumes and switches to the kernel idle task are skipped
  (per-CPU last-user-task tracking).
- **Verified.** New gated `make smoke-flush` (`FLUSH_SELFTEST`) asserts the stored
  flags match a fresh CPUID read, the flush path runs without faulting, and the
  switch policy flushes on a task change only (not on a repeat or on idle). Under
  TCG (CI, no KVM) the barrier CPUID features are not emulated, so the barriers are
  no-ops there and CI gates the *policy* + no-fault path; the `wrmsr`/`VERW`
  barriers and detection accuracy engage on real hardware / KVM.

Residual, documented: cache *partitioning* is still not done, and — critically —
this covers *time-sliced* co-tenancy only. A sibling **SMT** thread running
concurrently on the same core shares L1/L2 and is not covered; full isolation
needs SMT disabled or core scheduling (Roadmap Track 3). The rest of SMP scheduler
maturity — per-CPU run queues, priorities/fairness, CPU affinity — also remains.
`docs/LIMITATIONS.md` and `SECURITY.md` updated.

Verified: `smoke-flush` PASS, `smoke-session-smp` (the switch hook under -smp 4)
PASS, default boot unaffected, clean build.

### Fixed — generic (non-zero) copy-on-write break: two latent bugs fixed, path now tested

The generic COW break — the privileged page-copy path that `fork` would use — was
unreached by any runtime caller (fork is a non-goal; only the shared *zero* page is
broken today) and therefore untested. That absence hid **two latent bugs**:

- **Sole-owner infinite fault loop.** When the faulting task was the last owner
  (refcount 1), `rust_cow_copy_required` correctly returns "no copy needed", but the
  handler then merely re-incremented the refcount and returned **without upgrading
  the PTE** — it stayed COW + read-only, so the retried write re-faulted, forever.
- **Per-break refcount leak.** `alloc_user_physical_page` already sets a fresh
  frame's refcount to 1 for its single PTE, but the copy path incremented it again,
  leaving every COW-copied page at refcount 2. Teardown's `user_leaf_release`
  decrements and frees only at 0, so those pages were never reclaimed.

The break is now factored into `cow_break_pte()` and both cases are correct: the
sole owner is upgraded to writable in place (clear `PAGE_COW`, set `PAGE_WRITE`,
preserve NX — no copy, no loop), and a shared frame is duplicated into a private
writable page at refcount 1 with the shared frame decremented. A new gated
end-to-end test, **`make smoke-nzcow`** (`NZCOW_SELFTEST`), sets up a non-zero frame
shared read-only + COW by two PTEs (refcount 2) and asserts: the first write copies
to a *different* frame with byte-identical content while the sibling PTE and shared
frame are untouched (shared refcount → 1); and the sole-owner write upgrades the
PTE in place with **no** new allocation, content intact. Added to CI.

The zero-page break (`make smoke-cow`) and normal demand paging are unchanged and
still pass. `docs/LIMITATIONS.md` updated. (Lazy address-space reclamation — a dead
task's pages are released at slot reuse, not at death, to avoid a use-after-free of
page tables a CPU may still be walking — remains a deliberate, documented design
choice, not part of this fix.)

### Changed — boot log cleanup: microsecond TSC timestamps, no address noise, no stray AP digits

Follow-up polish to the Linux-style boot log:

- **Timestamps now advance.** They were sourced from the 100 Hz PIT tick, which
  is not running for most of early boot (interrupts come up late), so every line
  read `[    0.000]`. The clock is now the **TSC** (like Linux), calibrated once
  against PIT channel 2 (`kmsg_clock_init`, the same ~10 ms gate
  `lapic_timer_calibrate` uses), with **microsecond** resolution — e.g.
  `[    0.001804] mem: …`, `[    1.429916] smp: …`.
- **Address noise removed.** `boot: high-half OK, kernel at 0x… phys 0x…` is now
  `boot: high-half relocation verified`; the per-module `name@0x…` dump is now
  `boot: N boot modules loaded` (the manifest-verification line already reports
  the count); `smp: CPUs online` prints **decimal** `4` instead of
  `0x0000000000000004`.
- **Stray digits gone.** Under SMP the boot log showed a run of bare digits
  (`112323123`) before the `smp:` line — the AP trampoline
  (`ap_trampoline.S`) wrote `'1'`/`'2'`/`'3'` progress markers straight to COM1 at
  each real-/protected-/long-mode transition (3 APs × 3 stages). These debug
  writes are removed.

Verified: `make smoke` (uniprocessor, timestamps advance), `make smoke-console-smp`
(no stray digits, `CPUs online 4`, banner intact), `make smoke-session` (dmesg +
least-privilege), `make smoke-modules` (provisioning). Build stays reproducible.

### Added — Linux-style timestamped boot log + a root-only `dmesg` command

The kernel boot messages were an ad-hoc mix of `[tag]` prefixes (`[mem]`, `[smp]`,
`ATA:`, `HIGHHALF: PASS`). They now render like Linux `printk`: a monotonic
`[    S.mmm]` timestamp prefix (from the 100 Hz tick — early lines read
`[    0.000]`, just like real early boot) followed by a `subsys: message` line,
via new `kmsg()` / `kmsg_begin()` helpers in `terminal.c`. A boot banner opens the
sequence and the milestones read cleanly (`kernel ready, starting init (PID 1)`).
No behaviour change — only formatting; the smoke harness matches `*_SELFTEST: PASS`
markers, not boot info lines.

A **`dmesg`** shell command prints the kernel message ring (the existing 16 KiB
`klog` buffer that `print()` already feeds). It is **root-only**: the new
`SYS_DMESG` syscall enforces `uid == 0` against the caller's *kernel-attested*
identity (like Linux's `dmesg_restrict`), returning `SYS_ERR_PERM` otherwise. The
log is read in small chunks via an `(buf, offset, max)` ABI, so neither the shell
nor the kernel needs a multi-KiB buffer (the kernel copies from a small per-call
stack buffer — no shared state to race under SMP). Added to the centralised
capability-checked dispatch table with its compile-time slot assertion updated.

Verified: `make smoke` shows the reformatted boot log and still reaches the shell;
`make smoke-session` gains two steps — `dmesg` prints the boot log for root, and is
refused for a standard user — both pass. The session harness now also reports recent
serial context on an expect timeout.

### Changed — audit log is now forward-secure (tamper-proof for all history before a compromise)

The audit log was tamper-*evident* but not tamper-*proof*: every entry's MAC and
the running chain head were keyed by the single persistent per-boot pepper, so an
attacker who fully compromised the kernel and read the pepper could recompute a
self-consistent chain and rewrite history.

It is now **forward-secure** (forward integrity — Bellare–Yee / Schneier–Kelsey):

- A dedicated genesis key `K_0 = SHA256(domain ‖ pepper)` is derived once (the
  pepper itself is left intact for the password hash and user-DB tag). Each entry
  is MAC'd and folded into the head under the current key `K_i`, then the key is
  ratcheted one-way (`K_{i+1} = SHA256(domain ‖ K_i)`) and **erased in place**
  (`rust_audit_fs_record`). A kernel compromised at time _t_ holds only `K_t` and
  cannot recompute or forge any entry committed before _t_ — pre-compromise
  history is cryptographically unforgeable.
- Verification of that history moves to an external monitor recording the head via
  `SYS_AUDIT_DIGEST` (the kernel deliberately can no longer self-recompute old
  entries — that inability is the security property). An **unkeyed** sliding-window
  hash (`rust_audit_pub_init`/`_extend`, with an eviction-folded window start) lets
  the kernel still self-check the *retained* ring for accidental corruption after
  the keys are erased — a corruption detector, not anti-forgery.
- `SYS_AUDIT_DIGEST`'s 40-byte ABI (`seq ‖ head`) is unchanged; the CAP_AUDIT gate
  is unchanged.

Residual (the honest ceiling for a self-hosting kernel): entries logged *after* a
compromise, and whole-machine rollback, still need an external append-only anchor
(TPM NV monotonic counter / periodic PCR-extend of the head, or a remote WORM
sink). "Completely tamper-proof" is unachievable by crypto that runs inside the
attacker's own trust domain; forward integrity + a hardware/external anchor is the
maximum, and the anchor is the tracked next step. `docs/LIMITATIONS.md` updated.

Verified: 91 Rust unit tests including an external-verifier simulation that
re-derives every `K_i` by ratcheting `K_0` and confirms each recorded MAC, a proof
that each entry uses a fresh (ratcheted) key, and public-chain order-sensitivity;
`clippy -D warnings` clean; kernel links; `smoke-session` (login + sudo drive
`audit_log`) passes.

### Changed — capability use-after-revoke backstop is now active and precise: serial-keyed generations (finding 3.3)

The per-lineage generation counter — the defense-in-depth backstop behind
use-after-revoke and the IPC lookup/use TOCTOU revalidate guard — was in practice
**dormant**. It was keyed by a capability's `object`, and `lineage_check` treated
generation 0 as *always valid*. Because every capability in the running kernel is
created with generation 0 (all primordial roots, every `cap_install_*`, and
mint/grant, which inherited the source generation), a stale or snapshotted
capability passed the generation check unconditionally: the backstop did nothing,
and revocation correctness rested entirely on the structural sweep.

The reason it could not simply be "switched on" is that an `object`-keyed counter
cannot separate independent lineages: two capabilities to the same object share a
cell, so an object-wide bump would also invalidate live siblings and independent
same-object peers, breaking the least-privilege revocation guarantee (audit A1).
The generation layer is now keyed by each capability's globally-unique **`serial`**
instead, with **strict-equality** checking (no gen-0 escape hatch):

- `LINEAGE_GEN` is keyed by `serial`; empty and primordial (`0xC0DE****`) serials
  are exempt, so a hash collision can never invalidate a kernel root capability.
- On revoke, `revoke_subtree` bumps the generation of **exactly** the serials it
  enumerates (the target and its derivation subtree). A live sibling, ancestor, or
  independent same-object peer — a *different* serial — is never invalidated
  (A1 preserved), while a detached snapshot/copy of a revoked capability fails the
  check via its own bumped serial (finding 3.3 closed). A revoked capability is now
  invalidated by two independent mechanisms: its slot is nulled **and** its serial
  generation is bumped.
- Every C capability-creation site (`create_task`, `cap_install_from_root`,
  `cap_install_endpoint`, the sudo uid-0 caps, pipe endpoints, child-stdio and
  child-TCB grants, the revocation-set helper) stamps
  `generation = rust_lineage_current(serial)`, so a fresh serial that hashes onto
  a cell a prior revoke already bumped is born **valid**, not stale. The FFI
  (`rust_lineage_check` / `rust_lineage_bump` / new `rust_lineage_current`) is
  re-typed from `object: u64` to `serial: u32`; the capability struct layout is
  unchanged.

Residual: the 4096-slot table is still a lossy hash, so distinct serials can
collide and cause fail-safe *over*-invalidation (availability only, never an
authority leak) — the sole remaining A3 imprecision, to be retired by exact
per-serial storage (Roadmap Track 1).

**Verification:** two new Kani harnesses prove the invariants over the entire
`u32` space — `revoke_invalidates_recorded_generation` (after a bump, a capability
recording the pre-bump generation is invalid, and a bump never yields the pristine
0) and `revoke_does_not_touch_a_distinct_lineage_cell` (bumping one serial's cell
never invalidates a capability in a different cell). A new regression unit test
`test_gen0_snapshot_invalidated_after_revoke_finding_3_3` reproduces the exact
production scenario (a gen-0 derived capability whose snapshot used to survive its
parent's revocation) and asserts an independent same-object capability still
survives. Verified: 86 Rust unit tests, `clippy -D warnings` clean, `cargo kani`,
`make` (kernel links), and the QEMU `smoke-captest` (post-revoke-use refusals),
`smoke-session` (login/least-privilege/sudo), and `smoke-pipe` self-tests.

### Added — boot modules are verified against a SHA-256 manifest embedded in the kernel (audit A4)

A boot module becomes a **root-owned executable** in `/bin` that the shell will run, but its contents were trusted purely to the boot chain: anyone able to alter the ISO could swap a payload and have the kernel provision an arbitrary root-owned binary. The reproducible-build hash covered the *embedded* binaries, never the modules.

The kernel now embeds the SHA-256 of exactly the modules it was built to ship, and refuses anything else:

- **`tools/gen_module_manifest.sh`** generates `src/kernel/boot_module_manifest.h` at build time from the same `BOOT_MODULES` list the `boot.iso` rule consumes, so the manifest and the ISO cannot drift. It is a `main.o` prerequisite and rewrites the header only when the content changes, so an unchanged module set causes no rebuild churn. A build shipping no modules gets an **empty** manifest.
- **`boot_module_verify_all()`** runs at boot, after the multiboot tag walk and before any userspace exists. It hashes each module in place through `PHYS_KVA` (the same window the read syscall uses, via a new `rust_sha256` FFI over the crate's existing SHA-256) and requires an exact **(destination path, size, digest)** match, comparing with `rust_ct_eq`.
- **Fail closed at the choke point:** an unverified module is reported by `SYS_BOOT_MODULE_INFO` as an empty slot — so the `fs_server` provisioning loop skips it exactly as it skips a malformed one — and `SYS_BOOT_MODULE_READ` refuses its payload with `SYS_ERR_PERM`. It therefore can never reach `/bin`. An empty manifest verifies nothing, so a module-free kernel refuses every module it is handed: correct, since it attested to none.

No key is involved *by design*: the manifest ships inside the reproducible kernel image, so the image itself is the root of trust and an embedded key would be equally readable. The residual limitation is exactly that — this protects a tampered module payload, not a replaced kernel image, which is what pinned/attested builds (audit P4) and measured boot are for.

**New gating CI job `make smoke-modules-tamper`:** builds the kernel with its manifest, assembles a second ISO carrying the *same kernel* but one module payload corrupted by a single byte flip (size unchanged, so only the hash differs), and asserts the kernel refuses exactly that module and still boots. Falsification-tested — with verification neutered, the tampered module provisions happily and the gate goes red.

Verified: `smoke-modules` (all 23 modules verify and provision), `smoke-coreutils-shell` (a subset), `smoke` (module-free boot), 85 Rust tests including a `rust_sha256` known-answer + fail-closed test, `clippy -D warnings` clean, and `make reproducible-build` still byte-for-byte identical.

### Fixed — console_server no longer loses a startup race with its own endowment under SMP

An intermittent multi-core boot hang (`make smoke-console-smp` failing with `CONSOLE_SELFTEST: FAIL grant`, then timing out before the shell banner) was a spawn/endow ordering race, not a capability-system fault.

`init` launches the console server with `sys_spawn_named("console_server")` — which makes the child **runnable immediately** — and only *then* grants it the IPC gate and `CAP_IO_DEVICE`. The server's very first action is `sys_ioport_grant()`, which requires that capability. On one core the child cannot run until init blocks, so the grants always landed first; with SMP default-on the child can execute on another core *before* the grant arrives, be correctly refused for a capability it is about to be given, print `FAIL grant` and park forever. Nothing then drove the console, so the boot timed out.

The server now **retries the startup port-I/O grant** (bounded, `CON_GRANT_RETRIES`, yielding between attempts) so it waits for authority that is on its way. This waits for a capability to *arrive*; it never widens one — the kernel's `CAP_IO_DEVICE` check is untouched, and after the bound the server fails closed exactly as before. Because init grants the IPC gate (slot 3) before `CAP_IO_DEVICE` (slot 10), a successful port grant also implies the gate is in place.

Verified: `smoke-console-smp` run three times in a row (previously intermittent), plus `smoke-console`, `smoke-console-isolation` and `smoke-session-smp`.

### Added — machine-checked proofs that revocation hits exactly the target's subtree (audit A1)

The descendant-only revocation fix shipped with unit tests that *sample* serials; these two Kani harnesses prove the same invariants over the **entire** input space (every `u32` serial triple), by symbolic execution:

- **`revoke_descendant_never_nulls_ancestors`** — over a parent → child → grandchild derivation chain, revoking the grandchild's subtree leaves the parent and child intact (`typ` and `serial` unchanged) and nulls exactly the grandchild. This is precisely what the old equivalence-set matcher got wrong: it compared the target's `badge` against other caps' `serial`, so revoking a child also nulled its parent.
- **`revoke_root_nulls_every_descendant`** — the completeness half: revoking the root nulls the child *and* the grandchild, so no derived authority outlives its ancestor.

Together they pin revocation to exactly the target's subtree — no more (no ancestors, no siblings) and no less (all descendants). Kani also discharges the memory-safety checks and the loop-unwinding assertions on the closure, so the worklist is proved fully explored at the proof's size. `cargo kani` now verifies **6 harnesses, 0 failures** (up from 4). `rust/KANI.md` documents the new properties and the scope limits (single cspace, `object == 0`, so the shared `LINEAGE_GEN` static stays out of the model; the overflow fallback remains unit-tested).

### Fixed — boot modules can only land in `/bin` or `/usr/share/man` (audit A4, destination half)

Every boot module (the ported coreutils and their man pages, shipped as GRUB multiboot2 modules) is written into the store as a **root-owned** file — executables `0755` under `/bin`. The destination came straight from the module's cmdline with no validation, so a stray or tampered module list could plant a root-owned file at any path, including one with `..` components.

`fs_server.c` now gates every install on `module_dest_ok`: only a bare name (which defaults under `/bin`), a path under `bin/`, or a path under `usr/share/man/` is accepted; absolute paths and any empty, `.` or `..` component are refused. A rejected module is skipped with a log line instead of installed. Verified by `make smoke-modules` and `make smoke-coreutils-shell` (the real modules still provision and run end-to-end), plus `smoke-fs` / `smoke-init-fs`.

This is the *destination* half of audit A4. Module **content** is still trusted to the boot chain — verifying it in-kernel (embedded hash manifest vs. embedded public key + signed manifest) is scoped in `docs/ROADMAP.md` Track 2.1 and deliberately deferred rather than rushed, since it reorders the build graph or needs a new asymmetric primitive.

### Changed — Track 0 governance: `main` is branch-protected, code scanning is on (audit P1/P3/P5)

Acting on the audit's process findings (the assurance gap it called the highest-leverage fix):

- **`main` branch protection (P1).** The four hard-gate CI checks (Rust+clippy, kernel+ISO build, QEMU smoke-boot, reproducible build) are now **required** before merge, the rule is **enforced for administrators**, and **force-push + branch deletion are blocked**. Required CODEOWNERS review is intentionally left off while the project has a single maintainer (it would deadlock every merge — the P2 gap, documented as accepted).
- **Native code scanning + dependency security (P3).** Added `.github/workflows/codeql.yml` (CodeQL over the C kernel, SARIF → Security tab, advisory); enabled Dependabot vulnerability alerts + automated security updates; added the cargo ecosystem to `.github/dependabot.yml` and **grouped** GitHub-Actions updates into one PR (multi-ref actions like `codeql-action` must bump `init`/`analyze` together, else a v3/v4 mismatch fails CodeQL). Bumped `codeql-action` to v4.37.0.
- **Repository hygiene (P5).** Enabled `delete_branch_on_merge`; created the `dependencies`/`github-actions`/`rust` labels Dependabot needs. Pruning the ~55 already-merged branches and commit signing remain for the maintainer.

Docs updated (AUDIT-2026-07, ROADMAP Track 0, SECURITY). See docs/AUDIT-2026-07.md for the full findings.

### Fixed — capability revocation is descendant-only, not an equivalence-set sweep (audit A1)

Revocation nulled every capability whose `serial`, `badge`, **or** `object` matched the target. Since a derived cap records its parent's serial in its `badge` and all derived copies share the parent's `object`, that matched not just descendants but **ancestors, siblings, and any independent capability to the same object**. A supervisor that granted a revocable capability, then had the child revoke its copy, would find its *own* capability (and same-object peers) nulled too — a fail-safe but least-privilege-violating over-revocation.

`revoke_matching_in`/`lineage_matches` are replaced by `revoke_subtree`, which computes the target's exact **derivation subtree**: seed a bounded worklist with the target's serial, then close it under "child (`badge`) of an already-revoked serial", and null exactly those. Ancestors, siblings, and independent same-`object` capabilities are left intact. This builds on the A2 fix, which makes every derived cap record its immediate parent's serial in `badge` (a well-formed `serial → badge` forest).

Completeness is preserved as a fail-safe: if a subtree ever exceeds the worklist (`MAX_REVOKE_LINEAGE = 256` — hundreds of derived copies of one lineage, which does not occur in practice), the null pass *also* nulls every cap sharing the target's `object`. Because mint/transfer/grant all preserve `object`, that is a complete superset of the descendant set, so the fallback can only over-approximate — a descendant can never survive.

While fixing this, the lineage-**generation** mechanism (audit A3) was found to be **dormant**: no code path assigns a capability a non-zero `generation`, and `lineage_check` treats generation 0 as always-valid, so the object-keyed generation bump on revoke is a no-op and its hash collisions cannot invalidate anything today. Structural (descendant-only) revocation is the sole enforcement; the generation table is retained as dormant defense-in-depth and documented for a future per-object-exact rework if ever activated.

New Rust regression tests (revoke-child-leaves-parent/siblings, independent-same-object-cap-survives, overflow-fallback-is-complete) plus the existing suite pass; verified on hardware by `smoke-captest` / `smoke-proc` / `smoke-aspace` / `smoke-session` / `smoke-fs-conc`. Docs updated (AUDIT-2026-07, ROADMAP Track 1.1/1.3, SECURITY, LIMITATIONS, ARCHITECTURE, README).

### Fixed — SYS_CAP_GRANT goes through the locked, accounted cap-write path (audit A2)

`SYS_CAP_GRANT` delegated a capability into a supervised child with a raw cspace store: `capability_t granted = *src; ... tasks[target].cspace[dest_slot] = granted;`. Three problems, now fixed by routing grant through a new `cap_grant_into` (C) → `rust_cap_grant_into` (safe Rust) path:

- **SMP race with revoke.** The source was looked up *outside* `cap_lock` and copied, then stored under it — so under SMP a concurrent `rust_cap_revoke_global` could null the source between the read and the write, materialising a copy of a just-revoked capability. The lookup and store now happen together under `cap_lock`.
- **No `caps_in_use` accounting.** The granted cap was invisible to the target's `MAX_CAPS_PER_TASK` ceiling, and a later revoke's saturating decrement then desynced the counter. A newly-occupied destination slot is now counted.
- **Malformed lineage badge.** Grant copied the source's `badge` (the *grandparent*) instead of recording the grantor's cap as the parent. It now sets `badge = src.serial`, so the derivation tree is well-formed (a prerequisite for the audit-A1 descendant-only revocation rework). Rights are also masked to `new_rights & src.rights` — the plumbing for rights *reduction*; the 3-argument `SYS_CAP_GRANT` ABI still passes full rights for compatibility.

The audit's original "grant should enforce a `KERNEL_RESERVED_CAPS` slot floor" sub-point was **withdrawn as incorrect** — a grantor already dominates the target (it holds its `CAP_TCB`) and endowing a child's low slots (e.g. `init` granting a server's IPC gate into slot 3) is exactly what grant is for; enforcing the floor would have broken boot. Covered by three new Rust unit tests (rights masking, parent recording, fail-closed inputs, revoke-sweeps-grantee) and the existing `smoke-proc` / `smoke-captest` / `smoke-init-fs` / `smoke-session` self-tests. Docs updated (AUDIT-2026-07, ROADMAP Track 1.2, SECURITY, LIMITATIONS, ARCHITECTURE).

### Documented — July 2026 security & engineering audit; docs realigned to its findings (this pass)

A professional-grade audit of the kernel **and its development ecosystem** was recorded and the documentation set was updated to reflect it. No code changed in this pass — the findings set the [roadmap](docs/ROADMAP.md) priorities and the fixes are tracked there.

- **New `docs/AUDIT-2026-07.md`** — canonical record of the findings, rated against a high-assurance bar. Kernel findings: **A1** revocation matches an object/badge equivalence set rather than a derivation subtree (over-revokes; fails safe); **A2** `SYS_CAP_GRANT` skips the locked cap-write discipline (no reserved-slot floor, no `caps_in_use` accounting, copies full rights incl. `REVOKE`); **A3** the lineage-generation table is a lossy 4096-slot hash (object collisions spuriously revoke; fails safe); **A4** boot modules become root-owned `/bin` executables with no signature. Process findings: **P1** `main` has no branch protection (CODEOWNERS/CI advisory only — Critical); **P2** single-maintainer self-merge; **P3** Dependabot security updates + code-scanning off, SAST/fuzz/Kani non-gating; **P4** reproducibility ≠ provenance (unpinned toolchain, unsigned artifacts); **P5** hygiene (stale branches, unsigned commits). Verified strengths were also recorded (zero-trust refcount FFI, `PAGE_USER`+`PHYS_KVA` user-copy path, fail-closed CSPRNG seeding).
- **`docs/ROADMAP.md` reworked** around the audit: three top-priority remediation tracks — **Track 0** (assurance & governance: enforce `main`, independent review, CodeQL/Dependabot, hermetic signed builds), **Track 1** (capability-model correctness: derivation-tree revocation, locked grant path, exact lineage generations), **Track 2** (boot & supply-chain: signed module manifest → measured boot) — followed by the ongoing SMP/userspace/verification/driver-isolation tracks, with completed foundations kept as a record.
- **`SECURITY.md`** gained a "Development process & governance" section (P1–P4) and the A1/A2/A4 weaknesses, with fail-safe caveats added to the "no ambient authority" and "least-privilege process control" hardening bullets.
- **`docs/LIMITATIONS.md`** gained security-limitation subsections for A1–A4 and the process gap; **`docs/ARCHITECTURE.md`** gained an audit note on the revocation semantics; **`README.md`** and **`CONTRIBUTING.md`** point to the audit and reflect the branch-protection/review reality.

### Fixed — the console is a single writer/reader under SMP, and blocking IPC no longer fabricates a reply (this pass)

With SMP now the default, the real login/shell boot exposed two multi-core console races. Both are fixed; two new headless regression guards (`make smoke-console-smp`, `make smoke-session-smp`) lock them down.

- **Console output was doubled/interleaved under `-smp 4`.** The kernel's `print()` (serial `0x3F8` + VGA `0xB8000`) and the ring-3 `console_server`, which owns the same hardware natively via `SYS_IOPORT_GRANT` + `SYS_MAP_PHYS`, drove the one UART + framebuffer at once from different cores, so every byte came out twice, interleaved (`HHoorruuss  SSeeccuurree  MMiiccrrookkeerrnneell`). The console now has a **single writer**: `console_server` takes ownership when it is granted the ports, and the kernel's `print()`/`clear_screen()` stop touching the hardware while a ring-3 owner is live (it still records every byte to the kernel log, so panic dumps stay complete). Ownership is released if the owner dies (`task_teardown`), so the in-kernel console fallback keeps working after a `console_server` crash. Fail-closed both directions: the kernel's own console *read* path (`SYS_GET_LINE`/`SYS_GET_PASS`/`SYS_READ` fd 0) refuses to run while the server owns the UART, so the kernel can never become a second reader and steal bytes from a typed line.
- **Interactive logins failed intermittently (~half the time) under `-smp 4`.** Independent of the console, this was a lost-wakeup in the scheduler: a blocking `SYS_IPC_CALL` whose server was busy on another core had no other task to switch to on its own core, so `ipc_block_switch` un-published the block and **resumed the caller with a fabricated zero-length reply** (the correct single-CPU "resume and retry from ring 3" fallback — but under SMP the real reply arrives cross-core moments later). The shell then read a stale reply buffer, so a typed username/password came back empty or truncated and the login was rejected. The CPU now **idles** in that case (`enter_cpu_idle` returns it to `ap_idle_loop` with the task left genuinely blocked and schedulable) and a timer tick reschedules the woken caller once its cross-core reply lands — the caller never observes a reply that did not happen. A per-CPU `percpu_idle` flag lets the BSP be rescheduled out of a *genuine* idle without reintroducing preemption of its real ring-0 kernel work (e.g. the SMP self-test's result-spin loop).
- **`io_allowed` is now cleared on task teardown.** Task slots are reused without being zeroed, and the native-port-I/O grant was never reset, so a fresh task could in principle inherit a dead driver's port authority. It is now revoked in `task_teardown` (which also releases console ownership). Fail-closed hardening: authority is dropped when the holder dies rather than lingering into the slot's next occupant.
- **Program stdout now routes through the console server too, so making it the single writer did not silence everyone else.** With the kernel's `print()` hands-off while the server owns the hardware, a program that still wrote to fd 1 the old way vanished. Fixed at the source of each: the coreutils' libc (`posix_write`) and the shell's `man`-from-filesystem path now send fd-1 output to the console server over IPC, with the in-kernel path as fallback. A new read-only `SYS_CONSOLE_OWNED` lets a client tell whether the server owns the console, so images booted without one (e.g. the newlib self-test) keep using the kernel path instead of blocking on an IPC nobody answers. Console ownership itself now keys off the pair that uniquely identifies the real driver — it holds the console ports (`io_allowed`) **and** maps the VGA framebuffer — so `ioporttest` (ports only) and `mapphystest` (VGA only) keep their own kernel-console output. And a console owner that faults loses the console (fail-safe: a driver that just faulted must not keep muting the kernel's own console — which is how the blast-radius self-test reports containment). Guarded by `make smoke-coreutils-shell` / `make smoke-modules`.

### Changed — SMP is properly done and on by default: ACPI-driven CPU count, real multi-core scheduling in the normal boot (this pass)

Multi-core was previously gated behind `SMP=1` and only ever exercised by the marker self-tests; the real shell had never run under it. It is now the default build and the normal login/shell boot runs across every core.

- **The CPU count comes from ACPI, not a guess.** A new `src/kernel/acpi.c` locates the RSDP (EBDA + BIOS ROM), walks the RSDT/XSDT to the MADT, and counts the *enabled* Processor-Local-APIC entries. Firmware tables are treated as semi-trusted input: every signature and checksum is verified, every entry length is bounds-checked, and every physical pointer is confined to the `PHYS_KVA` window before it is dereferenced — anything that does not validate makes the probe fail closed and the BSP falls back to the old conservative broadcast. The BSP then waits for **exactly** the reported cores to check in instead of spinning a fixed `MAX_CPUS` timeout, and a uniprocessor skips AP bringup entirely (no trampoline staging, no INIT-SIPI, no wait).
- **The SMP scheduler is now armed in the normal boot.** `smp_sched_enabled` was only ever set by the SMP self-test, so a plain `SMP=1` boot left the online APs idle and the BSP never preempting — init reached `fs_server` and hung. `smp_bringup` now arms it once every AP is parked (still gated by `preempt_enabled`, so nothing switches early). With it on, the shipped init → `fs_server` → `console_server` → shell → login flow runs to completion across cores.
- **Async signals now deliver under SMP.** `preempt_on_tick`'s SMP branch never called `deliver_pending_signal`, so a signal sent to a ring-3 task (e.g. `SYS_KILL` from another CPU) was raised but its handler never ran. The SMP branch now mirrors the single-CPU path, delivering into this CPU's ring-3 frame under the scheduler lock. `make smoke-proc` (the `sigwaiter` case) passes under SMP.
- **`make run` boots multi-core** (`-smp $(SMP_CPUS)`, default 4). Verified: the marker self-tests (`smoke-proc/notify/fs/preempt/signal/captest`, `smoke-smp`), a full **interactive** login + `whoami` round-trip under `-smp 4`, and boot-to-login at 1/2/4 CPUs. `SMP=0` still compiles the whole subsystem out (0 objects carry `-DSMP`) and boots single-core unchanged.

### Changed — boot skips Argon2 on the ephemeral RAM vdisk (this pass)

The diskless/CI boot formats and unlocks an in-RAM encrypted volume whose "password" is a 256-bit CSPRNG value discarded right after unlock. Running the memory-hard Argon2id KDF over a full-entropy key adds no brute-force resistance — there is nothing to brute-force — so the vdisk's KEK now derives via `HKDF-SHA256` instead. A per-boot flag scopes this to the vdisk only; a real ATA disk, whose KEK comes from a low-entropy user password, keeps Argon2id unchanged. This removes both the format-time and unlock-time Argon2 runs from the diskless boot, cutting `ramfs_init` from ~1.5 s to ~0.25 s under TCG. `make smoke-fs` confirms the encrypted store still round-trips end-to-end with the HKDF-derived key.

### Added — driver privilege separation: the console driver moved out of the kernel into a ring-3 server (this pass)

The highest-risk, ring-3-reachable driver — the VGA/serial console, which parses input and handles password entry — has been moved out of the kernel's flat trust domain into a ring-3 server, `console_server`. A bug in it is now an ordinary ring-3 fault rather than a kernel-wide compromise. It landed as a design proposal (`docs/proposals/console-server.md`) followed by a commit-per-job program, each behavior-verified with a gated smoke test.

- **Three new device-delegation mechanisms** let a ring-3 driver own device hardware, all gated on a new `CAP_IO_DEVICE` capability that only the console server holds:
  - `SYS_MAP_PHYS` maps an **allowlisted** physical device frame (the VGA framebuffer / graphics plane) into a task's own address space — present, user, non-executable — over the existing page-table plumbing (`make smoke-mapphys`).
  - `SYS_IOPORT_GRANT` installs a **per-task TSS I/O-permission bitmap** so the driver runs `in`/`out` natively on the serial UART, PS/2 keyboard, and VGA register ports, while every other task's port I/O still `#GP`s (`make smoke-ioport`). This grew the TSS to carry an 8 KiB I/O bitmap and flips `iomap_base` on the single context-switch chokepoint.
  - `SYS_IRQ_REGISTER` routes a hardware IRQ to an async notification, so a ring-3 driver can be woken to service the device; safe to call from the ISR because syscalls and IRQs both run behind interrupt gates (`make smoke-irq`).
- **`console_server`** takes ownership of the console hardware with those mechanisms and serves the shell over IPC: output (`CON_OP_WRITE`) and input (`CON_OP_GETLINE` / `CON_OP_GETPASS`, doing the line editing, echo, and `*`-masking itself, a byte-for-byte port of the old in-kernel `h_get_line`/`h_get_pass`). It holds only its own capabilities and replies to each client by kernel-attested identity, like the filesystem server. `init` launches it before the shell.
- **The real shell routes its output *and* input through it** (`make smoke-session`, `smoke-modules`, `smoke-coreutils-shell`), with an in-kernel fallback so a console-server hiccup can never silence or hang login. Removing the fallback and re-running the full session — every password prompt included — confirmed input and output genuinely traverse ring 3 rather than falling back.
- **Blast-radius proof.** `make smoke-console-isolation` deliberately faults the ring-3 console server and asserts the kernel stays alive to report it — the containment the whole program set out to achieve.
- Retained deliberately: a minimal in-kernel serial writer for panic/early-boot output, the in-kernel console reader as a fallback, and PS/2 keyboard handling in the kernel (the tests and headless deployment drive serial; moving the keyboard into the server is future work).

### Added — a real filesystem: a directory skeleton, path-routed provisioning, and man pages on disk (this pass)

- **A fresh boot now comes up with a directory skeleton**, not an empty root. The `fs_server` creates `/bin`, `/etc`, `/home`, `/lib`, `/usr`, `/usr/share` and `/usr/share/man` at startup (idempotently), so a bare `ls` shows a real layout. The shell's `ls` no longer prints the `(empty)` string — an empty directory prints nothing, like `ls(1)`; a read *failure* is still surfaced distinctly, so a broken `fs_server` is never mistaken for emptiness.
- **Boot modules are routed to a destination path**, not always `/bin`. A module's multiboot2 cmdline is now the store path it provisions to — `bin/<name>` for a runnable binary, `usr/share/man/<name>` for a man page — and the `fs_server` creates any missing parent directories on the way (a bare name with no `/` still defaults under `/bin`). Executables under `/bin` are `0755`, everything else `0644`. `MAX_BOOT_MODULES` was raised 24 → 48 to hold the binaries plus their man pages.
- **Man pages live on the filesystem.** Each ported coreutil ships a plain-text man page (`userspace/man/<name>`) as its own boot module, provisioned to `/usr/share/man/<name>`, plus `hier(7)` describing the layout. `man <name>` reads `/usr/share/man/<name>` from the store and prints it; if there is no such file it falls back to the shell's built-in page table (so `man` still documents shell builtins and works on a module-free kernel). `man tail`, `man hier`, etc. now work.
- **`make run` ships the coreutils and their man pages** (`RUN_MODULES=1` by default), so the interactive/dev boot comes up with `/bin` populated and `man` reading `/usr/share/man`. Previously `make run` shipped no modules, so `/bin` did not exist, `ls` showed `(empty)`, and a coreutil like `tail` was an "unknown command". The plain `boot.iso` / release target stays module-free (no GPLv3-derived binary); set `RUN_MODULES=0` for a module-free interactive boot.
- **`make smoke-modules`** now also asserts the directory skeleton is present, that the man pages land in `/usr/share/man`, and that `man tail` / `man hier` read from there. `smoke-session` was updated: a fresh volume shows the skeleton rather than `(empty)`.

### Added — the store volume grew to 16 MiB so every coreutils binary lives in /bin at once (this pass)

- **The encrypted store was 2 MiB (4096 blocks), so only ~3–4 of the ~450 KiB newlib-linked coreutils fit in `/bin` at once** — the residency ceiling that replaced the (removed) kernel-image budget. It is now **16 MiB (32768 blocks, ~14 MiB usable)**, which holds all eleven ported utilities simultaneously. `make smoke-modules` ships the full set and asserts every one provisions into `/bin` with none dropped.
- **The data allocator uses a multi-block bitmap.** A single 512-byte bitmap block addresses only 4096 bits, which was the hard cap on data blocks (the "multi-block allocation bitmaps — not adopted" non-goal in the roadmap). `storage_alloc_block`/`storage_free_block` and the mount-time `fsck` now span as many bitmap blocks as the data region needs; the inode allocator stays single-block (4096 inodes is ample). `storage_format_sealed` solves for the bitmap span and lays the inode table and data region out past it. The single-block bitmap made a large-file *free* coalesce into one journal transaction; that still holds because `do_block_write` coalesces repeat writes to the same bitmap block, and a binary's ~800 contiguous blocks fall within one bitmap block.
- **The metadata rollback-HMAC is now hierarchical, so the per-write cost no longer scales with the volume.** `sb.meta_hmac` (which detects a physical attacker rolling back per-block nonce/tag metadata) used to be recomputed over the *entire* crypto-metadata array on every block write — 128 KiB at 2 MiB, and it would have been 1 MiB at 16 MiB, making provisioning (a block-by-block copy) dramatically slower on a larger volume. It is now `HMAC(key, all per-meta-block MACs)`, where each meta block's MAC binds its entries and its index; a single write refreshes one 512-byte block MAC plus the top MAC over `META_BLOCKS_COUNT × 32` bytes. **No on-disk format change** — the stored `sb.meta_hmac` is still one 32-byte value, verified once at unlock (a full recompute). At the old 2 MiB volume this is ~16× cheaper per write than before; at 16 MiB the per-write cost is *half* what the old design cost at 2 MiB. All 11 binaries provision in ~27 s under TCG.
- **The RAM vdisk's backing store moved off `.bss` into the physical pool.** `g_vdisk_buffer[BLOCKS_PER_DISK * BLOCK_SIZE]` was 2 MiB of `.bss` — fine then, but 16 MiB would blow the `__bss_end < USER_PHYS_BASE` (16 MiB) linker `ASSERT`. Like `loader_staging`, it is now a fixed reservation at the base of the pool (`g_vdisk_backing`, reached through `PHYS_KVA`), held back from the free list. `__bss_end` actually *dropped* to ~12.7 MiB (the 2 MiB array left `.bss`; the ~1 MiB `g_block_meta` growth is smaller). With several `module2` binaries now landing above 16 MiB (inside the pool), the `phys_in_boot_module` reservation added last pass is genuinely load-bearing.
- **The test ATA disk images are sized from the C `#define`, not a stale copy.** The Makefile's `BLOCKS_PER_DISK`/`PERSIST_BLOCKS` were hardcoded `1024` — smaller than the volume the kernel formats, which happened to work only because the tests touched only low blocks. At 16 MiB the metadata region alone exceeds a 1024-block image, so both are now read from `src/include/kernel.h` (`grep`), and the two-boot persistence/journal images are 16 MiB. All six FS tests (round-trip, persistence, journal crash-recovery, large files, permissions, concurrency) pass at the new size.

### Added — programs load from the filesystem via GRUB boot modules (this pass)

- **The ported GNU coreutils are no longer baked into the kernel image.** Each newlib-linked binary is ~400–610 KiB, and embedding them with `incbin` (the `CU_EMBED_<name>` mechanism) meant a build could only carry the subset of utilities its test drove before overrunning the kernel image's 16 MiB budget — the "400–600 KiB limitation." They now ship as **GRUB multiboot2 modules** (`module2` lines the `boot.iso` rule writes onto the ISO), which GRUB loads into RAM *outside* the kernel image, so that budget no longer applies and a full build can ship every utility at once.
- **The kernel records boot modules from the multiboot2 tags.** The existing tag walk that sizes the physical pool from the E820 map (`mb_scan_boot_info`, née `e820_detect_pool_pages`) now also reads the type-3 module tags into a `boot_module` table (physical extent + the `module2` cmdline as the name). A module that lands inside the physical pool is held back from the allocator free list (`phys_in_boot_module`) so it is never handed out as an anonymous page before it is read; one below the pool (where GRUB places them in practice, just above the kernel image) needs no reservation. `[mod] boot modules: …` is logged on every boot that carries one.
- **Two capability-gated syscalls expose them read-only** (`SYS_BOOT_MODULE_INFO` = 77, `SYS_BOOT_MODULE_READ` = 78), gated on `CAP_BLOCK_DEV` (slot 7) + uid 0 — the same authority that owns the encrypted store, since a boot module is a TCB-supplied image at the same trust tier. `READ` copies a bounded byte range out of the module's payload (reached through the `PHYS_KVA` window) into a user buffer.
- **The `fs_server` provisions each module into `/bin` on the encrypted store**, once, as a root-owned `0755` file (`provision_boot_modules`), idempotently (a module already present at the right size is skipped, so a persistent ATA volume is written only on the first boot that sees it). The shell then runs them from the filesystem: a bare command name resolves `/bin/<name>`, the shell loads the image over the `fs_server` and hands it to `SYS_SPAWN_IMAGE` (`try_run_from_bin`), and a `/bin/<name>` shadows the shell's lighter builtin. The `run` builtin's old 256 KiB image cap (below every coreutils binary) is lifted to `MAX_PROGRAM_SIZE`, and `run` now resolves absolute paths (`run /bin/hello`).
- **Provisioning is coordinated so it is not starved.** The shell reads the console with an unpreemptible ring-0 spin (`console_getc`), and the scheduler only preempts ring 3 — so a shell idling at the login prompt would monopolise the single core and starve the block-by-block copy into the store (measured: ~10 s of provisioning stretched past 200 s). `init` now blocks on a notification (slot 3, the shared gate endpoint) until the `fs_server` signals it has finished startup provisioning, and only then launches the shell. With `init` off the run queue and no shell yet, the copy runs at full speed. On a sealed ATA volume, which unlocks only at login, the `fs_server` signals immediately and provisions lazily post-login instead.
- **Residency in `/bin` is bounded by the store volume**, not the kernel image. Modules are installed in order and any that do not fit are skipped gracefully — the system always comes up with as many utilities as fit. (A follow-up in this same Unreleased set grew the volume from 2 MiB to 16 MiB so all eleven fit at once; see the store-volume entry above.) The kernel-image budget that the modules remove is a separate, now-lifted, constraint.
- **`make smoke-modules`** ships `printf`/`tail` as modules, boots normally, and asserts the `fs_server` provisioned them into `/bin` and that both run correctly through the real ring-3 shell (a ~530 KiB image reaching the filesystem without living in the kernel image). **`make smoke-coreutils-shell`** now does the same for `head`/`seq`/`wc`. The old `make smoke-coreutils` marker test (which spawned an embedded binary directly from the kernel — a path that no longer exists) and its kernel-side `coreutils_selftest` are retired; the two shell-driven session tests give strictly broader coverage.

### Added — printf and tail ported (this pass)

- **`printf(1)` and `tail(1)` join the ported GNU coreutils**, both vendored byte-identical from coreutils 9.5 and built against the newlib port shim — eleven utilities now (`echo`, `true`, `false`, `basename`, `dirname`, `cat`, `head`, `seq`, `wc`, `printf`, `tail`). `printf` needed two new MIT shim modules: `xprintf` (its error-checked stdout output) and `unicodeio` (`\u`/`\U` escapes, encoded straight to UTF-8), plus `quotearg_style` for its bad-argument diagnostics and `<inttypes.h>` for `strtoimax`/`strtoumax`.
- **`tail`'s gnulib surface was mostly already covered** (`argmatch`, `cl-strtod`, `xstrtol`/`xstrtod`, `safe-read`, `stat-size`, `xbinary-io`, `xdectoint`); the new pieces are follow/pipe helpers — `stat-time` (timestamp accessors + `timespec_cmp`), `isapipe` (always 0: no pipes), `posix2_version` (modern syntax), `iopoll`/`xnanosleep`, an `lstat`→`stat` alias (no symlinks), `PID_T_MAX`, and empty `fs.h`/`fs-is-local.h` stubs for tail's Linux-only remote-filesystem block. **`tail -f` follow is best-effort** — Horus exposes no inotify, `poll(2)`, pipes or wall-clock sleep to ring 3, so it degrades to a stat-polling loop paced by a bounded busy-spin; `-n`/`-c` line and byte selection are full upstream behaviour. See `userspace/ports/coreutils/README.md`.

### Added — the physical allocator is sized from the E820 memory map (this pass)

- **The pool was a hardcoded `[16 MiB, 80 MiB)` window, and no memory map was parsed at all.** `_start` reused `%ebx` — GRUB's pointer to the multiboot2 boot-information structure — as a scratch counter in its first few instructions, and `kernel_main` discarded its argument, so the kernel simply assumed 64 MiB of RAM existed above the image. On a smaller machine that is handing out frames that are not there; on a larger one it is leaving almost everything unused.
- **`_start` now saves the multiboot2 magic and info pointer** (`saved_mb_magic` / `saved_mb_info`) to `.data` through their physical addresses, before `%ebx` is clobbered and before paging is on. `kernel_main` walks the boot structure's tags for the memory-map tag (type 6), finds the available (type 1) region covering `USER_PHYS_BASE`, and sizes the pool from it (`e820_detect_pool_pages` → `phys_set_pool_pages`, before `paging_init` builds the free list). The info block is low RAM, read through the `PHYS_KVA` window that is already live at that point.
- **Under the harness's `-m 512M` the pool is now ~495 MiB, up from 64 MiB.** The runtime size is clamped to `[PHYS_POOL_MIN_PAGES, USER_PHYS_PAGES]` and to `PHYS_POOL_CEIL` (1 GiB, the extent of the `PHYS_KVA` window, so every frame stays reachable by the pager). The array capacity `USER_PHYS_PAGES` was raised 16384 → 131072 (512 MiB); its metadata is ~768 KiB of `.bss`, and `__bss_end` lands at ~14.1 MiB, still under the 16 MiB ceiling the linker `ASSERT` enforces. The Rust mirror of `USER_PHYS_PAGES` (`rust/src/memory.rs`, the refcount-table trust boundary) was bumped in lock-step — a mismatch makes `rust_page_refcounts_register` refuse the table and the kernel halt, which is exactly what a first cut of this hit.
- **A boot that cannot parse a map keeps the old 64 MiB default** (`USER_PHYS_DEFAULT_PAGES`), so nothing regresses when there is no multiboot2 map. `make smoke-e820` boots `-m 512M` and asserts the free frame count grew past the default; `[mem] physical pool: … MiB` is logged on every boot. This is the "real physical allocator" ROADMAP Phase 5 asked for; scaling past 1 GiB (wider `PHYS_KVA`, pool-bootstrapped metadata, fragmented maps) remains.

### Added — ring-3 `RDTSC` is disabled via `CR4.TSD` (this pass)

- **The timestamp counter was readable from ring 3**, giving mutually distrusting tasks a cycle-accurate timer — the highest-resolution primitive a cache/covert-channel attack leans on. `CR4.TSD` is now set alongside SMEP/SMAP/UMIP in `cpu_enable_protections()` (`crypto.c`), so a ring-3 `RDTSC`/`RDTSCP` raises `#GP`. The existing ring-3 trap path already routes such a fault into the task's registered handler (delivered as a fault signal), so `RDTSC` now traps rather than returning a count. Ring 0 keeps `RDTSC` — TSD gates CPL>0 only — so the kernel's own jitter-entropy source is untouched, and Horus exposes no userspace timing API, so nothing legitimate is lost.
- **This is deliberately partial.** Coarser timers and a counting-thread construction remain, and it does nothing about cache *state*; flush-on-switch / partitioning is still open (tracked in `SECURITY.md`). `make smoke-tsd` gates it: a payload registers a fault handler, executes `RDTSC`, and passes only if the handler runs instead of a timestamp coming back. `SECURITY.md` had listed TSD as a *possible future* mitigation; it is now implemented.
- **Enabled on every core, not just the BSP.** CR4 is per-CPU, and `ap_entry64()` never called `cpu_enable_protections()` — so under `SMP=1` an application processor came up with SMEP, SMAP, UMIP *and* TSD all off and ran ring-3 tasks that way, a silent hole that only opened on a non-boot core. APs now call it during bringup, closing the TSD gap and the pre-existing SMEP/SMAP one together. `make smoke-smp` still brings four cores online and runs tasks across them.

### Added — task 0's kernel stack is guarded (this pass)

- **Every ring-3 task's kernel stack already sat above an unmapped guard page, but task 0 — the kernel's own boot/idle/reaper task — did not.** It kept a separate, 16-byte-aligned, unguarded `task0_kernel_stack`, so an overflow of the reaper (which the page-fault handler resumes on when it kills a task and finds no successor) ran silently into whatever `.bss` followed. Meanwhile `per_task_kstacks[0]` sat allocated and never used.
- **Task 0 now runs on `per_task_kstacks[0]`**, bound by `create_user_pagedir(0)` above the same guard page `kstack_guards_init` unmaps for every other slot — which works precisely because that array lives in the 4 KiB-mapped kernel window (`KERN_SPLIT_PDES`), where a single guard page *can* be made absent (a separate `.bss` array is not guaranteed to). The duplicate `task0_kernel_stack` is gone. `make smoke-wx` asserts `MAX_TASKS` guards (was `MAX_TASKS - 1`) and verifies slot 0 specifically.
- **The fixed BSP boot stack and the three boot IST fault stacks are guarded too.** `stack_top` (the stack `kernel_main` and all early init run on) and `ist1`/`ist2`/`ist3` in `multiboot.S` are each laid out above a page-aligned guard page that a new `kern_fixed_stack_guards_init()` unmaps at boot. IST1 takes `#DF`/`#GP`/`#PF`, so its guard sits on the path of every demand page fault and every ring-3 fault delivery — exercised constantly, not just in theory. A one-page present anchor keeps `__bss_start` (which the W^X per-section check samples) off the guard. `smoke-wx` now also asserts the four fixed-stack guards are absent with their stacks present. The per-CPU AP IST stacks (SMP-only) and the dead early 32-bit boot stack remain unguarded (documented in `docs/LIMITATIONS.md`).

### Added — a real directory/coreutils surface on the userspace shell and libc (this pass)

- **Directory enumeration end-to-end.** The `fs_server`'s `FS_OP_READDIR` op existed but nothing above it did: newlib shipped no `<dirent.h>` backend (its own is a `#error` stub) and the shell could not stat entries. `opendir`/`readdir`/`closedir` are now provided in `newlib_glue.c` over new `posix_diropen`/`posix_readdir` (`posix.c`) with a project `include/dirent.h` that shadows newlib's stub, and the shell's `ls` gained a real `-l` long format (mode string, owning uid, size per entry).
- **A working directory.** `posix.c` gained cwd state; `path_walk`/`path_parent` now resolve relative paths against it, with `getcwd`/`chdir`/`mkdir` wired through newlib and `cd`/`pwd` builtins (plus cwd-relative `ls`/`cat`/`touch`/`mkdir`/`rm`) in the shell. `..`/`.` are folded by pure string normalization, so it never depends on on-disk `.`/`..` entries the store does not keep.
- **A coreutils command pack** built on the above — `cp`, `mv` (over `FS_OP_RENAME`), `wc`, `stat` — all riding existing syscalls, no new kernel surface. Gated: `make smoke-newlib` exercises `opendir`/`readdir` and `mkdir`/`chdir`/`getcwd` + relative resolution end-to-end, and `make smoke-session` drives `cd`/`pwd`/`ls -l`/`cp`/`mv`/`wc`/`stat` through the real ring-3 shell over serial.

### Fixed — SMEP and SMAP were never enabled (this pass)

- **Both were off on every boot the project had ever done**, while three documents described them as engaged when advertised. `ECX` is an *input* to `CPUID` as well as an output — on leaf 7 it selects the subleaf — and the helper declared it output-only, so the leaf-7 query inherited whatever the previous `CPUID` left there. The previous call is `cpuid(0)`, which returns the vendor string. Leaf 7 was therefore asked for subleaf `0x444D4163` (`"cAMD"`). Its max subleaf is 0, an out-of-range subleaf reads back as all zeros, and so `has_smep`/`has_smap` were both computed from `0`. `cpu_enable_protections()` then dutifully enabled nothing.
- **The smoke harness had been forcing `+smep,+smap` on the QEMU `-cpu` line the whole time.** The features were advertised; the kernel simply never saw them. Measured rather than reasoned about: `has_smep=0 has_smap=0 CR4.SMEP=0 CR4.SMAP=0` before, both set after, and the two queries side by side on one boot — stale subleaf → `SMEP=0 SMAP=0`, subleaf 0 → `SMEP=1 SMAP=1`.
- **Nothing was relying on them being off.** All suites pass with the protections genuinely engaged for the first time: the `stac`/`clac` discipline and the PHYS_KVA-based user copies were already correct, they were just never being enforced.
- **`make smoke-cpu` gates it now**, because a detection bug is invisible to a test that asks the kernel what it detected — the kernel and the test agree, and both are wrong. It also reads as correct in review, and is indistinguishable from a CPU that genuinely lacks the feature. The test pins the answer to the harness's `-cpu` line instead, so "not detected" is a bug rather than an honest report about the hardware.

### Fixed — the kernel's own image was writable and executable (this pass)

- **Kernel `.text` was writable, `.rodata` writable *and* executable, `.data`/`.bss` executable.** `multiboot.S` built one page directory covering physical `[0, 1 GiB)` as 2 MiB `P|W` pages with no NX, then hung it off three entries at once — the low identity map, the PHYS_KVA window, and the kernel's own higher-half mapping. Its own comment said so: *"One `pd` is aliased by all three of the entries below; a write here is visible through every view."* Tightening any view tightened all three, so none could be. `EFER.NXE` had been on since boot; no kernel PTE ever set the NX bit. `linker64.ld` already page-aligned every section — the information needed to do better was present and unused.
- **Each consumer now has a page directory of its own**, and the image is mapped `.text` r-x, `.rodata` r--, `.data`/`.bss` rw-NX, with the low megabyte, the dead `.boot` stage and the slack above `.bss` absent by construction. The de-aliasing landed as its own commit carrying *no* policy change: it is the step that triple-faults with no console if it is wrong, so it was made bisectable from the permissions it enables.
- **`CR0.WP` is set, and without it none of the above meant anything.** A supervisor write ignores the PTE's read/write bit when WP is clear, and ring 0 is the only ring that can reach these pages — so read-only kernel pages were enforced against ring 3 and disregarded for ring 0. `CR0` had read `0x80000013` since boot. Found by testing rather than reading: with the r-x PTEs live and WP still clear, a write to `__text_start` **succeeded**. NX needs no equivalent switch, so the executable half of the policy worked while the read-only half silently did not.
- **Three more aliases, each of which would have made the policy decorative.** The PHYS_KVA window was RW+X over the whole image — and NX alone only half-fixes it, because *writing* `.text` through the window and executing it at its kernel address defeats W^X across the pair while neither view is W+X by itself. `kern_pd`'s 2 MiB tail inherited `P|W` with no NX, a supervisor RWX alias of every page userspace owns (SMEP does not apply — the mapping is supervisor, not user). The identity map was a third RWX view of everything; it is now a single R+X page for the AP trampoline, which is written through PHYS_KVA and executed here, so neither alias is W+X alone.
- **The recursive self-map was RW *and* executable across 512 GiB.** Page-table pages are full of attacker-influenced physical addresses and are a known spray surface; nothing executes through the self-map. One NX bit on the upper-level entry covers the region.
- **Three comments claimed the identity map was load-bearing and all three were wrong** — `multiboot.S` said the LAPIC and VGA were reached through it (VGA goes through PHYS_KVA; the LAPIC through `pdpt[3]`), `ap_trampoline.S` said `pml4[0]` could never be dropped (true, but for the LAPIC), and `user_protect_page` said its walk relied on low memory being identity-mapped (its body had used PHYS_KVA for some time). One *real* dependency existed that none of them mentioned: the flat-binary loader hand-walked page tables dereferencing every level at its physical address. It is `copy_to_user` now, like the ELF path beside it. That also retired an **inverted SMAP bracket** in the same loop — it cleared AC before the copy and set it after, leaving SMAP *disabled* on exit — which was inert until the CPUID fix above made SMAP real.

### Added — the W^X invariant is swept, not asserted (this pass)

- **`make smoke-wx` walks every present leaf in the address space** and fails if any is simultaneously writable and executable, accumulating both permissions across page-table levels (NX is an OR — set at any level it vetoes execute beneath; W is an AND given `CR0.WP`). It also asserts `CR0.WP` and `EFER.NXE`, since the bits are only a policy if the CPU applies them.
- **The sweep rather than a per-section check, because every hole was an alias** — a second mapping of the same frames — and `.text`'s own PTE was correct throughout. Each of the four was found by hand, by guessing where to look. Mutation-tested against all of them: reopening the PHYS_KVA hole fails 4509 of 8790 leaves *while the per-section checks pass*, which is the entire argument for the sweep.
- **It covers all of `pml4`, not just the kernel half.** The identity map hangs off `pml4[0]` — the user half — though every page in it is a supervisor mapping the kernel installed for itself. The first version of the sweep checked `[256..511]`, read as thorough, and reported PASS on 8790 clean leaves with a gigabyte of writable, executable kernel image one entry to the left.
- **The sweep found the fifth hole on its own**, on its first widened run: the LAPIC's MMIO registers were mapped writable *and* executable. Outside the kernel image, where no per-section check would ever have looked.

### Added — UMIP and a kernel stack protector (this pass)

- **UMIP** (`CR4.11`) denies ring 3 `SGDT`/`SIDT`/`SLDT`/`STR`/`SMSW` — unprivileged instructions that hand out the linear addresses of the GDT, IDT, LDT and TSS, which is what turns a corruption primitive into a targeted one. `+umip` was added to the harness's `-cpu` line, without which the feature would have been dead in every test and this would be a feature added with no evidence it works.
- **`-fstack-protector-strong`**, replacing an explicit `-fno-stack-protector`: ~82 functions now carry a canary, and a failed check halts rather than returning through a corrupted frame. **`-mstack-protector-guard=global` is not optional company for it** — GCC's x86-64 default reads the canary from `%gs:0x28`, which in a kernel with no per-CPU GS base is a garbage address, and `__stack_chk_guard` would go entirely unreferenced. The guard is drawn from the CSPRNG at boot, because the build is reproducible and a fixed canary is therefore a *published* value. Where it is seeded from is forced, not chosen: GCC re-reads the global in every epilogue, so any protected frame live across the change would compare the new guard against its saved copy of the old one and die on return — `kernel_main` is the only site that is both after `entropy_init` and never returns.

### Fixed — four latent bugs (this pass)

- **`.bss` was 609 KiB from silently handing kernel memory to userspace.** The image grows up from 1 MiB through `.bss` (ending at 15.40 MiB) and the physical page allocator hands out frames from `USER_PHYS_BASE` (16 MiB) upward; nothing enforced that the two never meet, and `.bss` is mostly static arrays sized by compile-time constants. A routine bump to `MAX_TASKS` or `BLOCKS_PER_DISK` would have had `alloc_user_physical_page` issuing frames that are live kernel `.bss`. Now a link-time `ASSERT`. While there: `linker64.ld` was not a prerequisite of `kernel.elf` despite `LDFLAGS` passing `-T linker64.ld`, so every linker-script change to date had silently needed a manual clean.
- **The ELF64 loader read 8-byte fields 4 bytes wide.** `e_phoff`, and `p_offset`/`p_vaddr`/`p_filesz`/`p_memsz` for every `PT_LOAD`. The lost range was not the problem — the plumbing is 32-bit throughout and nothing legitimate lives above 4 GiB — but the truncation happened *before* the bounds checks, so every check validated a number that was not the one in the file. A header declaring `p_offset = 0x1_0000_0000` narrowed to `0` and sailed through `p_offset + p_filesz > MAX_PROGRAM_SIZE`. Now read at full width and refused if they do not fit, rather than silently narrowed.
- **The AP trampoline indexed idle stacks by raw LAPIC id** against an array of exactly `MAX_CPUS` (4) slots, with no bound. The id is 8 bits, and the BSP wakes the APs with a broadcast INIT-SIPI-SIPI ("all excluding self", no enumeration), so every core arrives regardless of how many slots exist. An AP with id ≥ 4 landed on `program_armed`, `armed_hdr` and `loader_staging` — the image being loaded and the entry point about to be jumped to. Reachable on any machine with more cores than `MAX_CPUS`; QEMU's default `-smp 4` matches exactly, which is why nothing tripped over it. Verified at `-smp 8`: before, `online=8` and the test still **passed** — the corruption was entirely silent.
- **A dead SMAP-enable block read an uninitialised struct.** `paging_init()` tested `platform.has_smap` three lines before `cpu_detect_features()` populated it, so it read zeroed `.bss` and never once fired. Harmless — `cpu_enable_protections()` sets SMAP properly a moment later — but it read as protection that was not there, and the comment recording *why* it could not work was sitting next to it rather than deleting it.

### Changed — ring 3 runs the 64-bit ABI (previous pass)

- **Userspace is 64-bit.** Ring-3 tasks now execute under the GDT's 64-bit user code segment (`cs = 0x23`) as `EM_X86_64` static-PIE images, against an `x86_64-elf` newlib. The descriptor side was smaller than it looked: selector `0x20` was *already* a 64-bit user code segment (L=1, D=0, DPL=3) and `ss = 0x33` was already correct, so this is a selector change, not new state. The cs flip, `-m64`, the 64-bit syscall operands and the newlib retarget landed as one commit because each half of the pair is a triple fault on its own — there is no bisectable middle.
- **Syscall operands and returns are 64-bit.** They carry user pointers, and `SYS_BRK`/`SYS_SBRK` return an *address* — a 32-bit return would have truncated the program break, handing `malloc` 4 GiB-minus-one instead of the `(void*)-1` newlib compares against. The scalar `(uint32_t)` casts on `fd`/`len`/`ep_slot` are deliberately kept: they normalise a negative `int` to the 32 bits the kernel compares, where widening would sign-extend.
- **Entry stack alignment.** SysV requires `rsp % 16 == 8` at a function's first instruction, because a `call` has just pushed a return address; GCC compiles `_start` against that and emits `movaps`. `iretq` pushes nothing, so handing over a 16-byte-aligned `rsp` put every spill slot 8 bytes out and the first `movaps` raised #GP. `sched_prepare_user_context` biases by 8 to reproduce what the entry point was compiled to expect.
- **The AP trampoline stays 32-bit, and always will.** An x86 CPU starts in real mode, GRUB hands over in 32-bit protected mode, and an application processor leaves SIPI in real mode. Those `.code16`/`.code32` blocks are the on-ramp to long mode, not leftovers. `userspace/elftest.o` also stays 32-bit on purpose, so `smoke-elf` keeps gating the loader's ELFCLASS32 path instead of silently duplicating `smoke-elf64`.

### Fixed — x87/SSE state was never saved across a kernel entry (previous pass)

- **A task's `xmm` registers were whatever the last task left behind.** The trap frame saves general-purpose registers only, and there was no `fxsave` anywhere in the tree. This was latent for as long as userspace was i386: SSE2 is not in that baseline, so generated code never held a live `xmm` across a syscall. Under `-m64` SSE2 *is* the baseline, and it became **silent data corruption**: gcc compiled a 16-byte fill in the fs client into a broadcast plus one `movups`, hoisted the broadcast out of the loop, and left it live in `xmm0` across `sys_ipc_call`. The fs_server's leftover `xmm0` was stored as file data and written to disk — with every checksum agreeing, because the corruption happened before the AEAD saw it. `smoke-fs-conc` was the only witness in nineteen targets.
- **Each task now carries a 512-byte FXSAVE image**, saved on entry from ring 3 and restored on return to it, keyed on the *current* task at each moment so a switch restores the task actually being entered. It wraps the dispatcher rather than living inside it: the dispatcher has many exit points (timer switch, IPC block, yield, exec re-enter, exit switch) and every one can resume a different task, so there is exactly one place that has to be right.
- **The kernel is built `-mno-sse -mno-mmx -mno-80387`.** It has no FPU state to keep, so anything it touches is collateral damage to the interrupted task and anything it leaves behind is a leak into ring 3. This was not theoretical: gcc was auto-vectorising ordinary integer loops throughout — `paging.o` carried 125 `xmm` references and `storage.o` 166. Keeping the kernel out of the FPU is also what makes the save cheap, since a ring-0 → ring-0 interrupt needs neither half.
- **`crypto.c` loses its `-msse2 -maes`**, which was vestigial: the hand-rolled AES-NI cipher it named is gone (encryption-at-rest has been ChaCha20 + HMAC-SHA256 in safe Rust for some time), and reporting a CPUID bit needs no SSE.
- Fixed properly rather than by building userspace `-mno-sse`. That would have gone green in one line and left newlib — 1848 `xmm` references, built by `tools/build_newlib.sh` outside `USERSPACE_CFLAGS` — silently exposed to the same corruption.

### Added — the loader relocates ELFCLASS64 images (previous pass)

- **`elf_apply_relocations_x86_64`** sits beside the i386 one: `Elf64_Rela` (24-byte entries), `DT_RELA`/`RELASZ`/`RELAENT`, type from `r_info & 0xFFFFFFFF` (not `& 0xFF`), `R_X86_64_RELATIVE == 8`, and the RELA write semantic `*(u64*)(r_offset + slide) = slide + r_addend` rather than the i386 REL read-modify-write. Every other relocation type still fails closed.
- Gated by **`make smoke-elf64`**, which loads and inspects a real 64-bit static-PIE (never executes it), so the gate stands independent of the ring-3 ABI — it was written while userspace was still 32-bit. Worth recording honestly: the two forms *agree* for ld-linked images because GNU ld pre-applies the addend into the field, so this test would not have caught a REL-vs-RELA semantic swap on its own; they diverge only for a linker that does not (lld's `--no-apply-dynamic-relocs`).

### Changed — the kernel dispatches on the real 64-bit trap frame (previous pass)

- **`struct regs` is retired.** It was an all-`uint32_t` mirror of the frame; `interrupt_handler64` marshalled the real frame into it, called the handler on the copy, and wrote two fields back — silently truncating every register to 32 bits. Handlers now read arguments from, and write return values to, the frame the CPU actually pushed (331 renames across 8 files).
- **`page_fault_handler`'s signature was a lie** and is now honest: it was declared `struct regs *` while every caller handed it a `struct interrupt_frame64 *`. See the error-code entry below — this is the same defect from the other side.
- The dead `interrupt_handler(struct regs *)` is deleted.

### Changed — kernel-side address types widened to 64-bit (previous pass)

- `tcb_t`'s `esp`/`eip`/`cr3`/`sig_handler`/`image_base`/`image_end`/`ipc_reply_buf`/`argv_ptr`/`sig_altstack_sp`, the Rust FFI (`rust_validate_page_fault`, `rust_get_user_page_protection` — the latter was *already* truncating high stack addresses), and the loader signatures are all 64-bit, ahead of the ring-3 ABI so the two moves stayed separable. This also fixed a latent `DEMO_TASK_STACK_TOP` truncation: `create_task` stored `0x7fffe0000000 - 256` into a `uint32_t`, yielding `0xdfffff00`.
- Header dependencies (`-MMD -MP`) were added in the same pass. Without them, editing a header rebuilt *nothing* that included it: the link happily reused objects compiled against the old declarations, so a signature change could report a clean build and then miscompile — exactly the hazard a 331-site type change runs into. `make smoke` also gained a `clean` (it was the only one of eighteen targets without one, and had been booting the previous target's ISO).

### Fixed — memory management (earlier passes)

- **Demand paging works** — it never did. A ring-3 task that grew its heap past ~128 KiB hung the machine; `malloc` was enough, no attacker required. Two defects stacked, the second hidden behind the first. **(1)** `create_user_pagedir` premaps only `[0, 16) MiB`, but the user page pool starts *at* `USER_PHYS_BASE` (16 MiB), and the pager — which runs on the faulting task's CR3 — reached page tables and freshly allocated frames through their *low identity* virtual address. Every such access was unmapped, so the pager faulted *inside itself*, and the nested fault re-entered the `page_lock` the outer invocation already held with interrupts off: a hard hang. It hid because the kernel's own CR3 identity-maps `[0, 1 GiB)`, so the same code works at spawn time and only fails from inside a fault. Physical access now goes through the higher-half alias (`PHYS_KVA`) that `create_user_pagedir` already replicates into every task via `pml4[256..511]`. **(2)** The heap could never be demand-paged where it sat: PD[2] is identity-filled present+supervisor because kernel `.bss` occupies `[4, 6) MiB`, so the pager always saw "already present", returned `-2`, and the fault fell through a validator that blesses all of `[4, 8) MiB` to a `cli; hlt`. The heap now starts at `USER_HEAP_BASE` (16 MiB), above the end of `.bss`, where the pager can install real user pages. `hello_newlib` had been running within 4–36 KiB of the halt, a margin that moved per boot with the randomised heap gap — `smoke-newlib` was one unlucky draw from flaking.
- **A ring-3 fault can no longer halt the machine** — reading a blessed-but-unmappable address (e.g. `0x570000`, `kernel_page_dir`) took `allowed == true` past the `if (!allowed)` block and into the trailing `cli; hlt`; the validator saying "valid" was precisely what killed the kernel. The task is killed instead, and `cli; hlt` is reserved for a fault with no task to blame. Deliberately not conditioned on `cs & 3`: the faulting access is often a *supervisor* one (the kernel touching a bad user address mid-syscall on that task's CR3), which is exactly how the heap-cliff halt presented.
- **`sbrk`/`brk` were dead for any task whose heap sat above the critical floor** — the clamp applied unconditionally, pulling `heap_max` below such a task's own `heap_start`, so every call returned `-1`. It now clamps only heaps that live in the contested low window.
- **The page walker ignored the PS bit** — a 2 MiB PDE (PD[0..7]) or 1 GiB PDPTE has no table beneath it, but the walker dereferenced its frame base as one, reading kernel `.bss` as a PTE and writing a user PTE over it, while the fault never resolved — re-faulting and draining the page pool. Huge entries are refused.
- **The pager had no ceiling, and `[0xA00000, 0xB00000)` was wrongly approved as user memory** — the gate read `fault_addr >= USER_AREA_BASE || fault_addr >= 0xA00000`, whose second clause is dead, so every address above 4 MiB reached the pager including kernel `.bss`. And that "user" window is not user memory at all: `argon2_scratch` spans `0x92a7a0..0xd2a7a0` straight through it, with `kernel_pepper`, `audit_mac`, `audit_log_buffer` and `loader_staging` alongside. Both windows corrected; a unit test that asserted the old behaviour now asserts the new.
- **Image-base ASLR was silently disabled** — 0 bits, while the docs advertised ~9. `choose_image_placement` bounded the window against `kernel_bss_floor`, which is the link-time *start* of `.bss` and lies *below* `USER_AREA_BASE`, so the guard's test was never true and the base was pinned to `USER_AREA_BASE` on every spawn. It failed safe, so nothing broke — it just did nothing. Bounding against `kernel_lowmem_critical_floor()` instead restores **430 pages ≈ 8.75 bits** (ceiling 8.91, where the premap must stay inside one 2 MiB PD entry). Measured: 8 distinct load bases over 8 boots.

### Fixed — copy-on-write and the page-fault validator (earlier passes)

- **The page-fault validator now scopes to the faulting task's own regions** — it previously blessed all of `[0x400000, 0x800000)` for every task, a window holding `kernel_page_dir`, `root_cnode`, `tasks[]` and `kernel_stacks`. Any fault in it was reported "valid", which (before the halt fix above) is what carried a bad address into `cli; hlt`. It now takes the caller's `image_base`/`image_end` and `heap_start`/`heap_end` and approves a fault only inside those, or the premapped low stack — so a direct fault into the critical window is a SIGSEGV instead of an allocation. The gate is on *allocation* only: a `present|write` fault still reaches the COW path, which a blanket floor check would have refused, killing any task that wrote to a shared page.
- **The page-fault error code was always `0`** — and nothing had noticed, because nothing had ever read it for a decision. `page_fault_handler` takes a `struct regs *`, but `interrupt_handler64` hands it a `struct interrupt_frame64 *`; the two disagree on where `err_code` sits (offset 44 vs 128), so `r->err_code` returned an unrelated field that happened to read zero. The write bit was therefore never set, `is_write` was always false, and **copy-on-write could not have fired at all** — the first thing to depend on the value was the first thing to expose it. Read through the actual frame type now.
- **Demand-zero reads share one zero page** — reading a sparse heap allocated a fresh zeroed frame per page touched. Reads now map a single immortal read-only zero frame (marked `PAGE_COW`), and the first write breaks it to a private page: one physical page for an arbitrarily large untouched heap. Breaking it needs no copy — duplicating an all-zero frame just means handing out a zeroed page — so the pager takes a special case that never touches the zero frame's refcount, which is correct precisely because it is aliased by many PTEs; `free_user_physical_page` refuses it by address so it can never be recycled. Proven end-to-end from ring 3 by `make smoke-cow`.
- **The COW path masked the frame address with `& ~0xFFF`, which leaves NX set** — bit 63 survives that mask, so a no-execute page's "physical address" carried `1 << 63`. It compared unequal to the shared zero frame and was then dereferenced through the higher-half alias as if it were a real frame — a wild access taken while holding `page_lock` with interrupts off, i.e. a hang, on the first write to any writable (hence NX) shared page. Now masked with `PTE_ADDR_MASK` (`0x000FFFFFFFFFF000`), which drops the flag bits at *both* ends.
- **`copy_to_user` into a read-only shared page faulted the kernel, not the task** — with demand-zero reads now landing on a read-only frame, a syscall writing into a buffer the task had only read is a *supervisor* write to a read-only page. `user_copy` breaks COW itself before writing rather than relying on the fault path to do it underneath the kernel's own copy.

### Removed — the vestigial Rust demand-fault handler (earlier passes)

- **`rust_handle_demand_page_fault` and its `DemandAction` enum are gone**, along with the weak C stub and the call in `page_fault_handler`. It was the last code in the tree still approving `[0x400000, 0x800000)` wholesale and `[0xA00000, 0xB00000)` — the window `argon2_scratch` spans — directly contradicting the region-scoped validator that replaced that logic. It could not actually act on those windows: the sole call site passed `is_cow = 0` as a literal, and the only path to `NoAction` is gated behind `is_cow && is_write && is_user`, so the function could only ever return `Invalid (-1)` or `DemandZero (0)`. `if (action == 2) return 0;` was therefore unreachable, its return value could not change behaviour, and the C pager was already the single authoritative decision point the stub's own comment described. Deleting it is behaviour-preserving by construction and removes a trap: the next reader could not have told it was inert. `rust_cow_copy_required` (used by the pager) stays.

### Changed — a user page directory now holds only user mappings (earlier passes)

Completes ROADMAP Phase 5. The higher-half move (below) made the kernel unreachable from a user address; this makes a user address space *contain* nothing but the task's own pages.

- **`create_user_pagedir` no longer identity-fills the low window.** It used to map physical `[0, 16 MiB)` into every task as supervisor 2 MiB huge pages, then punch USER holes for the image premap, because the kernel was linked low and had to reach `tasks[]`, the page tables and its own `.bss` while running on a user CR3. The kernel is now reached through the `pml4[256..511]` copy, so the fill had no purpose. A user PD holds the image premap and the low stack; every other entry is not-present. **A user mapping can no longer share a virtual address with kernel state by construction**, rather than because ASLR is bounded away from it.
- **Demand paging works in the low window again** — a consequence of the above. A fault there now finds a not-present page and reaches the pager, instead of finding an identity-supervisor page and being declined with "already present" (`-2`). The pager gates every mapping on `rust_validate_page_fault`, which approves only the faulting task's own image/heap/stack.
- **The "high ASLR stack" premap was fiction, and expensive fiction.** It claimed to map 64 pages at `ASLR_HIGH_STACK_BASE` (`0x7ff000000000`), but indexed `my_pd` — which hangs off `pml4[0]` and covers only `[0, 1 GiB)`. Reaching that VA needs `pml4[255]`. `hs_pdi` came out 511, so the pages landed at ~`0x3ffe0000` and nothing ever read them. It cost 260 KiB per task: **16.2 MiB of the 64 MiB pool** across 64 slots, a quarter of all user memory, allocated to pages at an address no code uses. Deleted.
- **`make smoke-aslr` (new, gated, in CI)** spawns 8 PIE images and asserts (1) the load base actually varies, and (2) every base keeps the premap inside a single page table — the invariant that bounds the entropy, and which a wrong bound would silently violate by writing past that table. Property (1) exists because it has been broken before: image-base ASLR was once disabled entirely while the docs advertised ~9 bits, and nothing caught it because nothing looked. Both assertions were checked against deliberately broken builds before landing. It does **not** assert a statistical entropy estimate: with 8 samples over 480 slots, any threshold tight enough to catch a regression is loose enough to flake. The entropy figure is structural — log2 of the bound the test checks.
- **The kernel image no longer has an RWX segment.** The higher-half change merged the boot stage's code and data into one output section, which emitted a single RWX `PT_LOAD` — a W^X hole in a kernel that advertises W^X. Split into `.boot` (r-x) and `.boot.data` (rw-).
**Found, not fixed here:** `src/kernel/rust_shims.c` — the no-Rust fallback — carries its own copy of `rust_validate_page_fault` and `rust_get_user_page_protection`, and they disagree with the Rust they mirror (the shim still grants `[0xA00000, 0xB00000)`, which the Rust refuses, and omits the demand-paged heap window). It is unreachable: `make RUST_ENABLED=0` does not build, and cannot without ~72 more C fallbacks (`rust_argon2id_hash`, `rust_aead_seal`, the audit MACs, the auth lockout…). It is a fossil from when Rust was optional, and the same shape of trap as the vestigial demand-fault handler removed earlier — a dead second answer to a policy question. Deleting it, and the `RUST_ENABLED=0` path, is a follow-up.

### Changed — the kernel runs in the higher half (earlier passes)

**`KERNEL_VMA = 0xFFFFFFFF80000000`.** The kernel is linked at −2 GiB and no kernel address is a user address any more. This is the ROADMAP Phase 5 "user/kernel address separation" item: previously the kernel was linked at 1 MiB with `.bss` running to 15.37 MiB, straight through the user window `[0x400000, 0x800000)`, so every task's low mappings shared virtual addresses with `tasks[]`, the page tables and the capability root, and three separate mechanisms existed to stop a user mapping shadowing kernel state.

- **The base is forced, not chosen.** `-mcmodel=kernel` lets GCC materialise symbol addresses as 32-bit *sign-extended* immediates (`R_X86_64_32S` — 964 of them), valid only in `[-2 GiB, +2 GiB)`; `0xFFFFFFFF80000000` is the base of the top half of that range. A "canonical higher-half" base like `0xFFFF800000000000` would blow every one and force `-mcmodel=large`. The old 1 MiB link satisfied `-mcmodel=kernel` only by accident: the signed-32 range is symmetric about zero, so the low 2 GiB fits too — the flag's contract was being violated while its implementation tolerated it. No CFLAGS change was needed; the move makes the flag *correct*.
- **The mapping was one entry.** `0xFFFFFFFF80000000` decodes to PML4[511], PDPT[510] — the same `high_pdpt` the boot code already built for the `PHYS_KVA` window at PDPT[2]. So `high_pdpt[510] = pd | 0x3` aliases the same `pd` the identity map uses, and the kernel image at physical 1 MiB appears at `0xFFFFFFFF80100000`.
- **Physical placement is unchanged.** Each high section carries `AT(vma - KERNEL_VMA)`, so `p_paddr` stays low; GRUB honours `p_paddr` (verified with a throwaway probe segment before any of this was written). `.boot` — the 32-bit entry code, its GDT and scratch stack — stays linked VA == PA at 1 MiB, because GRUB enters in 32-bit protected mode and `movl $sym, %edi` cannot encode a high address. The far jump that activates long mode is absolute and runs *after* `CR0.PG`, so it lands in a low 64-bit stub which escapes to the kernel's linked addresses via `movabs` + `jmp *%rax`.
- **The low identity map stays** — it is not vestigial. The SMP trampoline far-jumps to ~`0x8000` after enabling paging on the kernel's own CR3, and the LAPIC/VGA MMIO are reached at their physical addresses. What went away is the *kernel* needing to live there.
- **One more VA-as-physical bug, found by booting.** `user_copy` loaded `(uint64_t)(uintptr_t)pml4` into CR3 — a kernel VA, so a reserved-bit fault once relocated. The previous pass fixed three sites of this shape; this one was named `kcr3_phys`, which is exactly why a grep for the cast pattern missed it. It was the only thing standing between the relocation and a working ring 3.
- **Guards deleted, because they now guard nothing.** `kernel_lowmem_critical_floor()` and all three of its clamps are gone: the `h_sbrk`/`h_brk` heap clamp and the image-ASLR clamp. The function's contract was "lowest kernel VA a user mapping must not overlay", and after the move there is no such address. Keeping it would have meant truncation — both call sites assigned it into a `uint32_t`.
- **Image-base ASLR reaches its structural ceiling: 480 pages ≈ 8.91 bits**, up from 8.75. The only bound left is the premap fitting one 2 MiB PD entry, which is what `ASLR_MAX_LOAD_RANDOM_PAGES` (`512 - 32`) already encoded. Measured, not derived: 10 boots gave 10 distinct bases spanning page offsets 30–429, one of them (`0x5AD000`) above the old clamp's `0x550000` ceiling.
- **A botched relocation now fails loudly.** `kernel_main` asserts, before anything depends on it, that the linker's `KERNEL_VMA` matches the C one (they are necessarily duplicated — a linker script cannot include a header), that it is executing above `KERNEL_VMA`, and that `virt_to_phys`/`phys_to_virt` round-trip. Prints `HIGHHALF: PASS` with its own address, or halts.

**What this does not do yet.** `create_user_pagedir` still identity-fills the low window present+supervisor and punches USER holes for the image premap. That fill is now vestigial — the kernel is reached through `pml4[256..511]` — but until it is removed the low window still cannot be demand-paged and images stay capped at the 128 KiB premap.

### Fixed — address-translation groundwork (earlier passes)

Preparation for moving the kernel out of low memory (ROADMAP Phase 5, "user/kernel address separation"). No behaviour change; this makes the assumptions explicit and removes the traps that would turn a relocation into a silent boot hang.

- **`virt_to_phys()` / `phys_to_virt()` now name the kernel VA↔PA conversion** (`kernel.h`). The kernel is linked at 1 MiB and runs identity-mapped, so a kernel symbol's virtual address *is* its physical address — an identity that several sites relied on invisibly. `paging_init` built the page-table self-map as `pml4[510] = ((uint64_t)pml4) | 0x3`, writing a **virtual** address into a page-table entry, and `do_spawn`/`exec_into_armed_image` loaded `(uint64_t)(uintptr_t)pml4` straight into **CR3**. All three read as obviously correct and are correct only by accident of the link address; relocated, they would install a kernel VA as a physical frame number (bits above 51 set — a reserved-bit fault or a wild frame). `KERNEL_VMA` is `0`, so this compiles to exactly what it did before.
- **Three raw physical dereferences now go through `PHYS_KVA`** — `create_user_pagedir`'s low-stack premap (whose sibling paths already did), `user_copy`'s copy loop, and the ELF self-test's page reader (whose comment stated the assumption outright: *"user phys is identity-mapped under the kernel pml4"*). `PHYS_KVA` moved from `paging.c` to `kernel.h`, since the self-test and SMP bringup need it too.
- **The boot page-table zeroing loop was wrong by 4×, in a way that was load-bearing.** `rep stosl` stores a dword per iteration, so its `%ecx` is a dword count — but it was passed `12288`, a *byte* count for three tables. It therefore zeroed 48 KiB rather than 16 KiB, scribbling 32 KiB past the tables into `per_task_kstacks`; and had the count been "right" it would have missed `high_pdpt` entirely, leaving the PML4[511] subtree — the entire `PHYS_KVA` window — pointing at garbage. Harmless only because `.bss` is zero at boot and nothing had run yet. The range is now derived at link time from `boot_tables_start`/`boot_tables_end`, so it cannot drift as `.bss` moves.
- **Dead code removed**: `entry64.S` (a 7-line `.code32` `cli; hlt` stub, unreferenced despite the name suggesting it is the 64-bit entry point), `kernel_page_dir` (4 KiB of `.bss` held alive only by `__attribute__((used))`, never read — and, ironically, the `0x570000` that earlier work cited as the canonical unmappable-kernel-address example), `kernel_page_directory` (declared in `main.c`, never defined), `kernel_bss_floor` (`PROVIDE`d by the linker script but not emitted, since nothing references it), `is_user_address_valid`, the `uint32_t` `pde_t`/`pte_t` typedefs and the 32-bit-paging `PAGE_PRESENT`/`PAGE_COW` copies in `idt.c` (each a single occurrence — the definition), and two dead lines in `create_user_pagedir` (a self-map immediately overwritten by the kernel-half copy loop, and a re-zeroing of entries zeroed on the line above).
- **The eight `RECURSIVE_*_VADDR` macros are gone, and the docs they backed are corrected.** All eight were unexpanded — every grep hit was the `#define` itself — and their values were for a slot-**511** self-map while the code installs one at slot **510**. `docs/ARCHITECTURE.md` presented four of them as a memory-layout table and stated the kernel "uses recursive page table mapping"; in fact every page-table access goes through `PHYS_KVA`, and the self-map is maintained but never read.

### Added — CI coverage for two configs that were built but never gated (earlier passes)

- **`smoke-init-fs` is now a CI job.** It had a Makefile target and passed, but nothing ran it, so the path it covers was gated by nobody: the `fs_server` spawned and endowed by ring-3 `init` — the way the real system boots it — rather than directly by the kernel. That is the delegation the capability model exists to express, and it was the one filesystem path CI could not see regress.
- **`SMP=1` joins the `altconfigs` build matrix.** `smoke-smp` compiles `-DSMP`, but only via `SMP_SELFTEST=1`, which sets `SMP := 1` *and* pulls in the selftest harness. Nothing built the plain SMP kernel — the configuration an SMP user actually ships — so a break in `#ifdef SMP` code outside the selftest paths would not have surfaced.

### Working (current state of `main`)

- **Capability-based access control** — mint, transfer, move, grant, and revoke with transitive cross-task invalidation; no ambient authority (cap operations from a task without its own cspace are refused); lineage generation counters prevent use-after-revoke; a snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window in the IPC paths; primordial (root) capabilities cannot be revoked; C/Rust capability layout pinned by mirrored compile-time assertions.
- **Ring-3 process control** — `SYS_SPAWN` (spawn a named child, hands the caller its `CAP_TCB`), `SYS_EXEC_NAMED` (replace the caller's image in place), `SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE` (execve-from-fd: spawn or exec a program image the caller read from a file, validated by the same loader a named binary uses), `SYS_CAP_GRANT` (delegate a cap into a supervised child), `SYS_KILL` / `SYS_EXIT` (terminate, `CAP_TCB`-gated), `SYS_SIGNAL` (async task-to-task signal, `CAP_TCB`-gated), and `SYS_WAIT` (block until a task exits). The shell's `run <file>` reads a program from the `fs_server` and execs it. Proven by `make smoke-proc`.
- **Ring-3 `init` (PID 1)** — launches at boot, spawns the shell, endows it via `SYS_CAP_GRANT`, and blocking-supervises it with `SYS_WAIT`, relaunching on exit or fault.
- **Preemptive scheduling** — the PIT (100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch; ring-0 ticks never switch. Blocking (`SYS_IPC_CALL`, `SYS_WAIT`, `SYS_WAIT_NOTIFY`) uses the same block/switch path. Proven by `make smoke-preempt`.
- **Signals** — fault signals (`SYS_SIGACTION`/`SYS_SIGRETURN`: a ring-3 fault is delivered to a registered handler instead of killing the task), async task-to-task signals (`SYS_SIGNAL`), and alternate signal stacks (`SYS_SIGALTSTACK`: a handler runs on a registered stack with an `SS_ONSTACK` guard, so a corrupt or overflowed primary stack cannot stop it running). Handler address validated in safe Rust; no re-delivery inside a handler; no new authority. Proven by `make smoke-signal` and `make smoke-proc`.
- **Symmetric multiprocessing** *(behind `SMP=1`)* — application-processor bringup, a per-CPU LAPIC-timer scheduler over a shared runnable pool, IPC/notification locking, and acknowledged TLB-shootdown IPIs. Proven by `make smoke-smp`.
- **Filesystem** — a ring-3 `fs_server` over the kernel's encrypted object store (syscalls 56–61), reached over IPC; real `ls`/`cat`/`mkdir`/`rm`/`touch`/redirection. **Persistent by default**: the kernel probes for an ATA disk at boot (bounded, no hang on a diskless bus) and uses the encrypted store when one is present — files and their per-block crypto metadata survive a reboot; the disk comes up mounted-but-locked and is unwrapped at login (Argon2id-derived KEK) — falling back to an ephemeral in-RAM vdisk (auto-unlocked, no login) when no disk is attached. Proven by `make smoke-fs` and a two-boot `make smoke-fs-persist` (write on boot 1, verify on boot 2 against the same disk image). A latent ATA-only deadlock (the sector r/w took `storage_lock`, which the crypto layer already held) is fixed with a dedicated `ata_lock`. The encrypted `fs_server` is the system's single filesystem — the legacy in-memory capfs (`SYS_FS_*`) has been removed (see below).
- **Filesystem ownership & permissions (zero-trust)** — the `fs_server` is the filesystem reference monitor: it enforces POSIX owner/group/other rwx and ownership against the caller's **kernel-attested** identity (`SYS_IPC_SENDER` returns the sending task's login uid/gid — a client cannot forge it or place it in the request), with root (uid 0) as the only ambient authority. New inodes are owned by their creator; `chmod` is owner-or-root and `chown` is root-only (`SYS_FS_SET_META` persists owner/mode, server-only). A client cannot access what its real uid disallows, cannot reach the store directly (only the server holds the storage cap), and cannot bypass the checks. Proven by `make smoke-fs-perms`.
- **Crash-resilient filesystem (write-ahead journal)** — every multi-block object-store update (block bitmap + inode + per-block crypto metadata + superblock `meta_hmac` + data) runs as one transaction: staged in RAM, committed to an on-disk **redo journal** with an HMAC-authenticated header (keyed by a `disk_key`-derived key, replay targets bounds-checked), then applied to home locations. A crash mid-update is completed or discarded by replay at the next mount, so the filesystem is always fully before or fully after the operation — and this closed a latent brick where a crash between a metadata-sector write and the superblock write desynced `meta_hmac` and refused to mount. Mount-time `fsck` reclaims orphaned inodes and leaked data blocks. On-disk format v5. Proven by `make smoke-fs-wal` (boot 1 commits a write then crashes before applying it; boot 2 replays it and the data survives).
- **Large files (double-indirect blocks)** — the object store's block mapping now implements the double-indirect region, so one inode maps blocks through direct (12) + single-indirect (64) + double-indirect (64×64) = up to 4172 blocks, and the volume was raised to 4096 blocks (2 MiB). Fixed a latent single-indirect bug along the way: the pointers-per-block count was `1024` instead of the correct `BLOCK_SIZE/8 = 64`, which indexed a 512-byte stack buffer out of bounds for any file past block 76 (never triggered because no test wrote a file that large). `storage_free_inode_blocks` now frees the double-indirect tree too. Proven by `make smoke-fs-large` (writes + reads blocks across every mapping region including deep double-indirect, frees a ~130-block file in one journal transaction — the bitmap clears coalesce so it never overflows the 16-sector journal — and checks an unwritten hole reads as absent).
- **Legacy capfs removed (attack-surface reduction)** — the parallel in-memory capability filesystem (`SYS_FS_*` syscalls 38–45, `fs_objects[]`, the `capfs_*` engine and its separate at-rest AEAD) was deleted. It was a second filesystem, reachable from ring 3, with its own permission model and no persistence — redundant with the encrypted `fs_server`. The syscalls now fail closed (their dispatch-table entries are gone) and the numbers are reserved. The encrypted `fs_server`, which enforces POSIX ownership/permissions against the caller's kernel-attested identity, is now the system's single filesystem. The load-bearing simple `ramfs` (which backs the sealed user-account database) is unaffected.
- **Multi-client filesystem concurrency** — several clients can use the one (single-threaded) `fs_server` at once without their replies colliding. The server replies with `SYS_IPC_REPLY_TO`, which routes each reply to the request's kernel-recorded sender — delivered directly into that client's blocked `SYS_IPC_CALL`, never via a shared reply endpoint another client could poll or overwrite (the old single-client hazard). Requests still serialise (one processed at a time). Proven by `make smoke-fs-conc` (three clients hammer the server concurrently, each verifying it receives only its own replies).
- **Userspace runtime** — a demand-paged heap via `sbrk`/`brk`, a userspace `malloc`, and a newlib libc port over a per-process POSIX fd layer. Proven by `make smoke-newlib`.
- **libc `unlink()`** — the newlib `unlink()` stub is now a real syscall path: `unlink` → `posix_unlink` (a new `path_parent` resolver → the `fs_server`'s permission-checked `FS_OP_DELETE`) with `errno` mapping (`ENOENT`/`EACCES`/`ENOTEMPTY`). This uncovered and fixed a latent bug where `posix.h`'s `O_*` flag values disagreed with newlib's (`O_CREAT` was `0x40` vs newlib's `0x200`), silently dropping `O_CREAT` on the newlib `open()` path — the first end-to-end exercise of `posix.c`'s file path (the shell has its own client). `make smoke-newlib` now spawns the `fs_server` and drives real `open`/`write`/`unlink` end-to-end.
- **libc `stat()`/`fstat()` real metadata** — `posix_stat`/`posix_fstat` now report the file's actual permission bits, uid and gid from the `fs_server`'s `FS_OP_STAT` reply (plumbed through to `struct stat` `st_mode`/`st_uid`/`st_gid`) instead of the previous hardcoded `0644`/`0755`. Covered by `make smoke-newlib` (a freshly created file stats as a regular file, mode `0644`, uid 0).
- **libc `O_APPEND`** — appends now land at the end of the file. The flag was previously accepted by `open()` and then ignored by `write()`, which wrote at the fd's offset (0 for a freshly opened file), so an "append" silently overwrote the file from byte 0 with no error — a shell `>>` built on it would have eaten data. `posix_write` now sends a new `FS_OP_APPEND` op and the **server** picks the offset, at the file's current end: it already holds the size from the permission stat it does anyway, and it handles one request at a time, so reading the size and landing the data cannot be interleaved by another client. Doing this client-side (stat, then write where it said) would have raced any concurrent writer and overwritten their data. Both write ops now also return the end offset of the write, so a client tracks its position without a follow-up stat. The same pass refuses `FS_OP_WRITE`/`FS_OP_APPEND` against a *directory* inode (as `FS_OP_TRUNCATE` already did), closing a path by which a directory's owner could write raw bytes over its dirent array. Proven by `make smoke-newlib`, which asserts an append extends rather than overwrites, that `O_APPEND` beats an explicit `lseek` to byte 0 (the property that separates a real append from a seek-to-end), and that an append larger than one `FS_IO_MAX` chunk concatenates.
- **Table-driven syscall dispatch** — one descriptor table (numbers 0–75) enforces each syscall's fixed capability at a single choke point; unlisted numbers fail closed; a compile-time assertion pins the table to the syscall number space.
- **Hardware isolation & W^X** — Ring 0/3, per-task page tables, SMEP/SMAP (when advertised), NX; non-executable stacks and ELF `PT_LOAD` `p_flags` honoured. The kernel sits in the higher half, so a user mapping cannot share an address with kernel state; each task's x87/SSE register file is saved/restored across the ring-3 boundary, and the kernel holds no FPU state of its own.
- **ASLR** — per-spawn stack, heap, and PIE image base (relocated at load via `R_X86_64_RELATIVE`; `R_386_RELATIVE` still supported for ELFCLASS32); 8.91-bit image-base entropy, the structural ceiling now that the bound is the premap fitting one 2 MiB PD entry rather than the ABI.
- **User authentication** — login with lockout + anti-spray throttle, Argon2id memory-hard hashing; password changes persist across reboots.
- **Tamper-evident audit log** — per-entry HMAC (sequence-bound) + running hash-chain head, keyed by the per-boot pepper; `SYS_AUDIT_DIGEST` returns the digest + verify status.
- **Cryptography (safe `no_std` Rust)** — Argon2id/BLAKE2b, SHA-256/HMAC/HKDF/PBKDF2, a ChaCha20 + HMAC-SHA256 AEAD, and a ChaCha20 CSPRNG (RDRAND + timing-jitter seeded), all validated against published/reference vectors.
- **Boot / IO** — Multiboot2 via GRUB2 into x86-64 long mode, kernel linked at `KERNEL_VMA` (`0xFFFFFFFF80000000`) and asserted there at boot (`HIGHHALF: PASS`); VGA terminal + serial mirror; PS/2 keyboard. Ring 3 is 64-bit; the only 32-bit code is the multiboot entry stage and the AP SIPI trampoline.
- **Reproducible builds** — byte-for-byte deterministic `kernel.elf`.
- **Async notifications** — `SYS_NOTIFY` ORs a 32-bit badge into one of `MAX_NOTIFICATIONS` slots and wakes any task blocked on that slot (patching the accumulated badge into the waiter's saved trap frame, so no cross-address-space copy is needed); it accumulates the badge when no one is waiting. `SYS_WAIT_NOTIFY` returns a pending badge immediately or blocks via the same full-context path as IPC/`SYS_WAIT`, with the badge delivered in `rbx`. Gated by the endpoint capability in slot 3 (WRITE to notify, READ to wait). Proven by `make smoke-notify`.
- **Scripted integration session** — `make smoke-session` (`tools/session_test.py`) boots the shipped kernel and drives the **real** ring-3 shell over serial as a black box (no compiled-in assertion): it types at the login prompt and shell and asserts a wrong password is rejected, the right one accepted, `whoami` reports the kernel-attested uid, and a capability-gated admin op (`useradd`) is allowed for root but denied for a standard user (no ambient authority). The seed of the Phase 5 integration harness.
- **Tests / CI** — 57 Rust unit tests; GitHub Actions runs **24 jobs** (twenty-three gating; the `security` scan is advisory): rust test + `clippy -D warnings`, kernel/ISO build, alt-config matrix, nineteen QEMU self-tests — smoke-boot, ELF/W^X for ELFCLASS32 and ELFCLASS64, preemption, signals, process-control, copy-on-write, image-base ASLR, async notifications, SMP, the scripted `smoke-session` integration test, and the filesystem/libc suite: fs, fs-perms, fs-conc, fs-persist, fs-wal, fs-large, init-fs, newlib — plus a reproducible-build check and a security scan + SBOM.

### Added — process lifecycle and control (Phase 1)

- **`SYS_EXIT` + capability-gated `SYS_KILL`**, with waiter wake-up and (SMP-safe) teardown.
- **Ring-3 `SYS_SPAWN`** — a task spawns a named embedded binary; the load runs in the kernel address space and the caller receives the child's `CAP_TCB`.
- **In-place `SYS_EXEC_NAMED`** — replace the caller's image (same task id, capabilities preserved), plus scheduler resume-frame hardening.
- **`SYS_CAP_GRANT`** — delegate one capability slot into a supervised child's cspace (fixes an ASLR/kernel-data aliasing issue in the same pass; the user heap is now bounded below the kernel's low-memory critical data).
- **Ring-3 `init`** — a PID-1 process that launches, endows, and supervises the shell; the kernel no longer spawns the shell directly. Converted to a *blocking* `SYS_WAIT` supervisor once the wait path was hardened.
- **`SYS_SIGNAL`** — async task-to-task signalling gated on a `CAP_TCB`, delivered into the target's registered handler (reusing the fault-signal path); default-terminates when unhandled or for the uncatchable `SIG_KILL`.

### Added — SMP (multi-core, behind `SMP=1`)

Application-processor bringup, a LAPIC-timer per-CPU preemptive scheduler, IPC + notification locking for cross-CPU safety, and TLB-shootdown IPIs with acknowledgement. Gated behind `SMP=1` with a `make smoke-smp` CI job.

### Added — userspace filesystem server & newlib

- **Encrypted object-store syscalls (56–61)** — a capability-gated inode/block API to ring 3 (`SYS_FS_INODE_ALLOC`/`_FREE`, `SYS_FBLOCK_READ`/`_WRITE`, `SYS_FS_STAT`, `SYS_FS_SET_SIZE`); AEAD keys never leave the kernel TCB.
- **`fs_server`** — a real hierarchical FS (directories as inode data, root = inode 0) over a versioned IPC protocol (`include/fs_proto.h`) on two well-known endpoints; RAM or ATA backend. `make smoke-fs`.
- **newlib port** — a libc over a per-process POSIX fd layer with `malloc`/`sbrk`/`brk`. `make smoke-newlib`.
- **IPC is non-blocking** — `SYS_IPC_SEND`/`RECV` return a would-block code instead of spinning; callers poll from ring 3 where preemption interleaves them.

### Fixed — this session (scheduler / login)

- **Intermittent login hang.** `console_getc()` (and `serial2_read_char()`) waited for input by calling the cooperative `yield()`/`schedule()`, which cannot context-switch two mid-syscall ring-3 tasks — it swaps CR3/current and returns on the caller's own kernel stack. Once `init` became an always-runnable second ring-3 task, this toggled the active address space between shell and init, so a keystroke's `copy_to_user` and syscall return could land in the wrong task. Console/serial input now spins in place (hardware wait) without the cooperative scheduler.
- **`SYS_WAIT` on the preemptive path.** `h_wait` used the same broken cooperative spin; it now marks the caller `TASK_BLOCKED_WAIT` and suspends it on the block/switch path, woken by the target's teardown.
- **Fault-death wakes waiters.** The ring-3 fault-kill path raw-set `state=0` without waking a `SYS_WAIT` waiter; it now routes through `task_teardown()` + `task_exit_switch()`, so a blocking `init` relaunches a shell that *faulted*, not only one that exited cleanly.

### Security — earlier hardening passes

- **Encryption-at-rest replaced.** The block-storage layer's hand-rolled "AES-128" (a broken AES-NI key schedule + an unaudited ARX fallback, neither actually AES) and the ramfs per-file XOR keystream were both replaced with one ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`): fresh per-write nonce, independent HKDF subkeys, context as AAD, constant-time fail-closed verify.
- **Argon2id password hashing.** Replaced PBKDF2-HMAC-SHA256 with memory-hard Argon2id (RFC 9106), multi-lane + configurable cost, on an in-house BLAKE2b — validated against reference vectors.
- **Ring-3 storage backend callback removed.** `SYS_REGISTER_STORAGE_BACKEND` (which let userspace register function pointers the kernel called from ring 0) fails closed; the ABI slot is reserved.
- **Capability space zeroed on task-slot reuse**, so a reused slot cannot inherit a dead task's `CAP_USER`/`CAP_CONSOLE`/`CAP_ENCRYPTED_STORAGE`.
- **capfs generation checks** on every operation via `fs_resolve_cap()`; key material wiped on delete.
- **Account/password hygiene** — locked initial passwords for new accounts, password changes persist, cleartext buffers scrubbed after auth.
- **Table-driven syscall dispatch** with a fail-closed choke point and a compile-time table-size guard.
- **Tamper-evident audit log** added, with `SYS_AUDIT_DIGEST`.
- **W^X** enforced (non-executable stacks + ELF `p_flags`).
- **Full ASLR** — PIE userspace with a randomised load base.
- **Errno-aligned error codes** — a shared `SYS_ERR_*` vocabulary (`include/errno.h`) with `sys_strerror()`, distinguishing an unknown syscall from a missing capability.
- **32-bit kernel build removed** — the kernel is x86-64 long-mode only.

### Added — retire cooperative schedule (Phase 3)

- **Single full-context switch path** — `sched_enter_user` enters a task via its fabricated trap frame (pop+iretq, same epilogue as the ISR); boot of `init` and all self-test launches use it instead of `lretq`. `SYS_YIELD` requests a switch via `g_want_yield` and `sched_yield_switch` on the live trap frame. The cooperative `schedule()`/`context_switch()` path is deleted; idle is `kernel_idle` (sti; hlt). Page-fault kills use `task_teardown` + `task_exit_switch` like other fault paths.

### Added — concurrent-IPC publish order (Phase 3)

- **Save frame before waiter is visible** — `SYS_IPC_CALL` / `SYS_WAIT` / `SYS_WAIT_NOTIFY` only set `pending_block` (+ object fields). `ipc_block_switch` writes `saved_ksp`, barriers, then `ipc_publish_pending_block` publishes the waiter under the IPC lock. Cross-CPU replies/notifies/teardowns always patch a valid trap frame; a reply that arrives as a mailbox message before publish is consumed immediately.

### Known incomplete

- IPC: single-slot mailboxes, one in-flight request (multiple-client service is layered on top via `SYS_IPC_REPLY_TO`, but a richer multi-slot / worker-pool IPC is not built). Async notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) now work end-to-end (see above).
- Filesystem: Phase 2 is complete (persistent, per-file permissions, multi-client, crash-atomic journal, large files, single filesystem — legacy capfs removed). Residual limits are deliberate non-goals: volume size capped at 2 MiB by single-bitmap geometry, and full ACLs beyond POSIX owner/group/other + uid-0 superuser.
- Storage: persistent-by-default on ATA and crash-atomic journalling are done; the residual gap is larger volumes (a deferred non-goal). Diskless boots still use the ephemeral RAM vdisk.
- SMP: works behind `SMP=1` but not default-on; shared runnable pool, no per-CPU queues/priorities, no flush-on-switch.
- Bounded load-base ASLR entropy (~9 bits) from the 32-bit userspace window.
- Deeper booted-kernel integration tests (beyond the smoke self-tests) and fuzzing; `smoke-fs` / `smoke-newlib` are local targets, not yet gated in CI.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for detail.
