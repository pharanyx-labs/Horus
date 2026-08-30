# G-8: two CPUs on one kernel stack

*Extracted from [`../../TESTS.md`](../../TESTS.md), where it was one section of a test
catalogue. The narrative is kept in full: in this project the reasoning is the evidence, and
the record of which hypotheses were wrong is the part worth reusing.*

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md); the gates that
witness it are listed in [`../../TESTS.md`](../../TESTS.md).*

---

**Status: closed. `smoke-session-smp-soak` is restored to gating.** Read this subsection for
the answer; everything below it from *"`smoke-session-smp-soak` fails at roughly 2–3%"* onward
is the record of how it was read wrongly for eight days, kept deliberately.

#### The origin of the bad value

**A switch path handed the outgoing task to another CPU before this CPU had left that task's
kernel stack.**

Every switch path in `scheduler.c` (`preempt_on_tick`, `ipc_block_switch`, `sched_yield_switch`)
is called from `interrupt_handler64`, which is executing on the outgoing task's kernel stack:
the C frames sit immediately below the trap frame the CPU pushed on entry. Releasing
`task_running_cpu[cur]` and dropping the scheduler lock *there* published the task as claimable
while this CPU still had to run, in this order:

```
preempt_on_tick+0x1ce:  movl $0x0, scheduler_lock      <-- released here
                        pop %rbx / %rbp / %r12 / %r13 / %r14 / %r15   } from cur's stack
                        ret                                           } return addr on cur's stack
interrupt_handler64+0x123:  cmp/jae                    <-- #123's floor guard
                        testb $0x3,0x90(%rbp)          <-- out->cs
                        call fpu_restore
                        mov 0x28(%rsp),%rax            <-- stack-protector canary, from cur's stack
                        pop %rbx / %rbp / %r12 / %r13  } from cur's stack
                        ret                            } return addr on cur's stack
isr_common_stub64+0x1f: movq %rax,%rsp                 <-- FIRST instruction off cur's stack
```

A CPU that claimed the task inside that window resumed it to ring 3 from its saved frame, and
its very next trap re-entered the ISR **on the same stack, at the same depth, running the same
functions**, so it rewrote exactly the words this CPU had not finished reading.

**The exactness of the overlap is why this was invisible for eight days.** Two CPUs running the
same code path at the same depth put the *same* return addresses and the *same* stack canary
back at their own slots. So every frame validates, `__stack_chk_fail` is not taken, and both
`ret`s go where they should. Only the data differs, and the first datum out is the resume `%rsp`
on its way to `movq %rax,%rsp`. That is G-8's entire recorded signature: a plausible word from
the wrong context (a `.text` return address in one capture, `4` in another), a canary that
passed, and a claim invariant that read consistent.

#### The claim invariant was never evidence against the shared-stack hypothesis

This file said on 2026-08-13 that the hypothesis "now has no observation supporting it",
because the one `t > 0` capture showed `task_running_cpu[4] == 0` and
`percpu_current_task[0] == 4`. **That is withdrawn.** A deliberately reproduced collision
prints:

```
PANIC: two CPUs on one kernel stack task=4 'shell' entering-cpu=3 unwinding-cpu=0
  vec=14 errc=0x0
  rip=0xffffffff8010a7db cs=0x8 rflags=0x10086
  claim: task 4 running_cpu=3  percpu_current=[0,0,0,4]  imp=[0,0,0,0]
```

The invariant **holds** while two CPUs are on one kernel stack, and it holds because it is true.
The task really is running on exactly one CPU. The other one is merely still leaving.
`task_running_cpu[t] == c ⟺ percpu_current_task[c] == t` says nothing about a CPU that has
stopped running a task but has not stopped *reading its stack*, and no amount of that instrument
would ever have said anything about it.

That is the fourth time on this finding that a diagnostic's silence or agreement was read as
evidence, and it is the same lesson each time: **an instrument answers the question it was
built for, and the cost of forgetting that is measured in days.**

#### The fix: the claim ends where the stack does

`isr_common_stub64` calls `sched_release_deferred()` immediately after `movq %rax,%rsp` (the
first instruction at which this CPU is provably reading a different stack) and that is where the
hand-over completes. Interrupts are off (every gate is an interrupt gate) so it cannot re-enter,
and its frame lands in the same unused region of the *incoming* task's stack the ISR's own C
frames occupied on entry. The hold is a few tens of instructions; a CPU that wanted the task
takes it on the next tick.

#### The property is now checked, not asserted (SECURITY.md S20)

`g_kstack_inflight` carries bit *t* while some CPU is inside that window on task *t*'s stack,
and `interrupt_handler64` tests it on entry. A CPU arriving in an ISR for a task another CPU
has not finished leaving is two CPUs on one kernel stack, and the kernel says so and halts
rather than corrupting itself quietly. One load and a bit test on the common path; `MAX_TASKS`
is 64, so a single word covers every task exactly.

The detector reports **once per boot**. Both parties to a collision see it and would print the
same task and the same pair of CPUs, and the first control run garbled them into `task=
entering-cpu=3-2145272000`. That is deduplication, and it is deliberately *not* the muteness
#143 fixed: there the claim was taken by an unrelated fatal fault on another CPU and the event
went entirely unreported, whereas here it is taken by this same detector reporting this same
collision, under the bounded bracket that always emits. A second, *different* reporter (a
concurrent `#PF`) can still interleave with it: that is the standing trade-off of the bounded
claim and is why the marker is emitted as one `kfault_str`.

#### Falsified, both arms, in seconds instead of at 1 boot in 150

`KSTACK_RACE_WIDEN=1` stretches the window with a spin so it is entered on essentially every
switch. It is set in **both** arms, which is the whole point; the same widened window must be
harmless with the fix and fatal without it:

| Target | Build | Required |
|---|---|---|
| `smoke-kstack-race` | widened window, deferred release | session completes, marker **absent** |
| `smoke-kstack-race-control` | widened window, `KSTACK_RELEASE_EARLY=1` | marker **present** within `KSTACK_RACE_CONTROL_BOOTS` (8) boots, stopping at the first, and the session must **not** report PASS |

The control arm is the load-bearing one: without it, the first arm is consistent with "a kernel
with a spin in it still boots".

Three details recorded because each would have made the gate lie:

- **The obvious widener does not work, and only measurement said so.** Spinning after *every*
  switch is self-defeating: the CPU that must take the released task reaches the same spin on
  its own switch, so it is always a full spin behind; its own delay prevents the collision it
  exists to cause. Measured, per-boot reproduction of the pre-fix arm:

  | Widening | Reproduced |
  |---|---|
  | every switch, every CPU | **2 / 7** |
  | one switch in eight, every CPU | **0 / 3** |
  | every switch, `KSTACK_RACE_WIDEN_CPUMASK=0x5` (cpu 0 and 2 linger; cpu 1 and 3 take) | **12 / 12** |

  A control arm that reproduces two times in seven is not a control arm, it is a coin, and a
  red gate that goes green on a re-run is the exact habit this file blames for
  `smoke-console-smp` surviving months of CI. The split also runs about twice as fast, which is
  a side effect and not the reason.
- **The spin count is the value that was measured**, `KSTACK_RACE_WIDEN_SPINS ?= 200000`. A
  first draft left a round `2000000` as the Makefile default while every hand-run had used
  `200000`; the gate then ran the widened session ten times slower and *timed out* rather than
  concluding. Verified in the exact form it runs, after being caught not doing so.
- **The control arm asserts two things, not one.** The marker must appear AND the session must
  not report PASS. A build that reproduced the race and still reported success would mean the
  harness had stopped reading the wire, which is the failure mode `SOAK_MIN_CHECKS` exists for
  one level up.

#### The rate: paired, adjacent-boot alternating, 1600 boots at `-smp 4`

Both ISOs built from the committed tree, sha256 pinned, alternating on one host so the arms see
the same load. Nothing was rebuilt during the run, and the kernel binaries were checked
byte-identical to a fresh build of the tree afterwards.

| Arm | Failures | Rate |
|---|---|---|
| `KSTACK_RELEASE_EARLY=1` (the pre-fix release site) | **31 / 800** | 3.9% |
| shipped (deferred release) | **0 / 800** | 0% (95% upper bound, rule of three: 0.38%) |

Fisher exact, two-sided: **p = 6.9 × 10⁻¹⁰**.

The 3.9% decomposes exactly onto what this file already documented:

| What the failing boot showed | Count |
|---|---|
| caught at the collision by the new detector | 13 |
| stalled with no marker (signatures A / B) | 9 |
| supervisor `PAGE FAULT` | 6 |
| `PANIC: dispatcher returned a bogus resume rsp=` (#123's floor guard) | 3 |

The last three rows are **18 / 800 = 2.25%**: boots that ran on past the collision into a
downstream failure, which is G-8's documented **2–3% per boot**, reproduced. So the pre-fix arm
is not a worse kernel than `main`; it is `main`'s defect with an instrument attached that names
it before it does damage.

**An earlier 1600-boot run of the same design corroborates it**, at 44/800 against 0/800 (p =
6.2 × 10⁻¹⁴). Its binaries predated the detector's report deduplication, so it is quoted as a
second run rather than merged into the first: but note what did *not* move between them: the
downstream-failure subset was **18/800 = 2.25% in both**, to the boot. The total differs (44
against 31) because the detector's hit rate depends on how loaded the host is, and the first run
shared the machine with a stray QEMU. That is the expected direction: contention is what opens
the window, and it is why this finding was first seen on a CI runner and pinned cores rather
than on an idle workstation.

#### The second path: where a CPU parks when the last task dies: closed the same day

The paragraph that stood here recorded the `#PF`/exit fallback as an unwitnessed lead: all
three fallbacks in `idt.c` resumed a CPU with `frame->rsp = tasks[0].kernel_stack_top`, one
stack shared by every CPU taking the path, with one suggestive capture and no witness. It has a
witness now, and the lead was right.

**Why it looked latent, and what it actually is.** Measured with `KSTACK0_PARK_TRACE=1`, which
prints a line per park:

| Workload, `-smp 4` | Parks per boot | Two CPUs on one park stack |
|---|---|---|
| healthy scripted session | **0** (3 boots) |, |
| `PROC_SELFTEST` (kills tasks on purpose) | **5–8** | **2–3 per boot, 3 boots of 3** |

Every park used the same `rsp=0xffffffff80202ff0`. The collision report is exact:

```
PANIC: two CPUs parking on one kernel stack rsp=0xffffffff80202ff0 this-cpu=1 already-cpu=2 task=1 'exectest'
  claim: task 1 running_cpu=-1  percpu_current=[0,1,0,3]  imp=[0,0,0,0]
```

Two CPUs parked there both run `sti; hlt` on it and both push a trap frame at the same address
on the next tick, which is the `task=0`, `percpu_current=[0,0,0,0]`, `bogus resume
rsp=0xfee000b0` capture explained: the LAPIC EOI register address is a word out of the other
CPU's `lapic_eoi` frame.

**The distinction that mattered was "unreachable" versus "unexercised".** Three healthy sessions
said 0 parks, and that is the reading the earlier note nearly settled for. Choosing a workload
that kills tasks turned the same code into 5–8 parks a boot. A path that a test never enters is
not a path that cannot be entered.

**The fix.** Each CPU parks on its own ring-0 stack (the one `enter_cpu_idle()` already uses) so
the fault path joins the kernel's single park mechanism instead of keeping a worse second one.
`sched_note_park()` records the choice and halts if two CPUs ever pick the same stack.

**The gates, and the two corrections they needed.**

| Target | Build | Required |
|---|---|---|
| `smoke-kstack-park` | `PROC_SELFTEST=1`, `-smp 4` | self-test completes; ≥2 CPUs actually parked; **no** park stack used by more than one CPU; detector silent |
| `smoke-kstack-park-control` | + `KSTACK0_SHARED_PARK=1` | at least one park stack used by more than one CPU |
| `smoke-resume-guard-negative` | `RESUME_RSP_INJECT=1 RESUME_RSP_INJECT_VALUE=-7` | the guard's report **appears** on serial |
| `smoke-resume-guard-negative-control` | + `RESUME_GUARD_FLOOR_ONLY=1` | it is **absent**, the blind spot, on demand |
| `smoke-resume-guard-ist` | `CAPTEST_SELFTEST=1`, no injection | `CAPTEST: PASS` **and** the guard's report **absent**, it stays silent on a legal value |
| `smoke-resume-guard-ist-control` | + `RESUME_GUARD_BSS_ONLY=1` | the **false** rejection is **present**, and captest never finishes |
| `smoke-cr3-reclaim` | `PROC_SELFTEST=1`, `-smp 4`, N boots | no supervisor write fault at `0xFEE000B0` (0 in 30 measured) |
| `smoke-cr3-reclaim-control` | + `CR3_RECLAIM_UNGUARDED=1` | the free-in-use report is **present** (20 in 20 measured) |
| `smoke-exec-reenter` | `PROC_SELFTEST=1 SCHED_INVARIANTS=1`, `-smp 4`, N boots | the wrong-CPU exec re-entry report is **absent** (0 in 30 measured) |
| `smoke-exec-reenter-control` | + `EXEC_REENTER_GLOBAL=1` | it is **present** in at least one boot (5 in 20 measured) |

- **Both arms assert the same deterministic property**, read off the trace: was any one park
  stack used by more than one CPU. A first draft gated the control arm on the collision *PANIC*,
  which requires two CPUs parked at the **same instant**, a property of the schedule, not of
  the code, and it reproduced 2 boots in 3. Whether the park target is shared is what the
  change controls; whether two CPUs are simultaneously parked is not.
- **The fixed arm asserts that the path was entered at all.** Without the "≥2 CPUs parked"
  check, "no park stack was shared" is vacuously true on a kernel that never parks, which is
  exactly what a healthy session produces, and would have been a green gate over dead code.

Both arms: **3 of 3**.

**It also exposed a second gap, and S9 was overclaimed because of it.** The per-CPU idle stacks
had **no guard page**, so `SECURITY.md` S9 ("an unmapped guard page below every kernel stack")
was false, independently of this finding, since `enter_cpu_idle()` has always parked CPUs there.
The guard is now the first page of each slot, which leaves the stack *top* exactly where
`ap_trampoline.S` computes it and so needs no change to the trampoline or its duplicated stride
constant. Falsified by disabling the arming: `WX_SELFTEST: FAIL armed 0 AP idle-stack guards,
expected 4`, exit 2.

---

#### The record: how this was read, before it was understood

Everything below this line is the contemporaneous record. It is kept because the wrong readings
are the useful part.

`smoke-session-smp-soak` fails at roughly **2–3% per boot** on current `main`:

| Where | Result | Signature |
|---|---|---|
| `e8cc850`, pinned to two host cores | **1 hang in 45** | not captured (main's soak discarded it) |
| CI runner, PR #117 pre-rebase, run 12/15 | **1 hang in 15** | **A**, 9 checks, stalled at `apropos` |
| CI runner, PR #117 rebased, run 39/45 | **1 hang in 45** | **B**: 0 checks, stalled at **boot** |
| CI runner, `smoke-fs-persist` (2026-07-31) | intermittent | **C**: **uniprocessor**, stalled after fs provisioning |
| CI runner, `smoke-fs-conc` (2026-08-09) | intermittent | **C**, identical |
| `ba84e90` local, `-smp 4`, logs preserved (2026-08-13) | **1 fail in 150** | **A**, 6 checks, stalled mid-`man`; `#GP` at `iretq`. First fully symbolised capture |
| `e9aebdd` local, `-smp 4` (2026-08-13) | **1 fail in 150** | **A**: two events in one boot: `#GP` at `iretq` (cpu 3, resume = a `.text` address) **and** `#PF` at the first `pop` (cpu 0, resume = `4`). First `t > 0` claim capture: invariant **held** |
| PR #135 rebased onto `e9aebdd`, `-smp 4` (2026-08-13) | **0 fail in 150** |, (control arm: the fault is `main`'s, not #135's) |

**Three distinct signatures have been observed, and they are not the same failure.** Signature C
is not even an SMP problem; those boots report `smp: uniprocessor, 1 CPU`.

**Signature A**, the session gets 9 of its 12 checks in, then a command's output stops partway
through a line and the shell never returns to its prompt:

```
[ok] apropos finds pages by keyword
SESSION_TEST: FAIL, timeout after 120s waiting for 'root@horus#'
recent serial: "...apropos directory\r\n  ls  (1)  list directory entries\r\n ... rm          "
```

**A new observation, 2026-08-11 (PR #127 CI, 1 hang in 45: the documented rate).** The same
signature, captured with one more line of context than before, and that line changes what it is:

```
[ok] whatis prints the one-line summary
SESSION_TEST: FAIL, timeout after 120s waiting for 'mkdir'
recent serial: "...root@horus# apropos directory\r\n\r\n  ls   (1)  list directory entries\r\n
                  cd     init: shell exited, relaunching\r\n"
```

**The shell exited.** `init` noticed and relaunched it; that message is `init` doing its job,
not a stall. So the wording above ("the shell never returns to its prompt") describes the
symptom accurately but implies the wrong mechanism: this is a ring-3 process dying mid-write and
being restarted, not a livelock or a lost wakeup. The harness then times out because the
relaunched shell is not logged in, so nothing answers the next command.

That is a **substantially more tractable** bug than a hang: a task that exits has a reason (a
fault, an unhandled signal, an `exit()` path) and the kernel can be made to say which. It also
explains why the truncation always lands mid-line: the writer stopped existing partway through a
`write`.

Not yet a diagnosis, and deliberately not written up as one: it is one capture, the exit reason
was not recorded, and it does not obviously account for **signature B** (which never reaches a
login prompt at all, so there is no shell to exit). **The next step on G-8 is to make `init`
report *why* the shell exited** (status, and whether it faulted) rather than that it did. That
is a small change to `init` and the wait path, and it converts this signature from a timeout
into an error message.

*Two earlier readings of stalled sessions were wrong in this same area*, a split prompt read as
a hung kernel, and frozen audit counters read as a wedge (see `docs/ROADMAP.md` §1.1). Both were
"the observer failed", and this one is "the observed process died". None of the three was the
livelock the finding was originally filed as. Weight the livelock hypothesis accordingly.

**That instrument now exists (2026-08-11). It has not yet caught a G-8 boot.**

`SYS_TASK_EXIT_INFO` (93) records why a task died and hands the record to its `SYS_WAIT`
supervisor; `init` prints it in band, through `console_server`, as

```
init: shell exited: faulted on memory access at addr=0x... rip=0x... err=0x...; relaunching
```

instead of the bare `init: shell exited, relaunching`. Every `task_teardown` call site must now
state a cause (`TASK_EXIT_NORMAL` / `KILLED` / `SIGNAL` / `FAULT` / `PAGEFAULT`), so a task can
no longer disappear without saying why. **This is a mechanism, not a diagnosis**: nothing below
is a claim about what G-8 *is*.

*Why the kernel was silent, which is worth recording on its own.* The generic ring-3 trap path
already printed `[task N '<name>' killed: ...]`, but `print()` only appends to the klog once
ring-3 `console_server` owns the console (`terminal.c`), so during a live session that line
never reaches the wire. The ring-3 **`#PF` kill path printed nothing at all**: its banner is
gated on a ring-0 / task-0 fault. A shell killed by a page fault mid-`write` was therefore
completely silent, which is exactly the observed signature. Writing it at the UART anyway is
finding #126, so the record is read out in band instead; the same fix shape as roadmap 1.1 step
2b.

*One thing this already narrows, from source rather than from a capture.* `handle_command()`
holds the shell's only `sys_exit()` (`userspace/shell.c`), and it is reached from exactly one
call site, which intercepts `exit`/`logout` first and turns them into a **logout**, not a task
exit. **The shell has no reachable voluntary exit path.** So signature A's `init: shell exited`
cannot have been a clean `sys_exit`: it was a fault, an uncaught signal, or a kill. The new line
will say which.

*Falsified, both arms, before being believed* (`make smoke-proc`, which asserts the exact
reason for a clean `sys_exit` child and for a `ud2` faulter, so a hardcoded constant cannot
satisfy both):

| Deliberate break | Result |
|---|---|
| fault path reports `TASK_EXIT_NORMAL` | `FAIL fault-exitinfo-reason` (clean-exit arm still passed) |
| teardown never delivers the record | `FAIL exitinfo-normal-reason` |
| unmodified | `smoke-proc` PASS |

`proctest` also asserts the *rendered text* using the same `format_exit_reason()` that `init`
prints with, so the diagnostic is not first executed during the failure it exists to explain.
Session regression, adjacent-boot alternating: **0 failures / 8 boots** on this change and
**0 / 8** on `main` at `a017e02`, same host, interleaved.

**First soak on the instrumented build: the instrument did NOT fire. Read this before assuming
signature A is solved.** PR #130's CI soak hung 1 in 45 (the documented rate) at run 10/45, 6
checks in, truncating mid-line during `man ls`:

```
SESSION_TEST: FAIL, timeout after 120s waiting for 'ls - list directory entries'
recent serial: "...root@horus# man ls\r\n\r\nls(1)          "
```

**No `init: shell exited:` line anywhere**, and nothing further arrived in the whole 120 s
window. That is *not* the #127 capture repeated: there, `init: shell exited, relaunching`
appeared inline. Two readings remain open and this capture does not separate them:

1. **Signature A has more than one mechanism**, this boot's shell did not exit, so the #127
   capture was one member of a set, not the signature; or
2. **the shell did exit and `init`'s report never got out**: in which case the *reporting
   path* is what to investigate (init writes through `console_server`, so a console_server
   that is itself stuck would swallow the line).

Reading 2 is the one to rule out first, and it is the same lesson as every earlier G-8
misreading: **check the observer before the observed.** An instrument that is silent proves
nothing until it is known to be capable of speaking on that path, `proctest` proves the
kernel-side record and the rendering, but nothing yet proves `init` can get a line out at the
moment the shell dies under SMP. Do not quote the absence of the line as evidence the shell did
not exit.

#### The one datapoint G-8 has, and why its `rip` must be withdrawn

After #138 made `init`'s report reach the wire, CI's soak produced the first (and so far only)
recorded cause:

```
init: shell exited: faulted on memory access at addr=0x94 rip=0xffffffff80105f0f err=0x0
```

`addr=0x94` was read as a near-null dereference at a struct offset, and the `rip` was read as
the `out->cs` load in `interrupt_handler64` (`testb $0x3,0x90(%rbp)` with `out` ≈ 4). **That
reading does not survive checking.**

It was checked the only way that means anything: by fetching **CI's own `kernel.elf`
artifact** from the run that produced the line, rather than symbolising against a local
rebuild. (The builds are reproducible and the soak job uses the default configuration, so the
uploaded artifact is the soak's kernel.) In that binary:

```
ffffffff80105ef1:  cmp    %rbp,%rax          ; #123's floor guard
ffffffff80105ef4:  jae    ...                ;   -> panic if rsp is not higher-half
ffffffff80105ef6:  testb  $0x3,0x90(%rbp)    ; out->cs
ffffffff80105f03:  mov    0x28(%rsp),%rax    ; stack-protector epilogue
ffffffff80105f08:  sub    0xa41d9(%rip),%rax
ffffffff80105f0f:  0f 85 47 05 00 00   jne   ; <-- the reported rip
```

Three things follow, and they matter more than the lead they retire:

1. **`0x80105f0f` is `jne rel32`.** It has no memory operand, so it cannot raise a `#PF` on a
   data address at all, let alone `CR2 = 0x94`. The reported `rip` and the reported `addr`
   cannot both describe one event.
2. **The floor guard dominates the `out->cs` read**, `cmp`/`jae` sit immediately above it,
   on `%rbp`, in a register. So "`out` is near-null there" was never available as a mechanism
   while that guard is compiled in, whatever the `rip` had said.
3. **That `rip` is exactly where an interrupt would land.** An interrupt pushes the address of
   the *next* instruction, and `ISR_NOERRCODE64` pushes `err_code = 0`, matching `err=0x0`.
   The frame the fault handler read looks like an **IRQ frame**, not a `#PF` frame.

So the live question is no longer "what dereferences `0x94`" but **"why was `#PF` handling
running against a frame that is not the fault's frame?"**, a `CR2` genuinely from one event and
an `int_no`/`rip`/`err_code` from another. That is a considerably better lead, and it is also a
warning: the exit record is assembled from `CR2` (a register) and `f64->rip` (memory), and
nothing checks that they agree.

The report now prints the frame's own `vec` and `errc` beside the handler's `CR2`, so the next
occurrence answers that question in the capture instead of a year later. A healthy fault reads
`vec=14 errc=0x0` next to `PAGE FAULT at ...`; the injected one in `make smoke-kfault` shows
exactly that, which is what makes a disagreement legible when it appears.

#### One hypothesis that covers both open kernel-fault signatures

**Two CPUs executing on one kernel stack.**

- A `#PF` handler reading a frame whose `rip` and `err_code` belong to a *different* trap; 
  the datapoint above, is what a concurrent push by another CPU into the same frame region
  looks like.
- A trap frame that `iretq`s into a kernel stack address (`err=0x11`, `rip` and `rsp` 0x80
  apart in the same region); the fault then believed to be holding roadmap 1.1 in PR #135, is
  the same corruption once it reaches the `rip` slot.

Neither needs a second mechanism, and both are SMP-only, which fits: #135's boot-only harness
saw 0/20 at `-smp 1` on both lock arms and only ever saw the fault at `-smp 4`.

> **Superseded on 2026-08-13, read this section as the record of a hypothesis, not a
> conclusion.** Two later captures below show the invariant *holding* at a `t > 0` fault, and a
> resume value of `4` that needs no second CPU to explain. The attribution to PR #135 was also
> wrong: the fault reproduces on `main` without it, and #135 has since merged.

The invariant at stake is the one in `scheduler.c`: `task_running_cpu[t] == c` ⟺
`percpu_current_task[c] == t`. A fault is exactly the moment to ask whether it still holds, so
the fault report now dumps it:

```
claim: task 3 running_cpu=0  percpu_current=[3,0,0,0]  imp=[0,0,0,0]
```

That runs **only from a fault report**, which is deliberate. The previous attempt to attribute
this fault (PR #137) checked the resume `%rsp` on *every interrupt return* and raised the
failure rate it was meant to explain, 4/30 shell restarts against 0/30 for `main`. A diagnostic
that runs only after the failure cannot perturb the thing it measures. This is a hypothesis with
a test attached, not a diagnosis; the next capture either shows a violated claim or rules the
hypothesis out.

**The general lesson, for the third time in this file: symbolise against the binary that
produced the address.** #138's comment read the same `rip` as landing mid-instruction and
inferred a return address; this reading found it a clean boundary and inferred a load. Both
were done against rebuilt trees. The artifact was available from CI the whole time.

#### The first capture taken with the report audible (2026-08-13)

#140 made kernel fault reports reach the UART instead of the klog. Run against `ba84e90` at
`-smp 4`, keeping **every** failing run's full serial log: which `smoke-session-smp-soak` did
not do at the time, so it was done by hand; the target has since been fixed to do it (below) ,
the fault appeared **once in 150 boots**:

```
64-bit EXCEPTION vector=13 err=0x4388 task=0 ''
  vec=13 errc=0x4388
  rip=0xffffffff8011cc03 cs=0x8 rflags=0x10086
  rsp=0xffffffff8010e8e2 rbp=0xcbe8c35c415d5bc9 cpu=0
  claim: task 0 running_cpu=-1  percpu_current=[0,0,0,3]  imp=[0,0,0,0]
```

Symbolised against the binary that produced it (sha256 pinned before the run; no rebuild between
capture and analysis): **`rip` is exactly the `iretq` in `isr_common_stub64`**, not near it, the
instruction itself.

##### The resume `%rsp`, recovered and then proved

`kfault_frame` prints `f->rsp`, the RSP the CPU pushed at the fault. Between loading the
resume value and the `iretq` the stub does 15 `pop`s and `add $0x10`, so the value
`interrupt_handler64` actually returned was `0xffffffff8010e8e2 - 136 = 0xffffffff8010e85a`.
That address is not garbage:

```
ffffffff8010e857:  call   *%r12                  <-- the syscall dispatch call
ffffffff8010e85a:  call   get_current_task       <-- ITS RETURN ADDRESS
```

**The resume `%rsp` was the return address pushed by `call *%r12` in `syscall_handler`.**

That is a reconstruction, so it was checked rather than believed. If it holds, the stub's eighth
pop (`pop %rbp`) drew from `resume_rsp + 64`. The bytes at that address in the pinned binary are
`c9 5b 5d 41 5c c3 e8 cb`, little-endian **`0xcbe8c35c415d5bc9`**, which is *exactly* the `rbp`
in the report. A 64-bit match is not coincidence: the reconstruction predicts an observed
register and gets it right, so the GPRs demonstrably were loaded from `syscall_handler`'s own
instruction stream.

**The error code confirms it a third time, from an independent observable.** After the pops and
`add $0x10`, `iretq` reads its frame from `R+136`, so `CS` comes from `R+144`. The bytes there
are `…4389`. A `#GP` selector error code carries the index in bits 15:3 with the EXT/IDT/TI
flags below, so selector `0x4389` (index `0x871`, RPL 1) encodes as `0x871 << 3 = 0x4388`:
**exactly the reported error code**, with the RPL bits dropped precisely as the encoding
specifies.

Three independent quantities now agree on the same resume value: the faulting instruction,
`rbp` read from `R+64`, and the `#GP` error code derived from `R+144`. Index `0x871` is far
past any real GDT entry, which is why the `iretq` faulted rather than returning somewhere
plausible and corrupting silently.

##### The harness was destroying these captures, and no longer does

This capture had to be taken by hand, because `smoke-session-smp-soak` reused one `mktemp` log,
overwrote it every iteration, deleted it at the end, and printed `tail -20` of the failure. That
is not a hypothetical loss. On PR #142 (a docs-only change) CI hit an occurrence at run 34/45
and retained exactly this:

```
PAGE FAULT at 0x525c71a094 err=
```

It stops mid-assignment. The error code, `rip`, `rsp`, `rbp` and the `claim:` line (the whole
payload #140 was added to produce) were discarded by the harness that observed them. **Every G-8
occurrence CI has ever seen was thrown away this way**, including any `t > 0` capture, which is
the one that would settle the hypothesis above.

Two causes, both fixed:

1. **`session_test.py` stopped draining too early.** On seeing a fault marker it waited for the
   rest of the dump with `for _ in range(6): if not self._pump(0.25): break`, which gives up
   at the *first* quarter-second with no bytes. A fault report is not a continuous stream: the
   kernel formats each field, and under SMP may do so while another CPU is wedged, so a gap
   mid-dump is ordinary. It now tolerates gaps and stops on sustained silence, bounded by
   `FAULT_DRAIN_SECS`.
2. **The soak kept no evidence.** `session_test.py` has always supported `SESSION_SERIAL_LOG`,
   which writes the complete serial buffer; nothing set it. Each boot now writes one, passing
   runs are deleted, failing and vacuous ones are kept with their stdout, and CI uploads the
   directory, plus the exact `kernel.elf`, because symbolising against a rebuilt tree has
   already produced a wrong reading of this fault twice.

Verified in both directions rather than assumed. With `KFAULT_INJECT=1 KFAULT_INJECT_TICKS=40`
firing a deliberate supervisor fault mid-session, the retained log contains the report whole
(`PAGE FAULT` line, `vec`/`errc`, `rip`/`cs`/`rflags`, `rsp`/`rbp`/`cpu`, and `claim:`) where
CI's #142 capture had one truncated line. And a clean soak removes the directory, so a passing
run uploads nothing.

##### Why the floor guard did not catch it

`idt.c` has had a guard for exactly this since #123:

```c
if (rsp < 0xFFFF800000000000ULL) { /* PANIC: dispatcher returned a bogus resume rsp */ }
```

`0xffffffff8010e85a` **is** higher-half, so it passes and reaches the `iretq` unchallenged. The
guard tests *"is it higher-half"* where the property it needs is *"is it inside a live kernel
stack"*, necessary, not sufficient. A `.text` pointer satisfies the first and fails the second.

##### What this changes, and what it does not

It reframes the hypothesis above rather than confirming it. This is **not** a smear of corrupted
memory: one specific *value* (a return address) arrived where a stack *pointer* belongs. A
one-word value/pointer confusion does not require two CPUs writing one stack, so `-smp 4`-only
is no longer evidence for that mechanism specifically.

And the claim dump **did not discriminate here**. `scheduler.c` scopes the invariant to `t > 0`;
this capture is `task 0`, the idle/reaper sentinel (which `percpu_current=[0,0,0,3]` confirms,
three CPUs "on" it at once) so `running_cpu=-1` is outside the invariant's scope, not a breach
of it. Worth recording as a property of the instrument: **the claim line answers the question
only for `t > 0` faults**, and this one was not. A `t > 0` capture is still needed to decide the
two-CPU hypothesis either way.

One number to quote carefully: **1 in 150 is not a rate.** §5.2c documents ~2–3%; under a true
2.5% rate, seeing ≤1 event in 150 boots has probability ~11%, so this is the low end of the
documented range and not evidence of a change. Cite it as "1/150 observed". #126 is the
standing reminder of what a number stated past its evidence costs.

Next: `tasks[t].saved_ksp` is only ever assigned `frame_rsp` (`scheduler.c`), and callers pass
`(uint64_t)frame`, a stack address. Find the write that puts a return-address *value* there. The
fault landed mid-`man`-render with a `PAGE FAULT at 0x3` immediately after, so the shell-fault
teardown path is live in the same window, and `tasks[0].kernel_stack_top` is what the `#PF`
handler resumes on when it kills a task and finds no successor.

*(The section below supersedes that last paragraph: a second capture shows a resume value of
`4`, which no `saved_ksp` write produces, so the search it proposes is the wrong one.)*

#### A second capture: the hypothesis fails its first real test (2026-08-13)

Run to answer a different question, whether the fault recorded above as *"holding roadmap 1.1 in
PR #135"* belonged to that branch or to `main`, as two 150-boot arms on one host, both carrying
the evidence capture described below:

| Arm | Result |
|---|---|
| `main` at `e9aebdd` | **1 fail / 150** |
| PR #135 rebased onto it | **0 fail / 150** |

**1 against 0 at N=150 is not a difference** (Fisher p = 1.0), and no improvement is claimed for
the per-CPU lock. The load-bearing result is the other one: the fault **reproduces on `main`
with #135 absent**, twice across two independent builds (2 in 300 boots) with byte-identical
signatures. The attribution above was therefore wrong in one respect, corrected here rather than
quietly: this is `main`'s defect, not #135's, and it was never a reason to hold that PR. #135
merged on 2026-08-13.

##### Two corrupted resume values, two CPUs, one boot

```
64-bit EXCEPTION vector=13 err=0x4388 task=0 ''
  rip=0xffffffff8011c883 cs=0x8 rflags=0x10286
  rsp=0xffffffff8010e722 rbp=0xcbe8c35c415d5bc9 cpu=3
  claim: task 0 running_cpu=-1  percpu_current=[4,0,0,0]  imp=[0,0,0,0]
KERNEL FATAL EXCEPTION - halting

PAGE FAULT at 0x4 err=0x0(not-present,read,supervisor) task=4 'shell'
  rip=0xffffffff8011c868 cs=0x8 rflags=0x10286
  rsp=0x4 rbp=0x1ab3344b84c cpu=0
  claim: task 4 running_cpu=0  percpu_current=[4,0,3,0]  imp=[0,0,0,0]
```

Symbolised against the binary that produced it, `isr_common_stub64 = 0xffffffff8011c846`:

| Offset | Instruction | Matches |
|---|---|---|
| `+0x22` | `pop %r15`, the first pop after `mov %rax,%rsp` | fault **B**'s `rip` exactly |
| `+0x3d` | `iretq` | fault **A**'s `rip` exactly |

Fault A's resume value backs out to `0xffffffff8010e722 - 136 = 0xffffffff8010e69a`, the return
address of `call *%r12` in this build's `syscall_handler`, reproducing the previous capture **in
a different binary**, with `rbp` and the `#GP` error code byte-identical because the code bytes
at the same relative offsets are the same.

##### The hypothesis fails its first real test

Fault B is the **`t > 0`** capture the previous section said was needed. For task 4,
`task_running_cpu[4] == 0` and `percpu_current_task[0] == 4`: **the invariant holds.** That is
the discriminating observation, and it does not show two CPUs executing on one kernel stack.

One capture is not proof of absence. But the hypothesis now has no observation supporting it,
and the reasoning that made it attractive is separately weakened below.

##### Two different bad values, which changes the shape of the search

Fault A's resume `%rsp` was a `.text` address; fault B's was **`4`**. Two different garbage
values, two CPUs, one boot. So this is not one mis-assignment writing a return address into one
field, whatever produces it sits upstream of any single write site, and "find the line that
stores the wrong value into `saved_ksp`" is the wrong search. No `saved_ksp` write produces `4`.

It also removes the SMP-specific reasoning behind the shared-stack hypothesis: a one-word
value/pointer confusion does not need two CPUs, and `4` is not a stack address under any
interleaving.

##### The floor guard did not fire, and it should have

`rsp = 4` is unambiguously below `0xFFFF800000000000`, so `idt.c`'s guard (added in #123 for
exactly this) should have reported `PANIC: dispatcher returned a bogus resume rsp=`. **There is
no such line anywhere in the captured log.** The guard's own comment names this very value:

> *(Or earlier still, on the `out->cs` read just below: `rsp==4` faults at `0x94`, which is
> exactly what a reproduce-and-symbolise cycle spent an hour chasing.)*

Either the guard is not running on this path, or its report is being lost, and after #140 the
second should no longer be possible. This is now a sharper question than the `saved_ksp` search,
and it carries a warning about everything written above it: **a guard that does not fire on the
value it names is either misplaced or mute, so every "the guard did not catch it" statement
about this fault: including the one in the previous section, is an inference, not an
observation, until this is settled.**

##### Settled (2026-08-13): the guard was mute, and #140 did not cover it

The question above is answered, in both directions, by a gate rather than by another 150-boot
wait. **The report was being lost, and the loss was structural.**

`kfault_begin(1)` is `panic_begin()`, whose claim is **permanent**: the first CPU to report a
fatal fault takes it and never releases it, and every later CPU that asks for it halts **inside
`panic_begin`, without emitting a byte**. That is correct for its original purpose (two cores
tripping on the same tick used to interleave into `"PANICPANIC: : …"`). It is wrong for this
guard, which was bracketed `kfault_begin(1)`/`kfault_end(1)`.

The capture above is exactly that shape. **cpu 3 took a fatal `#GP` and halted holding the
claim, and its `KERNEL FATAL EXCEPTION - halting` line printed first.** The only report that got
out afterwards (cpu 0's `PAGE FAULT at 0x4`) is the one bracketed `kfault_begin(0)`, whose wait
is bounded and which prints anyway past the budget. So on that boot the guard could not have
been heard *whether or not it fired*, and #140's audibility fix genuinely did not reach this
call site: it moved the guard off `println()` and onto the UART, but left it behind a claim the
failure itself takes away.

**So the absence of the line was never evidence about the guard.** Every "the guard did not
catch it" statement about fault B is withdrawn.

The fix is one line of intent: report under the **bounded** claim, release it, *then* halt.
Halting is unchanged behaviour, `kfault_end(1)` already did it, and it is the fail-closed
answer, since `iretq`-ing onto a value just rejected is the one thing that must not happen. What
changes is that the line gets out first.

##### The two-arm gate, so this is never inferred again

`make smoke-resume-guard*` forces the dispatcher to return a bogus resume `%rsp` of **4** (G-8's
own recorded value, for the same reason `smoke-kfault` injects at `0x94`) once, after the
console handover, and asserts what reaches the wire. Four arms, run in seconds instead of at ~1
boot in 150:

| Target | Build | Required |
|---|---|---|
| `smoke-resume-guard` | injection only | PANIC line **after** the login prompt |
| `smoke-resume-guard-preclaim` | + permanent panic claim already held | PANIC line still appears |
| `smoke-resume-guard-legacy` | + claim held, **pre-fix `fatal=1` bracket** | PANIC line **absent** |
| `smoke-resume-guard-nofloor` | + guard compiled out | PANIC line **absent** |

The third row is the one that matters: it reproduces the defect on demand, so the second row is
a measurement rather than a story about one capture. Built with the old bracket, the injected
boot goes **completely silent at the login prompt** (no report, no secondary fault, nothing)
which is a signature worth recognising elsewhere in this file.

Two details that were nearly got wrong, recorded because both would have made the gate lie:

- The injected value is read through a `volatile`, not returned as a literal `4`. With a
  constant, GCC folds `4 < 0xFFFF800000000000` at compile time and jumps straight into the
  report; the arm would prove the *reporting* works while never executing the `cmp`/`jae` a
  real occurrence goes through. Verified in the disassembly, not assumed.
- The gate reuses `tools/kfault_test.sh` (via `REPORT_RE`) rather than copying it. It asks the
  same question ("is this report audible *after* the console handover") of a different
  reporter, and that ordering requirement is the whole test.

##### What the control arm then showed about the capture: a new narrowing

`smoke-resume-guard-nofloor` runs the same injected `rsp = 4` with the guard removed, and it
does **not** reproduce fault B. It faults at **`0x94`**:

```
PAGE FAULT at 0x94 err=0x0(not-present,read,supervisor) task=3 'console_server'
  rip=0xffffffff80106250 cs=0x8 rflags=0x10002
  rsp=0xffffffff8021bee0 rbp=0x4 cpu=0
```

That is `interrupt_handler64`'s own `out->cs` read, exactly as the guard's comment predicted,
and it is G-8's original `addr=0x94` datapoint, reproduced deliberately for the first time. But
**the capture faulted at `0x4`, in the stub's first `pop`**, meaning the value got past
`out->cs` too. `src/kernel/idt.c` and `lowlevel64.S` are byte-identical between `e9aebdd` (the
capture's commit) and current `main`, and in `main`'s build the guard dominates `out->cs`.

Both orderings of the two events give the same conclusion, so it does not depend on which CPU
faulted first: if the guard had fired it would either have printed (claim free) or halted this
CPU inside `panic_begin` (claim taken), and a halted CPU cannot go on to fault in the stub. So:

> **On that boot the resume value was not `4` when `interrupt_handler64` tested it, and was not
> `4` when it read `out->cs`. It became `4` in the epilogue window, after the guard, before the
> stub's `movq %rax,%rsp`.**

In that window the value lives in `%rbp` (callee-saved, moved to `%rax` *before* the `pop
%rbp`), and the frame's stack-protector canary **passed**, execution reached the stub, so
`__stack_chk_fail` was not taken. That points at a **register** that did not survive, not a
smeared stack, and it retires "find the write that stores a bad value into `saved_ksp`" a second
time.

Stated as an inference with its check named, per this file's standing rule: it rests on the
guard/`out->cs` ordering in a rebuild of an unchanged `idt.c`, not on the pinned binary, which
was not retained for this capture. The next occurrence settles it, and now that the guard is
audible, the next occurrence will say so itself.

**G-8 remains open.** What is closed is the instrument: the guard is now known to fire, and
known to be heard when it does.

*(Written 2026-08-13. It stayed open for four more days; the window this section identifies
correctly (after the guard, before `movq %rax,%rsp`) is the one closed on 2026-08-17. The
"register that did not survive" reading was the wrong half: a callee-saved register restored
from a stack slot a second CPU had rewritten is both a register and a stack. See the top of this
finding.)*

**Signature B**, nothing runs at all. Boot never reaches the login prompt:

```
SESSION_TEST: FAIL, timeout after 90s waiting for 'horus login:'
recent serial: "...init: starting, launching shell\r\n
                [console_server] ready (ring-3; owns serial + VGA framebuffer)\r\n\r\n"
```

**Signature C is diagnosed: and the first diagnosis of it, published here, was WRONG.**

It is not a livelock on the single-slot endpoint. It is a **startup race whose consequence was
retried forever**, and the two want completely different fixes.

*What the evidence actually showed.* Three watchdog dumps 1200 ticks apart in one hung boot:

```
==== HANG WATCHDOG dump 1/3 at tick 601 ====
task 1 'fsserver' state=1 rctx=1 ksp=1 pblock=0 blkon=-1 rip=0x000002696a584ea0
task 3 'fsclient' state=1 rctx=1 ksp=1 pblock=0 blkon=-1 rip=0x000000dfe6209060
task 4 'fsclient' state=1 rctx=1 ksp=1 pblock=0 blkon=-1 rip=0x0000019c6aaf1060
task 5 'fsclient' state=1 rctx=1 ksp=1 pblock=0 blkon=-1 rip=0x0000002c44728060
```

; and dumps 2 and 3 are **byte-identical** in those instruction pointers. Two facts follow, and
between them they exclude contention outright:

1. **No endpoint section printed at all**, in any dump. The dump lists every endpoint carrying
   a message, a waiter or a recorded sender. None ever did. **Not one byte of IPC traffic
   crossed any endpoint for the entire boot.** Contention on a single slot would show traffic
   and *then* stall; zero traffic from the start means the clients never had a capability to
   send with.
2. Every task `RUNNABLE`, `pblock=0`, `blkon=-1`. Nobody blocked, nobody waiting, timer alive.

*The mechanism.* `SYS_CONNECT_FS_SERVER` returns `-1` until `fs_server` has completed
`SYS_REGISTER_FS_SERVER`. The clients are made runnable at the same instant as the server, so
losing that race is ordinary. The client called connect **once and discarded the result**:

```c
(void)sys_connect_fs_server(CAPSLOT_FS_EP, CAP_R_W);   /* result ignored */
...
while ((r = sys_ipc_call(CAPSLOT_FS_EP, ...)) < 0) spin_delay();   /* forever */
```

With an empty capability slot every call returns `SYS_ERR_PERM` (**-1**) (a permanent condition)
into a loop that treats every negative as transient. `SYS_ERR_PERM` is -1 and the retryable code
is -2; they were always distinguishable, and nothing distinguished them.

*Why this is a security bug and not only a robustness one.* Fail-closed has to mean **stop,
loudly, where authority was refused**. A refusal retried forever is indistinguishable from a
hang, so the one event the capability system exists to make visible becomes the one nobody can
see. Revoke a capability out from under any of these loops today and the task wedges silently
instead of reporting that it was denied.

*The fix, falsified in both directions.* `syscall.h` now states the retry contract explicitly
(`IPC_AGAIN` is the only retryable code, `ipc_transient()` the predicate); all four userspace
loops retry transient-only and bounded; and `fs_connect_retry()` retries the connect, the same
discipline `fs_server` already applies to its own registration on the other side of the same
race.

| Build | Starved single-core boots | Result |
|---|---|---|
| before | 30 / 30 | **3 and 5 hangs** (two runs) |
| after | 40 | **0 failures** |
| race restored, retry discipline kept | 30 | **2 hit the race, 0 silent hangs**, every one reported `FAIL ipc-refused rc=-1` |

That third row is the important one: it proves the two halves independently. The connect retry
is what removes the failure; the retry discipline is what converts a silent unkillable hang
into a diagnosable message, so the *next* bug of this shape costs minutes instead of a day.

*The lesson, which cost a published wrong answer.* "All tasks runnable, nothing blocked" is
consistent with contention **and** with nobody ever having started: and the first reading picked
the interesting hypothesis over the boring one without an observation that could separate them.
The endpoint dump was the observation. **A rate is not a mechanism, and neither is a plausible
story about one.** This is the fourth wrong hypothesis about intermittent failures in this repo,
and the first that was written into the docs before it was tested.

**Signature C**: a **uniprocessor** boot that stops dead once the filesystem is up. It has hit
`smoke-fs-persist` and `smoke-fs-conc`, both of which are *gating*:

```
[    1.393302] smp: uniprocessor, 1 CPU, no APs to start
FS_SELFTEST: begin
[fs_server] userspace FS server starting (encrypted object store).
[fs_server] registered; serving.
[fs_server] filesystem provisioned
                                        <- nothing further, until the harness gives up
```

One CPU means no scheduler race, no claim leak, and no cross-core wake to lose. Whatever C is,
it is a different animal from A and B, and it is the one currently blocking merges.

**Signature B is the `smoke-console-smp` deadlock signature, verbatim.** Compare the
description of that bug earlier in this document: *"boot reaches `[console_server] ready`, the
shell banner never arrives."* That defect was root-caused and fixed (PRs #112–#115) and the
console stress harness has held 24/24, 24/24 and 30/30 since. Yet a boot hang with the same
observable shape is still occurring at ~2%, which the console harness's sample sizes would
witness only about half the time.

So the live question is no longer "is this a hang or a slow test" but **"is this the same
deadlock, incompletely fixed, or a second one that presents identically?"**

**What it is not.** Not the IPC lost-reply race: `#116` is present in every tree measured. Not
caused by PR #117, which changed no kernel source. And **not** simply the `apropos` budget: that
remains a plausible explanation for signature A (the note on `smoke-session-smp` in the
`Makefile` records that same step already forcing `SESSION_TIMEOUT` from 60s to 120s on a loaded
runner *with no code fault*), but it cannot explain B, where zero commands ran.

**A rate is not a mechanism**, and neither is one capture. This repo has now made that mistake
in both directions: `smoke-console-smp` was a real deadlock dismissed as flaky, and the
`SCHED_INVARIANTS` report above was a correct kernel accused of a defect, which blocked a
roadmap item for a fortnight. The first draft of *this* finding then guessed "slow `apropos`"
from a single capture, and the very next capture falsified it. Three guesses, three wrong.
Hence: signatures recorded, mechanism explicitly not claimed.

**Why it was advisory rather than gating** (2026-08-09 to 2026-08-17). At ~3% per boot,
`SOAK_RUNS=15` reddens roughly a third of all CI runs. A required check in that state teaches
everyone to hit re-run, which is precisely the reflex that let the console-smp deadlock survive
months of CI. A gate nobody believes is worse than an advisory job somebody reads. `SOAK_RUNS`
is raised to 45 in CI so the advisory job actually witnesses the thing it is reporting (~75% of
runs, against ~37% at 15). **Restore it to gating in the same commit that resolves G-8 (either
way) and quote a rate, not a green run.**

*Done 2026-08-17.* The job gates again, and the rate is at the top of this finding: 31/800 on
the pre-fix release site against 0/800 on the shipped one, paired and alternating, Fisher p =
6.9 × 10⁻¹⁰. It was advisory for eight days and it was reporting a real defect throughout, which
is the case for reading a red advisory job rather than deleting it.

**Capturing the failing run is what made this legible.** The soak used to send every run to
`/dev/null` and trust the exit status. It now keeps the failing run's output, and the first CI
run after that change produced signature B, which overturned the finding's own initial
hypothesis within hours. A soak that reports only `FAIL` would have left "slow `apropos`" on the
page indefinitely.

**The next experiment, in order:**

1. ~~Run `smoke-sched-invariants-stress` at a sample size matched to ~2%.~~ **Done
   2026-08-09: 150 boots pinned, 150 pass, no `PANIC`.** At a 2% event that is >95% detection,
   so **the claim invariant is intact and none of these hangs is a leaked claim.** The
   console-smp fix is not incomplete in that respect, and the scheduler's claim bookkeeping is
   excluded as a cause. (30/30 would *not* have supported this conclusion, 30 boots witness a
   2% event less than half the time. The sample size is the whole argument.)
2. **Signature C first, because it is the cheapest and it gates merges.** It is uniprocessor,
   so the entire SMP surface is irrelevant: no claim leak, no cross-core wake, no CPU-idle
   handoff. That removes most of the search space at zero cost. Suspect the fs_server request
   path or the `FS_SELFTEST` driver immediately after provisioning.
3. **Get the kernel's own view at the stall** for A and B. Whether `console_server` is blocked
   in `recv` and the shell in `SYS_IPC_CALL` separates a lost wake from a scheduling stall.
4. **Only then** decide whether signature A is the same bug arriving later, or genuinely the
   `apropos` budget. Do not fold them together until the evidence does.

**`HANG_WATCHDOG=1`, because signature C leaves no log to read.** The clients in `smoke-fs-conc`
print *nothing* on the happy path: a passing boot is `[fs_server] filesystem provisioned`
followed directly by `CONC_SELFTEST: PASS`. So a wedged boot and a merely slow one produce
**byte-identical serial logs**: 120 seconds of silence, and no amount of staring at CI output
can separate them. That is the same "a test that cannot distinguish two states is not evidence"
defect as **[I-11]**, arriving as an absence rather than a race.

The watchdog dumps the scheduler's view of every task once a boot passes `HANG_WATCHDOG_TICKS`
without finishing, then **lets the boot continue**, halting would stop a merely-slow boot from
going on to pass, and "it would have finished given another second" is precisely the hypothesis
under test. The harness's own timeout still fails the boot; this only makes the log say why.
Enabled on `smoke-fs-conc` and `smoke-fs-persist` (the two targets showing signature C) at 6000
ticks, inside a 120s budget. Compiled out of the ship kernel.

It reads like this (positive control, fired deliberately at 50 ticks on a *healthy* boot):

```
==== HANG WATCHDOG: no progress after 50 ticks ====
cpu 0: current=2 idle=0 imp=0
task 1 'fsserver' state=1 rctx=1 ksp=1 pblock=0 blkon=-1 waiter=-1 cpu=-1
task 2 'fsclient' state=1 rctx=1 ksp=1 pblock=0 blkon=-1 waiter=-1 cpu=0
...
```

which is enough to split the cases that matter:

| dump shows | means |
|---|---|
| every task `state=1`, none blocked | nobody is stuck; the run was slow, fix the budget |
| a task `state=2/3/4` with no peer to wake it | a lost wake or dropped reply |
| a task `state=1 rctx=1 ksp=1` never selected | a scheduling bug |

**A gate must assert the property it is named for.** `smoke-sched-invariants-stress` originally
failed on *any* failed boot, so a hang that never tripped the checker reddened a job whose
entire claim is "the claim invariant holds", silently converting a precise gate into one that
inherits every intermittent in the system, which is the exact defect this section documents. It
now runs with `STRESS_GATE=marker`: a `PANIC` fails it, a boot that hung without one is reported
loudly as a G-8 datapoint and does not gate. The stress harness also **prints** the failing
serial log rather than only saving it to a file, a gating job failed 1-in-30 on CI with the one
artifact needed to diagnose it sitting in a workspace that was then deleted.