# Scheduling and SMP

**Decided; steps 0, 1, 1b, 2a, 2, 3a, 4a and 4b are built (section 5).** The maintainer asked on 2026-10-09 for a more robust SMP kernel and a
scheduler of high quality, chosen with security first. The decisions below were taken the same day.

## 1. What exists

| Piece | State |
|---|---|
| Run lists | Every live task is homed on one CPU's circular list (`tasks[].rq_home`, `rq_next`, `rq_prev`). Every switch path chooses through one rule, `sched_selectable` and `sched_pick_after` (#524), which looks at its own CPU's list before any other, under the one global `scheduler_lock` (§3.5) |
| Policy | Within each CPU's budgeted work the highest priority, round robin within a level, then its slack in round robin (§3.1, §3.2). Every shipped task is at 255 |
| CPU time | Scheduling contexts (§3.1, step 4a, #592): every task is bound to one, and runs only on the time it grants. Every task runs on the BSP's root until a holder of a context binds it elsewhere, and nothing in the shipped system does yet |
| CPUs | `MAX_CPUS` is 8 (`src/include/cpu_limits.h`). Each costs about 104 KiB of `.bss` whether present or not: a 68 KiB idle stack (`ap_idle_stacks`), 24 KiB of IST stacks (`ap_ist`) and 8 KiB of TSS (`ap_tss`) |
| SMT | Every secondary thread is parked before its timer starts (S101). A parked sibling keeps interrupts on to answer shootdowns and is marked idle, and `preempt_on_tick` refuses to schedule on one whatever interrupts it (#525) |
| Time | The PIT at 100 Hz drives `system_ticks` on the BSP. Each AP's LAPIC timer is one-shot at the same 10 ms, re-armed only while the AP has a task; an idle AP stops, and the BSP's tick wakes stopped APs while work waits (§3.4). A CPU running a task on a budget smaller than a root's also arms its LAPIC timer for the moment that budget runs out (§3.4, step 3b). No per-task timer, no IPC timeout. Ring 3 sees 10 ms time and nothing finer (S34) |
| Wake | A wake sets a task runnable and nothing else; it touches no run list. When the waker blocks straight after (a call, a reply followed by a receive), its own CPU takes the woken task at once, from another CPU's list if need be: 59 of 64 wakes in a two-CPU boot ran within 100 µs (2026-10-09, an instrumented build, before the lists). When the waker keeps running, the woken task waits for the next tick of an idle CPU, up to 10 ms |
| Isolation on switch | The microarchitectural state is flushed on every switch between tasks; FPU state is saved and restored eagerly (S16) |
| Stack ownership | One CPU at a time on a task's kernel stack, held by the claim protocol and `sched_release_deferred` (S20) |
| TLB coherence | An address space is live on at most one CPU, there are no threads and no global pages, and `switch_cr3` flushes. So the ship kernel never needs a cross-CPU shootdown, and `smp_maybe_shootdown` is called only by the selftest. When its bounded wait runs out with an acknowledgement outstanding, it halts with a named panic (S124, #523) |
| Locks | `scheduler_lock`, `cap_lock`, `endpoint_lock`, `page_lock` and `storage_lock` are each global; the run lists have no lock of their own |
| IPC | An endpoint holds a bounded queue of messages and at most one blocked caller (`struct endpoint`). A server takes a message when it chooses, by `SYS_IPC_RECV` or `SYS_IPC_RECV_BLOCK` |

## 2. The decisions (2026-10-09)

1. **CPU time is a capability.** A scheduling context is a kernel object holding a budget and a
   period; a task runs only on the time a context it is bound to grants. Contexts descend from one
   root handed to `init`, and a split carves budget out of its parent, so time can be passed on and
   subdivided and never grown. This is the model of seL4's mixed-criticality kernel, adapted to
   Horus's budgets that only shrink.
2. **Priority is capped by authority.** A task's priority is fixed, and a task can set another's
   only through a `CAP_TCB` carrying the right to, and never above its own maximum.
3. **Passive servers.** A server may hold no time of its own and run on the time of the client
   whose call it is serving, so a client cannot make a server spend someone else's time, and the
   priority inversion across IPC that a busy server causes goes away.
4. **SMP, in scope:** per-CPU run queues (built as run lists, §3.5); per-CPU one-shot timers and tickless idle; targeted TLB
   shootdown; more than eight CPUs; affinity as a right that only narrows.
5. **SMT stays parked.** S101 does not change.
6. **Order:** LIMITATIONS 5.3e is settled first, then this document, then one pull request per
   step of §5, each with its gate and control arm.
7. **Time is accounted per CPU.** Each CPU has its own root of time, as in seL4. A budget is
   charged, enforced and refilled only by the CPU it belongs to, so no budget is ever touched by two
   CPUs at once, and a CPU whose contexts sum to no more than its whole time gives each a real
   guarantee. Where work runs is decided in ring 3, by whoever holds the authority to bind it.
   A machine-wide root was considered and refused: it needs cross-CPU budget accounting, which is
   new race surface in the code that has carried S20, G-8, G-12 and 5.3e.
8. **Slack time is best effort and moves.** A context may carry a slack right. Tasks bound to it
   run, round robin and below every priority, on any CPU in its mask that has no budgeted work, and
   only slack work is ever stolen by an idle CPU. Without it a busy machine with low budgets would
   sit idle; with it, existing programs still spread across every CPU.
9. **A passive server takes a send only on its own time.** A send or notification that reaches a
   passive server is queued, and taken only while the server runs on a context of its own, so no
   client ever pays for another's message.

Not chosen, and why: proportional share alone (no answer to a busy server); a fixed time partition
per security domain (wastes every idle slot; can be layered on later); feedback queues that guess a
priority from behaviour (a task can game them, and the guessed priority leaks what it is doing).
Deferred: the `%gs` per-CPU block (roadmap 1.2) and PCID.

**Step 4's open points, answered 2026-10-17** (each as recommended):

10. **Step 4 comes before 3b**, with budgets and periods given in microseconds and enforced to the
    10 ms tick until 3b brings deadline timers; 3b then makes enforcement finer without changing
    the interface.
11. **A context's memory comes from the caller's untyped region**, carved by the split itself as
    `SYS_RETYPE` carves an endpoint (S57), so no context holder can exhaust a kernel pool.
12. **Revoking a context gives its time back to its parent, and the tasks bound to it stop** until
    their supervisor binds them again: none falls back to time nobody gave it.
13. **Two pull requests**: 4a (contexts, budgets, binding) and then 4b (priorities and their
    maximum), budgets first because priority without a budget would let a spinner starve
    everything below it (§3.2).

## 3. The design

### 3.1 Scheduling contexts

A new capability type, `CAP_SCHED_CONTEXT`, names a context. A context holds:

- the **CPU** it belongs to, fixed when it is made;
- a **budget** and a **period**, in kernel time units (§3.4), with budget at most period;
- a **remaining** budget for the current period, refilled at its start by its own CPU;
- whether it carries the **slack right**, and the **mask** of CPUs its slack work may use (§3.6).

At boot the kernel creates one root context per schedulable CPU, each with that CPU's whole time
and the slack right, and hands `init` a capability to each, the way it hands `init` the root
untyped region. `SYS_SCHED_SPLIT` carves a child from a context on the same CPU: the child's share
comes out of the parent's, so a CPU's contexts never sum to more than its root. That is the
property a Kani proof states (§4). A split may drop the slack right and narrow the mask, never the
reverse.

A task is bound to exactly one context. **Several tasks may be bound to one context and then share
its budget**, so a context is an account, not a reservation for one thread. A spawned or forked
child is bound to its parent's context unless the spawner names another it holds. That needs no new
authority (the child spends what the parent already could), so every program that spawns today
keeps working unchanged.

When a context's remaining budget reaches zero, every task bound to it stops being selectable until
the refill. A task cannot run on time it was not given, which is the denial-of-service defence:
without it a task that never blocks takes a share of every CPU for ever.

**As built in step 4a (#592).** A context holds a *share* of its CPU in parts per million and spends
it as a budget every period; its budget is its share of its period, rounded down. Three syscalls:

- `SYS_SCHED_SPLIT` (WRITE on the parent, WRITE on an untyped) carves a child of `budget_us` every
  `period_us` (10 ms to 10 s) out of the parent's share. The child's share is the budget's share
  of its period rounded up, so the child gets at least the budget it asked for, and it is checked
  again by multiplication before anything moves (`rust_sc_split`, whose Kani proof holds for any
  share the division could produce). The child's capability is derived from the parent's, with
  its rights, so revoking the parent revokes it; the parent's slot is checked again under the
  install's lock, so a child made during a revoke of its parent is refused rather than missed.
  The slack right is kept only if asked for and the parent has it.
- `SYS_SCHED_BIND` (a `CAP_TCB` to the task with WRITE, WRITE on the context) binds a task. A task
  bound to a context without the slack right is homed on that context's CPU.
- `SYS_SCHED_INFO` (READ) reports a context, with times rounded to the 10 ms tick, so it is no finer
  a clock than `SYS_CLOCK_GETTIME` (S34).

The kernel makes one root per CPU at boot, a whole CPU each with a 100 ms period and the slack
right, and gives `init` alone a capability to each schedulable CPU's root, at
`CAPSLOT_SCHED_ROOT_FIRST + cpu`. A new task runs on its creator's context, and a task the kernel
creates on the BSP's root, so until a holder binds something elsewhere every task is budgeted
work on the BSP and slack on every AP, which is exactly step 2's behaviour. A destroyed context's
share goes to its nearest living ancestor, as do its children, and every task bound to it is
unbound and chosen by no CPU. A task created by an unbound task is unbound too, so a task whose
context is revoked while it runs cannot fork its way back to time before its CPU next chooses.

Time is measured, not sampled. Each CPU stamps the context and the time when it chooses a task,
and charges the elapsed time, measured with the TSC, when it next chooses or ticks, so a task
cannot run for nothing by yielding just before each tick. A tick that lands while the task is in
the kernel charges it too, and if the task is then out of budget it is switched away from on its
way back to ring 3, as if it had yielded. A CPU whose only task is out of budget idles rather
than run it. Since step 3b the CPU's timer is armed for the moment the budget runs out (§3.4), so
a task in ring 3 is switched away from then, and a task in the kernel on its way back to ring 3;
on a one-CPU machine, where the LAPIC timer is not calibrated, a budget still ends at the next
tick. Whatever overrun there is is debt, carried into the next period, so over many periods a
context runs its budget and no more.
In the `SMP=0` build, which is compiled in CI and not shipped, a task out of budget keeps the CPU
when nothing else can run, because that build has no idle frame to switch to; it still yields to
any other task.

### 3.2 Priority

`tasks[].priority` becomes real: 0 to 255, higher runs first, round robin within a level. Each task
also carries a **maximum controlled priority**. Setting a task's priority or maximum needs a
`CAP_TCB` to it with a new right, and the value must not exceed the caller's own maximum. A child
inherits its parent's priority and maximum. `init` starts at the top. So no task can make itself or
anything else more urgent than the authority it was given.

Priority decides who runs among tasks whose contexts have budget left; the budget bounds how long.
Priority without a budget would let a high-priority spinner starve everything below it, which is
why the two arrive together (§5, step 4).

**As built in step 4b (#594).** `CAP_RIGHT_PRIORITY` is bit 7 of a capability's rights, and means
something only on a `CAP_TCB`. `SYS_SCHED_SET_PRIORITY` (126) sets a task's priority and maximum;
each must be at most the caller's own maximum, read under the scheduler lock because a holder of a
`CAP_TCB` to the caller could be lowering it at the same moment. A task's own priority may stand
above its own maximum, as in seL4: the maximum bounds what a task hands out, so a supervisor can
keep a server urgent and still cap what the server can make urgent. `SYS_SCHED_GET_PRIORITY` (127)
reads both, with READ. A spawner's `CAP_TCB` to its child carries the right, and a child starts at
its creator's priority and maximum (set in `create_task`, for spawn and fork alike).

Selection keeps every source in the order step 4a used, and a later candidate replaces the one
found only when it is strictly more urgent, so at equal priorities nothing changes; a search stops
at the first candidate at 255. The task a CPU is running keeps the CPU over every budgeted
candidate it outranks, and over slack work, which is below every priority. Before 4b a tick or a
yield on a CPU with no other budgeted work gave the CPU to any slack work waiting there, so
budgeted work could lose every other tick to it (found by reading the code, not measured).

Two consequences are stated rather than hidden. A lower priority runs only when nothing above it
can, so a task that polls with `SYS_YIELD` keeps everything below it from its CPU unless a budget
bounds it; this is why a budget comes with every priority. And a task that becomes runnable at a
higher priority waits for its CPU's next tick, because a wake does not preempt; a reschedule
interrupt is where that would change.

### 3.3 Passive servers

A server bound to no context is **passive**. When it takes a message from a client blocked in
`SYS_IPC_CALL`, it runs on that client's context until it replies, and the reply hands the context
back. Its priority while serving is its own, which its spawner sets at or above its clients'.

A queued message whose sender is not blocked in a call (a send, or a notification) carries no time
to lend. A passive server must not take it on a caller's time, or client A would pay for client B's
request. §6 question 3 decides what happens to it.

### 3.4 Time in the kernel

Each CPU gets a one-shot timer: the TSC-deadline mode where `CPUID` reports it and the TSC is
invariant, the LAPIC one-shot mode otherwise. It is armed for the earliest of: the running context's
budget running out, a refill that would make a more urgent task runnable, and the next kernel
timer. A CPU with nothing to run arms only for a refill, and halts. Where the TSC is invariant
the PIT stops being the clock: `system_ticks` is derived from the TSC.

**Built first (step 3a): one-shot ticks and tickless idle.** Each AP's LAPIC timer is one-shot
at the calibrated 10 ms and re-armed after every tick or kick only if the AP then has a task, so a
busy AP is preempted exactly as before and an idle one takes its pending tick and stops. A stopped
AP is woken by whoever ticks: every tick, the BSP's PIT tick and every AP's, ends by counting the
tasks that could run now and are not running and kicking that many stopped APs (vector 0xFC). So a
waiting task still gets a CPU within a tick, as when every idle AP polled, and no wake site changed:
a CPU that makes a task runnable is running, so its own tick follows. One AP, the watcher, never
stops, because the BSP can sit in ring 0 with interrupts masked for seconds (an Argon2 hash; the SMP
selftest runs entirely so) and then takes no PIT tick either; without the watcher every CPU could be
waiting on it. A parked SMT sibling never asks to be woken.

**Built next (step 3b): budget deadlines.** At every choice a CPU arms its timer for the moment
the chosen task's budget runs out, unless that budget is a root's (a whole CPU, so it times
nothing): an AP for that moment or its next tick, whichever is first, and the BSP its otherwise
unused LAPIC timer for the deadline alone, its tick staying the PIT's. The CPU whose budget it
is arms it, at the charge (`sc_account`), so no CPU programs another's timer. A deadline found
already past when the timer is re-armed means the interrupt that came for it landed in the
kernel and lost the scheduler lock; it is dropped, and the next tick takes the charge, rather
than re-armed into an interrupt every 20 µs. An early interrupt costs one pass through
`preempt_on_tick`, which charges by the TSC, so nothing is charged twice.

**Built last (step 3c): the TSC-deadline timer, the TSC clock, and refills.**

- **The timer mode.** Where `CPUID` reports the TSC-deadline mode and the TSC is invariant, each
  CPU arms its timer with the TSC value it is to fire at (`IA32_TSC_DEADLINE`), on the clock the
  budgets are measured with, rather than a count of LAPIC ticks worked out from a rate calibrated
  over 10 ms. Each CPU decides from its own `CPUID`, once the BSP has found the TSC invariant;
  every other CPU keeps the LAPIC one-shot. QEMU's TCG offers neither bit, so the TCG gates run
  the LAPIC path and the KVM job, given both bits, the TSC-deadline one.
- **Refills.** At every choice a CPU also arms its timer for the earliest refill of one of its
  carved contexts that would let a more urgent task run: anything outranks an idle CPU and slack
  work, and among budgeted work a higher priority outranks a lower. A refill that would bring
  back only an equal waits for the next tick or yield, as a wake does. Only a carved context can
  wait for a refill and its tasks wait on its CPU's list, so a CPU with none, which is every CPU
  of the shipped system, looks for nothing.
- **Charging comes first.** The selection charges the last choice before it looks at any
  candidate, so the task a CPU is running is judged on what its budget has left. Charged after,
  a task whose deadline had just ended its budget still looked budgeted, kept its CPU over the
  lower priorities waiting there, and the CPU then went idle with that work waiting until its
  next interrupt.
- **A run that crosses its period's end is two charges**: the time before the end to that period,
  the rest to the next. Charged whole to the first, the time after the end was never charged,
  since the refill that followed gave a whole budget, so a task chosen late in a period with
  budget left could run up to twice its share in the next. A choice charges what ran since the
  last, so a tick between had always limited this to the time since the last choice before the
  end; with deadlines and refills shorter than a tick, nothing did.
- **One CPU.** The BSP calibrates its LAPIC timer whether or not there are APs to start, so a
  budget on a one-CPU machine ends when it runs out too.
- **The TSC clock.** Where the TSC is invariant, `system_ticks` is derived from it: each tick
  sets it to the whole ticks elapsed since the first, by the TSC, and never moves it back.
  Counting PIT interrupts lost time whenever the BSP held interrupts off for longer than a tick,
  since the 8259 holds one pending IRQ 0 and drops the rest. Without an invariant TSC the PIT
  stays the clock. The BSP's tick interrupt is still the PIT's in both cases.
- **Kernel timers.** There are none yet. Per-task timers (roadmap 2.2) will be armed at the
  same point, as a third candidate for the earliest deadline.

The shortest period stays one tick (`SC_MIN_PERIOD_US`), as step 4a set it.

**Ring 3's view does not change.** `SYS_CLOCK_GETTIME` still reports 10 ms resolution and
`CR4.TSD` stays set (S34). Fine time is the kernel's, not the task's.

This step also gives roadmap 2.2 its per-task timers and an IPC call with a timeout, each a later
syscall change of its own.

### 3.5 Per-CPU run lists

Built in step 2. Each CPU has a list of the tasks homed on it, and a CPU choosing what to run looks
at its own list first. A task is homed on the CPU that created it, and moves when another CPU takes
it. Homing is placement only: whether a task may run is still `sched_selectable`'s answer, and
every candidate passes it, so a list can make a task wait but never makes one run that the rule
would refuse.

- **Membership is not "runnable".** The usual queue holds exactly the runnable tasks, so every
  wake has to enqueue. Here more than a dozen sites make a task runnable, most of them under an
  IPC lock, and a wake that forgot to enqueue would leave its task on no queue, for good, found
  only by a hang. A task's list changes only at creation, at death and when another CPU takes it,
  so a wake touches no list, the IPC paths take no new lock, and the lost wake cannot be written.
  The price is that a pick walks past the blocked tasks on its own list, where the old pick walked
  every slot in the table. `SCHED_INVARIANTS=1` checks that the lists are sound and that every
  live task is on exactly one; the check is exact, since every list write is under the lock.
- **Where a CPU looks, in order:** a task waiting on the list of a CPU that has not chosen for more
  than two ticks (it is inside a long kernel operation, which the kernel never preempts); then its own list,
  round robin from the task it is leaving; then any other CPU's list. A task taken from another list
  is homed on the CPU that took it. Until scheduling contexts exist every task is slack work, which
  any CPU may take. When they do (step 4), budgeted work never moves on its own: its context belongs
  to one CPU, and moving it is a ring-3 decision made by rebinding it to a context on another CPU.
- **No policy change.** The old single pool let any CPU take any waiting task at its next choice.
  The lists keep that: a CPU with nothing else of its own takes another's waiting task, and a CPU
  stuck in the kernel loses its waiting tasks to the others after two ticks or so.
- **Migration keeps S20.** A task changes lists only under the scheduler lock and only while
  `task_running_cpu[]` shows it on no CPU, and the outgoing CPU keeps its claim until it has left
  the task's stack, exactly as before. The lists never touch the claim. The S20 gates and arms run
  against the new code unchanged.
- **Not built yet, and why.** A list of its own lock: every pick still holds the global
  `scheduler_lock`, so a second lock would protect nothing the first does not; it comes when
  selection stops holding the global one. A priority bitmap for constant-time choice: the walk is
  bounded by the table, and stops at the first task at 255, where every shipped task is. A reschedule interrupt to the woken task's CPU: built when a workload shows
  the wait for a tick mattering, which the two-CPU boot above does not.

### 3.6 Affinity

Budgeted work runs on its context's CPU and nowhere else. Slack work runs on the CPUs in its
context's mask, which a split may narrow and never widen. So a supervisor can give a sensitive task
a core no untrusted task can be scheduled on: bind it to a context on that CPU with a mask of that
CPU alone, and give every other context a root on another CPU and a mask without it. Being alone on a
core is what makes the switch flush (S16 and the microarchitectural flush) a defence rather than a
mitigation against a co-resident attacker.

### 3.7 More than eight CPUs

- The per-CPU blocks move out of `.bss` and are taken from the pool at boot, sized from the
  processors the ACPI MADT lists. `MAX_CPUS` becomes a ceiling on the table, not a cost.
- The 68 KiB idle stack shrinks: an idle CPU runs no task code.
- `endpoint_lock` becomes one lock per endpoint, because IPC is the path every server shares.
  `cap_lock`, `page_lock` and `storage_lock` stay global until a measurement says otherwise.

### 3.8 TLB shootdown

Nothing in the ship kernel needs a remote flush today (§1). So the targeted shootdown is built when
its first real caller arrives, which is threads sharing an address space or PCID, and not before.
What is done now:

- The broadcast's wait **fails closed**: if not every CPU has acknowledged when the bound runs out,
  the kernel halts with a named panic rather than returning as though the flush had happened.
- When the first caller arrives: each address space records the CPUs that have loaded it since
  their last flush, a shootdown goes only to those, and flushes are batched per call.

## 4. Security properties and their witnesses

Each gets a `SECURITY.md` row with its S-number when its step merges.

| Property | Witness | Control arm |
|---|---|---|
| A task never runs beyond its context's budget, over many periods (S153) | `smoke-sched-budget`: a spinner bound to a fifth of an AP counts the ticks it saw itself run in | `BUDGET_UNENFORCED=1` |
| A budget ends when it runs out, not at the next tick (S153, step 3b) | `smoke-sched-budget`: a counter given 1 ms every 100 ms counts the ticks it ran in over 30 periods; `smoke-sched-budget-up`, the same on one CPU | `DEADLINE_UNARMED=1`, `UP_TIMER_UNCALIBRATED=1` |
| A refill is noticed when it is due (S153, step 3c) | `smoke-sched-budget`: a counter given 9 ms every 10, alone on its CPU, runs nine tenths of the time | `REFILL_UNARMED=1` |
| A run across a period's end is charged to both periods, and a task out of budget does not keep its CPU (S153, step 3c) | `smoke-sched-budget`: a counter given 5 ms every 10 at priority 100, delayed in every other period by `schedtest` at 255 on 7 ms every 20, runs four tenths of the time | `BOUNDARY_UNSPLIT=1`, `CHARGE_AFTER_PICK=1` |
| The timers are TSC-deadline where the CPU offers it (step 3c) | `smoke-sched-budget-tscdl`: the budget checks under KVM, and the boot names the mode | `TSCDL_OFF=1` |
| The clock keeps time while the BSP holds interrupts off (step 3c) | `smoke-tsc-clock`: the BSP masked for half a second loses the clock no tick | `TSC_CLOCK_OFF=1` |
| A split never creates time: the children and the parent's remainder sum to the parent's share (S152) | Kani `a_split_never_creates_time` and `reclaim_never_exceeds_a_whole_cpu`; `schedtest`'s refusals | three `kani-arms.yml` arms: the subtraction dropped, the share believed, the reclaim unbounded |
| No task makes itself or another more urgent than the authority it holds (S155) | `smoke-captest`: a child capped at 250 can neither raise its maximum nor set 255, and a `CAP_TCB` minted without the right is refused | `PRIO_UNCAPPED=1`, `PRIO_RIGHT_UNCHECKED=1` |
| Among budgeted work the higher priority runs, and a yield lets in only its equals (S154) | `smoke-sched-budget`: `schedtest` at 255 yields beside a counter at 100 on one context, and the counter does not move | `PRIO_IGNORED=1` |
| A passive server runs only on the time of the client it is serving | two clients, one starved of budget, one server | `DONATE_ANY_CALLER=1` |
| A context's CPU mask only narrows | `smoke-captest` cases | `AFFINITY_WIDEN=1` |
| Budgeted work never runs off its context's CPU, and slack work never off its mask | a pinned task reports its CPU every tick, under stealing | `AFFINITY_IGNORED=1` |
| A revoked context's tasks stop, and do not run on a later context that takes its index (S152) | `smoke-sched-budget`: a counter bound to a context stops when it is revoked and stays stopped when a new context is carved | `SC_DESTROY_KEEPS_TASKS=1` |
| A task whose context is revoked while it runs cannot fork its way to time: its children are unbound too (S152) | `smoke-sched-budget`: the counter revokes its own context and forks at once, and no child runs | `SC_UNBOUND_CREATOR_GETS_ROOT=1` |
| A bind lands on the task whose `CAP_TCB` was checked, never on a successor in its slot (S100) | `smoke-sched-budget`: `task_tcb_held` refuses a check made outside the spawn lock, and the binds `schedtest` needs succeed | `SCHED_BIND_UNLOCKED=1` |
| A budget is charged only by its own CPU (S152) | `SCHED_INVARIANTS` halts at the one place a charge is made if the charging CPU is not the owner (`smoke-sched-invariants`, which scores only a boot in which a CPU closed a choice of another CPU's work, noted on COM3; about one boot in four on 8 CPUs never does) | `BUDGET_CROSS_CPU=1` |
| A shootdown that is not acknowledged halts | the selftest with one CPU made deaf | `SHOOTDOWN_FAIL_OPEN=1` |
| S20 holds over per-CPU run lists | the existing S20 gates | the existing S20 arms |

**What this does not close.** Tasks that share a context, or a passive server, can each observe
the other's consumption through when they are descheduled: sharing an account is a channel by
construction, and a supervisor that keeps two domains apart gives them separate contexts.
A budget that ends when it runs out (3b), and a refill that starts it again when due (3c), tell a
task only that it stopped and started, which counting its own loop already tells it; it reads no
clock finer than the tick (S34).

## 5. Steps

| Step | What | Depends on |
|---|---|---|
| 0 ✅ | LIMITATIONS 5.3e settled (#526) | |
| 1 ✅ | The shootdown wait fails closed (#523) | |
| 1b ✅ | `preempt_on_tick` refuses to schedule on an SMT sibling, whoever interrupts it (#525) | |
| 2a ✅ | One selection rule for every switch path (#524) | |
| 2 ✅ | Per-CPU run lists and stealing; no policy change (§3.5) | 0, 1b, 2a |
| 3a ✅ | One-shot AP timers and tickless idle, the BSP waking stopped APs (§3.4) | 2 |
| 3b ✅ | Budget deadlines: each CPU's timer armed for the moment a budget runs out (§3.4, #595) | 3a, 4a |
| 3c ✅ | The TSC-deadline timer, the TSC clock, and arming for refills (§3.4, #596) | 3b |
| 4a ✅ | Scheduling contexts, budgets and binding (§3.1, #592) | 3a |
| 4b ✅ | Priorities and their maximum (§3.2, #594) | 4a |
| 5 | Passive servers | 4b |
| 6 | Affinity | 4a |
| 7 | More than eight CPUs | 2 |
| 8 | Targeted shootdown | its first caller |
