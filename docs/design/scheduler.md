# Scheduling and SMP

**Decided; nothing built.** The maintainer asked on 2026-10-09 for a more robust SMP kernel and a
scheduler of high quality, chosen with security first. The decisions below were taken the same day.

## 1. What exists

| Piece | State |
|---|---|
| Run pool | One table of `MAX_TASKS` slots. Every switch path scans it linearly through one rule, `sched_selectable` and `sched_pick_after` (#524), under the one global `scheduler_lock` |
| Policy | Round robin. `tasks[].priority` is written (1 at init, copied on spawn) and never read |
| CPUs | `MAX_CPUS` is 8 (`src/include/cpu_limits.h`). Each costs about 104 KiB of `.bss` whether present or not: a 68 KiB idle stack (`ap_idle_stacks`), 24 KiB of IST stacks (`ap_ist`) and 8 KiB of TSS (`ap_tss`) |
| SMT | Every secondary thread is parked before its timer starts (S101). A parked sibling keeps interrupts on to answer shootdowns and is marked idle, and `preempt_on_tick` refuses to schedule on one whatever interrupts it (#525) |
| Time | The PIT at 100 Hz drives `system_ticks`; every CPU's LAPIC timer runs periodically at the same rate. No one-shot timer, no per-task timer, no IPC timeout. Ring 3 sees 10 ms time and nothing finer (S34) |
| Wake | A wake sets a task runnable and nothing else. When the waker blocks straight after (a call, a reply followed by a receive), its own CPU takes the woken task at once: 59 of 64 wakes in a two-CPU boot ran within 100 µs (2026-10-09, an instrumented build). When the waker keeps running, the woken task waits for the next tick of an idle CPU, up to 10 ms |
| Isolation on switch | The microarchitectural state is flushed on every switch between tasks; FPU state is saved and restored eagerly (S16) |
| Stack ownership | One CPU at a time on a task's kernel stack, held by the claim protocol and `sched_release_deferred` (S20) |
| TLB coherence | An address space is live on at most one CPU, there are no threads and no global pages, and `switch_cr3` flushes. So the ship kernel never needs a cross-CPU shootdown, and `smp_maybe_shootdown` is called only by the selftest. When its bounded wait runs out with an acknowledgement outstanding, it halts with a named panic (S124, #523) |
| Locks | `scheduler_lock`, `cap_lock`, `endpoint_lock`, `page_lock` and `storage_lock` are each global |
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
4. **SMP, in scope:** per-CPU run queues; per-CPU one-shot timers and tickless idle; targeted TLB
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
today a task that never blocks takes a share of every CPU for ever.

### 3.2 Priority

`tasks[].priority` becomes real: 0 to 255, higher runs first, round robin within a level. Each task
also carries a **maximum controlled priority**. Setting a task's priority or maximum needs a
`CAP_TCB` to it with a new right, and the value must not exceed the caller's own maximum. A child
inherits its parent's priority and maximum. `init` starts at the top. So no task can make itself or
anything else more urgent than the authority it was given.

Priority decides who runs among tasks whose contexts have budget left; the budget bounds how long.
Priority without a budget would let a high-priority spinner starve everything below it, which is
why the two arrive together (§5, step 4).

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
budget running out, a refill that would make a higher-priority task runnable, and the next kernel
timer. A CPU with nothing to run arms nothing and halts. The PIT stops being the clock once a
TSC-based source is calibrated; `system_ticks` becomes derived from it.

**Ring 3's view does not change.** `SYS_CLOCK_GETTIME` still reports 10 ms resolution and
`CR4.TSD` stays set (S34). Fine time is the kernel's, not the task's.

This step also gives roadmap 2.2 its per-task timers and an IPC call with a timeout, each a later
syscall change of its own.

### 3.5 Per-CPU run queues

Each CPU has its own queue of runnable tasks, with a bitmap of non-empty priority levels, so picking
the next task is constant time, and its own lock. The global `scheduler_lock` stays only around the
claim protocol until that is rebuilt over the queues.

- **A wake goes to a queue and sends a reschedule interrupt** to that CPU if the woken task
  outranks what it is running. That removes the wait for a tick when the waker keeps running.
  It is built when a workload shows that wait mattering; the two-CPU boot above does not.
- **An idle CPU steals only slack work**, from the busiest queue whose slack tasks' masks include
  it. Budgeted work never moves on its own: its context belongs to one CPU, and moving it is a
  ring-3 decision made by rebinding it to a context on another CPU.
- **Migration keeps S20.** A task leaves a queue only under that queue's lock and only once
  `task_running_cpu[]` shows it on no CPU, and the outgoing CPU keeps its claim until it has left
  the task's stack, exactly as now. The existing S20 gates and arms run against the new code
  unchanged, and they must stay green.

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
| A task never runs beyond its context's budget in a period | a spinner bound to a small context, measured by a peer | `BUDGET_UNENFORCED=1` |
| A split never creates time: the children and the parent's remainder sum to the parent's share | Kani proof over the split arithmetic | a `kani-arms.yml` arm that drops the subtraction |
| No task raises a priority above its own maximum | `smoke-captest` cases | `PRIO_UNCAPPED=1` |
| A passive server runs only on the time of the client it is serving | two clients, one starved of budget, one server | `DONATE_ANY_CALLER=1` |
| A context's CPU mask only narrows | `smoke-captest` cases | `AFFINITY_WIDEN=1` |
| Budgeted work never runs off its context's CPU, and slack work never off its mask | a pinned task reports its CPU every tick, under stealing | `AFFINITY_IGNORED=1` |
| A budget is charged only by its own CPU | a context's charge records the charging CPU; the gate asserts it is the owner | `BUDGET_CROSS_CPU=1` |
| A shootdown that is not acknowledged halts | the selftest with one CPU made deaf | `SHOOTDOWN_FAIL_OPEN=1` |
| S20 holds over per-CPU queues | the existing S20 gates | the existing S20 arms |

**What this does not close.** Tasks that share a context, or a passive server, can each observe
the other's consumption through when they are descheduled: sharing an account is a channel by
construction, and a supervisor that keeps two domains apart gives them separate contexts.
Budget exhaustion is no finer a clock than the 10 ms tick a task can already count.

## 5. Steps

| Step | What | Depends on |
|---|---|---|
| 0 ✅ | LIMITATIONS 5.3e settled (#526) | |
| 1 ✅ | The shootdown wait fails closed (#523) | |
| 1b ✅ | `preempt_on_tick` refuses to schedule on an SMT sibling, whoever interrupts it (#525) | |
| 2a ✅ | One selection rule for every switch path (#524) | |
| 2 | Per-CPU run queues, the reschedule interrupt, stealing; no policy change | 0, 1b, 2a |
| 3 | Per-CPU one-shot timers, tickless idle | 2 |
| 4 | Scheduling contexts, budgets, priorities and their maximum | 3 |
| 5 | Passive servers | 4 |
| 6 | Affinity | 4 |
| 7 | More than eight CPUs | 2 |
| 8 | Targeted shootdown | its first caller |
