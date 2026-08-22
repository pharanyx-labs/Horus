# Testing Horus

Horus's security argument rests on its tests, so they are treated as first-class engineering
artifacts rather than an afterthought. This document catalogues them and states what each one
actually proves.

**The design principle: test that the control *fires*, not merely that the happy path
works.** Several tests deliberately corrupt inputs or attempt forbidden operations and assert
refusal. Those are the valuable ones.

---

## The three layers

| Layer | Runs | Command |
|---|---|---|
| **Rust unit tests + Kani proofs** | On the host, in seconds | `cargo test --manifest-path rust/Cargo.toml` |
| **QEMU integration self-tests** | Boot a purpose-built kernel, assert a serial marker | `make smoke-<name>` |
| **Scripted shell sessions** | Type into the real ring-3 shell over serial | `make smoke-session` |

```bash
make smoke     # the basic gate: boots to the ring-3 shell banner and login prompt
make test      # the full local sweep
```

---

## How a self-test works

Most follow one shape. A `*_SELFTEST` compile flag guards a routine in
`src/kernel/selftest.c` — or a ring-3 program in `userspace/` — that runs the check and
prints `NAME: PASS` on the serial console. A `make smoke-name` target builds that
configuration, boots it headless under QEMU with a timeout, and greps for the marker.

The test-only code and any test-only syscalls are **absent from the default kernel**, so they
fail closed in a shipping build. `SYS_PREEMPT_TRACE` is the clearest example: defined and
wrapped, but with no dispatch-table entry outside `PREEMPT_SELFTEST`, so it returns
`SYS_ERR_NOSYS`.

Timeouts default to 40 s and are overridable: `make smoke-tcc SMOKE_TIMEOUT=320`. TCG
emulation is slow, and CI runners are slower; a timeout is usually not a real failure.

---

## Capability and authorisation

| Target | Proves |
|---|---|
| `smoke-captest` | **100 checks**: an unheld capability is refused; a revoked capability cannot be used; a stale snapshot fails revalidation; minting into a kernel-reserved slot is refused; bad input is rejected. Twelve cover capability-addressed IPC (finding C-1), twenty-two cover untyped memory and retyping (finding I-7), ten cover "identity is not authority" (findings I-1 and H-1, run as uid 0), four cover the one-shot reply capability and five the blocking receive (roadmap 1.3) — see below. The central conformance suite. |
| `cargo test` (`rust/src/capability.rs`) | Mint masks rights and cannot widen them; transfer shares lineage; system-wide revoke reaches another task's cspace; an unrelated capability survives; primordial roots cannot be revoked; the generation counter skips the pristine sentinel on wrap; serial allocation never yields 0 or a reserved value. **[I-3]:** a subtree past the old 256-entry bound, and a 300-link chain, are revoked *exactly* while an independent peer sharing the same object survives — falsified against `--features=revoke_legacy_bounded`, which CI runs. |
| Kani proofs | Revocation nulls **exactly** the target's derivation subtree — no descendant survives, no non-descendant is touched. |

**The C-1 refusal checks, and why they are asserted precisely.** Twelve checks in
`smoke-captest` cover capability-addressed IPC: a `CAP_FRAME` (the pre-fix authorisation
gate) authorises no IPC operation; a WRITE-only client capability is refused `recv`,
`reply_to`, and `sender` — the interception and reply-forgery halves of the finding; endpoint
and notification capabilities do not authorise each other's operations; empty slots are
refused.

Each asserts the **exact** code `SYS_ERR_PERM`, never merely "negative". `sys_ipc_recv`
returns `-2` for an empty mailbox, so a `< 0` assertion cannot distinguish "the kernel refused
me" from "I was allowed to read, and nothing was there" — and under the pre-fix kernel these
probes hit empty endpoints and returned `-2`. The first draft of the suite used `< 0` and
**passed with the vulnerable handler deliberately restored**, proving nothing.

The fix was therefore verified by falsification: reintroduce the pre-fix handler, confirm the
suite fails (`CAPTEST: FAIL ipc-recv-on-unheld-slot-allowed`), restore it, confirm 41/41.
**A test that cannot fail on the bug it targets is not evidence** — the same defect class as
**[I-11]** in `smoke-fs-wal`.

**The "identity is not authority" checks (section 4b, findings [I-1] and [H-1]).** Ten checks,
run deliberately as **uid 0**, assert that the most privileged identity in the system buys
nothing without the capability: `dmesg` without `CAP_KERNEL_LOG`, boot-module info/read
without `CAP_BOOT_MODULE`, `fs_stat`/`inode_alloc` without `CAP_ENCRYPTED_STORAGE`,
`useradd`/`userdel`/`passwd`-of-another-user without `CAP_USER`, and cross-task
`get_task_info` without `CAP_USER` or `CAP_AUDIT`.

The last four are new on 2026-08-15 (**[H-1]**). There was previously no `useradd` probe at
all: the suite covered the properties that had been enumerated when **[I-1]** was closed, and
the user database was not among them, so the ambient gate in `kusers.c` survived a suite whose
whole purpose was to prove it gone. One of the four — cross-task `get_task_info` — is not new
so much as *resurrected*: it sat in section 1 behind `if (sys_getuid() != 0)`, and captest runs
as uid 0, so it had never executed on any boot. Dead code that read as coverage.

**Falsification.** With the `uid == 0` fallback reintroduced into `current_user_is_admin()`
(`kusers.c`) and nothing else changed, `make smoke-captest` reports
`CAPTEST: FAIL useradd-allowed-by-uid0-without-CAP_USER`. Restored: `CAPTEST: PASS 100
checks`. Measured on the same tree, the count went **96 → 100**.

**The second witness is `smoke-session`, and it is the stronger one.** `smoke-captest` proves
a task without `CAP_USER` is refused; it cannot prove the ambient gate was doing real work.
`smoke-session` does: with the fallback deleted and no other change, the session test went red
at `[ok] useradd allowed for root`, because `launch_shell` had never delegated `CAP_USER` and
the shell's `useradd` had been running on the ambient gate alone. `init` now delegates it and
the shell enforces the per-user half, so the session asserts both directions — root may add a
user, a standard user is refused with `useradd: permission denied (root only)`. That expected
string is deliberately more specific than the old `useradd failed`, which would also match an
*authorised* useradd that failed on its arguments.

*A hypothesis recorded and withdrawn.* The first draft of this change assumed captest had been
silently holding `CAP_USER` through `do_spawn_inner`'s propagation, and added a step to the
harness to clear slot 6. It had not, and the step was removed: the refusals pass identically
with and without it, because the propagation calls `cap_lookup(6, …)` after
`load_staged_image_into` has made the child current, so it reads the child's own empty cspace
and never fires (`kspawn.c`, `do_spawn_inner`).

**The I-7 untyped-memory checks.** Twenty-two checks cover `CAP_UNTYPED` and `SYS_RETYPE`,
and unlike the C-1 set they deliberately run in **both directions**. `captest` is endowed with
a real `CAP_UNTYPED` (`captest_selftest`), so the suite asserts that a held capability actually
creates usable, mutually distinct endpoints — a refusal-only suite would be passed by a kernel
whose `SYS_RETYPE` returned `SYS_ERR_PERM` unconditionally. It then asserts every malformed
request is refused, that no refused call spends any of the region (a refusal that consumes what
it refused is a denial-of-service primitive against the caller's own budget), and that revoking
the last capability to a retyped endpoint **destroys the object** while leaving its sibling
intact.

Four gates were falsified against the patched kernel, each in isolation:

| Removed | Check that fired |
|---|---|
| the reserved-slot floor | `retype-into-reserved-slot-allowed` |
| the cspace range checks | `retype-past-cspace-end-allowed` |
| the capability-type check **and** the kernel-reserve guard | `retype-allowed-through-notification-cap-onto-kernel-reserve` |
| `kobj_gc` from `cap_revoke` | `revoked-endpoint-object-not-destroyed` |

**The blocking-receive checks (roadmap 1.3), and a lesson about how a test FAILS.**
`SYS_IPC_RECV_BLOCK` is a second way to receive, so it is a second place the C-1 gate has to
hold — and it is the one a *server* uses, which is where interception matters. Five checks in
`smoke-captest` cover it, plus the dedicated `smoke-recvblock`.

Four gates were falsified, each in isolation:

| Removed / changed | Check that fired |
|---|---|
| the block itself (return `IPC_AGAIN` on an empty queue) | `recv-block-returned-IPC_AGAIN` |
| `cap_install_reply_for` on the wake path | `woken-server-holds-no-reply-right` |
| the server made a *polling* receiver instead | `server-polled-instead-of-sleeping` |
| the `CAP_RIGHT_READ` requirement | `recv-block-allowed-with-write-only-client-cap` |

The third is the one worth keeping: it falsifies the **instrument**, not the kernel. The
"exactly one receive syscall per message" assertion is the only thing separating a receiver
that sleeps from one that spins, so it has to be shown to catch a spinner — and it does.

The fourth taught something that is not about capabilities at all. The first version of that
check probed an **empty** endpoint, so with the right requirement removed the receive was
allowed, found nothing, and **blocked forever**: captest is a single task, so the suite
reported a 60-second timeout rather than the name of the property that broke. A hang is
indistinguishable from a real hang, which is precisely the confusion **[G-8]** and the
interrupt-policy episodes cost days to unpick. The check now queues a message first (using the
WRITE right it legitimately holds), so a kernel that wrongly allows the receive returns a
*length*, and the suite fails by name with the diagnosis in the log. **Design the failure, not
just the assertion:** a security test that wedges on the bug it detects has told you almost
nothing.

#### The lost wakeup none of those gates caught

Every gate above passed, on a build that **hung roughly a third of `-smp 4` sessions under host
load**. Worth recording in full, because the reason they passed is structural.

`SYS_IPC_RECV_BLOCK` is completed by the *sender's* syscall, so the one-shot `CAP_REPLY` must
be minted into a cspace that is not the current one. The first version did that after marking
the waiter `TASK_RUNNABLE` and after dropping `ipc_lock`, to keep `cap_lock` from nesting under
the endpoint lock. But a task is schedulable the instant its state flips: another CPU picks it
up, it returns to ring 3, services the request and calls `SYS_IPC_REPLY_TO` — all before the
mint lands. `cap_lookup` finds no `CAP_REPLY` and returns `SYS_ERR_PERM`, which is **permanent**,
so the server correctly drops the reply (the retry contract forbids looping on it) and the
client waits forever.

**Why every gate missed it.** `smoke-recvblock` and `smoke-captest` run on one CPU, where there
is no second CPU to run the server inside the window, so the ordering cannot be observed to be
wrong. The full 17-target sweep passed. CI passed 61 of 63 checks. Only a *session under load*
showed it.

**How it was caught, and the general lesson.** By running the thing the change was supposed to
improve, against a control, on a **loaded** host — not by running the gates. Interleaved,
`-smp 4`, pinned: 5 failures in ~15 boots for the new build against 0 for the control. That
asymmetry is the signal; a one-armed run would have looked like the ambient **G-8** rate.

**How the mechanism was established, rather than guessed.** The first hypothesis (an ordering
hole in `h_ipc_call`) was wrong — reading the code showed that ordering was already correct and
documented. The second was confirmed by *instrumenting the silent path*: `console_server` drops
a permanently-refused reply without printing, so a temporary `ser_puts` was added to that branch
and the failure reproduced with the marker present in **4 of 5** failing boots. A stall with no
message is a hypothesis; a stall with `REPLY-PERM-DROP` in the log is a mechanism.

**The reproduction, for anyone who touches this path.** The race needs a second CPU to run the
woken server *and* needs that CPU descheduled inside the window, so an idle host will not show
it:

```sh
for i in 1 2 3; do taskset -c 6 sh -c 'while :; do :; done' & done   # hogs
QEMU_SMP=4 SESSION_TIMEOUT=120 taskset -c 6 python3 tools/session_test.py boot.iso
```

Four guest vCPUs squeezed onto one host core, against three hogs. That is the same discipline
`smoke-console-smp` needed — *an unpinned green run is not evidence* — applied to a race whose
window is opened by vCPU descheduling rather than by core count.

**The fix** mints the reply right under `ipc_lock`, before the wake, and both completion paths
now follow one rule without exception: *a receiver holds its reply right before it is
schedulable.* `cap_lock` nesting inside the endpoint lock is a new lock order and is safe
because it is the only one — no path in the tree takes an IPC lock while holding `cap_lock`.

Measured with the recipe above, interleaved, 25 boots per arm:

| Build | Failures |
|---|---|
| pre-fix | **8/25** |
| with the ordering fix | **0/25** |

All four falsifications were re-run against the fixed code, because the mint moved and a gate
that was only ever shown to fire at the old call site proves nothing about the new one.

The third row is the instructive one. Removing the type check *alone* was **not** detected:
the probes used a `CAP_FRAME` and a `CAP_ENDPOINT`, whose `object` fields fall far outside the
untyped index space, so the range check caught them and the type gate was never the thing
under test. The probe was rewritten to use a `CAP_NOTIFICATION` whose `object` is `0` — a
*valid* untyped index, and specifically the kernel's own cspace reserve — which passes range
and lands on the two gates that actually matter. Defence in depth is why the first attempt
survived; it is also why a falsification that "passes" must be read as a broken test, not as
a strong kernel.

**The one-shot reply-capability checks (roadmap 1.3).** Four checks assert that `CAP_REPLY`
behaves as a consumable right rather than a standing permission: issuing a reply to a client
that is not blocked still *spends* the right; a second reply to the same request is refused
with exactly `SYS_ERR_PERM`; and the spent right is not revived by holding a capability on a
different endpoint.

Falsified in two directions. Removing the consume on the dropped-reply path fails
`reply-twice-to-one-request-allowed`; reverting the reply routing to the old mutable
`last_sender` fails it too.

**One of these checks was renamed because falsification showed it did not test what its name
claimed.** It was written as `reply-without-having-received-allowed`, asserting that endpoint
authority does not imply reply authority. It does not: `CAPSLOT_REPLY` is per-**task**, not
per-endpoint, so the endpoint argument only selects the READ check and never selects which
reply right is used. Before the earlier replies consumed the right, that same call would have
succeeded. It is now `consumed-reply-right-revived-by-other-endpoint`, which is the property it
actually witnesses. A green check whose name overstates it is a worse artifact than no check —
it is a claim nobody will re-derive.

### `smoke-console-smp`: was flaky, was a real kernel bug, now fixed

**Resolved 2026-07-28.** For a long time this test failed roughly a third of the time and was
treated as flaky. It was not flaky. It was correctly reporting an intermittent **kernel
deadlock**, and every "just retry it" was a real defect going unlogged.

The symptom: boot reaches `[console_server] ready`, the shell banner never arrives, and the
`HHoorruuss` doubled-banner `FAIL_MARKER` does *not* trip — so it was visibly not the
single-writer regression the test was written to catch, and nobody looked further.

What it actually was: `preempt_on_tick` claimed an incoming task unconditionally but released
the outgoing one only on a ring-3 tick, so a ring-0 tick leaked a claim in
`task_running_cpu[]`. Every selection loop skips a claimed task, so the victim stayed
`RUNNABLE`, kept a valid resumable context, and became unschedulable **by every CPU including
the one holding the claim**. Fixed by never switching a CPU away from a live ring-0 context.

| Build | Runs | Failures |
|---|---|---|
| before the fix | 12 | **6** |
| after the fix | 24 | **0** |
| after the fix (independent re-run) | 24 | **0** |
| after the fix (clean build, 30 boots) | 30 | **0** |

The reason it read as flaky rather than as a bug is worth keeping: under TCG each guest vCPU
is a host thread, so on an idle many-core workstation the race window never opens and the
failing kernel scores 10/10 green. It only fails where vCPUs outnumber host cores — which is
what CI runners are. **The environment that made it look like noise was the developer
workstation.**

Two lessons this cost:

- **"Flaky" is a hypothesis, not a diagnosis.** This one hid a deadlock for months of CI runs.
  Before labelling a test flaky, get a *rate*, then explain the failure.
- **A single green run proves nothing about a scheduling change.** Ask for a rate; see the
  stress harness below.

### Measuring an intermittent failure: `make smoke-console-smp-stress`

```sh
make smoke-console-smp-stress                        # 20 boots, must be 20/20
STRESS_RUNS=40 make smoke-console-smp-stress         # tighter bound
STRESS_MAX_FAIL=2 make smoke-console-smp-stress      # characterise, don't gate
```

Builds once, then boots that ISO N times with QEMU pinned to a small host CPU set, and
reports a **rate**. Two design points, both learned the hard way:

**It builds once.** Every `make smoke-*` target starts with `clean` and a full rebuild, so
looping one spends nearly all its wall time in the compiler rather than in the kernel under
test.

**It pins the CPUs, and this is not a detail.** Under TCG each guest vCPU is a host thread.
On an idle workstation a 4-vCPU guest gets a core each, the scheduling windows never open, and
the failing build above scores **10/10 green**. Pinned to 2 host cores — what a CI runner
actually has — the same build hangs repeatedly. An unpinned stress run reporting 20/20 on a
kernel that fails a third of the time in CI is worse than no measurement, because it converts
absence of evidence into a claim. `STRESS_CPUSET=` disables pinning and the script says so
loudly when it does.

The corollary for reviewers: **a scheduling or IPC change is not evidenced by one green CI
run.** Ask for a rate.

### `make smoke-sched-invariants` — and the finding that turned out to be the checker

`SCHED_INVARIANTS=1` machine-checks the scheduler's claim invariant

```
task_running_cpu[t] == c  <=>  percpu_current_task[c] == t     (t > 0)
```

at every timer tick, panicking with the offending task, CPU and observer instead of
livelocking silently thousands of ticks later. Off in the ship kernel; **gated in CI** via
`make smoke-sched-invariants-stress` (30 pinned boots, reported as a rate).

**Resolved 2026-08-09.** This target used to be documented as expected to fail, reporting in
roughly one boot in five — 10 in 20 once the boots were pinned:

```
stale scheduler claim at preempt_on_tick: task 1 claimed by cpu N
but that cpu was running 4 (persisted across two audits)
```

It was read as `init`, blocked in `sys_wait()` on the shell, staying claimed by a CPU that had
moved on. **That reading was wrong, and the giveaway was in the serial log all along:** the
panic lands immediately after `init: console_server launched` and before the shell ever
starts. Task 1 is `init` and task 4 is the shell it is in the middle of **spawning**.

`do_spawn` → `load_staged_image_into` installs the *child* as the CPU's current task for the
whole ELF load, so the loader's `copy_to_user` resolves through the child's address space
(`kspawn.c` depends on this for capability propagation too). For that window
`percpu_current_task[]` deliberately does not describe the task the CPU is running — while
`init` remains correctly and legitimately claimed by it. The claim was live, not stale. The
auditor was reading a declared-in-code-comments-but-undeclared-to-the-checker impersonation
as a leak.

The two IPC sites that do the same trick (`sys_ipc_send`, `h_ipc_reply_to`) *had* been
declared, via a `percpu_in_user_copy` flag added when the checker false-positived on them.
The spawn window had not — and it is orders of magnitude longer: a ~450 KiB copy plus
page-table construction and relocation processing, which under TCG spans many ticks, so it
comfortably survives the two audits the checker requires.

The fix does not switch the checker off for those windows. `sched_impersonate_enter/exit`
record the task the CPU is *really* running (`percpu_real_task[]`) and the audit is stated
over that, so coverage stays continuous across the longest operation in the system — which is
exactly where a real leak would otherwise be easiest to hide. The bracket is a nesting depth,
not a flag, and is itself checked: a CPU reaching **ring 3** at non-zero depth means an
`enter()` lost its `exit()`, and panics. An exemption mechanism with no balance check is a
hole in the shape of the thing being checked.

| Build | Runs (pinned, 2 host cores) | Failures | What that establishes |
|---|---|---|---|
| before | 20 | **10** | ~50%: the impersonation false positive, unambiguously |
| after | 30 | **0** | the false positive is gone — **and nothing about a rare event** |

**That second row was read as more than it says, and this is the correction.** Thirty boots has
about a **26% chance** of observing a defect that occurs on 1% of boots, so a clean 30/30 was
never evidence of absence at that rate. It established what it was built to establish — that the
~50% impersonation false positive had stopped — and nothing beyond it.

### 2026-08-21: the claim invariant fired again, and it is not the old false positive

On the CI run for `615b384`, one boot in 30 panicked:

```
PANIC: stale scheduler claim at preempt_on_tick: task 4 claimed by cpu 1
       but that cpu was running 0 (persisted across two audits; observed by cpu 3)
```

**This is the inverse of the 2026-08-09 shape and cannot have the same explanation.** That one
read `task 1 claimed by cpu N but that cpu was running 4` — `init` claimed while the CPU
legitimately impersonated the child it was spawning. Here it is **task 4** that is claimed, by a
CPU running **0** — nothing. An idle CPU is not impersonating anyone, so `percpu_real_task[]`
has nothing to say about it. The claim is genuinely stale: this is a leak, and it is
**[G-9]**'s shape exactly — a claim left behind by a CPU that then went idle.

Measured either side of the commit it appeared on, pinned, same host:

| Tree | Boots | Failures | Rate |
|---|---|---|---|
| `615b384` (with `libhorus`) | 120 | 1 | 0.83% |
| `2d27ec7` (before `libhorus`) | 270 | 0 | 0% |

**The difference is not significant** (Fisher exact, p ≈ 0.31), and it cannot currently be
resolved: one event does not carry a confidence interval worth quoting. `libhorus` is a ring-3
library and cannot create kernel scheduler state, but it did resize four server binaries, which
moves timing — so "pre-existing and under-sampled" and "the same defect, made marginally easier
to hit" both fit the data. Recorded rather than concluded.

**A red here is a [G-9] reproduction, not a flake.** `smoke-sched-invariants` stays **required**
deliberately. It is not `smoke-kstack-park` as that gate stood until 2026-08-22, when it was advisory because
it reddened for a defect it does *not* test; this gate tests the claim invariant and what it
caught *was* a claim leak.
The gate is working. Before re-running it, **save `stress-first-failure.log`** — every boot that
reproduces this is a datapoint, and collecting them is how **[G-8]** was closed. Re-running
first and looking second is the reflex that costs the evidence.

Falsified in both directions rather than merely observed to pass:

- **Delete the claim release** in `preempt_on_tick`'s save-and-switch block (re-introducing a
  genuine leak): panics in 3 boots of 3. The checker is still alive.
- **Delete `sched_impersonate_exit()`** from `do_spawn`: fails in 3 boots of 3, once via the
  new bracket-balance panic. The bracket cannot rot silently.

Two things this cost that are worth keeping:

- **A checker that reports a violation is making a claim about the code, and it can be the one
  that is wrong.** This finding sat open for a fortnight as a suspected scheduler defect, and
  the roadmap blocked item 1.1 behind root-causing it. The invariant was true the whole time;
  the model of "what this CPU is running" was incomplete.
- **Read the log around the panic, not just the panic.** `init: console_server launched` two
  lines above it dated the event to the spawn of task 4 and ruled out `sys_wait()` immediately.
  The original diagnosis was reached from the message alone.

*(The concurrent-panic garbling that showed up during the falsification runs —
`PANICPANIC: : unbalanced impersostale scheduler claim...`, two cores tripping on the same
tick — is fixed with a first-CPU-wins latch. Same failure as the `PA[NIC: console_server]`
episode below, one level up.)*

**Three things this checker cost to get right, all worth knowing before extending it:**

1. **It must not panic on first sight.** Not every writer of `task_running_cpu[]` holds the
   scheduler lock, so an auditor on another core legitimately catches mid-flight updates. The
   check requires a violation to survive two audits. A first-sight version reported failures
   on a correct kernel.
2. **It must not print through `print()`.** Once a ring-3 console server owns the console the
   kernel's `print()` is suppressed, and during handover both writers touch COM1 from
   different cores — the panic arrived as `PA[NIC: console_server] ready`, i.e. the one
   message that had to survive was the one that did not, and the halt then looked like an
   ordinary timeout. It writes bytes to the UART directly.
3. **Dead tasks are exempt.** `task_teardown` releases the claim but the CPU keeps naming the
   task until `task_exit_switch` runs, and in between it does a full capability-graph sweep —
   long enough to span several audits. Exempting them costs nothing, since selection requires
   `state == 1`.

**And one thing the checker's own development established, by measurement:** "defensively"
clearing a stale claim makes things *worse*, not better. Two such repairs — sweeping claims
in `enter_cpu_idle`, and marking a CPU idle early in `task_exit_switch` — took the stress
harness from **24/24 to 13/20**, because a stale claim marks a task whose kernel context was
abandoned, and freeing it resumes that task from a stale frame. Both are now recorded as
explicit "do not do this" comments at the sites that invited them.

### Open finding G-9: a scheduler claim leaks on the spawn/reap path under SMP

**Status: open.** Found 2026-08-17 by `smoke-kstack-park`, and pre-existing — `PROC_SELFTEST` at `-smp 4` violated the claim invariant on about 40% of boots, a workload nothing had run at more than one CPU before. Two components were fixed the same week, taking it to roughly 1–2% of boots; the remainder is open.

**The full investigation is in [`docs/investigations/G-09-scheduler-claim-leak.md`](docs/investigations/G-09-scheduler-claim-leak.md).**


### Closed finding G-10: the spawn/exec path is process-wide singleton state, unserialised

**Status: closed 2026-08-18.** Found while narrowing [G-9]. Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needed in flight was a file-scope singleton with nothing serialising two CPUs through it. The page-table half was a use-after-free giving a cross-address-space read/write primitive reachable from ring 3.

**The full investigation is in [`docs/investigations/G-10-spawn-path-uaf.md`](docs/investigations/G-10-spawn-path-uaf.md).**


### Closed finding G-11: the armed program image was ambient state

**Status: closed 2026-08-18.** Nothing recorded which task armed a staged image, and the arm is a different syscall from the consume — so `SYS_SUDO`, which spawns whatever is armed **as uid 0**, would elevate another task's program to root.

**The full investigation is in [`docs/investigations/G-11-armed-image-ownership.md`](docs/investigations/G-11-armed-image-ownership.md).**


### Finding G-8: two CPUs on one kernel stack — CLOSED 2026-08-17

**Status: closed 2026-08-17.** A switch path handed the outgoing task to another CPU before this CPU had left that task's kernel stack. Measured over 1600 alternating boots: the pre-fix release site fails 31/800, the shipped one 0/800. The record of how it was read wrongly for eight days is kept deliberately.

**The full investigation is in [`docs/investigations/G-08-two-cpus-one-kernel-stack.md`](docs/investigations/G-08-two-cpus-one-kernel-stack.md).**

### `make smoke-irq-policy` — the interrupt policy, written down and gated

**Roadmap 1.1, steps 2 and 3.** Boot-time interrupt enablement used to be an *emergent*
property of a locking defect rather than a stated design: `spin_unlock`'s unconditional `sti`
turned interrupts on as a side effect of the first lock any syscall took (**[C-3.1]**). Since
2026-08-11 the policy is stated — [`ARCHITECTURE.md` §6](docs/ARCHITECTURE.md) — and this gate
is what holds the code to it. It records IF at named milestones and asserts each one.

| Milestone | IF | Why |
|---|---|---|
| `post-idt` | 0 | boot runs masked throughout |
| `post-paging` | 0 | |
| `post-protections` | 0 | |
| `kernel-ready` | 0 | |
| `first-syscall-entry` | 0 | `int 0x80` is an interrupt gate |
| `outermost-lock-release` | **0**, or **1** under `IRQ_LEGACY_GLOBAL_LOCK=1` | a critical section RESTORES the caller's IF, never imposes one |

The last row is the one that carries roadmap 1.1 step 3, and it is deliberately stated per
build so the control arm is gated too rather than merely tolerated. It records IF immediately
after the first outermost `spin_unlock` of the boot — the single observation that distinguishes
the two locks, since at that point in boot the caller always had IF clear. An unconditional
`sti` therefore cannot come back silently.

The first five were **measured, then written down** — they are what the kernel already did, so
the gate's job is to notice a change. Encoding a policy nobody has implemented would make the
test fail on a correct kernel, the failure mode this document keeps warning about.

All zero is the whole point: every syscall starts masked, so under the old lock the first lock
a handler released turned interrupts on for the rest of that syscall. That is why **[C-3.1]**
was load-bearing, and why it was measurable.

> **The totals this section used to quote — "99 accidental against 67 benign across a
> session" — were withdrawn on 2026-08-10.** The audit reports through `panic_str`, straight
> at the UART, bypassing the runtime suppression of `print()` that exists because ring-3
> `console_server` owns the serial line. The tick-41 report lands on the login prompt and
> splits it — `root@horus\n[irq-policy] handshake-early @tick=41: ...` — so `root@horus#`
> never appears contiguously and `tools/session_test.py` waits for a prompt that was cut in
> half. Measured **interleaved** — adjacent boots, alternating builds, so host drift cannot
> account for it — with the unmodified audit build kept in as a positive control:
>
> | Build | `session_test.py` failures |
> |---|---|
> | ship kernel (no audit) | **0 of 8** |
> | audit, `IRQ_POLICY_QUIET=1` | **0 of 8** |
> | audit, exactly as shipped | **8 of 8** |
>
> `IRQ_POLICY_QUIET=1` removes the reporting and nothing else — `spin_lock` and `spin_unlock`
> disassemble to **82 identical instruction lines** under both settings, against the same five
> counter symbols. Without that check, "quiet passes" would be equally consistent with quiet
> mode having simply switched the instrument off. The harness then stops issuing commands, the
> guest correctly runs nothing more, and
> the counters stop at **99/67** — the boot window of a session that never executed a command.
> A session the harness *can* drive reads **420/224 at tick 201**. The seven sites reproduce;
> the totals did not. See `docs/ROADMAP.md` §1.1.
>
> Two things this is *not*. It is not a kernel hang — the guest is healthy throughout, and
> frozen counters beside a live timer is what an idle kernel looks like, not a stalled one. And
> it is not **G-8**: an early draft of this correction guessed at both, from the same evidence,
> and was wrong on both. **This gate is unaffected** — it exits on its marker at tick 40 and
> never reaches a prompt, and the ship kernel it protects carries no audit at all.

Falsified in both directions, because a gate that cannot fail is not evidence:

| Break | Result |
|---|---|
| flip one expectation | `FAIL post-paging IF=0 expected 1` |
| delete a milestone hook | `FAIL milestone-never-reached post-protections` |

The second matters more than the first. A milestone that silently stops firing would otherwise
pass on four checks instead of five, and the gate would report success while measuring less
than it claims — the same defect as a refusal test that never reaches its probe.

Step 3 landed 2026-08-11 and added the sixth row. Falsified by crossing the two builds'
expectations — building the per-CPU lock while expecting the legacy value gives
`FAIL outermost-lock-release IF=0 expected 1`, so the milestone genuinely discriminates
between the two locks rather than recording a constant.

### `make measure-irq-policy` — the audit read out in band, not printed at the UART

**Roadmap 1.1 step 2b.** Not a gate: it produces a number, and a number is not a pass/fail. It
is a target so the measurement is *reproducible*, and so nobody re-derives it by making the
kernel print at the UART again — which is what corrupted every earlier figure.

`SYS_IRQ_POLICY_INFO` hands the counters to userspace on request and the shell's `irqpolicy`
builtin prints them through `console_server`, so the kernel is never a second writer. Because
the readout is on demand it can be taken **after** a workload rather than at a fixed tick,
which is the difference between a session-scale total and a boot-scale one. Fourteen commands,
each a `console_server` round trip:

```
irq-policy: accidental_sti=1439 suppressed_sti=0 benign_sti=720 sites=7 @tick=693
```

with `cap_install_object` (685) and `cap_consume_slot` (684) accounting for **95%** — both on
the IPC path, both scaling with message traffic, while the other five sites are fixed
boot-time costs.

**The equivalence check (roadmap 1.1 step 3).** Both locks count the *same* predicate — an
outermost release whose caller had IF clear. The legacy lock fires an `sti` for it and reports
`accidental`; the per-CPU lock suppresses it and reports `suppressed`. Run the same workload
against both builds:

| Build | accidental | suppressed | benign | total releases |
|---|---|---|---|---|
| `IRQ_LEGACY_GLOBAL_LOCK=1` | 1439 | 0 | 720 | **2159** |
| default | 0 | 2159 | 0 | **2159** |

**Equal totals is the evidence, not the zero.** A `suppressed` count of 0 would be equally
consistent with the fix working and with the instrument having been switched off; identical
release populations show the same events are still being observed, with 1439 of them no longer
enabling interrupts against the caller's intent.

The `benign` column going to zero is not a discrepancy, it is a consequence worth reading: a
release was only ever "benign" because an *earlier* accidental `sti` in the same syscall had
already turned interrupts on. Remove the first and every caller is correctly observed to have
had IF clear. The same effect saturates the per-site table (`sites=12`, the `IRQ_SITE_SLOTS`
ceiling): the legacy lock hid every lock site after the first in each syscall, so seven sites
were visible where there are at least twelve.

Gated like `SYS_DMESG` (`CAP_KERNEL_LOG`, READ), and absent from the dispatch table outside
`IRQ_POLICY_AUDIT` builds so the ship kernel answers `SYS_ERR_NOSYS`. `captest` 88 → 89.
**Falsified in both directions:**

| Break | Check that fired |
|---|---|
| capability gate removed (`SC_NONE`) | `irq-policy-info-allowed-without-kernel-log-cap` |
| kernel built with the audit, userspace without | `irq-policy-info-present-in-ship-kernel` |

The second was not a contrived break — it is how the check first failed. Userspace is compiled
with its own flags, so `#ifdef IRQ_POLICY_AUDIT` in `captest.c` was never true and the test
disagreed with the kernel it was testing about which kernel it was in. It failed loudly rather
than passing against the wrong expectation, which is the only reason it was noticed;
`USERSPACE_CFLAGS` now propagates the flag. **A test asserting an exact errno catches this. A
`< 0` assertion would have passed in both configurations** — the same lesson as the C-1 set.

*One honest gap.* The tool also asserts prompt integrity — that the expected prompt appeared
contiguously as many times as commands were sent — as a safety net against measuring a
corrupted session. That guard's failure path works (it fired during development on an
off-by-one), but **it has not been shown to fire on a genuine split prompt.** The corruption is
not a general race: it is deterministic for a particular prompt timing, and this tool's prompts
all land after the async reports finish at tick 201. `session_test.py` remains the instrument
that detects a split reliably (8/8 and 10/10 against the loud build). The guard is a net, not
evidence.

### `init`'s exit report never reached the wire

**The reason G-8 has been undiagnosable.** `init`'s `report()` was `sys_write(1, ...)`, which
lands in the kernel's `print()`, and `print()` stops driving the hardware the moment
`console_server` takes ownership (`terminal.c`: `drive_hw = (console_owner_task == 0)`). So
every init message after the handover went to the klog and **nothing reached serial** —
including `report_shell_exit()`, which is the entire point of #130. That PR's own comment says
init prints "through console_server like any other program"; the code used the kernel path.

The symptom, seen repeatedly before it was understood: a boot where the shell restarted showed
**two startup banners and no exit report at all**. That looks identical to a shell restarting
for no reason, which is exactly the ambiguity G-8 has cost days to.

Measured with the *same* heartbeat probe on both builds, ownership confirmed as `owned=1`, the
console routing as the only variable:

| `init`'s `report()` | Heartbeats on serial after the handover |
|---|---|
| `sys_write` (before) | **0** |
| via `console_server` (after) | **2** |

The handover itself is visibly two writers on one UART — a line truncated mid-word,
`init: st[console_server] ready`.

**Three wrong turns getting here, all worth recording**, because each looked conclusive:

1. Concluding init was muted from *absence* of init output in 100 captured boots — init simply
   has nothing to say while blocked in `sys_wait`. Absence of evidence.
2. "Disproving" that with a probe that printed fine — it fired *before* ownership was actually
   registered. `[console_server] ready` is the server's own native write and does not mark the
   handover.
3. "Re-proving" it with a heartbeat that produced zero lines — the probe never ran, because
   `settle()` is 40 000 iterations and calling it 1 500 times per beat is ~10 s under TCG.

Only the fourth attempt — identical probe, identical ownership state, routing as the sole
difference — measured anything. **A probe that produces no output has two explanations, and
"the thing I am testing is broken" is the less likely one.**

### Two diagnostics for a corrupted resume `%rsp`

Every return from `interrupt_handler64` is a kernel `%rsp` that `isr_common_stub64` loads and
immediately pops fifteen registers from. A bogus value there does not fail where the mistake
was made — it faults *inside the ISR epilogue*, at an address near zero, and the banner names
the stub. That is almost the least informative place a kernel can fault.

It cost a full reproduce-and-symbolise cycle to learn that `PAGE FAULT at 0x94` meant "the
dispatcher returned 4": `0x94` is `rsp + 0x90`, the `out->cs` read in `interrupt_handler64`
itself. Two changes make the kernel say so directly:

- **A guard at the dispatcher choke point.** Kernel stacks are higher-half, so any returned
  value below that floor is a `0`/`1`/`-1` or something wild, never a frame. It panics with
  the value, the task, its state and its `pending_block`.
- **The faulting RIP and RSP in the ring-0 `#PF` banner.** A ring-0 fault previously reported
  only *that* the kernel dereferenced something bad, never *where* — and the where is the whole
  diagnosis. Symbolise with `addr2line -e kernel.elf <rip>`.

**Falsified**, because a guard never seen to fire is an assumption rather than a control:
injecting `rsp = 4` on a ring-3 return produces
`PANIC: dispatcher returned a bogus resume rsp=` instead of the old `PAGE FAULT at 0x94`.

*A third instrument was written and deliberately NOT kept.* It recorded which dispatcher path
had returned, in a global — which under SMP another core can overwrite between the panicking
core's return and its print, so its attribution is unreliable exactly where it would be used.
It named a path the disassembly then contradicted. Per-CPU it would be sound; global it is
worse than nothing, because it looks authoritative. Left out rather than shipped with a
caveat nobody would read at 3am.

## Memory protection and isolation

| Target | Proves |
|---|---|
| `smoke-wx` | The kernel image is r-x / r-- / rw-, and a sweep of **every leaf PTE** finds no writable-and-executable page. |
| `smoke-wx-smp` | The same under SMP, and that every AP's IST fault stack sits above an unmapped guard page. |
| `smoke-cpu` | SMEP and SMAP are detected **and actually set in CR4** — not merely attempted. Boots under `-cpu +smep,+smap`. |
| `smoke-percpu` | `this_cpu()`'s TSS-selector derivation agrees with the LAPIC **on every core that came online**, checked on each core as its TSS is loaded, and `EFER.SCE` is clear so the staged SYSCALL path stays unreachable. Needs ≥2 cores: on one CPU the mapping is right by accident, so a UP run fails rather than passing vacuously. |
| `smoke-aspace` | Rebuilding a task slot repeatedly returns every physical page to the pool — a dead task's address space leaks nothing. |
| `smoke-cow` | Copy-on-write breaks correctly for the shared zero page. |
| `smoke-heap64` | The heap syscalls **and the pager's region gate** are 64-bit clean (**[I-2]**, roadmap 1.5). Builds `USER_HEAP_HIGH_BASE=1`, which places every heap at **8 GiB** — above the 4 GiB line, below `USER_IMAGE_ASLR_BASE` — so the truncation is *reachable* instead of latent, then runs `captest`, which calls `sbrk`/`brk` directly and writes to the page it is handed. **Control arm:** built from a tree without the fix, the same target reports `CAPTEST: FAIL (sbrk-grow-failed)`. Verified in both directions before the target existed. |
| `smoke-nzcow` | The generic (non-zero) COW break is correct — added after a real bug in that path. |
| `smoke-stackguard` | The stack canary is re-seeded from the CSPRNG at boot and is no longer the compile-time default. |
| `smoke-aslr` | Image, heap, and stack bases are randomised. |
| `smoke-e820` | The physical pool is sized from the multiboot2 memory map, not a hardcoded fallback. |

## Boot integrity and measured boot

These are the most adversarial tests in the suite.

| Target | Proves |
|---|---|
| `smoke-modules` | Boot modules are provisioned into `/bin` and run from the filesystem. |
| `smoke-modules-tamper` | **Corrupts a module payload inside the ISO** and asserts the kernel refuses it — the manifest gate fires. |
| `smoke-tpm` | Kernel and modules are measured into PCR 8 and 9, and the values equal an independent host recomputation (`tools/tpm_expected_pcr.py`). |
| `smoke-tpm-tamper` | A corrupted module is refused **and** the measured PCRs diverge — detection as well as prevention. |
| `smoke-tpm-seal-roundtrip` | A secret sealed under `PolicyPCR(8,9)` unseals on a good boot and is **denied after a PCR change**. |
| `smoke-tpm-seal` | The real vdisk KEK: a measured-good boot unlocks the volume; a changed PCR leaves it locked. |

Requires `swtpm` and `swtpm-tools`. Driven through `tools/run_with_swtpm.sh`.

## Scheduling, SMP, and side channels

| Target | Proves |
|---|---|
| `smoke-preempt` | The timer genuinely time-slices two ring-3 tasks. |
| `smoke-signal` | A ring-3 fault is delivered to a registered handler. |
| `smoke-smp` | APs come online from the MADT, run scheduled tasks on distinct CPUs, and TLB shootdown completes. |
| `smoke-smt` | SMT sibling threads are parked, closing same-core co-residency. |
| `smoke-flush` | Flush-on-switch detection matches CPUID, the gated barriers execute without faulting, and the **policy** flushes only on a genuine task change. (Barriers are no-ops under TCG; they engage on hardware or KVM.) |
| `smoke-tsd` | A ring-3 `RDTSC` faults under `CR4.TSD`. |
| `smoke-proc` | Process control: spawn, wait, kill, signals (incl. mask/unmask and altstack delivery), and the `CAP_TCB` authority behind them. |
| `smoke-notify` | Async notifications wake a blocked waiter with the accumulated badge. |
| `smoke-recvblock` | A ring-3 server waiting with `SYS_IPC_RECV_BLOCK` makes **exactly one receive syscall per message** while the client dawdles before each send — the witness that it slept rather than polled — and the wake leaves it holding the one-shot reply right. Roadmap 1.3. |
| `smoke-recvblock-smp` | The same, under `-smp 4`, so the CROSS-CPU wake path runs at all. It does not reliably catch the ordering race that path is prone to — see "The lost wakeup none of those gates caught" — but it is one boot. |

Both run in CI as of this change. They are **not** required status checks — like every other
gate added after the ruleset was written, they land in the advisory set (finding **[C-6]**),
so a red `smoke-recvblock` does not block a merge. Read it anyway.

## ELF loading

| Target | Proves |
|---|---|
| `smoke-elf` | `try_elf_load` enforces W^X on loaded segments. |
| `smoke-elf64` | x86-64 RELA relocations are applied correctly. |
| `cargo fuzz` (`rust/fuzz/`) | The pointer and scalar predicates at the FFI boundary do not panic or misbehave on adversarial input. |

The ELF loader migration to Rust found two real out-of-bounds bugs in the C original.

## Filesystem

| Target | Proves |
|---|---|
| `smoke-fs` | Basic file operations over the encrypted object store. |
| `smoke-init-fs` | `init` provisions the filesystem at boot. |
| `smoke-fs-perms` | POSIX rwx is enforced against the **kernel-attested** uid/gid, not a client-supplied one. |
| `smoke-fs-persist` | Data survives a reboot (two-boot test). |
| `smoke-fs-wal` | The write-ahead journal recovers a crash-interrupted write (two-boot test). Proves the **redo logic**; says nothing about durability, which is what the two gates below are for. Boot 1 ends via a QMP quit and a confirmed process exit, not a signal (**[I-11]**, fixed 2026-08-16 — see below). |
| `smoke-fs-wal-flush` | Every `FLUSH CACHE` fails with `EIO` (`blkdebug`), and the journal must **refuse to commit** and say so. Proves the barrier is both *issued* and *checked*. Falsified by `WAL_NO_FLUSH=1`: `make smoke-fs-wal-flush-control`. |
| `smoke-fs-wal-order` | An IDE command-register trace must end `0x30 → 0xe7 → 0x30 → 0xe7` — data write, barrier A, commit header, barrier B. Proves the barriers are in the right *place*, not merely present. Falsified by `WAL_NO_FLUSH=1`: `make smoke-fs-wal-order-control`. |
| `smoke-fs-conc` | Multiple clients are served concurrently without cross-talk, via `SYS_IPC_REPLY_TO`. Uses `CONC_TIMEOUT` (default 120s), not the 40s default: it waits on several clients, and on a loaded host it exceeded the shorter budget and failed as a *timeout* — never reaching a verdict, which reads red without being evidence of a defect. A real `CONC_SELFTEST: FAIL` still fails immediately. |
| `smoke-fs-large` | Double-indirect blocks address large files. |

> **`smoke-fs-wal` — both defects fixed on 2026-08-16 ([I-10] durability, [I-11] harness).**
>
> **[I-10] is fixed as of 2026-08-16, but not by the method originally planned.** The obvious
> fix — re-run the two-boot test under `cache=writeback` — does **not work**, and the reason
> generalises to any test of this shape. Under `writeback` QEMU writes guest blocks into the
> *host page cache* with `write()`; killing the QEMU process does not lose them, because the
> host kernel still holds the pages and any later read of the image sees them. Only a host
> power failure would lose them. So a kernel that never issues `FLUSH CACHE` and one that
> flushes correctly produce **identical** results, and switching the cache mode would have
> built a second vacuous gate beside the one it was meant to repair.
>
> There is no QEMU cache mode in which a two-boot outcome depends on whether the guest
> flushed. The property has to be observed some other way, so the two gates above do:
>
> - **`smoke-fs-wal-flush`** inverts the question. `blkdebug` returns `EIO` for every
>   `flush_to_disk`, so the *presence* of the command becomes visible through the kernel's
>   reaction to its failure. A kernel with barriers prints
>   `WAL: FLUSH FAILED before commit header - transaction aborted` and commits nothing.
>   It runs under **`cache=writeback`, and must**: under `writethrough` QEMU may satisfy each
>   guest write with a write *plus a flush*, so the injected error fails ordinary writes too —
>   the volume never formats, `storage_unlock` fails, and the gate times out having tested
>   nothing. That is not hypothetical; it is how this target failed in CI on its first run
>   (`WAL_CRASHTEST: FAIL unlock`) while passing against a local QEMU 10.0.11 that satisfies
>   writethrough with `O_DSYNC` and emits no per-write flush. Writeback keeps a write a write,
>   leaving the guest's own `FLUSH CACHE` as the only `flush_to_disk` event.
> - **`smoke-fs-wal-order`** traces the IDE command register and asserts the tail of the
>   commit sequence is `0x30 0xe7 0x30 0xe7`. Presence is not enough: a barrier placed *after*
>   the commit header would satisfy error injection identically while losing the write-ahead
>   rule outright. `tools/smoke_test.sh` fails closed when the QEMU build has no trace
>   backend, so this can never pass by observing nothing.
>
> **Falsification (2026-08-16).** Against `WAL_NO_FLUSH=1`, which compiles the barriers out
> and restores the pre-fix kernel:
>
> | Control arm | Result | Marker |
> |---|---|---|
> | `make smoke-fs-wal-flush-control` | commits happily; no flush is ever issued so `blkdebug` never fires | `WAL: FLUSH FAILED` **absent**; `WAL_CRASHTEST: crashed-after-commit` present |
> | `make smoke-fs-wal-order-control` | checker rejects | `WAL_ORDER: FAIL no FLUSH CACHE (0xe7) was ever issued` |
>
> Deterministic, not a rate: the barriers are either compiled in or they are not.
>
> **[I-11] is fixed as of 2026-08-16, and half of it was already gone.** Barrier B is a real
> `FLUSH CACHE` that runs *before* `WAL_CRASHTEST: crashed-after-commit` is printed, so the
> journal write is on stable media by the time the harness sees the marker — the physical race
> the finding describes was closed by the [I-10] work without anyone saying so.
>
> The diagnostic half is what this fixes. Boot 1 now ends by asking QEMU to quit over its QMP
> monitor (`tools/qmp_quit.py`, driven by `WAIT_FOR_EXIT=1`) and **waiting for the process to
> exit**. The end of a run is a process exit, not a signal sent at a moment of the harness's
> choosing, so a guest that reaches the marker and then fails to leave is a timeout rather than
> a pass. `isa-debug-exit`, which roadmap 1.55 prescribed, does not terminate QEMU 10.0.11 —
> measured, reverted, and recorded at the crash hook.
>
> **Falsification (2026-08-16), four ways**, each confirmed to exit non-zero:
>
> | Reintroduced defect | Result |
> |---|---|
> | `qmp_quit.py` stubbed to refuse | **`crashed-after-commit` on serial, run still FAILS** — the old harness scored that identical log a pass |
> | `python3` absent (minimal `PATH`) | `SMOKE FAIL: WAIT_FOR_EXIT=1 needs python3 for the QMP quit` |
> | `qmp_quit.py` not executable | `SMOKE FAIL: … needs tools/qmp_quit.py to be executable` |
> | unreachable QMP socket | `qmp_quit` exits 1; run reports `could not ask QEMU to quit over QMP` |
>
> The first is the one that matters: the marker alone is no longer sufficient to pass.
>
> **Rate: 20/20 two-boot runs passed**, one fresh 32768-block image per run. Read that as
> corroboration, not proof — the pre-fix flakiness was load-dependent and did not reproduce on
> this machine, so it is not a before/after comparison. The substantive argument is structural.
>
> *Two harness bugs found while doing this, both worth knowing.* An exit the harness **asked
> for** was reported as `QEMU exited before the banner (triple fault?)`, because QEMU could die
> between the inner and outer liveness checks. And an early soak reported 0/20 because the
> images were created 4096 blocks against a `BLOCKS_PER_DISK` of 32768 — the volume could not
> lay out and boot 2 failed `WAL_CRASHTEST: FAIL read`, which is *exactly* the signature of the
> defect being measured. A soak that measures its own harness measures nothing; derive the
> image size from `kernel.h` the way the Makefile does.

## Device delegation and the console

| Target | Proves |
|---|---|
| `smoke-mapphys` | `SYS_MAP_PHYS` maps an allowlisted device frame — and only an allowlisted one. |
| `smoke-ioport` | The TSS I/O-bitmap grant gives native ring-3 port I/O to the holder. |
| `smoke-irq` | A hardware IRQ is routed to a userspace notification. |
| `smoke-console` | The ring-3 console server owns the hardware and serves clients. |
| `smoke-console-isolation` | A task **without** `CAP_IO_DEVICE` cannot reach the device-delegation syscalls. |
| `smoke-console-smp` | The single-writer console discipline holds under SMP. |
| `smoke-term` | Raw terminal mode: termios, winsize, and a keystroke through the real shell. |

## Userspace and libc

| Target | Proves |
|---|---|
| `smoke-newlib` | The newlib libc works in ring 3. |
| `smoke-newlib-tamper` | The pinned newlib SHA-256 **refuses** a tampered tarball — before unpacking it, and quarantining it so it cannot wedge the next build. Also asserts the genuine tarball still *passes*, because a gate that refused everything would sail through the negative case alone. No network or QEMU needed. Falsified by disabling the checksum gate: 3 controls fail. |
| `smoke-pipe` | Bounded pipes with `EAGAIN` back-pressure and EOF/EPIPE on close. |
| `smoke-coreutils-shell` | `head`, `wc`, and `seq` run on real files, driven through the actual ring-3 shell. |
| `smoke-tcc` | TCC is provisioned into `/bin` and `tcc -v` runs. (Needs `SMOKE_TIMEOUT=320`.) |
| `smoke-session` | A scripted session drives the real shell over serial and asserts on output. |
| `smoke-session-smp` | The same under SMP. |
| `smoke-session-smp-soak` | `SOAK_RUNS` consecutive SMP sessions, **all** of which must complete. Gates the IPC lost-reply race (see CHANGES.md), which hung ~1 boot in 5 — a rate a single-boot test passes four times out of five, which is how it went unnoticed. One hang fails; there is no retry. Falsified at 2/10 hangs against the pre-fix kernel. Each run must also emit `SESSION_TEST: PASS` **and** clear `SOAK_MIN_CHECKS` (default 8) `[ok]` steps — a run that exits 0 having proven nothing is reported `VACUOUS` and fails, so the gate cannot go green on a test that stopped testing. **Keeps evidence:** each failing or vacuous boot's **full serial log** is retained in `$(SOAK_EVIDENCE_DIR)` (default `soak-evidence/`) alongside its stdout, and CI uploads the directory plus the exact `kernel.elf` as artifacts; a clean run removes the directory. Until 2026-08-13 the target reused one temp log, overwrote it every iteration, deleted it at the end and printed `tail -20`, so it destroyed the diagnostic it existed to produce — see G-8 below. **GATING again as of 2026-08-17**, restored in the commit that closed **[G-8]**; it was advisory from 2026-08-09 while that finding was open, and it was correctly reporting a real defect the whole time. |

## Can the kernel be heard when it faults?

| Target | Proves |
|---|---|
| `smoke-kfault` | A page fault taken at **CPL 0** is reported on the **serial line**, after the console handover. `KFAULT_INJECT=1` makes the kernel fault on purpose — a read of `0x94`, G-8's exact address — on a timer tick once `console_server` owns the console, and the harness requires the report to appear *after* the login prompt. |
| `smoke-kfault-legacy` | The same injection with reporting restored to `println()` (`KFAULT_LEGACY_PRINTLN=1`): the report must **not** reach serial. The control arm. |
| `smoke-resume-guard` | `idt.c`'s resume-`%rsp` floor guard fires and is **heard**. `RESUME_RSP_INJECT=1` forces the dispatcher to return a bogus resume `%rsp` of `4` — G-8's own recorded value — once, after the console handover; the `PANIC: dispatcher returned a bogus resume rsp=0x4` line must appear after the login prompt. Replaces a ~1-in-150 wait with a gate. |
| `smoke-resume-guard-preclaim` | The same, with the **permanent panic claim already held** — the state another CPU's fatal exception leaves behind. The report must still get out. This is the arm that witnesses the fix. |
| `smoke-resume-guard-legacy` | Control arm for the fix: same injection and claim, with the guard's pre-fix `kfault_begin(1)`/`kfault_end(1)` bracket restored (`RESUME_GUARD_LEGACY_FATAL=1`). The report must **not** reach serial — the boot goes silent at the login prompt, which is the defect on demand. |
| `smoke-resume-guard-nofloor` | Control arm for the guard: same injection, guard compiled out (`RESUME_GUARD_DISABLE=1`). The PANIC line must **not** appear; the kernel instead faults at `0x94` on `out->cs`, which is G-8's original datapoint reproduced deliberately. |
| `smoke-kstack-race` | **S20** — a task's kernel stack is executed by at most one CPU at a time. `KSTACK_RACE_WIDEN=1` stretches the window between handing a task to another CPU and the ISR epilogue leaving that task's stack, so it is entered on essentially every switch instead of at **[G-8]**'s 2–3% per boot. With the deferred release the claim is held across the window, so nothing can take the stack: the session must complete and `PANIC: two CPUs on one kernel stack` must be **absent**. |
| `smoke-kstack-park` | **ADVISORY, not gating — see finding G-9 below.** **S20**, park path — a CPU whose last runnable task dies parks on its **own** ring-0 stack. Boots the task-killing `PROC_SELFTEST` at `-smp 4` (a healthy session never enters the path: 0 parks in 3 boots) and asserts four things, because three of them pass vacuously alone: the self-test completes, at least two CPUs actually parked, no park stack was used by more than one CPU, and `sched_note_park()`'s report is absent. |
| `smoke-kstack-park-control` | Control arm. Same workload with `KSTACK0_SHARED_PARK=1` restoring `tasks[0].kernel_stack_top` as the shared park target; at least one park stack must come back used by more than one CPU. **Boots up to `KSTACK_PARK_CONTROL_BOOTS` (8) times and stops at the first reproduction.** A *shared* park needs two CPUs to reach the park path in the same boot, which is a property of the schedule: measured 2026-08-22, it reproduced **9 boots in 12** on the branch under test and **10 in 12** on unmodified `main`, and every miss recorded exactly one park in the whole boot — so the collision was impossible in that boot, not merely unobserved. A single-boot assertion is therefore ~25% red, which is what it was until 2026-08-22 and what failed the first unrelated PR after the job was promoted to merge-gating. At 75%/boot a clean sweep of 8 is ~1 run in 65000. Accepts **either** signal: a park stack traced from two CPUs, or the kernel's own collision PANIC. The PANIC used to be excluded on the grounds that it needs both CPUs parked at the same instant — but `sched_note_park` *halts* on detecting the second CPU, so on exactly those boots the second `PARKTRACE` line is never printed and a trace-only test scores the hardest reproduction as a miss. Observed doing so on 2026-08-22. |
| `smoke-resume-guard-negative` | **[G-9]** residual, detector half. The resume-`%rsp` guard must reject a *negative* bogus value. `RESUME_RSP_INJECT_VALUE=-7` forces the dispatcher to return `-7` once after the console handover; the guard's PANIC line must reach serial. Until 2026-08-18 the predicate was `rsp < 0xFFFF800000000000ULL` — a floor with no ceiling — so `-7` (`0xFFFFFFFFFFFFFFF9`) sailed over it and faulted inside the ISR epilogue instead, with a banner naming the stub and nothing about the value. The bound is now `[__bss_start, __bss_end)`, taken from the linker, because every 64-bit kernel stack is a `.bss` array. |
| `smoke-resume-guard-negative-control` | Control arm. `RESUME_GUARD_FLOOR_ONLY=1` restores the floor-only predicate; the report must be **absent**. Note the regex matches the injected *value*, not just the banner — the first version of this pair reused the `rsp=0x4` regex from `smoke-resume-guard`, which made the `EXPECT_REPORT=1` arm fail against a guard that was working correctly and, worse, made this control arm **pass vacuously**: a pattern that can never match is trivially absent. A control arm that cannot fail is not a control arm. |
| `smoke-resume-guard-ist` | The guard's **false-positive** arm, and the one whose absence let a regression ship. Every other arm injects a bogus value and asks whether the report appears — they measure false *negatives*, so a predicate that rejected the whole address space would pass all of them. This one injects nothing: it boots the captest workload, which faults through IST1 as a matter of course, and requires `CAPTEST: PASS 100 checks` with the guard's report **absent**. |
| `smoke-resume-guard-ist-control` | Control arm. `RESUME_GUARD_BSS_ONLY=1` restores the bound the ceiling first shipped with — `[__bss_start, __bss_end)` alone, on the premise that every 64-bit kernel stack is a `.bss` array. The three IST stacks are in `.data`; IST1 serves `#DF`/`#GP`/`#PF`; the guard halts on a rejection. So that build dies on the first ring-3 page fault with `bogus resume rsp=0xffffffff801a9f50` — an address `0xf50` into `ist1_stack_bottom`'s page. Requires that fault to be **present**, via `smoke_test.sh`'s `EXPECT_FAULT` (`kfault_test.sh` cannot serve here: it anchors its verdict after the console handover, and this build dies long before a login prompt). |
| `smoke-cr3-reclaim` | **[G-10]**, page-table half. A task slot's page tables must not be recycled while any CPU still has them loaded in CR3. Boots the `PROC_SELFTEST` workload at `-smp 4` `CR3_RECLAIM_RUNS` times (default 20) and requires no supervisor write fault at `0xFEE000B0` — the LAPIC EOI register, which lives in each task's own `pml4[0]` identity map and is therefore the first thing to disappear when a leaf PTE is recycled. Measured 0 in 30, against 6 in 30 before the fix. Asserts on the marker, not on the boot's exit status: the rest of **[G-9]** still fails ~7% of these boots and this gate is not about that. |
| `smoke-cr3-reclaim-control` | Control arm. `CR3_RECLAIM_UNGUARDED=1` restores the unconditional free; the free-in-use report must come back. Only 3 boots are needed because it is deterministic — measured 20 in 20 — which is also why the pair asserts different markers: the free-in-use happens every boot while the fault it causes lands on ~20%, so gating this arm on the fault would be flaky for no gain. |
| `smoke-spawn-owner` | **[G-11]**, property **S21**. A staged program image is spawnable only by the task that armed it. One boot with `SPAWN_OWNER_SELFTEST=1`: the self-test forges a foreign owner on a legitimately staged image and requires `do_spawn` to refuse it, then re-arms honestly and requires the spawn to succeed. Deterministic — the concurrent half of roadmap 1.7 is not reachable in any bootable workload (see the G-10 section), and this gate is about the rule rather than the race. Control arm `SPAWN_OWNER_UNCHECKED=1` (`make smoke-spawn-owner-control`) removes the refusal and spawns the foreign image on every boot. |
| `smoke-klog-forge` | **[H-2]**, property **S23**. A ring-3 task cannot forge entries into the kernel message ring, nor evict what is already there. One boot with `KLOG_FORGE_SELFTEST=1`: the kernel seeds a marker into `klog` immediately before ring-3 entry, and a probe endowed with `CAP_KERNEL_LOG` pushes 28800 bytes of a distinctive pattern through `SYS_WRITE` fd 1 — more than the 16 KiB ring holds — then reads the ring back through `SYS_DMESG` and requires the pattern **absent** and the marker **present**. Deterministic; nothing here is racy. **The probe is endowed on purpose.** Its capability carries `CAP_RIGHT_READ` and nothing else, because `root_cnode[15]` mints it that way and delegation may only narrow — so it can read the ring to check its own work and is still refused the direction it was not given. A bare task would have proved that a task holding *no* capability cannot write, which is a weaker claim than the one the finding makes. |
| `smoke-defect-flags` / `-control` | **Build provenance.** Every boot prints `DEFECT FLAGS: <list>` or `DEFECT FLAGS: none`, compiled in from the Makefile's `DEFECT_FLAGS` list. It prints **unconditionally**, including the clean case: an absent line is ambiguous between "clean", "the reporting was removed" and "the boot died early", and only one of those is good news. The control arm builds with `KSP_GUARD_INJECT=1` and requires the flag to be named — without it, a kernel that printed `none` unconditionally would satisfy the gate. |
| `smoke-defect-flags-rebuild` / `-control` | **The footgun itself.** A `-D` flag is not a prerequisite of an object file, so `make FLAG=1` then `make` leaves every unchanged `.c` compiled with the flag and says nothing. On 2026-08-20 that gave a [G-9] measurement campaign a kernel still carrying `KSP_GUARD_INJECT`: the guard "fired" in 2 boots of 3 with the injected constant, which briefly read as a reproduction of the defect being hunted. It was caught because `-7` is implausibly exact and 67% implausibly high — by luck, not method. The gate builds injected, rebuilds **without** `clean` or the flag, and requires `none`. `BUILD_FLAGS_UNSTAMPED=1` drops the `.build-flags` dependency and requires the stale flag to **survive**, which is what proves the stamp is doing the work. |
| `gate-pairs` | **The coverage question applied to the gates themselves.** `tools/check_gate_pairs.py` enforces four structural rules, each violated at least once in this tree: a control arm must extend a base gate that exists; a control arm must actually be invoked by CI; a gate must be invoked or listed in `.github/gate-exceptions.yml` with a reason; and an exception must name a real target and give one. Source analysis, no build. Falsified all four ways — orphan arm, unrun arm, stale exception, empty reason. It was written because `smoke-ksp-guard-control` had **no positive counterpart**: an arm proving the guard *could* fire, with nothing asking whether it stayed silent on a legal value. |
| `smoke-ksp-guard` | The **false-positive** arm for the producer-side resume-`%rsp` guard, and the direction whose absence is a known way to ship a regression. Every other arm on this guard injects a bogus value and asks whether it fires — they measure false *negatives*, and a predicate that rejected every stack pointer would satisfy all of them. This boots the **default** workload, where every resume value is legal, and requires `SCHED BOGUS KSP` to be **absent**. Falsified by `KSP_GUARD_ALWAYS=1`, which makes `ksp_is_bogus()` reject everything: the guard then fires on a legitimate address (`ipc_block_switch task=2 ksp=0xffffffff8020cf40`) and the gate goes red. The default workload rather than `PROC_SELFTEST` on purpose — the latter still trips [G-9] on ~1–2% of boots and would make this intermittently red for an unrelated reason. |
| `smoke-ksp-guard-control` | **[G-9]**, producer side. All four switch functions (`preempt_on_tick`, `ipc_block_switch`, `sched_yield_switch`, `task_exit_switch`) end in the same three lines — take `tasks[next].saved_ksp`, drop the lock, return it — and every selection loop above them required that value to be merely **non-zero**. Each now validates it **against the page tables** (`kern_addr_present`), not an address range: `per_task_kstacks`, `ap_idle_stacks` and `ap_ist` all live inside `[__bss_start, __bss_end)` and their guards are armed by being made *absent*, so a pointer sitting in a guard page passes every range test in the tree. Both the value and the byte 8 below it are checked, since that is where the epilogue pushes. On failure it names the producing function and returns 0, so the caller parks instead of `iretq`-ing onto it. `KSP_GUARD_INJECT=1` forges `-7` and requires `SCHED BOGUS KSP from task_exit_switch` on the wire. **A detector, not a fix** — across 57 pinned boots containing a live reproduction it did not fire once, which is what rules those four producers out. |
| `syscall-coverage` | **The coverage claim over the syscall table.** Boots three workloads under `SYSCALL_COVERAGE=1` — the scripted ring-3 session, the conformance suite, and the boot-modules session — and records which syscall **handler bodies** are entered, then diffs the union against `.github/syscall-coverage.yml`. Currently **51 of 81** implemented syscalls. It does not demand all of them; it demands the number be decided rather than drifting, and every gap be written down. Fails four ways, all falsified: a syscall in neither list, a `covered` one whose handler stopped running, an `uncovered` one whose handler *did* run (a stale reason), and a serial log with no `SYSCOV` lines at all — that last is what stops a mis-built arm from reporting a page of spurious regressions, or an empty log from passing silently. |
| `syscall-abi` | **Issue #176**, property **S24**. `tools/check_syscall_abi.py` parses `include/syscall.h` and requires every pointer argument of every inline wrapper to reach `syscall()`/`syscall6()` full-width. Source analysis, no build, no QEMU — which is the point: a runtime gate only covers the syscalls some probe happens to call, and this covers all 46 pointer arguments including wrappers nothing calls yet. Falsified two ways: narrowing one wrapper's pointer (names the wrapper), and narrowing `SYSCALL_UPTR`'s own default definition — the obvious way to defeat a per-wrapper check, so it is checked separately. |
| `smoke-klog-forge-abi-control` | Control arm for the above at runtime. `SYSCALL_PTR_TRUNC32=1` restores the truncating wrappers; the probe's buffer is a static, so it is above 4 GiB and gets truncated, and `KLOGTEST: FAIL setup dmesg rc=-14` must come back. Measured **3 boots in 3**. This arm is also what stops `smoke-klog-forge` from quietly losing half its coverage: if the probe's buffer ever moves back to the stack the truncation becomes a no-op, this arm goes green, and the failure is visible instead of silent. |
| `smoke-klog-forge-control` | Control arm. `KLOG_WRITE_UNGATED=1` restores the unconditional `klog_append` on the ring-3 write path; `KLOGTEST: FAIL forged+evicted` must come back, and `smoke-klog-forge` must go red under the same flag. Measured **3 boots in 3** — one boot is enough because the defect is not a race. **Both halves are evaluated before either is reported**, which is what makes this arm exercise both branches rather than only the first in source order. That matters: a fix that merely rate-limited ring-3 appends would keep the marker and still leak the forgery, and one that dropped the bytes while still advancing the ring would lose the marker, so an assertion on either half alone passes a half-fix. |
| `smoke-exec-reenter` | **[G-9]**, exec component. The exec re-entry hand-off must be consumed by the CPU that armed it. Boots the `PROC_SELFTEST` workload at `-smp 4` `EXEC_REENTER_RUNS` times (default 20) and requires the `SCHED_INVARIANTS` wrong-CPU report to be **absent** from every boot; measured 0 in 30. Asserts on the marker, never on the boot's exit status — the workload still fails 2 boots in 30 (~7%) on the rest of **[G-9]**, and gating on completion would make this a detector for that rather than a witness for this property. |
| `smoke-exec-reenter-control` | Control arm. `EXEC_REENTER_GLOBAL=1` restores the single shared `g_exec_reenter_task`; the wrong-CPU report must come back in at least one boot. Needs many boots because the theft is a race — measured 5 in 20 (~25%/boot), so a single-boot arm would report a false green three times in four. This arm carries reachability for the pair: if the theft stops reproducing with the global restored, `smoke-exec-reenter`'s green proves nothing either. |
| `smoke-kstack-race-control` | Control arm, and the load-bearing one. Same widened window, `KSTACK_RELEASE_EARLY=1` restoring the pre-fix release site. The marker must be **present** *and* the session must not report PASS — a build that reproduced the race and still reported success would mean the harness had stopped reading the wire. Without this arm, `smoke-kstack-race` proves only that a kernel with a spin in it still boots. |

**The control arm boots up to eight times, and did not always used to.** The pre-fix release
site reproduces the race *probabilistically*, and this arm asserted it from a **single boot**.
Measured 2026-08-19: **7 reproductions in 12 boots** locally (58%), so it misses about 42% of
the time on a workstation. On CI it reddened `main` **twice the same day** (runs `32244509317` and
`32251467694`) — two of the last eight runs — with the fixed arm green in the same job both times, on
trees whose content had already passed that job on a branch.

A single boot cannot assert a probabilistic event. This document's own rule is to quote a rate
over N boots, and the arm was quoting one while asserting from n=1. It now boots up to
`KSTACK_RACE_CONTROL_BOOTS` (8), stops at the first reproduction and names the boot it came on.
At 58% the expected cost is under two boots and a false failure across eight is 0.42⁸ — about
one run in a thousand.

**Nothing was weakened, and that was falsified rather than argued.** Rebuilt with
`KSTACK_RELEASE_EARLY` *removed*, so the defect is absent, the arm attempted all 8 boots, found
nothing, and failed with `KSTACK RACE CONTROL: FAIL - the pre-fix build did NOT reproduce the
race in 8 boots` (exit 2). With the defect present it reproduced on boot 1 of 8. Adding retries
to a probabilistic check is exactly the change that can turn a gate into one that cannot fail,
so the arm that proves it still can is the one worth running.

The fixed arm stays at **one** boot deliberately: its assertion is that the panic *never*
appears, which a single boot can falsify. Its statistical power comes from
`smoke-session-smp-soak` and `tools/stress_boot.sh`, not from this pair.

This pair is the inverse of every other target here: it wants a kernel fault and fails if the
kernel takes one quietly.

**Why it exists.** `print()` stops driving the hardware the moment `console_server` owns the
console (`terminal.c`), so a report emitted that way during a live session lands in the klog
and nothing reaches the wire. All three CPL-0 reports were emitted that way — the `#PF`
banner, the fatal-exception dump, and #123's bogus-resume-`rsp` guard — and a live session is
the only state in which any of them has ever been observed. G-8's supervisor fault tore down
the ring-3 shell on every occurrence while the kernel computed the address, the error code and
the faulting `rip`, printed them, and threw them away.

**Why the control arm is the point.** `smoke-kfault` passing tells you a report arrived. Only
`smoke-kfault-legacy` — same kernel, same injection, same tick, reporting through `println()`,
and **nothing on the wire** — tells you the gate is measuring the routing rather than the
existence of the fault. Compare the falsification discipline in the C-1 and 1.3 sections: a
test that cannot fail on the bug it targets is not evidence.

The ordering assertion is deliberate. "The report appeared" is satisfied by early-boot output,
when `print()` still drives the UART; "the report appeared **after** the login prompt" is not.

## Build integrity

| Target | Proves |
|---|---|
| `reproducible-build` | `kernel.elf` is byte-for-byte identical across two clean builds, and the record covers every artifact the build produces. **A required CI check.** `boot.iso` is recorded but deliberately not compared — it is not byte-reproducible (`docs/LIMITATIONS.md` §5.3a). |
| `smoke-repro-sha` | The hash-recording step refuses a build missing an artifact, and writes no `.build.sha` at all when it refuses; and records every artifact when the build is complete. Both directions. Host-side, sub-second. Falsified by `smoke-repro-sha-control`. |
| `smoke-repro-sha-control` | `REPRO_SHA_UNCHECKED=1`. Restores the pre-2026-08-19 recording step *and* the goal list that made it silent; the incomplete record and the success report must both appear. |
| `doc-claims` | Every count declared in `.github/doc-claims.yml` matches the value derived from the tree, every declared occurrence still matches its pattern, and no retired phrasing has reappeared unquoted. **A required CI check.** `tools/check_doc_claims.py`; static, no QEMU. |
| `security` | Semgrep, Trivy, gitleaks, cppcheck, flawfinder, cargo-audit, plus a CycloneDX SBOM. **A required status check.** Its *findings* stay advisory (one deliberate `continue-on-error`), but since #154 the job asserts each scanner is actually installed and fails if one is missing — it had previously been a required check on which every step carried `continue-on-error`, so it could not go red for any reason, including scanning nothing at all. |

### The build-hash record: a step that could not fail, over an artifact that was never built

**Fixed 2026-08-19.** The recording step at the end of `reproducible-build` was:

```make
@sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null || true
```

and the target's build goal was `all`, which is `all: kernel.elf`. Since the target *deletes*
`boot.iso` at the top and nothing rebuilt it, that `sha256sum` failed on a missing operand on
every run it has ever had. `2>/dev/null` discarded the message naming the file and `|| true`
discarded the status, so the target printed "Reproducible build recorded." over a `.build.sha`
containing one line. Three mechanisms had to line up for that to be silent and all three did.

**The fix is `tools/record_build_sha.sh`**, invoked with the artifact list. It fails on a
missing artifact, does not redirect stderr, and writes `.build.sha` by rename from a temporary
after removing the old one — so a failed run leaves no file rather than a partial one that
cannot be told apart from a complete record of a smaller build.

**Falsified deterministically, in both directions.**

| Arm | Command | Required |
|---|---|---|
| fixed, incomplete build | `make smoke-repro-sha` | `REPRO_SHA: PASS refused an incomplete build, wrote nothing` — and no `.build.sha` on disk |
| fixed, complete build | `make smoke-repro-sha` | `REPRO_SHA: PASS recorded 2 artifacts, kernel.elf boot.iso` |
| control | `make smoke-repro-sha-control` | `REPRO_SHA_CONTROL: FAIL recorded 1 of 2 artifacts and reported success` |
| the gate against the defect | `make smoke-repro-sha REPRO_SHA_UNCHECKED=1` | **must fail**: `REPRO_SHA: FAIL recorded-a-build-missing-boot.iso`, make exits 1 |

Both directions matter here for the usual reason: a recording step that refused everything
would satisfy the first row while making `reproducible-build` permanently red, so the second
row is what stops the fix from being "refuse always".

The control arm restores **both** halves — the swallowed status *and* the goal list that
omitted `boot.iso`. That is deliberate and was checked: with the ISO present, a swallowed
status changes nothing observable, so an arm that restored only the `|| true` would pass for
the wrong reason and prove nothing about the gate.

Host-side and sub-second — it exercises the recording step against a scratch directory, not a
real build, because what is under test is the step's behaviour when an artifact is absent. The
end-to-end half lives in the `reproducible` CI job, which now requires the record to name both
artifacts before it diffs the `kernel.elf` line.

**What building the ISO revealed:** `boot.iso` is not byte-reproducible. `grub-mkrescue`
stamps `/.disk/<wall-clock-second>.uuid` into the image and embeds that UUID in the EFI loaders
it generates, while everything this project authors inside the ISO is byte-identical across
builds. The CI job therefore compares only the `kernel.elf` line. The first measurement said
the ISO *was* reproducible, because two back-to-back builds landed inside the same wall-clock
second; crossing a second boundary makes them differ. Recorded because a measurement fast
enough to be convenient was fast enough to be wrong. See `docs/LIMITATIONS.md` §5.3a.

### Documented numbers are derived, not trusted — property S22

**Added 2026-08-19**, after an audit found nine stale numbers across five files in one morning:
CI job counts, context counts, the required set, and the capability suite's check count, which
two other files carried correctly. CLAUDE.md has said *"re-derive every number you cite"* since
long before that. A rule only a reader enforces fails silently, and silence is how it failed.

`.github/doc-claims.yml` declares each derivable count and **every place that states it**;
`tools/check_doc_claims.py` derives the value from the source of truth and compares. The
`doc-claims` CI job gates it.

| Derived | From |
|---|---|
| `ci_jobs`, `all_jobs`, `contexts`, `required`, `advisory` | the workflow files and `.github/ci-gating.yml`, via `check_ci_gating.load_jobs` — imported, not reimplemented, because a second copy of the context-expansion rules is one more thing to drift |
| `smoke_targets`, `control_arms` | `^smoke-*:` in the `Makefile` |
| `captest_checks` | `check(` calls in `userspace/captest.c` — verified equal to the runtime `CAPTEST: PASS 100 checks` on 2026-08-19 |

**Three failure modes, all three falsified.**

| Arm | Injected | Required |
|---|---|---|
| stale number | `README.md` 72 → 69 jobs, the value that was actually wrong that morning | `README.md: says 69 for ci_jobs …, live value is 72`, exit 1 |
| claim deleted by rewording | replace the sentence with "CI runs a lot of jobs" | `claim 'ci_jobs' is declared here but its pattern matches nothing`, exit 1 |
| retired phrasing reasserted | put `build twice from clean and diff` back into `docs/BUILDING.md` | `forbidden phrasing …`, exit 1 |

The second arm is the one worth explaining. If a declared occurrence matching nothing were
merely tolerated, rewording a sentence would delete the check silently along with the claim —
the failure mode in miniature. So a claim that stops matching is an error, and the fix is to
update the pattern or remove the occurrence deliberately.

**Retired phrasings are a ratchet.** When a fact is corrected, its old wording goes in the
manifest's `forbidden` list so it cannot reappear in another file later. A match **inside double
quotes is ignored**: this project's style is to record the wrong thing when correcting it —
*"this paragraph previously said X"* — and a blanket ban would forbid exactly the practice that
makes a correction auditable. Quoted text is reported, not asserted. That allowance was not
theoretical: the first run of this checker flagged three lines, and all three were corrections
quoting what they had corrected.

**What it deliberately does not do.** No network, no QEMU, no ruleset read — comparing the live
ruleset needs `Administration: read` and belongs to `ruleset-audit`. It checks numbers and
retired phrasings, not prose: a document can still be wrong in a way no regex catches, which is
what review is for.

**One exclusion, deliberately.** `docs/history/DEVLOG-2026.md` is exempt from the ratchet. It is a
frozen record of what was written on the day it was written — entries there assert things that
were true then and are not now, and that *is* the content. The exemption is the same principle as
the quoted-text allowance: the log reports a past state rather than asserting a present one. It is
also never named as a numeric occurrence, so no derived claim can live in it. Falsified both ways
on 2026-08-21: a retired phrasing appended to `docs/LIMITATIONS.md` fails the check naming file and
line; the same phrasing appended to the log does not.

### The defect-flag table is the complete list it claims to be

**`tools/check_defect_flags.py`, required job `defect-flags-documented`.**
`docs/BUILDING.md` says of its defect-reproducing-builds table: *"This table is the complete
list."* That sentence was **false when it was written**. Three members of the Makefile's
`DEFECT_FLAGS` had no row — `RESUME_RSP_INJECT`, `RESUME_RSP_INJECT_PRECLAIM` and
`WAL_CRASHTEST` — and one of them appeared nowhere in the file at all. That table is the only
index of the control arms, so an undocumented arm is indistinguishable from a deleted one: a
falsification nobody can find is one nobody re-runs.

It derives the flag set from the Makefile and enforces three rules. Each was falsified
separately, which is the only reason two of them work:

| Rule | Arm | Result |
|---|---|---|
| Every `DEFECT_FLAGS` member has a table row | delete the `WAL_CRASHTEST` row | exit 1, naming it |
| Every row names a flag some build defines | add a row for `WAL_RETIRED_ARM=1` | exit 1, naming it |
| A tuning parameter is named in the row it tunes | strip every mention of `RESUME_RSP_INJECT_VALUE` | exit 1, naming it |

**Rules 2 and 3 did not fire on their first attempt, and that is the finding worth recording.**
Rule 2's loop skipped any flag absent from the Makefile — which is precisely the condition it
existed to catch — so a row naming a flag no build defines passed silently. It is the same shape
as the `smoke-ksp-guard` gap this suite recorded three days earlier: an arm that only injects
measures false *negatives*. A checker with three rules needs three arms, not one.

---

## CI

`.github/workflows/ci.yml` defines **87** jobs, run on every push and pull request;
`codeql.yml` adds one more, C/C++ static analysis (plus a weekly schedule); `ruleset-audit.yml`
adds one that runs only on a daily schedule. All three are covered by the gating classification
below — **89** jobs, **92** contexts. Counts from `tools/check_ci_gating.py`, which prints them;
do not copy them forward from here.

Every job carries `timeout-minutes` as of 2026-08-20 — a backstop, not a budget. The default is
360, which let three runs on 2026-08-19 hang on a package-mirror stall rather than fail: jobs sat
on their install step for 95 minutes, two hours, and in one case until the run was cancelled
seven hours in with `main` still holding no verdict. A short timeout on the *install step* was
measured and rejected: the median install is about 20 seconds but the legitimate tail reaches 32
minutes, and 12 of 74 installs exceeded 15 minutes in a run that was green on all 77 checks. A
step budget would have reddened it. The distinction that matters is between slow and never
returning, and only a generous cap draws it.

All third-party actions are pinned to full commit SHAs. Workflow `permissions:` blocks are
least-privilege. There are no self-hosted runners.

### A known weakness in the gate

Of those, **22 were required status checks** before 2026-08-16 — read the current set from
`gh api repos/pharanyx-labs/Horus/rulesets/19007209`, not from this file, which is the kind of
hand-maintained number this document exists to distrust.

`smoke-captest` joined that set on 2026-08-15. It is the named witness for eight of the
S-numbered properties in `SECURITY.md`, and until then it could not block a merge — a change
that broke the capability refusal suite went green, which is precisely how **[C-1]** survived
every automated gate in the first place.

This is finding **[C-6]** and roadmap item 4.2, and promoting one job never closed it. The
mechanism was the problem: the required list lived only in the ruleset, which no commit
touches, so every job added to `ci.yml` landed in the advisory set **by default** and nothing
asked whether it should have. When this finding was filed there were ~30 jobs and 21 required;
immediately before 2026-08-16 there were 66 and 22.

### The classification is now checked in

`.github/ci-gating.yml` lists every job in `ci.yml` and `codeql.yml` under either `required:`
or `advisory:` **with a written reason**. The `ci-gating` job (and `make check-gating`) fails
the build when a job is in neither, in both, or names a job that no longer exists. There is no
default — defaulting is the defect. Run it before opening a PR; it is pure text analysis, no
build and no QEMU.

Falsified on 2026-08-16, three ways, each confirmed to exit non-zero against the passing
baseline:

| Reintroduced defect | Result |
|---|---|
| A new job added to `ci.yml`, classified nowhere | `job 'smoke-brand-new-gate' is in neither list` |
| An advisory entry naming a job that no longer exists | `advisory job 'smoke-deleted-long-ago' is not defined in any workflow` |
| An advisory entry with a placeholder reason (`slow`) | `advisory job 'smoke-tcc' has no substantive reason (got 4 chars…)` |

It also caught a real one on its first run: the CodeQL `analyze` job was unclassified, which is
the same omission class the finding describes.

The intended set is **89 required contexts and 3 reasoned exemptions** — read off
`tools/check_ci_gating.py`, which prints them, rather than from this sentence — `fuzz` (a fixed
30-second search is evidence of effort, not of absence), `kani` (manual-only, so there is no
conclusion to gate on), `ruleset-audit` (schedule-only, so it never runs on a pull request) and
`smoke-kstack-park` (its workload trips **[G-9]**). `smoke-fs-wal` was a third until **[I-11]** was fixed and it was
promoted back to gating; `smoke-session-smp-soak` a fourth until **[G-8]** was closed on
2026-08-17, and it was promoted in the same commit. Three of the four are properties of the test
itself; `smoke-kstack-park` was the one exemption that stood for an **open defect**, and it was
**promoted on 2026-08-22**, one merge after **[G-9]** closed. Its workload ran 0 failures in 200
boots after the fix (95% upper bound 1.49%) against ~45% before [G-9]'s exec and page-table
components and ~7% after them; the gate itself passed 5 of 5 in its exact form, which at a 7%
rate is only ~70% power and is corroboration rather than the evidence. **No exemption now stands
for an open defect** — the three that remain (`fuzz`, `kani`, `ruleset-audit`) are properties of
those tests. The promotions are backed
by measurement, not optimism: across 18 CI runs sampled on 2026-08-16, **64 of 66 jobs had zero
failures over 1152 job-executions**; the only two that ever failed are `security` (2/18, both
deliberate, during #154) and `smoke-session-smp-soak` (1/18, which was [G-8] at its documented
2–3% per boot — the defect that job was correctly reporting).

`smoke-fs-wal` is deliberately **demoted** from required. A flaky gate that blocks merges
spuriously teaches the maintainer to re-run red checks, which costs more than the coverage it
buys, and the durability property it used to be credited with is now witnessed by the
deterministic `smoke-fs-wal-flush` and `smoke-fs-wal-order`.

### What this does *not* do

**CI cannot verify the ruleset.** The ruleset was synced on 2026-08-16 —
`tools/check_ci_gating.py --sync-ruleset` took it from 22 required contexts toward 67,
preserving `strict_required_status_checks_policy` and bypass actors, and re-read it to confirm.
Run from a feature branch, it also required three contexts `main` could not yet produce, which
blocks every PR on a check that never reports; `tools/prune_unsatisfiable_checks.py` dropped
them (67 → 64) and encodes the rule that promotion must **lag** the job landing by one merge. So every
security target now blocks a merge, and the old advice to run them locally *because CI will not
stop you* no longer applies.

But reading a ruleset needs Administration permissions the workflow `GITHUB_TOKEN` does not
have and cannot be granted, so the `ci-gating` job proves the classification is **complete**,
not that the ruleset **matches** it. A change made in the GitHub UI could reopen the gap and
nothing in CI would notice. `--check-ruleset` is the check; it has to be run deliberately, and
it is the reason **[C-6]** stays open.

`strict_required_status_checks_policy` is now **true**, so a PR can no longer merge having
passed CI against a stale base. (This document previously said it was false; that was correct
when written and is not any more.)

---

## The claim audit's exemption outlives the release it exempts — [G-9] closed

> **A regression this gate caught the day after, and what it costs to skip one.**
> The [G-9] fix shipped in #188 also moved the `g_kstack_inflight` clear inside the
> scheduler lock — which the property it was establishing never required. Under
> `KSTACK_RACE_WIDEN`'s 200,000-iteration spin the wider critical section pushed the
> session past its 90-second budget, and `smoke-kstack-race` — a **required** gate —
> went red on `main`. It reproduced deterministically, so it was not a flake.
>
> The gates for [G-9] and the core smoke set were run before that merge.
> `smoke-kstack-race` was not, despite the change being inside
> `sched_release_deferred()` — which *is* the [G-8] deferred-release machinery that
> gate exists to exercise. **Editing a function means running the gate named after
> its finding**, not only the gate named after the finding you are working on.
>
> The fix is to narrow the critical section to what the property needs: the
> exemption must outlive the claim release; the bit clear was never part of that.
> Verified by the control arm still reproducing on boot 1, which is what says the
> narrower lock did not quietly weaken the fix.

**`smoke-defer-exemption`, required job `defer-exemption`.** `percpu_deferred_release[]` is not
just a CPU's note of work owed — `sched_assert_claims()` uses it as the **exemption** that says a
claim is mid-handover rather than leaked. `sched_release_deferred()` cleared it *before* taking
the lock that drops the claim, so for the width of a lock acquisition the task was claimed,
un-exempt and mid-release. A CPU auditing in that window reported a leak that was not one.

**The checker's second false positive**, and the same family as 2026-08-09, where it read a
deliberate spawn-time impersonation as a leak. Both times it observed its own exemption machinery
mid-update. *A checker that exempts a state must hold the exemption for the whole of that state.*

**Why the pair is widened.** The natural event is ~4.5% with variance wide enough that 200-boot
arms cannot separate 4.5% from 6.5% — the baseline itself ran 2/50 and then 9/200, and an
intermediate 13/200 was briefly read as a regression before a significance test returned p = 0.39.
`DEFER_WINDOW_WIDEN=1` is set in **both** arms, which is what makes them a measurement.

| Arm | Boots | Panics |
|---|---|---|
| widened, exemption held to the end (shipped) | 10 | **0** |
| widened, `DEFER_CLEAR_EARLY=1` (pre-fix) | 10 | **8** |

Fisher p ≈ 0.0007. Natural rate 9 in 200 → **0 in 200** (p = 0.0036), which bounds the residual
at under 1.49% at 95% confidence — a bound, not a proof of zero. The deterministic pair is the
evidence; the clean run is corroboration.

---

## A refused switch leaves no claim behind — [G-9]'s root cause

**`smoke-switch-commit`, required job `switch-commit`.** `task_exit_switch()` returns `0` for
two incompatible things: *"nothing runnable, caller parks"* (no claim taken) and, via
`ksp_refuse()`, *"I already claimed `next` and named it current, but its resume value is
bogus"*. All three callers in `idt.c` read `if (rsp) return rsp;` and otherwise park the CPU, so
a refusal was indistinguishable from an empty run queue — and the claimed task stayed claimed
forever, skipped by every selection loop, unschedulable by every CPU including its holder.

**The resume guard added *for* [G-9] is what committed the switch before validating it.** The
instrument installed to catch the leak was creating one.

All four switch paths now validate before committing: nothing is claimed, no address space
installed, no task named current until the resume value is known good, so a refusal has no state
to unwind.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-switch-commit` (`KSP_GUARD_INJECT=1`) | `stale scheduler claim` **absent** | guard fires, no claim orphaned |
| `smoke-switch-commit-control` (+ `SWITCH_COMMIT_EARLY=1`) | `stale scheduler claim` **present** | **every boot** |

**Deterministic, not a soak.** `KSP_GUARD_INJECT` forges the bogus resume value, so the pair
reproduces on every boot where the natural event runs at ~3%. That is the difference between a
gate and a campaign — and this finding has cost two of the latter.

**It did not close [G-9].** The natural rate went 2–4% → **2 in 130 (1.5%)**, which is not
statistically distinguishable from where it started. One cause is removed and gated; another
path is still leaking, with the same claim site and no chokepoint hit. Recorded in
`docs/investigations/G-09-scheduler-claim-leak.md` rather than rounded up here.

---

## The claim-release invariant — a CPU in ring 3 owes no deferred release

**`smoke-claim-release`, required job `claim-release`.** Since **[G-8]**, a switch path holds the
outgoing task's claim until the CPU has left that task's kernel stack, and drops it from
`sched_release_deferred()` on the ISR epilogue. If any route to ring 3 skips that call, the claim
is stuck forever: every selection loop skips a claimed task, so it becomes unschedulable by every
CPU **including its holder**. That is **[G-9]**'s shape.

**The periodic claim audit structurally cannot catch this.** `sched_assert_claims()` deliberately
exempts a task whose holder's deferred slot names it — correctly, because such a claim is
mid-handover rather than leaked. An *unpaid* debt therefore hides inside the very exemption that
keeps the auditor honest, and surfaces ~10ms later at whatever site happens to run the next audit.
That is why every report for this finding has named `preempt_on_tick`, which had nothing to do
with it.

So the debt is checked where it is provably settled instead: at ring 3. Every route there goes
through an epilogue, so a CPU observed in ring 3 owing a release means some path reached user mode
without paying.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-claim-release` | the guard stays **silent** through a boot to ring 3 | passes; measured 0 in 30 |
| `smoke-claim-release-control` (`CLAIM_RELEASE_SKIP=1`) | `ring 3 reached with a deferred release outstanding` **present** | fires on boot 1, naming the owed task |

It found one real hole immediately: `sched_enter_user()` carried a second hand-written copy of the
ISR epilogue that omitted the release call. Latent in this workload — `CLAIM_TRACE=1` shows the
path is never reached owing a debt — but it orphaned both the claim and the task's
`g_kstack_inflight` bit, and a stuck inflight bit makes the **[G-8]** detector report a collision
that is not happening. Two copies of one sequence is what allowed it; this gate is what stops a
third drifting.

---

## The shared userspace runtime

### `smoke-vfs` — two servers, two mounts, one namespace

Roadmap 2.4's gate. `fs_server` is mounted at `/` and `dev_server` at `/dev`, and the assertions
are about **which server a path reaches** and **what it took to reach it**.

`dev_server` exists to be the other server. A mount table with one mount is unfalsifiable —
every path resolves to the same task, so "longest prefix wins" and "the capability decides, not
the path" cannot fail. It holds exactly one capability, the listen end of its own endpoint: no
object store, no boot modules, no user database. That asymmetry is the point of a per-mount VFS
and is not expressible in a monolithic one.

**Routing is checked by which server answered, not by a return code.** Under first-match the
`/` mount also matches `/dev/zero`, and the root filesystem has an inode 0 of its own — so it
does not fail, it answers about a different object. A return-code check would call that success.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-vfs` | `VFSTEST: PASS`, no `FAIL` | **14 checks**, read off the wire |
| `smoke-vfs-prefix-control` (`VFS_FIRST_MATCH=1`) | `FAIL wrong-server-answered` present | 4 checks fail — routing, inode, and `..` all break together |
| `smoke-vfs-mount-control` (`VFS_MOUNT_UNGATED=1`) | `FAIL mounted-without-a-capability` present | exactly 1 check fails — the arm is aimed at one property and hits one |

Both arms are deterministic properties of a build, not races, so three boots is corroboration
rather than evidence and one is the sample size that matters.

**The positive direction is in the same target** (`tools/check_gate_pairs.py` requires it): the
suite reads zeros through `/dev/zero`, keeps `/bin` on the root mount, and confirms `/devices`
does **not** match the `/dev` prefix — a plain string compare would route it to the wrong server.

### `smoke-passwd-probe` — the in-kernel ramfs is unreachable from ring 3

Roadmap 2.4's first gate, and it exists because of what orienting on 2.4 turned up: four paths
into the in-kernel ramfs authorised on cspace slot 3 with `SC_ANYTYPE`, which the legacy
`CAP_FRAME` in every task satisfies (**[H-3]**).

A ring-3 task runs as the ordinary uid-1000 account with no capability anyone delegated to it,
and asserts four refusals: it cannot open the file `kusers.c` writes the user database into,
cannot read bytes out of any ramfs fd, cannot create a file, and cannot list the store. The
harness changes a password before spawning it — the ordinary self-service operation any account
may perform on itself — because that is what puts the database into the ramfs at all.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-passwd-probe` | `PASSWDPROBE: PASS` present, no `FAIL` | passes; all four return `SYS_ERR_NOSYS` |
| `smoke-passwd-probe-control` (`RAMFS_SLOT3_GATE=1`) | `FAIL opened-the-user-database` present | passes; all **4 of 4 doors open**, and `smoke-passwd-probe` goes red under the same flag |

**The control arm reads out more than the base arm asks about**, which is why it prints what it
finds rather than only whether it succeeded: it recovered 24, 64 and 32 bytes from three
separate ramfs files and enumerated the store. A gate whose control arm only answers yes/no
would have reported one open door instead of four.

**What the finding did not disclose, and why that is luck.** The 32 bytes from the
user-database file are the trailing HMAC tag, not the `salt[16]` + `pass_hash[32]` records,
because `ramfs_write` takes no offset and rewrites from byte 0 on every call
(`docs/LIMITATIONS.md` §2.6). The hashes were one bug-fix away from being world-readable.

### `smoke-frame` — a frame capability names an object, and a delegate maps only what it holds

Roadmap 2.1's gate. Two ring-3 tasks and one physical page: `frametest` holds a `CAP_UNTYPED`,
retypes a `KOBJ_FRAME` out of it, maps it, and asserts every refusal the map path owes;
`framepeer` holds **nothing** except the `READ`-only capability `frametest` mints and grants
it, and proves both halves of what shared memory has to mean.

**The check the whole design turns on is the decoy.** Every task in this system is born
holding a `CAP_FRAME` in slot 3 — `READ|WRITE|EXEC`, object `USER_AREA_BASE`, installed by
`create_task`, identical in every task, asked for by nobody. It is the capability that made
**[C-1]** reachable when the dispatch table gated IPC on slot 3. Giving `CAP_FRAME` a meaning
put it back in play, so `frametest` calls `SYS_MAP_FRAME` on slot 3 on every boot and requires
a refusal. It is refused because a frame capability names an **index** into a table the kernel
populates and `USER_AREA_BASE` is not one — a bound, not an allowlist.

**Both directions in one target.** A gate that only ever refuses is satisfied by a kernel that
refuses everything, which is what `tools/check_gate_pairs.py` exists to reject, so the legal
path is exercised too: the frame is mapped, written, read back, and then read by the *other
task at a different virtual address*.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-frame` | `FRAMETEST: PASS` present, `FRAMETEST: FAIL` absent | passes, **3 boots in 3**; 17 parent checks + 5 peer checks, read off the wire |
| `smoke-frame-index-control` (`FRAME_INDEX_UNCHECKED=1`) | `FRAMETEST: FAIL legacy-cap-mapped` present | passes, **3 boots in 3**; `smoke-frame` goes red under the same flag |
| `smoke-frame-rights-control` (`FRAME_RIGHTS_UNCHECKED=1`) | `FRAMETEST: FAIL readonly-delegate-wrote` present | passes, **3 boots in 3**; `smoke-frame` goes red under the same flag |

Three boots rather than a rate over hundreds, and that is a claim about the defects rather
than about the effort: neither arm is a race. Both are deterministic properties of a build,
observed identically on every boot, so the sample size that matters here is 1 and 3 is
corroboration. Contrast `smoke-kstack-park`, where the underlying event is probabilistic and a
single green boot says nothing.

**The index arm reproduces the defect in its realistic form, not by deleting a check.** The
shortcut a frame-mapping syscall invites is to put the physical address in
`capability_t.object` and map it — one field, no table, no resolver — so that is what
`FRAME_INDEX_UNCHECKED=1` builds. Simply removing the range test would have made
`dyn_frames[0x400000 - 1]` a wild read that faults, and the arm would have measured the bounds
check crashing rather than the authority being wrong.

**The rights arm had to be re-aimed, and the first version could not have failed.** It was
written against the `have & want` intersection in `frame_pte_flags`: build the PTE from `want`
alone and see whether a `READ`-only delegate can write. It cannot, and neither can it under
the fix — because `cap_lookup(slot, rights)` has already refused unless the capability holds
at least every right requested, so `have & want == want` at every reachable call and the two
builds produce the same PTE. The arm now removes the **floor** instead, which is the thing
that actually decides. Recorded here because a control arm that cannot fail is indistinguishable
from one that works until somebody tries to make it fire.

### `smoke-libhorus` — libhorus keeps its bounds, and refuses rather than spins

Every freestanding userspace program — `init`, `shell`, `fs_server`, `console_server` and the
selftests — links `libhorus`. That sharing is a trade: before it, a bug in one program's
private `umemcpy` broke one program; now a bug in `libhorus` breaks all four servers at once.
The trade is only worth making if the shared copy is held to a standard the seven private
copies never were, which is what this gate is for.

A ring-3 task asserts the properties the call sites actually depend on: that every bounded
write stays inside its bounds (checked with a guard byte either side, because a length check
alone cannot see an off-by-one), that `n == 0` writes nothing, and that `ustrncpy` **always**
terminates — at exact fit, at truncation, and at `n == 1`.

**The one that is a security property.** `ipc_call_retry` must return a *permanent* IPC refusal
rather than retry it. `SYS_ERR_PERM` means the caller holds no capability for that endpoint,
and the pre-libhorus loop — `while (r < 0) spin_delay();` — spun on it forever, turning the one
event the capability system exists to make visible into an indistinguishable hang. That is
finding **[G-8]** signature C. Until now the property was asserted by comments in two programs
and tested by nothing; the selftest calls into an empty capability slot and requires the call
to come back.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-libhorus` | `LIBHORUS_SELFTEST: PASS` present | passes |
| `smoke-libhorus-retry-control` (`LIBHORUS_RETRY_ANY=1`) | pre-call line present, `PASS` **absent** | passes; `smoke-libhorus` **times out** under the same flag |
| `smoke-libhorus-strncpy-control` (`LIBHORUS_STRNCPY_UNTERMINATED=1`) | `FAIL strncpy-truncate-unterminated` present | passes; `smoke-libhorus` **goes red** under the same flag |

**A test for a hang cannot be an equality check**, which is why the retry arm asserts an
*absence*. Under the defect the call never returns, so there is no value to compare — the
assertion has to be that the marker which follows it never appears. Same shape as
`smoke-kfault-legacy`.

**The migration's own witness was the existing suite.** `libhorus` was extracted from 22
hand-copied definitions, deliberately verbatim, so that each program's diff is a deletion plus
an `#include` and no call site changes meaning. `smoke-fs`, `smoke-fs-perms`, `smoke-console`,
`smoke-recvblock`, `smoke-init-fs`, `smoke-captest` and `smoke` are what hold that claim up.
One of them earned its keep immediately: `smoke-fs` caught a name collision in `fsclient.c`
that the default build does not compile at all, because `fsclient` is only built under
`FS_SELFTEST=1`. A green `make` says nothing about the programs `make` does not build.

---

## Where the binding coverage lives

There is deliberately no host-side C test directory. `tests/` held one 20-line file until
2026-08-21, and it was a tautology: it defined its own `struct capability` and its own
`cap_lookup` and then tested those. The kernel's `capability_t` has a `uint64_t object` and a
`generation` field — the use-after-revoke backstop — and the copy had neither, so no kernel
regression could have failed it. `tests/README.md` had also claimed `make test` ran it, which
nothing did. A test that cannot fail is not a test, and one that exercises none of the system
is not a test of the system.

Anything algebraic belongs in the Rust crate, where it can also carry a Kani proof; anything
touching kernel state belongs in a QEMU self-test. The binding suites are:

| Suite | Location | Run with |
|---|---|---|
| Capability algebra unit tests | `rust/src/capability.rs` | `cargo test --manifest-path rust/Cargo.toml` |
| Kani proofs (revocation subtree) | `rust/src/` | `cargo kani` |
| FFI boundary fuzzing | `rust/fuzz/` | `cargo +nightly fuzz run <target>` |
| Kernel integration self-tests | `src/kernel/selftest.c`, `userspace/` | `make smoke-<name>` |
| Capability conformance (100 checks — the suite prints its own count as `CAPTEST: PASS <n> checks`; read it from there) | `userspace/captest.c` | `make smoke-captest` |
| Scripted shell sessions | `tools/*_session.py` | `make smoke-session` |

---

## Writing a new test

1. Decide which layer it belongs to. Algebraic properties → Rust unit test or Kani proof.
   Kernel behaviour → QEMU self-test. End-to-end user-visible behaviour → scripted session.
2. For a self-test: add a `*_SELFTEST`-guarded routine that prints `NAME: PASS`, and a
   `make smoke-name` target that boots it and greps for the marker. Copy an existing target.
3. **Make it adversarial where you can.** Assert the refusal, not just the success.
4. Reference it in your PR body and in the invariant statement (see `CONTRIBUTING.md`).
