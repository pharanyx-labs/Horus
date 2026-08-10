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
| `smoke-captest` | **88 checks**: an unheld capability is refused; a revoked capability cannot be used; a stale snapshot fails revalidation; minting into a kernel-reserved slot is refused; bad input is rejected. Twelve cover capability-addressed IPC (finding C-1), twenty-two cover untyped memory and retyping (finding I-7), and four cover the one-shot reply capability (roadmap 1.3) — see below. The central conformance suite. |
| `cargo test` (`rust/src/capability.rs`) | Mint masks rights and cannot widen them; transfer shares lineage; system-wide revoke reaches another task's cspace; an unrelated capability survives; primordial roots cannot be revoked; the generation counter skips the pristine sentinel on wrap; serial allocation never yields 0 or a reserved value. |
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

| Build | Runs (pinned, 2 host cores) | Failures |
|---|---|---|
| before | 20 | **10** |
| after | 30 | **0** |

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

### Open finding G-8: the SMP session soak is not clean, and nobody knows why yet

**Status: open, mechanism not established. The CI job is advisory, not gating.**

`smoke-session-smp-soak` fails at roughly **2–3% per boot** on current `main`:

| Where | Result | Signature |
|---|---|---|
| `e8cc850`, pinned to two host cores | **1 hang in 45** | not captured (main's soak discarded it) |
| CI runner, PR #117 pre-rebase, run 12/15 | **1 hang in 15** | **A** — 9 checks, stalled at `apropos` |
| CI runner, PR #117 rebased, run 39/45 | **1 hang in 45** | **B** — 0 checks, stalled at **boot** |
| CI runner, `smoke-fs-persist` (2026-07-31) | intermittent | **C** — **uniprocessor**, stalled after fs provisioning |
| CI runner, `smoke-fs-conc` (2026-08-09) | intermittent | **C** — identical |

**Three distinct signatures have been observed, and they are not the same failure.**
Signature C is not even an SMP problem — those boots report `smp: uniprocessor, 1 CPU`.

**Signature A** — the session gets 9 of its 12 checks in, then a command's output stops
partway through a line and the shell never returns to its prompt:

```
[ok] apropos finds pages by keyword
SESSION_TEST: FAIL — timeout after 120s waiting for 'root@horus#'
recent serial: "...apropos directory\r\n  ls  (1)  list directory entries\r\n ... rm          "
```

**Signature B** — nothing runs at all. Boot never reaches the login prompt:

```
SESSION_TEST: FAIL — timeout after 90s waiting for 'horus login:'
recent serial: "...init: starting, launching shell\r\n
                [console_server] ready (ring-3; owns serial + VGA framebuffer)\r\n\r\n"
```

**Signature C is diagnosed — and the first diagnosis of it, published here, was WRONG.**

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

— and dumps 2 and 3 are **byte-identical** in those instruction pointers. Two facts follow,
and between them they exclude contention outright:

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

With an empty capability slot every call returns `SYS_ERR_PERM` (**-1**) — a permanent
condition — into a loop that treats every negative as transient. `SYS_ERR_PERM` is -1 and the
retryable code is -2; they were always distinguishable, and nothing distinguished them.

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
| race restored, retry discipline kept | 30 | **2 hit the race, 0 silent hangs** — every one reported `FAIL ipc-refused rc=-1` |

That third row is the important one: it proves the two halves independently. The connect retry
is what removes the failure; the retry discipline is what converts a silent unkillable hang
into a diagnosable message, so the *next* bug of this shape costs minutes instead of a day.

*The lesson, which cost a published wrong answer.* "All tasks runnable, nothing blocked" is
consistent with contention **and** with nobody ever having started — and the first reading
picked the interesting hypothesis over the boring one without an observation that could
separate them. The endpoint dump was the observation. **A rate is not a mechanism, and neither
is a plausible story about one.** This is the fourth wrong hypothesis about intermittent
failures in this repo, and the first that was written into the docs before it was tested.

**Signature C** — a **uniprocessor** boot that stops dead once the filesystem is up. It has hit
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

**What it is not.** Not the IPC lost-reply race — `#116` is present in every tree measured.
Not caused by PR #117, which changed no kernel source. And **not** simply the `apropos` budget:
that remains a plausible explanation for signature A (the note on `smoke-session-smp` in the
`Makefile` records that same step already forcing `SESSION_TIMEOUT` from 60s to 120s on a
loaded runner *with no code fault*), but it cannot explain B, where zero commands ran.

**A rate is not a mechanism** — and neither is one capture. This repo has now made that
mistake in both directions: `smoke-console-smp` was a real deadlock dismissed as flaky, and
the `SCHED_INVARIANTS` report above was a correct kernel accused of a defect, which blocked a
roadmap item for a fortnight. The first draft of *this* finding then guessed "slow `apropos`"
from a single capture, and the very next capture falsified it. Three guesses, three wrong.
Hence: signatures recorded, mechanism explicitly not claimed.

**Why advisory rather than gating.** At ~3% per boot, `SOAK_RUNS=15` reddens roughly a third
of all CI runs. A required check in that state teaches everyone to hit re-run, which is
precisely the reflex that let the console-smp deadlock survive months of CI. A gate nobody
believes is worse than an advisory job somebody reads. `SOAK_RUNS` is raised to 45 in CI so
the advisory job actually witnesses the thing it is reporting (~75% of runs, against ~37% at
15). **Restore it to gating in the same commit that resolves G-8 — either way — and quote a
rate, not a green run.**

**Capturing the failing run is what made this legible.** The soak used to send every run to
`/dev/null` and trust the exit status. It now keeps the failing run's output — and the first
CI run after that change produced signature B, which overturned the finding's own initial
hypothesis within hours. A soak that reports only `FAIL` would have left "slow `apropos`" on
the page indefinitely.

**The next experiment, in order:**

1. ~~Run `smoke-sched-invariants-stress` at a sample size matched to ~2%.~~ **Done
   2026-08-09: 150 boots pinned, 150 pass, no `PANIC`.** At a 2% event that is >95% detection,
   so **the claim invariant is intact and none of these hangs is a leaked claim.** The
   console-smp fix is not incomplete in that respect, and the scheduler's claim bookkeeping is
   excluded as a cause. (30/30 would *not* have supported this conclusion — 30 boots witness a
   2% event less than half the time. The sample size is the whole argument.)
2. **Signature C first, because it is the cheapest and it gates merges.** It is uniprocessor,
   so the entire SMP surface is irrelevant: no claim leak, no cross-core wake, no CPU-idle
   handoff. That removes most of the search space at zero cost. Suspect the fs_server request
   path or the `FS_SELFTEST` driver immediately after provisioning.
3. **Get the kernel's own view at the stall** for A and B. Whether `console_server` is blocked
   in `recv` and the shell in `SYS_IPC_CALL` separates a lost wake from a scheduling stall.
4. **Only then** decide whether signature A is the same bug arriving later, or genuinely the
   `apropos` budget. Do not fold them together until the evidence does.

**`HANG_WATCHDOG=1` — because signature C leaves no log to read.** The clients in
`smoke-fs-conc` print *nothing* on the happy path: a passing boot is
`[fs_server] filesystem provisioned` followed directly by `CONC_SELFTEST: PASS`. So a wedged
boot and a merely slow one produce **byte-identical serial logs** — 120 seconds of silence —
and no amount of staring at CI output can separate them. That is the same "a test that cannot
distinguish two states is not evidence" defect as **[I-11]**, arriving as an absence rather
than a race.

The watchdog dumps the scheduler's view of every task once a boot passes
`HANG_WATCHDOG_TICKS` without finishing, then **lets the boot continue** — halting would stop
a merely-slow boot from going on to pass, and "it would have finished given another second" is
precisely the hypothesis under test. The harness's own timeout still fails the boot; this only
makes the log say why. Enabled on `smoke-fs-conc` and `smoke-fs-persist` (the two targets
showing signature C) at 6000 ticks, inside a 120s budget. Compiled out of the ship kernel.

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
| every task `state=1`, none blocked | nobody is stuck — the run was slow, fix the budget |
| a task `state=2/3/4` with no peer to wake it | a lost wake or dropped reply |
| a task `state=1 rctx=1 ksp=1` never selected | a scheduling bug |

**A gate must assert the property it is named for.** `smoke-sched-invariants-stress` originally
failed on *any* failed boot, so a hang that never tripped the checker reddened a job whose
entire claim is "the claim invariant holds" — silently converting a precise gate into one that
inherits every intermittent in the system, which is the exact defect this section documents. It
now runs with `STRESS_GATE=marker`: a `PANIC` fails it, a boot that hung without one is
reported loudly as a G-8 datapoint and does not gate. The stress harness also **prints** the
failing serial log rather than only saving it to a file — a gating job failed 1-in-30 on CI
with the one artifact needed to diagnose it sitting in a workspace that was then deleted.

## Memory protection and isolation

| Target | Proves |
|---|---|
| `smoke-wx` | The kernel image is r-x / r-- / rw-, and a sweep of **every leaf PTE** finds no writable-and-executable page. |
| `smoke-wx-smp` | The same under SMP, and that every AP's IST fault stack sits above an unmapped guard page. |
| `smoke-cpu` | SMEP and SMAP are detected **and actually set in CR4** — not merely attempted. Boots under `-cpu +smep,+smap`. |
| `smoke-percpu` | `this_cpu()`'s TSS-selector derivation agrees with the LAPIC **on every core that came online**, checked on each core as its TSS is loaded, and `EFER.SCE` is clear so the staged SYSCALL path stays unreachable. Needs ≥2 cores: on one CPU the mapping is right by accident, so a UP run fails rather than passing vacuously. |
| `smoke-aspace` | Rebuilding a task slot repeatedly returns every physical page to the pool — a dead task's address space leaks nothing. |
| `smoke-cow` | Copy-on-write breaks correctly for the shared zero page. |
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
| `smoke-fs-wal` | The write-ahead journal recovers a crash-interrupted write (two-boot test). **Known flaky and known weak — see below.** |
| `smoke-fs-conc` | Multiple clients are served concurrently without cross-talk, via `SYS_IPC_REPLY_TO`. Uses `CONC_TIMEOUT` (default 120s), not the 40s default: it waits on several clients, and on a loaded host it exceeded the shorter budget and failed as a *timeout* — never reaching a verdict, which reads red without being evidence of a defect. A real `CONC_SELFTEST: FAIL` still fails immediately. |
| `smoke-fs-large` | Double-indirect blocks address large files. |

> **`smoke-fs-wal` — two known defects (findings [I-10], [I-11]).**
>
> **It is nondeterministic.** The harness kills QEMU the moment boot 1's marker appears on
> serial, then reboots on the same image. The marker proves the guest *reached* that point,
> not that its journal writes completed — serial and IDE are independent paths, and
> `cache=writethrough` only makes *completed* writes durable. On a loaded runner boot 2 fails
> with `WAL_CRASHTEST: FAIL read` against an unmodified kernel. It is a **required** status
> check, so it blocks merges spuriously.
>
> **It cannot detect the bug it exists to catch.** The kernel issues no ATA `FLUSH CACHE`
> (0xE7) — ever. On real hardware the commit record can sit in the drive's volatile cache and
> be lost to a power failure. `cache=writethrough` hides this completely: the emulator
> supplies the durability the kernel omits. The test therefore verifies crash-atomicity in
> the one configuration where it is guaranteed by something other than the code under test.
>
> A green `smoke-fs-wal` is not evidence of crash-atomicity on hardware. Fixing it needs a
> `cache=writeback` variant *and* a real flush in the driver.

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
| `smoke-session-smp-soak` | `SOAK_RUNS` consecutive SMP sessions, **all** of which must complete. Gates the IPC lost-reply race (see CHANGES.md), which hung ~1 boot in 5 — a rate a single-boot test passes four times out of five, which is how it went unnoticed. One hang fails; there is no retry. Falsified at 2/10 hangs against the pre-fix kernel. Each run must also emit `SESSION_TEST: PASS` **and** clear `SOAK_MIN_CHECKS` (default 8) `[ok]` steps — a run that exits 0 having proven nothing is reported `VACUOUS` and fails, so the gate cannot go green on a test that stopped testing. **Currently ADVISORY in CI, not gating — see finding G-8 below.** |

## Build integrity

| Target | Proves |
|---|---|
| `reproducible-build` | `kernel.elf` is byte-for-byte identical across two clean builds. **A required CI check.** |
| `security` | Semgrep, Trivy, gitleaks, cppcheck, flawfinder, cargo-audit, plus a CycloneDX SBOM. Currently **advisory** (`continue-on-error`). |

---

## CI

`.github/workflows/ci.yml` runs roughly 30 jobs on every push and pull request;
`codeql.yml` adds C/C++ static analysis (advisory, plus a weekly schedule).

All third-party actions are pinned to full commit SHAs. Workflow `permissions:` blocks are
least-privilege. There are no self-hosted runners.

### A known weakness in the gate

Of those jobs, **21 are required status checks** — but the security-specific ones are not
among them. `smoke-captest`, `smoke-wx`, `smoke-cpu`, `smoke-tpm*`, `smoke-modules-tamper`,
`smoke-flush`, and `smoke-stackguard` can all fail while a pull request merges green.

The required set is inverted: functional tests block merges, security tests do not. This is
finding **[C-6]** and roadmap item 4.2. Until it is fixed, **run the security targets locally
before opening a PR** — CI will not stop you.

Additionally, `strict_required_status_checks_policy` is false, so a PR can merge having passed
CI against a stale base.

---

## Host-side tests

`tests/` holds host-compiled test code (`test_capability.c`) used for quick iteration on the
capability logic outside QEMU. The authoritative capability tests are the Rust unit tests,
the Kani proofs, and `smoke-captest`.

---

## Writing a new test

1. Decide which layer it belongs to. Algebraic properties → Rust unit test or Kani proof.
   Kernel behaviour → QEMU self-test. End-to-end user-visible behaviour → scripted session.
2. For a self-test: add a `*_SELFTEST`-guarded routine that prints `NAME: PASS`, and a
   `make smoke-name` target that boots it and greps for the marker. Copy an existing target.
3. **Make it adversarial where you can.** Assert the refusal, not just the success.
4. Reference it in your PR body and in the invariant statement (see `CONTRIBUTING.md`).
