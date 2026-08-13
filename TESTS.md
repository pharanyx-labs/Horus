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
| `smoke-captest` | **96 checks**: an unheld capability is refused; a revoked capability cannot be used; a stale snapshot fails revalidation; minting into a kernel-reserved slot is refused; bad input is rejected. Twelve cover capability-addressed IPC (finding C-1), twenty-two cover untyped memory and retyping (finding I-7), four cover the one-shot reply capability and five the blocking receive (roadmap 1.3) — see below. The central conformance suite. |
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

**Status: open. The CI job is advisory, not gating.** As of 2026-08-13 the *proximate*
mechanism is established and proved — a corrupted resume `%rsp` reaching `iretq`, see the
capture below — but the **origin of that value is not**, so the finding stays open.

`smoke-session-smp-soak` fails at roughly **2–3% per boot** on current `main`:

| Where | Result | Signature |
|---|---|---|
| `e8cc850`, pinned to two host cores | **1 hang in 45** | not captured (main's soak discarded it) |
| CI runner, PR #117 pre-rebase, run 12/15 | **1 hang in 15** | **A** — 9 checks, stalled at `apropos` |
| CI runner, PR #117 rebased, run 39/45 | **1 hang in 45** | **B** — 0 checks, stalled at **boot** |
| CI runner, `smoke-fs-persist` (2026-07-31) | intermittent | **C** — **uniprocessor**, stalled after fs provisioning |
| CI runner, `smoke-fs-conc` (2026-08-09) | intermittent | **C** — identical |
| `ba84e90` local, `-smp 4`, logs preserved (2026-08-13) | **1 fail in 150** | **A** — 6 checks, stalled mid-`man`; `#GP` at `iretq`. First fully symbolised capture |

**Three distinct signatures have been observed, and they are not the same failure.**
Signature C is not even an SMP problem — those boots report `smp: uniprocessor, 1 CPU`.

**Signature A** — the session gets 9 of its 12 checks in, then a command's output stops
partway through a line and the shell never returns to its prompt:

```
[ok] apropos finds pages by keyword
SESSION_TEST: FAIL — timeout after 120s waiting for 'root@horus#'
recent serial: "...apropos directory\r\n  ls  (1)  list directory entries\r\n ... rm          "
```

**A new observation, 2026-08-11 (PR #127 CI, 1 hang in 45 — the documented rate).** The same
signature, captured with one more line of context than before, and that line changes what it
is:

```
[ok] whatis prints the one-line summary
SESSION_TEST: FAIL — timeout after 120s waiting for 'mkdir'
recent serial: "...root@horus# apropos directory\r\n\r\n  ls   (1)  list directory entries\r\n
                  cd     init: shell exited, relaunching\r\n"
```

**The shell exited.** `init` noticed and relaunched it — that message is `init` doing its job,
not a stall. So the wording above ("the shell never returns to its prompt") describes the
symptom accurately but implies the wrong mechanism: this is a ring-3 process dying mid-write
and being restarted, not a livelock or a lost wakeup. The harness then times out because the
relaunched shell is not logged in, so nothing answers the next command.

That is a **substantially more tractable** bug than a hang: a task that exits has a reason —
a fault, an unhandled signal, an `exit()` path — and the kernel can be made to say which. It
also explains why the truncation always lands mid-line: the writer stopped existing partway
through a `write`.

Not yet a diagnosis, and deliberately not written up as one: it is one capture, the exit
reason was not recorded, and it does not obviously account for **signature B** (which never
reaches a login prompt at all, so there is no shell to exit). **The next step on G-8 is to
make `init` report *why* the shell exited** — status, and whether it faulted — rather than
that it did. That is a small change to `init` and the wait path, and it converts this
signature from a timeout into an error message.

*Two earlier readings of stalled sessions were wrong in this same area* — a split prompt read
as a hung kernel, and frozen audit counters read as a wedge (see `docs/ROADMAP.md` §1.1). Both
were "the observer failed", and this one is "the observed process died". None of the three was
the livelock the finding was originally filed as. Weight the livelock hypothesis accordingly.

**That instrument now exists (2026-08-11). It has not yet caught a G-8 boot.**

`SYS_TASK_EXIT_INFO` (93) records why a task died and hands the record to its `SYS_WAIT`
supervisor; `init` prints it in band, through `console_server`, as

```
init: shell exited: faulted on memory access at addr=0x... rip=0x... err=0x...; relaunching
```

instead of the bare `init: shell exited, relaunching`. Every `task_teardown` call site must
now state a cause (`TASK_EXIT_NORMAL` / `KILLED` / `SIGNAL` / `FAULT` / `PAGEFAULT`), so a task
can no longer disappear without saying why. **This is a mechanism, not a diagnosis** — nothing
below is a claim about what G-8 *is*.

*Why the kernel was silent, which is worth recording on its own.* The generic ring-3 trap path
already printed `[task N '<name>' killed: ...]` — but `print()` only appends to the klog once
ring-3 `console_server` owns the console (`terminal.c`), so during a live session that line
never reaches the wire. The ring-3 **`#PF` kill path printed nothing at all**: its banner is
gated on a ring-0 / task-0 fault. A shell killed by a page fault mid-`write` was therefore
completely silent, which is exactly the observed signature. Writing it at the UART anyway is
finding #126, so the record is read out in band instead — the same fix shape as roadmap 1.1
step 2b.

*One thing this already narrows, from source rather than from a capture.* `handle_command()`
holds the shell's only `sys_exit()` (`userspace/shell.c`), and it is reached from exactly one
call site — which intercepts `exit`/`logout` first and turns them into a **logout**, not a task
exit. **The shell has no reachable voluntary exit path.** So signature A's `init: shell exited`
cannot have been a clean `sys_exit`: it was a fault, an uncaught signal, or a kill. The new
line will say which.

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

**First soak on the instrumented build: the instrument did NOT fire. Read this before
assuming signature A is solved.** PR #130's CI soak hung 1 in 45 — the documented rate — at
run 10/45, 6 checks in, truncating mid-line during `man ls`:

```
SESSION_TEST: FAIL — timeout after 120s waiting for 'ls - list directory entries'
recent serial: "...root@horus# man ls\r\n\r\nls(1)          "
```

**No `init: shell exited:` line anywhere**, and nothing further arrived in the whole 120 s
window. That is *not* the #127 capture repeated: there, `init: shell exited, relaunching`
appeared inline. Two readings remain open and this capture does not separate them:

1. **Signature A has more than one mechanism** — this boot's shell did not exit, so the #127
   capture was one member of a set, not the signature; or
2. **the shell did exit and `init`'s report never got out** — in which case the *reporting
   path* is what to investigate (init writes through `console_server`, so a console_server
   that is itself stuck would swallow the line).

Reading 2 is the one to rule out first, and it is the same lesson as every earlier G-8
misreading: **check the observer before the observed.** An instrument that is silent proves
nothing until it is known to be capable of speaking on that path — `proctest` proves the
kernel-side record and the rendering, but nothing yet proves `init` can get a line out at the
moment the shell dies under SMP. Do not quote the absence of the line as evidence the shell
did not exit.

#### The one datapoint G-8 has, and why its `rip` must be withdrawn

After #138 made `init`'s report reach the wire, CI's soak produced the first — and so far
only — recorded cause:

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
2. **The floor guard dominates the `out->cs` read** — `cmp`/`jae` sit immediately above it,
   on `%rbp`, in a register. So "`out` is near-null there" was never available as a mechanism
   while that guard is compiled in, whatever the `rip` had said.
3. **That `rip` is exactly where an interrupt would land.** An interrupt pushes the address of
   the *next* instruction, and `ISR_NOERRCODE64` pushes `err_code = 0` — matching `err=0x0`.
   The frame the fault handler read looks like an **IRQ frame**, not a `#PF` frame.

So the live question is no longer "what dereferences `0x94`" but **"why was `#PF` handling
running against a frame that is not the fault's frame?"** — a `CR2` genuinely from one event
and an `int_no`/`rip`/`err_code` from another. That is a considerably better lead, and it is
also a warning: the exit record is assembled from `CR2` (a register) and `f64->rip` (memory),
and nothing checks that they agree.

The report now prints the frame's own `vec` and `errc` beside the handler's `CR2`, so the next
occurrence answers that question in the capture instead of a year later. A healthy fault reads
`vec=14 errc=0x0` next to `PAGE FAULT at ...`; the injected one in `make smoke-kfault` shows
exactly that, which is what makes a disagreement legible when it appears.

#### One hypothesis that covers both open kernel-fault signatures

**Two CPUs executing on one kernel stack.**

- A `#PF` handler reading a frame whose `rip` and `err_code` belong to a *different* trap —
  the datapoint above — is what a concurrent push by another CPU into the same frame region
  looks like.
- A trap frame that `iretq`s into a kernel stack address (`err=0x11`, `rip` and `rsp` 0x80
  apart in the same region) — the fault holding roadmap 1.1 in PR #135 — is the same
  corruption once it reaches the `rip` slot.

Neither needs a second mechanism, and both are SMP-only, which fits: #135's boot-only harness
saw 0/20 at `-smp 1` on both lock arms and only ever saw the fault at `-smp 4`.

The invariant at stake is the one in `scheduler.c`: `task_running_cpu[t] == c` ⟺
`percpu_current_task[c] == t`. A fault is exactly the moment to ask whether it still holds, so
the fault report now dumps it:

```
claim: task 3 running_cpu=0  percpu_current=[3,0,0,0]  imp=[0,0,0,0]
```

That runs **only from a fault report**, which is deliberate. The previous attempt to attribute
this fault (PR #137) checked the resume `%rsp` on *every interrupt return* and raised the
failure rate it was meant to explain — 4/30 shell restarts against 0/30 for `main`. A
diagnostic that runs only after the failure cannot perturb the thing it measures. This is a
hypothesis with a test attached, not a diagnosis; the next capture either shows a violated
claim or rules the hypothesis out.

**The general lesson, for the third time in this file: symbolise against the binary that
produced the address.** #138's comment read the same `rip` as landing mid-instruction and
inferred a return address; this reading found it a clean boundary and inferred a load. Both
were done against rebuilt trees. The artifact was available from CI the whole time.

#### The first capture taken with the report audible (2026-08-13)

#140 made kernel fault reports reach the UART instead of the klog. Run against `ba84e90` at
`-smp 4`, keeping **every** failing run's full serial log — `smoke-session-smp-soak` reuses one
temp log, overwrites it per iteration, deletes it at the end and prints only `tail -20`, so it
would have discarded this — the fault appeared **once in 150 boots**:

```
64-bit EXCEPTION vector=13 err=0x4388 task=0 ''
  vec=13 errc=0x4388
  rip=0xffffffff8011cc03 cs=0x8 rflags=0x10086
  rsp=0xffffffff8010e8e2 rbp=0xcbe8c35c415d5bc9 cpu=0
  claim: task 0 running_cpu=-1  percpu_current=[0,0,0,3]  imp=[0,0,0,0]
```

Symbolised against the binary that produced it (sha256 pinned before the run; no rebuild
between capture and analysis): **`rip` is exactly the `iretq` in `isr_common_stub64`** — not
near it, the instruction itself.

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

That is a reconstruction, so it was checked rather than believed. If it holds, the stub's
eighth pop (`pop %rbp`) drew from `resume_rsp + 64`. The bytes at that address in the pinned
binary are `c9 5b 5d 41 5c c3 e8 cb` — little-endian **`0xcbe8c35c415d5bc9`**, which is
*exactly* the `rbp` in the report. A 64-bit match is not coincidence: the reconstruction
predicts an observed register and gets it right, so the GPRs demonstrably were loaded from
`syscall_handler`'s own instruction stream.

**The error code confirms it a third time, from an independent observable.** After the pops
and `add $0x10`, `iretq` reads its frame from `R+136`, so `CS` comes from `R+144`. The bytes
there are `…4389`. A `#GP` selector error code carries the index in bits 15:3 with the
EXT/IDT/TI flags below, so selector `0x4389` — index `0x871`, RPL 1 — encodes as
`0x871 << 3 = 0x4388`: **exactly the reported error code**, with the RPL bits dropped precisely
as the encoding specifies.

Three independent quantities now agree on the same resume value: the faulting instruction,
`rbp` read from `R+64`, and the `#GP` error code derived from `R+144`. Index `0x871` is far
past any real GDT entry, which is why the `iretq` faulted rather than returning somewhere
plausible and corrupting silently.

##### Why the floor guard did not catch it

`idt.c` has had a guard for exactly this since #123:

```c
if (rsp < 0xFFFF800000000000ULL) { /* PANIC: dispatcher returned a bogus resume rsp */ }
```

`0xffffffff8010e85a` **is** higher-half, so it passes and reaches the `iretq` unchallenged. The
guard tests *"is it higher-half"* where the property it needs is *"is it inside a live kernel
stack"* — necessary, not sufficient. A `.text` pointer satisfies the first and fails the second.

##### What this changes, and what it does not

It reframes the hypothesis above rather than confirming it. This is **not** a smear of
corrupted memory: one specific *value* — a return address — arrived where a stack *pointer*
belongs. A one-word value/pointer confusion does not require two CPUs writing one stack, so
`-smp 4`-only is no longer evidence for that mechanism specifically.

And the claim dump **did not discriminate here**. `scheduler.c` scopes the invariant to
`t > 0`; this capture is `task 0`, the idle/reaper sentinel — which `percpu_current=[0,0,0,3]`
confirms, three CPUs "on" it at once — so `running_cpu=-1` is outside the invariant's scope,
not a breach of it. Worth recording as a property of the instrument: **the claim line answers
the question only for `t > 0` faults**, and this one was not. A `t > 0` capture is still needed
to decide the two-CPU hypothesis either way.

One number to quote carefully: **1 in 150 is not a rate.** §5.2c documents ~2–3%; under a true
2.5% rate, seeing ≤1 event in 150 boots has probability ~11%, so this is the low end of the
documented range and not evidence of a change. Cite it as "1/150 observed". #126 is the
standing reminder of what a number stated past its evidence costs.

Next: `tasks[t].saved_ksp` is only ever assigned `frame_rsp` (`scheduler.c`), and callers pass
`(uint64_t)frame` — a stack address. Find the write that puts a return-address *value* there.
The fault landed mid-`man`-render with a `PAGE FAULT at 0x3` immediately after, so the
shell-fault teardown path is live in the same window, and `tasks[0].kernel_stack_top` is what
the `#PF` handler resumes on when it kills a task and finds no successor.

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

### `make smoke-irq-policy` — the boot interrupt policy, written down

**Roadmap 1.1 step 2.** The kernel's boot-time interrupt enablement is currently an *emergent*
property of a locking defect rather than a stated design: `spin_unlock`'s unconditional `sti`
turns interrupts on as a side effect of the first lock any syscall takes (**[C-3.1]**). This
gate records IF at named boot milestones and asserts it.

| Milestone | IF |
|---|---|
| `post-idt` | 0 |
| `post-paging` | 0 |
| `post-protections` | 0 |
| `kernel-ready` | 0 |
| `first-syscall-entry` | 0 |

**The expectations are measured, not designed.** They are what the kernel does today, written
down so a change cannot arrive silently. Encoding a policy nobody has implemented would make
the test fail on a correct kernel — the failure mode this document keeps warning about.

All zero is the whole point: every syscall starts with interrupts masked (the `int 0x80` gate
clears IF), so the first lock a handler releases turns them on for the rest of that syscall.
That is why **[C-3.1]** is load-bearing, and it is measurable — `IRQ_POLICY_AUDIT=1` identifies
the depth-zero releases that enable interrupts the caller had masked, over seven sites, all of
them syscall-context lock users.

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

When step 3 lands the IF-preserving lock, some of these values will change. That is the
intent: the diff will have to say which, rather than the startup handshake quietly acquiring or
losing preemption windows the way it did on 2026-07-27.

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
irq-policy: accidental_sti=1439 benign_sti=720 sites=7 @tick=693
```

with `cap_install_object` (685) and `cap_consume_slot` (684) accounting for **95%** — both on
the IPC path, both scaling with message traffic, while the other five sites are fixed
boot-time costs.

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

## Can the kernel be heard when it faults?

| Target | Proves |
|---|---|
| `smoke-kfault` | A page fault taken at **CPL 0** is reported on the **serial line**, after the console handover. `KFAULT_INJECT=1` makes the kernel fault on purpose — a read of `0x94`, G-8's exact address — on a timer tick once `console_server` owns the console, and the harness requires the report to appear *after* the login prompt. |
| `smoke-kfault-legacy` | The same injection with reporting restored to `println()` (`KFAULT_LEGACY_PRINTLN=1`): the report must **not** reach serial. The control arm. |

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
