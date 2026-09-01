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

Most follow one shape. A `*_SELFTEST` compile flag guards a routine in `src/kernel/selftest.c`
(or a ring-3 program in `userspace/`) that runs the check and prints `NAME: PASS` on the serial
console. A `make smoke-name` target builds that configuration, boots it headless under QEMU with
a timeout, and greps for the marker.

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
| `smoke-captest` | **180 checks**: an unheld capability is refused; a revoked capability cannot be used; a stale snapshot fails revalidation; minting into a kernel-reserved slot is refused; bad input is rejected. Twelve cover capability-addressed IPC (finding C-1), twenty-two cover untyped memory and retyping (finding I-7), ten cover "identity is not authority" (findings I-1 and H-1, run as uid 0), four cover the one-shot reply capability and five the blocking receive (roadmap 1.3), see below. The central conformance suite. |
| `smoke-auditprobe` | **13 checks**, from a task that is not `captest`. `SYS_READ_AUDIT` and `SYS_AUDIT_DIGEST` carry a real `CAP_AUDIT` in their dispatch rows, so the central gate refuses `captest` and its two checks naming them assert a refusal the **table** issued — the handler bodies had never run, which is the shape that hid issue #176. `userspace/auditprobe.c` is a second task in the `CAPTEST_SELFTEST` image, **uid 1000**, holding one `CAP_AUDIT` at slot 7 and nothing else; `captest`'s own cspace is untouched, because endowing the one task whose job is to hold nothing would trade the property for the number. It causes two audited events of its own — **denied capability grants**, refused by `h_cap_grant`'s authority check, so the log gains entries and the cspace gains nothing — then requires the digest's **count to advance and its chain head to move** across them, the records to come back with the fields where the caller declared them, and the two syscalls it does *not* hold a capability for (`SYS_DMESG`, `SYS_ROTATE_KEYS`) to be refused. Every call is made twice, once into a stack buffer and once into a static — statics are above 4 GiB by construction, stack buffers are not, which is the class distinction #176 turned on. **The audited event is a denied grant and not a denied mint, and the reason is a lesson rather than a detail:** the first version used `sys_cap_mint` against an empty slot, and `cap_mint`/`cap_transfer` are the only two callers of `kcap_lookup` — S52's halting assert. Under `CAP_LOOKUP_ASSERT_HANG=1` this probe wedged inside the syscall holding `cap_lock`, so `smoke-captest-mint-hang-control` failed because `captest` never reached the section-12 marker its `EXPECT_STALL` requires *first*. That arm was right and the probe was wrong. **Adding a task to a shared image changes which task reaches an existing arm's trigger**, so a new probe means re-running every arm in its job, not only the new ones. `h_cap_grant` audits from an authority check that runs before any lookup and uses `cap_lookup`, so it is inert under that flag. **5 boots in 5.** |
| `smoke-auditprobe-control` | Control arm, and issue **#176** on the wrapper it was named after. `SYSCALL_PTR_TRUNC32=1` narrows the caller's buffer pointer to 32 bits; marker `AUDITPROBE: FAIL digest-into-a-static-buffer`, **3 boots in 3**. The transcript carries the signature rather than merely a failure: `audit_digest(stack) -> 0` and `read_audit(stack, 2) -> 2` still succeed while every static call fails, which is #176 exactly and is what distinguishes this arm from a build that broke. It asserts the **bytes**, not the return code, because the truncation is not fail-closed — an address that happens to be mapped is written to and success is reported. |
| `smoke-auditprobe-abi-control` | Control arm for **S71**, the defect entering the handler found. `AUDIT_ABI_LEGACY=1` restores both divergent declarations of `struct audit_event` and the raw kernel-sized copy between them — both rings under one flag, because the defect is the disagreement rather than either side. Marker `AUDITPROBE: FAIL read-audit-wrote-past-the-array`, **3 boots in 3**, with `read-audit-did-not-return-our-own-event` beside it. The marker is the **overrun**, not the misread field: the stride the kernel writes at is part of the ABI and no return code can report it, so the probe reads into an array with a guard region immediately after it (one struct, not two statics — adjacency in `.bss` is a property of the linker, not the language) and requires the guard untouched. The array is **two** records, not sixteen: at the legacy 256-byte stride a sixteen-slot array needs eleven records before the write runs past it, and the probe makes two — a guard the defect cannot reach is a check that cannot fail. |
| `smoke-captest` | **180 checks**: an unheld capability is refused; a revoked capability cannot be used; a stale snapshot fails revalidation; minting into a kernel-reserved slot is refused; bad input is rejected. Twelve cover capability-addressed IPC (finding C-1), twenty-two cover untyped memory and retyping (finding I-7), ten cover "identity is not authority" (findings I-1 and H-1, run as uid 0), four cover the one-shot reply capability and five the blocking receive (roadmap 1.3), and six cover the installer's format authority (**S72**, section 15: both calls refused with exactly `SYS_ERR_PERM`, the survey buffer unwritten on the refusal, and a wrong-type capability minted into the gate's own slot refused too), see below. The central conformance suite. |
| `cargo test` (`rust/src/capability.rs`) | Mint masks rights and cannot widen them; transfer shares lineage; system-wide revoke reaches another task's cspace; an unrelated capability survives; primordial roots cannot be revoked; the generation counter skips the pristine sentinel on wrap; serial allocation never yields 0 or a reserved value. **[I-3]:** a subtree past the old 256-entry bound, and a 300-link chain, are revoked *exactly* while an independent peer sharing the same object survives, falsified against `--features=revoke_legacy_bounded`, which CI runs. |
| Kani proofs | Revocation nulls **exactly** the target's derivation subtree: no descendant survives, no non-descendant is touched. |

**The C-1 refusal checks, and why they are asserted precisely.** Twelve checks in
`smoke-captest` cover capability-addressed IPC: a `CAP_FRAME` (the pre-fix authorisation gate)
authorises no IPC operation; a WRITE-only client capability is refused `recv`, `reply_to`, and
`sender`; the interception and reply-forgery halves of the finding; endpoint and notification
capabilities do not authorise each other's operations; empty slots are refused.

Each asserts the **exact** code `SYS_ERR_PERM`, never merely "negative". `sys_ipc_recv` returns
`-2` for an empty mailbox, so a `< 0` assertion cannot distinguish "the kernel refused me" from
"I was allowed to read, and nothing was there", and under the pre-fix kernel these probes hit
empty endpoints and returned `-2`. The first draft of the suite used `< 0` and **passed with the
vulnerable handler deliberately restored**, proving nothing.

The fix was therefore verified by falsification: reintroduce the pre-fix handler, confirm the
suite fails (`CAPTEST: FAIL ipc-recv-on-unheld-slot-allowed`), restore it, confirm 41/41. **A
test that cannot fail on the bug it targets is not evidence**: the same defect class as
**[I-11]** in `smoke-fs-wal`.

**The "identity is not authority" checks (section 4b, findings [I-1] and [H-1]).** Ten checks,
run deliberately as **uid 0**, assert that the most privileged identity in the system buys
nothing without the capability: `dmesg` without `CAP_KERNEL_LOG`, boot-module info/read
without `CAP_BOOT_MODULE`, `fs_stat`/`inode_alloc` without `CAP_ENCRYPTED_STORAGE`,
`useradd`/`userdel`/`passwd`-of-another-user without `CAP_USER`, and cross-task
`get_task_info` without `CAP_USER` or `CAP_AUDIT`.

The last four are new on 2026-08-15 (**[H-1]**). There was previously no `useradd` probe at all:
the suite covered the properties that had been enumerated when **[I-1]** was closed, and the
user database was not among them, so the ambient gate in `kusers.c` survived a suite whose whole
purpose was to prove it gone. One of the four (cross-task `get_task_info`) is not new so much as
*resurrected*: it sat in section 1 behind `if (sys_getuid() != 0)`, and captest runs as uid 0,
so it had never executed on any boot. Dead code that read as coverage.

**Falsification.** With the `uid == 0` fallback reintroduced into `current_user_is_admin()`
(`kusers.c`) and nothing else changed, `make smoke-captest` reports
`CAPTEST: FAIL useradd-allowed-by-uid0-without-CAP_USER`. Restored: `CAPTEST: PASS 100
checks`. Measured on the same tree, the count went **96 → 100**.

**The second witness is `smoke-session`, and it is the stronger one.** `smoke-captest` proves a
task without `CAP_USER` is refused; it cannot prove the ambient gate was doing real work.
`smoke-session` does: with the fallback deleted and no other change, the session test went red
at `[ok] useradd allowed for root`, because `launch_shell` had never delegated `CAP_USER` and
the shell's `useradd` had been running on the ambient gate alone. `init` now delegates it and
the shell enforces the per-user half, so the session asserts both directions, root may add a
user, a standard user is refused with `useradd: permission denied (root only)`. That expected
string is deliberately more specific than the old `useradd failed`, which would also match an
*authorised* useradd that failed on its arguments.

*A hypothesis recorded and withdrawn.* The first draft of this change assumed captest had been
silently holding `CAP_USER` through `do_spawn_inner`'s propagation, and added a step to the
harness to clear slot 6. It had not, and the step was removed: the refusals pass identically
with and without it, because the propagation calls `cap_lookup(6, …)` after
`load_staged_image_into` has made the child current, so it reads the child's own empty cspace
and never fires (`kspawn.c`, `do_spawn_inner`).

**The I-7 untyped-memory checks.** Twenty-two checks cover `CAP_UNTYPED` and `SYS_RETYPE`, and
unlike the C-1 set they deliberately run in **both directions**. `captest` is endowed with a
real `CAP_UNTYPED` (`captest_selftest`), so the suite asserts that a held capability actually
creates usable, mutually distinct endpoints: a refusal-only suite would be passed by a kernel
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
hold, and it is the one a *server* uses, which is where interception matters. Five checks in
`smoke-captest` cover it, plus the dedicated `smoke-recvblock`.

Four gates were falsified, each in isolation:

| Removed / changed | Check that fired |
|---|---|
| the block itself (return `IPC_AGAIN` on an empty queue) | `recv-block-returned-IPC_AGAIN` |
| `cap_install_reply_for` on the wake path | `woken-server-holds-no-reply-right` |
| the server made a *polling* receiver instead | `server-polled-instead-of-sleeping` |
| the `CAP_RIGHT_READ` requirement | `recv-block-allowed-with-write-only-client-cap` |

The third is the one worth keeping: it falsifies the **instrument**, not the kernel. The
"exactly one receive syscall per message" assertion is the only thing separating a receiver that
sleeps from one that spins, so it has to be shown to catch a spinner, and it does.

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

`SYS_IPC_RECV_BLOCK` is completed by the *sender's* syscall, so the one-shot `CAP_REPLY` must be
minted into a cspace that is not the current one. The first version did that after marking the
waiter `TASK_RUNNABLE` and after dropping `ipc_lock`, to keep `cap_lock` from nesting under the
endpoint lock. But a task is schedulable the instant its state flips: another CPU picks it up,
it returns to ring 3, services the request and calls `SYS_IPC_REPLY_TO`: all before the mint
lands. `cap_lookup` finds no `CAP_REPLY` and returns `SYS_ERR_PERM`, which is **permanent**, so
the server correctly drops the reply (the retry contract forbids looping on it) and the client
waits forever.

**Why every gate missed it.** `smoke-recvblock` and `smoke-captest` run on one CPU, where there
is no second CPU to run the server inside the window, so the ordering cannot be observed to be
wrong. The full 17-target sweep passed. CI passed 61 of 63 checks. Only a *session under load*
showed it.

**How it was caught, and the general lesson.** By running the thing the change was supposed to
improve, against a control, on a **loaded** host: not by running the gates. Interleaved, `-smp
4`, pinned: 5 failures in ~15 boots for the new build against 0 for the control. That asymmetry
is the signal; a one-armed run would have looked like the ambient **G-8** rate.

**How the mechanism was established, rather than guessed.** The first hypothesis (an ordering
hole in `h_ipc_call`) was wrong, reading the code showed that ordering was already correct and
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
`smoke-console-smp` needed (*an unpinned green run is not evidence*) applied to a race whose
window is opened by vCPU descheduling rather than by core count.

**The fix** mints the reply right under `ipc_lock`, before the wake, and both completion paths
now follow one rule without exception: *a receiver holds its reply right before it is
schedulable.* `cap_lock` nesting inside the endpoint lock is a new lock order and is safe
because it is the only one: no path in the tree takes an IPC lock while holding `cap_lock`.

Measured with the recipe above, interleaved, 25 boots per arm:

| Build | Failures |
|---|---|
| pre-fix | **8/25** |
| with the ordering fix | **0/25** |

All four falsifications were re-run against the fixed code, because the mint moved and a gate
that was only ever shown to fire at the old call site proves nothing about the new one.

The third row is the instructive one. Removing the type check *alone* was **not** detected: the
probes used a `CAP_FRAME` and a `CAP_ENDPOINT`, whose `object` fields fall far outside the
untyped index space, so the range check caught them and the type gate was never the thing under
test. The probe was rewritten to use a `CAP_NOTIFICATION` whose `object` is `0` (a *valid*
untyped index, and specifically the kernel's own cspace reserve) which passes range and lands on
the two gates that actually matter. Defence in depth is why the first attempt survived; it is
also why a falsification that "passes" must be read as a broken test, not as a strong kernel.

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
per-endpoint, so the endpoint argument only selects the READ check and never selects which reply
right is used. Before the earlier replies consumed the right, that same call would have
succeeded. It is now `consumed-reply-right-revived-by-other-endpoint`, which is the property it
actually witnesses. A green check whose name overstates it is a worse artifact than no check; it
is a claim nobody will re-derive.

### `smoke-console-smp`: was flaky, was a real kernel bug, now fixed

**Resolved 2026-07-28.** For a long time this test failed roughly a third of the time and was
treated as flaky. It was not flaky. It was correctly reporting an intermittent **kernel
deadlock**, and every "just retry it" was a real defect going unlogged.

The symptom: boot reaches `[console_server] ready`, the shell banner never arrives, and the
`HHoorruuss` doubled-banner `FAIL_MARKER` does *not* trip, so it was visibly not the
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

The reason it read as flaky rather than as a bug is worth keeping: under TCG each guest vCPU is
a host thread, so on an idle many-core workstation the race window never opens and the failing
kernel scores 10/10 green. It only fails where vCPUs outnumber host cores, which is what CI
runners are. **The environment that made it look like noise was the developer workstation.**

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

**It pins the CPUs, and this is not a detail.** Under TCG each guest vCPU is a host thread. On
an idle workstation a 4-vCPU guest gets a core each, the scheduling windows never open, and the
failing build above scores **10/10 green**. Pinned to 2 host cores (what a CI runner actually
has) the same build hangs repeatedly. An unpinned stress run reporting 20/20 on a kernel that
fails a third of the time in CI is worse than no measurement, because it converts absence of
evidence into a claim. `STRESS_CPUSET=` disables pinning and the script says so loudly when it
does.

The corollary for reviewers: **a scheduling or IPC change is not evidenced by one green CI
run.** Ask for a rate.

### `make smoke-sched-invariants`: and the finding that turned out to be the checker

`SCHED_INVARIANTS=1` machine-checks the scheduler's claim invariant

```
task_running_cpu[t] == c  <=>  percpu_current_task[c] == t     (t > 0)
```

at every timer tick, panicking with the offending task, CPU and observer instead of
livelocking silently thousands of ticks later. Off in the ship kernel; **gated in CI** via
`make smoke-sched-invariants-stress` (30 pinned boots, reported as a rate).

**Resolved 2026-08-09.** This target used to be documented as expected to fail, reporting in
roughly one boot in five, 10 in 20 once the boots were pinned:

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
`percpu_current_task[]` deliberately does not describe the task the CPU is running, while `init`
remains correctly and legitimately claimed by it. The claim was live, not stale. The auditor was
reading a declared-in-code-comments-but-undeclared-to-the-checker impersonation as a leak.

The two IPC sites that do the same trick (`sys_ipc_send`, `h_ipc_reply_to`) *had* been declared,
via a `percpu_in_user_copy` flag added when the checker false-positived on them. The spawn
window had not, and it is orders of magnitude longer: a ~450 KiB copy plus page-table
construction and relocation processing, which under TCG spans many ticks, so it comfortably
survives the two audits the checker requires.

The fix does not switch the checker off for those windows. `sched_impersonate_enter/exit` record
the task the CPU is *really* running (`percpu_real_task[]`) and the audit is stated over that,
so coverage stays continuous across the longest operation in the system, which is exactly where
a real leak would otherwise be easiest to hide. The bracket is a nesting depth, not a flag, and
is itself checked: a CPU reaching **ring 3** at non-zero depth means an `enter()` lost its
`exit()`, and panics. An exemption mechanism with no balance check is a hole in the shape of the
thing being checked.

| Build | Runs (pinned, 2 host cores) | Failures | What that establishes |
|---|---|---|---|
| before | 20 | **10** | ~50%: the impersonation false positive, unambiguously |
| after | 30 | **0** | the false positive is gone: **and nothing about a rare event** |

**That second row was read as more than it says, and this is the correction.** Thirty boots has
about a **26% chance** of observing a defect that occurs on 1% of boots, so a clean 30/30 was
never evidence of absence at that rate. It established what it was built to establish (that the
~50% impersonation false positive had stopped) and nothing beyond it.

### 2026-08-21: the claim invariant fired again, and it is not the old false positive

On the CI run for `615b384`, one boot in 30 panicked:

```
PANIC: stale scheduler claim at preempt_on_tick: task 4 claimed by cpu 1
       but that cpu was running 0 (persisted across two audits; observed by cpu 3)
```

**This is the inverse of the 2026-08-09 shape and cannot have the same explanation.** That one
read `task 1 claimed by cpu N but that cpu was running 4`: `init` claimed while the CPU
legitimately impersonated the child it was spawning. Here it is **task 4** that is claimed, by a
CPU running **0**, nothing. An idle CPU is not impersonating anyone, so `percpu_real_task[]` has
nothing to say about it. The claim is genuinely stale: this is a leak, and it is **[G-9]**'s
shape exactly, a claim left behind by a CPU that then went idle.

Measured either side of the commit it appeared on, pinned, same host:

| Tree | Boots | Failures | Rate |
|---|---|---|---|
| `615b384` (with `libhorus`) | 120 | 1 | 0.83% |
| `2d27ec7` (before `libhorus`) | 270 | 0 | 0% |

**The difference is not significant** (Fisher exact, p ≈ 0.31), and it cannot currently be
resolved: one event does not carry a confidence interval worth quoting. `libhorus` is a ring-3
library and cannot create kernel scheduler state, but it did resize four server binaries, which
moves timing, so "pre-existing and under-sampled" and "the same defect, made marginally easier
to hit" both fit the data. Recorded rather than concluded.

**A red here is a [G-9] reproduction, not a flake.** `smoke-sched-invariants` stays **required**
deliberately. It is not `smoke-kstack-park` as that gate stood until 2026-08-22, when it was
advisory because it reddened for a defect it does *not* test; this gate tests the claim
invariant and what it caught *was* a claim leak. The gate is working. Before re-running it,
**save `stress-first-failure.log`**: every boot that reproduces this is a datapoint, and
collecting them is how **[G-8]** was closed. Re-running first and looking second is the reflex
that costs the evidence.

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

*(The concurrent-panic garbling that showed up during the falsification runs (`PANICPANIC: :
unbalanced impersostale scheduler claim...`, two cores tripping on the same tick) is fixed with
a first-CPU-wins latch. Same failure as the `PA[NIC: console_server]` episode below, one level
up.)*

**Three things this checker cost to get right, all worth knowing before extending it:**

1. **It must not panic on first sight.** Not every writer of `task_running_cpu[]` holds the
   scheduler lock, so an auditor on another core legitimately catches mid-flight updates. The
   check requires a violation to survive two audits. A first-sight version reported failures
   on a correct kernel.
2. **It must not print through `print()`.** Once a ring-3 console server owns the console the
   kernel's `print()` is suppressed, and during handover both writers touch COM1 from
   different cores; the panic arrived as `PA[NIC: console_server] ready`, i.e. the one
   message that had to survive was the one that did not, and the halt then looked like an
   ordinary timeout. It writes bytes to the UART directly.
3. **Dead tasks are exempt.** `task_teardown` releases the claim but the CPU keeps naming the
   task until `task_exit_switch` runs, and in between it does a full capability-graph sweep; 
   long enough to span several audits. Exempting them costs nothing, since selection requires
   `state == 1`.

**And one thing the checker's own development established, by measurement:** "defensively"
clearing a stale claim makes things *worse*, not better. Two such repairs (sweeping claims in
`enter_cpu_idle`, and marking a CPU idle early in `task_exit_switch`) took the stress harness
from **24/24 to 13/20**, because a stale claim marks a task whose kernel context was abandoned,
and freeing it resumes that task from a stale frame. Both are now recorded as explicit "do not
do this" comments at the sites that invited them.

### Closed finding G-9: a scheduler claim leaks on the spawn/reap path under SMP

**Status: CLOSED 2026-08-21.** Found 2026-08-17 by `smoke-kstack-park`, and pre-existing,
`PROC_SELFTEST` at `-smp 4` violated the claim invariant on about 40% of boots, a workload
nothing had run at more than one CPU before. It was a cluster rather than one defect and took
four components to close; the natural rate went 9 in 200 boots to 0 in 200 (Fisher p = 0.0036),
and the last component was the claim auditor clearing its own exemption before the release it
exempts, which was a false positive of the checker rather than a leak.

*This section read "**Status: open**" until 2026-08-30, while five other places in the tree
(including line 1319 of this same file) said closed. The current status of every finding is
authoritative in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).*

**The full investigation is in [`docs/investigations/G-09-scheduler-claim-leak.md`](docs/investigations/G-09-scheduler-claim-leak.md).**


### Closed finding G-10: the spawn/exec path is process-wide singleton state, unserialised

**Status: closed 2026-08-18.** Found while narrowing [G-9]. Everything `SYS_SPAWN` / `SYS_EXEC_NAMED` needed in flight was a file-scope singleton with nothing serialising two CPUs through it. The page-table half was a use-after-free giving a cross-address-space read/write primitive reachable from ring 3.

**The full investigation is in [`docs/investigations/G-10-spawn-path-uaf.md`](docs/investigations/G-10-spawn-path-uaf.md).**


### Closed finding G-11: the armed program image was ambient state

**Status: closed 2026-08-18.** Nothing recorded which task armed a staged image, and the arm is
a different syscall from the consume, so `SYS_SUDO`, which spawns whatever is armed **as uid
0**, would elevate another task's program to root.

**The full investigation is in [`docs/investigations/G-11-armed-image-ownership.md`](docs/investigations/G-11-armed-image-ownership.md).**

 ### Finding G-8: two CPUs on one kernel stack; CLOSED 2026-08-17

**Status: closed 2026-08-17.** A switch path handed the outgoing task to another CPU before this CPU had left that task's kernel stack. Measured over 1600 alternating boots: the pre-fix release site fails 31/800, the shipped one 0/800. The record of how it was read wrongly for eight days is kept deliberately.

**The full investigation is in [`docs/investigations/G-08-two-cpus-one-kernel-stack.md`](docs/investigations/G-08-two-cpus-one-kernel-stack.md).**

### `make smoke-irq-policy`: the interrupt policy, written down and gated

**Roadmap 1.1, steps 2 and 3.** Boot-time interrupt enablement used to be an *emergent* property
of a locking defect rather than a stated design: `spin_unlock`'s unconditional `sti` turned
interrupts on as a side effect of the first lock any syscall took (**[C-3.1]**). Since
2026-08-11 the policy is stated ([`ARCHITECTURE.md` §6](docs/ARCHITECTURE.md)) and this gate is
what holds the code to it. It records IF at named milestones and asserts each one.

| Milestone | IF | Why |
|---|---|---|
| `post-idt` | 0 | boot runs masked throughout |
| `post-paging` | 0 | |
| `post-protections` | 0 | |
| `kernel-ready` | 0 | |
| `first-syscall-entry` | 0 | `int 0x80` is an interrupt gate |
| `outermost-lock-release` | **0**, or **1** under `IRQ_LEGACY_GLOBAL_LOCK=1` | a critical section RESTORES the caller's IF, never imposes one |

The last row is the one that carries roadmap 1.1 step 3, and it is deliberately stated per build
so the control arm is gated too rather than merely tolerated. It records IF immediately after
the first outermost `spin_unlock` of the boot; the single observation that distinguishes the two
locks, since at that point in boot the caller always had IF clear. An unconditional `sti`
therefore cannot come back silently.

The first five were **measured, then written down**, they are what the kernel already did, so
the gate's job is to notice a change. Encoding a policy nobody has implemented would make the
test fail on a correct kernel, the failure mode this document keeps warning about.

All zero is the whole point: every syscall starts masked, so under the old lock the first lock
a handler released turned interrupts on for the rest of that syscall. That is why **[C-3.1]**
was load-bearing, and why it was measurable.

> **The totals this section used to quote, "99 accidental against 67 benign across a
> session", were withdrawn on 2026-08-10.** The audit reports through `panic_str`, straight
> at the UART, bypassing the runtime suppression of `print()` that exists because ring-3
> `console_server` owns the serial line. The tick-41 report lands on the login prompt and
> splits it (`root@horus\n[irq-policy] handshake-early @tick=41: ...`) so `root@horus#`
> never appears contiguously and `tools/session_test.py` waits for a prompt that was cut in
> half. Measured **interleaved**, adjacent boots, alternating builds, so host drift cannot
> account for it, with the unmodified audit build kept in as a positive control:
>
> | Build | `session_test.py` failures |
> |---|---|
> | ship kernel (no audit) | **0 of 8** |
> | audit, `IRQ_POLICY_QUIET=1` | **0 of 8** |
> | audit, exactly as shipped | **8 of 8** |
>
> `IRQ_POLICY_QUIET=1` removes the reporting and nothing else: `spin_lock` and `spin_unlock`
> disassemble to **82 identical instruction lines** under both settings, against the same five
> counter symbols. Without that check, "quiet passes" would be equally consistent with quiet
> mode having simply switched the instrument off. The harness then stops issuing commands, the
> guest correctly runs nothing more, and
> the counters stop at **99/67**, the boot window of a session that never executed a command.
> A session the harness *can* drive reads **420/224 at tick 201**. The seven sites reproduce;
> the totals did not. See `docs/ROADMAP.md` §1.1.
>
> Two things this is *not*. It is not a kernel hang; the guest is healthy throughout, and
> frozen counters beside a live timer is what an idle kernel looks like, not a stalled one. And
> it is not **G-8**: an early draft of this correction guessed at both, from the same evidence,
> and was wrong on both. **This gate is unaffected**, it exits on its marker at tick 40 and
> never reaches a prompt, and the ship kernel it protects carries no audit at all.

Falsified in both directions, because a gate that cannot fail is not evidence:

| Break | Result |
|---|---|
| flip one expectation | `FAIL post-paging IF=0 expected 1` |
| delete a milestone hook | `FAIL milestone-never-reached post-protections` |

The second matters more than the first. A milestone that silently stops firing would otherwise
pass on four checks instead of five, and the gate would report success while measuring less than
it claims; the same defect as a refusal test that never reaches its probe.

Step 3 landed 2026-08-11 and added the sixth row. Falsified by crossing the two builds'
expectations, building the per-CPU lock while expecting the legacy value gives `FAIL
outermost-lock-release IF=0 expected 1`, so the milestone genuinely discriminates between the
two locks rather than recording a constant.

### `make measure-irq-policy`: the audit read out in band, not printed at the UART

**Roadmap 1.1 step 2b.** Not a gate: it produces a number, and a number is not a pass/fail. It
is a target so the measurement is *reproducible*, and so nobody re-derives it by making the
kernel print at the UART again, which is what corrupted every earlier figure.

`SYS_IRQ_POLICY_INFO` hands the counters to userspace on request and the shell's `irqpolicy`
builtin prints them through `console_server`, so the kernel is never a second writer. Because
the readout is on demand it can be taken **after** a workload rather than at a fixed tick,
which is the difference between a session-scale total and a boot-scale one. Fourteen commands,
each a `console_server` round trip:

```
irq-policy: accidental_sti=1439 suppressed_sti=0 benign_sti=720 sites=7 @tick=693
```

with `cap_install_object` (685) and `cap_consume_slot` (684) accounting for **95%**, both on the
IPC path, both scaling with message traffic, while the other five sites are fixed boot-time
costs.

**The equivalence check (roadmap 1.1 step 3).** Both locks count the *same* predicate, an
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

The second was not a contrived break; it is how the check first failed. Userspace is compiled
with its own flags, so `#ifdef IRQ_POLICY_AUDIT` in `captest.c` was never true and the test
disagreed with the kernel it was testing about which kernel it was in. It failed loudly rather
than passing against the wrong expectation, which is the only reason it was noticed;
`USERSPACE_CFLAGS` now propagates the flag. **A test asserting an exact errno catches this. A `<
0` assertion would have passed in both configurations**, the same lesson as the C-1 set.

*One honest gap.* The tool also asserts prompt integrity (that the expected prompt appeared
contiguously as many times as commands were sent) as a safety net against measuring a corrupted
session. That guard's failure path works (it fired during development on an off-by-one), but
**it has not been shown to fire on a genuine split prompt.** The corruption is not a general
race: it is deterministic for a particular prompt timing, and this tool's prompts all land after
the async reports finish at tick 201. `session_test.py` remains the instrument that detects a
split reliably (8/8 and 10/10 against the loud build). The guard is a net, not evidence.

### `init`'s exit report never reached the wire

**The reason G-8 has been undiagnosable.** `init`'s `report()` was `sys_write(1, ...)`, which
lands in the kernel's `print()`, and `print()` stops driving the hardware the moment
`console_server` takes ownership (`terminal.c`: `drive_hw = (console_owner_task == 0)`). So
every init message after the handover went to the klog and **nothing reached serial**, including
`report_shell_exit()`, which is the entire point of #130. That PR's own comment says init prints
"through console_server like any other program"; the code used the kernel path.

The symptom, seen repeatedly before it was understood: a boot where the shell restarted showed
**two startup banners and no exit report at all**. That looks identical to a shell restarting
for no reason, which is exactly the ambiguity G-8 has cost days to.

Measured with the *same* heartbeat probe on both builds, ownership confirmed as `owned=1`, the
console routing as the only variable:

| `init`'s `report()` | Heartbeats on serial after the handover |
|---|---|
| `sys_write` (before) | **0** |
| via `console_server` (after) | **2** |

The handover itself is visibly two writers on one UART, a line truncated mid-word, `init:
st[console_server] ready`.

**Three wrong turns getting here, all worth recording**, because each looked conclusive:

1. Concluding init was muted from *absence* of init output in 100 captured boots, init simply
   has nothing to say while blocked in `sys_wait`. Absence of evidence.
2. "Disproving" that with a probe that printed fine; it fired *before* ownership was actually
   registered. `[console_server] ready` is the server's own native write and does not mark the
   handover.
3. "Re-proving" it with a heartbeat that produced zero lines; the probe never ran, because
   `settle()` is 40 000 iterations and calling it 1 500 times per beat is ~10 s under TCG.

Only the fourth attempt (identical probe, identical ownership state, routing as the sole
difference) measured anything. **A probe that produces no output has two explanations, and "the
thing I am testing is broken" is the less likely one.**

### Two diagnostics for a corrupted resume `%rsp`

Every return from `interrupt_handler64` is a kernel `%rsp` that `isr_common_stub64` loads and
immediately pops fifteen registers from. A bogus value there does not fail where the mistake was
made; it faults *inside the ISR epilogue*, at an address near zero, and the banner names the
stub. That is almost the least informative place a kernel can fault.

It cost a full reproduce-and-symbolise cycle to learn that `PAGE FAULT at 0x94` meant "the
dispatcher returned 4": `0x94` is `rsp + 0x90`, the `out->cs` read in `interrupt_handler64`
itself. Two changes make the kernel say so directly:

- **A guard at the dispatcher choke point.** Kernel stacks are higher-half, so any returned
  value below that floor is a `0`/`1`/`-1` or something wild, never a frame. It panics with
  the value, the task, its state and its `pending_block`.
- **The faulting RIP and RSP in the ring-0 `#PF` banner.** A ring-0 fault previously reported
  only *that* the kernel dereferenced something bad, never *where*, and the where is the whole
  diagnosis. Symbolise with `addr2line -e kernel.elf <rip>`.

**Falsified**, because a guard never seen to fire is an assumption rather than a control:
injecting `rsp = 4` on a ring-3 return produces
`PANIC: dispatcher returned a bogus resume rsp=` instead of the old `PAGE FAULT at 0x94`.

*A third instrument was written and deliberately NOT kept.* It recorded which dispatcher path
had returned, in a global, which under SMP another core can overwrite between the panicking
core's return and its print, so its attribution is unreliable exactly where it would be used. It
named a path the disassembly then contradicted. Per-CPU it would be sound; global it is worse
than nothing, because it looks authoritative. Left out rather than shipped with a caveat nobody
would read at 3am.

## Memory protection and isolation

| Target | Proves |
|---|---|
| `smoke-wx` | The kernel image is r-x / r-- / rw-, and a sweep of **every leaf PTE** finds no writable-and-executable page. |
| `smoke-wx-smp` | The same under SMP, and that every AP's IST fault stack sits above an unmapped guard page. |
| `smoke-cpu` | SMEP and SMAP are detected **and actually set in CR4**, not merely attempted. Boots under `-cpu +smep,+smap`. |
| `smoke-percpu` | `this_cpu()`'s TSS-selector derivation agrees with the LAPIC **on every core that came online**, checked on each core as its TSS is loaded, and `EFER.SCE` is clear so the staged SYSCALL path stays unreachable. Needs ≥2 cores: on one CPU the mapping is right by accident, so a UP run fails rather than passing vacuously. |
| `smoke-aspace` | Rebuilding a task slot repeatedly returns every physical page to the pool, a dead task's address space leaks nothing. |
| `smoke-cow` | Copy-on-write breaks correctly for the shared zero page. |
| `smoke-heap64` | The heap syscalls **and the pager's region gate** are 64-bit clean (**[I-2]**, roadmap 1.5). Builds `USER_HEAP_HIGH_BASE=1`, which places every heap at **8 GiB** (above the 4 GiB line, below `USER_IMAGE_ASLR_BASE`) so the truncation is *reachable* instead of latent, then runs `captest`, which calls `sbrk`/`brk` directly and writes to the page it is handed. **Control arm:** built from a tree without the fix, the same target reports `CAPTEST: FAIL (sbrk-grow-failed)`. Verified in both directions before the target existed. |
| `smoke-nzcow` | The generic (non-zero) COW break is correct, added after a real bug in that path. Since 2026-08-27 it also asserts the break is **refused** on a page belonging to a kernel object (**S38**); arm `smoke-nzcow-arena-control`. |
| `smoke-stackguard` | The stack canary is re-seeded from the CSPRNG at boot and is no longer the compile-time default. |
| `smoke-aslr` | Image, heap, and stack bases are randomised. |
| `smoke-e820` | The physical pool is sized from the multiboot2 memory map, not a hardcoded fallback. |

## Boot integrity and measured boot

These are the most adversarial tests in the suite.

| Target | Proves |
|---|---|
| `smoke-modules` | Boot modules are provisioned into `/bin` and run from the filesystem. |
| `smoke-modules-tamper` | **Corrupts a module payload inside the ISO** and asserts the kernel refuses it; the manifest gate fires. |
| `smoke-tpm` | Kernel and modules are measured into PCR 8 and 9, and the values equal an independent host recomputation (`tools/tpm_expected_pcr.py`). |
| `smoke-tpm-tamper` | A corrupted module is refused **and** the measured PCRs diverge, detection as well as prevention. |
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
| `smoke-recvblock` | A ring-3 server waiting with `SYS_IPC_RECV_BLOCK` makes **exactly one receive syscall per message** while the client dawdles before each send (the witness that it slept rather than polled) and the wake leaves it holding the one-shot reply right. Roadmap 1.3. |
| `smoke-recvblock-smp` | The same, under `-smp 4`, so the CROSS-CPU wake path runs at all. It does not reliably catch the ordering race that path is prone to (see "The lost wakeup none of those gates caught") but it is one boot. |

Both run in CI as of this change. They are **not** required status checks: like every other gate
added after the ruleset was written, they land in the advisory set (finding **[C-6]**), so a red
`smoke-recvblock` does not block a merge. Read it anyway.

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
| `smoke-users-persist` | **S62.** Two boots on one disk image: boot 1 adds an account and sets its password, and requires it to verify **in the boot that set it** — without that, a boot-2 failure cannot be told from "never worked". Boot 2 requires the password to still verify **and** a wrong one to still be refused, because "it verifies" alone is satisfied by a kernel that accepts everything (a table restored as all-zero salts and hashes could look exactly like that). |
| `smoke-users-persist-control` | Control arm for **S62**. `USERS_PEPPER_PER_BOOT=1` restores the per-boot pepper in account hashes, so the table is stored faithfully and the hash in it still cannot verify — `docs/LIMITATIONS.md` 2.6 reason 3. **Its own first version could not reproduce**: the selftest was hooked before `users_init` ran, so `kernel_pepper` was all zeros in both boots and the flag changed nothing. The arm found its own test's defect by refusing to go red. |
| `smoke-users-tamper` | **S62, adversarial half.** Boot 1 writes a real table; boot 2 flips a byte of the ciphertext on the platter before it is read, and requires logins to be refused **and** that no account was restored. Both halves matter: refusing while still reseeding would pass a check that only looked at the refusal, and reseeding is the actual danger — it restores the compiled-in `root` password. |
| `smoke-storage-noformat` | **S63.** A blank ATA image is booted with the shipping default and the unlock is driven directly; `NOFORMAT_SELFTEST: REFUSED` is required. |
| `smoke-storage-noformat-control` | Control arm for **S63**. `STORAGE_AUTOFORMAT=1` restores format-on-login and `NOFORMAT_SELFTEST: FORMATTED` is required. **Both arms assert which branch was taken, positively.** The first version had the control require the refusal message to be *absent* — and it passed vacuously, because the boot stops at `horus login:` and neither arm ever called `storage_unlock`. An absence assertion is satisfied by a run that never reached the code. |
| `smoke-storage-survey` | **S72, the positive half.** A capability HOLDER learns what volume this machine has. **Two boots of one kernel**, one with a blank ATA image attached and one without, requiring `init` to report `INIT_STORAGE: disk present` in the first and `INIT_STORAGE: no persistent volume` in the second -- and each arm requires the OTHER arm's marker to be **absent**, so a build printing both cannot satisfy either. It exists because `smoke-captest`'s storage refusals are all satisfied by a syscall that refuses everyone: a survey reporting the same thing on every machine would pass a one-boot version of this gate and tell an installer nothing. |
| `smoke-captest-storage-format-control` | Control arm for **S72**. `STORAGE_FORMAT_UNGATED=1` removes the whole dispatch-table row in front of `SYS_STORAGE_FORMAT` -- slot, rights and type -- so `captest`, holding no `CAP_STORAGE_FORMAT`, reaches the handler; marker `CAPTEST: FAIL storage-format-without-cap-storage-format`. **The whole row goes rather than half of it**: either half alone still refuses, so an arm against one would pass for a reason that is not the one being measured. **The ungated call SUCCEEDS rather than failing differently**, which is what a refusal test needs -- `captest` boots on the ephemeral vdisk, already mounted and unlocked, so `storage_unlock` is idempotent and nothing is destroyed. Measured 2026-09-01: base arm `CAPTEST: PASS 180 checks`; control arm marker present; `make smoke-captest STORAGE_FORMAT_UNGATED=1` exits 2 on `SMOKE FAIL: saw fail marker`. |
| `smoke-tui` | libhorus's TUI, asserted against **its own buffers rather than a screen**. Every property here is invisible on a terminal: a correct damage diff and a full repaint draw the identical picture, and so do a bounds check and its absence. So the checks are on the byte count handed to the console and on cell contents. Covers: an unchanged screen emits nothing; a one-cell change costs under 60 bytes rather than a repaint; the cell written is the cell asked for and its neighbour is untouched; out-of-range writes (past the last row, past the last column, and negative) are discarded; `tui_field` pads and truncates to its width; and the key decoder maps `ESC [ A`, `ESC O B`, `ESC [ 1 ~`, CR and DEL correctly while yielding `TUI_KEY_ESC` for a **truncated** escape and a bare ESC. Since 2026-09-01 it also covers the two INTERACTIONS an installer is built out of. The cursor is diffed like a cell — an unchanged request costs zero bytes, a moved one costs some, and an out-of-range request **hides** rather than clamping to an edge, because a cursor parked somewhere the caller did not ask for is a lie about where the next character lands. `tui_input` is bounded by the smaller of `cap - 1` and `width` (a field is exactly as long as it looks), terminates within its capacity, removes exactly one character *and one cell* on backspace, empties the buffer on ESC rather than handing back a partial answer, and under `TUI_IN_MASK` puts the clear text in the caller's buffer and never in a cell. `tui_menu` clamps its selection to `0..n-1` at **both** ends, leaves `*sel` untouched on ESC, and refuses `n <= 0` or a null item list. Every fed sequence also asserts `tui_test_keys_left() == 0`: a loop that returned early leaves keys unread, and its result can still be the expected one — a menu that ignored every arrow returns the initial selection, which is indistinguishable from a menu that clamped correctly unless somebody asks whether the arrows were consumed. The library adds no privilege: every operation is a request on the console endpoint the caller already holds. |
| `smoke-tui-mask-control` | Control arm, and the disclosure half. `TUI_INPUT_ECHO_SECRET=1` drops `tui_input`'s mask so a password field paints what was typed: `TUITEST: FAIL a masked field showed its characters`. **The returned value is identical either way** — neither the caller nor a test that inspects the buffer can tell — so the witness reads the back buffer. It asserts "it drew stars" and "it did not draw the secret" as two checks, because those are the same sentence only while the alphabet excludes `*`, and separately that the cells past the content are **blank rather than masked**: padding to the field width would disclose nothing about the text and everything about its length. |
| `smoke-tui-bound-control` | Control arm, and the memory-safety half of the editor. `TUI_INPUT_UNBOUNDED=1` drops the `cap` bound and **keeps** the visible-width bound, so a caller that passed a small buffer and a wide field is written past the end of it: `TUITEST: FAIL an input overran the buffer it was given`. Keeping the second bound is deliberate — removing both reproduces an unbounded write, which no realistic mistake makes, where the mistake this guards against is trusting a single bound. The guard region is **inside the same array** as the buffer under test: adjacency between two separate arrays is the linker's business, not the language's. |
| `smoke-tui-menu-control` | Control arm. `TUI_MENU_UNCLAMPED=1` lets a menu's selection run past either end of its item list: `TUITEST: FAIL a menu selected past its last item`. **The screen is identical** — every cell a menu paints is clamped by `tui_putc` regardless — so what breaks is the *caller*, which indexes `items[*sel]` on return; for an installer that array is the list of disks it is about to destroy one of. The marker is therefore the returned index, and **both ends are checked**, since a single-direction arm would miss a clamp lost only at the top. |
| `smoke-tui-diff-control` | Control arm. `TUI_NO_DAMAGE_DIFF=1` makes `tui_flush` repaint every cell. The screen looks identical, which is the point — only the byte count for a one-cell change tells them apart, and the marker is `TUITEST: FAIL a one-cell change repainted the screen`. |
| `smoke-tui-clamp-control` | Control arm, and the memory-safety half. `TUI_CLAMP_OFF=1` removes the single bounds check every drawing call funnels through, so a write one row past the end lands in the buffers and the next flush notices: `TUITEST: FAIL an out-of-range write reached the buffer`. |
| `smoke-keyslots` | **S61.** Several passwords open one volume, and revoking one revokes exactly that one. **Two boots on one disk image**, because the property is about surviving a power cycle: boot 1 meets a blank disk, formats it under password A (slot 0, uid 0), adds a slot for B (uid 1000), and requires B to open the volume **in the boot that added it** — without that, a boot-2 failure could not be told from "never worked". Boot 2 requires both A and B to still open it, revokes B, then requires B refused and A untouched, and finally requires the last remaining slot to be **un-removable**. Phase is read off the disk (a blank disk is boot 1, two slots is boot 2), so no boot counter is needed. |
| `smoke-keyslots-control` | Control arm for **S61**. `KEYSLOT_REMOVE_NOOP=1` makes `storage_keyslot_remove` report success and leave the wrap openable, so a revoked password still unlocks the volume. **The marker is the PASSWORD, not the slot count** (`KEYSLOT_SELFTEST: FAIL revoked-password-still-opens-the-volume`): the count drops either way, so a count-based check passes under the defect and witnesses nothing. Measured 2026-08-31: base arm two boots green, control arm red with the marker. |
| `smoke-meta-crash` | **S65, Arm A of `docs/design/meta-cache-merkle.md`.** A metadata update in a committed journal transaction is durable, whether or not its cache line was evicted first. Two boots on one ATA image: boot 1 writes 400 distinct blocks — a working set spanning more metadata blocks than the cache has lines — and crashes with the last block committed but not applied; boot 2 replays and must read every block back byte-for-byte. **Both boots also assert `meta_cache_evictions() != 0`**, which is the difference between "the blocks verified" and "the blocks verified *despite* eviction": a working set that fits the cache never evicts and would pass while testing nothing. Measured 2 evictions per boot, 0 of them dirty. **It reddened once on `main` on 2026-09-01 and passed on re-run**, so the cause is not established; the failure path now prints `phys=`, `ata_refusals=` and `evictions=` before its marker, because "block N lost" covers five distinct causes and none of them was distinguishable from the log. A non-zero `ata_refusals` would mean the transport refused a transfer (S69), not that the filesystem lost anything. `META_CACHE_TINY=1` is set in every arm — a window widener, not a defect, dropping the cache from 32 lines to 2 so that a few hundred blocks provably exceed it (the `KSTACK_RACE_WIDEN` pattern). |
| `smoke-meta-crash-control` | Control arm for **S65**, failure modes E1 and E4. `META_CACHE_NO_WRITEBACK=1` takes the write-back out of the cache entirely — `journal_commit` does not flush dirty lines and eviction drops them — so metadata a committed transaction promised never reaches the disk. Boot 2 *mounts* (the region and its HMAC still agree, both being the format-time zeros) and then cannot decrypt anything: `METACACHE: FAIL block 0 lost after eviction`. |
| `smoke-meta-crash-txn-control` | Control arm for **S65**, failure mode **E2**, and it earns its own arm because E2 is what turns a recoverable loss into a lost block. `META_CACHE_WB_OUTSIDE_TXN=1` keeps the write-back and moves it *past the end of* `journal_commit`, where `do_block_write` goes straight home. Every value written is still correct; what is gone is the atomicity between a block's nonce and the ciphertext it opens. It names a **different block from the arm above** — `METACACHE: FAIL block 399 lost after eviction`, precisely the block the crash committed, whose ciphertext the journal replayed and whose metadata write was never in the transaction. Two arms naming two different blocks is what shows the two rules fail independently. |
| `smoke-meta-crash-vacuity-control` | Control arm on the **gate** rather than on the property. The same build *without* the `META_CACHE_TINY` widener has 32 lines, the 400-block working set fits, nothing evicts — and boot 1 must print `METACACHE: FAIL no eviction occurred - this run tested nothing` rather than passing. This is what shows the newly-gating eviction assertion can fail; without it, raising the cache or shrinking the set would silently turn `smoke-meta-crash` into a no-op with nothing to say so. One boot, because the refusal happens before the crash. |
| `smoke-merkle-replay` | **S66, Arm B of `docs/design/meta-cache-merkle.md`.** A metadata block is served only when it verifies against the path to the **current** rollback root. **Three boots on one ATA image**, with the *host* doing the tampering between them (`tools/merkle_replay.sh`), because a physical attacker with the disk is what the property is about. Boot 1 writes set A and reports two blocks; the host copies the image aside. Boot 2 writes set B into the same metadata block, so that block, its leaf, the node above it and every ancestor up to the root are rewritten. The host then restores **both** the metadata block and the level-0 node that recorded it. Boot 3 must refuse every set-A block (measured 6 refused, 0 served). **The restored bytes are a genuine past state of this volume** — correctly encrypted, correctly MAC'd, correctly indexed — so the refusal cannot come from a hash that failed, which is the whole difference between testing the tree and testing the MAC. Restoring the block *without* its node is refused by construction and proves nothing; the script therefore restores the pair, and refuses to reach boot 3 unless boot 2 provably changed both. The phase counter lives one block past the end of the volume, storage the filesystem can never reach. Each arm passes its counterpart's marker as `FAIL_MARKER`, so a run whose outcome flipped stops in seconds and names which way it went, rather than timing out after 600 s with "no required marker" — which is what an infrastructure problem looks like. |
| `smoke-merkle-replay-control` | Control arm for **S66**, failure mode R1. `MERKLE_NODE_TRUST_CACHED=1` sets a node line's `verified` flag where the line is **filled** rather than where it is checked, so residency in the node cache becomes the trust criterion instead of a path from the root. That is the natural performance shortcut — re-checking a node on every cache *hit* really is wasteful, and the flag exists to skip it; setting it one line too early skips the check that mattered. Marker: `MERKLE: FAIL stale node accepted - subtree served a rolled-back block`, with 6 of 6 blocks served and all 6 matching the earlier contents. **Positive**: the volume handed the rollback back, not merely "no refusal arrived". |
| `smoke-merkle-parent-bind-control` | Second control arm for **S66**, and it exists because the witness returns at its first failure so the arm above never reaches this rule (the `smoke-cap-lookup-range-control` lesson). `MERKLE_SKIP_PARENT_BIND=1` checks the leaf **against the node that records it** and does not place that node under the root. Deliberately not "check nothing": measured 2026-08-31, this build still refuses a metadata block restored *without* its node, 6 of 6 — so what the arm removes is provably the chain and not the MAC. With the pair restored it serves all 6 rolled-back blocks. |
| `smoke-fsck-refs` | **S67.** `fsck` does not free the blocks of a live file. Two boots on one image: boot 1 writes a file reaching into the double-indirect tree — asserted **positively against the inode**, so a run whose working set stayed in the single-indirect region fails rather than passing vacuously — and boot 2 asks the **block bitmap** whether those blocks survived the fsck that unlock just ran. It asks the bitmap rather than reading the file back, because a freed-but-still-referenced block reads back perfectly: the inode still points at it and the bytes are untouched, and the corruption only appears once the allocator hands the block to someone else. A read-back witness would pass over the defect and fail later, elsewhere, for a reason nobody would connect to fsck. The consequence is checked second: a freshly allocated block must not be one the file owns. |
| `smoke-fsck-refs-control` | Control arm for **S67**. `FSCK_SHALLOW_REFS=1` restores the pre-2026-08-31 reference walk, which marked `direct[]` and the single-indirect block and stopped. Marker: `FSCKREF: FAIL fsck freed 4 of 4 blocks of a live file, first at 4396` — **counted**, so a partial reproduction is visible rather than rounded to "it failed". Falsified in both directions: `make smoke-fsck-refs FSCK_SHALLOW_REFS=1` goes red on the same marker. |
| `smoke-fs-16g` | **S68, and the end-to-end gate for the whole storage track.** A 16 GiB volume formats, mounts, survives a reboot **and a crash**, and holds a file whose offsets are past the old 1.00 GiB double-indirect ceiling. Everything the other storage gates check in isolation has to hold at once: the bounded metadata cache (a whole-volume mirror would be 128 MiB of `.bss`), the Merkle tree (a flat MAC would hash 1 MiB per write and read the entire region at mount), the device-derived volume size, triple-indirect, and the inode scaling. **Three boots** on a **sparse** image — 16 GiB declared, ~130 MiB actually written, because `dd count=N` would write sixteen real gigabytes of zeros first. Boot 1 formats and writes; boot 2 mounts what boot 1 left, checks a block came back *before* crashing (so a boot-3 failure cannot be blamed on a reboot that had already lost the data), then commits a write and halts before applying it home; boot 3 replays and reads everything back. The crash boot is nearly free because the volume is already formatted, so testing recovery at *this* size rather than trusting `smoke-meta-crash` at 128 MiB costs about a minute — and the journal's targets are absolute block numbers, with the metadata block a write touches here thirty-two thousand blocks further into the region. It asserts **positively** that the volume is at least `BLOCKS_PER_DISK` blocks and that the file reached the triple-indirect tree: a gate for a 16 GiB volume that a 128 MiB image satisfies is a gate for nothing, and the image size lives in the Makefile where nothing else would notice it shrinking. A hole in the triple-indirect region must read as **absent**, which is the failure a mis-wired level produces that a written-then-read check cannot see. Boot 1 takes minutes (zeroing a 128 MiB metadata region and hashing it into the tree, through emulated PIO); boots 2 and 3 mount in the ordinary time, and that difference is what the Merkle tree bought. |
| `smoke-fs-shrink` | **S68's other half.** A volume is never served on a disk too small to hold it. Now that the device is sized from IDENTIFY rather than from a constant, a superblock claiming more blocks than the disk reports means the volume was formatted on a larger disk and this one is a **truncated copy** — every offset past the end is simply not there. Two boots with the *host* truncating the image between them, because a disk that is smaller than it was is something that happens to a disk, not something a kernel can do to itself. Boot 1 asserts positively that it formatted a volume (an empty disk would give boot 2 nothing to be too small for). Boot 2's refusal is asserted **by count**, not by a volume failing to come up — that same silence is produced by a bad magic, a version mismatch or an unreadable superblock, and a witness that cannot tell those apart is not a witness for this. |
| `smoke-fs-shrink-control` | Control arm for **S68**. `STORAGE_MOUNT_ANY_SIZE=1` drops the check and the truncated volume mounts. The marker is what **happened** — `SHRINK: FAIL a volume larger than its disk mounted` — not a refusal that failed to arrive. Falsified in both directions, and each arm carries its counterpart's marker as `FAIL_MARKER`, so a run whose outcome flipped stops in seconds (measured: 300 s of timeout became 13 s) rather than timing out with "no required marker", which is what an infrastructure problem looks like. |
| `smoke-alloc-hint` | A block allocation does not rescan the whole data bitmap. `storage_alloc_block` scans for a clear bit and **where it starts decides the cost**: from block 0 every time, a volume whose first N bitmap blocks are full costs N+1 reads *per allocation*. One boot on a **2 GiB** image, because one bitmap block covers 32768 blocks — at 128 MiB there is no second block to scan, and the gate says so (`the bitmap is too small for a scan to exist`) rather than passing. The workload writes the bitmap directly instead of allocating two million blocks to reach the same state: the bytes are identical, only the hours are skipped, and the allocations measured afterwards are real ones out of what is left. **Both halves are asserted** — the read count, *and* that the scan still wraps: the volume is then filled completely, one block is freed in bitmap block 0 behind the hint, and the next allocation must return exactly that block. A gate measuring cost alone would pass a fix that was fast because it gave up early. Measured 47 reads for 32 allocations. |
| `smoke-alloc-hint-control` | Control arm. `ALLOC_NO_HINT=1` starts every scan at bitmap block 0 again: **512 reads for the same 32 allocations**, exactly 32 × 16, against a budget of 79. The marker carries the count, so a partial regression is visible as a number rather than rounded to "it failed". Falsified in both directions — `make smoke-alloc-hint ALLOC_NO_HINT=1` goes red on the same marker in 38 s. |
| `smoke-ata-ready` | **S69.** A sector transfer happens only when the drive says it is ready. Checked as a **pure function over all 256 status bytes**, requiring exactly the 16 with DRQ set and BSY, ERR and DF clear. Tested that way deliberately: the statuses that matter are the ones a working QEMU never produces — BSY still set after the wait gave up, DRQ never asserted, DF raised — so an integration test could only exercise what the emulator chooses to generate and would pass over every case the rule exists for. Same reason `sched_domain_switch_would_flush` is a pure function. One boot, no disk, seconds. It also checks the second predicate, `ata_bus_absent`: exactly **2 of 256** statuses (all-ones and all-zero) mean nobody is driving the bus. That one pays for the busy-wait's spin bound — with it, an absent bus exits on the first read, so the bound can be what ATA-8 allows rather than what keeps a diskless boot fast. Getting it wrong in the direction of matching *more* would abandon a working but slow drive on its first busy read. |
| `smoke-ata-ready-control` | Control arm for **S69**. `ATA_READY_ERR_ONLY=1` restores ERR-alone: **128 of 256** statuses accepted, the first being `0x00` — a drive that said nothing at all. The marker names the status and why it was wrongly accepted, so it reports a transfer that *would have gone ahead* rather than a rule that failed to fire. |
| `smoke-nvcounter` | **S70's anchor, checked before anything is built on it.** The TPM NV counter provisions, is idempotent to re-provision (every boot after the first meets an index that already exists), reads back, and **only ever goes up** — a counter that could be made to repeat a value would let a rolled-back volume match, which is the whole attack. It also requires a provisioned counter to be non-zero, because 0 is exactly what an *unanchored* superblock field holds and the two must not collide. A run without a TPM reports **FAIL**, not skip: this gate exists to test the anchor, and a CI job that lost its swtpm must not look green. No control arm — the property is the TPM's, and the arm for *our* use of it is `smoke-rollback-control`. |
| `smoke-rollback` | **S70.** A volume older than the machine is refused. **Three boots on one image with a kept TPM state directory**: boot 1 formats an anchored volume and writes era 1, the host images the disk, boot 2 writes era 2, the host restores **the entire image**, boot 3 must refuse it. The tampering is a whole-image `cp` because that *is* the attack — there is nothing partial to model, and every internal relationship in the restored volume holds. Before boot 3 the harness asserts positively that boot 2 both changed the image **and advanced the generation**; a restore that replays nothing, or an anchor that is not moving, would let boot 3 pass having tested nothing. **Each boot's marker is printed after its write is durable**, not before: the harness ends a boot the moment it sees the marker it waits for, and the first version announced what it had read *before* writing what the next boot needs to find. That passed four times locally and failed in CI, where boot 1 was stopped four seconds in and boot 2 then correctly reported finding nothing. |
| `smoke-rollback-control` | Control arm for **S70**. `ROLLBACK_ANCHOR_IGNORE=1` drops the comparison against the counter and boot 3 mounts, reporting `found era 1` — the state the machine had already left, where a current volume holds era 2. **A rolled-back boot cannot identify itself from inside the guest**, and that is not a shortcoming of the test but the attack itself: the restored volume is byte-identical to one that legitimately reached that state, so the harness supplies the context the guest cannot have. Falsified both ways — `make smoke-rollback ROLLBACK_ANCHOR_IGNORE=1` goes red in 25 s. |
| `smoke-vdisk-bound` | **S64.** A block device accepts only blocks it has memory for. The RAM vdisk advertised `BLOCKS_PER_DISK` (32768) over a `VDISK_BLOCKS` (4096) reservation in the physical pool, so block 4096 was accepted and written into the FREE PAGE POOL that begins immediately after it — reachable from ring 3 by writing enough file data on any diskless boot. The gate asserts **both directions in one boot**: the last in-range block must still be writable and read back, and the first out-of-range block must be refused. An arm asking only for the refusal is satisfied by a bound that rejects everything, which is the `KSP_GUARD_ALWAYS` lesson. |
| `smoke-vdisk-bound-control` | Control arm for **S64**. `VDISK_TOTAL_UNBOUNDED=1` restores the pre-2026-08-31 device — `total_blocks = BLOCKS_PER_DISK`, no second check against the backing store. Its marker is the pattern **read back out of the page pool** (`VDISKBOUND: FAIL a write past the backing store reached the free page pool`), not a missing refusal: an assertion of absence is satisfied by a run that never reached the code. Falsified in both directions — `make smoke-vdisk-bound VDISK_TOTAL_UNBOUNDED=1` goes red on the same marker. |
| `smoke-fs-persist` | Data survives a reboot (two-boot test). |
| `smoke-fs-wal` | The write-ahead journal recovers a crash-interrupted write (two-boot test). Proves the **redo logic**; says nothing about durability, which is what the two gates below are for. Boot 1 ends via a QMP quit and a confirmed process exit, not a signal (**[I-11]**, fixed 2026-08-16, see below). |
| `smoke-fs-wal-flush` | Every `FLUSH CACHE` fails with `EIO` (`blkdebug`), and the journal must **refuse to commit** and say so. Proves the barrier is both *issued* and *checked*. Falsified by `WAL_NO_FLUSH=1`: `make smoke-fs-wal-flush-control`. |
| `smoke-fs-wal-order` | An IDE command-register trace must end `0x30 → 0xe7 → 0x30 → 0xe7`, data write, barrier A, commit header, barrier B. Proves the barriers are in the right *place*, not merely present. Falsified by `WAL_NO_FLUSH=1`: `make smoke-fs-wal-order-control`. |
| `smoke-fs-conc` | Multiple clients are served concurrently without cross-talk, via `SYS_IPC_REPLY_TO`. Uses `CONC_TIMEOUT` (default 120s), not the 40s default: it waits on several clients, and on a loaded host it exceeded the shorter budget and failed as a *timeout*, never reaching a verdict, which reads red without being evidence of a defect. A real `CONC_SELFTEST: FAIL` still fails immediately. |
| `smoke-fs-large` | Double-indirect blocks address large files. |

> **`smoke-fs-wal`: both defects fixed on 2026-08-16 ([I-10] durability, [I-11] harness).**
>
> **[I-10] is fixed as of 2026-08-16, but not by the method originally planned.** The obvious
> fix (re-run the two-boot test under `cache=writeback`) does **not work**, and the reason
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
>   guest write with a write *plus a flush*, so the injected error fails ordinary writes too; 
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
> journal write is on stable media by the time the harness sees the marker; the physical race
> the finding describes was closed by the [I-10] work without anyone saying so.
>
> The diagnostic half is what this fixes. Boot 1 now ends by asking QEMU to quit over its QMP
> monitor (`tools/qmp_quit.py`, driven by `WAIT_FOR_EXIT=1`) and **waiting for the process to
> exit**. The end of a run is a process exit, not a signal sent at a moment of the harness's
> choosing, so a guest that reaches the marker and then fails to leave is a timeout rather than
> a pass. `isa-debug-exit`, which roadmap 1.55 prescribed, does not terminate QEMU 10.0.11; 
> measured, reverted, and recorded at the crash hook.
>
> **Falsification (2026-08-16), four ways**, each confirmed to exit non-zero:
>
> | Reintroduced defect | Result |
> |---|---|
> | `qmp_quit.py` stubbed to refuse | **`crashed-after-commit` on serial, run still FAILS**, the old harness scored that identical log a pass |
> | `python3` absent (minimal `PATH`) | `SMOKE FAIL: WAIT_FOR_EXIT=1 needs python3 for the QMP quit` |
> | `qmp_quit.py` not executable | `SMOKE FAIL: … needs tools/qmp_quit.py to be executable` |
> | unreachable QMP socket | `qmp_quit` exits 1; run reports `could not ask QEMU to quit over QMP` |
>
> The first is the one that matters: the marker alone is no longer sufficient to pass.
>
> **Rate: 20/20 two-boot runs passed**, one fresh 32768-block image per run. Read that as
> corroboration, not proof; the pre-fix flakiness was load-dependent and did not reproduce on
> this machine, so it is not a before/after comparison. The substantive argument is structural.
>
> *Two harness bugs found while doing this, both worth knowing.* An exit the harness **asked
> for** was reported as `QEMU exited before the banner (triple fault?)`, because QEMU could die
> between the inner and outer liveness checks. And an early soak reported 0/20 because the
> images were created 4096 blocks against a `BLOCKS_PER_DISK` of 32768; the volume could not
> lay out and boot 2 failed `WAL_CRASHTEST: FAIL read`, which is *exactly* the signature of the
> defect being measured. A soak that measures its own harness measures nothing; derive the
> image size from `kernel.h` the way the Makefile does.

## Device delegation and the console

| Target | Proves |
|---|---|
| `smoke-net` | A ring-3 driver holding one device capability and one untyped region completes an ARP exchange on the wire (**S44**). Two control arms. |
| `smoke-devcap` | A `CAP_IO_DEVICE` names **one device**: each of two capabilities reaches its own device's frame, port and IRQ, and is refused the other's (**S43**). Three control arms. |
| `smoke-mapphys` | `SYS_MAP_PHYS` maps a frame the named device declares, and only such a frame. |
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
| `smoke-newlib-tamper` | The pinned newlib SHA-256 **refuses** a tampered tarball: before unpacking it, and quarantining it so it cannot wedge the next build. Also asserts the genuine tarball still *passes*, because a gate that refused everything would sail through the negative case alone. No network or QEMU needed. Falsified by disabling the checksum gate: 3 controls fail. |
| `smoke-pipe` | Bounded pipes with `EAGAIN` back-pressure and EOF/EPIPE on close. |
| `smoke-coreutils-shell` | `head`, `wc`, and `seq` run on real files, driven through the actual ring-3 shell. |
| `smoke-tcc` | TCC is provisioned into `/bin` and `tcc -v` runs. (Needs `SMOKE_TIMEOUT=320`.) |
| `smoke-session` | A scripted session drives the real shell over serial and asserts on output. |
| `smoke-session-smp` | The same under SMP. |
| `smoke-session-smp-soak` | `SOAK_RUNS` consecutive SMP sessions, **all** of which must complete. Gates the IPC lost-reply race (see CHANGES.md), which hung ~1 boot in 5, a rate a single-boot test passes four times out of five, which is how it went unnoticed. One hang fails; there is no retry. Falsified at 2/10 hangs against the pre-fix kernel. Each run must also emit `SESSION_TEST: PASS` **and** clear `SOAK_MIN_CHECKS` (default 8) `[ok]` steps, a run that exits 0 having proven nothing is reported `VACUOUS` and fails, so the gate cannot go green on a test that stopped testing. **Keeps evidence:** each failing or vacuous boot's **full serial log** is retained in `$(SOAK_EVIDENCE_DIR)` (default `soak-evidence/`) alongside its stdout, and CI uploads the directory plus the exact `kernel.elf` as artifacts; a clean run removes the directory. Until 2026-08-13 the target reused one temp log, overwrote it every iteration, deleted it at the end and printed `tail -20`, so it destroyed the diagnostic it existed to produce, see G-8 below. **GATING again as of 2026-08-17**, restored in the commit that closed **[G-8]**; it was advisory from 2026-08-09 while that finding was open, and it was correctly reporting a real defect the whole time. |

## Can the kernel be heard when it faults?

| Target | Proves |
|---|---|
| `smoke-kfault` | A page fault taken at **CPL 0** is reported on the **serial line**, after the console handover. `KFAULT_INJECT=1` makes the kernel fault on purpose (a read of `0x94`, G-8's exact address) on a timer tick once `console_server` owns the console, and the harness requires the report to appear *after* the login prompt. |
| `smoke-kfault-legacy` | The same injection with reporting restored to `println()` (`KFAULT_LEGACY_PRINTLN=1`): the report must **not** reach serial. The control arm. |
| `smoke-resume-guard` | `idt.c`'s resume-`%rsp` floor guard fires and is **heard**. `RESUME_RSP_INJECT=1` forces the dispatcher to return a bogus resume `%rsp` of `4` (G-8's own recorded value) once, after the console handover; the `PANIC: dispatcher returned a bogus resume rsp=0x4` line must appear after the login prompt. Replaces a ~1-in-150 wait with a gate. |
| `smoke-resume-guard-preclaim` | The same, with the **permanent panic claim already held**, the state another CPU's fatal exception leaves behind. The report must still get out. This is the arm that witnesses the fix. |
| `smoke-resume-guard-legacy` | Control arm for the fix: same injection and claim, with the guard's pre-fix `kfault_begin(1)`/`kfault_end(1)` bracket restored (`RESUME_GUARD_LEGACY_FATAL=1`). The report must **not** reach serial; the boot goes silent at the login prompt, which is the defect on demand. |
| `smoke-resume-guard-nofloor` | Control arm for the guard: same injection, guard compiled out (`RESUME_GUARD_DISABLE=1`). The PANIC line must **not** appear; the kernel instead faults at `0x94` on `out->cs`, which is G-8's original datapoint reproduced deliberately. |
| `smoke-kstack-race` | **S20**, a task's kernel stack is executed by at most one CPU at a time. `KSTACK_RACE_WIDEN=1` stretches the window between handing a task to another CPU and the ISR epilogue leaving that task's stack, so it is entered on essentially every switch instead of at **[G-8]**'s 2–3% per boot. With the deferred release the claim is held across the window, so nothing can take the stack: the session must complete and `PANIC: two CPUs on one kernel stack` must be **absent**. Since 2026-08-27 it distinguishes a **broken property** from an **inconclusive run**: up to `KSTACK_RACE_BOOTS` (4) attempts, stopping at the first completed session; a detected race fails immediately on any attempt and is never retried; all-inconclusive **fails**. |
| `smoke-kstack-park` | **Merge-gating since #190** (advisory before that, for **[G-9]**, now closed). **S20**, park path: a CPU whose last runnable task dies parks on its **own** ring-0 stack. Boots the task-killing `PROC_SELFTEST` at `-smp 4` (a healthy session never enters the path: 0 parks in 3 boots) and asserts four things, because three of them pass vacuously alone: the self-test completes, at least two CPUs actually parked, no park stack was used by more than one CPU, and `sched_note_park()`'s report is absent. |
| `smoke-kstack-park-control` | Control arm. Same workload with `KSTACK0_SHARED_PARK=1` restoring `tasks[0].kernel_stack_top` as the shared park target; at least one park stack must come back used by **more than one CPU**. Accepts either that or the kernel's own collision PANIC, `sched_note_park` *halts* on detecting the second CPU, so on exactly those boots the second `PARKTRACE` line never prints and a trace-only test scores the hardest reproduction as a miss. **Boots until it reproduces, up to `KSTACK_PARK_CONTROL_BOOTS` (8) boots that RAN TO COMPLETION or `KSTACK_PARK_CONTROL_ATTEMPTS` (24) attempts, whichever comes first.** A boot the workload *died* in (`PROC_SELFTEST: FAIL`) is **inconclusive**, not a miss: the park path was never exercised to the end, so it is evidence in neither direction, and it is named, tallied and re-booted rather than spent. That distinction is the whole gate: the deaths are `KSTACK0_PARK_TRACE`'s doing, 8 of 20 boots against 0 of 20 without it on the same *fixed* kernel (p = 0.0016): so they say nothing about the park target. Exhausting the attempts is a *differently worded* red, because a run that could not measure must not read like one that measured. |
| `smoke-resume-guard-negative` | **[G-9]** residual, detector half. The resume-`%rsp` guard must reject a *negative* bogus value. `RESUME_RSP_INJECT_VALUE=-7` forces the dispatcher to return `-7` once after the console handover; the guard's PANIC line must reach serial. Until 2026-08-18 the predicate was `rsp < 0xFFFF800000000000ULL` (a floor with no ceiling) so `-7` (`0xFFFFFFFFFFFFFFF9`) sailed over it and faulted inside the ISR epilogue instead, with a banner naming the stub and nothing about the value. The bound is now `[__bss_start, __bss_end)`, taken from the linker, because every 64-bit kernel stack is a `.bss` array. |
| `smoke-resume-guard-negative-control` | Control arm. `RESUME_GUARD_FLOOR_ONLY=1` restores the floor-only predicate; the report must be **absent**. Note the regex matches the injected *value*, not just the banner; the first version of this pair reused the `rsp=0x4` regex from `smoke-resume-guard`, which made the `EXPECT_REPORT=1` arm fail against a guard that was working correctly and, worse, made this control arm **pass vacuously**: a pattern that can never match is trivially absent. A control arm that cannot fail is not a control arm. |
| `smoke-resume-guard-ist` | The guard's **false-positive** arm, and the one whose absence let a regression ship. Every other arm injects a bogus value and asks whether the report appears: they measure false *negatives*, so a predicate that rejected the whole address space would pass all of them. This one injects nothing: it boots the captest workload, which faults through IST1 as a matter of course, and requires `CAPTEST: PASS 100 checks` with the guard's report **absent**. |
| `smoke-resume-guard-ist-control` | Control arm. `RESUME_GUARD_BSS_ONLY=1` restores the bound the ceiling first shipped with: `[__bss_start, __bss_end)` alone, on the premise that every 64-bit kernel stack is a `.bss` array. The three IST stacks are in `.data`; IST1 serves `#DF`/`#GP`/`#PF`; the guard halts on a rejection. So that build dies on the first ring-3 page fault with `bogus resume rsp=0xffffffff801a9f50`: an address `0xf50` into `ist1_stack_bottom`'s page. Requires that fault to be **present**, via `smoke_test.sh`'s `EXPECT_FAULT` (`kfault_test.sh` cannot serve here: it anchors its verdict after the console handover, and this build dies long before a login prompt). |
| `smoke-cr3-reclaim` | **[G-10]**, page-table half. A task slot's page tables must not be recycled while any CPU still has them loaded in CR3. Boots the `PROC_SELFTEST` workload at `-smp 4` `CR3_RECLAIM_RUNS` times (default 20) and requires no supervisor write fault at `0xFEE000B0`; the LAPIC EOI register, which lives in each task's own `pml4[0]` identity map and is therefore the first thing to disappear when a leaf PTE is recycled. Measured 0 in 30, against 6 in 30 before the fix. Asserts on the marker, not on the boot's exit status: when this gate was written the rest of **[G-9]** was open and failed ~7% of these boots, and this gate is not about that. [G-9] closed on 2026-08-21; the marker-only assertion stays, because a gate that also required completion would go red for reasons outside the property it witnesses. **It does now require that the boots happened at all.** Until 2026-08-30 it did not, and `make smoke-cr3-reclaim CR3_RECLAIM_TIMEOUT=2` — every boot dead at GRUB — exited 0 reporting PASS. Boots printing `CR3_RECLAIM_LIVE_RE` are counted and the gate refuses to conclude below `CR3_RECLAIM_MIN_LIVE` (10 of 20), which keeps the tolerance the marker-only assertion is for while making the vacuous case impossible. |
| `smoke-cr3-reclaim-control` | Control arm. `CR3_RECLAIM_UNGUARDED=1` restores the unconditional free; the free-in-use report must come back. Only `CR3_RECLAIM_CONTROL_BOOTS` (3) boots are needed because it is deterministic (measured 20 in 20, and 3 in 3 on 2026-08-30) which is also why the pair asserts different markers: the free-in-use happens every boot while the fault it causes lands on ~20%, so gating this arm on the fault would be flaky for no gain. Scores every boot HIT / clean / INCONCLUSIVE and keeps the serial log when it goes red, for the reason recorded against `smoke-exec-reenter-control`. Falsified against the *guarded* kernel on 2026-08-30 with `CR3_RECLAIM_CONTROL_FLAG=0`: **0 hit, 3 clean**, red — so the arm is still able to tell the two kernels apart. |
| `smoke-spawn-owner` | **[G-11]**, property **S21**. A staged program image is spawnable only by the task that armed it. One boot with `SPAWN_OWNER_SELFTEST=1`: the self-test forges a foreign owner on a legitimately staged image and requires `do_spawn` to refuse it, then re-arms honestly and requires the spawn to succeed. Deterministic: the concurrent half of roadmap 1.7 is not reachable in any bootable workload (see the G-10 section), and this gate is about the rule rather than the race. Control arm `SPAWN_OWNER_UNCHECKED=1` (`make smoke-spawn-owner-control`) removes the refusal and spawns the foreign image on every boot. |
| `smoke-klog-forge` | **[H-2]**, property **S23**. A ring-3 task cannot forge entries into the kernel message ring, nor evict what is already there. One boot with `KLOG_FORGE_SELFTEST=1`: the kernel seeds a marker into `klog` immediately before ring-3 entry, and a probe endowed with `CAP_KERNEL_LOG` pushes 28800 bytes of a distinctive pattern through `SYS_WRITE` fd 1 (more than the 16 KiB ring holds) then reads the ring back through `SYS_DMESG` and requires the pattern **absent** and the marker **present**. Deterministic; nothing here is racy. **The probe is endowed on purpose.** Its capability carries `CAP_RIGHT_READ` and nothing else, because `root_cnode[15]` mints it that way and delegation may only narrow, so it can read the ring to check its own work and is still refused the direction it was not given. A bare task would have proved that a task holding *no* capability cannot write, which is a weaker claim than the one the finding makes. |
| `smoke-rng-seed` | Property **S30**. The CSPRNG refuses to emit keystream from a pool that has never been reseeded from real entropy. Both arms build with `RNG_UNSEEDED_PROBE=1`, which asks for 16 bytes immediately before `entropy_init()`. Asserts the refusal **and** a boot that still reaches the shell banner, in one run: a `fill()` that refuses everything satisfies the first half and dies on the second. Until 2026-08-23 the property held only by boot ordering (`entropy_init` runs before the first consumer) which is a fact about one call site rather than anything the RNG enforced. |
| `smoke-rng-seed-control` | Control arm. `RNG_UNSEEDED_LEGACY=1` passes a **cargo feature** down rather than a `-D`, compiling the `!self.seeded` check out of `RngState::fill`; `RNGPROBE: SERVED unseeded keystream` must come back, 3 boots in 3, and `smoke-rng-seed` goes red under the same flag. Paired with the Rust arm in the `rust` job, where `rng_refuses_before_seeding` must fail and `rng_serves_after_seeding` must not. |
| `smoke-session` (2026-08-23) | **Roadmap 3.6's positive half.** The scripted session runs `capview` and requires the shell's **own** `debug` capability with `r-----` rights, not merely that something printed. "No capabilities anywhere" is exactly what a broken readout looks like, and the read-only rights are part of the claim: `CAP_DEBUG` observes and cannot be widened into anything that writes. |
| `smoke-captest-capenum-control` | `CAP_ENUMERATE_UNGATED=1` removes `SYS_CAP_ENUMERATE`'s declared capability, so the central gate admits everyone and captest (which holds no `CAP_DEBUG`) reads another task's cspace. Aimed at the **gate**, because the handler contains no authority check at all: the table is the gate, so an arm weakening something inside the handler would be testing code that does not exist. |
| `smoke-captest-getline-control` | **An arm that asserts a STALL**, because the failure it reproduces blocks rather than returns. `GETLINE_SLOT3_FALLBACK=1` restores `h_get_line`'s untyped slot-3 fallback; captest (holding that decoy and no `CAP_CONSOLE`) gets past the gate into the console read and waits for input that never comes, printing nothing. `EXPECT_STALL` (added to `tools/smoke_test.sh` for this) makes a timeout a PASS **only** behind three fences: a progress marker that must appear, a forbidden marker that must not, and no fault. Falsified three ways, a build that completes fails it, a missing progress marker fails it, and `EXPECT_STALL` without `ABSENT_MARKER` is refused outright, because a stall on its own proves nothing. |
| `smoke-captest-mint-hang-control` | **The second stall arm, and the one that found a live defect rather than guarding a fixed one.** `CAP_LOOKUP_ASSERT_HANG=1` restores the source-slot resolver `cap_mint` and `cap_transfer` used until 2026-08-29: `cap_lookup` followed by `kassert_cap`, an unconditional `for(;;){}` on NULL, executed while holding `cap_lock` with interrupts masked. captest's section 12 hands those calls an empty slot and an out-of-range slot, both freely nameable from ring 3, and the guest never comes back. Measured 2026-08-29: the run reaches `CAPTEST: cap-derivation-probes` and never prints `CAPTEST: PASS`. `EXPECT_STALL` fences it the same three ways the getline arm is fenced, so a boot that died before the probes fails the arm instead of satisfying it. `make smoke-captest` goes red under the same flag, confirmed by running captest's own assertion against the arm's ISO. **S52.** |
| `smoke-iommu-teardown` | **S53.** An in-kernel witness, run before any ring-3 task exists, under a real VT-d unit (`SMOKE_IOMMU=1`) with a real device on the bus (`SMOKE_NET=e1000`). It retypes a frame, asserts the device does *not* translate it, maps it into the device's domain, asserts it *does*, destroys the frame through the shipping `destroy_dyn_frame`, and asserts the translation is gone. The positive half is load-bearing: without it the final assertion is satisfied by a mapping that was never installed. **Stated limit:** it reads the device's second-level table through a kernel-internal query, so it shows the entry is removed, not that the device observed the removal. A DMA-based witness was rejected rather than skipped, because proving it with a packet means pointing a live device at a page the arena has already reallocated. |
| `smoke-iommu-teardown-control` | The falsifying arm. `IOMMU_NO_FRAME_TEARDOWN=1` restores `destroy_dyn_frame` as it stood until 2026-08-29: the run is scrubbed and returned to the arena with every device translation of it still installed. Measured 2026-08-29: `IOMMUTEST: FAIL device-still-translates-destroyed-frame`. The marker names the specific check rather than any `IOMMUTEST` failure, so an arm that reddens the test for another reason does not satisfy it. The second flag, `IOMMU_NO_TASK_TEARDOWN=1`, has **no arm**: reproducing it needs a driver holding a device capability to die under `SMOKE_IOMMU` while a peer still holds the frame, and no workload here does that yet. |
| captest check ORDER is load-bearing | `fail()` calls `sys_exit()`, so the suite stops at its **first** failing check and a control arm sees only that one marker. A check that fires under some arm therefore cannot be placed before the check that arm's marker names, on 2026-08-24 one was, and `smoke-captest-capenum-control` timed out waiting for a line captest never reached. Stated in the file beside the check that has to sit last. |
| `smoke-proc-taskinfo-control` | **The narrowing of cross-task introspection** (roadmap 3.6). `TASKINFO_WIDE_AUTHORITY=1` lets `CAP_USER` or `CAP_AUDIT` answer "may I see the process list" again. The witness is `grantee` (the one task in the tree holding a granted `CAP_AUDIT` and **no** `CAP_DEBUG`) and it proves that capability is live via `SYS_READ_AUDIT` **before** asserting the refusal, so "it holds nothing" cannot explain the pass. It also reads its own info successfully, so a blanket refusal cannot either. |
| `smoke-captest` (clock, 2026-08-24) | Seven checks on `SYS_CLOCK_GETTIME` (roadmap 2.2): `nsec` in range and a whole PIT tick, `reserved` zeroed, a second read that never goes backwards, and three refused clock ids. The resolution check is the security-relevant one, if `nsec` stopped being a multiple of a tick, the syscall would be handing back the cycle-accurate timer `CR4.TSD` exists to deny, and nothing else in the tree would notice. |
| `smoke-captest-clock-control` | **A control arm whose defect is an improvement.** `CLOCK_TSC_RESOLUTION=1` reports real microseconds off the calibrated TSC: more accurate, more useful, and it undoes `CR4.TSD`. `CAPTEST: FAIL clock-resolution-finer-than-a-pit-tick` must appear. Worth having precisely because the tempting mistake here does not look like a mistake. |
| `miri` | **The only check here that looks for undefined behaviour.** `cargo miri test` interprets the security core and checks out-of-bounds access, invalid pointer use, and the Stacked Borrows aliasing rules, which is what raw-pointer FFI breaks. 77 tests, ~2 minutes, no `continue-on-error`. Four crypto modules are excused in `.github/miri-scope.yml` (argon2 is memory-hard by construction and does not finish under an interpreter; the other three have no `unsafe` at all), and `tools/check_miri_scope.py` fails the build on a module that is neither run nor excused. **The job derives its `--skip` flags from that manifest**, so the scope and the command are one list rather than two that can drift. |
| `kani-bounded` | **The first Kani job that can fail anything.** Eleven harnesses over the capability algebra, run with no `continue-on-error`, plus `check_kani_harnesses.py` refusing a proof classified as neither gating nor excused. The advisory `kani` job it sits beside is `workflow_dispatch`-only *and* `continue-on-error` on every step, thirteen proofs that could not redden a build, which is `smoke-kstack-park`'s shape applied to formal verification. 319 s measured end to end; the four excused harnesses are named with reasons in `.github/kani-harnesses.yml`. |
| `smoke-passwd-probe` (2026-08-23) | **Eight checks now, not four.** The probe (uid 1000, no delegated capability) also asserts that the four syscalls retired that day fail closed at `SYS_ERR_NOSYS`. The one that matters is `SYS_EXEC_LEGACY` (14): it **created a task**, authorised on cspace slot 3, and this probe was handed task id 2 by it before it was removed. |
| `smoke-passwd-probe-legacy-control` | `LEGACY_SYSCALLS_PRESENT=1` restores all four entries. The required marker is `FAIL legacy-exec-spawned-a-task` specifically, so an arm that reddened the probe for any other reason would not satisfy it; the same discipline as the two `smoke-newlib` arms failing at different markers. |
| `smoke-measured-boot-required` | **The kernel half of `docs/LIMITATIONS.md` §2.9.** `MEASURED_BOOT_REQUIRED=1` makes an unavailable measured boot fatal. The base arm boots that build **under swtpm** and requires `tpm: measured boot OK`, because a gate that only checked the refusal is passed by a kernel that halts on every boot, which is the same shape as the `KSP_GUARD_ALWAYS` mutation. |
| `smoke-measured-boot-required-control` / `-volume-control` | Two refusals, two arms. Without a TPM the machine must halt (`no TPM present`); the exact case §2.9 described. With a TPM but an **unsealed volume** it must refuse to unlock: a never-sealed volume opens on its password alone, so a re-formatted disk would make the requirement evaporate. The default boot runs on the exempt ephemeral vdisk, so `MEASURED_VOLUME_EXEMPT_NONE=1` removes the exemption to reach the branch; the arm proves the refusal fires, **not** that a persistent on-disk volume reaches it, and that gap is stated in §2.9 rather than implied. Both assert through `EXPECT_FAULT`, since the success condition is a halt and `PANIC` is in the harness's fault regex on purpose. |
| `smoke-newlib` (2026-08-23) | **Roadmap 2.4's witness.** The libc walks paths through `hvfs` now, so this gate asserts `.` and `..` in paths passed to `open()`; the paths a libc program actually uses, and the ones a private walker got wrong. Four checks: `.` resolves, `..` steps back out of a directory the walker descended, `..` is pinned at the mount root rather than erroring, and a missing name under a `..` prefix is still `ENOENT`. |
| `smoke-newlib-walk-control` / `-dotdot-control` | Two arms, two different defects, and they fail at **different markers** on purpose. `POSIX_LEGACY_WALK=1` restores `posix.c`'s private walker: `FAIL dot-here`, the first check, because it resolves neither. `HVFS_DOTDOT_SERVER=1` restores hvfs's original `..` branch, which asks `fs_server` for a `..` entry it never creates: `FAIL dotdot-back`, `.` still works, and only the descending `..` does not. That branch shipped **dead** in #195 and nothing caught it, because the one test touching `..` used the pinned case, which returns before the lookup. A gate that only checked "some `..` works" would still be passing. |
| `smoke-defect-flags` / `-control` | **Build provenance.** Every boot prints `DEFECT FLAGS: <list>` or `DEFECT FLAGS: none`, compiled in from the Makefile's `DEFECT_FLAGS` list. It prints **unconditionally**, including the clean case: an absent line is ambiguous between "clean", "the reporting was removed" and "the boot died early", and only one of those is good news. The control arm builds with `KSP_GUARD_INJECT=1` and requires the flag to be named, without it, a kernel that printed `none` unconditionally would satisfy the gate. |
| `smoke-defect-flags-rebuild` / `-control` | **The footgun itself.** A `-D` flag is not a prerequisite of an object file, so `make FLAG=1` then `make` leaves every unchanged `.c` compiled with the flag and says nothing. On 2026-08-20 that gave a [G-9] measurement campaign a kernel still carrying `KSP_GUARD_INJECT`: the guard "fired" in 2 boots of 3 with the injected constant, which briefly read as a reproduction of the defect being hunted. It was caught because `-7` is implausibly exact and 67% implausibly high, by luck, not method. The gate builds injected, rebuilds **without** `clean` or the flag, and requires `none`. `BUILD_FLAGS_UNSTAMPED=1` drops the `.build-flags` dependency and requires the stale flag to **survive**, which is what proves the stamp is doing the work. |
| `gate-pairs` | **The coverage question applied to the gates themselves.** `tools/check_gate_pairs.py` enforces four structural rules, each violated at least once in this tree: a control arm must extend a base gate that exists; a control arm must actually be invoked by CI; a gate must be invoked or listed in `.github/gate-exceptions.yml` with a reason; and an exception must name a real target and give one. Source analysis, no build. Falsified all four ways, orphan arm, unrun arm, stale exception, empty reason. It was written because `smoke-ksp-guard-control` had **no positive counterpart**: an arm proving the guard *could* fire, with nothing asking whether it stayed silent on a legal value. The same job also runs `tools/check_gate_evidence.py`, which refuses a multi-boot gate that cannot tell a dead boot from a passing one — every `smoke-*` target that loops over boots must be declared in `.github/gate-evidence.yml`, either with the marker and floor it uses to count live boots (both of which must be real Makefile variables, *read by a grep* and *compared against in a numeric test* respectively) or with a written reason naming the mechanism it uses instead. Declarative rather than inferred, because the sweep that found the defect flagged six targets and four were false positives establishing liveness correctly in four different ways. Falsified six ways; rule 3 failed first and had to be strengthened, because it accepted a floor that was merely *present* in the recipe — which a floor quoted in the failure message satisfies while the comparison beside it reads `-lt 0`. |
| `smoke-ksp-guard` | The **false-positive** arm for the producer-side resume-`%rsp` guard, and the direction whose absence is a known way to ship a regression. Every other arm on this guard injects a bogus value and asks whether it fires: they measure false *negatives*, and a predicate that rejected every stack pointer would satisfy all of them. This boots the **default** workload, where every resume value is legal, and requires `SCHED BOGUS KSP` to be **absent**. Falsified by `KSP_GUARD_ALWAYS=1`, which makes `ksp_is_bogus()` reject everything: the guard then fires on a legitimate address (`ipc_block_switch task=2 ksp=0xffffffff8020cf40`) and the gate goes red. The default workload rather than `PROC_SELFTEST` on purpose; the latter still trips [G-9] on ~1–2% of boots and would make this intermittently red for an unrelated reason. |
| `smoke-ksp-guard-control` | **[G-9]**, producer side. All four switch functions (`preempt_on_tick`, `ipc_block_switch`, `sched_yield_switch`, `task_exit_switch`) end in the same three lines (take `tasks[next].saved_ksp`, drop the lock, return it) and every selection loop above them required that value to be merely **non-zero**. Each now validates it **against the page tables** (`kern_addr_present`), not an address range: `per_task_kstacks`, `ap_idle_stacks` and `ap_ist` all live inside `[__bss_start, __bss_end)` and their guards are armed by being made *absent*, so a pointer sitting in a guard page passes every range test in the tree. Both the value and the byte 8 below it are checked, since that is where the epilogue pushes. On failure it names the producing function and returns 0, so the caller parks instead of `iretq`-ing onto it. `KSP_GUARD_INJECT=1` forges `-7` and requires `SCHED BOGUS KSP from task_exit_switch` on the wire. **A detector, not a fix**, across 57 pinned boots containing a live reproduction it did not fire once, which is what rules those four producers out. |
| `syscall-coverage` | **The coverage claim over the syscall table.** Boots three workloads under `SYSCALL_COVERAGE=1` (the scripted ring-3 session, the conformance suite, and the boot-modules session) and records which syscall **handler bodies** are entered, then diffs the union against `.github/syscall-coverage.yml`. Currently **82 of 94** implemented syscalls. It does not demand all of them; it demands the number be decided rather than drifting, and every gap be written down. Fails four ways, all falsified: a syscall in neither list, a `covered` one whose handler stopped running, an `uncovered` one whose handler *did* run (a stale reason), and a serial log with no `SYSCOV` lines at all; that last is what stops a mis-built arm from reporting a page of spurious regressions, or an empty log from passing silently. |
| `syscall-coverage` | **The coverage claim over the syscall table.** Boots three workloads under `SYSCALL_COVERAGE=1` (the scripted ring-3 session, the conformance suite, and the boot-modules session) and records which syscall **handler bodies** are entered, then diffs the union against `.github/syscall-coverage.yml`. Currently **82 of 94** implemented syscalls. It does not demand all of them; it demands the number be decided rather than drifting, and every gap be written down. Fails four ways, all falsified: a syscall in neither list, a `covered` one whose handler stopped running, an `uncovered` one whose handler *did* run (a stale reason), and a serial log with no `SYSCOV` lines at all; that last is what stops a mis-built arm from reporting a page of spurious regressions, or an empty log from passing silently. |
| `smoke-proc` (2026-08-30) | **Creating a task now costs authority**, property **S57**, and this gate is where it is witnessed. `grantee` is spawned by `proctest` and deliberately **not** endowed with `CAP_UNTYPED` — it is literally "a task spawned without the right to spawn further tasks", which is the property audit finding 4.1 asked for — and asserts that `SYS_SPAWN`, `SYS_FORK` and `SYS_SPAWN_IMAGE` all return **`SYS_ERR_PERM`**. That error specifically: a spawn can fail for want of a free slot, a bad name, or an unarmed image, and none of those says anything about authority. The distinction between "refused" and "failed" is the whole test. |
| `smoke-proc-spawn-decoy-control` | Control arm. `SPAWN_SLOT3_DECOY_GATE=1` restores the pre-fix gate — cspace slot 3 with `SC_ANYTYPE`, which `create_task` fills in **every** task — and `grantee` can then spawn: `PROC_SELFTEST: FAIL spawn-without-untyped`, base gate red under the same flag. **The arm is what shows the old gate was vacuous rather than merely different**: the un-endowed child passes it, which is what "the check could not fail" means in practice. |
| `smoke-proc` (what the endowments say) | Worth recording because the change is visible in *policy*, not only in code. Three tasks gained a `CAP_UNTYPED` because they create tasks: the **shell** (`spawn` is a shell command), **proctest**, and — already held — `init`. Each grant is now a written, revocable statement that this task may create tasks, where previously every task could and no grant expressed anything. `grantee` is the control: it is spawned by a task that holds one and is not given it. |
| `smoke-captest` section 14 | **A budget can be subdivided**, property **S58**, and it repairs an overclaim rather than adding a feature. S57 said *"a task given a small region can spawn a bounded number of times"* while nothing could mint a small region — `SYS_CAP_GRANT` of a `CAP_UNTYPED` names the **same** region, so a delegate got its grantor's whole budget. The checks are all about the parent paying: the child is the size asked for and **born unspent**, it is **retypable** (a region that cannot be spent is a budget in name only), and `after.free + child.size <= before.free` — an inequality rather than an equality, because the carve is page-aligned so the parent may also lose padding, but it must never lose *less* than it handed over, which is the direction that would mean the split created memory. A **refused** split must leave the caller's free bytes unchanged: asking for something you cannot pay for must not cost anything. Plus the [C-1] shapes this suite asks of every syscall — an empty source slot, a wrong-type source, a kernel-reserved destination, a zero length. |
| `smoke-captest-lookup-type-control` | Control arm for **S60**. `CAP_LOOKUP_TYPE_UNCHECKED=1` restores the pre-2026-08-31 resolver, which returned whatever the slot held and left the type to its ~40 callers; because the dispatch table's own `c->type != d->ctype` test was folded into the same call, the syscall gate's type enforcement goes with it. captest then reports `FAIL notification-cap-authorised-endpoint-recv` — a `CAP_NOTIFICATION` authorising an endpoint receive. **What it does not claim:** every live caller tested its own type before the change, so the flag reopens nothing that was ever open. It witnesses that the rule now lives in ONE place, by deleting that place. Measured 2026-08-31: base `CAPTEST: PASS`, arm red with the marker. |
| `smoke-captest-split-control` | Control arm. `UNTYPED_SPLIT_FREE_BYTES=1` stops the parent's watermark advancing, so the split mints memory instead of spending it and two capabilities name overlapping bytes: `CAPTEST: FAIL split-did-not-charge-the-parent`, base gate red under the same flag. Measured 2026-08-30. |
| `smoke-captest` (a deadlock found by hanging) | **The witness above found a defect in the code it was written for, by not finishing.** `cap_mint_untyped_child` called `cap_alloc_fresh_serial()` while holding `cap_lock` — and that function takes `cap_lock` itself, on a spinlock with no recursion, with interrupts masked. That is **S52's exact shape**, "a refused capability operation that halts instead of returning", reintroduced by the commit adding the split. It presented as `smoke-captest` timing out at 40s with no FAIL marker, which is precisely why S52's own arm asserts a **stall** rather than a marker. The serial is allocated before the lock now, as every other mint site in this tree already does. |
| `smoke-init-provision` | **A supervisor provisions a server on an endpoint it created**, property **S59**. Every other server `init` launches is delegated an endpoint the *kernel* minted into its cspace before ring 3 existed; this one `init` retypes from its own untyped, so the object does not exist at boot. The probe drives `FS_OP_STAT` on the server's root inode — the same operation `hvfs_mount` performs to decide whether a mount can be installed, so a server that answers it is one a mount table can mount. **`init` is its own client**, which is the tightest statement rather than a shortcut: the server got `READ`, `init` kept a `WRITE`-only mint, so a completed round trip proves both halves reached the right task *and* that `init` did not keep the receive right — a request it could dequeue would answer itself. |
| `smoke-init-provision-control` | Control arm. `INIT_PROVISION_NO_UNTYPED=1` retypes from a slot holding no `CAP_UNTYPED` — the state `ROADMAP.md` asserted `init` was permanently in — and the provisioning stops at step 1; base gate red under the same flag. Without it, "init provisioned a server" is consistent with the untyped being irrelevant. |
| `smoke-init-provision` (a blocker that was never true) | **The bullet this closes was stale, and the staleness was the cost.** `ROADMAP.md` said *"`init` cannot provision a mount yet. It holds no `CAP_UNTYPED`… Giving the delegation root that authority is a real widening and belongs in its own commit."* `init` holds one — `kshell.c` installs it at boot with a comment saying so, and `init` grants it onward to the shell, which it could not do otherwise. Measured before any code was written: `PROBE: untyped_info rc=0` / `retype endpoint -> OK` / `second endpoint -> OK`. The *observation* was right (the VFS gate does install `dev_server`'s cap from the root cnode); the *explanation* and the conclusion were not, and the "real widening" had already happened. **A blocker nobody re-tests is indistinguishable from a real one** — this one made the item look expensive for as long as it stood. |
| `smoke-init-provision` (what the gate caught) | Four defects while building it, each named by a different mechanism. (1) The flag reached `CFLAGS` but not `USERSPACE_CFLAGS`, so the ring-3 probe **compiled out and printed nothing at all** — no PASS, no FAIL, which reads as a hang; that is the trap `SYSCALL_PTR_TRUNC32`'s comment records as *"first written and silently did nothing"*, walked into again and caught by the gate's own timeout. (2) A failure that did not say **which step** cost a rebuild to read, so the message names the stage now. (3) A scripted edit landed the externs **inside** a neighbouring `#ifdef`, caught by `unterminated #ifdef`. (4) The probe used inode **1** for `dev_server`'s root, which is `0` — and the check caught it precisely because it asserts the reply is a mountable *directory* rather than merely that a reply arrived. |
| `smoke-cspace-release` | **A dead task holds no capability**, property **S56**. `task_teardown` released every device resource a task held — IRQ route, MSI route, IOMMU domain, port grant, console, pipe ends — and left its **capabilities** in its cspace until the slot was next used, which may be never. Nothing could reach them, and that is the point: three separate readers each avoided a dead cspace by testing `state == 0` (`mark_reachable`, `h_cap_enumerate`, `create_task`'s zeroing), so the property was held by three readers agreeing about a flag rather than by the data. The witness plants the **primordial `CAP_CONSOLE`** in a scratch task and tears it down **through `task_teardown`**, not by calling `cap_release_cspace` — a witness that calls the function under test proves the function works and says nothing about whether anything invokes it. It checks **every** slot, not just the planted one; and it checks the cspace **pointer survives** and the slot is **reusable**, because a teardown that destroyed the cspace outright, or a `create_task` that could no longer install anything, would satisfy the emptiness check while breaking task creation. |
| `smoke-cspace-release-control` | Control arm. `CSPACE_KEEP_ON_TEARDOWN=1` restores the pre-fix teardown; measured 2026-08-30, the dead task still holds **slot 0 — its own `CAP_TCB`** (`FAIL a dead task still holds capability slot 0 (type 1)`), and the base gate is red under the same flag. The marker naming slot 0 rather than the planted `CAP_CONSOLE` is the loop reaching the lowest occupied slot first, and is the stronger evidence: what survives a task's death is the capability naming the task itself. |
| `CSPACE_RELEASE_BEFORE_PIPES` (an arm that cannot fail) | The release must run **after** `pipe_close_task_ends`, which walks the cspace for `CAP_PIPE` and unrefs each end so the peer sees EOF. Move it earlier and that function finds nothing: the peer waits forever. A comment saying "do not move this" is not a gate, so the arm was written — and then **measured, not assumed**. `smoke-pipe` and `smoke-modules` (a real two-stage pipeline out of `/bin`) **both pass under it**, because every pipe user in this tree closes its ends explicitly (`shell.c` after the pipeline, `posix.c` on fd close), so by the time a stage dies the teardown backstop has nothing to find — it exists for a task that dies *without* closing, and no workload here does that while holding a pipe end. Kept and ungated: **a control arm that cannot fail cannot gate**, the same call `SPAWN_STAGE_UNSERIALISED` and `NET_NO_BUSMASTER` got. It becomes a gate the day a workload kills a task mid-pipeline. |
| `smoke-cspace-release` (what "reclaim" cannot mean) | Worth recording because every document said the opposite. **The bytes are not returned and must not be.** `untyped.c`'s header: *"With a free list, an object's bytes can be handed straight back out and retyped as a DIFFERENT class while a stale capability still names the old address — the classic type-confusion-through-reuse."* And `UNTYPED_KERNEL_BYTES` holds exactly `MAX_TASKS` cspaces with a watermark that never rewinds, so a free-then-reallocate exhausts the reserve on the first slot reuse and `create_task` halts the machine. The gate asserts the pointer **survives** precisely so a future "improvement" that frees it goes red. |
| `smoke-cap-lookup` | **`cap_lookup` fails closed**, property **S55**. The single resolver every capability gate goes through used to end in `else { root_cnode }`, reached two ways: a task with **no cspace** resolved every slot against the primordial root cnode, and a task asking **past the end of its own cspace** got `root_cnode[slot]` — the same escalation by arithmetic rather than by a null pointer, and documented nowhere. **Neither was reachable, and neither by a property of `cap_lookup`**: the first rests on `create_task` halting rather than running a task whose cspace allocation failed, the second on it setting `cspace_size = CNODE_SIZE` — one assignment, in another file. So the witness **manufactures** both conditions (a scratch task with its cspace nulled; one with a deliberately short cspace), because a refusal test whose ungated path could not have succeeded witnesses nothing. It also checks that **task 0 still resolves**: both refusals are satisfied by a `cap_lookup` returning NULL for everything, which would break every gate in the kernel while passing. |
| `smoke-cap-lookup-control` | Control arm, rule 1 of 2. `CAP_LOOKUP_ROOT_FALLBACK=1` restores the whole `else`; measured 2026-08-30, the cspace-less probe resolves a live primordial `CAP_CONSOLE` and the witness reports `FAIL cspace-less task resolved a primordial capability`. Base gate red under the flag. |
| `smoke-cap-lookup` (self-review) | Two things worth checking rather than assuming, both checked. `set_current_task` loads the TSS I/O bitmap from `tasks[v].io_device`, so impersonating a scratch slot could in principle have granted it a device's ports — `IODEV_NONE` is 0 and `scheduler_init` zeroes `tasks[]`, so a zeroed slot grants nothing. And `saved_state` was declared `uint8_t` against a `uint32_t` `tcb.state`: a truncating restore, harmless only while every state value fits in a byte, which is a fact about the enum rather than about this code. |
| `smoke-cap-lookup-range-control` | Control arm, rule 2 of 2. `CAP_LOOKUP_RANGE_FALLBACK=1` restores **only** the out-of-range half — the caller keeps its cspace and a slot past its end resolves in the root cnode: `FAIL a slot past the caller's cspace resolved in the root cnode`, base gate red. **A second arm because the witness returns at its first failure**, so under the arm above the cspace-less probe fails and the range check is never reached. The arms' ordering is what shows the two rules fail independently — the same reason the device-capability family needs three flags rather than one. |
| `smoke-task-ceiling` (2026-08-30, second pass) | **The ceiling stopped being compile-time.** `tasks[]` is carved from the kernel's untyped reserve, `g_max_tasks` is derived at boot from the reserve that exists, and 127 bounds across fourteen files read it. The boot reports what it arrived at (`tasks: 256 provisioned…`), so the derivation is observable rather than asserted — and it reported **191** on the first run, which is how a real defect surfaced: `untyped.c` recomputed the reserve from `CNODE_SIZE` instead of reading `UNTYPED_KERNEL_BYTES`, so the two drifted the moment the macro grew a TCB allowance. That is **[H-3]**'s shape in the sizing of the region that file exists to manage, and the fix is that one expression is now read by both the allocation and the checks. |
| `smoke-task-ceiling` (what the arms caught) | Two defects found by running the **control arms and `SMP=0`**, not the happy path. The `KSTACK_INFLIGHT_LEGACY_WORD` arm kept `volatile uint64_t g_kstack_inflight[1]` against a shipped pointer and **stopped compiling** — a control arm that does not build is a gate that *cannot fail*, worse than one failing for the wrong reason; both arms share the shipped type now, so the arm tests only the indexing arithmetic. And `SMP=0` broke at the **linker**: `task_running_cpu` and the inflight witness are declared inside `#ifdef SMP` and were being allocated unconditionally. `make SMP=0` is gated because it has silently broken before; here it broke loudly. |
| `smoke-task-ceiling` | **The task ceiling is real, not merely compiled.** `MAX_TASKS` moved 64 → 256 on 2026-08-30, and "it builds and boots" is no evidence for that: a boot uses about six tasks, all below 64, so every defect the change could introduce lives in the range no boot visits. Three things had to scale and **all three fail silently** — an aliased kernel stack (two tasks permanently on one stack, S20 by construction), an aliased inflight bit (the S20 *detector* answering about the wrong task), and a short cspace reserve. The witness asserts on the alias pair **(255, 191)**, the pair each defect makes identical: distinct stacks, distinct cspaces, independent inflight bits, and `kstack_slots_mapped` accounting for exactly two new binds. Runs after `scheduler_init`, which is what makes that counter meaningful. |
| `smoke-task-ceiling-control` | Control arm, rule 1 of 2. `KSTACK_INFLIGHT_LEGACY_WORD=1` restores the pre-2026-08-30 single-word `g_kstack_inflight` — one `uint64_t`, bit selected by `1ULL << t` with no bound on `t`. Measured 2026-08-30: `TASKCEIL_SELFTEST: FAIL setting task 255 also set task 191 -- the witness aliases`, and `make smoke-task-ceiling` goes **red** under the same flag. **This is the arm that matters**, because the defect it restores produces no fault, no warning and no wrong answer for any task below 64: the [G-8] detector simply goes blind above it, and a blind detector is indistinguishable from a clean system. |
| `smoke-task-ceiling-stack-control` | Control arm, rule 2 of 2. `KSTACK_SLOT_INDEX_TRUNC=1` truncates the kernel-stack slot index to 6 bits, so tasks 255 and 191 are permanently bound to one stack. Measured 2026-08-30: `TASKCEIL_SELFTEST: FAIL alias pair shares a kernel stack slot`, base gate **red** under the flag. **Two arms rather than one, and the split is the point**: the flag above blinds the *detector* for S20, this one creates the *condition* S20 describes. A single arm covering both would leave it unestablished that the stack-distinctness check can fire at all. |
| `smoke-wx` (2026-08-30) | **The stack-guard check changed shape when the stacks left `.bss`, and the new shape says more.** It required all `MAX_TASKS` stacks present — true only because they were a static array mapped in its entirety whether a task existed or not. Slots are bound on first use now, so that assertion would fail on a healthy boot. It splits the two cases the array could not distinguish instead: a **bound** slot has its guard absent and its whole stack present (every page, not just the first — a bind that mapped one page and stopped would satisfy a single-page check and fault as soon as the stack grew), an **unbound** slot has both absent, and the bound count is cross-checked against `kstack_slots_mapped` so an empty loop cannot satisfy it vacuously. It also had to move after `scheduler_init` in `main.c`: run before it, nothing is bound and the test passes by inspecting nothing. |
| `smoke-task-ceiling` (self-review) | **Two defects in the change were found by reading it rather than by running it**, and both are the kind a green gate would not have shown. (1) `create_user_pagedir`'s task-0 branch took no lock, correctly, while it only computed an address into a static array — it *allocates* now, and `alloc_user_physical_page` is a bare pop off `free_page_stack` with no locking of its own. Safe today by circumstance (one CPU, once, at boot); it takes `page_lock` now, because "safe as long as nobody calls this again" is a fact about other functions and this file has been bitten by that before. (2) `kstack_bind` returned early when page **0** of a slot was present, so a bind that failed part-way would be reported complete by the next call, handing back a stack top for a stack full of holes — the task runs until it grows past the last mapped page, then takes a not-present supervisor write in an ISR epilogue, which is [G-9]'s signature manufactured. Same fail-open S35 names for `SYS_MAP_REGION`: a partial result reported as a whole one. A partial slot is now completed by the next call, and the counter increments only when a call actually maps something. |
| `smoke-aspace` (2026-08-30) | **Its own new assertion caught a defect in the change that prompted it.** The page accounting began failing by 9 — 8 stack pages plus a page table — because `create_user_pagedir` now binds a permanent kernel stack on first use, and those are deliberately not returned by `free_user_aspace_for_test`. The fix is a warm-up build-and-free before the accounting starts, so every count is address-space pages and nothing else. The assertion added alongside it, that rebuilding an address space binds **no** further stacks, then failed: `kstack_slots_mapped` was incremented on every call rather than every slot, so it counted *binds* and the `smoke-wx` cross-check reading it was passing only because nothing had rebuilt an address space before that test ran. A counter that counts the wrong noun is worse than no counter when two tests read it. |
| `syscall-coverage` (2026-08-30) | **Thirteen syscalls promoted, and the argument was already in the file three times over.** Twelve of the 26 `uncovered` entries carried `SC_NONE` dispatch rows: the central check admits every caller and the authority is tested inside the handler, so the body is reachable from ring 3 by a task holding nothing, and a `captest` probe proving the call says no is a probe that ran the body. That is precisely why `SYS_GET_LINE` (2026-08-24), the device family (2026-08-28) and S52's capability trio (2026-08-29) were promoted, each written up in the manifest as "the same structural reason". Nobody had asked it of the whole list. `captest` section 13 enters twelve; `tools/session_test.py` gains an `rm` for the thirteenth, `SYS_FS_INODE_FREE`, which `fs_server` calls on its unlink path and which was one shell command away from running on every session boot. **65 → 78 of 91.** |
| `smoke-syscall-coverage-control` | Control arm for the promotion above. `SYSCOV_PROBES_ABSENT=1` compiles section 13 out and the coverage gate must go red naming **exactly** the twelve, asserted as a set rather than as "it failed": measured 2026-08-30, `CONTROL PASS: section 13 removed, and the coverage gate names exactly its twelve`, against a base arm reporting `handler entered (measured): 78` = `declared covered: 78`. **The arm is what makes the promotion a measurement.** Without it a promotion the probes earned is indistinguishable from one that was free all along, some other workload already entering the body, in which case deleting the probes would leave this gate green. It rebuilds and reboots **all three** workloads though the flag changes only `captest`, because running the one arm leaves the other two transcripts missing and the checker then also names the eight syscalls only the modules session enters, reddening the gate without the defect contributing anything. `SYS_FS_INODE_FREE` is deliberately **not** in the expected set: the flag does not touch the session. The base gate's own reddening was measured separately and in the form the checker runs it, `tools/check_base_gate_reddens.sh SYSCOV_PROBES_ABSENT` → RED: the control target asserting the checker fails is not the same statement as the documented `must go red`, and the two come apart whenever an arm watches a marker its gate does not. |
| `smoke-captest` section 13 | **The reachability claim, and where it stops.** Nineteen checks over the twelve handlers it promotes (139 → 158 for the suite), each leaving `captest`'s state as it found it because the section is followed by none that would read what it changed — `brk(0)` is the query form, and the `sigaction` probe takes the refusal path, which returns before `sig_handler` is written. Two SC_NONE handlers were **not** promoted, and both were found by trying: `SYS_GET_PASS` blocks (its only early return is `console_hw_owned()`, no ring-3 server owns the UART in this image, and the first draft of the probe hung the gate for the full 40s timeout with no marker) and `SYS_SHLIB_INFO` would enter a body that returns at its first line because `shlib_active()` is false in every tracked image. **"The body was entered" stops being coverage when the body is one branch of a feature compiled out.** The fd-0 hang is the sharper lesson: `SYS_GET_LINE` is `covered` by a refusal and looks identical from the dispatch table, but `h_get_line` tests `CAP_CONSOLE` inside the handler where `h_read`'s fd 0 branch tests no authority at all. The probe reads fd 3 instead, which asserts the retired [H-3] ramfs door still answers `SYS_ERR_NOSYS` — a branch nothing had checked since it was shut. |
| `syscall-coverage` (2026-08-23) | **The deriver now describes a kernel that exists.** `scan_table` evaluates the preprocessor, so the three entries compiled only under a defect arm or a selftest flag stop counting as shipped and move to a `conditional:` section that records the flag guarding each; and a **bare numeric dispatch index is refused**, which made seven more entries visible: five of them live in the ship build, four with no userspace wrapper anywhere in the tree. 81 → 83, and neither figure was ever a build. Seven new rules, seven falsifying arms: a guarded entry becoming unconditional, an undeclared guarded entry, a `conditional:` naming the wrong flag, a guarded syscall declared covered, a bare numeric index, an `#if` form the deriver cannot evaluate, and a `SYSCOV` number no active entry claims. The sixth arm **did not fire on the first attempt**, it mutated an `#ifdef` earlier in the file than the table, so it was testing nothing; an arm that passes for the wrong reason is the failure this section exists to catch. |
| `syscall-abi` | **Issue #176**, property **S24**. `tools/check_syscall_abi.py` parses `include/syscall.h` and requires every pointer argument of every inline wrapper to reach `syscall()`/`syscall6()` full-width. Source analysis, no build, no QEMU: which is the point: a runtime gate only covers the syscalls some probe happens to call, and this covers all 46 pointer arguments including wrappers nothing calls yet. Falsified two ways: narrowing one wrapper's pointer (names the wrapper), and narrowing `SYSCALL_UPTR`'s own default definition; the obvious way to defeat a per-wrapper check, so it is checked separately. |
| `smoke-klog-forge-abi-control` | Control arm for the above at runtime. `SYSCALL_PTR_TRUNC32=1` restores the truncating wrappers; the probe's buffer is a static, so it is above 4 GiB and gets truncated, and `KLOGTEST: FAIL setup dmesg rc=-14` must come back. Measured **3 boots in 3**. This arm is also what stops `smoke-klog-forge` from quietly losing half its coverage: if the probe's buffer ever moves back to the stack the truncation becomes a no-op, this arm goes green, and the failure is visible instead of silent. |
| `smoke-klog-forge-control` | Control arm. `KLOG_WRITE_UNGATED=1` restores the unconditional `klog_append` on the ring-3 write path; `KLOGTEST: FAIL forged+evicted` must come back, and `smoke-klog-forge` must go red under the same flag. Measured **3 boots in 3**: one boot is enough because the defect is not a race. **Both halves are evaluated before either is reported**, which is what makes this arm exercise both branches rather than only the first in source order. That matters: a fix that merely rate-limited ring-3 appends would keep the marker and still leak the forgery, and one that dropped the bytes while still advancing the ring would lose the marker, so an assertion on either half alone passes a half-fix. |
| `smoke-exec-reenter` | **[G-9]**, exec component. The exec re-entry hand-off must be consumed by the CPU that armed it. Boots the `PROC_SELFTEST` workload at `-smp 4` `EXEC_REENTER_RUNS` times (default 20) and requires the `SCHED_INVARIANTS` wrong-CPU report to be **absent** from every boot; measured 0 in 30. Asserts on the marker, never on the boot's exit status: when this gate was written the workload failed 2 boots in 30 (~7%) on the rest of **[G-9]**, and gating on completion would have made this a detector for that rather than a witness for this property. [G-9] closed on 2026-08-21; the assertion stays marker-only for the same reason. **It does now require that the boots happened at all**, which until 2026-08-30 it did not: with `EXEC_REENTER_TIMEOUT=2` every boot died at GRUB and the gate exited 0 with `PASS - no CPU took another CPU's exec re-entry in 20 boots at -smp 4`, an absence asserted over twenty boots that never ran. Boots printing `EXEC_REENTER_LIVE_RE` are counted and the gate refuses to conclude below `EXEC_REENTER_MIN_LIVE` (10 of 20); the floor rather than a per-boot exit-status assertion, so the documented ~7% stall tolerance survives. Falsified both ways on 2026-08-30: starved, red with `the gate never ran the experiment`; unstarved, PASS over 20 live boots. |
| `smoke-exec-reenter-control` | Control arm. `EXEC_REENTER_GLOBAL=1` restores the single shared `g_exec_reenter_task`; the wrong-CPU report must come back in at least one boot. Needs many boots because the theft is a race, measured 5 in 20 (~25%/boot), so a single-boot arm would report a false green three times in four. This arm carries reachability for the pair: if the theft stops reproducing with the global restored, `smoke-exec-reenter`'s green proves nothing either. Read off CI on 2026-08-30 the rate is **43 hits in 200 boots over ten runs** (21.5%), so a clean sweep of 20 is 0.79% — about one PR in 127 — *provided every boot ran*. The first figure recorded here was 26.7%, taken over six **green** runs; that sample conditions on `hits ≥ 1` and structurally excludes every 0-hit run, so it could not contain the event under investigation and overstated the rate. Since a 0.79% false red is not acceptable on a required gate, a 0-hit sweep is now followed by up to `EXEC_REENTER_EXTRA` (15) further boots that stop at the first hit, putting the false-red rate at 0.03% while leaving the first 20 boots always run so the rate stays comparable across CI runs — and that proviso is why each boot is now scored **HIT**, **clean** (the workload completed and no CPU stole the re-entry) or **INCONCLUSIVE** (it died before the exec path, so nothing was measured). Only the first two count toward the sample, and the arm prints the tail of the serial log when it reddens instead of deleting it. Falsified in three directions on 2026-08-30: with the defect, **5 hit, 15 clean, 0 inconclusive of 20** (PASS, 25% against CI's pooled 21.5%); against the fixed kernel via `EXEC_REENTER_CONTROL_FLAG=0`, **0 hit, 20 clean**, red — the arm can still distinguish; and with `EXEC_REENTER_TIMEOUT=2` starving the boots, **20 inconclusive**, red with `the arm never ran the experiment` and a log tail ending at the GRUB banner. That third case is the repair: the previous version reported it as "did NOT reproduce in 20 boots", in wording identical to the fixed-kernel run, having already `rm -f`'d the only evidence that could separate them. The bounded extension was falsified in both directions in turn: against the fixed kernel all 35 boots ran and none hit (**red**, `did NOT reproduce in 35 conclusive boots of 35`), so the extra attempts cannot launder a miss; against the defect build it passed on **1 hit in 20** with no extra boots needed — a run one boot away from a false red under the old bound, which is the case for the extension in a single observation. |
### The harness threw away the diagnosis at the point of detection

`tools/smoke_test.sh` carries two failure signals. `FAIL_MARKER` is the **specific** string a
gate declares as its forbidden condition. `FAULT_RE` is a blanket `PAGE FAULT|Exception!
Vector|PANIC|Rejected by validator` that every gate inherits. Until 2026-08-27 the blanket was
checked **first**, and the `fault` branch printed one line (`SMOKE FAIL: kernel fault/panic on
serial`) and exited, discarding the log.

**Both problems bit the same investigation.** `smoke-switch-commit` forbids `stale scheduler
claim`. Run on `origin/main` with every core busy, six boots produced one `PANIC: stale
scheduler claim at preempt_on_tick` (*its own marker*) and one `PANIC: unclaimed running task`.
CI reported all of it as a generic fault, with no context, so the information that the forbidden
condition had occurred was thrown away at the moment of detection. Diagnosing it required
reproducing locally under artificial load, which is exactly what a CI log should have made
unnecessary.

Two changes, neither of which alters a verdict:

- **A named detection outranks the generic backstop.** `FAIL_MARKER` is now checked before
  `FAULT_RE`. Both statuses exit 1, so only the message differs. The one place a fault is a
  *success* signal is `EXPECT_FAULT`, and that case keeps the original ordering, making the
  order depend on which role the fault plays, rather than forbidding the combination.
- **Both failure paths print the matching lines** (up to three, with line numbers). `FAULT_RE`
  is four alternatives and several gates run workloads that fault on purpose; "a fault
  happened" was the least useful thing the harness could say.

Demonstrated on the log that caused the confusion: the old ordering scores it `fault (generic)`,
the new one `marker_fail (named detection)`. Under load, `smoke-switch-commit` now reports
`PANIC: unclaimed running task at preempt_on_tick: task 1 claimed by cpu 0 but that cpu was
running -1` instead of nothing.

### `EXPECT_FAULT` did not require the fault: five control arms could not fail

**Found 2026-08-27, and it is the worst class this repository has.** `tools/smoke_test.sh`'s
header has always said `EXPECT_FAULT` makes a run *"PASS if a kernel fault containing it appears
and FAIL if none does."* The code never implemented the second half. A build that booted cleanly
to the login prompt fell through to the success paths and exited 0 with the named fault nowhere
on the wire. `EXPECT_FAULT` **inverted** the verdict for a fault that happened; it never
**required** one.

Every user of it is a control arm whose entire purpose is that a reintroduced defect kills the
kernel before the login prompt:

| Arm | Defect it must reproduce |
|---|---|
| `smoke-claim-release-control` | `CLAIM_RELEASE_SKIP=1`, ring 3 reached owing a deferred release |
| `smoke-switch-commit-control` | `SWITCH_COMMIT_EARLY=1`, a stale scheduler claim |
| `smoke-resume-guard-negative-control` | the resume-`%rsp` guard rejecting an IST stack |
| `smoke-measured-boot-required-control` | measured boot required with no TPM |
| `smoke-measured-boot-required-volume-control` | measured boot required, volume unsealed |

**All five passed whether or not their defect reproduced**, and the only thing that could redden
them was a boot too slow to reach the banner. Exactly inverted: failing on runs that prove
nothing, passing on runs that *disprove* the defect.

**Measured when it was found**, rather than argued: `smoke-claim-release-control`'s kernel
rebuilt with no defect flag (`DEFECT FLAGS: none` on the wire) booted to `horus login:` with the
guard string absent from the log entirely, and the harness printed `SMOKE PASS`.

`EXPECT_FAULT` is now checked over the **complete** log at the end, for the same reason
`ABSENT_MARKER` is: in the poll loop it would only ever mean "has not appeared yet".

**And the three outcomes are now distinguished**, which is what the CI flake that led here was
really about. For the two arms that assert a *scheduling-dependent* fault at `SMP_CPUS=4`:

| Outcome | Means | Now |
|---|---|---|
| the fault appears | defect reproduced | PASS |
| the run **completes** without it | defect did **not** reproduce | FAIL at once: **never retried** |
| the boot reaches neither | no evidence either way | INCONCLUSIVE, retried up to `*_CONTROL_BOOTS` (3) |

Retrying a real miss is how an N-try loop becomes a way of passing, so it is not retried. The
other three arms keep their single boot: their defects are deterministic and not timing-bound.

**Falsified in all three directions**, against real builds:

| Direction | Result |
|---|---|
| defect present | PASS on boot 1 of 3 |
| defect **absent** (`DEFECT FLAGS: none`) | FAIL on attempt 1: *"never appeared, and the run completed"*, not retried |
| every attempt inconclusive (`SMOKE_TIMEOUT=1`) | FAIL, *"Exhausting the loop is a FAILURE, not a pass"* |

All five arms still reproduce their own defects after the change.

### `smoke-kstack-race`: a died-in boot is inconclusive, not a miss

**Until 2026-08-27 the base arm conflated two outcomes**, and only one of them is about the
property:

| Outcome | What it means | Was scored |
|---|---|---|
| `PANIC: two CPUs on one kernel stack` | the property is **broken** | FAIL, correct |
| the session did not complete | the workload died or timed out at `-smp 4` under a window this build **deliberately widens** so it is entered on every switch | FAIL: **wrong** |

The second says nothing about whether two CPUs shared a stack. It is the absence of evidence,
and it was being scored as evidence against.

**This is the third time this lesson has had to be learned in one file.**
`smoke-kstack-park`'s control arm scored its own strongest reproductions as misses, and the
repair was to name a died-in boot *inconclusive* and boot again. `KSTACK_RACE_CONTROL_BOOTS`,
forty lines below this target, has carried the sample-size half since 2026-08-19. The arm next
door got neither, and reddened a PR on 2026-08-27 whose entire kernel diff was an early return
in a function no live session calls.

**The property assertion is unchanged, and the retry does not weaken it.** The detector still
fails the build on sight, on every attempt, and no number of retries can turn a detected race
into a pass. What changed is that a run producing *no evidence either way* stops counting
against the build.

**The fence that makes the retry honest: if every attempt is inconclusive, the gate FAILS.** A
kernel that never boots must not pass by exhausting the loop: that is the obvious way for a
retry to become a way of not testing. Inconclusive attempts are named and tallied as they go, so
a build that is merely slow to die stays visible instead of being silently absorbed.

**Falsified in all three directions**, because an N-try loop that only ever goes green is not a
gate:

| Direction | Forced with | Result |
|---|---|---|
| a healthy build still passes |, | PASS, first attempt, no retries |
| all attempts inconclusive must fail | `KSTACK_RACE_TIMEOUT=1 KSTACK_RACE_BOOTS=2` | FAIL, *"no attempt completed a session in 2 tries"* |
| a detected race must fail, never be retried past | `KSTACK_RELEASE_EARLY=1` | FAIL on **attempt 1**: *"two CPUs shared a kernel stack with the fix in place"* |

| `smoke-kstack-race-control` | Control arm, and the load-bearing one. Same widened window, `KSTACK_RELEASE_EARLY=1` restoring the pre-fix release site. The marker must be **present** *and* the session must not report PASS, a build that reproduced the race and still reported success would mean the harness had stopped reading the wire. Without this arm, `smoke-kstack-race` proves only that a kernel with a spin in it still boots. |

**The control arm boots up to eight times, and did not always used to.** The pre-fix release
site reproduces the race *probabilistically*, and this arm asserted it from a **single boot**.
Measured 2026-08-19: **7 reproductions in 12 boots** locally (58%), so it misses about 42% of
the time on a workstation. On CI it reddened `main` **twice the same day** (runs `32244509317`
and `32251467694`) (two of the last eight runs) with the fixed arm green in the same job both
times, on trees whose content had already passed that job on a branch.

A single boot cannot assert a probabilistic event. This document's own rule is to quote a rate
over N boots, and the arm was quoting one while asserting from n=1. It now boots up to
`KSTACK_RACE_CONTROL_BOOTS` (8), stops at the first reproduction and names the boot it came on.
At 58% the expected cost is under two boots and a false failure across eight is 0.42⁸, about one
run in a thousand.

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
console (`terminal.c`), so a report emitted that way during a live session lands in the klog and
nothing reaches the wire. All three CPL-0 reports were emitted that way (the `#PF` banner, the
fatal-exception dump, and #123's bogus-resume-`rsp` guard) and a live session is the only state
in which any of them has ever been observed. G-8's supervisor fault tore down the ring-3 shell
on every occurrence while the kernel computed the address, the error code and the faulting
`rip`, printed them, and threw them away.

**Why the control arm is the point.** `smoke-kfault` passing tells you a report arrived. Only
`smoke-kfault-legacy` (same kernel, same injection, same tick, reporting through `println()`,
and **nothing on the wire**) tells you the gate is measuring the routing rather than the
existence of the fault. Compare the falsification discipline in the C-1 and 1.3 sections: a test
that cannot fail on the bug it targets is not evidence.

The ordering assertion is deliberate. "The report appeared" is satisfied by early-boot output,
when `print()` still drives the UART; "the report appeared **after** the login prompt" is not.

## Build integrity

| Target | Proves |
|---|---|
| `reproducible-build` | `kernel.elf` is byte-for-byte identical across two clean builds, and the record covers every artifact the build produces. **A required CI check.** `boot.iso` is recorded but deliberately not compared; it is not byte-reproducible (`docs/LIMITATIONS.md` §5.3a). |
| `smoke-repro-sha` | The hash-recording step refuses a build missing an artifact, and writes no `.build.sha` at all when it refuses; and records every artifact when the build is complete. Both directions. Host-side, sub-second. Falsified by `smoke-repro-sha-control`. |
| `smoke-repro-sha-control` | `REPRO_SHA_UNCHECKED=1`. Restores the pre-2026-08-19 recording step *and* the goal list that made it silent; the incomplete record and the success report must both appear. |
| `doc-claims` | Every count declared in `.github/doc-claims.yml` matches the value derived from the tree, every declared occurrence still matches its pattern, and no retired phrasing has reappeared unquoted. **A required CI check.** `tools/check_doc_claims.py`; static, no QEMU. |
| `security` | Semgrep, Trivy, gitleaks, cppcheck, flawfinder, cargo-audit, plus a CycloneDX SBOM. **A required status check.** Since 2026-08-30 (roadmap 4.3) `gitleaks` and `cargo-audit` findings **fail the build**, in a step above the advisory one so `continue-on-error` cannot hide them; both are falsified by `tools/test_security_gates.sh` (five arms: a planted credential must fail gitleaks, an innocuous tree must not, the finding must be redacted, a failing `cargo audit` must fail the target, and a *missing* cargo-audit must fail rather than report a clean scan — which is what the previous `|| echo "not installed or no advisories found"` did). The other four scanners' *findings* stay advisory (one deliberate `continue-on-error`), but since #154 the job asserts each scanner is actually installed and fails if one is missing; it had previously been a required check on which every step carried `continue-on-error`, so it could not go red for any reason, including scanning nothing at all. |

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
after removing the old one, so a failed run leaves no file rather than a partial one that cannot
be told apart from a complete record of a smaller build.

**Falsified deterministically, in both directions.**

| Arm | Command | Required |
|---|---|---|
| fixed, incomplete build | `make smoke-repro-sha` | `REPRO_SHA: PASS refused an incomplete build, wrote nothing`, and no `.build.sha` on disk |
| fixed, complete build | `make smoke-repro-sha` | `REPRO_SHA: PASS recorded 2 artifacts, kernel.elf boot.iso` |
| control | `make smoke-repro-sha-control` | `REPRO_SHA_CONTROL: FAIL recorded 1 of 2 artifacts and reported success` |
| the gate against the defect | `make smoke-repro-sha REPRO_SHA_UNCHECKED=1` | **must fail**: `REPRO_SHA: FAIL recorded-a-build-missing-boot.iso`, make exits 1 |

Both directions matter here for the usual reason: a recording step that refused everything
would satisfy the first row while making `reproducible-build` permanently red, so the second
row is what stops the fix from being "refuse always".

The control arm restores **both** halves: the swallowed status *and* the goal list that omitted
`boot.iso`. That is deliberate and was checked: with the ISO present, a swallowed status changes
nothing observable, so an arm that restored only the `|| true` would pass for the wrong reason
and prove nothing about the gate.

Host-side and sub-second; it exercises the recording step against a scratch directory, not a
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

### Documented numbers are derived, not trusted: property S22

**Added 2026-08-19**, after an audit found nine stale numbers across five files in one morning:
CI job counts, context counts, the required set, and the capability suite's check count, which
two other files carried correctly. CLAUDE.md has said *"re-derive every number you cite"* since
long before that. A rule only a reader enforces fails silently, and silence is how it failed.

`.github/doc-claims.yml` declares each derivable count and **every place that states it**;
`tools/check_doc_claims.py` derives the value from the source of truth and compares. The
`doc-claims` CI job gates it.

| Derived | From |
|---|---|
| `ci_jobs`, `all_jobs`, `contexts`, `required`, `advisory` | the workflow files and `.github/ci-gating.yml`, via `check_ci_gating.load_jobs`, imported, not reimplemented, because a second copy of the context-expansion rules is one more thing to drift |
| `smoke_targets`, `control_arms` | `^smoke-*:` in the `Makefile` |
| `captest_checks` | `check(` calls in `userspace/captest.c`, verified equal to the runtime `CAPTEST: PASS 100 checks` on 2026-08-19 |

**Three failure modes, all three falsified.**

| Arm | Injected | Required |
|---|---|---|
| stale number | `README.md` 72 → 69 jobs, the value that was actually wrong that morning | `README.md: says 69 for ci_jobs …, live value is 72`, exit 1 |
| claim deleted by rewording | replace the sentence with "CI runs a lot of jobs" | `claim 'ci_jobs' is declared here but its pattern matches nothing`, exit 1 |
| retired phrasing reasserted | put `build twice from clean and diff` back into `docs/BUILDING.md` | `forbidden phrasing …`, exit 1 |

The second arm is the one worth explaining. If a declared occurrence matching nothing were
merely tolerated, rewording a sentence would delete the check silently along with the claim; the
failure mode in miniature. So a claim that stops matching is an error, and the fix is to update
the pattern or remove the occurrence deliberately.

**Retired phrasings are a ratchet.** When a fact is corrected, its old wording goes in the
manifest's `forbidden` list so it cannot reappear in another file later. A match **inside double
quotes is ignored**: this project's style is to record the wrong thing when correcting it
(*"this paragraph previously said X"*) and a blanket ban would forbid exactly the practice that
makes a correction auditable. Quoted text is reported, not asserted. That allowance was not
theoretical: the first run of this checker flagged three lines, and all three were corrections
quoting what they had corrected.

**What it deliberately does not do.** No network, no QEMU, no ruleset read, comparing the live
ruleset needs `Administration: read` and belongs to `ruleset-audit`. It checks numbers and
retired phrasings, not prose: a document can still be wrong in a way no regex catches, which is
what review is for.

**One exclusion, deliberately.** `docs/history/DEVLOG-2026.md` is exempt from the ratchet. It is
a frozen record of what was written on the day it was written: entries there assert things that
were true then and are not now, and that *is* the content. The exemption is the same principle
as the quoted-text allowance: the log reports a past state rather than asserting a present one.
It is also never named as a numeric occurrence, so no derived claim can live in it. Falsified
both ways on 2026-08-21: a retired phrasing appended to `docs/LIMITATIONS.md` fails the check
naming file and line; the same phrasing appended to the log does not.

### The defect-flag table is the complete list it claims to be

**`tools/check_defect_flags.py`, required job `defect-flags-documented`.** `docs/BUILDING.md`
says of its defect-reproducing-builds table: *"This table is the complete list."* That sentence
was **false when it was written**. Three members of the Makefile's `DEFECT_FLAGS` had no row
(`RESUME_RSP_INJECT`, `RESUME_RSP_INJECT_PRECLAIM` and `WAL_CRASHTEST`) and one of them appeared
nowhere in the file at all. That table is the only index of the control arms, so an undocumented
arm is indistinguishable from a deleted one: a falsification nobody can find is one nobody
re-runs.

It derives the flag set from the Makefile and enforces three rules. Each was falsified
separately, which is the only reason two of them work:

| Rule | Arm | Result |
|---|---|---|
| Every `DEFECT_FLAGS` member has a table row | delete the `WAL_CRASHTEST` row | exit 1, naming it |
| Every row names a flag some build defines | add a row for `WAL_RETIRED_ARM=1` | exit 1, naming it |
| A tuning parameter is named in the row it tunes | strip every mention of `RESUME_RSP_INJECT_VALUE` | exit 1, naming it |

**Rules 2 and 3 did not fire on their first attempt, and that is the finding worth recording.**
Rule 2's loop skipped any flag absent from the Makefile (which is precisely the condition it
existed to catch) so a row naming a flag no build defines passed silently. It is the same shape
as the `smoke-ksp-guard` gap this suite recorded three days earlier: an arm that only injects
measures false *negatives*. A checker with three rules needs three arms, not one.

---

## CI

`.github/workflows/ci.yml` defines **101** jobs, run on every push and pull request;
`codeql.yml` adds one more, C/C++ static analysis (plus a weekly schedule); `ruleset-audit.yml`
adds one that runs only on a daily schedule. All three are covered by the gating classification
below: **103** jobs, **106** contexts. Counts from `tools/check_ci_gating.py`, which prints
them; do not copy them forward from here.

Every job carries `timeout-minutes` as of 2026-08-20, a backstop, not a budget. The default is
360, which let three runs on 2026-08-19 hang on a package-mirror stall rather than fail: jobs
sat on their install step for 95 minutes, two hours, and in one case until the run was cancelled
seven hours in with `main` still holding no verdict. A short timeout on the *install step* was
measured and rejected: the median install is about 20 seconds but the legitimate tail reaches 32
minutes, and 12 of 74 installs exceeded 15 minutes in a run that was green on all 77 checks. A
step budget would have reddened it. The distinction that matters is between slow and never
returning, and only a generous cap draws it.

All third-party actions are pinned to full commit SHAs. Workflow `permissions:` blocks are
least-privilege. There are no self-hosted runners.

### A known weakness in the gate

Of those, **22 were required status checks** before 2026-08-16, read the current set from `gh
api repos/pharanyx-labs/Horus/rulesets/21815299`, not from this file, which is the kind of
hand-maintained number this document exists to distrust.

`smoke-captest` joined that set on 2026-08-15. It is the named witness for eight of the
S-numbered properties in `SECURITY.md`, and until then it could not block a merge, a change that
broke the capability refusal suite went green, which is precisely how **[C-1]** survived every
automated gate in the first place.

This is finding **[C-6]** and roadmap item 4.2, and promoting one job never closed it. The
mechanism was the problem: the required list lived only in the ruleset, which no commit
touches, so every job added to `ci.yml` landed in the advisory set **by default** and nothing
asked whether it should have. When this finding was filed there were ~30 jobs and 21 required;
immediately before 2026-08-16 there were 66 and 22.

### The classification is now checked in

`.github/ci-gating.yml` lists every job in `ci.yml` and `codeql.yml` under either `required:` or
`advisory:` **with a written reason**. The `ci-gating` job (and `make check-gating`) fails the
build when a job is in neither, in both, or names a job that no longer exists. There is no
default, defaulting is the defect. Run it before opening a PR; it is pure text analysis, no
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

The intended set is **103 required contexts and 3 reasoned exemptions** (read off
`tools/check_ci_gating.py`, which prints them, rather than from this sentence) `fuzz` (a fixed
30-second search is evidence of effort, not of absence), `kani` (manual-only, so there is no
conclusion to gate on), `ruleset-audit` (schedule-only, so it never runs on a pull request) and
`smoke-kstack-park` (its workload trips **[G-9]**). `smoke-fs-wal` was a third until **[I-11]**
was fixed and it was promoted back to gating; `smoke-session-smp-soak` a fourth until **[G-8]**
was closed on 2026-08-17, and it was promoted in the same commit. Three of the four are
properties of the test itself; `smoke-kstack-park` was the one exemption that stood for an
**open defect**, and it was **promoted on 2026-08-22**, one merge after **[G-9]** closed. Its
workload ran 0 failures in 200 boots after the fix (95% upper bound 1.49%) against ~45% before
[G-9]'s exec and page-table components and ~7% after them; the gate itself passed 5 of 5 in its
exact form, which at a 7% rate is only ~70% power and is corroboration rather than the evidence.
**No exemption now stands for an open defect**: the three that remain (`fuzz`, `kani`,
`ruleset-audit`) are properties of those tests. The promotions are backed by measurement, not
optimism: across 18 CI runs sampled on 2026-08-16, **64 of 66 jobs had zero failures over 1152
job-executions**; the only two that ever failed are `security` (2/18, both deliberate, during
#154) and `smoke-session-smp-soak` (1/18, which was [G-8] at its documented 2–3% per boot; the
defect that job was correctly reporting).

`smoke-fs-wal` is deliberately **demoted** from required. A flaky gate that blocks merges
spuriously teaches the maintainer to re-run red checks, which costs more than the coverage it
buys, and the durability property it used to be credited with is now witnessed by the
deterministic `smoke-fs-wal-flush` and `smoke-fs-wal-order`.

### What this does *not* do

**CI cannot verify the ruleset.** The ruleset was synced on 2026-08-16,
`tools/check_ci_gating.py --sync-ruleset` took it from 22 required contexts toward 67,
preserving `strict_required_status_checks_policy` and bypass actors, and re-read it to confirm.
Run from a feature branch, it also required three contexts `main` could not yet produce, which
blocks every PR on a check that never reports; `tools/prune_unsatisfiable_checks.py` dropped
them (67 → 64) and encodes the rule that promotion must **lag** the job landing by one merge. So
every security target now blocks a merge, and the old advice to run them locally *because CI
will not stop you* no longer applies.

But reading a ruleset needs Administration permissions the workflow `GITHUB_TOKEN` does not
have and cannot be granted, so the `ci-gating` job proves the classification is **complete**,
not that the ruleset **matches** it. A change made in the GitHub UI could reopen the gap and
nothing in CI would notice. `--check-ruleset` is the check; it has to be run deliberately, and
it is the reason **[C-6]** stays open.

`strict_required_status_checks_policy` is now **true**, so a PR can no longer merge having
passed CI against a stale base. (This document previously said it was false; that was correct
when written and is not any more.)

---

## The claim audit's exemption outlives the release it exempts: [G-9] closed

> **A regression this gate caught the day after, and what it costs to skip one.**
> The [G-9] fix shipped in #188 also moved the `g_kstack_inflight` clear inside the
> scheduler lock, which the property it was establishing never required. Under
> `KSTACK_RACE_WIDEN`'s 200,000-iteration spin the wider critical section pushed the
> session past its 90-second budget, and `smoke-kstack-race`, a **required** gate; 
> went red on `main`. It reproduced deterministically, so it was not a flake.
>
> The gates for [G-9] and the core smoke set were run before that merge.
> `smoke-kstack-race` was not, despite the change being inside
> `sched_release_deferred()`, which *is* the [G-8] deferred-release machinery that
> gate exists to exercise. **Editing a function means running the gate named after
> its finding**, not only the gate named after the finding you are working on.
>
> The fix is to narrow the critical section to what the property needs: the
> exemption must outlive the claim release; the bit clear was never part of that.
> Verified by the control arm still reproducing on boot 1, which is what says the
> narrower lock did not quietly weaken the fix.

**`smoke-defer-exemption`, required job `defer-exemption`.** `percpu_deferred_release[]` is not
just a CPU's note of work owed: `sched_assert_claims()` uses it as the **exemption** that says a
claim is mid-handover rather than leaked. `sched_release_deferred()` cleared it *before* taking
the lock that drops the claim, so for the width of a lock acquisition the task was claimed,
un-exempt and mid-release. A CPU auditing in that window reported a leak that was not one.

**The checker's second false positive**, and the same family as 2026-08-09, where it read a
deliberate spawn-time impersonation as a leak. Both times it observed its own exemption machinery
mid-update. *A checker that exempts a state must hold the exemption for the whole of that state.*

**Why the pair is widened.** The natural event is ~4.5% with variance wide enough that 200-boot
arms cannot separate 4.5% from 6.5%; the baseline itself ran 2/50 and then 9/200, and an
intermediate 13/200 was briefly read as a regression before a significance test returned p =
0.39. `DEFER_WINDOW_WIDEN=1` is set in **both** arms, which is what makes them a measurement.

**The control arm kept no evidence until 2026-08-30.** It piped each boot straight into
`grep -q 'stale scheduler claim'` and discarded the rest, so a boot that died at GRUB and a boot
that ran cleanly without the stale claim were the same observation, and the failure message
(`the pre-fix order did not reproduce in N boots`) could name neither. Found in the sweep that
followed the same defect in `smoke-exec-reenter-control`. It now captures each boot, scores it
HIT / clean / INCONCLUSIVE against `DEFER_EXEMPTION_LIVE_RE`, prints the last three lines of
every attempt, and reports `the arm never ran the experiment` rather than a miss when fewer than
`DEFER_EXEMPTION_MIN_LIVE` boots reached the defer path.

| Arm | Boots | Panics |
|---|---|---|
| widened, exemption held to the end (shipped) | 10 | **0** |
| widened, `DEFER_CLEAR_EARLY=1` (pre-fix) | 10 | **8** |

Fisher p ≈ 0.0007. Natural rate 9 in 200 → **0 in 200** (p = 0.0036), which bounds the residual
at under 1.49% at 95% confidence, a bound, not a proof of zero. The deterministic pair is the
evidence; the clean run is corroboration.

---

## A refused switch leaves no claim behind: [G-9]'s root cause

**`smoke-switch-commit`, required job `switch-commit`.** `task_exit_switch()` returns `0` for
two incompatible things: *"nothing runnable, caller parks"* (no claim taken) and, via
`ksp_refuse()`, *"I already claimed `next` and named it current, but its resume value is
bogus"*. All three callers in `idt.c` read `if (rsp) return rsp;` and otherwise park the CPU, so
a refusal was indistinguishable from an empty run queue, and the claimed task stayed claimed
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
gate and a campaign, and this finding has cost two of the latter.

**It did not close [G-9].** The natural rate went 2–4% → **2 in 130 (1.5%)**, which is not
statistically distinguishable from where it started. One cause is removed and gated; another
path is still leaking, with the same claim site and no chokepoint hit. Recorded in
`docs/investigations/G-09-scheduler-claim-leak.md` rather than rounded up here.

---

## The claim-release invariant: a CPU in ring 3 owes no deferred release

**`smoke-claim-release`, required job `claim-release`.** Since **[G-8]**, a switch path holds the
outgoing task's claim until the CPU has left that task's kernel stack, and drops it from
`sched_release_deferred()` on the ISR epilogue. If any route to ring 3 skips that call, the claim
is stuck forever: every selection loop skips a claimed task, so it becomes unschedulable by every
CPU **including its holder**. That is **[G-9]**'s shape.

**The periodic claim audit structurally cannot catch this.** `sched_assert_claims()`
deliberately exempts a task whose holder's deferred slot names it, correctly, because such a
claim is mid-handover rather than leaked. An *unpaid* debt therefore hides inside the very
exemption that keeps the auditor honest, and surfaces ~10ms later at whatever site happens to
run the next audit. That is why every report for this finding has named `preempt_on_tick`, which
had nothing to do with it.

So the debt is checked where it is provably settled instead: at ring 3. Every route there goes
through an epilogue, so a CPU observed in ring 3 owing a release means some path reached user mode
without paying.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-claim-release` | the guard stays **silent** through a boot to ring 3 | passes; measured 0 in 30 |
| `smoke-claim-release-control` (`CLAIM_RELEASE_SKIP=1`) | `ring 3 reached with a deferred release outstanding` **present** | fires on boot 1, naming the owed task |

It found one real hole immediately: `sched_enter_user()` carried a second hand-written copy of
the ISR epilogue that omitted the release call. Latent in this workload (`CLAIM_TRACE=1` shows
the path is never reached owing a debt) but it orphaned both the claim and the task's
`g_kstack_inflight` bit, and a stuck inflight bit makes the **[G-8]** detector report a
collision that is not happening. Two copies of one sequence is what allowed it; this gate is
what stops a third drifting.

---

## The shared userspace runtime

### `smoke-vfs`: two servers, two mounts, one namespace

Roadmap 2.4's gate. `fs_server` is mounted at `/` and `dev_server` at `/dev`, and the assertions
are about **which server a path reaches** and **what it took to reach it**.

`dev_server` exists to be the other server. A mount table with one mount is unfalsifiable, every
path resolves to the same task, so "longest prefix wins" and "the capability decides, not the
path" cannot fail. It holds exactly one capability, the listen end of its own endpoint: no
object store, no boot modules, no user database. That asymmetry is the point of a per-mount VFS
and is not expressible in a monolithic one.

**Routing is checked by which server answered, not by a return code.** Under first-match the `/`
mount also matches `/dev/zero`, and the root filesystem has an inode 0 of its own, so it does
not fail, it answers about a different object. A return-code check would call that success.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-vfs` | `VFSTEST: PASS`, no `FAIL` | **14 checks**, read off the wire |
| `smoke-vfs-prefix-control` (`VFS_FIRST_MATCH=1`) | `FAIL wrong-server-answered` present | 4 checks fail, routing, inode, and `..` all break together |
| `smoke-vfs-mount-control` (`VFS_MOUNT_UNGATED=1`) | `FAIL mounted-without-a-capability` present | exactly 1 check fails; the arm is aimed at one property and hits one |

Both arms are deterministic properties of a build, not races, so three boots is corroboration
rather than evidence and one is the sample size that matters.

**The positive direction is in the same target** (`tools/check_gate_pairs.py` requires it): the
suite reads zeros through `/dev/zero`, keeps `/bin` on the root mount, and confirms `/devices`
does **not** match the `/dev` prefix, a plain string compare would route it to the wrong server.

### `smoke-passwd-probe`: the in-kernel ramfs is unreachable from ring 3

Roadmap 2.4's first gate, and it exists because of what orienting on 2.4 turned up: four paths
into the in-kernel ramfs authorised on cspace slot 3 with `SC_ANYTYPE`, which the legacy
`CAP_FRAME` in every task satisfies (**[H-3]**).

A ring-3 task runs as the ordinary uid-1000 account with no capability anyone delegated to it,
and asserts four refusals: it cannot open a file in the store, cannot read bytes out of
any ramfs fd, cannot create a file, and cannot list the contents.

**The first check used to target the user database and no longer can.** `kusers.c`'s save/load
pair was deleted on 2026-08-22 as code that had never run (`LIMITATIONS.md` §2.6), so nothing
writes `"passwd"` any more and a check against it would pass **trivially in both arms**: a
required gate silently measuring nothing. It targets a seeded demo file instead. **S28 is
unchanged**: the property was never about what sat behind the gates.

**The control arm also has to rebuild the store, not just the gates.** Restoring the four slot-3
entries onto an *empty* ramfs reproduced only **2 of 4** doors (open and read had nothing to
find) which is what an arm looks like when it half-measures and still reports success. It builds
`ramfs_init()` (seeding included) so all four fire.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-passwd-probe` | `PASSWDPROBE: PASS` present, no `FAIL` | passes; all four return `SYS_ERR_NOSYS` |
| `smoke-passwd-probe-control` (`RAMFS_SLOT3_GATE=1`) | `FAIL opened-a-ramfs-file` present | passes; all **4 of 4 doors open**, and `smoke-passwd-probe` goes red under the same flag |

**The control arm reads out more than the base arm asks about**, which is why it prints what it
finds rather than only whether it succeeded: it recovered 24, 64 and 32 bytes from three
separate ramfs files and enumerated the store. A gate whose control arm only answers yes/no
would have reported one open door instead of four.

**What the finding did not disclose, and why that is luck.** The 32 bytes from the
user-database file are the trailing HMAC tag, not the `salt[16]` + `pass_hash[32]` records,
because `ramfs_write` takes no offset and rewrites from byte 0 on every call
(`docs/LIMITATIONS.md` §2.6). The hashes were one bug-fix away from being world-readable.

### `smoke-rng-seed`: the CSPRNG refuses to emit keystream before it is seeded

Property **S30**. `RngState::fill` (`rust/src/rng.rs`) returns false and zeroes the caller's
buffer while `seeded` is false. Before 2026-08-23 it did not look at `seeded` at all: asked
early it would have run ChaCha20 under the hardcoded startup key in `RngState::new()` (a
constant that is **published**, because the build is reproducible) and handed the result back as
randomness.

**Nothing reached it, and that is the finding.** `entropy_init()` runs at `src/kernel/main.c`
before the first consumer and halts if the pool did not take, so the property held. But it
held as an ordering fact about one call site, not as anything the RNG enforced, and an
ordering fact is precisely what a refactor moves. Same shape as the frame refcount in #192:
a safety claim propped up by something nobody checks. There was no live defect here and there
is no finding ID; the gate exists so that the claim is the RNG's own.

**The instrument.** Both arms build with `RNG_UNSEEDED_PROBE=1`, which asks the pool for 16
bytes immediately before `entropy_init()` and prints which of three things happened: `SERVED
unseeded keystream`, `REFUSED unseeded request`, or `REFUSED but modified the buffer`. The probe
calls the FFI directly rather than `secure_random_bytes`, so it can *report* a refusal instead
of halting on one; both arms then read their answer off the wire in the same shape. The pool
really is untouched at that point: `entropy_add_sample` is the only other path into
`add_entropy` and it currently has no callers.

**Both directions in one boot, deliberately without `MARKER_ONLY`.** The base arm requires the
refusal marker **and** a boot that still reaches the ring-3 shell banner. Without the second
half the gate is passed by a `fill()` that refuses everything, which is not hypothetical: the
`if !self.seeded` → `if true` mutation was run against this target and it goes red, on `PANIC:
CSPRNG refused secure_random_bytes` from `stack_protector_init`, the first consumer after the
seed. That same run is also the only execution of the C-side halt path, which is otherwise
unreachable by design.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-rng-seed` | `RNGPROBE: REFUSED unseeded request` present, `SERVED` absent, shell banner reached | passes, **3 boots in 3** |
| `smoke-rng-seed-control` (`RNG_UNSEEDED_LEGACY=1`) | `RNGPROBE: SERVED unseeded keystream` present | passes, **3 boots in 3**; `smoke-rng-seed` goes red under the same flag |
| `cargo test --features rng_unseeded_legacy` | `rng_refuses_before_seeding` **FAILED**, `rng_serves_after_seeding` **ok** | as required; the `rust` job asserts both lines, so an arm that broke every RNG test would not pass for it |

Three boots rather than a rate, and as with `smoke-frame` that is a claim about the defect
rather than about the effort: this is a deterministic property of a build, observed identically
on every boot, so the sample size that matters is 1 and 3 is corroboration.

**The control arm is a cargo feature, not a `-D`.** The defect lives in Rust, so
`RNG_UNSEEDED_LEGACY=1` turns into `cargo --features rng_unseeded_legacy`. It is stamped into
`DEFECT FLAGS` all the same (a transcript that does not name it is one nobody can audit) and the
staticlib gained `.build-flags` as a prerequisite so that flipping the feature re-runs cargo.
That prerequisite list also stopped naming five of the crate's source files by hand: it did not
include `rng.rs`, so editing this very file rebuilt nothing and the kernel linked the previous
library. The control arm would have been measured against source the binary did not contain.

**Why the FFI changed shape.** `rust_rng_u64()` returned a `uint64_t` with no way to signal a
refusal (every value including zero is a legal draw) so neither of its callers (`loader.c` spawn
entropy, `aslr.c` stack jitter) could have failed closed even if it wanted to. It is now
`rust_rng_u64_checked(uint64_t *)`, wrapped by `secure_random_u64()`, which halts. A path that
cannot report a refusal is not gated by adding a check upstream of it.

### `smoke-frame`: a frame capability names an object, and a delegate maps only what it holds

Roadmap 2.1's gate. Two ring-3 tasks and one physical page: `frametest` holds a `CAP_UNTYPED`,
retypes a `KOBJ_FRAME` out of it, maps it, and asserts every refusal the map path owes;
`framepeer` holds **nothing** except the `READ`-only capability `frametest` mints and grants
it, and proves both halves of what shared memory has to mean.

**The check the whole design turns on is the decoy.** Every task in this system is born holding
a `CAP_FRAME` in slot 3: `READ|WRITE|EXEC`, object `USER_AREA_BASE`, installed by `create_task`,
identical in every task, asked for by nobody. It is the capability that made **[C-1]** reachable
when the dispatch table gated IPC on slot 3. Giving `CAP_FRAME` a meaning put it back in play,
so `frametest` calls `SYS_MAP_FRAME` on slot 3 on every boot and requires a refusal. It is
refused because a frame capability names an **index** into a table the kernel populates and
`USER_AREA_BASE` is not one, a bound, not an allowlist.

**Both directions in one target.** A gate that only ever refuses is satisfied by a kernel that
refuses everything, which is what `tools/check_gate_pairs.py` exists to reject, so the legal
path is exercised too: the frame is mapped, written, read back, and then read by the *other
task at a different virtual address*.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-frame` | `FRAMETEST: PASS` present, `FRAMETEST: FAIL` absent | passes, **3 boots in 3**; **58 parent checks** + 9 peer checks, read off the wire |
| `smoke-frame-index-control` (`FRAME_INDEX_UNCHECKED=1`) | `FRAMETEST: FAIL legacy-cap-mapped` present | passes, **3 boots in 3**; `smoke-frame` goes red under the same flag |
| `smoke-frame-rights-control` (`FRAME_RIGHTS_UNCHECKED=1`) | `FRAMETEST: FAIL readonly-delegate-wrote` present | passes, **3 boots in 3**; `smoke-frame` goes red under the same flag |
| `smoke-frame-region-control` (`FRAME_REGION_NO_ROLLBACK=1`) | `FRAMETEST: FAIL region-rollback-page0` present | passes, **3 boots in 3**; fails *only* the two rollback checks; `smoke-frame` goes red under the same flag |
| `smoke-frame-region-wide-control` (`FRAME_REGION_ROLLBACK_WIDE=1`) | `FRAMETEST: FAIL region-rollback-ate-blocker` present | passes, **3 boots in 3**; fails *only* that check; `smoke-frame` goes red under the same flag |
| `smoke-frame-pages-control` (`FRAME_PAGES_SAME_PHYS=1`) | `FRAMETEST: FAIL sized-pages-distinct` present | passes, **3 boots in 3**; also reddens the unmap checks, which is the defect showing rather than the test leaking; `smoke-frame` goes red under the same flag |
| `smoke-frame-info-control` (`FRAME_INFO_BY_INDEX=1`) | `FRAMETEST: FAIL peer-frame-pages-not-an-index` present | passes, **3 boots in 3**; the marker is the **delegate's**, which is the point; `smoke-frame` goes red under the same flag |

Three boots rather than a rate over hundreds, and that is a claim about the defects rather
than about the effort: neither arm is a race. Both are deterministic properties of a build,
observed identically on every boot, so the sample size that matters here is 1 and 3 is
corroboration. Contrast `smoke-kstack-park`, where the underlying event is probabilistic and a
single green boot says nothing.

**The size arm's marker comes from the DELEGATE, and it has to.** `SYS_FRAME_PAGES` exists so a
task handed a capability can learn how big the object behind it is, and the way to get that
wrong is to answer from a frame index the caller supplies instead of from the capability it
holds. Asked from `frametest` (which holds every frame in play) an index and a slot are hard to
tell apart. Asked from `framepeer`, which holds exactly one delegated `CAP_FRAME` and nothing
else, they separate cleanly: slots 1 and 2 are empty in that task while frame indices 1 and 2
are live, so a handler that confuses them answers about frames the asker has no capability to.
**Probing the range then turns a number into an oracle** for which frames exist across every
task in the system, which is the part that makes it a security property rather than an ABI
preference.

### `invariants`: every security property is bound to a witness that exists

Roadmap 4.12 / finding **[F-4.1]**, and the question none of the earlier sweeps asked: *which
claims have no witness at all?* Ambient-authority sweeps looked for gates that were **absent**;
the **[H-3]** sweep looked for gates that were **vacuous**. Neither would have found **S16**,
whose gate was present, correct, and bound to nothing, an em-dash in its witness column against
`fpu_save`/`fpu_restore`, real code called on every ring transition.

**`SECURITY.md`'s table is the registry.** It already carries id, statement, enforcing code and
witness, so `tools/check_invariants.py` parses it rather than adding an `invariants.yaml` beside
it. A hand-maintained parallel manifest would be a second copy of claims that already exist,
drifting from the first, which is **[H-3]** restated as documentation. **Does the base gate go
red under the flag? Measured 2026-08-30, 30 of 30.** `docs/BUILDING.md` claims 31 times that a
named gate "must go red" under a defect flag, and nothing tested it: an arm builds *with* the
flag and asserts its own FAIL marker, the gate builds *without* it and asserts PASS, and nobody
built the gate with the flag. Those come apart whenever the arm and the gate watch different
markers, an arm can redden its own assertion beside a gate that would stay green while the
property was broken. `tools/check_base_gate_reddens.sh` derives the pairs from
`docs/BUILDING.md` (not a copy of them) and runs each one; every pair reddened. It is not in CI
on purpose: each pair is a clean rebuild plus a boot, so the sweep is hours, and it belongs
before promoting an arm or during an audit rather than on every pull request.

**Which smoke target is a control arm is declared, not inferred, since 2026-08-30.**
`.github/gate-pairs.yml` names all 166 targets: each control arm with the base gate it extends,
and each base gate. `check_gate_pairs.py` refuses a target in neither list. It replaced a
substring test for `control` in the target name, which missed four arms and made two published
counts wrong (69/97 against a true 73/93). Falsified seven ways by `tools/test_check_gate_pairs.sh`.

**The property table's `enforced by` column is validated, and every S-number is cited from the
code that carries it, since 2026-08-30.** `check_invariants.py` gained R7 (every backticked path
and identifier in that column must exist; 236 tokens) and R8 (every S-number must appear in the
shipping tree; 20 of 56 did not). Ten arms in `tools/test_check_invariants.sh`, one per rule.

**No build depends on a repository this project does not use, gated since 2026-08-30.**
`tools/check_apt_hardening.py` (required job `apt-hardening`) refuses a raw `apt-get` in any
workflow: every install goes through `.github/actions/apt`, which strips the runner image's
vendor repository lists before updating and retries what remains. It exists because `main` went
red when `packages.microsoft.com` answered 403 and `apt-get update` exited 100 in a job that
installs binutils and QEMU from the Ubuntu archive and nothing else. 87 of 101 jobs ran a bare
`apt-get`, so the run reddened at 1-(1-p)^87 rather than p. The check found two calls in
`codeql.yml` the manual sweep had missed. Falsified five ways by
`tools/test_check_apt_hardening.sh`, including an arm for the one exemption (it must still strip)
and an arm for the unmutated tree, because four "is it caught" arms are satisfied by a checker
that rejects everything.

**Every gate-asserted marker is emitted in one write, gated since 2026-09-01.**
`tools/check_split_markers.py` (required, beside `check_capslots.py` and `check_abi_structs.py`)
fails the build when a marker some gate asserts as a contiguous string is emitted in more than one
write to the shared console. Another task's output can land between the writes, and the gate then
times out looking for a string that **was** printed, in pieces — reporting an infrastructure
failure for a run in which the defect reproduced perfectly.

**It exists because the hand sweep that was supposed to have closed this missed two instances.**
`docs/LIMITATIONS.md` 2.6a recorded all ten as fixed on 2026-08-31; `userspace/captest.c` was not
among them, because the sweep searched for the `report(prefix); report(detail);` shape and captest
has a private `out()` and does not include `libhorus.h`. Ten `smoke-captest-*-control` arms assert
a contiguous `CAPTEST: FAIL <detail>`. It reddened CI on 2026-09-01, the day after `auditprobe`
became a second ring-3 writer in that image — a latent split marker and a second writer are the
same defect, and only one of them is observable. The kernel's `DEFECT FLAGS: ` line, asserted by
six gates, was the second instance and was found by the checker rather than by anyone looking.

It deliberately does not flag **ungated** multi-write output — 91 such runs exist and rewriting
them would be churn with no property behind it. Falsified four ways by
`tools/test_check_split_markers.sh`: a split userspace marker, a split kernel marker, an *ungated*
split that must **not** be flagged, and the unmutated tree — because three "is it caught" arms are
all satisfied by a checker that rejects everything. **No runtime arm**, and that is a decision:
the interleave is timing and did not reproduce in 0 of 12 local boots of the exact configuration
CI fails on, so a runtime witness would be a coin toss asserting a property that is decidable
statically.

**Every ABI struct is identical in both headers, gated since 2026-08-30 — and since 2026-09-01
the tool decides which structs those are.** `tools/check_abi_structs.py` runs beside
`check_capslots.py` and compares the structs that cross the ring-3 boundary and are written down
in both `src/include/kernel.h` and `include/syscall.h`. It compares (type, name, array) triples,
so a field added, removed, renamed, retyped or reordered fails and is named on both sides; it
does not check `sizeof` or offsets, which are properties of a compilation rather than of a
header.

**The list was hand-maintained, and that is how it missed the one that had drifted.** It carried
seven names from an audit sweep; `struct audit_event` was the eighth, was not in that sweep's
output, and was the one already broken (**S71**). So the declared list is no longer the whole
check: the tool now **discovers** every struct defined in both headers and fails on one enrolled
in neither list, which asks "is this enrolled?" of the headers rather than of whoever last added
a struct. The declared list stays, because discovery cannot notice a struct *disappearing* from
one header. Discovery immediately found four more that were never enrolled and do agree
(`fs_stat`, `task_info`, `irq_policy_info`, `irq_policy_site_info`) and one that does not
(`program_header`, `docs/LIMITATIONS.md` 2.18), which is the tool's single `UNRESOLVED` entry —
an exemption naming an open finding, which the checker fails if it is dropped **or if it starts
agreeing**, since an exemption that has outlived its reason is a check that cannot fail.

Falsified **seven** ways: a renamed field, a removed field, a struct absent from one header, and
the four rules added with discovery — an unenrolled struct defined in both headers, an enrolled
name that no longer crosses the boundary, an `UNRESOLVED` entry that now agrees, and a typedef'd
struct the field extractor used to skip silently (which for a discovered struct would have been
the checker excusing itself from the comparison).

**Every production `unsafe` states its caller's obligations, gated since 2026-08-29.**
`tools/check_unsafe_safety.py` (required job `unsafe-safety`) walks `rust/src/*.rs`, skipping
test modules, and requires a `# Safety` clause on the enclosing item of every `unsafe`. It was
added because `CLAUDE.md` §7 required exactly this and nothing enforced it: 30 of 49 sites had
no clause, including all six in `memory.rs`. Its own harness,
`tools/test_check_unsafe_safety.sh`, falsifies it four ways and **found a defect in it on the
first run**, a fixed 30-line lookback let an undocumented item inherit its neighbour's clause,
which is how a 30th undocumented site (`rust_hmac_sha256`) had been missed by hand. What the
gate does not do is stated in the tool: it proves an obligation is written, never that it is
true or upheld. Miri and `kani-bounded` test the code beneath it.

**The `forbidden:` ratchet scans source as well as prose, since 2026-08-29.** It covered
`*.md`, `*.html` and `*.yml`, which meant a retired claim could be corrected in every document
and stay alive in the comment beside the check it describes. It did: #243 added "there is no
IOMMU" to the ratchet while four copies survived in `.c` and `.h` files, two of them stating the
security argument for a disclosure. The globs now include `*.c`, `*.h`, `*.rs`, `*.py`, `*.sh`
and the `Makefile`, and switching it on found eight further live instances, including a
`Makefile` comment naming a different failing marker than its own recipe asserts. Falsified
three ways: a planted phrasing in a `.c` file is caught with file and line; the same phrasing in
`docs/history/` stays exempt, because that log records what was true when written; and a
phrasing inside a quotation stays exempt, so a comment can record the wrong thing while
correcting it.

`.github/invariants.yml` holds exemptions only, and is currently **empty**: all 74 properties
name a witness that resolves to a make target or a CI job.

| Rule | Rejects |
|---|---|
| R1 | a property whose witness names nothing runnable; S16's real prior state |
| R2 | a witness naming a `make` target that does not exist; the residue a renamed gate leaves, where the row still reads as bound |
| R3 | a witness target no workflow runs, a witness in principle only |
| R4 | a control-arm flag absent from `DEFECT_FLAGS`, so a boot under it is unstamped and its measurements cannot be told from an unflagged run |
| R5 | a duplicated id, or a gap in the numbering |
| R6 | an exemption for an unknown id, or one that has outlived its reason |

**R4 is the subtle one.** A witness column naming `FOO_UNGUARDED=1` is claiming the property is
falsifiable on demand. If that flag is not in `DEFECT_FLAGS` the boot banner will not stamp it,
and a measurement taken under it is indistinguishable from one taken without: which is how a
stale `KSP_GUARD_INJECT` once turned a **[G-9]** campaign into a false reproduction.

**Every rule is falsified** by `tools/test_check_invariants.sh`, run in the same job: eight
arms, each mutating a **copy** of the tree so the harness cannot leave the repository modified,
and each required to be reported under *its own* rule rather than merely to fail. A checker
nobody has seen reject anything is indistinguishable from `return 0`, and this repository has
been bitten by precisely that, of the first three rules in an earlier checker, two silently
could not fail.

**The checker's own first run produced a false finding, and that was fixed before anything else.**
S26's witness cell contains `CAP_RIGHT_WRITE \| CAP_RIGHT_EXEC`, and a naive split on `|` chopped
the row there, truncating the witness to `WRITE\` and reporting a well-witnessed property as
unwitnessed. The first thing anyone does with a checker that invents findings is learn to skim
past it, which costs more than the checker was ever going to save.

### `smoke-net`: a device reaches only the memory its driver mapped for it

**S45**'s witness, and the point at which the IOMMU stops being a boot message. `netd` is
spawned holding a `CAP_IO_DEVICE` naming the NIC and one untyped region, brings up an e1000, and
completes a **DMA round trip**: the device reads its descriptor ring, reads the packet buffer,
and writes the completion status back. Every one of those addresses was mapped into that
device's address space by `SYS_DMA_ADDR` and by nothing else; the space starts empty.

The gate boots q35 with an Intel VT-d unit (`SMOKE_IOMMU`) and an **e1000** (`SMOKE_NET=e1000`).

**THE DRIVER WAS VIRTIO AND HAD TO BE REWRITTEN, and that is the entry worth reading.** The
first version drove legacy virtio-net, which was the easier device: no MMIO, no PCI capability
walk. Under VT-d it kept working **with an empty device address space**: translation enabled
(`GSTS=0xC0000000`), root table installed, zero faults recorded, and the exchange completing
anyway. Paravirtual virtio devices access guest memory directly; they are not on the far side of
the IOMMU unless the device negotiates `VIRTIO_F_ACCESS_PLATFORM`, and a *legacy* virtio device
has no such bit. QEMU says so outright when asked:

```
-device virtio-net-pci,iommu_platform=on:
VIRTIO_F_IOMMU_PLATFORM was supported by neither legacy nor transitional device
```

So the obvious gate would have been a property stated, enforced by real code, and **bound to a
device that bypassed it**: passing while proving nothing. e1000 is a real device model whose DMA
goes through the device's address space like any bus master's. **Check that your witness is on
the far side of the mechanism you are testing.**

**It also now witnesses S46**: `netd` registers its NIC's own declared interrupt line, enables
the device's transmit-completion interrupt, and is woken by a **real hardware interrupt**, which
it services and acknowledges. That half is deliberately sequenced *after* the DMA witness, so
the two fail separately, an interrupt that never arrives leaves `NETTEST: PASS` standing and
only `IRQ PASS` missing.

**MSI-X is where the previous property's shape genuinely failed.** S47 keeps vector choice in
the kernel by putting the register out of ring 3's reach: configuration space. That argument
does not transfer to MSI-X, whose vector table lives in a **BAR**: ordinary device memory a
driver maps page by page with a capability it legitimately holds. *"The kernel programs it"* is
no answer when the driver can program it too.

So **S48** refuses the page. `netd` is told where its own table is and is turned away from it
both writable and read-only, holding a valid `CAP_IO_DEVICE` for that device, on a page inside a
BAR the device declares, `NETTEST: MSIX PASS`. `devcaptest` had to be taught to route *around*
that page when picking a BAR page to map, which is exactly what a real driver does and is the
clearest demonstration that the refusal is real.

**Scope, because the gate would otherwise overclaim:** the kernel does not yet *enable* MSI-X,
so while MSI-X Enable stays clear the table is inert and S48 is defence in depth rather than
load-bearing. It ships first deliberately, `docs/LIMITATIONS.md` §2.15 records why enabling is
deferred (an unverified cause-to-entry register on the only MSI-X device here, and an interrupt
that never arrived; a path that appears to work by guesswork is how a device never interrupts on
real hardware).

**S46's mask is now tested DIRECTLY, and getting there needed a new syscall.** The property is
"no notification arrives while the line is masked", and a blocking wait cannot witness it: it
either returns because the event happened (the property is broken) or blocks forever (the
property held, and the harness reports a timeout indistinguishable from a crash). So the only
available witness was the *consequence* (a livelock) and consequences are environment-dependent
in a way properties are not: QEMU storms on the 8259 and does not on the I/O APIC, so moving
routing left the arm unable to fail on the path the ship build uses.

`SYS_POLL_NOTIFY` makes absence observable. `smoke-net-mask-control` now clears the device's
cause, re-raises the line with a second transmit, and requires `IPC_AGAIN` on **every** poll
while the line is masked (repeatedly rather than once, so it fails if the notification arrives
anywhere in the window) and a badge after the ack. Deterministic, marker-based, and it fails on
the I/O APIC path where the storm arm cannot.

**The storm arm asserts a STALL rather than a marker, and that is the honest shape of it.** A
level-triggered line left unmasked when it fires re-delivers forever: ring 3 never runs, the
driver never clears the device, and nothing further is ever printed. There is no marker a
livelocked machine can emit, so the assertion is that `NETTEST: PASS` was reached and
`NETTEST: IRQ PASS` never was.

**What the interrupt work found:** the IDT had no gates for vectors 34–47. The stubs
`isr34`–`isr47` had existed since the IDT was written; nothing installed a gate, because the PIC
masked every line above 1 so none could arrive. Unmasking without them is not "the interrupt is
ignored": a vector with no gate raises **#GP**, attributed to whatever was interrupted, so the
first PCI interrupt kills an innocent ring-3 task at a random instruction. `netd` died with
`ring-3 trap vector 13` on the store immediately after enabling its device's interrupt, and the
store was not the problem. Bisecting with markers found the boundary; skipping the interrupt
enable proved it was delivery rather than the store.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-net` | `NETTEST: IRQ PASS` present, `NETTEST: FAIL` absent | passes, **3 boots in 3** |
| `smoke-net-msix-table-control` (`MSIX_TABLE_MAPPABLE=1`) | `NETTEST: FAIL msix-table-mapped` present | passes, **3 boots in 3** |
| `smoke-net-mask-control` (`IRQ_NO_MASK_ON_FIRE=1`) | `NETTEST: FAIL irq-while-masked` present | passes, **3 boots in 3** |
| `smoke-net-irq-storm-control` (`IRQ_NO_MASK_ON_FIRE=1`, `IRQ_FORCE_PIC=1`) | `NETTEST: PASS` reached, then a stall with `IRQ PASS` **absent** | passes, **3 boots in 3** |
| `smoke-net-iommu-control` (`NET_IOMMU_NO_MAP=1`) | `NETTEST: FAIL dma-never-completed` present | passes, **3 boots in 3**; `smoke-net` goes red under the same flag |
| `smoke-net-decode-control` (`NET_NO_DECODE=1`) | `NETTEST: FAIL mac-not-valid` present | passes; `smoke-net` goes red under the same flag |

**The IOMMU arm withholds the mapping and nothing else.** Same driver, same device, every
capability check still run, every address still correct, and the device cannot read its own
descriptor ring. That is what makes the mapping load-bearing rather than ceremonial, and it is
why `DMA_ADDR_NO_MAP` is a real ABI flag rather than a kernel `#ifdef`: an ifdef around the map
call would also compile out the capability checks above it, and the arm would then demonstrate
something weaker.

**The decode arm caught the rewrite before the rewrite caught anything.** `NET_NO_DECODE` had a
`#ifdef` in the virtio driver; the e1000 rewrite dropped it, the arm silently stopped being
wired, and the gate went green for the wrong reason. A defect flag must follow every rewrite of
the function it mutates: the same lesson `A_DEFECT_FLAG_MUST_FOLLOW_EVERY_SPLIT` records, here
earned by a whole-file rewrite rather than a split.

**What this gate does NOT assert: reception.** `netd` transmits and does not receive; the cause
is unknown and everything ruled out is written down in `docs/LIMITATIONS.md` §2.14. It is not a
gap in S45: both directions of DMA are exercised by the transmit path alone, since the device
must *read* the ring and *write* the completion, but it is a gap in `netd` as a network driver.

### `smoke-devcap`: a device capability names one device, and reaches only that device

Roadmap 2.7's gate, and **S43**'s witness. `devcaptest` is spawned holding *two* device
capabilities; the legacy platform device (VGA, the UARTs, the PS/2 controller, the PIT) and the
machine's PCI network controller, plus a `CAP_NOTIFICATION` and a `CAP_CONSOLE` that are there
to be the wrong type. Both device capabilities are copies of the same primordial root, with the
same type and the same rights: **they differ in exactly one field, the object**, which is the
point. If the object did not matter the two would be interchangeable.

The suite is a matrix, checked in both directions on one boot:

|  | platform capability | NIC capability |
|---|---|---|
| VGA framebuffer | maps | **refused** |
| the NIC's own BAR | **refused** | maps |
| IRQ 1 (the PS/2 keyboard) | its own line | **refused** |
| COM1 | reads under its grant | **refused** after regranting to the NIC |

**Both directions are required, and that is not symmetry for its own sake.** "The NIC capability
is refused the VGA framebuffer" is satisfied by a kernel that refuses everything, and by the
*old* kernel too, which refused everything off its compiled-in allowlist, whatever capability
you held. The positives are what rule both out, and they are in the same run.

**The port half can observe exactly one fault per boot, so which one it is had to be chosen.** A
denied `in`/`out` traps, there is no return value to test, and the fault handler cannot resume
the faulting instruction. The first arrangement read the NIC's *own* port under a NIC grant and
then a console port; it detected the global-bitmap defect, but by the wrong half: with one
console bitmap loaded for every grant, the NIC's own port is the one that is denied, so the
probe died at `nic-own-port-faulted` and never reached the read that would have shown the
console's ports being handed over. **A detector that halts truncates its own evidence**, the
lesson `smoke-kstack-park` paid for, one gate over. It now reads the *same* port twice; COM1
under a platform grant (must succeed) and COM1 again after regranting to the NIC (must fault),
so the second fault means "the grant followed the capability" rather than "port I/O is broken
here". The positive that the NIC capability reaches its own device is carried by the BAR map.

`SMOKE_NET=1` puts a virtio-net NIC on the bus for these four targets alone; every other boot
keeps `-net none`. The backend is a **hubport**, not `-netdev user`: what these gates need is a
device on the bus, not a network (nothing in the guest sends a packet) and a hubport needs no
slirp, so the gate does not depend on how the runner's QEMU was built. **The guest FAILS rather
than skips when it finds no NIC**: a second device is the whole experiment, and with only the
platform device present every refusal above is vacuous and the suite would pass on the very
kernel it exists to reject.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-devcap` | `DEVCAPTEST: PASS` present, `DEVCAPTEST: FAIL` absent | passes, **3 boots in 3** |
| `smoke-devcap-object-control` (`IO_DEVICE_OBJECT_UNCHECKED=1`) | `DEVCAPTEST: FAIL nic-cap-mapped-vga` present | passes, **3 boots in 3**; `smoke-devcap` goes red under the same flag |
| `smoke-devcap-ports-control` (`IO_DEVICE_PORTS_GLOBAL=1`) | `DEVCAPTEST: FAIL nic-cap-got-console-ports` present | passes, **3 boots in 3**; `smoke-devcap` goes red under the same flag |
| `smoke-devcap-irq-control` (`IO_DEVICE_IRQ_UNCHECKED=1`) | `DEVCAPTEST: FAIL nic-cap-took-platform-irq` present | passes, **3 boots in 3**; `smoke-devcap` goes red under the same flag |

**A fourth arm lives in `smoke-captest`, and it is the one the other three cannot supply.** All
three above bypass the *object* check while the capability lookup stays; none of them can say
whether a capability is still required at all: and that question got sharper with this change,
because the four device syscalls **lost their dispatch-table entries**. Their gate moved into
`iodev_from_slot`, so the handler is now the only thing standing there.
`IO_DEVICE_CAP_UNCHECKED=1` removes that lookup, and `captest`: which holds no `CAP_IO_DEVICE`,
maps the console's framebuffer holding nothing: `make smoke-captest-devcap-control` requires
`CAPTEST: FAIL map-phys-without-cap-io-device` (3 boots in 3), and `smoke-captest` goes red
under the same flag. captest gained seven checks for it (115 → 122), covering the three distinct
ways to have no authority: the conventional device slot never endowed, a slot holding a live
capability of the **wrong type** (slot 3's `CAP_FRAME`, the decoy every task is born with and
the one that made **[C-1]** reachable), and a slot that has never held anything.

**Each arm breaks exactly one marker, and the probe's ordering is what lets that be read off.**
The checks run object → ports-positive → IRQ → ports-negative, and the probe stops at its first
failure. So the IRQ arm reaching `nic-cap-took-platform-irq` proves the object check still
passed under it, and the ports arm reaching `nic-cap-got-console-ports` proves the object *and*
IRQ checks still passed under it. Three separate flags rather than one `IO_DEVICE_BROKEN`, for
the reason the FPU pair below gives: a single flag would redden every marker at once and say
nothing about whether any individual check can fail on its own. The one gap is honest and
inherent; the object arm dies first, so it demonstrates nothing about the other two.

### `smoke-fpu`: a task cannot read another's XMM register file

**S16's witness column was a literal em-dash until 2026-08-28.** The property was stated in
`SECURITY.md`, `fpu_save` / `fpu_restore` were real code called from `interrupt_handler64` on
every ring transition, and nothing connected the two. That is the **[C-1]** shape (a documented
property with no test binding it to the code) sitting in the table for the life of the project,
and it is the first thing roadmap 4.12's invariant registry would have caught.

Two ring-3 tasks share one CPU. `fputest` loads a sentinel into all sixteen xmm registers and
requires it intact after 64 switches away and back; `fpupeer` never writes an xmm register and
requires that none of them ever holds that sentinel. `-smp 1` is load-bearing: the disclosure
needs the two tasks to interleave on **one physical register file**, and on separate cores they
would not share one; the test would pass for the wrong reason.

**The load, the yields and the read-back are ONE `asm volatile` block.** Userspace here is
compiled with SSE2 as the baseline (the kernel is `-mno-sse`), so the compiler may use xmm
registers for its own purposes at any point. Split across three statements, this would be a test
of whatever GCC happened to leave in those registers, passing or failing on optimisation
settings rather than on kernel behaviour. One block removes the question: no compiler-generated
instruction can run between the write and the read.

**The peer needs no such care, and the asymmetry is the reason.** It asserts the *absence* of a
specific 256-byte pattern. Compiler-generated SSE cannot manufacture `fputest`'s sentinel, so
anything running before the read can only make the check **miss** a leak, never invent one, and
the control arm is what establishes that it does not miss.

**THE ARM CAUGHT THE TEST BEFORE IT CAUGHT THE KERNEL, and that is the entry worth reading.**
The first version released both tasks together with `selftest_resume_all`, and the leak arm
reproduced on **2 boots in 3**. The miss was not the kernel being intermittent: `fpupeer`
samples a bounded number of times and then reports success, so when it was scheduled early it
could spend its entire window while `fputest` was still in `fill_sentinel`, finding nothing, and
reporting "no leak" having never once looked at a moment when there was one to see.

**A gate that can pass because it looked too early is worth nothing**, and the obvious repair
(raise `SAMPLES` until the misses stop) would have hidden the race rather than removed it, and
left the arm's rate a property of the host's timing. That is the `smoke-kstack-park` mistake: a
bigger N cannot fix a biased sample.

The peer is now spawned **suspended** and released by `fputest` itself, from inside the asm
block, after the sentinel is in the registers and before the first yield: so its first sample is
ordered after the load *by construction*. `frametest` holds its peer back for the same class of
reason. Measured after the fix: **6 boots in 6**, where it was 2 in 3 before.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-fpu` | `FPUTEST: PASS no-xmm-leak` present, `FPUTEST: FAIL` absent | passes, **6 boots in 6** |
| `smoke-fpu-leak-control` (`FPU_NO_RESTORE=1`) | `FPUTEST: FAIL peer-saw-sentinel` present | passes, **6 boots in 6** (2 in 3 before the ordering fix below); `smoke-fpu` goes red under the same flag |
| `smoke-fpu-save-control` (`FPU_NO_SAVE=1`) | `FPUTEST: FAIL own-xmm-lost` present | passes, **3 boots in 3**; `smoke-fpu` goes red under the same flag |

**The two arms are separable, and measuring that is what proves the checks are independent.**
Under `FPU_NO_RESTORE=1` the leak check fails and the **integrity check still passes**, the
sentinel survives in the physical registers precisely because the peer never writes any, so
nothing clobbers it. Under `FPU_NO_SAVE=1` the integrity check fails and the **leak check still
passes**, the peer is handed its own stale image, which discloses nothing. One loses state, the
other leaks it. A single `FPU_BROKEN` flag would have reddened both markers at once and told you
nothing about whether either check could fail on its own.

### `smoke-shlibc-link`: a program links against the shared libc and carries none of it

`smoke-shlibc` proves the library *works*, by indexing its export table by hand. This proves a
**program** can be built against it. `hello_shared.c` is ordinary C (it calls `printf` and
`strlen` by name) and links no libc at all: only the generated stub archive and a `crt0_shared`
that binds the library before `main`.

**Measured, same source and flags, only the libc link differing:**

| | bytes |
|---|---|
| static libc | 106,392 |
| shared libc | **13,088** (8.1× smaller) |

**The check before the boot is the falsification.** If `hello_shared` had linked `libc.a` it would
print exactly the same thing and prove nothing, so every libc symbol it defines must be a
**14-byte thunk** (`mov m64,%r11; jmp *disp(%r11)`) rather than an implementation. Falsified
against the statically-linked build of the *same source*, which the predicate rejects naming
sizes: `printf is 168 bytes, malloc is 428 bytes, sprintf is 240 bytes, …`.

*The first attempt at that falsification was wrong and passed:* substituting the static ELF and
running the target does nothing, because the target begins with `make clean` and rebuilds over it.
The predicate has to be exercised directly.

**Why the thunks are assembly, and why `%r11`.** A C forwarder needs each callee's prototype,
and variadic functions cannot be forwarded from C at all without a `va_list` wrapper per
function. A tail jump needs no prototype. The scratch register is not `%rax` because **`%al`
carries the number of vector registers used when calling a variadic function**, clobbering it
tells `printf` how many xmm registers to spill.

That hazard is measured, not assumed, and it is nastier than it looks: `%al` too *large* merely
spills more than needed, which is harmless, so a `%rax` thunk passes every test until the table
pointer happens to land on an address ending in a small byte. Forced to zero, the same
`sprintf("%.1f")` call **segfaults**. `%r11` is caller-saved, never an argument register, and
has no role in the variadic convention, which is why a real PLT uses it.

**No runtime control arm, and the reason is recorded rather than omitted.** The obvious one
(generate `%rax` thunks) is *probabilistic* for exactly the reason above, and the library's base
is randomised per boot (S51), so the arm would reproduce only sometimes. An off-by-one index arm
crashes the task rather than printing a marker. A gate must not assert something it can only
sometimes observe, so the deterministic static check is the falsification.

**What has no stub, and what happens instead.** Data symbols cannot be thunked, a variable
reference is an address the compiler emits directly, which is what needs a GOT. `_impure_ptr`
survives as a program-local *pointer* initialised from the library's (S50 makes the target
per-task); `environ` likewise, empty on both sides; `optarg`/`optind` **are** the state and get
no stub, so a program needing them fails to **link** rather than running with an `optind` that
silently stops advancing.

### `smoke-shlibc`: a ring-3 task calls newlib out of the shared library

Every other shlib gate demonstrates the **mechanism's properties** (text shared and unwritable
(S49), data private per task (S50), base drawn per boot (S51)) on `shlibdemo.so`, a three-page
object written for the purpose. This one loads the **real** shared libc: ~135 KiB of newlib, its
port glue and libhorus, 36 pages (34 shared text, 2 per-task data), and requires a ring-3 task
to map it and call in.

**A demo object cannot fail the way a libc can**, which is the whole reason this exists. newlib
has writable state (`_impure_ptr`, errno, the stdio buffers, the atexit list, the rand state),
it calls back into the port's syscall glue, and it allocates. Each of those crosses the
shared/private boundary S50 draws, and none was exercised by an object whose entire data segment
was one `int`.

What `libctest` asserts, in an order chosen so a failure isolates itself:

| Check | What it establishes |
|---|---|
| `strlen`, `strcmp` through the table | shared text executes at the base the kernel reported |
| `*_impure_ptr` lands inside `[base, base+pages*4096)` | the reentrancy pointer resolves into the library's **own per-task data**, not null and not outside the mapping |
| `sprintf` returns `"horus-42"` | a call that goes **through** that writable state, not only through pure text |

Pure text first, deliberately: if `strlen` does not work the library is not mapped where it was
relocated for, and every later check would fail for that one reason.

**The gate also checks something static, before booting.** `libctest` must define none of
`strlen`, `strcmp`, `sprintf`, `_impure_ptr` itself. If it did, the call would resolve locally,
the library would never be entered, and `LIBCTEST: PASS` would mean nothing; **a witness has to
be behind the mechanism it witnesses**. Falsified by giving `libctest` its own `strlen` and
confirming the check fires. Measured: the probe is 10,192 bytes with 8 defined symbols, against
the library's 711,952.

**THE EXPORT SET WAS TOOLCHAIN-DEPENDENT, and CI is what showed it.** The list is derived from
what the shipped programs leave undefined, and that varies by compiler. gcc 14 on Debian leaves
`sprintf` undefined in the coreutils objects; the compiler on GitHub's runners does not. So the
table held a symbol on one machine and not the other, and `libctest` compiled here and failed
there on `SHLIB_IDX_sprintf undeclared`. **An interface that changes with the compiler is not an
interface.**

`gen_libc_exports.sh` now unions the derived set with a **required core**, `__errno`,
`_impure_ptr`, `free`, `malloc`, `memcmp`, `memcpy`, `memset`, `sprintf`, `strcmp`, `strlen`,
exported whether or not any shipped program references them, because they are what a libc
*means* and what a caller may rely on being there. A required symbol that `libc.a` does not
define is a **hard error**, not a quiet omission: a table that does not contain what it promises
fails closed.

Falsified both ways, because locally every required symbol was already in the derived set and the
union path would otherwise never have executed: a required symbol `libc.a` does not define is
refused (`horus_not_a_real_symbol`), and a required symbol the coreutils do *not* reference
(`qsort`, 0 references) is exported anyway, taking the table from 59 to 60.

The derived remainder still varies by toolchain, and that is fine, an unreferenced symbol is
library text nobody calls. It is also why the index header must be regenerated *with* the table
and never remembered.

**THE FIRST RUN FOUND A DEFECT IN THE ABI, and it is the kind only the real object could find.**
`SYS_SHLIB_INFO` reported `data_page` (a single index) which was true of the demo and false of
newlib, whose writable segment is **two** pages. The probe asked for READ|EXEC on the second,
its capability carried READ|WRITE, and the map failed (`LIBCTEST: FAIL partial-map`). The call
reports `data_first`/`data_pages` now. The range is contiguous because the loader accepts
exactly one writable `PT_LOAD`, which `check_shared_object.py` enforces at build time; the probe
does not assume it, and neither does the handler, which counts what is marked.

**One task, not two,** and the asymmetry with `smoke-shlib` is deliberate. That test's question
is cross-task (can one holder write what another executes) and needs a peer to answer. This
one's question is whether the library *works*, which one task settles. A second task here would
be a second copy of a test that already exists rather than a stronger claim.

### `smoke-shlib-aslr`: the library does not load at the same address twice

**Two boots, because the property is not observable from inside one.** A single run sees an
address either way and cannot tell a random base from a compiled-in one. So both boots report
theirs (`SHLIBBASE: <hex>`, from `shlibtest`) and the gate requires the two to differ. The base
gate and its control arm are the same script with the comparison inverted, which is what makes the
pair a measurement rather than two tests.

Both boots must also reach `SHLIBTEST: PASS`. Without that, a boot that died before printing a
base would leave the comparison to a missing value, and "the two differ" would be satisfied by a
failure.

**Why this landed before the thing it protects.** The base was compiled in, which was fine for a
three-page demo. It stops being fine when newlib moves onto this mechanism: ~135 KiB of
executable code at an address printed in the binary, mapped into every task: and a *regression*,
because a program's static libc today lives inside its own PIE image, which the loader already
randomises.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-shlib-aslr` | two boots, bases DIFFER, both PASS | passes, **3 runs in 3** |
| `smoke-shlib-aslr-control` (`SHLIB_BASE_FIXED=1`) | two boots, bases IDENTICAL | passes, **3 in 3**; `smoke-shlib-aslr` goes red under the flag |
| `smoke-shlib-info-control` (`SHLIB_INFO_UNGATED=1`) | `SHLIBTEST: FAIL shlib-info-with-wrong-cap-type` | passes, **3 in 3**; `smoke-shlib` goes red |
| `smoke-shlib-info-object-control` (`SHLIB_INFO_TYPE_ONLY=1`) | `SHLIBTEST: FAIL shlib-info-with-data-frame` | passes, **3 in 3**; `smoke-shlib` goes red |

**THE GATE CAUGHT ITS OWN CHANGE ON THE FIRST RUN, and that is the entry worth reading.** The
first version drew the base from `aslr_random_offset` and reported the *same* address on both
boots. The draw was correct; the PRNG was not seeded. `aslr_init_seed()` was called after
`smp_bringup()`, which on the 64-bit path **does not return** (it spawns the shell and enters
ring 3) so the call was unreachable and the xorshift state sat at its compile-time constant for
the whole boot.

That had been harmless, and checking *why* mattered more than fixing it. Every other consumer of
that PRNG sits downstream of `choose_image_placement`, which mixes `read_tsc()` and
`secure_random_u64()` before it draws, so image base, stack offset and heap gap were randomised
by that mix and not by the dead seed. **The image ASLR was never broken**, which is worth
stating plainly because the obvious reading of a dead `aslr_init_seed()` is that it was.
`shlib_init` was simply the first consumer to draw *before* any spawn, and so the first to see
the unseeded state. The seed now runs immediately behind `entropy_init()`, where it is
reachable.

**Two unequal draws do not prove much on their own**, they are consistent with a 1-bit source.
This gate asserts that the base is not a constant. The entropy claim rests on
`aslr_random_offset`, which is rejection-sampled over 2^30 page-aligned positions (30 bits, the
same window the image gets), and it is stated here rather than implied by the test.

**The refusals are falsified one arm per rule.** `SYS_SHLIB_INFO` applies two: the capability
must be a `CAP_FRAME`, and it must name a frame the library *owns*. With only the ungated arm,
the second rule would never have been shown to fire; the probe stops at its first failure, and
the type check runs first. `SHLIB_INFO_TYPE_ONLY` keeps the type check and drops the object
test, so the probe reaches the second check and *that* one fires. Neither probe uses an empty
slot: an empty slot is refused by `cap_lookup` before any of the call's own logic runs, so it
would pass whether or not the gate existed.

The sharper of the two is the object rule. The capability it refuses is one the task
**legitimately holds** (its own private copy of the library's writable page (S50)) and a gate
that tested only the type would answer it.

### `shared-objects`: an object the kernel's loader would refuse never gets built

`make check-shared-objects` builds every shared object in the tree and checks it against what
`src/kernel/shlib.c` actually enforces. Required CI job; static, not a boot test.

**Why static.** `shlib_init` refuses anything but `R_X86_64_RELATIVE`. Refusing is correct and a
terrible diagnostic: the library is simply **absent**, and the first symptom is a task faulting on
a call into an address nothing mapped. The properties are decidable by reading the object, so they
are read at build time where the error names the cause.

**Every rule here exists because building the shared libc hit it, and none of them is a link
error:**

| Mistake | Object gets |
|---|---|
| port's syscall glue not linked in | 10 undefined symbols, 10 `R_X86_64_JUMP_SLOT` |
| no `-Wl,-Bsymbolic` | intra-library references become `R_X86_64_GLOB_DAT` |
| no `-Wl,-z,nodynamic-undefined-weak` | one `GLOB_DAT`, from `__on_exit_args` alone |

**Falsified one arm per rule**, because a checker with four rules and one arm has three rules that
have never been shown to fire:

| Rule | Falsified against | Result |
|---|---|---|
| only `R_X86_64_RELATIVE` | a libc linked without the glue | 10x `JUMP_SLOT` reported |
| no undefined symbols | the same object | 10 undefined named |
| fits `SHLIB_MAX_PAGES` | `SHLIB_MAX_PAGES` temporarily set to 4 | "needs 36 pages" |
| one page-aligned writable `PT_LOAD` | `shlibdemo.c` linked with the DEFAULT script | "starts at 0x3f20, not page-aligned" |

The last is worth keeping: it is the exact layout `userspace/shlib.ld` exists to prevent, so the
rule is checked against the thing it was written for rather than a synthetic case.

`SHLIB_MAX_PAGES` is read from `src/include/kernel.h`, not copied into the checker; the two
cannot drift.

### `smoke-shlib`: one library, executed by many, writable by none, with data private to each

**This section did not exist until 2026-08-29, and S49 landed without it.** The property had a
witness that ran and a control arm that reproduced; what it did not have was an entry here. Worth
recording as the near-miss it is: `invariants` binds an S-number to a target and would have caught
a *missing* witness, but nothing binds a witness to its write-up, so a test can be real and
undocumented. Noted rather than quietly filled in.

The library is one shared object (`userspace/shlibdemo.c`), loaded once into frames at boot by
`src/kernel/shlib.c` and mapped by two ring-3 tasks that each call into it.

**Two properties, two segments, and the split is the whole design.**

`userspace/shlib.ld` puts the object into exactly two loadable segments, page-aligned apart:

    LOAD  R E   .text .shlib_exports .dynamic   -> SHARED between every task   (S49)
    LOAD  R W   .data .bss                      -> instantiated PER TASK       (S50)

Text is endowed from a primordial carrying READ\|EXEC and never WRITE; data from a *separate*
primordial carrying READ\|WRITE and never EXEC. A page a task may write is a page it may not
jump into, and vice versa. **The isolation is not in the rights** (every task holds identical
rights over its data) it is in the *object* each capability names being a different frame.

**Why a shared libc needs the second half.** Measured going into the newlib migration: of the
**59** newlib symbols the shipped coreutils reference, exactly **three** are writable,
`_impure_ptr` (errno, the stdio buffers, the atexit list, the rand state), `optarg` and
`optind`. Shared, one task reads and writes another's errno and stdio buffers and can corrupt an
allocator another task is mid-call in. Sharing a libc's *text* is an optimisation; sharing its
*data* is a defect, and it is the same argument S49 makes about text arriving one segment
further on.

**The peer is the witness, and it has to be.** A task cannot distinguish a private copy from a
shared one by looking at its own writes; it sees what it wrote either way. So `shlibtest` writes
a sentinel into its copy and `shlibpeer`, which wrote nothing, reports what it sees. The peer is
spawned suspended and released by `shlibtest` after its own checks, for the same reason
`fputest` holds its peer: a peer that read early would report a pass that meant nothing.

**Nothing in the test writes the library's constants down.** The expected initialiser is read
from the library's own *text* (`shlib_state_initial`), and the export-table offset, page count
and data-page index are generated from the object by `tools/shlib_offsets.sh` into
`userspace/shlib_offsets.h`. Both used to be literals: the export table was `SHLIB_VA + 0x4000`
in two files, correct for exactly one layout, and `shlib.ld` moved it. **A test that reads the
wrong address does not fail honestly: it reads whatever is there and reports on it.**

| Arm | Asserts | Result |
|---|---|---|
| `smoke-shlib` | `SHLIBTEST: PASS` present, `SHLIBTEST: FAIL` absent | passes, **3 boots in 3** |
| `smoke-shlib-writable-control` (`SHLIB_TEXT_WRITABLE=1`) | `SHLIBTEST: FAIL peer-saw-patched-code` present | passes, **3 boots in 3** |
| `smoke-shlib-data-shared-control` (`SHLIB_DATA_SHARED=1`) | `SHLIBTEST: FAIL peer-saw-our-data` present | passes, **3 boots in 3**; `smoke-shlib` goes red under the same flag |
| `smoke-shlib-data-init-control` (`SHLIB_DATA_UNINITIALISED=1`) | `SHLIBTEST: FAIL data-not-initialised` present | passes, **3 boots in 3**; `smoke-shlib` goes red under the same flag |

**The two S50 arms break different things**: `SHLIB_DATA_SHARED` hands every task the template
frame itself (disclosure), `SHLIB_DATA_UNINITIALISED` carves a private frame and zero-fills it
(loss). A libc whose data is private but uninitialised is a libc whose `_impure_ptr` is NULL; it
leaks nothing and simply does not work, which is a different defect and gets a different arm.

**Only one direction of their separability is witnessed, and the other is not claimed.** Under
`SHLIB_DATA_SHARED` the initialisation check still passes, and that is visible on the wire,
`SHLIBTEST: data initialised from the image, and written` prints before the peer reports the
disclosure. The reverse is *not* observed: under `SHLIB_DATA_UNINITIALISED`, `shlibtest` fails
its own initialisation check and exits before it ever resumes the peer, so the privacy check
does not run. The privacy property does still hold there in the code, a fresh frame is carved
either way and only the copy is skipped, but this arm does not witness it, so the claim is not
made. **A detector that stops at its first failure chooses what it demonstrates**, which is the
same reason `smoke-shlib-writable-control` skips the refusal checks deliberately.

### `smoke-fork`: a forked child's memory is a copy, and a kernel object is never forked

Roadmap 2.3's gate. `forktest` writes two heap pages, forks itself, and the two sides check each
other's isolation; then, back in the parent, it retypes a `KOBJ_FRAME`, maps it, and requires
the next fork to be **refused**, and the one after the unmap to succeed.

**The two isolation directions are tested differently, because only one has a rendezvous.**
Child-writes-invisible-to-parent is exact: the child writes and exits, the parent `sys_wait()`s
(a real happens-before) and reads. Parent-writes-invisible-to-child has no such handshake,
because a forked child shares nothing with its parent through which the two could synchronise;
that is the property under test. So the child spins reading the page for a bounded number of
iterations while the parent writes immediately after the fork returns. The bound makes the test
terminate, and it does not make the assertion probabilistic: a miss can only ever fall in the
direction of *passing* the shared-page arm, and the arm is run to confirm it does not.

Both directions are in fact **one PTE operation** (`clone_user_aspace` downgrades the parent's
leaf and the child's alike) so an arm that breaks one breaks both. The second check exists
because "in fact one operation" is a fact about today's implementation, which is the class of
thing this repository has been bitten by asserting.

**The witness had to be falsified before the kernel was.** The first version had a failing child
report and `sys_exit()`. Under `FORK_SHARE_WRITABLE=1` the run printed `FORKTEST: FAIL
child-saw-parent-write` **and then** `FORKTEST: PASS`: the child had exited before writing the
page the parent's own check reads, so the parent found nothing wrong and gave a verdict. A gate
that emits both verdicts is decided by whichever the harness latches first. A failing child now
**dies** instead; it writes through a null pointer, the kernel records `TASK_EXIT_PAGEFAULT`,
and the parent reads that back with `SYS_TASK_EXIT_INFO` after the wait. The manner of its death
is the one channel a forked child still has to its parent, and it is enough. The parent's own
memory checks run **before** that one, deliberately, so a kernel that fails both reports both,
otherwise the arm's named marker would be unreachable.

**Both directions on the refusal, too.** Requiring only that a mapped frame refuses the fork is
satisfied by a kernel whose fork never works, so the same target unmaps the frame and requires
the identical call to succeed.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-fork` | `FORKTEST: PASS` present, `FORKTEST: FAIL` absent | passes, **3 boots in 3** |
| `smoke-fork-share-control` (`FORK_SHARE_WRITABLE=1`) | `FORKTEST: FAIL parent-clobbered` present | passes, **3 boots in 3**; also emits `FORKTEST: FAIL child-saw-parent-write`, and no `PASS`; `smoke-fork` goes red under the same flag |
| `smoke-fork-arena-control` (`FORK_ARENA_UNCHECKED=1`) | `FORKTEST: FAIL forked-with-frame-mapped` present | passes, **3 boots in 3**; `smoke-fork` goes red under the same flag |
| `smoke-fork-cspace-flat-control` (`FORK_CSPACE_FLAT_COPY=1`) | `FORKTEST: FAIL child-cap-shares-serial` present | passes, **3 boots in 3**; `smoke-fork` goes red under the same flag |
| `smoke-fork-cspace-orphan-control` (`FORK_CSPACE_ORPHAN_COPY=1`) | `FORKTEST: FAIL child-cap-not-derived` present | passes, **3 boots in 3**; also emits `FORKTEST: FAIL child-cap-survived-revoke`; `smoke-fork` goes red under the same flag |

Three boots rather than a rate over hundreds, for the same reason as `smoke-frame`: neither
defect is a race. Both are deterministic properties of a build (the leaves are downgraded or
they are not, the arena test is compiled in or it is not) and the `-smp 1` in these targets is
what keeps the parent's post-fork write ordered ahead of the child's first look, so the sample
size that matters is 1 and 3 is corroboration.

**The cspace half is checked STRUCTURALLY, and that is what makes it exact.**
`SYS_CAP_ENUMERATE` reports a capability's `serial` and `badge` (the nodes and edges of the
derivation graph) which is precisely the statement **S41** makes, so the test reads the
invariant off the graph rather than inferring it from behaviour. That matters here more than
usual: a forked child shares nothing with its parent through which the two could synchronise, so
any behavioural check would need the bounded-spin treatment the memory half uses. The structural
one needs no rendezvous and no timing assumption at all, and `forktest` holds a `CAP_DEBUG` for
exactly this. It is an *observability* capability; it discloses type, rights, serial and badge
and deliberately not `object`, so granting it to the witness adds no reach.

**Three ways to get the derivation wrong, and each fails a different check.** No copy at all
(the kernel before this change) leaves the slot unoccupied. A verbatim copy gives two
capabilities one serial. A copy with a fresh serial but no parent edge is a second *root*.
The last two are the control arms; the first is what the base gate's `child-cap-absent` and
`child-cannot-use-inherited-cap` checks catch, and it is why the base gate would have failed
against `main` one commit ago.

**The four S41 checks deliberately do not short-circuit.** Each states a separate rule and the
arms are one per rule, so an early exit on the first failure would leave the later checks
unreachable from any arm, a check that cannot fail. `FORK_CSPACE_ORPHAN_COPY=1` fails **both**
the badge check and the end-to-end revoke check, and it should: the structural claim and its
consequence are different assertions, and an edge nothing traverses is not a revocation path. A
`bad` flag suppresses the `PASS` at the end, so no run emits both verdicts.

### `smoke-forkexec`: an exec replaces the image, not the authority

Roadmap 2.3's pairing. `fork` and `exec` were each gated; the two **in sequence** (the only
sequence a shell ever performs) were not. `forkexectest` forks itself, the child mints a
capability from the `CAP_UNTYPED` it inherited and then replaces its image with `forkexecee`
through `SYS_EXEC_NAMED`, and the driver reads the result out of the derivation graph.

**The property is the ABSENCE of a step, which is the hardest kind to witness.**
`exec_into_armed_image` rebuilds the address space and does nothing at all to the cspace: that
is **S42**. Nothing can be pointed at, so nothing goes stale visibly and no reviewer is prompted
to ask whether it still holds. The two control arms therefore *add* the steps an exec is tempted
to take, and the gate measures the difference.

**`EXEC_ROOT_CSPACE=1` is the one the property exists for, and it is invisible to every
functional check.** It keeps every capability and re-mints each as a **root**: fresh serial, no
badge. The task's authority is byte-for-byte what it was, so it can still do everything it could
before: what it has lost is its position in the graph, and the parent's revoke stops reaching
it. That is finding **3.3**'s shape one syscall over from `FORK_CSPACE_ORPHAN_COPY`, and
combined with `SYS_FORK` it is an authority-laundering primitive: fork to inherit a derived
copy, exec to turn it into a root nobody can revoke.

**The revocation is three generations deep**, deliberately: the driver's `CAP_UNTYPED`, the
child's forked copy of it (**S41**), and the capability the child minted from *that* before
execing. Revoking the first must sweep the third, across a fork and an exec.

**Everything the execed task reports, it reports through the capability graph.** `forkexecee`
mints into slots the driver reads with `SYS_CAP_ENUMERATE` rather than printing, for two
reasons. A gate decided by matching two tasks' prose on one wire is decided by whichever line
the harness latches first: which is exactly how `forktest`'s first version printed a `FAIL` and
then a `PASS`. And the console is not a channel this task is guaranteed: in this selftest boot
nothing has taken the console so even `EXEC_RESET_CSPACE=1` can still print (measured, not
assumed), but once a ring-3 console server owns the hardware, printing needs the delegated
endpoint in slot 5, precisely what an exec that rebuilt the cspace would discard. A report a
defect can silence is not a report.

**The rendezvous signals are minted from slot 0, never from the capability under test.** A
handshake that depends on the property being measured cannot report that property's absence: it
hangs instead, and a gate that hangs prints no marker at all. Slot 0 is also the *only* birth
capability `SYS_CAP_MINT` will accept as a source (it is the one carrying `CAP_RIGHT_MINT`,
where slot 3 is `READ|WRITE|EXEC` and slot 4 `READ|WRITE`) and using slot 3 instead made every
signal in this test fail silently while it was being written. `FE_SLOT_READY` is minted **last
and unconditionally**, so it means "I have finished and recorded what I found" rather than "I am
alive", and every wait in the driver is bounded with its own named `FAIL` on expiry.

**It also carries the one memory claim `smoke-fork` cannot reach.** `task_teardown` does not
free an address space (a dead task's tree is reclaimed later, when its slot is reused) so a
forked child that merely exits never exercises the reference `clone_user_aspace` took on each
shared page. An exec does, through `create_user_pagedir`'s reclaim, and this is the **only path
in the tree that frees a copy-on-write clone while its parent is still running**. A reference
dropped once too often would put a live page of the parent's on the free page stack, to be
handed out as somebody's fresh anonymous page. The driver re-reads its own byte after the exec.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-forkexec` | `FORKEXECTEST: PASS` present, `FORKEXECTEST: FAIL` absent | passes, **3 boots in 3** |
| `smoke-forkexec-reset-control` (`EXEC_RESET_CSPACE=1`) | `FORKEXECTEST: FAIL exec-dropped-inherited-cap` present | passes, **3 boots in 3**; also emits `FORKEXECTEST: FAIL exec-lost-inherited-cap`, and no `PASS`; `smoke-forkexec` goes red under the same flag |
| `smoke-forkexec-root-control` (`EXEC_ROOT_CSPACE=1`) | `FORKEXECTEST: FAIL child-cap-survived-revoke-after-exec` present | passes, **3 boots in 3**; also emits `FORKEXECTEST: FAIL exec-recreated-inherited-cap` and `exec-orphaned-inherited-cap`; `smoke-forkexec` goes red under the same flag |
| S39 across the exec (`FORK_SHARE_WRITABLE=1`, no new flag) | `FORKEXECTEST: FAIL parent-clobbered-by-exec` present | passes, **3 boots in 3** |

**Each arm fails only its own rule's checks**, which is what makes them two rules rather than
one gate wearing two names: the reset arm never reaches the lineage comparisons (they sit inside
the `occupied` branch), and the root arm passes the presence and usability checks by
construction. The checks do not short-circuit, for `smoke-fork`'s reason (an early exit on the
first failure would leave the later ones unreachable from any arm) and a `bad` flag suppresses
the `PASS`, so no run emits both verdicts.

Three boots rather than a rate over hundreds: neither defect is a race. Both are deterministic
properties of a build, and the `-smp 1` in these targets makes the three tasks' interleaving the
scheduler's rather than the host's.

### `smoke-nzcow-arena-control`: a kernel object's page is never copied out from under it

Roadmap 2.1 asked what a copy-on-write break means for a capability two tasks hold. It means two
things the kernel must not do, so `cow_break_pte` refuses any page inside the untyped arena
(**S38**). The shared branch allocates from the *anonymous* pool, so a frame holder would obtain
a private writable page no untyped region ever paid for; and the PTE would be repointed at
memory no capability names, detaching the mapping from the object while the frame's
`1 + mappings` pin arithmetic went on claiming otherwise.

**The case uses a real `KOBJ_FRAME` at refcount 2, and the refcount is the whole point.** A
freshly retyped frame sits at 1 (its permanent pin) and at 1 an unguarded break takes the
*sole-owner* path: it upgrades the PTE in place and allocates nothing. That is the wrong half of
the defect to measure. It would show a read-only mapping turning writable but not the page
appearing outside the untyped budget, which is the half that breaks the object model. Raising
the count to 2 first puts the arm on the branch that allocates.

**Nothing in the tree reaches this path, and the gate exists for that reason rather than in
spite of it.** Two circumstances prevent it: `user_map_frame_page` sets
`PRESENT|USER[|WRITE][|NX]` and never `PAGE_COW`, and `rust_validate_page_fault` admits only
image, heap and stack, so a frame mapped elsewhere never reaches the pager. **Neither is a
statement about frames**: both are facts about other functions, which is exactly the shape
**S28** and **S30** turned out to have when someone looked. This entry named roadmap 2.3's
`fork` as the function that would change it; `fork` landed on 2026-08-28, and it does mark
present user PTEs copy-on-write. It does **not** reach this path, because it refuses to clone an
arena page at all (**S40**, `smoke-fork-arena-control`), a refusal one layer earlier than this
one, for the reason given there. So the guard below is still reached by nothing, and is now
defended by a stated property rather than by two circumstances.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-nzcow` | `NZCOW_SELFTEST: PASS` present | passes, **3 boots in 3** |
| `smoke-nzcow-arena-control` (`COW_ARENA_UNGUARDED=1`) | `NZCOW_SELFTEST: FAIL arena-cow-broken` present | passes, **3 boots in 3**; `smoke-nzcow` goes red under the same flag |

**A CONTROL ARM IS AS SPLIT AS THE THING IT INJECTS INTO**, and this pair proved it by going
red. Giving a frame a length created a *second* function turning `CAP_FRAME.object` into a fact
about an object (`frame_pages_by_index` beside `frame_phys_by_index`) and
`FRAME_INDEX_UNCHECKED=1` was written when there was only one. Under the arm the address
resolver returned the object as an address exactly as intended, and then the *length* resolver
applied the bound the arm exists to remove, answered 0 for the legacy slot-3 capability, and the
map path refused it. `FRAMETEST: FAIL legacy-cap-mapped` stopped appearing and
`smoke-frame-index-control` went red **for want of a failure**, the arm had quietly stopped
reproducing anything.

Nothing about the property was wrong and the base gate passed all 48 checks throughout. What
broke was the measurement, which is the harder thing to notice: a green base arm says nothing
about whether its control arm still fires. The arm now lives in both resolvers, and the lesson
generalises past this file; **when you split a function that a defect flag mutates, the flag has
to follow every piece.** It was caught by CI rather than locally because the local run exercised
the new arm and the two region arms and not the two that already existed.

**A frame carries a LENGTH since 2026-08-27** (**S36**), and the arm aims at the thing that does
not announce itself. A sized frame is a run of contiguous pages under one capability, and the
plausible slip in mapping one is to advance the virtual cursor and forget the physical one: one
of two cursors in a loop that reads correctly. That does not crash. The caller gets exactly the
pages it asked for, present, writable, with the right bits, all aliasing page 0. Nothing reports
it, so the only way to see it is to write a distinct word to each page and read them all back,
which is what `sized-pages-distinct` does.

**The arm reddens four checks, and that is correct.** `unmap_run` withdraws page *k* by naming
`base + k`, and `user_unmap_frame_page` requires the PTE to hold exactly that physical page,
under aliasing it does not, so the unmap fails too. Those three extra failures are downstream of
the defect rather than a leaky test, and the distinction matters: an arm whose blast radius you
have not accounted for is an arm you cannot use to say "only this property broke".

**The unwind is SHARED between a sized frame and a run of slots**, so
`FRAME_REGION_NO_ROLLBACK=1` reddens `region-rollback-page0` *and* `sized-rollback-page0` from
one flag. One policy, one implementation, one arm covering both levels, which is the point of
the shared helper rather than a coincidence worth noting once.

**The region arms are a PAIR, and neither alone would settle the policy** (roadmap 2.1,
**S35**). `SYS_MAP_REGION` is all-or-nothing: a run that fails part-way withdraws every page it
had already mapped. That is one claim with two ways to get it wrong, so it has one arm each.
`FRAME_REGION_NO_ROLLBACK=1` drops the unwind; the failure is reported and pages 0 and 1 of the
four-page run stay mapped, which is prefix semantics and a fail-*open*, since a PTE is authority
the caller has just been told it did not get. `FRAME_REGION_ROLLBACK_WIDE=1` unwinds too much;
the whole *requested* range rather than the pages installed, so the cleanup destroys the
pre-existing mapping that caused the refusal, a primitive any task could aim at a mapping it
disliked.

**`frametest` blocks the MIDDLE of the run** so it fails at page 2 of 4: an unwind that handled
only the first page, or only the last, would pass a run that failed at either end. And the
blocker is the run's **own** page-2 frame, which is what makes the wide arm falsifiable at all,
against an unrelated frame, `user_unmap_frame_page`'s `expect_phys` test would refuse the wide
unmap by itself, the check would pass under the arm, and the arm would measure nothing. Aim at
the range logic, not at the guard underneath it.

**The rollback is probed without touching the pages.** Mapping over a present page is refused,
so a single-page `SYS_MAP_FRAME` that *succeeds* at the address proves it is free. Reading the
page would prove the same thing by taking a fault and killing the task, a detector that destroys
its own evidence and reports a rollback bug as a dead workload.

**The index arm reproduces the defect in its realistic form, not by deleting a check.** The
shortcut a frame-mapping syscall invites is to put the physical address in `capability_t.object`
and map it (one field, no table, no resolver) so that is what `FRAME_INDEX_UNCHECKED=1` builds.
Simply removing the range test would have made `dyn_frames[0x400000 - 1]` a wild read that
faults, and the arm would have measured the bounds check crashing rather than the authority
being wrong.

**The rights arm had to be re-aimed, and the first version could not have failed.** It was
written against the `have & want` intersection in `frame_pte_flags`: build the PTE from `want`
alone and see whether a `READ`-only delegate can write. It cannot, and neither can it under the
fix: because `cap_lookup(slot, rights)` has already refused unless the capability holds at least
every right requested, so `have & want == want` at every reachable call and the two builds
produce the same PTE. The arm now removes the **floor** instead, which is the thing that
actually decides. Recorded here because a control arm that cannot fail is indistinguishable from
one that works until somebody tries to make it fire.

### `smoke-libhorus`: libhorus keeps its bounds, and refuses rather than spins

Every freestanding userspace program (`init`, `shell`, `fs_server`, `console_server` and the
selftests) links `libhorus`. That sharing is a trade: before it, a bug in one program's private
`umemcpy` broke one program; now a bug in `libhorus` breaks all four servers at once. The trade
is only worth making if the shared copy is held to a standard the seven private copies never
were, which is what this gate is for.

A ring-3 task asserts the properties the call sites actually depend on: that every bounded write
stays inside its bounds (checked with a guard byte either side, because a length check alone
cannot see an off-by-one), that `n == 0` writes nothing, and that `ustrncpy` **always**
terminates, at exact fit, at truncation, and at `n == 1`.

**The one that is a security property.** `ipc_call_retry` must return a *permanent* IPC refusal
rather than retry it. `SYS_ERR_PERM` means the caller holds no capability for that endpoint, and
the pre-libhorus loop (`while (r < 0) spin_delay();`) spun on it forever, turning the one event
the capability system exists to make visible into an indistinguishable hang. That is finding
**[G-8]** signature C. Until now the property was asserted by comments in two programs and
tested by nothing; the selftest calls into an empty capability slot and requires the call to
come back.

| Arm | Asserts | Result |
|---|---|---|
| `smoke-libhorus` | `LIBHORUS_SELFTEST: PASS` present | passes |
| `smoke-libhorus-retry-control` (`LIBHORUS_RETRY_ANY=1`) | pre-call line present, `PASS` **absent** | passes; `smoke-libhorus` **times out** under the same flag |
| `smoke-libhorus-strncpy-control` (`LIBHORUS_STRNCPY_UNTERMINATED=1`) | `FAIL strncpy-truncate-unterminated` present | passes; `smoke-libhorus` **goes red** under the same flag |

**A test for a hang cannot be an equality check**, which is why the retry arm asserts an
*absence*. Under the defect the call never returns, so there is no value to compare; the
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
`generation` field (the use-after-revoke backstop) and the copy had neither, so no kernel
regression could have failed it. `tests/README.md` had also claimed `make test` ran it, which
nothing did. A test that cannot fail is not a test, and one that exercises none of the system is
not a test of the system.

Anything algebraic belongs in the Rust crate, where it can also carry a Kani proof; anything
touching kernel state belongs in a QEMU self-test. The binding suites are:

| Suite | Location | Run with |
|---|---|---|
| Capability algebra unit tests | `rust/src/capability.rs` | `cargo test --manifest-path rust/Cargo.toml` |
| Kani proofs (revocation subtree) | `rust/src/` | `cargo kani` |
| FFI boundary fuzzing | `rust/fuzz/` | `cargo +nightly fuzz run <target>` |
| Kernel integration self-tests | `src/kernel/selftest.c`, `userspace/` | `make smoke-<name>` |
| Capability conformance (180 checks; the suite prints its own count as `CAPTEST: PASS <n> checks`; read it from there) | `userspace/captest.c` | `make smoke-captest` |
| Scripted shell sessions | `tools/*_session.py` | `make smoke-session` |

---

## Writing a new test

1. Decide which layer it belongs to. Algebraic properties → Rust unit test or Kani proof.
   Kernel behaviour → QEMU self-test. End-to-end user-visible behaviour → scripted session.
2. For a self-test: add a `*_SELFTEST`-guarded routine that prints `NAME: PASS`, and a
   `make smoke-name` target that boots it and greps for the marker. Copy an existing target.
3. **Make it adversarial where you can.** Assert the refusal, not just the success.
4. Reference it in your PR body and in the invariant statement (see `CONTRIBUTING.md`).
