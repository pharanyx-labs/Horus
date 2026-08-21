# G-11: the armed program image was ambient state

*Extracted from [`../../TESTS.md`](../../TESTS.md), where it was one section of a test
catalogue. The narrative is kept in full: in this project the reasoning is the evidence, and
the record of which hypotheses were wrong is the part worth reusing.*

*Current status is authoritative in [`../LIMITATIONS.md`](../LIMITATIONS.md); the gates that
witness it are listed in [`../../TESTS.md`](../../TESTS.md).*

---

**Found and closed 2026-08-18, while serialising [G-10]'s staging window.** Nothing recorded
which task armed the staged image, and one syscall turns that from an oddity into a privilege
boundary. `SYS_SUDO` re-authenticates the caller and then spawns whatever image is armed **as
uid 0**, endowing it with `CAP_FRAME`, `CAP_USER` and a `CAP_TCB` — and the arm is a *different
syscall* from the consume:

1. task A (any task holding the spawn capability) arms its own image;
2. task B authenticates correctly with `SYS_SUDO`;
3. B's sudo spawns **A's** program at uid 0.

Neither task confuses a rights check. The authority came from the pairing, which is why it is
recorded as its own adversary (`SECURITY.md` **A1c**) rather than folded into A1. It is a
G-number and not a C-number only because nothing in userspace calls `sudo` today.

**Fix.** `loader_arm_commit()` is the sole way to publish an armed image and records the arming
task; `loader_disarm()` clears both together. `do_spawn` refuses an image owned by another task,
`h_sudo` refuses before spending the elevation and audits the refusal rather than logging a
failure. Fail closed: an image with no recorded owner cannot be consumed at all, so forgetting
to stamp one is a broken spawn, not a silent ambient one.

**Witness, falsified both ways** (`make smoke-spawn-owner`, single boot, deterministic):

| Arm | Marker | Result |
|---|---|---|
| default | `SPAWN_OWNER_SELFTEST: PASS refused a foreign staged image, spawned its own` | present, 3 boots in 3 |
| `SPAWN_OWNER_UNCHECKED=1` | `SPAWN_OWNER_SELFTEST: FAIL foreign-image-spawned pid 1` | present, 3 boots in 3 |

The self-test asserts **both** directions in one run: it forges the state a second task's arm
leaves behind (a legitimately staged image whose recorded owner is another task) and requires
the refusal, then re-arms honestly and requires the spawn to succeed. A gate that only checked
the refusal would pass on a kernel that refused every spawn — which is the failure mode a
fail-closed change is most likely to have.

---
