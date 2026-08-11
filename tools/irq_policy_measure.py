#!/usr/bin/env python3
"""Measure the roadmap 1.1 interrupt-policy audit across a real shell session.

Roadmap 1.1 step 2b. This is the supported way to obtain the numbers finding
**[C-3.1]** is stated over, and it exists because the previous way was wrong in a
way nobody noticed for a day.

*What went wrong before.* The audit used to report itself, from the timer ISR,
straight at the UART — around the single-writer console rather than through it.
Its tick-41 report landed on the login prompt and split it:

    root@horus\\n[irq-policy] handshake-early @tick=41: accidental_sti=96 ...

so `root@horus#` never appeared contiguously, the harness driving the session
waited forever for a prompt that was never written whole, and the guest — which
was perfectly healthy — simply ran out of commands to execute. The counters then
stopped climbing, and the frozen totals were published as a measurement "across a
scripted shell session". They were the boot window of a session that never ran a
command. Interleaved against the ship kernel, the loud audit build failed the
session harness 10 boots in 10; the quiet one, 0 in 8.

*How this works instead.* The kernel writes nothing. `SYS_IRQ_POLICY_INFO` hands
the counters to userspace on request, and the shell's `irqpolicy` builtin prints
them through `console_server` like any other program — so there is never a second
writer to interleave with. Because the readout is on demand, it can be taken
*after* a representative workload rather than at a fixed tick, which is what makes
the totals session-scale.

Requires a build with IRQ_POLICY_AUDIT=1 (quiet is the default, and is what you
want here). `make measure-irq-policy` builds it and runs this.

Usage:  tools/irq_policy_measure.py boot.iso
Env:    BOOT_TIMEOUT (default 90), STEP_TIMEOUT (default 60)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import session_test as st  # noqa: E402  (path set above)

BOOT_TIMEOUT = int(os.environ.get("BOOT_TIMEOUT", "90"))
STEP_TIMEOUT = int(os.environ.get("STEP_TIMEOUT", "60"))
PROMPT = "root@horus#"

# A workload chosen to exercise the paths the audit is about, not to look busy.
# The two dominant sites (cap_install_object, cap_consume_slot) are on the IPC
# path: every one of these commands is at least one console_server round trip,
# and the fs commands add fs_server round trips on top. Anything that does not
# cross an endpoint contributes nothing and is not worth the wall clock.
WORKLOAD = [
    "ls /bin",
    "ls -l /",
    "cat /etc/motd",
    "man ls",
    "whatis stat",
    "apropos directory",
    "cd /tmp",
    "pwd",
    "echo measured > f1",
    "cp f1 f2",
    "wc f2",
    "stat f2",
    "cd /",
    "ps",
]


def main():
    if len(sys.argv) < 2:
        print("usage: irq_policy_measure.py <boot.iso>", file=sys.stderr)
        sys.exit(2)

    s = st.Serial(sys.argv[1])
    try:
        s.expect("horus login:", BOOT_TIMEOUT)
        s.send("root")
        s.expect("Password:", STEP_TIMEOUT)
        s.send("rootpass")
        s.expect(PROMPT, STEP_TIMEOUT)

        for cmd in WORKLOAD:
            s.send(cmd)
            s.expect(PROMPT, STEP_TIMEOUT)

        s.send("irqpolicy")
        s.expect("irq-policy: end", STEP_TIMEOUT)
        # Consume the prompt that follows, so the integrity count below covers
        # the readout command itself rather than being one short of its own
        # expectation.
        s.expect(PROMPT, STEP_TIMEOUT)

        report = s.buf[s.buf.rindex("irq-policy: accidental"):]
        lines = [ln.strip() for ln in report.splitlines() if "irq-policy:" in ln]

        print("workload: %d commands, all through console_server" % len(WORKLOAD))
        for ln in lines:
            print(ln)

        # The prompt was written whole every time, which is the property the old
        # instrument destroyed. Assert it rather than assume it: a run that
        # measured a corrupted session is exactly the failure being corrected.
        seen = s.buf.count(PROMPT)
        expected = len(WORKLOAD) + 2          # login + each command + irqpolicy
        print("prompt integrity: %d contiguous %r (expected >= %d)"
              % (seen, PROMPT, expected))
        if seen < expected:
            print("IRQ_POLICY_MEASURE: FAIL prompt was split — the readout is "
                  "not trustworthy on this run", file=sys.stderr)
            sys.exit(1)
        if not any("accidental_sti=" in ln for ln in lines):
            print("IRQ_POLICY_MEASURE: FAIL no counters returned — is this an "
                  "IRQ_POLICY_AUDIT build?", file=sys.stderr)
            sys.exit(1)
        print("IRQ_POLICY_MEASURE: PASS")
    except st.SessionFail as e:
        print("IRQ_POLICY_MEASURE: FAIL — %s" % e, file=sys.stderr)
        sys.exit(1)
    finally:
        s.close()


if __name__ == "__main__":
    main()
