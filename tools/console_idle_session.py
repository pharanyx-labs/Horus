#!/usr/bin/env python3
"""A console waiting at a prompt sleeps, and still answers both of its inputs.

WHAT IT GUARDS. Until 2026-09-25 console_server waited for a key with a loop of
sys_yield. A console at a prompt waits nearly all the time, so the machine kept
a core busy doing nothing: under QEMU the guest held one host core at 100% at
the login prompt, and on a two-core laptop the kernel counted about 70,000
yields a second. Now the server blocks on a notification that IRQ 1 (the
keyboard) and IRQ 0 (the tick) signal (con_idle in userspace/console_server.c).

THREE CHECKS, IN ORDER.

  1. The server says it waits: `[console_server] input: waits on IRQ 1 and the
     tick` on the wire. A build that fell back to polling says `polled`.
  2. It really is idle: with the guest at the login prompt and nothing typed,
     QEMU's own CPU time over IDLE_SECONDS must stay under IDLE_LIMIT percent of
     one host core. The measurement is the host's, from /proc, so it cannot be
     satisfied by the guest saying so. A spinning console keeps QEMU's vCPU
     thread at about 100% and a waiting one lets the guest halt; both numbers
     are printed, so a drift towards the limit is visible before it fails.
  3. Both inputs still wake it. The login is typed on the machine's keyboard
     (QMP send-key, which only IRQ 1 or the tick can deliver), and a command is
     then typed on COM1, whose line is not routed to the server, so only the
     tick can make it look. A server that slept and never woke would pass (2)
     and fail here.

The control arm, CONSOLE_INPUT_SPIN=1, is the server before the change and must
fail on exactly `the console kept a core busy at an idle prompt`.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail   # noqa: E402

WAITS = "[console_server] input: waits on IRQ 1 and the tick"
POLLED = "[console_server] input: polled"
IDLE_SECONDS = 10.0
# Measured 2026-09-25 under TCG: 7.2% waiting, 100.0% spinning. The limit sits
# far from both, so a busy CI host neither fails the gate nor passes the arm.
IDLE_LIMIT = 40.0


def qemu_cpu_seconds(pid):
    """User plus system CPU time of the QEMU process, in seconds."""
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iso", default="horus.iso")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="toor")
    ap.add_argument("--boot-timeout", type=float, default=240.0)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--serial-log", default=None)
    a = ap.parse_args()

    g = Serial(a.iso)
    rc = 1
    try:
        g.expect("horus login: ", a.boot_timeout)
        if POLLED in g.buf:
            line = g.buf[g.buf.index(POLLED):].splitlines()[0]
            print(f"CONSOLE_IDLE: the server polls: {line!r}", flush=True)
        elif WAITS in g.buf:
            print("CONSOLE_IDLE: the server waits on IRQ 1 and the tick", flush=True)
        else:
            raise SessionFail("console_server did not say how it waits for input")

        # Let the boot's own work finish before measuring what idling costs.
        g._pump(3.0)
        pid = g.proc.pid
        c0, t0 = qemu_cpu_seconds(pid), time.monotonic()
        g._pump(IDLE_SECONDS)
        c1, t1 = qemu_cpu_seconds(pid), time.monotonic()
        busy = 100.0 * (c1 - c0) / (t1 - t0)
        if busy >= IDLE_LIMIT:
            raise SessionFail(f"the console kept a core busy at an idle prompt: QEMU "
                              f"used {busy:.1f}% of a host core over {t1 - t0:.1f}s "
                              f"(limit {IDLE_LIMIT:.0f}%)")
        print(f"CONSOLE_IDLE: idle at the prompt costs {busy:.1f}% of a host core "
              f"over {t1 - t0:.1f}s (limit {IDLE_LIMIT:.0f}%)", flush=True)

        # The keyboard: only IRQ 1 or the tick can deliver these.
        g.send_key_text(a.user + "\n", 0.15)
        g.expect("assword", a.timeout)
        g.send_key_text(a.password + "\n", 0.15)
        g.expect("@horus", a.timeout)
        print("CONSOLE_IDLE: a login typed on the keyboard was read", flush=True)

        # COM1: its line is not routed to the server, so only the tick wakes it.
        g.send("echo idle-wakes-on-serial")
        g.expect("idle-wakes-on-serial", a.timeout)     # the line, echoed as typed
        g.expect("idle-wakes-on-serial", a.timeout)     # and the command's output
        g.expect("@horus", a.timeout)
        print("CONSOLE_IDLE: PASS, and a command typed on COM1 was read too", flush=True)
        rc = 0
    except SessionFail as e:
        print(f"CONSOLE_IDLE: FAIL {e}", flush=True)
        rc = 1
    finally:
        if a.serial_log:
            try:
                with open(a.serial_log, "a") as f:
                    f.write(g.buf)
            except OSError as e:
                print(f"CONSOLE_IDLE: could not write serial log: {e}", flush=True)
        g.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
