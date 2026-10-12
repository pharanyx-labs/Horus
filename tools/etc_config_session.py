#!/usr/bin/env python3
"""etc_config_session.py -- the /etc configuration files do what their manual
pages say, and refuse what they say they refuse (docs/design/configuration.md).

Driven through the real ring-3 shell over serial on a live boot:

  1. fs_server seeded /etc/shell.conf and /etc/login.conf from their module.
  2. `hostname = lab-1` in shell.conf is the prompt after the next login.
  3. `hostname = Evil!` is REFUSED with a message naming the line, and the
     prompt keeps the default. The character check is what stops a file from
     putting control bytes in front of everything a user types.
  4. `failure_delay = 2` in login.conf makes a wrong password wait two seconds,
     measured on the host's clock.
  5. `failure_delay = 31` is REFUSED, not rounded down to 30.

ETC_CONFIG_EXPECT_UNCHECKED=1 is for the control arm (CONF_VALUE_UNCHECKED=1):
there step 3 must show the defect, the prompt `root@Evil!#`, and the run passes
only if it does.

Usage:  tools/etc_config_session.py [horus.iso]
Exit:   0 and "ETC_CONFIG_SESSION: PASS" (or "CONTROL PASS"); 1 and a FAIL line.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail, _dump_serial  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))
UNCHECKED = os.environ.get("ETC_CONFIG_EXPECT_UNCHECKED") == "1"


def step(msg):
    print(f"ETC_CONFIG_SESSION: ok - {msg}", flush=True)


def run():
    s = Serial(ISO)

    def login(prompt):
        s.expect("login:", STEP)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect(prompt, STEP)

    def cmd(prompt, line, *waits):
        s.send(line)
        for w in waits:
            s.expect(w, STEP)
        s.expect(prompt, STEP)

    def rewrite(prompt, name, text):
        # The shell's echo writes from offset 0 and does not truncate, so the
        # old file goes first.
        cmd(prompt, f"rm {name}", "removed")
        cmd(prompt, f"echo {text} > {name}")

    try:
        s.expect("filesystem provisioned", BOOT)
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect("root@horus#", STEP)
        step("logged in with the default hostname")

        cmd("root@horus#", "ls /etc", "login.conf", "shell.conf")
        step("fs_server seeded /etc/shell.conf and /etc/login.conf")

        cmd("root@horus#", "cd /etc")
        rewrite("root@horus#", "shell.conf", "hostname = lab-1")
        s.send("logout")
        login("root@lab-1#")
        step("shell.conf hostname = lab-1 is the prompt after the next login")

        cmd("root@lab-1#", "cd /etc")
        rewrite("root@lab-1#", "shell.conf", "hostname = Evil!")
        s.send("logout")
        s.expect("login:", STEP)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        if UNCHECKED:
            s.expect("root@Evil!#", STEP)
            print("ETC_CONFIG_SESSION: CONTROL PASS - a hostname with a byte "
                  "outside a-z 0-9 - reached the prompt", flush=True)
            return 0
        s.expect("shell.conf: line 1: bad value for hostname", STEP)
        s.expect("root@horus#", STEP)
        step("hostname = Evil! is refused with the line named, and the default stands")

        # A wrong password with no delay first, as the baseline: the time from
        # sending it to "Login incorrect" includes the password check itself,
        # so the delay is measured as the DIFFERENCE between the two.
        def wrong_password_secs():
            s.expect("login:", STEP)
            s.send("root")
            s.expect("Password:", STEP)
            t0 = time.time()
            s.send("wrong-password")
            s.expect("Login incorrect", STEP)
            return time.time() - t0

        s.send("logout")
        base = wrong_password_secs()
        login("root@horus#")
        cmd("root@horus#", "cd /etc")
        rewrite("root@horus#", "login.conf", "failure_delay = 2")
        s.send("logout")
        delayed = wrong_password_secs()
        # THE BOUND IS 0.8 s, NOT 2 s, and on purpose: under QEMU's TCG
        # emulator the guest's monotonic clock runs at twice wall-clock speed
        # (10 guest seconds took 5.0 host seconds on 2026-10-11; LIMITATIONS
        # 2.27), so two guest seconds are about one host second. 0.8 s is
        # still far above "no pause at all", which is what a defect here
        # looks like (the baseline difference is a few hundredths).
        if delayed - base < 0.8:
            raise SessionFail(f"failure_delay = 2 added only {delayed - base:.2f}s "
                              f"({delayed:.2f}s against a baseline of {base:.2f}s)")
        step(f"failure_delay = 2 added {delayed - base:.1f}s to a wrong password "
             f"(baseline {base:.1f}s, host clock)")

        login("root@horus#")
        cmd("root@horus#", "cd /etc")
        rewrite("root@horus#", "login.conf", "failure_delay = 31")
        s.send("logout")
        s.expect("login.conf: line 1: bad value for failure_delay", STEP)
        s.expect("login:", STEP)
        step("failure_delay = 31 is refused, not rounded to 30")

        print("ETC_CONFIG_SESSION: PASS", flush=True)
        return 0
    except SessionFail as e:
        print(f"ETC_CONFIG_SESSION: FAIL - {e}", file=sys.stderr, flush=True)
        tail = s.buf[-1800:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        _dump_serial(getattr(s, "buf", ""))
        s.close()


if __name__ == "__main__":
    sys.exit(run())
