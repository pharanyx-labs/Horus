#!/usr/bin/env python3
"""shellwatch_session.py -- init hears of the shell's death through the watcher,
and the watcher can only wait (docs/design/filesystem.md, decision 19).

On a SHELLWATCH_PROBE build: init checks, through CAP_DEBUG, that the watcher's
capability to the shell carries READ and not WRITE, and says which. Then the
shell is ended twice with the probe command `shellwatch-die`; each time init
must report the exit with its cause and bring up a login prompt that works, so
the watcher, the endpoint and the slots init revokes all survive a relaunch.

SHELLWATCH_EXPECT_FULL=1 is for the control arm (INIT_WATCH_TCB_FULL=1): the
probe must then report that the watcher can do more than wait.

Exit: 0 and "SHELLWATCH_SESSION: PASS" (or "CONTROL PASS"); 1 and a FAIL line.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail, _dump_serial  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))
FULL = os.environ.get("SHELLWATCH_EXPECT_FULL") == "1"


def step(msg):
    print(f"SHELLWATCH_SESSION: ok - {msg}", flush=True)


def run():
    s = Serial(ISO)
    try:
        if FULL:
            s.expect("SHELLWATCH_PROBE: FAIL the watcher can do more than wait on the shell", BOOT)
            print("SHELLWATCH_SESSION: CONTROL PASS - the watcher was given WRITE on the shell",
                  flush=True)
            return 0
        s.expect("SHELLWATCH_PROBE: the watcher holds the shell READ-only", BOOT)
        if "SHELLWATCH_PROBE: FAIL" in s.buf:
            raise SessionFail("the watcher holds more than READ on the shell")
        step("the watcher holds the shell READ-only")

        for n in (1, 2):
            s.expect("horus login:", BOOT)
            s.send("root")
            s.expect("Password:", STEP)
            s.send("toor")
            s.expect("root@horus#", STEP)
            s.send("shellwatch-die")
            s.expect("init: shell exited:", STEP)
            s.expect("relaunching", STEP)
            step(f"shell ended ({n}); init heard it through the watcher and relaunched")
            if n == 1:
                s.expect("SHELLWATCH_PROBE: the watcher holds the shell READ-only", STEP)
                step("the relaunched shell's watcher holds it READ-only too")
        s.expect("horus login:", STEP)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect("root@horus#", STEP)
        step("a login works after two relaunches")
        if "init: FATAL" in s.buf:
            raise SessionFail("init reported a fatal error")
        print("SHELLWATCH_SESSION: PASS", flush=True)
        return 0
    except SessionFail as e:
        print(f"SHELLWATCH_SESSION: FAIL - {e}", file=sys.stderr, flush=True)
        tail = s.buf[-1800:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        _dump_serial(getattr(s, "buf", ""))
        s.close()


if __name__ == "__main__":
    sys.exit(run())
