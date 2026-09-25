#!/usr/bin/env python3
"""seal_session.py -- SYS_MEM_SEAL makes a page read-only for good, and reaches
only the caller's own image (docs/design/shared-libc.md §9, step 2).

Boots a MEM_SEAL_MODULES=1 build, logs in through the REAL shell over serial,
and runs /bin/sealprobe twice:

  1. `sealprobe data`: a page of its own .data, written, sealed, written again.
     The second write must fault, and the probe's fault handler says so.
  2. `sealprobe heap`: a heap page it owns is outside the image, so the seal
     must be refused.

Each failure names the property, in words the control arms grep for:

  "a sealed page took a write"          (MEM_SEAL_KEEPS_WRITE)
  "a page outside the image was sealed" (MEM_SEAL_ANY_ADDRESS)

Usage:  tools/seal_session.py [horus.iso]
Exit:   0 and "SEAL_SESSION: PASS"; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "90"))
PROMPT = "root@horus#"


def step(msg):
    print(f"SEAL_SESSION: ok - {msg}")


def run_cmd(s, cmd):
    start = len(s.buf)
    s.send(cmd)
    s.expect(PROMPT, STEP)
    return s.buf[start:s.pos]


def run():
    s = Serial(ISO)
    try:
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect(PROMPT, STEP)
        step("logged in")

        out = run_cmd(s, "sealprobe data")
        if "SEALPROBE: FAIL the sealed page took a write" in out:
            raise SessionFail("a sealed page took a write: " + out.strip())
        if "SEALPROBE: the sealed page refused the write" not in out:
            raise SessionFail("sealprobe data did not report the fault:\n" + out.strip())
        step("a sealed page of the program's own .data refuses a write")

        out = run_cmd(s, "sealprobe heap")
        if "SEALPROBE: FAIL a page outside the image was sealed" in out:
            raise SessionFail("a page outside the image was sealed: " + out.strip())
        if "SEALPROBE: a heap page, outside the image, was refused" not in out:
            raise SessionFail("sealprobe heap did not report:\n" + out.strip())
        step("a page outside the program's image cannot be sealed")

        print("SEAL_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"SEAL_SESSION: FAIL {e}", file=sys.stderr)
        print("---- serial tail ----\n" + s.buf[-1500:], file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
