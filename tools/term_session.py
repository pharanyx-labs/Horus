#!/usr/bin/env python3
"""term_session.py — prove the console raw-terminal layer end to end.

Boots a TERM_MODULE=1 build, logs in through the real ring-3 shell, runs
/bin/termtest, and drives the full-screen path: termtest queries the window size
(cooked), switches to raw mode, emits an ANSI clear+prompt, and blocks reading one
un-echoed key. We send exactly one raw byte ('A' = 0x41) and assert termtest read
it and reports PASS — exercising CON_OP_WINSZ, CON_OP_WRITE_RAW, CON_OP_READ_RAW,
and tcsetattr raw/cooked switching.

Usage:  tools/term_session.py [boot.iso]
Exit:   0 and "TERM_SESSION: PASS" on success; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "90"))


def step(msg):
    print(f"TERM_SESSION: ok - {msg}")


def run():
    s = Serial(ISO)
    PROMPT = "root@horus#"
    try:
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("rootpass")
        s.expect(PROMPT, STEP)
        step("logged in")

        # Run the raw-terminal probe from /bin (resolved + loaded via the shell).
        s.send("termtest")

        # 1. Geometry via ioctl(TIOCGWINSZ) -> CON_OP_WINSZ (in cooked mode).
        s.expect("size 80x24", STEP)
        step("ioctl(TIOCGWINSZ) reported the console geometry")

        # 2. Raw mode entered; the ANSI clear + prompt reached the terminal
        #    verbatim (CON_OP_WRITE_RAW). termtest is now blocked in read().
        s.expect("raw mode; press a key", STEP)
        step("raw mode + escape output reached the terminal")

        # 3. Send exactly one raw byte (no newline) — CON_OP_READ_RAW returns it
        #    un-echoed. 'A' = 0x41, a value absent from the command line.
        os.write(s.fd, b"A")
        s.expect("key=0x41", STEP)
        step("raw read returned the un-echoed key byte")

        s.expect("TERMRAW_SELFTEST: PASS", STEP)
        s.expect(PROMPT, STEP)
        step("cooked mode restored; probe reported PASS")

        print("TERM_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"TERM_SESSION: FAIL - {e}", file=sys.stderr)
        tail = s.buf[-1500:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
