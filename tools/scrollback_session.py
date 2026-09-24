#!/usr/bin/env python3
"""Shift+PgUp shows what scrolled off the console, and the console comes back.

WHAT IS CLAIMED. A line that scrolls off the top of the machine's own screen is
kept, Shift+PgUp and Shift+PgDn page through it, and leaving it loses nothing:
Shift+PgDn back to the bottom restores the live screen, and a key typed or
output printed while scrolled back goes to the live screen and is seen there.
On a machine with no serial port the screen is the only copy of the boot log,
so without this the lines that scroll past are simply gone.

HOW. Log in over serial and run dmesg four times, so there is history.
Then, on the emulated 8042 over QMP send-key: Shift+PgUp must change the screen
far beyond the cursor's blink (measured in the run, as in
tools/backspace_session.py), a second Shift+PgUp must change it again, two
Shift+PgDn must put it back to within the blink, and a command typed on the
keyboard while scrolled back must run (its output on the wire) with the screen
back to live. Output arriving while scrolled back must bring the screen back
too. Every screendump is kept.

  smoke-console-scrollback          the gate
  smoke-console-scrollback-control  CONSOLE_NO_SCROLLBACK=1, which must fail on
                                    "Shift+PgUp showed no history"
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail   # noqa: E402


def chord(g, *keys):
    if g.qmp("send-key", keys=[{"type": "qcode", "data": k} for k in keys]) is None:
        raise SessionFail(f"QMP send-key failed for {keys!r}")
    g._pump(1.0)


def shot(g, shots, name):
    path = os.path.join(shots, name)
    if os.path.exists(path):
        os.unlink(path)
    g.qmp("screendump", filename=path)
    for _ in range(30):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            time.sleep(0.3)
            break
        time.sleep(0.1)
    if not os.path.exists(path):
        raise SessionFail(f"no screendump at {path}")
    return open(path, "rb").read()


def delta(a, b):
    return sum(1 for p, q in zip(a, b) if p != q) + abs(len(a) - len(b))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iso", default="horus.iso")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="toor")
    ap.add_argument("--boot-timeout", type=float, default=240.0)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--shots", default=os.environ.get("SCROLLBACK_SHOTS", "/tmp/horus-scrollback"))
    ap.add_argument("--serial-log", default=None)
    a = ap.parse_args()
    os.makedirs(a.shots, exist_ok=True)

    g = Serial(a.iso)
    rc = 1
    try:
        g.expect("horus login: ", a.boot_timeout)
        g.send(a.user)
        g.expect("assword", a.timeout)
        g.send(a.password)
        g.expect("@horus", a.timeout)
        # HISTORY FROM COMMANDS THIS IMAGE HAS. The first version ran `seq 1 300`,
        # which a default image does not carry: the shell said "Unknown command",
        # expect("300") matched the echo of the command line itself, and the gate
        # went red on "a second Shift+PgUp did not page further back" because
        # there were only ~50 lines of history to page through. dmesg is here for
        # root on every build, so four of them are well over two screens.
        for _ in range(4):
            mark = len(g.buf)
            g.send("dmesg")
            g.expect("@horus", a.timeout)
            if "Unknown command" in g.buf[mark:]:
                raise SessionFail("dmesg is not a command in this image; no history to test")
        g._pump(2.0)

        s0 = shot(g, a.shots, "1-live.ppm")
        g._pump(4.0)
        s_idle = shot(g, a.shots, "2-idle.ppm")
        blink = delta(s0, s_idle)
        tol = max(4 * blink, 4096)

        chord(g, "shift", "pgup")
        s_up1 = shot(g, a.shots, "3-shift-pgup.ppm")
        moved = delta(s_idle, s_up1)
        if moved <= tol:
            raise SessionFail(f"Shift+PgUp showed no history: the screen moved {moved} "
                              f"bytes against a blink of {blink} (tolerance {tol})")
        print(f"SCROLLBACK: Shift+PgUp showed history ({moved} bytes)", flush=True)

        chord(g, "shift", "pgup")
        s_up2 = shot(g, a.shots, "4-shift-pgup-again.ppm")
        if delta(s_up1, s_up2) <= tol:
            raise SessionFail("a second Shift+PgUp did not page further back")
        print("SCROLLBACK: a second Shift+PgUp paged further back", flush=True)

        chord(g, "shift", "pgdn")
        chord(g, "shift", "pgdn")
        s_back = shot(g, a.shots, "5-shift-pgdn-twice.ppm")
        off = delta(s_idle, s_back)
        if off > tol:
            raise SessionFail(f"two Shift+PgDn left the screen {off} bytes from the live "
                              f"console (blink {blink}, tolerance {tol})")
        print(f"SCROLLBACK: two Shift+PgDn restored the live screen ({off} bytes off)",
              flush=True)

        # A key typed while scrolled back goes to the live console and is seen.
        chord(g, "shift", "pgup")
        s_up = shot(g, a.shots, "6-scrolled-again.ppm")
        mark = len(g.buf)
        g.send_key_text("echo KEYSNAP\n", 0.15)
        g.expect("KEYSNAP", a.timeout)
        g.expect("@horus", a.timeout)
        g._pump(1.0)
        s_key = shot(g, a.shots, "7-after-typing.ppm")
        if delta(s_up, s_key) <= tol:
            raise SessionFail("typing while scrolled back left the old view on screen")
        print("SCROLLBACK: a key typed while scrolled back went to the live screen",
              flush=True)

        # Output arriving while scrolled back brings the live screen back too.
        chord(g, "shift", "pgup")
        s_up = shot(g, a.shots, "8-scrolled-for-output.ppm")
        g.send("echo OUTSNAP")
        g.expect("OUTSNAP", a.timeout)
        g.expect("@horus", a.timeout)
        g._pump(1.0)
        s_out = shot(g, a.shots, "9-after-output.ppm")
        if delta(s_up, s_out) <= tol:
            raise SessionFail("output while scrolled back did not return to the live screen")
        print("SCROLLBACK: PASS, and output while scrolled back returns to live", flush=True)
        rc = 0
    except SessionFail as e:
        print(f"SCROLLBACK: FAIL {e}", flush=True)
        rc = 1
    finally:
        if a.serial_log:
            try:
                with open(a.serial_log, "a") as f:
                    f.write(g.buf)
            except OSError as e:
                print(f"SCROLLBACK: could not write serial log: {e}", flush=True)
        g.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
