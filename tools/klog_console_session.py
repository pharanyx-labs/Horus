#!/usr/bin/env python3
"""The Alt+F2 kernel log console: present where it is built, absent where it is not.

WHAT IT IS. A KLOG_CONSOLE=1 build lets Alt+F2 show the kernel log on the
machine's own screen with nobody logged in, and Alt+F1 put the console back
(klog_view in userspace/console_server.c). It exists for a laptop whose install
failed on the one boot where no account had a password, so `dmesg` could not be
reached and the evidence sat in a ring nobody could read.

TWO DIRECTIONS, AND THE ABSENT ONE IS THE SECURITY CLAIM. Reading the kernel log
without a login is authority for standing at the keyboard. That is acceptable in
an instrument that announces itself in DEFECT FLAGS and is never shipped; it
would be a defect in a shipped image. So:

  --present   (KLOG_CONSOLE=1)  Alt+F2 opens the view, Shift+PgUp scrolls it,
              Alt+F1 closes it and the screen is what it was, and a login typed
              afterwards on the keyboard succeeds, so the keys went back.
  --absent    (a ship build)    Alt+F2 does nothing: no marker on the wire and
              the screen unchanged beyond the cursor's blink, and the login
              that follows still works.

The control arm runs --absent against a KLOG_CONSOLE=1 build and must fail,
which is what proves --absent can see the view when it is there.

SCREENDUMPS ARE THE SCREEN'S EVIDENCE, WITH AN IDLE CONTROL. The view draws to
the display and not to the serial line, so "the screen changed" and "the screen
came back" are read off QMP screendumps. The cursor blinks, so two dumps of an
idle screen already differ by a little; that difference is measured in the run
and is the tolerance, as in tools/backspace_session.py. Every dump is kept.
"""
import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail   # noqa: E402

OPENED = "KLOG_CONSOLE: showing the kernel log"
CLOSED = "KLOG_CONSOLE: back to the console"


def chord(g, *keys):
    """Press several keys together (a modifier and a key), as a person does."""
    if g.qmp("send-key", keys=[{"type": "qcode", "data": k} for k in keys]) is None:
        raise SessionFail(f"QMP send-key failed for {keys!r}")
    time.sleep(0.5)


def shot(g, shots, name):
    path = os.path.join(shots, name)
    if os.path.exists(path):
        os.unlink(path)
    g.qmp("screendump", filename=path)
    for _ in range(30):                  # the dump is written asynchronously
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
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--present", action="store_true")
    mode.add_argument("--absent", action="store_true")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="toor")
    ap.add_argument("--boot-timeout", type=float, default=240.0)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--shots", default="/tmp/horus-klog-console")
    ap.add_argument("--serial-log", default=None)
    a = ap.parse_args()
    os.makedirs(a.shots, exist_ok=True)

    g = Serial(a.iso)
    rc = 1
    try:
        g.expect("horus login: ", a.boot_timeout)
        time.sleep(2)
        s0 = shot(g, a.shots, "1-prompt.ppm")
        time.sleep(4)
        s_idle = shot(g, a.shots, "2-idle.ppm")
        blink = delta(s0, s_idle)
        # The tolerance: what the screen does on its own, with room for a blink
        # that lands between the dumps differently. A view that is really there
        # rewrites the whole grid and is orders of magnitude past this.
        tol = max(4 * blink, 4096)

        mark = len(g.buf)
        chord(g, "alt", "f2")
        # PUMP, not sleep: Serial.buf only grows while something reads the line,
        # so a marker the guest wrote during a sleep is not in it yet. The first
        # version of this harness slept here and reported a view that had opened
        # (the screen moved 86,641 bytes) as one that had not.
        g._pump(3.0)
        s_view = shot(g, a.shots, "3-after-alt-f2.ppm")
        opened_wire = OPENED in g.buf[mark:]
        changed = delta(s_idle, s_view)

        if a.absent:
            if opened_wire or changed > tol:
                raise SessionFail(
                    "Alt+F2 did something in a build without KLOG_CONSOLE: "
                    f"marker on the wire={opened_wire}, screen changed by {changed} "
                    f"bytes against a blink of {blink} (tolerance {tol}). The kernel "
                    "log must not be readable without a login in a shipped image.")
            print(f"KLOG_CONSOLE: absent, as required (screen moved {changed} "
                  f"bytes, blink {blink})", flush=True)
        else:
            if not opened_wire:
                raise SessionFail("Alt+F2 did not open the kernel log view "
                                  f"(no {OPENED!r} on the wire)")
            if changed <= tol:
                raise SessionFail(f"Alt+F2 reported the view open but the screen moved "
                                  f"only {changed} bytes (blink {blink}, tolerance {tol})")
            print(f"KLOG_CONSOLE: Alt+F2 opened the view (screen moved {changed} bytes)",
                  flush=True)

            # Whether there is anything to scroll is the guest's to say: the marker
            # carries the log's height and the screen's. A log that fits must NOT
            # move (a view that scrolls into blank rows is wrong too), and one that
            # does not fit must.
            m = re.search(r"\((\d+) rows, (\d+) on screen\)", g.buf[mark:])
            if not m:
                raise SessionFail("the open marker did not say how tall the log is")
            total, room = int(m.group(1)), int(m.group(2))
            chord(g, "shift", "pgup")
            g._pump(1.5)
            s_back = shot(g, a.shots, "4-after-shift-pgup.ppm")
            scrolled = delta(s_view, s_back)
            if total > room:
                if scrolled <= tol:
                    raise SessionFail(f"Shift+PgUp did not move a {total}-row log on a "
                                      f"{room}-row screen ({scrolled} bytes)")
                print(f"KLOG_CONSOLE: Shift+PgUp scrolled a {total}-row log on a "
                      f"{room}-row screen ({scrolled} bytes)", flush=True)
            else:
                if scrolled > tol:
                    raise SessionFail(f"Shift+PgUp moved a {total}-row log that fits a "
                                      f"{room}-row screen ({scrolled} bytes)")
                print(f"KLOG_CONSOLE: the {total}-row log fits the {room}-row screen, and "
                      f"Shift+PgUp left it still (scrolling itself NOT exercised)",
                      flush=True)

            mark = len(g.buf)
            chord(g, "alt", "f1")
            g.expect(CLOSED, a.timeout)
            time.sleep(1.5)
            s_after = shot(g, a.shots, "5-after-alt-f1.ppm")
            restored = delta(s_idle, s_after)
            if restored > tol:
                raise SessionFail(f"Alt+F1 left the screen {restored} bytes away from "
                                  f"the console it replaced (blink {blink}, tolerance {tol})")
            print(f"KLOG_CONSOLE: Alt+F1 put the console back ({restored} bytes off, "
                  f"blink {blink})", flush=True)

        # Either way the keys must still reach the console: a view that ate the
        # keyboard, or an absent one that did, is a machine nobody can log into.
        g.send_key_text(a.user + "\n", 0.15)
        g.expect("assword", a.timeout)
        g.send_key_text(a.password + "\n", 0.15)
        g.expect("@horus", a.timeout)
        print("KLOG_CONSOLE: PASS, and the keyboard logs in afterwards", flush=True)
        rc = 0
    except SessionFail as e:
        print(f"KLOG_CONSOLE: FAIL {e}", flush=True)
        rc = 1
    finally:
        if a.serial_log:
            try:
                with open(a.serial_log, "a") as f:
                    f.write(g.buf)
            except OSError as e:
                print(f"KLOG_CONSOLE: could not write serial log: {e}", flush=True)
        g.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
