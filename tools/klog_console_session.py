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
              Alt+F1 closes it and the screen is what it was (outside the
              console's grid on a framebuffer, cleared: see residue), the view's
              header spans the whole display, and a login typed
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


GRID = re.compile(r"fb: console on the framebuffer, (\d+)x(\d+) cells, (\d+)x(\d+) "
                  r"font at (\d+)x, origin \((\d+),(\d+)\)")


def residue(before, after, grid):
    """Bytes by which the screen after the view differs from the one before it.

    Inside the console's grid every pixel counts. Outside it, a pixel that came
    back black does not: leaving the view repaints the whole display from the
    console's cells, so whatever the kernel drew there before the handover (a
    remnant of its progress panel) is cleared, and that is the point, it is
    stale text. A pixel outside the grid that is lit and different is something
    of the view's left behind, and counts. `grid` is (x0, y0, x1, y1) in pixels,
    or None on VGA text, where every pixel counts."""
    if grid is None or before[:2] != b"P6" or len(before) != len(after):
        return delta(before, after)
    w, _, off = ppm_offset(before)
    x0, y0, x1, y1 = grid
    n = 0
    for i in range(off, len(before) - 2, 3):
        p, q = before[i:i + 3], after[i:i + 3]
        if p == q:
            continue
        px = (i - off) // 3
        x, y = px % w, px // w
        if q == b"\x00\x00\x00" and not (x0 <= x < x1 and y0 <= y < y1):
            continue
        n += sum(1 for a, b in zip(p, q) if a != b)
    return n


def ppm_offset(data):
    """(width, height, offset of the first pixel) for a binary P6 screendump."""
    fields, i = [], 0
    while len(fields) < 4:               # magic, width, height, maxval
        while data[i:i + 1].isspace():
            i += 1
        j = i
        while not data[j:j + 1].isspace():
            j += 1
        fields.append(data[i:j])
        i = j
    if fields[0] != b"P6":
        raise SessionFail(f"screendump is {fields[0]!r}, not a P6 PPM")
    return int(fields[1]), int(fields[2]), i + 1   # one whitespace byte, then pixels


def ppm(data):
    """(width, height, pixel(x, y)) for a binary P6 screendump."""
    w, h, i = ppm_offset(data)
    return w, h, lambda x, y: data[i + 3 * (y * w + x):i + 3 * (y * w + x) + 3]


def header_reaches_edge(data):
    """Whether the view's header bar runs the full width of the display.

    The header is the view's top row, painted in its own colour from the first
    column to the last. The first version laid the view out on the console's
    80-column grid, so on a wider framebuffer the bar stopped part-way and the
    rest of the screen kept what the installer had drawn there (the
    maintainer's report, 2026-09-25). Row 2 of the bar is sampled at its left
    and right ends, where the header has only spaces."""
    w, h, px = ppm(data)
    left, right = px(1, 2), px(w - 2, 2)
    return left == right, w, h, left, right


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
            full, w, h, left, right = header_reaches_edge(s_view)
            if not full:
                raise SessionFail(f"the kernel log view does not cover the display: its "
                                  f"header is {left.hex()} at the left and {right.hex()} "
                                  f"at the right edge of a {w}x{h} screen")
            print(f"KLOG_CONSOLE: the view's header spans the whole {w}x{h} display",
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
            # The console's grid, from the kernel's own line about it; the last
            # one wins, as the console_server announces the layout it takes over.
            g_all = GRID.findall(g.buf)
            grid = None
            if g_all:
                cols, rows, cw, chh, sc, ox, oy = map(int, g_all[-1])
                grid = (ox, oy, ox + cols * cw * sc, oy + rows * chh * sc)
            restored = residue(s_idle, s_after, grid)
            if restored > tol:
                raise SessionFail(f"Alt+F1 left the screen {restored} bytes away from "
                                  f"the console it replaced (blink {blink}, tolerance {tol})")
            print(f"KLOG_CONSOLE: Alt+F1 put the console back ({restored} bytes off, "
                  f"{delta(s_idle, s_after)} counting pixels cleared to black; "
                  f"blink {blink})", flush=True)

            # ANY OTHER KEY IS IGNORED: it must neither close the view nor move
            # it. 'x' and Esc are the two a person is likeliest to try.
            chord(g, "alt", "f2")
            g.expect(OPENED, a.timeout)
            g._pump(1.5)
            s_open = shot(g, a.shots, "6-reopened.ppm")
            mark = len(g.buf)
            chord(g, "x")
            chord(g, "esc")
            g._pump(1.5)
            s_keys = shot(g, a.shots, "7-after-x-esc.ppm")
            if CLOSED in g.buf[mark:] or delta(s_open, s_keys) > tol:
                raise SessionFail("a key other than the five the view uses changed it")
            chord(g, "alt", "f1")
            g.expect(CLOSED, a.timeout)
            print("KLOG_CONSOLE: other keys are ignored in the view", flush=True)

            # MEDIA-KEY MODE: Alt+Volume Down opens and Alt+Mute closes, which is
            # what Alt+F2 and Alt+F1 send on a laptop whose F-row needs Fn.
            chord(g, "alt", "volumedown")
            g.expect(OPENED, a.timeout)
            chord(g, "alt", "audiomute")
            g.expect(CLOSED, a.timeout)
            print("KLOG_CONSOLE: Alt+VolumeDown / Alt+Mute work as Alt+F2 / Alt+F1", flush=True)

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
