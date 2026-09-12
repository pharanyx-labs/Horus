#!/usr/bin/env python3
"""A full screen must SCROLL, not restart at the top.

WHAT WAS WRONG. Both of console_server's putc paths ended a full screen with
`pos = 0`, so the next line landed on top of the OLDEST one: the display became a
ring buffer with nothing marking the seam, its bottom half older than its top
half. The kernel's emit_char has called scroll_screen at that point since it was
written, and the ring-3 console that took the hardware over did not inherit it.
On a machine with no serial port that is why a boot log cannot be read back --
the lines are not merely gone off the top, they have been overwritten in place,
and there is no second copy anywhere.

HOW IT IS OBSERVED, and why the obvious version of this test measures nothing.
Input is driven over SERIAL, which is fast and reliable; only the assertion is on
pixels. The first attempt filled the screen by pressing Enter at the login prompt
and then asked whether one more line changed the screen: it did not, on either
build, because every line was the identical `horus login:` and SCROLLING UNIFORM
CONTENT PRODUCES AN IDENTICAL IMAGE. The second attempt used one `dmesg`, whose
~49 lines against a 50-row screen leave the top of the display still blank, so a
shift moved almost nothing: fixed and arm both answered 594. Three `dmesg` runs
fill the screen densely with DISTINCT lines, and then one more line is decisive
because scrolling moves every glyph on the screen.

  scroll   the whole screen shifts up      -> 85161 bytes change (measured)
  wrap     one line changes mid-screen     ->   681 bytes change (measured)

THE ARM'S EXPECTED RESULT IS A SMALL NUMBER, WHICH IS ALSO WHAT A DEAD BOOT
GIVES. That is the trap in this gate and the reason for the three positive
checks below: the login must be reached, the shell must be reached, and the
screen must actually be dense with text before any delta is believed. Without
them the control arm would pass whenever the guest failed to boot at all, which
is a gate that cannot fail.

  smoke-console-scroll          the gate
  smoke-console-scroll-control  CONSOLE_NO_SCROLL=1, which must NOT scroll
"""
import argparse, json, os, socket, subprocess, sys, time

# Measured 2026-09-12: 85161 scrolling, 681 wrapping. The threshold sits two
# orders of magnitude from the wrap case and a quarter of the scroll case.
SCROLL_MIN = 20000
# A full screen of text is 62k-86k non-zero bytes; a blank or barely-started one
# is near zero. This rejects "the guest never got there" before any conclusion.
DENSITY_MIN = 30000
DMESG_RUNS = 3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--boot-timeout", type=int, default=60)
    ap.add_argument("--expect-no-scroll", action="store_true")
    ap.add_argument("--shots", default="/tmp/horus-scroll-evidence")
    a = ap.parse_args()

    os.makedirs(a.shots, exist_ok=True)
    qs = os.path.join(a.shots, "qmp.sock")
    ss = os.path.join(a.shots, "serial.sock")
    for x in (qs, ss):
        if os.path.exists(x):
            os.unlink(x)

    qsrv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    qsrv.bind(qs)
    qsrv.listen(1)

    qemu = subprocess.Popen(
        ["qemu-system-x86_64", "-m", "512M", "-machine", "q35", "-smp", "2",
         "-display", "none", "-qmp", f"unix:{qs}", "-net", "none",
         "-no-reboot", "-no-shutdown",
         "-serial", f"unix:{ss},server=on,wait=off", "-cdrom", a.iso],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    qsrv.settimeout(a.boot_timeout)
    try:
        qc, _ = qsrv.accept()
    except socket.timeout:
        qemu.kill()
        print("CONSOLE_SCROLL: FAIL QEMU never opened the QMP socket")
        return 1
    f = qc.makefile("rw")

    def qmp(**kw):
        f.write(json.dumps(kw) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if not line:
                return None
            m = json.loads(line)
            if "return" in m or "error" in m:
                return m

    f.readline()
    qmp(execute="qmp_capabilities")

    sc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(60):
        try:
            sc.connect(ss)
            break
        except OSError:
            time.sleep(0.5)
    sc.settimeout(0.5)

    log = {"buf": b""}

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                d = sc.recv(65536)
            except Exception:
                d = b""
            if d:
                log["buf"] += d
            else:
                time.sleep(0.05)

    def wait(token, timeout):
        end = time.time() + timeout
        while time.time() < end:
            pump(0.4)
            if token in log["buf"].decode("utf8", "replace"):
                return True
        return False

    def shot(name):
        path = os.path.join(a.shots, name)
        if os.path.exists(path):
            os.unlink(path)
        qmp(execute="screendump", arguments={"filename": path})
        time.sleep(1.5)
        return open(path, "rb").read() if os.path.exists(path) else b""

    def fail(msg):
        with open(os.path.join(a.shots, "serial.log"), "wb") as fh:
            fh.write(log["buf"])
        qemu.kill()
        qemu.wait()
        print(f"CONSOLE_SCROLL: FAIL {msg} (evidence in {a.shots})")
        return 1

    # --- the three positive checks, before any pixel is believed -------------
    if not wait("horus login:", a.boot_timeout):
        return fail("the guest never reached a login prompt")
    sc.sendall(b"root\n")
    if not wait("Password:", 30):
        return fail("no password prompt after the user name")
    sc.sendall(b"rootpass\n")
    if not wait("#", 30):
        return fail("the login did not reach a shell")

    log["buf"] = b""
    for _ in range(DMESG_RUNS):
        sc.sendall(b"dmesg\n")
        pump(7)
    if len(log["buf"]) < 2000:
        return fail("dmesg produced almost nothing, so the screen was never filled")

    before = shot("1-filled.ppm")
    sc.sendall(b"\n")
    time.sleep(2)
    after = shot("2-one-more-line.ppm")

    if not before or not after:
        return fail("no screendump")

    density = sum(1 for b in before if b)
    if density < DENSITY_MIN:
        return fail(f"the screen is not full of text (density {density} < {DENSITY_MIN}), "
                    f"so nothing can be concluded about scrolling")

    delta = sum(1 for x, y in zip(before, after) if x != y)
    scrolled = delta >= SCROLL_MIN
    verdict = f"density={density} one-more-line delta={delta}"

    with open(os.path.join(a.shots, "serial.log"), "wb") as fh:
        fh.write(log["buf"])
    qemu.kill()
    qemu.wait()

    if a.expect_no_scroll:
        if scrolled:
            print(f"CONSOLE_SCROLL: FAIL the arm scrolled; CONSOLE_NO_SCROLL did not "
                  f"reproduce the defect ({verdict})")
            return 1
        print(f"CONSOLE_SCROLL: PASS the arm wraps to the top, as it must ({verdict})")
        return 0

    if not scrolled:
        print(f"CONSOLE_SCROLL: FAIL a full screen did not scroll -- the newest line is "
              f"overwriting the oldest ({verdict}, evidence in {a.shots})")
        return 1
    print(f"CONSOLE_SCROLL: PASS a full screen scrolls ({verdict})")
    # Only a passing run may clear its evidence.
    for n in ("1-filled.ppm", "2-one-more-line.ppm", "serial.log"):
        try:
            os.unlink(os.path.join(a.shots, n))
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
