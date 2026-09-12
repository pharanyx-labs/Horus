#!/usr/bin/env python3
"""Backspace must ERASE ON THE SCREEN, not just shorten the line buffer.

WHY NO EXISTING GATE COVERS IT. Every session test types at COM1, and a terminal
on the far end of a UART interprets 0x08 itself -- so the erase looked correct on
every one of them while `console_server` was drawing the 0x08 as a glyph. Neither
fb_putc nor vga_putc had a case for it, so con_getline's "\\b \\b" painted three
cells of rubbish and advanced three columns. The line buffer was always right;
only the screen lied, which is the worst shape for a masked password field, and
the reason this is gated on PIXELS rather than on the bytes the guest accepted.

THE ASSERTION IS A ROUND TRIP: type N characters, then backspace N times, and
require the screen to come back to where it started. That is stronger than
looking for an absence of rubbish -- it fails both if the erase draws something
and if the erase does not move the cursor -- and it needs no OCR.

  typed-vs-prompt   must be LARGE   (the characters really were echoed)
  erased-vs-prompt  must be SMALL   (the screen returned to the prompt)

Both are measured against the same idle control the no-serial gate uses, because
the cursor blinks and a bare before/after diff attributes the blink to the keys.

  smoke-console-backspace          the gate
  smoke-console-backspace-control  CONSOLE_BACKSPACE_NO_ERASE=1, which must not
"""
import argparse, json, os, socket, subprocess, sys, time

# TWELVE, NOT SIX, AND THE MARGIN IS THE REASON. Measured 2026-09-12, six
# characters moved 427 bytes against a 216-byte blink -- clearing the
# blink+200 floor by eleven. A pixel diff with eleven bytes of headroom is a
# flake waiting for a font change, so the signal is widened rather than the
# threshold lowered: twelve characters move ~640, which clears it by ~220.
TYPE = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--boot-timeout", type=int, default=45)
    ap.add_argument("--expect-no-erase", action="store_true")
    ap.add_argument("--shots", default="/tmp/horus-backspace")
    a = ap.parse_args()

    os.makedirs(a.shots, exist_ok=True)
    sock = "/tmp/horus-backspace-qmp.sock"
    if os.path.exists(sock):
        os.unlink(sock)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock)
    srv.listen(1)

    qemu = subprocess.Popen(
        ["qemu-system-x86_64", "-m", "512M",
         "-cpu", "qemu64,+aes,+rdrand,+smep,+smap", "-smp", "2",
         "-machine", "accel=kvm:tcg", "-display", "none",
         "-qmp", f"unix:{sock}", "-net", "none", "-no-reboot", "-no-shutdown",
         "-serial", "none", "-cdrom", a.iso],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    srv.settimeout(a.boot_timeout)
    conn, _ = srv.accept()
    f = conn.makefile("rw")

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
    time.sleep(a.boot_timeout)

    def shot(name):
        path = os.path.join(a.shots, name)
        if os.path.exists(path):
            os.unlink(path)
        qmp(execute="screendump", arguments={"filename": path})
        time.sleep(1.5)
        return open(path, "rb").read() if os.path.exists(path) else b""

    def send(key):
        qmp(execute="send-key", arguments={"keys": [{"type": "qcode", "data": key}]})
        time.sleep(0.25)

    def delta(x, y):
        return sum(1 for p, q in zip(x, y) if p != q)

    s0 = shot("1-prompt.ppm")
    time.sleep(6)
    s_idle = shot("2-idle.ppm")          # what the screen does on its own
    for k in TYPE:
        send(k)
    time.sleep(1)
    s_typed = shot("3-typed.ppm")
    for _ in TYPE:
        send("backspace")
    time.sleep(1)
    s_erased = shot("4-erased.ppm")

    qemu.kill()
    qemu.wait()

    # Screendumps stay on the failure path; they are the only evidence there is.
    if not s0 or not s_typed or not s_erased:
        print(f"CONSOLE_BACKSPACE: FAIL no screendump; the guest never reached a "
              f"display (artifacts in {a.shots})")
        return 1

    blink = delta(s0, s_idle)
    typed = delta(s_idle, s_typed)
    erased = delta(s_idle, s_erased)

    # The keys must have reached the screen at all, or the run says nothing about
    # backspace -- a dead keyboard would otherwise read as a perfect erase.
    if typed <= blink + 200:
        print(f"CONSOLE_BACKSPACE: FAIL the typed characters never reached the screen, "
              f"so this run is inconclusive about backspace (blink={blink} "
              f"typed={typed}, artifacts in {a.shots})")
        return 1

    erased_clean = erased <= blink + 200
    verdict = f"blink={blink} typed={typed} erased={erased}"

    if a.expect_no_erase:
        if erased_clean:
            print(f"CONSOLE_BACKSPACE: FAIL the arm erased correctly; "
                  f"CONSOLE_BACKSPACE_NO_ERASE did not reproduce the defect ({verdict})")
            return 1
        print(f"CONSOLE_BACKSPACE: PASS the arm leaves the screen dirty, as it must "
              f"({verdict})")
        return 0

    if not erased_clean:
        print(f"CONSOLE_BACKSPACE: FAIL backspace did not restore the screen -- the "
              f"erase drew instead of rubbing out ({verdict}, artifacts in {a.shots})")
        return 1
    print(f"CONSOLE_BACKSPACE: PASS typed and erased on the screen ({verdict})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
