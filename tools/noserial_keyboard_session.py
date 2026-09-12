#!/usr/bin/env python3
"""Type on the keyboard of a machine that has NO SERIAL PORT.

WHY THIS GATE EXISTS, AND WHY smoke-keyboard DOES NOT COVER IT. smoke-keyboard
types on QEMU's emulated 8042 and reads the guest's echo off COM1 -- so it needs
a UART to observe the result, and it therefore always runs on a machine that has
one. The defect this gate is built around only appears when there is NO UART:
every register at 0x3F8 floats to 0xFF, bit 0 of the line-status register means
"receive data ready", and 0xFF has bit 0 set. con_getc's serial branch then
claims a byte on every pass, returns the floating 0xFF as a character, and the
ps2_poll() beneath it is never reached. The keyboard is unreachable on exactly
the machines -- laptops with soldered eMMC and no serial header -- that have no
other way in. Reported from an IdeaPad on 2026-09-12 as `PS2 n=00001 sc=00
st=15`: one scancode in the 8042's output buffer, unread, and an IRQ 1 count
stuck at 1 because the controller raises no further interrupt until it is taken.

SO THE OBSERVATION CANNOT USE SERIAL, and this reads the SCREEN over QMP
instead, exactly as smoke-fb-console does for pixels.

THE IDLE CONTROL IS INSIDE THE GATE, not beside it, and that is the part worth
copying. The first version of this experiment compared one screendump before
typing with one after, saw 216 of 864,015 bytes differ, and reported a working
keyboard. 216 bytes is the CURSOR BLINK: an idle control over the same elapsed
time, typing nothing, moved by the identical 216. A gate that measures a screen
must know what that screen does when left alone, or it scores a blinking cursor
as a keystroke. Measured 2026-09-12: idle 216, sixteen keys on the fixed build
853, sixteen keys under SERIAL_PRESENCE_UNCHECKED=1 exactly 216.

  smoke-keyboard-noserial          the gate: typing moves the screen
  smoke-keyboard-noserial-control  SERIAL_PRESENCE_UNCHECKED=1, which must not
"""
import argparse, json, os, socket, subprocess, sys, time

KEYS = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"]
# The separation measured is 216 vs 853, so this sits far from both edges. It is
# a margin over the control rather than an absolute, because the control is what
# the blink costs and that is the quantity being subtracted.
MARGIN = 200
# A blank screen must not read as a dead keyboard: both produce no delta, and
# they want different fixes. Any real console has far more than this set.
MIN_NONBLANK = 5000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--boot-timeout", type=int, default=45)
    ap.add_argument("--expect-no-keyboard", action="store_true")
    ap.add_argument("--shots", default="/tmp/horus-noserial")
    a = ap.parse_args()

    os.makedirs(a.shots, exist_ok=True)
    sock = "/tmp/horus-noserial-qmp.sock"
    if os.path.exists(sock):
        os.unlink(sock)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock)
    srv.listen(1)

    # -serial none is the whole point: QEMU leaves 0x3F8 unassigned, and reads of
    # an unassigned port return 0xFF, which is what a floating ISA bus gives on
    # the hardware this reproduces.
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

    def delta(x, y):
        return sum(1 for p, q in zip(x, y) if p != q)

    s1 = shot("1-boot.ppm")
    time.sleep(6)
    s2 = shot("2-idle.ppm")
    for k in KEYS:
        qmp(execute="send-key", arguments={"keys": [{"type": "qcode", "data": k}]})
        time.sleep(0.25)
    time.sleep(2)
    s3 = shot("3-typed.ppm")

    qemu.kill()
    qemu.wait()

    # THE SCREENDUMPS ARE THE EVIDENCE AND THEY STAY, especially on the failure
    # path -- that is the only case anyone needs them. An `rm -f` here has
    # destroyed a real reproduction in this tree before.
    if not s1 or not s3:
        print("NOSERIAL_KEYBOARD: FAIL no screendump; the guest never reached a display "
              f"(artifacts in {a.shots})")
        return 1
    if len(set(s1)) < 3 or delta(s1, b"\x00" * len(s1)) < MIN_NONBLANK:
        print("NOSERIAL_KEYBOARD: FAIL the screen is blank -- inconclusive about the "
              f"keyboard, and a boot failure in its own right (artifacts in {a.shots})")
        return 1

    control, signal = delta(s1, s2), delta(s2, s3)
    live = signal - control >= MARGIN
    verdict = f"idle-control={control} after-{len(KEYS)}-keys={signal}"

    if a.expect_no_keyboard:
        if live:
            print(f"NOSERIAL_KEYBOARD: FAIL the arm typed successfully; "
                  f"SERIAL_PRESENCE_UNCHECKED did not reproduce the defect ({verdict})")
            return 1
        print(f"NOSERIAL_KEYBOARD: PASS the arm cannot type, as it must ({verdict})")
        return 0

    if not live:
        print(f"NOSERIAL_KEYBOARD: FAIL typing moved the screen no further than the "
              f"cursor blink -- the keyboard is unreachable with no UART present "
              f"({verdict}, artifacts in {a.shots})")
        return 1
    print(f"NOSERIAL_KEYBOARD: PASS typed on the keyboard with no serial port ({verdict})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
