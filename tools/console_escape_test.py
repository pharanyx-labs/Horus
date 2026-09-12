#!/usr/bin/env python3
"""An arrow key must not type its own escape sequence into the line.

WHAT WAS WRONG. con_getline drops bytes below 32, which disposes of the ESC --
and the REST of an escape sequence is ordinary printable text, so `ESC [ A` left
`[A` in the line buffer and on the screen. Measured 2026-09-12 at the login
prompt: Up echoed `[A`, Down `[B`, Left `[D`, Right `[C`. Pressing Up for
history, which is the first thing anybody does at a prompt, put two junk
characters into the user name; at the PASSWORD prompt it put them into the
password, where the masking means nobody can see what went wrong.

THE ASSERTION IS THE CONSEQUENCE, NOT THE ECHO. Checking only that nothing is
echoed would pass on a guest that had stopped reading the serial line at all. So
this presses Up FIRST and then logs in normally: under the defect the user name
is `[Aroot` and the login fails, and under the fix the arrow does nothing and the
login succeeds. The echo is checked too, but the login is what makes the run
mean something.

RAW MODE IS NOT TOUCHED and must not be: the installer's TUI reads through
con_read_raw and decodes arrows itself, which is how its disk survey is
navigated. `make smoke-keyboard-installer` and `make smoke-installer` cover that
path and are the regression check for this change.
"""
import argparse, os, socket, subprocess, sys, time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iso", required=True)
    ap.add_argument("--boot-timeout", type=int, default=70)
    ap.add_argument("--expect-literal", action="store_true")
    ap.add_argument("--log", default="/tmp/horus-escape-evidence.log")
    a = ap.parse_args()

    ss = "/tmp/horus-escape-serial.sock"
    if os.path.exists(ss):
        os.unlink(ss)
    qemu = subprocess.Popen(
        ["qemu-system-x86_64", "-m", "512M", "-machine", "q35", "-smp", "2",
         "-display", "none", "-net", "none", "-no-reboot", "-no-shutdown",
         "-serial", f"unix:{ss},server=on,wait=off", "-cdrom", a.iso],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    sc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(120):
        try:
            sc.connect(ss)
            break
        except OSError:
            time.sleep(0.5)
    sc.settimeout(0.5)

    buf = {"b": b""}

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            try:
                d = sc.recv(65536)
            except Exception:
                d = b""
            if d:
                buf["b"] += d
            else:
                time.sleep(0.05)

    def wait(token, timeout):
        end = time.time() + timeout
        while time.time() < end:
            pump(0.4)
            if token in buf["b"].decode("utf8", "replace"):
                return True
        return False

    def done(code, msg):
        with open(a.log, "wb") as fh:
            fh.write(buf["b"])
        qemu.kill()
        qemu.wait()
        print(msg)
        return code

    if not wait("horus login:", a.boot_timeout):
        return done(1, f"CONSOLE_ESCAPE: FAIL the guest never reached a login prompt "
                       f"(evidence: {a.log})")

    buf["b"] = b""
    sc.sendall(b"\x1b[A")            # Up, at the login prompt
    pump(2)
    echoed = buf["b"].decode("utf8", "replace")
    literal = "[A" in echoed

    # Now log in normally. The arrow must have left the line buffer untouched.
    sc.sendall(b"root\n")
    got_pw = wait("Password:", 30)
    sc.sendall(b"rootpass\n")
    logged_in = wait("#", 30) if got_pw else False

    verdict = f"echoed={echoed!r} password_prompt={got_pw} logged_in={logged_in}"

    if a.expect_literal:
        if literal and not logged_in:
            return done(0, f"CONSOLE_ESCAPE: PASS the arm types the sequence and the login "
                           f"fails, as it must ({verdict})")
        return done(1, f"CONSOLE_ESCAPE: FAIL the arm did not reproduce the defect -- the "
                       f"sequence was not typed, or the login survived it ({verdict})")

    if literal:
        return done(1, f"CONSOLE_ESCAPE: FAIL an arrow key typed its escape sequence into the "
                       f"line ({verdict}, evidence: {a.log})")
    if not logged_in:
        return done(1, f"CONSOLE_ESCAPE: FAIL nothing was echoed, but the login did not "
                       f"succeed either -- inconclusive rather than clean ({verdict}, "
                       f"evidence: {a.log})")
    return done(0, f"CONSOLE_ESCAPE: PASS an arrow key does nothing and the login is unharmed "
                   f"({verdict})")


if __name__ == "__main__":
    sys.exit(main())
