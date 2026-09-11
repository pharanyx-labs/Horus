#!/usr/bin/env python3
"""Log into Horus using the machine's KEYBOARD, and nothing else.

WHY THIS GATE EXISTS, and why no existing one covers it. Every other session
test types at COM1: `Serial.send` writes to the serial pty, the guest reads a
UART byte, and not one instruction of the keyboard path runs. So the entire
suite passed on 2026-09-10 with a kernel that consumed every scancode into a
buffer nothing read -- the machine booted to a login prompt on real hardware and
could not be typed at, and no gate could see it, because the gates do not use
the keyboard. A property nothing exercises is not guarded by a passing test.

This drives QEMU's emulated 8042 over QMP `send-key` instead. The guest sees a
real scancode, a real IRQ 1, and must translate it in ring 3 to get anywhere.
The assertion is the whole login: type the user name, get the password prompt,
type the password, get a shell. Nothing about that is reachable without the
keyboard working end to end.

THE ECHO IS THE EVIDENCE, not the prompt that follows it. The guest echoes each
character it accepts, on serial as well as the screen, so `horus login: root`
appearing on the wire proves those four bytes travelled 8042 -> ring-3 poll ->
translate -> echo. Waiting only for the shell prompt would also be satisfied by
a guest that logged itself in for some other reason.

  smoke-keyboard          the gate: the login succeeds, typed on the keyboard
  smoke-keyboard-control  CONSOLE_NO_KBD=1, which must FAIL to log in
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail   # noqa: E402

def run_installer(g, args):
    """Drive the installer's disk survey with the arrow keys.

    WHY THIS SCREEN. `screen_survey` offers { "Cancel, change nothing",
    "Continue" } with the cursor on **Cancel**, so a person at the machine
    cannot install without pressing Down first. The arrow is not a convenience
    here -- it is the only way past the screen, which makes "the arrows work" a
    property with real consequences rather than a nicety.

    WHAT IT CATCHES, and both failures land on the same marker. An arrow that is
    dropped leaves the cursor on Cancel, and Enter cancels. An arrow delivered
    SPLIT across two console replies is decoded as a bare ESC -- a real key --
    and cancels immediately, before Enter is even pressed. Either way the
    installer says `INSTALLER: nothing was written`, which is the assertion.

    The gate wants that marker ABSENT and the next screen reached; the arm
    (`--expect-cancel`, built with CONSOLE_KBD_SPLIT_ESC=1) wants it present.
    """
    g.expect("INSTALLER: waiting on the destroy-this-disk choice", args.boot_timeout)
    print("KEYBOARD: the installer is asking about the disk", flush=True)

    mark = len(g.buf)
    g.send_key("down", args.key_delay)

    if args.expect_cancel:
        # The arm. A split escape cancels the moment it arrives, so the marker
        # should be here without Enter ever being pressed -- but press it anyway
        # and allow either ordering, because asserting on WHICH keystroke caused
        # the cancel would be asserting on the bug's timing rather than on the
        # bug.
        g.send_key("ret", args.key_delay)
        g.expect("INSTALLER: nothing was written", args.timeout)
        print("KEYBOARD INSTALLER CONTROL: PASS the arrow cancelled the screen "
              "(the gate can fail)", flush=True)
        return 0

    g.send_key("ret", args.key_delay)
    # Reaching the password screen means Down moved the cursor off Cancel AND
    # Enter accepted Continue. Nothing else gets here.
    g.expect("INSTALLER: waiting on the password", args.timeout)
    seen = g.buf[mark:]
    if "nothing was written" in seen:
        raise SessionFail("the installer cancelled and then asked for a password; "
                          "read the log rather than trusting this ordering")
    print("KEYBOARD: PASS the arrow keys drove the installer past the disk "
          "survey", flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--iso", default="horus.iso")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="rootpass")
    ap.add_argument("--boot-timeout", type=float, default=180.0)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--key-delay", type=float, default=0.15)
    ap.add_argument("--serial-log", default=None)
    ap.add_argument("--installer", action="store_true",
                    help="drive the installer's disk survey with the ARROW keys "
                         "instead of logging in")
    ap.add_argument("--expect-cancel", action="store_true",
                    help="the installer arm's direction: assert the arrow "
                         "CANCELS, which is what a split escape sequence does")
    ap.add_argument("--expect-no-keyboard", action="store_true",
                    help="the control arm's direction: assert the keyboard does "
                         "NOT work, so a passing arm proves the gate can fail")
    args = ap.parse_args()

    g = Serial(args.iso)
    rc = 1
    try:
        if args.installer:
            return run_installer(g, args)
        g.expect("horus login: ", args.boot_timeout)
        print("KEYBOARD: login prompt reached", flush=True)

        # Everything from here is typed on the emulated keyboard. Nothing is
        # written to the serial line -- that would defeat the whole test.
        mark = len(g.buf)
        g.send_key_text(args.user + "\n", args.key_delay)

        if args.expect_no_keyboard:
            # The control arm. Give the guest a generous window to react and
            # then assert it did NOT: no echo of the user name, and no password
            # prompt. Bounded by a WAIT rather than an expect(), because the
            # thing being asserted is an absence and an expect() that times out
            # is indistinguishable from a harness fault (memory: absence needs a
            # non-blocking observer).
            g._pump(20.0)
            seen = g.buf[mark:]
            if args.user in seen or "assword" in seen:
                raise SessionFail(
                    "KEYBOARD CONTROL: the guest RESPONDED to keyboard input "
                    "under CONSOLE_NO_KBD, so the arm reproduces nothing and "
                    f"the gate above it proves nothing. Saw: {seen[-400:]!r}")
            print("KEYBOARD CONTROL: PASS no response to the keyboard "
                  "(the gate can fail)", flush=True)
            return 0     # the finally below still runs and still keeps the log

        # The echo of what we typed is the first real evidence.
        g.expect(args.user, args.timeout)
        print(f"KEYBOARD: the guest echoed {args.user!r} back", flush=True)

        g.expect("assword", args.timeout)
        g.send_key_text(args.password + "\n", args.key_delay)

        # A password is not echoed, so the shell prompt is the evidence here.
        # "@horus" rather than the full "<user>@horus# ": the suffix is '#' for
        # uid 0 and '$' otherwise, and a gate that hard-codes the root form
        # scores every non-root login as a refusal (memory: match the prompt,
        # not the privilege).
        g.expect("@horus", args.timeout)
        print("KEYBOARD: PASS logged in with the keyboard alone", flush=True)
        rc = 0
    except SessionFail as e:
        print(f"KEYBOARD: FAIL {e}", flush=True)
        rc = 1
    finally:
        if args.serial_log:
            # Written on BOTH paths on purpose. A gate must keep its evidence in
            # the case it goes red, which is the only case anyone needs it.
            try:
                with open(args.serial_log, "a") as f:
                    f.write(g.buf)
            except OSError as e:
                print(f"KEYBOARD: could not write serial log: {e}", flush=True)
        g.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
