#!/usr/bin/env python3
"""session_handover.py -- a login never holds an earlier login's filesystem (S147).

Driven through the real ring-3 shell over serial on a live boot that has a
program in /bin (COREUTILS_MODULES=1, `seq` alone):

  1. root logs in and runs /bin/seq, a foreground program, so the shell lends it
     the keyboard; then logs out.
  2. The standard account logs in. With HANDOVER_EXPECT=own (the plain build)
     it must have its OWN session: `ls /` lists bin/ and not var/, which only
     root's policy line reaches; and `mkdir handover_probe` at / must be
     refused, since its own session gives it nothing to write there and only
     root's capability would let it through.
  3. With HANDOVER_EXPECT=nosession, init refuses the account its session, and
     the shell must end the login, saying why, before it can reach any file
     (phase 1b step 6, decided 2026-10-16).

Until 2026-10-15 the shell lent the keyboard from slot 26, the slot its session
capability was in, so step 1 destroyed it: logout ended nothing, the account in
step 2 got no session, and the shell mounted root's root, still in slot 24.

Since step 6 a login with no session never reaches a prompt, so the account
cannot be left walking by root's root even if the slot still held it; the
shell's refusal to mount a root slot without a session (fss_connect) and its
drop of both slots at logout stay behind that, as a second layer.

HANDOVER_EXPECT:
  own       the plain build: own session, mkdir refused
  nosession INIT_SESSION_DEAF_AFTER_FIRST=1: init refuses every session after
            the first, so the account has none; its login must be ended
  lost      the arm SH_LEND_SLOT_SESSION=1: the slot collision is back, so the
            account's login must be ended for want of a session, in a build
            whose init answers every request
  leak      the arm SHELL_STALE_ROOT=1 with SHELL_NO_SESSION_ALLOWED=1 under
            the deaf instrument: both layers gone, the login stays and mkdir
            must SUCCEED (root's capability was used)
            Either arm passes as CONTROL PASS only when it shows its defect.

Usage:  tools/session_handover.py [horus.iso]
Exit:   0 and "HANDOVER_SESSION: PASS" (or "CONTROL PASS"); 1 and a FAIL line.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))
EXPECT = os.environ.get("HANDOVER_EXPECT", "own")
ROOT_PROMPT = "root@horus#"
USER_PROMPT = "user@horus$"


def step(msg):
    print(f"HANDOVER_SESSION: ok - {msg}", flush=True)


def run():
    if EXPECT not in ("own", "nosession", "lost", "leak"):
        raise SessionFail("HANDOVER_EXPECT must be own, nosession, lost or leak")
    s = Serial(ISO)

    def cmd(line, prompt):
        """Run one command; return what it printed before the next prompt."""
        start = len(s.buf)
        s.send(line)
        s.expect(prompt, STEP)
        out = s.buf[start:]
        return out[:out.rfind(prompt)]

    def login(name, pw, prompt, timeout):
        s.expect("login:", timeout)
        s.send(name)
        s.expect("Password:", STEP)
        s.send(pw)
        s.expect(prompt, STEP)

    def login_ended(name, pw):
        """Log in and require the login to be ended for want of a session."""
        s.expect("login:", STEP)
        start = len(s.buf)
        s.send(name)
        s.expect("Password:", STEP)
        s.send(pw)
        s.expect("Login ended.", STEP)
        s.expect("login:", STEP)
        out = s.buf[start:]
        if USER_PROMPT in out:
            raise SessionFail("the login reached a prompt before it was ended: %r" % out)
        if "No filesystem session could be opened for this login." not in out:
            raise SessionFail("the login was ended without saying why: %r" % out)

    try:
        login("root", "toor", ROOT_PROMPT, BOOT)
        out = cmd("seq 3", ROOT_PROMPT)
        if "3" not in out:
            raise SessionFail("/bin/seq did not run as root: %r" % out)
        step("root ran /bin/seq, a foreground program the keyboard was lent to")
        s.send("logout")

        if EXPECT in ("nosession", "lost"):
            login_ended("user", "password")
            if EXPECT == "lost":
                step("CONTROL: the program root ran took the shell's session capability, and "
                     "the standard account's login was ended for want of a session")
                print("HANDOVER_SESSION: CONTROL PASS")
                return 0
            step("the standard account, refused its session, was told why and its login ended")
            print("HANDOVER_SESSION: PASS")
            return 0

        login("user", "password", USER_PROMPT, STEP)
        root_ls = cmd("ls /", USER_PROMPT)
        cmd("cd /", USER_PROMPT)
        made = cmd("mkdir handover_probe", USER_PROMPT)
        created = "mkdir: created handover_probe" in made

        if EXPECT == "leak":
            if not created:
                raise SessionFail("CONTROL: the standard account could not create at /, "
                                  "so root's capability was not left to it: %r" % made)
            step("CONTROL: the standard account created a directory at / with root's capability")
            print("HANDOVER_SESSION: CONTROL PASS")
            return 0

        if created:
            raise SessionFail("the standard account created a directory at /: it holds "
                              "an earlier login's filesystem (S147)")
        step("the standard account cannot create at /")
        if "bin/" not in root_ls or "var/" in root_ls:
            raise SessionFail("the standard account has no session of its own after root's "
                              "logout: `ls /` says %r" % root_ls)
        step("and it has its own session: `ls /` shows bin/ and not var/")
        print("HANDOVER_SESSION: PASS")
        return 0
    finally:
        s.close()


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SessionFail as e:
        print(f"HANDOVER_SESSION: FAIL {e}", file=sys.stderr)
        sys.exit(1)
