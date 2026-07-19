#!/usr/bin/env python3
"""modules_session.py — prove the filesystem comes up with a real directory
skeleton, that ALL ported GNU coreutils (shipped as GRUB boot modules, not baked
into the kernel image) are provisioned into /bin and fit the store volume at once,
that their man pages land in /usr/share/man, and that `man` reads them from there —
all driven through the REAL ring-3 shell over serial.

Fixtures use the raw `fss_create` + `fss_write` builtins (not coreutil names),
because /bin/echo now shadows the shell's echo builtin so its redirection cannot
create a file.

Usage:  tools/modules_session.py [boot.iso]
Exit:   0 and "MODULES_SESSION: PASS" on success; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))

ALL = ["echo", "true", "false", "basename", "dirname",
       "cat", "head", "seq", "wc", "printf", "tail"]
SKEL = ["bin", "etc", "home", "lib", "usr"]


def step(msg):
    print(f"MODULES_SESSION: ok - {msg}")


def run():
    s = Serial(ISO)
    PROMPT = "root@horus#"

    def cmd(line, *waits):
        s.send(line)
        for w in waits:
            s.expect(w, STEP)
        s.expect(PROMPT, STEP)

    try:
        s.expect("filesystem provisioned", BOOT)
        step("fs_server provisioned the filesystem")
        if "did not fit" in getattr(s, "buf", ""):
            raise SessionFail("a boot module did not fit the store volume")
        step("all boot modules fit the store volume (no 'did not fit')")

        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("rootpass")
        s.expect(PROMPT, STEP)
        step("logged in")

        # Directory skeleton: a bare `ls` on the root shows real directories, not
        # the old "(empty)" string.
        s.send("ls")
        for d in SKEL:
            s.expect(d, STEP)
        s.expect(PROMPT, STEP)
        step("root shows the directory skeleton (/bin /etc /home /lib /usr)")

        # Every utility landed in /bin.
        cmd("cd /bin")
        for u in ALL:
            cmd("ls", u)
        step(f"all {len(ALL)} coreutils present in /bin")

        # Man pages landed in /usr/share/man, and `man` reads them from there.
        cmd("cd /usr/share/man")
        for p in ["hier", "tail", "printf"]:
            cmd("ls", p)
        step("man pages present in /usr/share/man")
        cmd("cd /")
        cmd("man tail", "TAIL(1)", "output the last part of a file")
        step("man tail reads the page from /usr/share/man")
        cmd("man hier", "Horus Filesystem Hierarchy")
        step("man hier documents the layout")

        # printf and tail actually run from /bin.
        cmd("printf %s=%d\\n foo 7", "foo=7")
        step("printf runs (upstream printf.c, from /bin)")
        cmd("fss_create cu.txt", "created")
        cmd("fss_write cu.txt one two three four five six", "wrote")
        cmd("tail -c 3 cu.txt", "six")
        step("tail runs (upstream tail.c, from /bin)")

        print("MODULES_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"MODULES_SESSION: FAIL - {e}", file=sys.stderr)
        tail = s.buf[-1800:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
