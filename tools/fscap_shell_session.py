#!/usr/bin/env python3
"""fscap_shell_session.py -- the shell walks by capability, and so does what it runs.

Phase 1b step 2 (docs/design/filesystem.md section 11.1), driven through the REAL
ring-3 shell over serial on an INIT_SHELL_ROOT_READONLY build: init hands the
shell the root directory narrowed to read, lookup and exec, and nothing else.

The session logs in as root. On the uid path root may write anywhere, so every
refusal below is the capability deciding, not the mode bits:

  - `ls /bin`, `cd`, `pwd`, a relative `ls` and `man` read through the
    capability;
  - /bin/wc, run from the shell, reads a file: the child was handed the
    shell's root (hvfs_grant_fs) and walks with it;
  - `mkdir`, `touch` and `rm` are refused "permission denied". `mkdir-refused`
    is the check the control arm SHELL_CAP_FALLBACK=1 must turn red: a shell
    that sends a refused request again down the uid path, which as root
    succeeds.

Usage:  tools/fscap_shell_session.py [horus.iso]
Exit:   0 and "FSCAP_SHELL_SESSION: PASS" on success; 1 and a FAIL line otherwise.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail, _dump_serial  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))


def step(msg):
    print(f"FSCAP_SHELL_SESSION: ok - {msg}")


def run():
    s = Serial(ISO)
    PROMPT = "root@horus#"

    def cmd(line, *waits):
        s.send(line)
        for w in waits:
            s.expect(w, STEP)
        s.expect(PROMPT, STEP)

    def refused(line, what, name):
        start = len(s.buf)
        s.send(line)
        s.expect(f"{what}: ", STEP)
        s.expect(PROMPT, STEP)
        said = s.buf[start:]
        if f"{what}: permission denied" not in said:
            raise SessionFail(f"{name}: '{line}' was not refused permission denied")

    try:
        s.expect("horus login:", BOOT)
        if "could not hand the shell its read-only root" in getattr(s, "buf", ""):
            raise SessionFail("init could not grant the shell its root")
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect(PROMPT, STEP)
        step("logged in")

        cmd("ls /bin", "wc")
        step("ls /bin lists through the root capability")
        cmd("cd /usr/share/man")
        cmd("pwd", "/usr/share/man")
        cmd("ls", "hier")
        step("cd, pwd and a relative ls work through the working directory's capability")
        cmd("man hier", "Horus Filesystem Hierarchy")
        step("man reads a page through a capability")

        # A child: /bin/wc is handed the shell's root and reads a file with it.
        # The COUNT LINE is asserted, not the name, which the typed command
        # echoes too; and in GNU wc's layout (one space before the name), which
        # the shell's own wc builtin does not print, so it is the child's.
        start = len(s.buf)
        cmd("wc /usr/share/man/hier")
        if not re.search(r"\d+\s+\d+\s+\d+ /usr/share/man/hier", s.buf[start:]):
            raise SessionFail("child-read: /bin/wc printed no count line for the file")
        step("/bin/wc, handed the shell's root, read a file")

        cmd("cd /")
        refused("mkdir capx", "mkdir", "mkdir-refused")
        refused("touch capf", "touch", "touch-refused")
        refused("rm bin", "rm", "rm-refused")
        step("mkdir, touch and rm are refused through the read-only root, though the session is root")

        print("FSCAP_SHELL_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"FSCAP_SHELL_SESSION: FAIL {e}")
        return 1
    finally:
        # The whole serial, on a pass as on a failure: the evidence is kept.
        _dump_serial(getattr(s, "buf", ""))
        s.close()


if __name__ == "__main__":
    sys.exit(run())
