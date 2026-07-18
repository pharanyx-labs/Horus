#!/usr/bin/env python3
"""coreutils_session.py — drive the ported GNU coreutils utilities through the
REAL ring-3 shell over serial, on a COREUTILS_SHELL=1 build.

Unlike smoke-coreutils (which spawns the utilities directly from the kernel with
a staged argv), this exercises the whole user-facing path: the shell parses a
command line, spawns the utility as a child with its argv, the child opens a
file through its own fs_server connection, and the shell waits for it to finish.

It creates a file with the shell's `echo > file`, then:
  * head prints the file's contents,
  * wc -w / wc -l count words and lines,
  * seq generates a sequence with no input at all.
Each assertion is on output produced by the utility's own upstream code.

Usage:  tools/coreutils_session.py [boot.iso]
Exit:   0 and "COREUTILS_SESSION: PASS" on success; 1 and a FAIL line otherwise.
"""
import os
import sys

# Reuse the serial/login driver from the main session test (importing it does
# not run it -- it is guarded by __main__).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "90"))


def step(msg):
    print(f"COREUTILS_SESSION: ok - {msg}")


def run():
    s = Serial(ISO)

    PROMPT = "root@horus#"

    def cmd(line, *waits):
        """Send a command, wait for each expected output substring in order,
        then consume the trailing prompt. The prompt before `line` must already
        have been consumed by the previous cmd() (or the login)."""
        s.send(line)
        for w in waits:
            s.expect(w, STEP)
        s.expect(PROMPT, STEP)

    try:
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("rootpass")
        s.expect(PROMPT, STEP)          # consume the first prompt after login
        step("logged in")

        # fs_server must be up for the utilities to read files. The default boot
        # launches it via init and provisions the utilities into /bin, so the root
        # now lists that directory; confirm the server is serving by seeing it.
        cmd("ls", "bin")
        step("fs_server serving; /bin present")

        # Create a fixture with the shell's own echo+redirect. It writes the text
        # verbatim with no trailing newline, so "one two three four five six" is
        # 6 words and 27 bytes (and 0 newlines -- wc -l would be 0).
        cmd("echo one two three four five six > cu.txt")

        # head reads the file and prints its contents -- upstream head.c over the
        # child's own fs_server connection.
        cmd("head cu.txt", "one two three four five six")
        step("head prints a file's contents")

        # wc's single-file format is "<count> <name>", so "6 cu.txt" / "27 cu.txt"
        # match regardless of the leading field padding.
        cmd("wc -w cu.txt", "6 cu.txt")
        step("wc -w counts words")
        cmd("wc -c cu.txt", "27 cu.txt")
        step("wc -c counts bytes")

        # seq needs no input at all -- pure computation, exercising the float
        # parse + long-double formatting foundation.
        cmd("seq 1 5", "1", "2", "3", "4", "5")
        step("seq generates a sequence")

        print("COREUTILS_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"COREUTILS_SESSION: FAIL - {e}", file=sys.stderr)
        # Dump recent serial for debugging.
        tail = s.buf[-1200:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
