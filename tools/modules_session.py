#!/usr/bin/env python3
"""modules_session.py — prove GNU coreutils utilities shipped as GRUB *boot
modules* (not baked into the kernel image) are provisioned into /bin and run
through the REAL ring-3 shell over serial.

This is the transport gate for loading programs from the filesystem: the kernel
records each module from the multiboot2 tags, the fs_server copies it into /bin
on the encrypted store, and the shell resolves /bin/<name>, loads the ~530 KiB
image over the fs_server, and spawns it — none of it living in the 16 MiB kernel
image. It doubles as the coverage for the two newly ported utilities, printf and
tail, each of which is far larger than the old per-image embedding limit.

Fixtures use the shell's own `echo`+redirect (its echo builtin is unshadowed,
since echo is not in this module set), and every assertion is on output produced
by the utility's own upstream code.

Usage:  tools/modules_session.py [boot.iso]
Exit:   0 and "MODULES_SESSION: PASS" on success; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
# Provisioning ~500 KiB binaries block-by-block through the encrypted+journaled
# store is slow under TCG, so allow generous headroom before the banner.
BOOT = float(os.environ.get("BOOT_TIMEOUT", "240"))


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
        # The fs_server prints this once it has copied the boot modules into /bin.
        s.expect("provisioned boot modules into /bin", BOOT)
        step("fs_server provisioned boot modules into /bin")

        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("rootpass")
        s.expect(PROMPT, STEP)
        step("logged in")

        # The utilities landed in /bin as real files, from the modules.
        cmd("cd /bin")
        cmd("ls", "printf", "tail")
        step("/bin lists printf and tail (provisioned from boot modules)")
        cmd("cd /")

        # printf: real coreutils printf.c formatting. The shell splits on spaces,
        # so "%s=%d\n" is one arg and printf expands \n itself.
        cmd("printf %s=%d\\n foo 7", "foo=7")
        step("printf formats (upstream printf.c, loaded from /bin)")

        # tail: create a fixture with the shell's echo builtin (unshadowed here),
        # then select the tail of it. "one two three four five six" is 27 bytes
        # with no trailing newline, so its last 3 bytes are "six".
        cmd("echo one two three four five six > cu.txt")
        cmd("tail -c 3 cu.txt", "six")
        step("tail -c selects trailing bytes (upstream tail.c)")
        cmd("tail -n 1 cu.txt", "one two three four five six")
        step("tail -n selects the last line")

        print("MODULES_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"MODULES_SESSION: FAIL - {e}", file=sys.stderr)
        tail = s.buf[-1600:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
