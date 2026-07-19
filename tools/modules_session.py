#!/usr/bin/env python3
"""modules_session.py — prove ALL ported GNU coreutils, shipped as GRUB *boot
modules* (not baked into the kernel image), are provisioned into /bin and fit the
store volume at once, then run through the REAL ring-3 shell over serial.

This is the transport gate for loading programs from the filesystem AND the
residency gate for the grown store volume: the kernel records each module from
the multiboot2 tags, the fs_server copies every one into /bin on the encrypted
store, and all of them fit (no "did not fit") — which is what the multi-block
allocation bitmap, the off-.bss RAM vdisk, and the hierarchical metadata MAC
deliver. It then runs printf and tail from /bin. Each binary is ~450-610 KiB, far
over the old per-image embedding limit.

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
# Provisioning all ~11 * ~450 KiB binaries block-by-block through the encrypted
# store is the slow part under TCG; allow generous headroom before the banner.
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))

ALL = ["echo", "true", "false", "basename", "dirname",
       "cat", "head", "seq", "wc", "printf", "tail"]


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

        # Residency: every module fit the 16 MiB volume. The fs_server prints the
        # "did not fit" line only when the volume filled — assert it did NOT.
        if "did not fit" in getattr(s, "buf", ""):
            raise SessionFail("a boot module did not fit the store volume")
        step("all boot modules fit the store volume (no 'did not fit')")

        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("rootpass")
        s.expect(PROMPT, STEP)
        step("logged in")

        # Every utility landed in /bin as a real file, from the modules.
        cmd("cd /bin")
        for u in ALL:
            cmd("ls", u)
        step(f"all {len(ALL)} coreutils present in /bin")
        cmd("cd /")

        # printf: real coreutils printf.c formatting. The shell splits on spaces,
        # so "%s=%d\n" is one arg and printf expands \n itself.
        cmd("printf %s=%d\\n foo 7", "foo=7")
        step("printf formats (upstream printf.c, loaded from /bin)")

        # tail: build a fixture with fss_create + fss_write (echo is a module here,
        # so its redirection can't), then select its tail. fss_write stores exactly
        # the text — "one two three four five six" is 27 bytes, last 3 are "six".
        cmd("fss_create cu.txt", "created")
        cmd("fss_write cu.txt one two three four five six", "wrote")
        cmd("tail -c 3 cu.txt", "six")
        step("tail -c selects trailing bytes (upstream tail.c)")
        cmd("tail -n 1 cu.txt", "one two three four five six")
        step("tail -n selects the last line")

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
