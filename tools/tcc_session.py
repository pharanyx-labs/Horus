#!/usr/bin/env python3
"""tcc_session.py — prove /bin/tcc (the ported Tiny C Compiler) runs on Horus.

Boots a TCC_MODULE=1 build, logs in through the REAL ring-3 shell over serial,
confirms the fs_server provisioned tcc into /bin, and runs `tcc -v`. TCC prints
its version banner ("tcc version 0.9.27 (x86_64 ...)") and returns 0, so the
"0.9.27" assertion is on output produced by tcc's own upstream code — end to end:
the shell resolves /bin/tcc, loads the ~1 MiB image over the fs_server, and spawns
it as a child, which writes to stdout through the console server.

Usage:  tools/tcc_session.py [boot.iso]
Exit:   0 and "TCC_SESSION: PASS" on success; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "90"))
# The tcc image is ~1 MiB — several times a coreutil — and loads block-by-block
# over the fs_server, so give the spawn a generous budget on a starved runner.
LOAD = max(STEP, 240.0)


def step(msg):
    print(f"TCC_SESSION: ok - {msg}")


def run():
    s = Serial(ISO)
    PROMPT = "root@horus#"
    try:
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("rootpass")
        s.expect(PROMPT, STEP)
        step("logged in")

        # Sanity: the fs_server is up and serving (root holds /bin). The shell's
        # `ls` lists the current directory (root), where the provisioned bin dir
        # shows up as "bin".
        s.send("ls")
        s.expect("bin", STEP)
        s.expect(PROMPT, STEP)
        step("fs_server serving; /bin present")

        # Run tcc by bare name: the shell resolves /bin/tcc (try_run_from_bin),
        # loads the ~1 MiB image over the fs_server, and spawns it. `tcc -v`
        # prints its version banner and exits 0. "0.9.27" is absent from the
        # command line, so it cannot false-match the echo. If tcc had not been
        # provisioned, the shell would answer "Unknown command" instead.
        s.send("tcc -v")
        s.expect("0.9.27", LOAD)
        s.expect(PROMPT, LOAD)
        step("/bin/tcc loaded and ran on Horus, reporting its version")

        print("TCC_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"TCC_SESSION: FAIL - {e}", file=sys.stderr)
        tail = s.buf[-1500:] if hasattr(s, "buf") else ""
        print("---- serial tail ----\n" + tail, file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
