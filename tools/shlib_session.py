#!/usr/bin/env python3
"""shlib_session.py -- the shared libc is handed out by inheritance, and only to
programs that ask for it (docs/design/shared-libc.md, step 1).

Boots a SHLIB_INHERIT_MODULES=1 build: the kernel loads the library from the
verified lib/libc.so boot module, endows init, init grants the shell the text,
and every program below is spawned by the REAL shell from /bin over serial.

  1. the boot says the library loaded;
  2. `shlibprobe`, whose image does not ask, holds NO library capability;
  3. `shlibdata set`, whose image asks (DT_NEEDED "libc.so"), binds it and runs;
  4. `shlibdata get`: errno set by the previous program is not this one's, so
     each spawn got its own copy of the library's data;
  5. `shlibdata exec`: errno set before an exec is not the new image's errno, so
     an exec gets a fresh copy too;
  6. `hello_shared`, an ordinary program using printf and malloc, binds and runs.

Each failure names the property it is, in words the control arms grep for:

  "a program that never asked holds the library"   (SHLIB_INHERIT_ANY_IMAGE)
  "one program's library data reached the next"    (SHLIB_DATA_TEMPLATE_SHARED)
  "the image after an exec could not bind"         (SHLIB_EXEC_NO_DATA)
  "the library's data template is gone"           (SHLIB_TEMPLATE_UNPINNED)

Usage:  tools/shlib_session.py [horus.iso]
Exit:   0 and "SHLIB_SESSION: PASS"; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "90"))
PROMPT = "root@horus#"


def step(msg):
    print(f"SHLIB_SESSION: ok - {msg}")


def run_cmd(s, cmd, needles, timeout=STEP):
    """Type `cmd`, wait for the prompt after it, and return what it printed.

    The whole output up to the next prompt is returned rather than expecting one
    needle, so a wrong answer is reported as what the program SAID, not as a
    timeout waiting for what it did not say."""
    start = len(s.buf)
    s.send(cmd)
    s.expect(PROMPT, timeout)
    out = s.buf[start:s.pos]
    missing = [n for n in needles if n not in out]
    return out, missing


def run():
    s = Serial(ISO)
    try:
        s.expect("shlib: ", BOOT)
        s.expect("pages loaded", STEP)
        step("the kernel loaded the library from its boot module")
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect(PROMPT, STEP)
        step("logged in")

        out, missing = run_cmd(s, "shlibprobe", ["SHLIBPROBE: holds no library capability"])
        if "SHLIBPROBE: HOLDS" in out:
            raise SessionFail("a program that never asked holds the library: " + out.strip())
        if missing:
            raise SessionFail("shlibprobe did not report:\n" + out.strip())
        step("a program that does not ask is given nothing")

        # shlibdata set is the FIRST program since boot that binds the library,
        # and that order is deliberate: every step until hello_shared (last)
        # avoids stdio, so a defect shows as the value it leaks rather than as a
        # crash on another program's stdio buffers. See userspace/shlibdata.c.
        out, missing = run_cmd(s, "shlibdata set", ["SHLIBDATA: set errno=4321"])
        if "no private copy of the library's data was mapped" in out:
            # The first program to bind, after shlibprobe exited: its data is
            # copied from the library's template, and the template was gone.
            raise SessionFail("the library's data template is gone: " + out.strip())
        if missing:
            raise SessionFail("shlibdata set, whose image asks for the library, did not "
                              "bind and run it:\n" + out.strip())
        step("a program that asks for the library inherits it, binds it and runs")
        out, missing = run_cmd(s, "shlibdata get", ["SHLIBDATA: errno=0 at start"])
        if "could not bind the shared libc" in out:
            raise SessionFail("a second program that asks for the library could not bind it "
                              "(the first did): " + out.strip())
        if "errno=4321 at start" in out:
            raise SessionFail("one program's library data reached the next: errno set by "
                              "`shlibdata set` was still set in `shlibdata get`")
        if missing:
            raise SessionFail("shlibdata get did not report a fresh errno:\n" + out.strip())
        step("each spawn gets its own copy of the library's data")

        out, missing = run_cmd(s, "shlibdata exec", ["SHLIBDATA: errno=0 at start"])
        if "could not bind the shared libc" in out:
            raise SessionFail("the image after an exec could not bind the library: "
                              + out.strip())
        if "errno=4321 at start" in out:
            raise SessionFail("one program's library data reached the next, across an "
                              "exec: " + out.strip())
        if missing:
            raise SessionFail("shlibdata exec did not reach its new image:\n" + out.strip())
        step("an exec starts the new image from a fresh copy of the library's data")

        out, missing = run_cmd(s, "hello_shared", ["HELLOSHARED: PASS"])
        if missing:
            raise SessionFail("hello_shared, whose image asks for the library, did not "
                              "bind and run it:\n" + out.strip())
        step("an ordinary program (printf, malloc) inherits the library, binds it and runs")

        print("SHLIB_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"SHLIB_SESSION: FAIL {e}", file=sys.stderr)
        print("---- serial tail ----\n" + s.buf[-2000:], file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
