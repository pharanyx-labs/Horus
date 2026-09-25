#!/usr/bin/env python3
"""dynlink_session.py -- programs linked against the shared libc by name are
resolved and sealed before main, and refused when they cannot be
(docs/design/shared-libc.md §8, step 3).

Boots a DYNLINK_MODULES=1 build and drives the REAL shell over serial:

  1. `hello_dyn -n horus a b`: getopt_long sets optarg and optind, which are the
     library's DATA, reached through the GOT; the program must see name=horus and
     optind=3, and printf, malloc and sprintf must work.
  2. `hello_dyn seal`: a write to its own resolved table must fault.
  3. `dyncanary`: references a name the library does not export; crt0 must
     refuse it, naming the name, before main.
  4. `dynstale`: built against a different table; crt0 must refuse it before
     main.

Each failure names the property, in words the control arms grep for:

  "the resolved table took a write"                         (DYNLINK_NO_SEAL)
  "a program ran with a name the library does not export"    (DYNLINK_UNKNOWN_ZERO)
  "a program ran against a library it was not built for"    (DYNLINK_ABI_UNCHECKED)

Usage:  tools/dynlink_session.py [horus.iso]
Exit:   0 and "DYNLINK_SESSION: PASS"; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "90"))
PROMPT = "root@horus#"
REFUSED = "crt0: the shared libc could not be linked: "


def step(msg):
    print(f"DYNLINK_SESSION: ok - {msg}")


def run_cmd(s, cmd):
    start = len(s.buf)
    s.send(cmd)
    s.expect(PROMPT, STEP)
    return s.buf[start:s.pos]


def run():
    s = Serial(ISO)
    try:
        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send("toor")
        s.expect(PROMPT, STEP)
        step("logged in")

        out = run_cmd(s, "hello_dyn -n horus a b")
        for want in ("HELLODYN: name=horus optind=3 of argc=5", "HELLODYN: horus-42",
                     "HELLODYN: PASS"):
            if want not in out:
                raise SessionFail(f"hello_dyn did not say `{want}`:\n" + out.strip())
        step("a linked program's getopt_long shares optarg/optind with it, and runs")

        out = run_cmd(s, "hello_dyn seal")
        if "HELLODYN: FAIL the resolved table took a write" in out:
            raise SessionFail("the resolved table took a write: " + out.strip())
        if "HELLODYN: the resolved table refused a write" not in out:
            raise SessionFail("hello_dyn seal did not report:\n" + out.strip())
        step("the program's resolved table is sealed before main")

        out = run_cmd(s, "dyncanary")
        if "DYNCANARY: ran" in out:
            raise SessionFail("a program ran with a name the library does not export: "
                              + out.strip())
        if REFUSED + "the library exports no __horus_link_canary" not in out:
            raise SessionFail("dyncanary was not refused by name:\n" + out.strip())
        step("a name the library does not export refuses the program before main")

        out = run_cmd(s, "dynstale")
        if "DYNSTALE: ran" in out:
            raise SessionFail("a program ran against a library it was not built for: "
                              + out.strip())
        if REFUSED + "the library is not the one this program was built against" not in out:
            raise SessionFail("dynstale was not refused:\n" + out.strip())
        step("a program built against a different library is refused before main")

        print("DYNLINK_SESSION: PASS")
        return 0
    except SessionFail as e:
        print(f"DYNLINK_SESSION: FAIL {e}", file=sys.stderr)
        print("---- serial tail ----\n" + s.buf[-1500:], file=sys.stderr)
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(run())
