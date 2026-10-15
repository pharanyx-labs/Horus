#!/usr/bin/env python3
"""session_admin_caps.py -- administration is lent to an administrator's session only (S149).

Driven through the real ring-3 shell over serial on a live boot:

  1. root logs in. The shell must hold what administration needs, because init
     lent it for this session: `dmesg` prints the kernel log, `capview` shows
     the shell's own CAP_DEBUG read-only, `ps` lists other tasks (fs_server),
     and `useradd`/`userdel` work. Then logout, which takes them back.
  2. The standard account logs in. Each of those must be refused BY THE KERNEL,
     because the shell no longer asks who is logged in, it holds nothing:
     `dmesg` and `irqpolicy` are refused (CAP_KERNEL_LOG), `capview` is refused
     (CAP_DEBUG), `ps` lists the shell alone, `useradd` is refused (CAP_USER),
     and `passwd 0` is refused before any password is asked for. The demo
     commands are gone from the shipped shell: `spawn hello` is unknown.
  3. root logs in again and `dmesg` works again: the lending is per session,
     not once per boot.

ADMINCAPS_EXPECT:
  pass   the plain build: as above
  held   either arm (INIT_ADMIN_CAPS_KEPT=1, INIT_ADMIN_CAPS_AT_LAUNCH=1): the
         standard account's `dmesg` must PRINT the kernel log, which only a
         capability it should not hold allows. CONTROL PASS only then.

Until 2026-10-15 init granted the shell CAP_KERNEL_LOG, CAP_DEBUG and CAP_USER
for the whole boot, and the shell's own uid check was all that kept a standard
account from them.

Usage:  tools/session_admin_caps.py [horus.iso]
Exit:   0 and "ADMINCAPS_SESSION: PASS" (or "CONTROL PASS"); 1 and a FAIL line.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "60"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))
EXPECT = os.environ.get("ADMINCAPS_EXPECT", "pass")
ROOT_PROMPT = "root@horus#"
USER_PROMPT = "user@horus$"
# A line every boot's kernel log carries (session_test.py step 4b uses it too).
KLOG_LINE = "mem: physical pool"
DENIED = "permission denied (an administrator's session only"


def step(msg):
    print(f"ADMINCAPS_SESSION: ok - {msg}", flush=True)


def run():
    if EXPECT not in ("pass", "held"):
        raise SessionFail("ADMINCAPS_EXPECT must be pass or held")
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

    def need(cond, why, out):
        if not cond:
            raise SessionFail("%s: %r" % (why, out[-600:]))

    try:
        # --- 1. the administrator's session holds administration -----------
        login("root", "toor", ROOT_PROMPT, BOOT)
        out = cmd("dmesg", ROOT_PROMPT)
        need(KLOG_LINE in out, "root's dmesg did not print the kernel log", out)
        out = cmd("capview", ROOT_PROMPT)
        need("debug" in out and "r-----" in out,
             "root's capview did not show the shell's CAP_DEBUG, read-only", out)
        out = cmd("ps", ROOT_PROMPT)
        need("fs_server" in out, "root's ps did not list fs_server", out)
        out = cmd("useradd 1007 carol", ROOT_PROMPT)
        need("user added" in out, "root's useradd failed", out)
        out = cmd("userdel 1007", ROOT_PROMPT)
        need("user deleted" in out, "root's userdel failed", out)
        step("root's session reads the kernel log and the capability graph, "
             "sees every task, and manages accounts")
        s.send("logout")

        # --- 2. the standard account's session holds none of it ------------
        login("user", "password", USER_PROMPT, STEP)
        out = cmd("dmesg", USER_PROMPT)
        if EXPECT == "held":
            need(KLOG_LINE in out, "CONTROL: the standard account's dmesg was refused, "
                 "so the shell does not hold the kernel log in its session", out)
            step("CONTROL: the standard account read the kernel log with a capability "
                 "its session should not hold")
            print("ADMINCAPS_SESSION: CONTROL PASS")
            return 0
        need(KLOG_LINE not in out and "dmesg: " + DENIED in out,
             "the standard account's dmesg was not refused by the kernel", out)
        step("dmesg is refused for the standard account, by the kernel")
        # A ship build has no interrupt-policy counters at all (the syscall is
        # IRQ_POLICY_AUDIT only and answers NOSYS to everyone), so either answer
        # is right here; what must not happen is counters being printed.
        out = cmd("irqpolicy", USER_PROMPT)
        need("accidental_sti=" not in out and
             ("irqpolicy: " + DENIED in out or "not an IRQ_POLICY_AUDIT build" in out),
             "the standard account's irqpolicy was not refused", out)
        step("irqpolicy prints no counters for the standard account")
        out = cmd("capview", USER_PROMPT)
        need("capview: refused - this task holds no CAP_DEBUG" in out,
             "the standard account's capview was not refused", out)
        step("capview is refused: the shell holds no CAP_DEBUG")
        out = cmd("ps", USER_PROMPT)
        need("shell" in out and "fs_server" not in out and "init" not in out,
             "the standard account's ps listed tasks other than the shell", out)
        step("ps lists the shell alone")
        out = cmd("useradd 1008 mallory", USER_PROMPT)
        need("useradd: " + DENIED in out and "user added" not in out,
             "the standard account's useradd was not refused by the kernel", out)
        step("useradd is refused, by the kernel")
        out = cmd("passwd 0", USER_PROMPT)
        need("passwd: permission denied" in out and "New password" not in out,
             "the standard account's passwd 0 was not refused before the prompt", out)
        step("passwd for another account is refused before any password is asked")
        out = cmd("spawn hello", USER_PROMPT)
        need("Unknown command" in out, "spawn is still in the shipped shell", out)
        step("the demonstration commands are not in the shipped shell")
        s.send("logout")

        # --- 3. lent again to the next administrator's session -------------
        login("root", "toor", ROOT_PROMPT, STEP)
        out = cmd("dmesg", ROOT_PROMPT)
        need(KLOG_LINE in out, "root's second session could not read the kernel log", out)
        step("root's next session holds the kernel log again: lent per session")
        print("ADMINCAPS_SESSION: PASS")
        return 0
    finally:
        s.close()


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SessionFail as e:
        print(f"ADMINCAPS_SESSION: FAIL {e}", file=sys.stderr)
        sys.exit(1)
