#!/usr/bin/env python3
"""passwd_session.py — `passwd <uid>` changes THAT account, and only that account.

WHAT IS BEING MEASURED, and why it takes two boots.

The shell's `passwd` matched an argument (`strncmp(cmd, "passwd ", 7)`) and then
dropped it: every call went to sys_getuid(). A root operator who created an
account and typed `passwd 1001` to give it a password got `password changed` --
a true sentence about a different account than the one they named -- and silently
changed their OWN. The reply could not distinguish the two cases, because it is
true of whichever account was actually written.

THAT IS A CREDENTIAL CHANGE, NOT A MIS-PRINT, and the second boot is what shows
it. do_passwd re-wraps the volume key whenever target_uid == my_uid, so the string
typed for somebody else's account became the volume's key-slot password too. The
machine's own installer says a forgotten password is a lost volume; this was a way
to change it without being asked, discoverable only at the next power-on.

So boot 1 does the administration and boot 2 asks the disk who it now belongs to.

BOTH ARMS ASSERT POSITIVELY. The base arm requires the ORIGINAL password to still
open the machine on boot 2 and the new account to log in with what it was given;
the control arm requires the machine to open with the OTHER account's password --
a login that succeeds, not one that fails, because an assertion of refusal is
satisfied by a boot that never got to a prompt.

Usage:  passwd_session.py [boot.iso]
Env:    SESSION_DISK    the disk image; REQUIRED, and the same one for both boots
        ROOT_PASSWORD   the password the volume is sealed to (default "rootpass",
                        the compiled-in default from users_init)
        BOB_PASSWORD    the password given to the new account (default "bobpass1")
        PASSWD_EXPECT_SELF   control arm: require root's password to have become
                             BOB_PASSWORD
        SESSION_TIMEOUT / BOOT_TIMEOUT   expect budgets
Exit:   0 and "PASSWD_SESSION: PASS"; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "120"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))
ROOT_PW = os.environ.get("ROOT_PASSWORD", "rootpass")
BOB_PW = os.environ.get("BOB_PASSWORD", "bobpass1")
CONTROL = os.environ.get("PASSWD_EXPECT_SELF") == "1"

BOB_UID = "1001"


def step(msg):
    print(f"PASSWD_SESSION: ok - {msg}", flush=True)


def login(s, user, pw, timeout=STEP):
    """Try one login. Returns True on a shell prompt, False on a refusal."""
    s.expect("horus login:", timeout)
    s.send(user)
    s.expect("Password:", timeout)
    s.send(pw)
    try:
        # "@horus" and not "@horus#": the prompt's last character is the uid --
        # `#` for root and `$` for everyone else -- so matching the root form
        # would make every non-root login in this file look like a refusal.
        s.expect("@horus", timeout)
        return True
    except SessionFail:
        return False


def boot1():
    """Administer: create an account, give it a password, and check whose changed."""
    s = Serial(ISO)
    try:
        # The first login of a boot on an unformatted volume is what seals it, so
        # this password is the volume's as well as root's from here on.
        if not login(s, "root", ROOT_PW, BOOT):
            raise SessionFail("root could not log in on the install boot")
        step("logged in as root and sealed the volume")

        s.send(f"useradd {BOB_UID} bob")
        s.expect("user added", STEP)
        step("created an account from the root account")

        # THE COMMAND UNDER TEST. Under the defect this changes root's own
        # password (and re-seals the volume) while reporting success.
        s.send(f"passwd {BOB_UID}")
        s.expect("New password:", STEP)
        s.send(BOB_PW)
        # The reply names the uid it wrote, and the two arms differ in it right
        # here -- 1001 against 0. That is the discriminator the old `password
        # changed` could not provide, being true of whichever account was
        # actually written; the logins below are its consequences.
        s.expect("password changed for uid " + ("0" if CONTROL else BOB_UID), STEP)
        s.expect("@horus", STEP)
        step(f"ran `passwd {BOB_UID}`, and it reported the uid it wrote")

        s.send("logout")
        if CONTROL:
            # The defect, observed inside the same boot: root's own password is
            # now the one typed for the other account. Asserted as a login that
            # SUCCEEDS, which a boot that got nowhere cannot fake.
            if not login(s, "root", BOB_PW):
                raise SessionFail(
                    "CONTROL: root's password did not become the other account's; "
                    "the defect did not reproduce")
            step("CONTROL: root logged in with the password meant for another account")
        else:
            if not login(s, "root", ROOT_PW):
                raise SessionFail("root's own password was changed by `passwd <uid>`")
            step("root's own password is untouched")
            s.send("logout")
            if not login(s, "bob", BOB_PW):
                raise SessionFail("the account passwd named cannot log in with what it was given")
            step("the new account logs in with the password it was given")
    finally:
        s.close()


def boot2():
    """Power on again and ask the disk which password now opens it."""
    s = Serial(ISO)
    try:
        if CONTROL:
            if not login(s, "root", BOB_PW, BOOT):
                raise SessionFail(
                    "CONTROL: the volume did not re-seal to the other account's password")
            step("CONTROL: the volume opens with the password meant for another account")
        else:
            if not login(s, "root", ROOT_PW, BOOT):
                raise SessionFail(
                    "the volume no longer opens with the password it was sealed to")
            step("the volume still opens with the password it was sealed to")
    finally:
        s.close()


def run():
    if not os.environ.get("SESSION_DISK", ""):
        raise SessionFail("SESSION_DISK must name the image both boots share")
    boot1()
    boot2()
    print("PASSWD_SESSION: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SessionFail as e:
        print(f"PASSWD_SESSION: FAIL {e}", file=sys.stderr, flush=True)
        sys.exit(1)
