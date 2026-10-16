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

AND AN ACCOUNT'S OWN `passwd` RE-SEALS ITS OWN KEY SLOT (LIMITATIONS 1.27).
After the administration, bob logs in on the same boot, after root has logged
out, and changes his own password. The volume is unlocked once per boot, by
root's login, and the kernel used to re-seal the slot of that FIRST unlock
whoever asked: root's. So boot 2 logs root in first and requires `ls` to list
the volume (root's password must still open it: root's login alone proves
nothing, since the compiled-in account table answers it while the volume is
locked), and boot 3 logs bob in first and requires his old password refused and
his new one to open the volume. PASSWD_EXPECT_FIRST_SLOT=1 is that defect's arm:
root's login on boot 2 must open no volume, so the shell ends it for want of a
session (or, were it to reach a prompt, `ls` must say it cannot read the volume).

Usage:  passwd_session.py [horus.iso]
Env:    SESSION_DISK    the disk image; REQUIRED, and the same one for both boots
        ROOT_PASSWORD   the password the volume is sealed to (default "toor",
                        the compiled-in default from users_init)
        BOB_PASSWORD    the password given to the new account (default "bobpass1")
        BOB_NEW_PASSWORD     the password bob changes his own to (default "bobpass2")
        PASSWD_EXPECT_SELF   control arm: require root's password to have become
                             BOB_PASSWORD
        PASSWD_EXPECT_FIRST_SLOT  control arm: require bob's own passwd to have
                             re-sealed root's slot, so root's password opens nothing
        SESSION_TIMEOUT / BOOT_TIMEOUT   expect budgets
Exit:   0 and "PASSWD_SESSION: PASS"; 1 and a FAIL line otherwise.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "horus.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "120"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "300"))
ROOT_PW = os.environ.get("ROOT_PASSWORD", "toor")
BOB_PW = os.environ.get("BOB_PASSWORD", "bobpass1")
BOB_PW2 = os.environ.get("BOB_NEW_PASSWORD", "bobpass2")
CONTROL = os.environ.get("PASSWD_EXPECT_SELF") == "1"
FIRST_SLOT = os.environ.get("PASSWD_EXPECT_FIRST_SLOT") == "1"

BOB_UID = "1001"


def step(msg):
    print(f"PASSWD_SESSION: ok - {msg}", flush=True)


def login_state(s, user, pw, timeout=STEP):
    """Try one login. Returns "prompt" on a shell prompt, "incorrect" on a
    refusal of the password, and "ended" when the password was accepted but
    the shell ended the login because no filesystem session opened for it
    (phase 1b step 6: a login whose volume did not open is one). Each is a line
    the shell printed; silence raises, so a boot that got nowhere is none of
    them. Until 2026-10-16 a timeout here read as a refusal."""
    s.expect("horus login:", timeout)
    s.send(user)
    s.expect("Password:", timeout)
    start = s.pos
    s.send(pw)
    # "@horus" and not "@horus#": the prompt's last character is the uid --
    # `#` for root and `$` for everyone else -- so matching the root form
    # would make every non-root login in this file look like a refusal.
    needles = (("@horus", "prompt"), ("Login incorrect", "incorrect"),
               ("Login ended.", "ended"))
    deadline = time.time() + timeout
    while True:
        hits = [(s.buf.find(n, s.pos), n, what) for n, what in needles]
        hits = [h for h in hits if h[0] >= 0]
        if hits:
            idx, n, what = min(hits)
            s.pos = idx + len(n)
            if what == "ended" and "No filesystem session could be opened" not in s.buf[start:s.pos]:
                raise SessionFail("%s's login was ended, but not for want of a session" % user)
            return what
        if time.time() >= deadline:
            raise SessionFail("no answer to %s's login: no prompt, refusal or ended login" % user)
        s._pump(0.25)


def login(s, user, pw, timeout=STEP):
    """Try one login. Returns True on a shell prompt, False on a refusal; a
    login ended for want of a session is neither, and raises."""
    what = login_state(s, user, pw, timeout)
    if what == "ended":
        raise SessionFail("%s's password was accepted, but no filesystem session "
                          "opened for the login" % user)
    return what == "prompt"


def refused(s, user, pw, timeout=STEP):
    """Require one login to be REFUSED, by the shell's own words for it. The
    caller then logs in successfully in the same boot, so a boot that never
    reached a prompt cannot pass as a refusal."""
    s.expect("horus login:", timeout)
    s.send(user)
    s.expect("Password:", timeout)
    s.send(pw)
    s.expect("Login incorrect", timeout)


def volume_listed(s):
    """`ls /` after a login: True if the volume answered with its root
    directory, False if the shell says it cannot read the volume. Each answer
    is a line the shell printed, so a dead session fails on the expect instead
    of passing as either."""
    start = s.pos
    s.send("ls /")
    s.expect("@horus", STEP)
    out = s.buf[start:s.pos]
    # A locked volume answers in one of two ways: fs_server cannot stat the
    # root of a volume it cannot read, or the shell reports it not unlocked.
    if "the volume is not unlocked" in out or "ls: no such directory: /" in out:
        return False
    if "bin/" in out:
        return True
    raise SessionFail("`ls /` gave neither a listing nor the locked-volume message: "
                      + repr(out[-200:]))


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

            # THE SECOND COMMAND UNDER TEST (LIMITATIONS 1.27): bob's OWN
            # passwd, on a boot whose volume root's login unlocked. It must
            # re-seal bob's slot, and under the defect it re-seals root's.
            s.send("passwd")
            s.expect("New password:", STEP)
            s.send(BOB_PW2)
            s.expect("password changed for uid " + BOB_UID, STEP)
            s.expect("@horus", STEP)
            step("bob changed his own password after root had logged out")
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
            # root's login answers from the compiled-in table even when the
            # volume stays locked, so the volume's answer is asked separately:
            # since phase 1b step 6 a login the volume did not open for has no
            # session and is ended before its prompt, and otherwise `ls /`
            # says whether the volume answers.
            what = login_state(s, "root", ROOT_PW, BOOT)
            if what == "incorrect":
                raise SessionFail(
                    "the volume no longer opens with the password it was sealed to")
            listed = what == "prompt" and volume_listed(s)
            if FIRST_SLOT:
                if listed:
                    raise SessionFail(
                        "CONTROL: root's password still opens the volume; bob's own "
                        "passwd did not re-seal root's slot")
                step("CONTROL: root's password no longer opens the volume after bob's own passwd")
            else:
                if not listed:
                    raise SessionFail(
                        "root's password no longer opens the volume: another "
                        "account's own passwd re-sealed root's key slot")
                step("the volume still opens with the password it was sealed to")
    finally:
        s.close()


def boot3():
    """Bob first: his own passwd must have re-sealed HIS slot."""
    s = Serial(ISO)
    try:
        refused(s, "bob", BOB_PW, BOOT)
        step("bob's old password is refused")
        if not login(s, "bob", BOB_PW2):
            raise SessionFail("bob's new password does not open the machine")
        if not volume_listed(s):
            raise SessionFail("bob's new password logs in but opens no key slot")
        step("bob's new password opens the volume as the first login of a boot")
    finally:
        s.close()


def run():
    if not os.environ.get("SESSION_DISK", ""):
        raise SessionFail("SESSION_DISK must name the image both boots share")
    boot1()
    boot2()
    if not CONTROL and not FIRST_SLOT:
        boot3()
    print("PASSWD_SESSION: PASS", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SessionFail as e:
        print(f"PASSWD_SESSION: FAIL {e}", file=sys.stderr, flush=True)
        sys.exit(1)
