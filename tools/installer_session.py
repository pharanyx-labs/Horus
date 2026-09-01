#!/usr/bin/env python3
"""installer_session.py — install onto a bare disk, then boot what was installed.

TWO BOOTS ON ONE IMAGE, and the second boot is the whole point. A format that
returns 0 is not an install; the claim being made is "this machine now boots what
was put on it", and that is a property of the NEXT power cycle, not of a return
code. So boot 1 drives the installer to completion and boot 2 powers the machine
on again and logs in with the password the installer was given.

WHY BOOT 2 IS NOT OPTIONAL. The volume is sealed to a password and the root
account is verified against a password, by different mechanisms with different
salts. An installer that sealed the volume and left the account on its
compiled-in default produces a disk that is perfectly installed and that nobody
can log into -- and boot 1 cannot tell, because everything it can observe
succeeded. Only a login can.

WHY IT DRIVES ON MARKERS AND TYPES BLIND. The installer is a full-screen program:
tui_flush emits a run of changed cells behind a cursor address, so what is on the
screen is not a contiguous string on the wire, and which cells change depends on
what the previous screen left behind. Expecting on drawn text would be reading a
picture. Each point at which the installer blocks for a key announces itself with
one console write instead, and those are the sync points.

Usage:  installer_session.py [boot.iso]
Env:    SESSION_DISK      the disk image; REQUIRED, and the same one for both boots
        INSTALLER_MODE    "refuse" or "provision"; default is the install-then-login pair
        INSTALLER_EXPECT_EMPTY_BIN  provision mode's control arm: require the empty /bin
        INSTALL_PASSWORD  the password to install with (default "installpw1")
        SESSION_TIMEOUT   per-step expect timeout (default 90; formatting is slow)
        BOOT_TIMEOUT      time to the first marker (default 120)
Exit:   0 and "INSTALLER_SESSION: PASS"; 1 and a FAIL line otherwise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "90"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "120"))
PASSWORD = os.environ.get("INSTALL_PASSWORD", "installpw1")

ENTER = b"\r"
DOWN = b"\x1b[B"


def step(msg):
    print(f"INSTALLER_SESSION: ok - {msg}")


def boot1(disk):
    """Drive the installer to completion on a blank disk."""
    s = Serial(ISO)
    try:
        s.expect("INIT_STORAGE: disk present", BOOT)
        step("init surveyed the disk and found no volume")
        s.expect("no Horus volume -- an install is needed", STEP)

        s.expect("init: this machine has a disk and no volume; running the installer", STEP)
        step("init launched the installer rather than a login prompt")

        # 1. the destroy-this-disk choice. Cancel is the default and the cursor
        #    starts on it, so reaching Continue takes a deliberate keystroke --
        #    which is exactly the property being relied on, so the harness has to
        #    press it rather than assume it.
        s.expect("INSTALLER: waiting on the destroy-this-disk choice", STEP)
        os.write(s.fd, DOWN)
        os.write(s.fd, ENTER)
        step("chose to continue")

        # 2. the typed confirmation. A menu can be reached by holding return; a
        #    word cannot.
        s.expect("INSTALLER: waiting on the typed confirmation", STEP)
        os.write(s.fd, b"FORMAT" + ENTER)
        step("typed the confirmation word")

        # 3. the password, twice, masked.
        s.expect("INSTALLER: waiting on the password", STEP)
        os.write(s.fd, PASSWORD.encode() + ENTER)
        s.expect("INSTALLER: waiting on the password again", STEP)
        os.write(s.fd, PASSWORD.encode() + ENTER)
        step("entered the password twice")

        # THE PASSWORD MUST NOT BE ON THE WIRE. The mask is a property of what
        # tui_input DRAWS, and this is the end-to-end version of the check
        # smoke-tui-mask-control makes against the cell buffers: whatever the
        # library did, the characters must not have reached the terminal. The
        # console server does not echo in raw mode, so a hit here means either
        # the mask or the raw-mode contract failed.
        s.expect("INSTALLER: formatting", STEP)
        if PASSWORD in s.buf:
            raise SessionFail("the password appeared on the serial line")
        step("the password never reached the terminal")

        s.expect("INSTALLER: PASS installed", STEP)
        step("the installer reported a completed install")

        # It hands the machine back: a login prompt on the same boot.
        s.expect("horus login:", STEP)
        step("init went on to a login prompt on the same boot")
    finally:
        s.close()


def boot2(disk):
    """Power on again and use what was installed."""
    s = Serial(ISO)
    try:
        s.expect("INIT_STORAGE: disk present", BOOT)
        # The volume is recognised now, so the machine must NOT offer to install
        # again. Asserted positively -- on the survey saying a volume is present
        # -- rather than by the absence of the installer marker, because an
        # absence is satisfied by a boot that got nowhere.
        s.expect("a Horus volume is present", STEP)
        step("the second boot recognised the volume the installer wrote")

        s.expect("horus login:", BOOT)
        if "running the installer" in s.buf:
            raise SessionFail("the installer ran again on a machine that has a volume")
        step("no installer on a machine that already has a volume")

        # THE CLAIM THIS GATE EXISTS FOR. Log in with the password the installer
        # was given -- which the volume's seal and the root account must BOTH
        # accept, by two different mechanisms.
        s.send("root")
        s.expect("Password:", STEP)
        s.send(PASSWORD)
        s.expect("Welcome, root", STEP)
        step("logged in with the password the installer was given")

        s.expect("root@horus#", STEP)
        s.send("ls")
        s.expect("bin/", STEP)
        step("the base system is on the installed volume")
    finally:
        s.close()


def refuse(disk):
    """Answer the confirmation with the wrong word; require nothing to be written.

    THIS IS THE HALF THAT MATTERS MOST, and it is the S63 lesson one layer up:
    there, a password typed at a login prompt was taken as consent to format, and
    the repair was to make formatting need an act that means only that. Here the
    act is a typed word, and this arm is what shows the word is load-bearing
    rather than decorative.

    BOTH DIRECTIONS ARE ASSERTED POSITIVELY. It requires "nothing was written" to
    be PRESENT and "INSTALLER: formatting" to be ABSENT -- and the absence alone
    would be satisfied by a run that never reached the installer at all, which is
    exactly how the first version of the S63 pair passed vacuously. Under
    INSTALLER_NO_CONFIRM=1 the comparison is gone and the same keystrokes produce
    "formatting", which is the control arm.
    """
    s = Serial(ISO)
    try:
        s.expect("init: this machine has a disk and no volume; running the installer", BOOT)
        s.expect("INSTALLER: waiting on the destroy-this-disk choice", STEP)
        os.write(s.fd, DOWN)
        os.write(s.fd, ENTER)
        s.expect("INSTALLER: waiting on the typed confirmation", STEP)

        # Not the word. Deliberately something a hurried operator might type.
        os.write(s.fd, b"yes" + ENTER)
        step("answered the confirmation with the wrong word")

        if os.environ.get("INSTALLER_EXPECT_FORMAT") == "1":
            # CONTROL ARM. With the comparison compiled out the wrong word is
            # accepted, and the FIRST observable is that the installer moves on to
            # the password screen at all -- a screen the base arm never reaches.
            #
            # THE ARM DOES NOT STOP THERE, and the first version of it did, which
            # is why this comment exists. It asserted "INSTALLER: formatting"
            # immediately after the wrong word and timed out: the installer was
            # sitting at the password prompt, waiting for input the refuse-mode
            # harness never sends. The defect had reproduced perfectly and the arm
            # reported a timeout -- an arm asserting the right property at the
            # wrong point in the conversation.
            #
            # So the arm answers the remaining questions and requires the FORMAT.
            # That is the stronger statement anyway: not merely that consent was
            # skipped, but that the whole install proceeds to destroy the disk
            # without it. A refusal test needs the ungated path to actually
            # succeed, and succeeding here means reaching the format.
            s.expect("INSTALLER: waiting on the password", STEP)
            step("CONTROL: the wrong word was accepted and the install continued")
            os.write(s.fd, PASSWORD.encode() + ENTER)
            s.expect("INSTALLER: waiting on the password again", STEP)
            os.write(s.fd, PASSWORD.encode() + ENTER)
            s.expect("INSTALLER: formatting", STEP)
            step("CONTROL: the disk was formatted without the confirmation word")
            print("INSTALLER_SESSION: PASS (control arm reproduced)")
            return

        s.expect("INSTALLER: nothing was written", STEP)
        if "INSTALLER: formatting" in s.buf:
            raise SessionFail("the disk was formatted despite the wrong confirmation word")
        step("nothing was written, and the format was never reached")

        # And the machine still has no volume: the survey on the way to the login
        # prompt is the disk's own account of itself, which a marker is not.
        s.expect("horus login:", STEP)
        step("the machine went on to a login prompt with the disk untouched")
    finally:
        s.close()


def provision(disk):
    """Install, power off BEFORE logging in, boot again, and require a /bin.

    THE POWER-OFF IS THE EXPERIMENT, not a shortcut. fs_server copies the base
    system into the store the moment the volume becomes readable, which on boot 1
    is when the installer formats it -- so an operator who installs and walks away
    at the login prompt leaves that copy unfinished. What the machine must do on
    the NEXT boot is finish it. That is the only boot on which S74 is observable,
    and it is a boot every real install passes through.

    WHAT WENT WRONG, so the arm is read as the measurement it is. The store used
    to answer SYS_FS_STAT on a SEALED volume -- mounted and locked, the normal
    state of an installed machine before its password is typed -- because the
    handlers tested `mounted` and not `unlocked`. fs_server asks exactly that
    question at startup to decide whether the store is usable, got yes, ran the
    copy against a locked volume where every data write failed inside the AEAD,
    and recorded itself provisioned anyway; the post-login retry never ran again.
    Measured 2026-09-01 on this sequence: `/bin` empty on that disk on every
    subsequent boot, permanently.

    BOTH ARMS ASSERT A MARKER POSITIVELY, and the marker is the branch fs_server
    took rather than the absence of one. The base arm requires the store to say it
    was SEALED at startup; the control requires it to say it was OPEN -- on the
    same disk, in the same state, with only STORE_LOCKED_UNCHECKED between them.
    An arm that asserted only "/bin is empty" would be satisfied by a run that
    never reached a shell, which is how the S63 pair first passed vacuously.

    The `ls` is the consequence and is checked in both directions too: present in
    the base arm, absent in the control. `basename` is the probe rather than the
    whole listing because the listing is a shell-formatted column layout and one
    name is a contiguous string on the wire.
    """
    control = os.environ.get("INSTALLER_EXPECT_EMPTY_BIN") == "1"

    # ---- boot 1: install, then power off at the login prompt ----
    s = Serial(ISO)
    try:
        s.expect("init: this machine has a disk and no volume; running the installer", BOOT)
        s.expect("INSTALLER: waiting on the destroy-this-disk choice", STEP)
        os.write(s.fd, DOWN)
        os.write(s.fd, ENTER)
        s.expect("INSTALLER: waiting on the typed confirmation", STEP)
        os.write(s.fd, b"FORMAT" + ENTER)
        s.expect("INSTALLER: waiting on the password", STEP)
        os.write(s.fd, PASSWORD.encode() + ENTER)
        s.expect("INSTALLER: waiting on the password again", STEP)
        os.write(s.fd, PASSWORD.encode() + ENTER)
        s.expect("INSTALLER: PASS installed", STEP)
        s.expect("horus login:", STEP)
        step("boot 1: installed, and powered off at the login prompt without logging in")
    finally:
        s.close()

    # ---- boot 2: the same disk, now carrying a sealed volume ----
    s = Serial(ISO)
    try:
        if control:
            s.expect("FS_STORE: open at startup; provisioning now", BOOT)
            step("CONTROL: the sealed store answered, so fs_server provisioned against a locked volume")
        else:
            s.expect("FS_STORE: sealed at startup; provisioning deferred until unlock", BOOT)
            step("the sealed store refused, so fs_server deferred to the post-login pass")

        s.expect("horus login:", BOOT)
        s.send("root")
        s.expect("Password:", STEP)
        s.send(PASSWORD)
        s.expect("root@horus#", STEP)
        step("logged in with the password the installer was given")

        # Everything from here is the answer to one `ls`, so the window is cut at
        # the prompt before it: a `basename` printed earlier in the boot (the
        # provisioning log, say) must not be read as a directory entry.
        s.send("cd bin")
        s.expect("root@horus#", STEP)
        mark = len(s.buf)
        s.send("ls")
        s.expect("root@horus#", STEP)
        listing = s.buf[mark:]

        if control:
            if "basename" in listing:
                raise SessionFail("CONTROL: /bin was provisioned; the defect did not reproduce")
            step("CONTROL: /bin is empty on the installed disk, and no later boot repairs it")
        else:
            if "basename" not in listing:
                raise SessionFail("/bin is empty on the installed disk")
            step("the base system is on the volume, provisioned by the post-login pass")
    finally:
        s.close()


def run():
    disk = os.environ.get("SESSION_DISK", "")
    if not disk:
        raise SessionFail("SESSION_DISK must name the image both boots share")
    mode = os.environ.get("INSTALLER_MODE")
    if mode == "refuse":
        refuse(disk)
        print("INSTALLER_SESSION: PASS")
        return 0
    if mode == "provision":
        provision(disk)
        print("INSTALLER_SESSION: PASS")
        return 0
    boot1(disk)
    boot2(disk)
    print("INSTALLER_SESSION: PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SessionFail as e:
        print(f"INSTALLER_SESSION: FAIL {e}", file=sys.stderr)
        sys.exit(1)
