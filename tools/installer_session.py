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
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from session_test import Serial, SessionFail  # noqa: E402

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP = float(os.environ.get("SESSION_TIMEOUT", "90"))
BOOT = float(os.environ.get("BOOT_TIMEOUT", "120"))
PASSWORD = os.environ.get("INSTALL_PASSWORD", "installpw1")
# The format is the longest operation in the run, so it gets a budget of its own
# rather than borrowing STEP: raising STEP to cover it would loosen every other
# wait in the file, including the refusal assertions, where a generous budget is
# exactly what turns a real wedge into a slow pass.
#
# THE DEFAULT IS NOT RAISED, and that is deliberate. This gate went red on `main`
# twice (2026-09-01 19:18, 2026-09-02 00:20), both times a 300s timeout here --
# and the same step takes **5.7s** on a developer machine (measured 2026-09-02,
# once this harness started timing its own steps). A shared CI runner under TCG is
# slower than a workstation, but not fifty times slower, so "the budget is too
# small" does not survive its own measurement. The knob exists so the bound can be
# argued with independently; the number stays where the evidence leaves it.
# RETIRED as the format's deadline; see expect_while_writing. Kept because
# smoke-installer-accounts and the other scenarios still pass it around, and
# because the number is the historical bound [G-13] was measured against.
FORMAT_STEP = float(os.environ.get("INSTALLER_FORMAT_TIMEOUT", "300"))
# The format's deadline is now a STALL, not a total. Sized from what it separates
# rather than from how long a format takes: the guest issues ~4,700 writes over
# the step, so 30s of complete silence is ~140 writes' worth of nothing at the
# slowest rate ever measured, and a real wedge produces it immediately.
FORMAT_STALL = float(os.environ.get("INSTALLER_FORMAT_STALL", "30"))
# Backstop only. Neither candidate reaches it: a wedge trips the stall in 30s and
# a slow disk finishes. It exists so a guest that writes forever cannot hang CI.
FORMAT_CAP = float(os.environ.get("INSTALLER_FORMAT_CAP", "900"))
USER_NAME = os.environ.get("INSTALL_USER", "alice")
USER_PASSWORD = os.environ.get("INSTALL_USER_PASSWORD", "userpw2")
USER_UID = os.environ.get("INSTALL_USER_UID", "1000")

ENTER = b"\r"
DOWN = b"\x1b[B"


_step_t0 = [time.time()]
_timeline = []

_SERIAL_LOG = os.environ.get("SESSION_SERIAL_LOG", "")
_serial_parts = [0]


def keep_serial(buf):
    """Append this boot's serial to SESSION_SERIAL_LOG, labelled.

    A GATE MUST KEEP ITS EVIDENCE IN THE CASE IT GOES RED, and this one did not.
    [G-13]'s two CI captures survive only as the 600-character tail the timeout
    message happened to quote -- which was enough to see `INSTALLER: formatting`
    and nothing after it, and not enough for anything else anybody wanted to ask.

    APPENDED AND LABELLED, not written. session_test's _dump_serial opens "w",
    which is right for a one-boot scenario and wrong here: every scenario in this
    file drives two or three boots, so the last one would overwrite the one that
    failed. Called from every scenario's finally, pass or fail.
    """
    if not _SERIAL_LOG:
        return
    _serial_parts[0] += 1
    try:
        with open(_SERIAL_LOG, "a") as fh:
            fh.write("\n===== boot %d =====\n" % _serial_parts[0])
            fh.write(buf)
    except OSError:
        pass    # a diagnostic must never be the reason a run fails


def _timeline_note():
    """This run's own step timings, for the failure message.

    The point is not decoration: the boot step is in here, and it is the step the
    [G-13] argument leaned on. A reader of a future failure can compare it
    against the ~2s this scenario takes on an idle developer machine and see for
    themselves whether the machine was uniformly slow -- rather than being told,
    as the old message told them, that it could not have been.
    """
    if not _timeline:
        return ""
    parts = ", ".join("%s %.1fs" % (m, e) for m, e in _timeline)
    return " This run's steps so far: " + parts + "."


def _io_ops(s):
    """Guest disk operations so far, from QEMU's own block statistics.

    See Serial.blockstats_ops for why this and not the image's mtime, the
    process's write_bytes, or its read-syscall count. All three were measured
    against a throttled format and all three are wrong here, in two different
    directions.
    """
    return s.blockstats_ops()


def expect_while_doing_io(s, needle, stall, cap):
    """Wait for `needle`, failing on a STALL rather than on a total budget.

    ---- WHY THIS IS NOT A TIMEOUT: finding [G-13] ---------------------------

    The installer's format step went red twice on CI, both times a 300s timeout
    with `INSTALLER: formatting` last on the wire and nothing after it. It takes
    ~6s locally, and the argument that stalled the investigation for a day was
    that a runner slow enough to explain 300s would have to be ~50x slower, which
    the boot step says it is not.

    That argument does not hold, and it was settled by measurement rather than by
    more of it (2026-09-03, numbers in docs/LIMITATIONS.md 5.2h):

      * twelve CPU burners slow the boot step AND the format by ~2.1x and leave
        the format:boot ratio at 2.6 -- CPU load does not decouple them;
      * disk contention leaves the boot at 1.9s and takes the format to 15s;
      * throttling BANDWIDTH does nothing until ~100 KB/s, because the format
        writes only ~2.3 MB;
      * throttling IOPS gives format ~= 5.2s + 4700/iops, with the BOOT STEP FLAT
        AT 1.7s at every point.

    So the format is ~4,700 synchronous PIO operations and the boot step is
    perfectly insensitive to the disk -- it cannot witness a slow disk, which is
    the whole of what the "50x" argument asked it to do. At <=16 IOPS the format
    crosses 300s, and SESSION_DISK_IOPS=12 reproduces the CI signature exactly,
    normal boot step and all.

    A TOTAL budget therefore cannot distinguish the two candidates at any value:
    raise it and a wedge takes longer to report, lower it and a slow disk fails.
    A STALL budget distinguishes them by construction -- a slow disk keeps
    writing, a wedged format does not -- so it never punishes a slow runner and
    catches a real wedge in `stall` seconds instead of five minutes.

    `cap` remains as a backstop against a guest that writes forever without
    finishing, which is neither candidate and should not hang CI.
    """
    t0 = time.time()
    # The counters are polled on their own, slower cadence than the serial pump.
    # An instrument is not free: each sample is a QMP round trip, and at the pump
    # rate a 420s format would take ~1,700 of them. Two seconds is far below the
    # 30s it has to resolve and far above anything worth worrying about.
    poll_every = 2.0
    next_poll = 0.0
    last = _io_ops(s)
    if last is None:
        raise SessionFail(
            "the format's stall bound needs QEMU's block statistics over QMP and "
            "they are unreachable. FAILING CLOSED rather than falling back to a "
            "total budget: a total budget cannot tell a slow disk from a wedge at "
            "any value, which is the whole of [G-13], and silently degrading to "
            "one would put this gate back where it started while still reporting "
            "the new wording.")
    last_change = time.time()
    while True:
        idx = s.buf.find(needle, s.pos)
        if idx >= 0:
            s.pos = idx + len(needle)
            return time.time() - t0
        now = time.time()
        if now >= next_poll:
            next_poll = now + poll_every
            cur = _io_ops(s)
            if cur is not None and cur != last:
                last, last_change = cur, now
        if now - last_change >= stall:
            raise SessionFail(
                "the format WEDGED: the guest issued no disk operation at all "
                "for %.0fs (INSTALLER_FORMAT_STALL), %.0fs after `INSTALLER: "
                "formatting`. This is not a slow runner -- a slow disk keeps "
                "doing I/O, and this one stopped.%s "
                "See docs/LIMITATIONS.md 5.2h."
                % (stall, now - t0, _timeline_note()))
        if now - t0 >= cap:
            raise SessionFail(
                "the format is STILL DOING I/O after %.0fs "
                "(INSTALLER_FORMAT_CAP) and has not finished. The guest is "
                "making progress, so this is NOT a wedge; it is a disk slower "
                "than anything measured -- the format is ~4700 synchronous ops, "
                "so finishing no sooner than this implies under %.1f IOPS. Do "
                "not raise the cap without saying what made the disk that "
                "slow.%s See docs/LIMITATIONS.md 5.2h."
                % (cap, 4700.0 / max(cap, 1.0), _timeline_note()))
        if s.proc.poll() is not None and not s._pump(0):
            raise SessionFail("QEMU exited while formatting")
        s._pump(0.25)


def step(msg):
    """Report the step AND how long it took.

    The elapsed time is not decoration. On 2026-09-01 and 2026-09-02 this gate
    went red on `main` twice, both times a 300s timeout waiting for
    `INSTALLER: PASS installed` with the screen still showing "this takes a
    moment" -- a format that had not finished inside the budget. Sizing that
    budget from the CI logs turned out to be impossible: this harness buffers
    stdout and the runner timestamps the FLUSH, so consecutive step lines land
    microseconds apart however long the guest actually took. So the harness
    measures its own steps, and the next person to argue about the number has
    data instead of the two of us guessing.

    flush=True for the same reason -- a buffered line is a line whose timestamp
    belongs to somebody else. """
    now = time.time()
    elapsed = now - _step_t0[0]
    _timeline.append((msg, elapsed))
    print(f"INSTALLER_SESSION: ok - {msg} ({elapsed:.1f}s)", flush=True)
    _step_t0[0] = now


def expect_any(s, needles, timeout):
    """Wait for whichever of `needles` appears first; return its index, or -1.

    Serial.expect takes ONE needle, so a scenario that asks "did this succeed or
    was it refused" can only wait for success and read a timeout as the answer.
    That makes every deliberate refusal cost the whole budget: this file's login
    step is sized for a boot (300s), and smoke-installer-accounts ends by
    requiring the compiled-in account to be gone -- one refusal, five minutes,
    with the guest having answered in about a second. Racing both outcomes turns
    that back into what it is, a fast negative. Related to the reasoning in
    docs/BUILDING.md on bounds: a budget is what a FAILING path spends.
    """
    deadline = time.time() + timeout
    while True:
        best, which = None, -1
        for i, n in enumerate(needles):
            idx = s.buf.find(n, s.pos)
            if idx >= 0 and (best is None or idx < best):
                best, which = idx, i
        if which >= 0:
            s.pos = best + len(needles[which])
            return which
        if time.time() >= deadline:
            return -1
        s._pump(0.25)


def login(s, user, pw, timeout=None):
    """One login attempt. True on a shell prompt, False on a refusal.

    Matches "@horus" and not "@horus#": the prompt's last character is the uid --
    `#` for root and `$` for everyone else -- so the root form would score every
    unprivileged login in this file as a refusal.

    A refusal is read from the shell SAYING SO rather than from a timeout, so an
    expected refusal is quick and an unexpected hang is still a timeout. The two
    are different answers and were previously the same one.
    """
    t = timeout if timeout is not None else STEP
    s.expect("horus login:", t)
    s.send(user)
    s.expect("Password:", t)
    s.send(pw)
    return expect_any(s, ["@horus", "Login incorrect"], t) == 0


def answer_accounts(s, root_pw=None, user=None, user_pw=None):
    """Answer every account screen the installer asks, in order.

    ONE PLACE, BECAUSE FOUR COPIES IS WHAT BROKE. Each scenario in this file
    drives the same conversation and diverges only at the end, and when the
    installer grew the two user-account screens on 2026-09-02 exactly one of the
    four copies was taught about them. `smoke-installer` then sat at the username
    prompt and timed out after 300s waiting for `INSTALLER: PASS installed` -- a
    green gate turned red by a change to a screen it never asserts on, reported
    as a timeout, which is the failure shape docs/LIMITATIONS.md 2.6a exists to
    complain about. A harness that mirrors a conversation has to mirror it once.

    Every step is driven off the marker the installer emits when it BLOCKS, never
    off drawn text: tui_flush emits changed cells behind a cursor address, so
    what is on the screen is not a contiguous string on the wire.
    """
    root_pw = PASSWORD if root_pw is None else root_pw
    user = USER_NAME if user is None else user
    user_pw = USER_PASSWORD if user_pw is None else user_pw

    s.expect("INSTALLER: waiting on the password", STEP)
    os.write(s.fd, root_pw.encode() + ENTER)
    s.expect("INSTALLER: waiting on the password again", STEP)
    os.write(s.fd, root_pw.encode() + ENTER)

    s.expect("INSTALLER: waiting on the user name", STEP)
    os.write(s.fd, user.encode() + ENTER)
    s.expect("INSTALLER: waiting on the user password", STEP)
    os.write(s.fd, user_pw.encode() + ENTER)
    s.expect("INSTALLER: waiting on the user password again", STEP)
    os.write(s.fd, user_pw.encode() + ENTER)


def answer_confirm(s, word=b"FORMAT", first_timeout=None):
    """Choose Continue, then type the confirmation word.

    Cancel is the default and the cursor starts on it, so reaching Continue takes
    a deliberate keystroke -- which is the property being relied on, so the
    harness presses it rather than assuming it.
    """
    s.expect("INSTALLER: waiting on the destroy-this-disk choice",
             STEP if first_timeout is None else first_timeout)
    os.write(s.fd, DOWN)
    os.write(s.fd, ENTER)
    s.expect("INSTALLER: waiting on the typed confirmation", STEP)
    os.write(s.fd, word + ENTER)


def boot1(disk):
    """Drive the installer to completion on a blank disk."""
    s = Serial(ISO)
    try:
        s.expect("INIT_STORAGE: disk present", BOOT)
        step("init surveyed the disk and found no volume")
        s.expect("no Horus volume -- an install is needed", STEP)

        s.expect("init: this machine has a disk and no volume; running the installer", STEP)
        step("init launched the installer rather than a login prompt")

        # The destroy-this-disk choice, then the typed word -- a menu can be
        # reached by holding return, a word cannot -- then every account screen.
        answer_confirm(s)
        step("chose to continue and typed the confirmation word")
        answer_accounts(s)
        step("answered both accounts' screens")

        # THE PASSWORD MUST NOT BE ON THE WIRE. The mask is a property of what
        # tui_input DRAWS, and this is the end-to-end version of the check
        # smoke-tui-mask-control makes against the cell buffers: whatever the
        # library did, the characters must not have reached the terminal. The
        # console server does not echo in raw mode, so a hit here means either
        # the mask or the raw-mode contract failed.
        s.expect("INSTALLER: formatting", STEP)
        if PASSWORD in s.buf or USER_PASSWORD in s.buf:
            raise SessionFail("a password appeared on the serial line")
        step("neither password reached the terminal")

        # FORMAT_STEP, not STEP: everything between `formatting` and this marker
        # is one uninterruptible write of the whole volume. A timeout here means
        # the format did not finish in the budget -- which on a slow runner is a
        # budget problem and not a defect -- so it is reported as its own thing
        # rather than as a generic step timeout that reads like a wedge.
        took = expect_while_doing_io(s, "INSTALLER: PASS installed",
                                    FORMAT_STALL, FORMAT_CAP)
        step(f"the installer reported a completed install [{took:.0f}s of writing]")

        # It hands the machine back: a login prompt on the same boot.
        s.expect("horus login:", STEP)
        step("init went on to a login prompt on the same boot")
    finally:
        keep_serial(s.buf)
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
        keep_serial(s.buf)
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
        # Not the word. Deliberately something a hurried operator might type.
        answer_confirm(s, b"yes")
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
            step("CONTROL: the wrong word was accepted and the install continued")
            answer_accounts(s)
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
        keep_serial(s.buf)
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
        answer_confirm(s)
        answer_accounts(s)
        # Same stall bound as boot1's, and for the same reason: every scenario in
        # this file formats a volume, so every one of them was exposed to [G-13].
        expect_while_doing_io(s, "INSTALLER: PASS installed", FORMAT_STALL, FORMAT_CAP)
        s.expect("horus login:", STEP)
        step("boot 1: installed, and powered off at the login prompt without logging in")
    finally:
        keep_serial(s.buf)
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
        keep_serial(s.buf)
        s.close()


def accounts(disk):
    """Install two accounts, power off, and let the UNPRIVILEGED one boot the machine.

    THE FIRST LOGIN OF BOOT 2 IS THE WHOLE PROPERTY. `h_auth` calls
    users_unlock_and_restore(typed_password) BEFORE it consults the account
    table, because on a sealed volume the table it would otherwise read is the
    compiled-in one users_init seeded. An account with no key slot therefore
    opens nothing, the persisted table is never loaded, the account is not found,
    and the login is refused -- while working perfectly on a machine somebody
    else has already unlocked. That asymmetry is docs/LIMITATIONS.md 2.6b, and it
    is why a test that logs in as root first can never see it.

    So this arm logs in as the USER first, on a machine nobody has opened.

    BOTH ARMS ASSERT POSITIVELY, and the control's third step is the one that
    makes the pair mean something. Under PASSWD_NO_KEYSLOT the user's first
    login is refused (`Login incorrect`, which is text on the wire, not an
    absence) -- and then root logs in, and then the SAME user logs in in the same
    boot. That last step separates "this account is broken" from "this account
    has no key slot": the account is fine, the volume was the thing it could not
    open.
    """
    control = os.environ.get("INSTALLER_EXPECT_NO_SLOT") == "1"

    # ---- boot 1: install, two accounts ----
    s = Serial(ISO)
    try:
        answer_confirm(s, first_timeout=BOOT)
        answer_accounts(s)
        step("answered the root password, then named the everyday account")

        expect_while_doing_io(s, "INSTALLER: PASS installed", FORMAT_STALL, FORMAT_CAP)
        # NEITHER password may reach the terminal. The user's field is masked by
        # the same tui_input flag as root's, so this is the second half of the
        # check smoke-tui-mask-control makes against the cell buffers.
        if PASSWORD in s.buf or USER_PASSWORD in s.buf:
            raise SessionFail("a password appeared on the serial line")
        step("both accounts installed, neither password on the wire")
        s.expect("horus login:", STEP)
    finally:
        keep_serial(s.buf)
        s.close()

    # ---- boot 2: the same disk, sealed, nobody has opened it ----
    s = Serial(ISO)
    try:
        first = login(s, USER_NAME, USER_PASSWORD, BOOT)
        if control:
            if first:
                raise SessionFail(
                    "CONTROL: the user opened the volume; the missing key slot did not reproduce")
            step("CONTROL: the user was refused as the first login of the boot")
            if not login(s, "root", PASSWORD):
                raise SessionFail("CONTROL: root could not log in either")
            step("CONTROL: root logged in, so the machine and the volume are fine")
            s.send("logout")
            if not login(s, USER_NAME, USER_PASSWORD):
                raise SessionFail(
                    "CONTROL: the user is refused even on an opened machine, so the "
                    "account itself is broken and this arm proves nothing about key slots")
            step("CONTROL: the same user logs in once root has opened the volume -- "
                 "the account was never the problem, the key slot was")
        else:
            if not first:
                raise SessionFail(
                    "2.6b is not closed: the user cannot be the first login after a power cycle")
            step("the unprivileged account was the FIRST login after a power cycle")
            s.send("whoami")
            s.expect("uid=%s" % USER_UID, STEP)
            step("and it is the uid the installer created, not root")

            # ---- THE FILESYSTEM, ON A REAL VOLUME ---------------------------
            #
            # Until 2026-09-02 no gate touched the filesystem after unlocking an
            # installed volume: this scenario and smoke-installer both logged in,
            # ran `whoami`, and logged out. That is the one path on which
            # fs_server's provisioning runs LATE -- a sealed volume defers it
            # until a login unlocks it (S74) -- so the whole of it was exercised
            # only on the ephemeral RAM vdisk, where it runs at boot instead.
            #
            # An operator reported `ls` hanging on an installed machine on
            # 2026-09-02. It did not reproduce, in three shapes including this
            # one, and the cause was most likely host contention rather than the
            # guest. The gap it exposed is real either way: a regression of
            # exactly that shape would have shipped green.
            #
            # `ls` first, because "the server answers at all" is the weaker claim
            # and has to hold before the stronger one means anything.
            s.expect("%s@horus$" % USER_NAME, STEP)
            s.send("ls")
            s.expect("bin/", STEP)
            step("the filesystem answers an unprivileged login on the installed volume")

            # And S78 on a REAL volume rather than the RAM vdisk: the account has
            # a home directory it owns and can write in. On this path the
            # directory is created when the login unlocks the store, not at boot.
            s.expect("%s@horus$" % USER_NAME, STEP)
            s.send("cd /home/%s" % USER_NAME)
            s.expect("%s@horus$" % USER_NAME, STEP)
            s.send("mkdir installed_home_probe")
            s.expect("mkdir: created installed_home_probe", STEP)
            step("S78 on the installed volume: the home exists, is the account's, "
                 "and it can write there")
            s.send("cd /")

            s.send("logout")
            if not login(s, "root", PASSWORD):
                raise SessionFail("root could not log in on its own key slot")
            step("root logs in too, on a slot of its own")
            s.send("logout")
            # The compiled-in account must NOT have been persisted onto the volume.
            # users_init seeds `user`/`password` and a fresh volume's table is
            # seeded from that RAM image, so without the installer deleting it
            # every installed machine would ship a login whose password is in the
            # source. Asserted as a refusal that is fenced by two successes above,
            # so a boot that reached no prompt cannot satisfy it.
            if login(s, "user", "password"):
                raise SessionFail("the compiled-in user/password account survived the install")
            step("the compiled-in user/password account is not on the installed volume")
    finally:
        keep_serial(s.buf)
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
    if mode == "accounts":
        accounts(disk)
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
