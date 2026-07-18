#!/usr/bin/env python3
"""
Scripted integration session — drives the *real* ring-3 shell over serial.

Where the marker-based self-tests compile an assertion into the kernel and only
watch the serial log, this harness treats Horus as a black box: it boots the
shipped kernel under QEMU, opens COM1 as a bidirectional terminal, and types at
the login prompt and shell exactly as a user would — asserting on what comes
back. It is the seed of the Phase 5 scripted integration harness.

The scenario proves security properties end-to-end through the actual syscall
path (sys_auth / sys_getuid / sys_useradd), not a compiled-in shortcut:

  * authentication rejects a wrong password and accepts the right one,
  * the kernel-attested identity is what `whoami` reports,
  * a capability-gated admin op (useradd) is ALLOWED for root but DENIED for a
    standard user — i.e. no ambient authority; least privilege is enforced
    against the login identity, not anything the client asserts.

Usage:  tools/session_test.py [boot.iso]
Env:    SESSION_TIMEOUT   per-step expect timeout, seconds (default 45)
        BOOT_TIMEOUT      time to reach the first login prompt (default 90)
Exit:   0 and "SESSION_TEST: PASS" on success; 1 and "SESSION_TEST: FAIL ..." otherwise.
"""

import os
import re
import select
import shutil
import subprocess
import sys
import time

ISO = sys.argv[1] if len(sys.argv) > 1 else "boot.iso"
STEP_TIMEOUT = float(os.environ.get("SESSION_TIMEOUT", "45"))
BOOT_TIMEOUT = float(os.environ.get("BOOT_TIMEOUT", "90"))

# Any of these on the wire means the kernel faulted — fail the run immediately.
FAULT_RE = re.compile(r"PAGE FAULT|Exception! Vector|PANIC|Rejected by validator")


class SessionFail(Exception):
    pass


class Serial:
    """A COM1 terminal backed by a QEMU-created pty."""

    def __init__(self, iso):
        qemu = shutil.which("qemu-system-x86_64")
        if not qemu:
            print("SESSION SKIP: qemu-system-x86_64 not found", file=sys.stderr)
            sys.exit(2)
        if not os.path.isfile(iso):
            raise SessionFail(f"ISO '{iso}' not found (run 'make boot.iso' first)")

        # -serial pty: QEMU allocates a pty for COM1 and prints its path on
        # stderr. -accel tcg for CI hosts without /dev/kvm; -no-reboot so a
        # triple fault halts (and QEMU exits) instead of looping.
        # Merge stderr into stdout and keep it a PIPE: QEMU prints the pty path
        # ("char device redirected to /dev/pts/N") on one of them at startup, and
        # we must not block waiting on the wrong stream.
        self.proc = subprocess.Popen(
            [qemu,
             "-m", "512M", "-cpu", "qemu64,+aes,+rdrand,+smep,+smap", "-accel", "tcg",
             "-display", "none", "-no-reboot", "-no-shutdown",
             "-device", "isa-debug-exit,iobase=0x604,iosize=0x04",
             "-serial", "pty", "-net", "none", "-cdrom", iso],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        self.fd = self._await_pty()
        self.buf = ""      # everything seen so far
        self.pos = 0       # cursor: expect() only matches at/after here

    def _await_pty(self):
        deadline = time.time() + 15
        pat = re.compile(rb"char device redirected to (\S+)")
        out = self.proc.stdout
        seen = b""
        while time.time() < deadline:
            r, _, _ = select.select([out], [], [], min(0.5, max(0.0, deadline - time.time())))
            if r:
                chunk = os.read(out.fileno(), 4096)
                if chunk:
                    seen += chunk
                    m = pat.search(seen)
                    if m:
                        return os.open(m.group(1).decode(), os.O_RDWR | os.O_NOCTTY)
            if self.proc.poll() is not None and not r:
                raise SessionFail("QEMU exited before allocating a serial pty")
        raise SessionFail("QEMU never reported its serial pty path")

    def _pump(self, timeout):
        """Drain available bytes for up to `timeout` seconds into self.buf."""
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return False
        try:
            chunk = os.read(self.fd, 4096)
        except OSError:
            return False
        if chunk:
            self.buf += chunk.decode("latin-1", "replace")
        return bool(chunk)

    def expect(self, needle, timeout):
        """Wait until `needle` appears at/after the cursor; advance past it."""
        deadline = time.time() + timeout
        while True:
            idx = self.buf.find(needle, self.pos)
            if idx >= 0:
                self.pos = idx + len(needle)
                return
            fault = FAULT_RE.search(self.buf, self.pos)
            if fault:
                raise SessionFail(f"kernel fault on serial: {fault.group(0)!r}")
            if self.proc.poll() is not None and not self._pump(0):
                raise SessionFail(f"QEMU exited while waiting for {needle!r}")
            if time.time() >= deadline:
                raise SessionFail(f"timeout after {timeout:.0f}s waiting for {needle!r}")
            self._pump(min(0.5, max(0.0, deadline - time.time())))

    def send(self, line):
        os.write(self.fd, (line + "\n").encode("latin-1"))

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass


def run():
    s = Serial(ISO)
    try:
        # --- reach the login prompt --------------------------------------
        s.expect("horus login:", BOOT_TIMEOUT)
        step("reached login prompt")

        # --- 1. a wrong password is rejected -----------------------------
        s.send("root"); s.expect("Password:", STEP_TIMEOUT)
        s.send("wrongpass"); s.expect("Login incorrect", STEP_TIMEOUT)
        step("wrong password rejected")

        # --- 2. the correct root password is accepted --------------------
        s.expect("horus login:", STEP_TIMEOUT)
        s.send("root"); s.expect("Password:", STEP_TIMEOUT)
        s.send("rootpass")
        s.expect("Welcome, root", STEP_TIMEOUT)
        s.expect("administrator (root)", STEP_TIMEOUT)
        step("root login accepted")

        # --- 3. whoami reports the kernel-attested identity --------------
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("whoami"); s.expect("uid=0 (root)", STEP_TIMEOUT)
        step("whoami reports uid 0 (root)")

        # --- 4. a capability-gated admin op is ALLOWED for root ----------
        s.send("useradd 1234 alice"); s.expect("user added", STEP_TIMEOUT)
        step("useradd allowed for root")

        # --- 4a. the manual: man / whatis / apropos -----------------------
        #        These are the shell's own reference pages, held in the binary
        #        (there is no /usr/share/man to read), so they work before any
        #        filesystem is mounted. Assert the man page renders its sections
        #        rather than just printing something: a page missing SYNOPSIS or
        #        SEE ALSO is the failure worth catching, and an unknown command
        #        must say so rather than silently print nothing.
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("man ls")
        s.expect("ls - list directory entries", STEP_TIMEOUT)
        s.expect("SYNOPSIS", STEP_TIMEOUT)
        s.expect("SEE ALSO", STEP_TIMEOUT)
        step("man renders a full reference page")

        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("whatis stat"); s.expect("show a file's metadata", STEP_TIMEOUT)
        step("whatis prints the one-line summary")

        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("apropos directory"); s.expect("mkdir", STEP_TIMEOUT)
        step("apropos finds pages by keyword")

        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("man nosuchthing"); s.expect("No manual entry", STEP_TIMEOUT)
        step("man reports an unknown page instead of printing nothing")

        # --- 4b. filesystem coreutils drive the real shell + fs_server ----
        #        cd/pwd/mkdir/ls -l/echo/cat/wc/cp/mv/stat over the encrypted
        #        fs_server, all relative to a working directory. Each step first
        #        consumes the prompt left by the previous command so the next
        #        command's output can't be confused with a stale prompt.
        #
        #        ls reports "(empty)" only when it read a directory to its end,
        #        never as the silent answer to a failed/denied readdir. A fresh
        #        volume is really empty; after mkdir, ls lists the entry and
        #        terminates at end-of-directory (the load-bearing NOENT stop:
        #        drop it and ls either lists nothing or spins to its 4096 cap).
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("ls"); s.expect("(empty)", STEP_TIMEOUT)
        step("ls reports (empty) on a fresh volume")
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("mkdir sess_d"); s.expect("mkdir: created sess_d", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("ls"); s.expect("sess_d/", STEP_TIMEOUT)
        step("ls lists a real entry and stops at end-of-directory")
        s.expect("root@horus#", STEP_TIMEOUT)
        # ls -l is a table now: a header row, then aligned columns. Assert the
        # header and the directory's mode string, so a regression in the column
        # layout shows up here rather than only to the eye.
        s.send("ls -l"); s.expect("Mode", STEP_TIMEOUT)
        s.expect("drwxr-xr-x", STEP_TIMEOUT)
        step("ls -l prints an aligned table with a header")
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("cd sess_d")                       # no output; next prompt confirms
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("pwd"); s.expect("/sess_d", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("echo hello > note")               # no output on success
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("cat note"); s.expect("hello", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("wc note"); s.expect("5  note", STEP_TIMEOUT)   # 0 lines, 1 word, 5 bytes
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("cp note note2"); s.expect("cp: copied to note2", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("cat note2"); s.expect("hello", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("mv note2 note3"); s.expect("mv: note2 -> note3", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("ls -l"); s.expect("note3", STEP_TIMEOUT)
        s.expect("root@horus#", STEP_TIMEOUT)
        # stat's labels are padded into a column now, and a regular file is
        # named as one (POSIX's term, and what real stat(1) prints), so match the
        # value rather than the old unpadded "Type: file".
        s.send("stat note"); s.expect("regular file", STEP_TIMEOUT)
        s.expect("-rw-r--r--", STEP_TIMEOUT)   # symbolic mode column
        s.expect("root@horus#", STEP_TIMEOUT)
        s.send("cd /")                            # back to root for the logout below
        step("filesystem coreutils (cd/pwd/ls -l/cp/mv/wc/stat) work as root")

        # --- 5. log out and log back in as a standard user ---------------
        s.send("logout"); s.expect("Logging out", STEP_TIMEOUT)
        s.expect("horus login:", STEP_TIMEOUT)
        s.send("user"); s.expect("Password:", STEP_TIMEOUT)
        s.send("password")
        s.expect("Welcome, user", STEP_TIMEOUT)
        s.expect("standard user", STEP_TIMEOUT)
        step("standard-user login accepted")

        s.expect("user@horus$", STEP_TIMEOUT)
        s.send("whoami"); s.expect("uid=1000", STEP_TIMEOUT)
        step("whoami reports uid 1000")

        # --- 6. the same admin op is DENIED for a standard user ----------
        #        The point of the whole session: authority derives from the
        #        login identity the kernel attests, never from the request.
        s.send("useradd 1235 eve"); s.expect("useradd failed", STEP_TIMEOUT)
        step("useradd denied for standard user (least privilege enforced)")

        # --- 7. sudo refuses to take the password on the command line ----
        #        It would be echoed to the console and mirrored to the serial
        #        log, which is where this was found: the password was legible
        #        in a pasted session transcript.
        s.send("sudo password"); s.expect("takes no argument", STEP_TIMEOUT)
        step("sudo rejects a command-line password")

        # --- 8. a wrong password at the sudo prompt is rejected -----------
        s.send("sudo"); s.expect("Password:", STEP_TIMEOUT)
        s.send("wrongpass"); s.expect("incorrect password or locked out", STEP_TIMEOUT)
        step("sudo rejects a wrong password")

        # --- 9. the CORRECT password does not report "invalid argument" ---
        #        The regression this encodes: sudo authenticated, then failed
        #        the armed-image check and reported SYS_ERR_INVAL — so typing
        #        the right password blamed the password. Nothing is armed here,
        #        so the honest answer is "nothing to elevate".
        s.send("sudo"); s.expect("Password:", STEP_TIMEOUT)
        s.send("password"); s.expect("no image is armed", STEP_TIMEOUT)
        step("sudo with the correct password reports the real reason")

    finally:
        transcript = s.buf
        s.close()

    return transcript


def step(msg):
    print(f"  [ok] {msg}", flush=True)


def main():
    print(f"SESSION_TEST: driving the ring-3 shell over serial ({ISO})", flush=True)
    try:
        transcript = run()
    except SessionFail as e:
        print(f"\nSESSION_TEST: FAIL — {e}", file=sys.stderr, flush=True)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        print(f"\nSESSION_TEST: FAIL — unexpected {type(e).__name__}: {e}",
              file=sys.stderr, flush=True)
        sys.exit(1)
    _ = transcript
    print("SESSION_TEST: PASS", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
