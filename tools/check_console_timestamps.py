#!/usr/bin/env python3
"""Fail if any line of the BOOT LOG reaches the console without a timestamp.

WHAT THE PROPERTY IS. From the kernel's first message to the moment the session
starts, every non-blank line on the console carries a `[    S.uuuuuu] ` prefix,
and the prefixes do not go backwards. Both halves matter and they fail
separately: a log can be fully stamped and still unreadable if the stamps
disagree about when now is.

WHY IT NEEDS A CHECKER AND NOT A MARKER. The old rule was "call kmsg() instead of
print()", enforced by nothing, and roughly half the boot console did not follow
it -- `  [ OK ] ...` from crypto.c and main.c, every ring-3 line arriving through
SYS_WRITE (which cannot call kmsg() at all), and console_server's own status
lines. A gate that asserted one marker would have said nothing about the next
line somebody adds. So the assertion is over EVERY line in the window instead:
the only way to pass is for the writer to stamp, which is what
src/kernel/terminal.c and userspace/console_server.c now do.

THE WINDOW. It opens at the kernel's first line and closes at the shell's
banner, which is the first output of the session. Nothing after that is checked
and nothing after that is stamped, deliberately: the console stops being a log
there and becomes a terminal, and a timestamp in front of a shell prompt, an
echoed keystroke or a column of `ls -l` is wrong rather than merely noisy. That
boundary is a decision init sends (CON_OP_BOOT_DONE), not one this script
infers; the script only checks that it landed where it was supposed to.

TWO CLOCKS, ONE FORMAT. The console changes hands mid-boot, so the first part of
the window is stamped by the kernel from the calibrated TSC (microseconds) and
the rest by console_server from SYS_CLOCK_GETTIME (quantised to a 10 ms PIT
tick, because CR4.TSD denies ring 3 anything finer and a syscall must not hand
it back). The format is identical by construction and this script holds both to
one regex. The monotonicity check therefore allows a backwards step of up to
BACKSTEP_TOLERANCE_US, which is three PIT ticks: the ring-3 stamp rounds down to
a tick, and the offset that puts the two clocks on one epoch was itself captured
rounded down to a tick. It does NOT allow the failure it exists to catch --
counting ring-3 time from the first timer interrupt instead of from boot, which
was 1.07 s of SMP bring-up on the boot measured on 2026-09-06, thirty-five times
the tolerance.

Usage: tools/check_console_timestamps.py <serial-log>
Exit 0 if every line in the window is stamped and the stamps advance.
"""
import re
import sys

# The prefix both writers emit. Width-5 seconds field, six-digit microseconds --
# kmsg_stamp() in src/kernel/terminal.c and hstamp() in userspace/libhorus.c.
STAMP = re.compile(r"^\[\s*(\d+)\.(\d{6})\] ")

# The window. START is the kernel's first message. END is the first line of the
# SESSION, which is the shell's banner (userspace/shell.c _start) -- and the
# banner is a box, so the first line of it is the box's top rule and not the
# text. Matching the text alone left the rule above it inside the window and the
# gate reported one unstamped line for a system behaving exactly as intended;
# whichever of the two comes first ends the window.
START     = "Horus secure microkernel (x86_64) booting"
END_TEXT  = "Horus Secure Microkernel"
END_RULE  = re.compile(r"^\s*\+[-+]{10,}\+\s*$")

# Three PIT ticks. See the module docstring for why it is not zero and why it is
# not large enough to admit the defect.
BACKSTEP_TOLERANCE_US = 30_000

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def clean(line):
    return ANSI.sub("", line.replace("\r", "")).rstrip()


def main(path):
    try:
        raw = open(path, errors="replace").read()
    except OSError as e:
        print(f"CONSOLE TIMESTAMPS: FAIL cannot read {path}: {e}")
        return 1

    lines = [clean(l) for l in raw.split("\n")]

    start = next((i for i, l in enumerate(lines) if START in l), None)
    if start is None:
        print("CONSOLE TIMESTAMPS: FAIL the boot never reached the kernel's first "
              f"message ({START!r}); this is a broken boot, not an unstamped one")
        return 1
    end = next((i for i, l in enumerate(lines[start:], start)
                if END_TEXT in l or END_RULE.match(l)), None)
    if end is None:
        print("CONSOLE TIMESTAMPS: FAIL the boot never reached the session "
              f"({END_TEXT!r}); the window has no end and nothing was checked")
        return 1

    window = [(i, l) for i, l in enumerate(lines[start:end], start) if l.strip()]
    if not window:
        print("CONSOLE TIMESTAMPS: FAIL the window is empty")
        return 1

    unstamped, backwards = [], []
    prev_us = None
    prev_line = None
    for i, l in window:
        m = STAMP.match(l)
        if not m:
            unstamped.append((i, l))
            continue
        us = int(m.group(1)) * 1_000_000 + int(m.group(2))
        if prev_us is not None and us + BACKSTEP_TOLERANCE_US < prev_us:
            backwards.append((i, l, prev_us - us, prev_line))
        prev_us, prev_line = us, l

    if unstamped or backwards:
        # Keep the evidence in the case the gate goes red -- that is the only
        # case anyone needs it (CLAUDE.md §2).
        print(f"CONSOLE TIMESTAMPS: FAIL {len(unstamped)} unstamped line(s) and "
              f"{len(backwards)} backwards step(s) in {len(window)} boot-log lines")
        for i, l in unstamped[:12]:
            print(f"  line {i + 1}: no timestamp: {l[:100]}")
        if len(unstamped) > 12:
            print(f"  ... and {len(unstamped) - 12} more")
        for i, l, back, prev in backwards[:6]:
            print(f"  line {i + 1}: went back {back / 1e6:.6f}s")
            print(f"    after: {prev[:90]}")
            print(f"    then:  {l[:90]}")
        return 1

    print(f"CONSOLE TIMESTAMPS: PASS {len(window)} boot-log lines, every one "
          f"stamped, none out of order (window {lines[start][:40]!r} .. line {end + 1})")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_console_timestamps.py <serial-log>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
