#!/bin/bash
# Check what is actually ON THE SCREEN.
#
# WHY THIS EXISTS WHEN A SERIAL GATE ALREADY PASSES. `smoke-fb-tag-gfx` asserts
# that the kernel says it moved the console to the framebuffer. It cannot assert
# that anything legible arrived there. The defect this is aimed at -- a blitter
# that reads the font's bit 0 as the leftmost pixel instead of bit 7 -- leaves
# every serial line correct, the console reporting itself started, the klog
# complete, and the screen mirrored and unreadable. That is the whole class of
# framebuffer bug a wire-reading gate is blind to.
#
# HOW. The guest draws a known glyph BELOW the 80x50 grid (FB_CONSOLE_SELFTEST),
# in the region the console never scrolls over, and the host screendumps over
# QMP and inspects those pixels.
#
# WHY 'L', AND WHY NOT AN EXACT BITMAP COMPARISON. An exact comparison would
# pin this gate to one font and break on the next commit, which replaces it.
# 'L' is strongly left-heavy in any font that draws an L at all -- a stem down
# the left, a foot to the right -- so "more foreground on the left than the
# right" is a property of the LETTER rather than of the font, and it inverts
# exactly when the bit order does.
#
# Usage: tools/fb_console_test.sh [iso]
#   FB_CONSOLE_EXPECT=ok        (default) the glyph is drawn and not mirrored
#   FB_CONSOLE_EXPECT=mirrored  require it to BE mirrored (the control arm)
#   FB_CONSOLE_EXPECT=server    ring 3 owns the display and has painted it
#   SMOKE_TIMEOUT               seconds (default 90)
set -u

ISO="${1:-horus.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-90}"
EXPECT="${FB_CONSOLE_EXPECT:-ok}"
EVID="${FB_CONSOLE_EVIDENCE:-.fbcon-evidence}"
PORT="${FB_CONSOLE_QMP_PORT:-4471}"
# Extra QEMU arguments, word-split deliberately. It exists so the SAME pixel
# check can be pointed at a display of a different depth: OVMF with QEMU's
# default `-vga std` is 800x600 at 24bpp, where a pixel is three bytes and a
# 32-bit store shears every glyph. Checking the letter is the only way to know
# the byte-wise blitter is right -- "it reached a login prompt" does not.
EXTRA="${FB_CONSOLE_QEMU_EXTRA:-}"

rm -rf "$EVID"; mkdir -p "$EVID"
[ -f "$ISO" ] || { echo "fb-console: no such ISO: $ISO"; exit 2; }

LOG="$EVID/serial.log"
SHOT="$EVID/screen.ppm"

# shellcheck disable=SC2086  # EXTRA is a deliberate word-split argument list
qemu-system-x86_64 -m 512M -cpu qemu64 -display none -no-reboot -cdrom "$ISO" \
    $EXTRA \
    -serial "file:$LOG" -qmp "tcp:127.0.0.1:$PORT,server=on,wait=off" >/dev/null 2>&1 &
QPID=$!
# shellcheck disable=SC2064
trap "kill $QPID 2>/dev/null" EXIT

# Wait for the guest to reach the point this arm inspects, rather than sleeping a
# guessed interval: a fixed sleep measures the host, and this runs on CI too.
case "$EXPECT" in
  server)        WAIT_FOR="horus login:" ;;
  server-absent) WAIT_FOR="CONSOLE_SELFTEST: FAIL vga" ;;
  refused)       WAIT_FOR="CONSOLE_SELFTEST: FAIL vga" ;;
  *)             WAIT_FOR="fb: selftest glyph drawn" ;;
esac
deadline=$(( $(date +%s) + TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    grep -qa "$WAIT_FOR" "$LOG" 2>/dev/null && break
    kill -0 $QPID 2>/dev/null || break
    sleep 1
done
if ! grep -qa "$WAIT_FOR" "$LOG" 2>/dev/null; then
    echo "fb-console: FAIL - the guest never reached '$WAIT_FOR'"
    echo "  (built without the flag this arm needs, or the console never started)"
    grep -aE "fb:|CONSOLE_|kernel ready" "$LOG" 2>/dev/null | sed 's/^/    /' || echo "    (no serial output)"
    echo "  evidence: $LOG"
    exit 1
fi

python3 - "$PORT" "$SHOT" <<'PY'
import json, socket, sys
port, out = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=20)
f = s.makefile("rw", encoding="utf-8", newline="\n")
f.readline()
f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n"); f.flush(); f.readline()
f.write(json.dumps({"execute": "screendump", "arguments": {"filename": out}}) + "\n"); f.flush()
reply = json.loads(f.readline())
if "error" in reply:
    print("screendump failed:", reply["error"]); sys.exit(1)
PY
rc=$?
[ $rc -eq 0 ] || { echo "fb-console: FAIL - could not screendump over QMP"; exit 1; }

python3 - "$SHOT" "$EXPECT" "$LOG" <<'PY'
import sys, re
shot, expect, log = sys.argv[1], sys.argv[2], sys.argv[3]

with open(shot, "rb") as fh:
    data = fh.read()
# Minimal binary PPM (P6) reader: magic, width height, maxval, then RGB triples.
parts, idx = [], 2
while len(parts) < 3:
    while data[idx:idx+1].isspace(): idx += 1
    if data[idx:idx+1] == b"#":
        while data[idx:idx+1] not in (b"\n", b""): idx += 1
        continue
    start = idx
    while not data[idx:idx+1].isspace(): idx += 1
    parts.append(int(data[start:idx]))
idx += 1
W, H, _maxv = parts
px = data[idx:]
def rgb(x, y):
    o = (y * W + x) * 3
    return (px[o], px[o+1], px[o+2])

# The one band both arms of this pair measure: empty when ring 3 cleared the
# display and painted its session, full of the kernel's boot log when it did not.
# Declared once so the gate and its control can never drift onto different bands
# and stop being a pair. Derived by measurement -- the numbers, and why it moved
# on 2026-09-10, are in the `server` arm below.
CLEARED_BAND = (352, 512)

# Where the guest drew it: directly below the 80x50 grid, plus the 8px gap the
# kernel leaves. Both the font height and the scale are read off the guest's own
# report so this does not have to know either.
if expect == "server-absent":
    # THE PRE-FIX STATE, asserted positively. console_server never asks what the
    # display is, maps a text window that is not there, fails its own round trip
    # and parks -- so the kernel's boot log is still on the screen, because
    # nothing in ring 3 ever cleared it. The lower band being FULL is the
    # evidence; "no login prompt" alone would also describe a machine that never
    # booted.
    fail = 0
    def check(desc, ok):
        global fail
        print(("  [ OK ] " if ok else "  [FAIL] ") + desc)
        if not ok: fail = 1
    def ink(y0, y1):
        n = 0
        for y in range(y0, min(y1, H)):
            for x in range(0, min(700, W)):
                if rgb(x, y) != (0, 0, 0): n += 1
        return n
    # THE BAND IS MEASURED, NOT GUESSED, and it is the SAME band the `server` arm
    # requires to be empty -- one measurement, two opposite expectations, which is
    # what makes this pair a pair rather than two checks that happen to disagree.
    # See the `server` arm below for why it moved from y 200-400 on 2026-09-10 and
    # for the numbers on both builds.
    mid = ink(*CLEARED_BAND)
    print(f"  non-black pixels in y {CLEARED_BAND[0]}-{CLEARED_BAND[1]}: {mid}")
    check("the kernel's boot log is still on the screen", mid > 0)
    check("ring 3 never took the display (it failed its VGA check)",
          b"CONSOLE_SELFTEST: FAIL vga" in open(log, "rb").read())
    # EXITS HERE. Without this the branch falls through to the glyph checks at
    # the bottom, which this arm cannot satisfy -- no glyph is ever drawn when
    # ring 3 does not take the display. It was lost on 2026-09-12 when the
    # `refused` branch below was inserted between these checks and the exit that
    # used to close them, and CI caught it.
    sys.exit(fail)

elif expect == "refused":
    fail = 0
    def check(desc, ok):
        global fail
        print(("  [ OK ] " if ok else "  [FAIL] ") + desc)
        if not ok: fail = 1
    # THE BLACK SCREEN, ASSERTED AS SUCH. On a UEFI machine there is no VGA text
    # window to fall back to, so a console that refuses the display leaves
    # NOTHING on the screen -- which is why `server-absent` (whose first check is
    # that the kernel's log is still visible) is the wrong expectation here: that
    # one describes a BIOS machine, where the fallback exists.
    #
    # Asserted from the log rather than the pixels, because "the screen is black"
    # is also what a guest that never booted produces, and the two want different
    # fixes. The three markers together say the machine got far enough to look at
    # the display, decided it could not drive it, and stopped.
    blob = open(log, "rb").read()
    check("the kernel refused the depth and said so",
          b"-bit pixels are not supported" in blob)
    check("ring 3 could not take the display either",
          b"CONSOLE_SELFTEST: FAIL vga" in blob)
    check("no selftest glyph was ever drawn",
          b"fb: selftest glyph drawn" not in blob)
    sys.exit(fail)

if expect == "server":
    # WHAT RING 3 PUT ON THE SCREEN. The kernel drew its whole boot log here --
    # roughly thirty rows of it -- and console_server CLEARS the display when it
    # takes over, then writes a banner and a prompt. So two things are true only
    # if ring 3 really painted: there is text near the top, and the lower half is
    # blank. The kernel's log would have filled that lower half, so "it is empty"
    # is evidence of the clear rather than of nothing having happened -- which is
    # why the top-half check alone would not do.
    fail = 0
    def check(desc, ok):
        global fail
        print(("  [ OK ] " if ok else "  [FAIL] ") + desc)
        if not ok: fail = 1

    def ink(y0, y1):
        n = 0
        for y in range(y0, min(y1, H)):
            for x in range(0, min(700, W)):
                if rgb(x, y) != (0, 0, 0): n += 1
        return n

    # THE CLEARED BAND HAS TO SIT BELOW ANYTHING THE SESSION PAINTS, and on
    # 2026-09-10 it stopped doing so. It was y 200-400, measured when the login
    # banner was a four-line box: ring 3 then reached y 192 and the band had ONE
    # row of margin under it. The neofetch-style banner is fifteen lines with the
    # blank line and the prompt, reaches y 299, and put 1281 pixels inside a band
    # asserted to be empty -- a red gate that was not describing a defect. Note
    # what the old margin means: at one row, the band would equally have reddened
    # for a kernel line added before the handover, which shifts the session down
    # without changing anything about the clear.
    #
    # Re-measured on this tree, both builds, same host, 1024x768 at a 16px cell:
    #   band        cleared (server)   not cleared (server-absent)
    #   y 200-400            1281                    11492   <- no longer separates
    #   y 320-512               0                    10307
    #   y 352-512               0                     9116   <- chosen
    #   y 384-512               0                     7593
    # 352 is 53 pixels (3.3 rows) below the session's deepest ink, and the broken
    # build still puts 9116 pixels in the band -- nearly three times the 3217 the
    # old band had to work with. So this is the same assertion with more room on
    # both sides, not a softer one. The kernel's log ends near y 512; a change
    # that shortened it by eight rows would quiet this band on the broken build
    # too, so re-measure both arms if that log gets materially shorter.
    top = ink(0, 200)          # the banner console_server writes
    mid = ink(*CLEARED_BAND)   # inside the kernel's grid, and blank once cleared
    print(f"  non-black pixels: {top} in y 0-200, "
          f"{mid} in y {CLEARED_BAND[0]}-{CLEARED_BAND[1]}")
    check("ring 3 painted text near the top", top > 500)
    check(f"the display was cleared: y {CLEARED_BAND[0]}-{CLEARED_BAND[1]} is blank",
          mid == 0)
    sys.exit(fail)

m = re.search(rb"(\d+)x(\d+) font at (\d+)x", open(log, "rb").read())
if not m:
    print("  [FAIL] the guest never reported its font geometry"); sys.exit(1)
fw, fh, scale = int(m.group(1)), int(m.group(2)), int(m.group(3))
cw, chh = fw * scale, fh * scale
# WHERE THE GUEST PUT IT, derived from the guest's own report rather than from a
# constant here. It is to the RIGHT of the grid: at a 16-pixel cell the 48 rows
# fill a 768-line display exactly and there is nothing below them, whereas the
# horizontal margin survives by construction because columns are capped at 80.
# The first version of this computed `50 * cell + 8` and went off the bottom of
# the screen the moment the font grew -- a constant standing in for something the
# kernel derives, which is the same defect the grid gate caught one commit back.
px0 = 80 * cw + 8
py0 = 0
print(f"  glyph cell: {cw}x{chh} at ({px0},{py0})  [font {fw}x{fh} at {scale}x]")

if px0 + cw > W or py0 + chh > H:
    print(f"  [FAIL] the selftest glyph is off the screen ({W}x{H})"); sys.exit(1)

cells = [[rgb(px0 + x, py0 + y) for x in range(cw)] for y in range(chh)]
flat = [c for row in cells for c in row]
colours = set(flat)

fail = 0
def check(desc, ok):
    global fail
    print(("  [ OK ] " if ok else "  [FAIL] ") + desc)
    if not ok: fail = 1

# 1. Something was drawn: a uniform block means the glyph never landed.
check("the glyph cell is not uniform", len(colours) > 1)
# 2. Exactly two colours, and they are the ones asked for. Catches a wrong pixel
#    format or a channel swap, which would still produce "some pixels".
check("it uses exactly the two colours it was given",
      colours <= {(255, 255, 255), (0, 0, 0)} and len(colours) == 2)

fgcount = sum(1 for c in flat if c == (255, 255, 255))
left  = sum(1 for y in range(chh) for x in range(cw // 2)      if cells[y][x] == (255,255,255))
right = sum(1 for y in range(chh) for x in range(cw // 2, cw)  if cells[y][x] == (255,255,255))
print(f"  foreground pixels: {fgcount} total, {left} left / {right} right")
check("the glyph has foreground pixels at all", fgcount > 0)

if expect == "mirrored":
    check("the glyph is MIRRORED (right-heavy), as the arm requires", right > left)
else:
    check("the glyph is not mirrored (an 'L' is left-heavy)", left > right)

sys.exit(fail)
PY
rc=$?
if [ $rc -ne 0 ]; then
    echo "FB-CONSOLE FAIL ($EXPECT)"
    echo "  evidence: $SHOT and $LOG"
    exit 1
fi
echo "FB-CONSOLE PASS ($EXPECT)"
