#!/bin/bash
# Require the kernel to say what GRUB told it the display is.
#
# WHY THIS NEEDS THREE EXPECTATIONS RATHER THAN ONE. The multiboot2 framebuffer
# tag is ALWAYS present -- a plain boot of this tree's grub.cfg reports EGA text
# 80x25 at 0xB8000 -- so a parser that only ever saw that answer would look
# correct while being untested on the one case it exists for. A linear
# framebuffer appears only when the KERNEL HEADER asks for one (the type-5
# request tag, built under FB_REQUEST) and grub.cfg has loaded a video driver.
# Measured 2026-09-08: `set gfxpayload` does not apply to a multiboot2 payload
# and changed nothing; the header tag with no video driver silently falls back
# to text; with both, the same machine reports RGB 1024x768x32 at 0xFD000000.
#
# THAT ADDRESS IS THE POINT of asserting the geometry rather than merely "a
# framebuffer was found": 0xFD000000 is far above the PHYS_KVA window, so a
# later mapper cannot reach it the way it reaches every other physical address
# this kernel touches. A gate that accepted any address would not notice a
# parser that read the field from the wrong offset.
#
# Usage: tools/fb_tag_test.sh [iso]
#   FB_EXPECT=text     (default) EGA text, and the boot reaches the login prompt
#   FB_EXPECT=rgb      a linear framebuffer, its geometry, and the consequence
#   FB_EXPECT=unparsed the tag is not recorded, so the reporter falls back (control arm)
#   FB_EXPECT=map      the framebuffer window is built and reachable from a task
#   FB_EXPECT=map-lowhalf  the window is in the low half, so no task has it (control arm)
#   SMOKE_TIMEOUT      seconds (default 60)
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-60}"
EXPECT="${FB_EXPECT:-text}"
EVID="${FB_EVIDENCE:-.fb-evidence}"

rm -rf "$EVID"; mkdir -p "$EVID"
[ -f "$ISO" ] || { echo "fb-tag: no such ISO: $ISO"; exit 2; }

LOG="$EVID/serial.log"
timeout "$TIMEOUT" qemu-system-x86_64 -m 512M -cpu qemu64 \
    -display none -no-reboot -cdrom "$ISO" -serial "file:$LOG" >/dev/null 2>&1

if [ ! -s "$LOG" ]; then
    echo "fb-tag: FAIL - the guest produced no serial output at all"
    exit 1
fi

dump() { grep -aE "fb:|FBMAP|DEFECT FLAGS|kernel ready" "$LOG" | sed 's/\r//' | sed 's/^/    /' || echo "    (nothing)"; }

fail=0
check() {  # $1 = description, $2 = pattern
    if grep -qa "$2" "$LOG"; then echo "  [ OK ] $1"; else echo "  [FAIL] $1"; fail=1; fi
}
refute() {
    if grep -qa "$2" "$LOG"; then echo "  [FAIL] $1"; fail=1; else echo "  [ OK ] $1"; fi
}

case "$EXPECT" in
unparsed)
    # NOT A SILENCE CHECK, and that is deliberate. FB_TAG_IGNORED compiles out
    # the RECORDER, not the reporter, so the kernel does not go quiet -- it falls
    # back and says it has no usable tag. Asserting that fallback POSITIVELY is
    # what makes this arm attributable: it proves the reporting code ran and
    # found nothing recorded, so the missing geometry is the parse's absence and
    # not a boot that died before reaching it. A bare "no fb: line" check would
    # have been satisfied by a kernel that never got there.
    check  "the reporter ran and found nothing recorded" "fb: no usable framebuffer tag"
    refute "no geometry is reported"                     "fb: EGA text "
    refute "no framebuffer is reported"                  "fb: RGB "
    check  "the boot still completed"                    "kernel ready"
    ;;
text)
    check "the tag was parsed as EGA text"      "fb: EGA text "
    # The GEOMETRY, not just the mode: a parser reading width from the wrong
    # offset still prints "EGA text".
    check "the text geometry is 80x25"          "fb: EGA text 80x25 "
    check "the buffer is the VGA text window"   "fb: EGA text 80x25 at 0x00000000000B8000"
    check "the console stays on VGA text"       "console on VGA text"
    # And the ordinary boot is unaffected -- this whole change must be invisible
    # to every other gate, and reaching the login prompt is how that is checked
    # here rather than by running all of them.
    check "the machine reached the login prompt" "horus login:"
    ;;
rgb)
    check "the request tag is recorded in the build"  "DEFECT FLAGS: FB_REQUEST"
    check "the tag was parsed as a linear framebuffer" "fb: RGB "
    # Geometry, depth AND pitch. Pitch is separate because it is the field a
    # renderer indexes rows with, and 1024x32bpp implies 4096 only when nothing
    # padded the row -- so a parser that computed it instead of reading it would
    # be right here and wrong on hardware that pads.
    check "the geometry, depth and pitch are the mode's" "fb: RGB 1024x768x32 pitch 4096 "
    # The base address, which PHYS_KVA cannot reach. Asserted explicitly so a
    # later change that quietly starts trusting PHYS_KVA has something to fail.
    check "the base address is the one GRUB gave"        "at 0x00000000FD000000"
    # And the kernel must say what the CONSOLE did about it, not only what the
    # display is. On this path the VGA text window does not exist, so a console
    # that silently kept writing to it would produce a black screen and no error
    # -- which is how the first framebuffer experiment presented, and it cost a
    # session to attribute. Until 2026-09-08 this line was a warning that there
    # was no pixel console; there is one now, and the assertion moved with it.
    check "the console moved to the framebuffer" "fb: console on the framebuffer"
    check "the boot still completed"                     "kernel ready"
    ;;
map)
    # The window exists AND is reachable from a task's address space. Two
    # questions, and the second is the one worth asking: the first is answered on
    # the kernel's own cr3, where a low-half mapping looks perfect.
    check  "the window was built and reads back"     "FBMAP: boot readback OK"
    check  "it is present in a task address space"   "present in the task address space"
    refute "no address space is missing it"          "ABSENT FROM THE TASK ADDRESS SPACE"
    check  "the boot still completed"                "kernel ready"
    ;;
map-lowhalf)
    # The control arm's signature, and BOTH halves are asserted. That the boot
    # readback still passes is not incidental -- it is the lesson: a check made
    # on the kernel's cr3 cannot see this defect at all, which is why the SDHCI
    # register file shipped, probed clean, and faulted the moment ring 3 asked.
    check  "the boot-time check is BLIND to it"      "FBMAP: boot readback OK"
    check  "a task address space is missing it"      "ABSENT FROM THE TASK ADDRESS SPACE"
    refute "no address space claims to have it"      "present in the task address space"
    check  "the boot still completed"                "kernel ready"
    ;;
*)
    echo "fb-tag: unknown FB_EXPECT: $EXPECT"; exit 2 ;;
esac

if [ "$fail" != 0 ]; then
    echo "FB-TAG FAIL ($EXPECT): what the guest actually said:"
    dump
    echo "  evidence: $LOG"
    exit 1
fi
echo "FB-TAG PASS ($EXPECT)"
