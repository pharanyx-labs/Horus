#!/bin/bash
# Boot one ISO the ways a person actually boots it, and require the kernel to
# come up in every one of them.
#
# WHY THIS EXISTS. Every other gate in this tree boots `-cdrom boot.iso` under
# SeaBIOS, which is one cell of a four-cell table. The other three were broken
# and nothing could see it: `grub.cfg` said `set root=(cd)`, naming the BIOS El
# Torito CD-ROM, which is not a device that exists when the same image is
# written to a USB stick with dd (it is `(hd0)` there) or booted through UEFI.
# GRUB then looked the kernel up on the network -- "error: no server is
# specified", then "you need to load the kernel first" -- and stopped. Measured
# 2026-09-06: BIOS+CD booted, BIOS+disk failed, UEFI+CD failed.
#
# THE MODES ARE MEDIA, NOT FIRMWARE ALONE. A dd'd USB stick is the same bytes as
# the ISO presented as a raw disk rather than as optical media, which is exactly
# what `-drive format=raw,if=ide` gives. That is the case a laptop install starts
# from, and it is the one no gate covered.
#
# Usage: tools/boot_media_test.sh [iso]
#   BOOT_MEDIA_MODES  space-separated subset of: bios-disk uefi-cd uefi-disk
#                     (bios-cd is deliberately absent -- every other smoke target
#                     already covers it, so repeating it here buys nothing)
#   SMOKE_TIMEOUT     seconds per boot (default 60)
#   OVMF_CODE         firmware path (default: the Debian/Ubuntu location)
set -u

ISO="${1:-boot.iso}"
MODES="${BOOT_MEDIA_MODES:-bios-disk uefi-cd uefi-disk}"
TIMEOUT="${SMOKE_TIMEOUT:-60}"
OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
OVMF_VARS="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
BANNER="${BOOT_MEDIA_BANNER:-Horus secure microkernel}"

# Evidence lives here and is NOT deleted on the failure path: the run that goes
# red is the only run anyone needs the transcript of.
EVID="${BOOT_MEDIA_EVIDENCE:-.boot-media-evidence}"
rm -rf "$EVID"; mkdir -p "$EVID"

[ -f "$ISO" ] || { echo "boot-media: no such ISO: $ISO"; exit 2; }

need_uefi=0
for m in $MODES; do case "$m" in uefi-*) need_uefi=1 ;; esac; done
if [ "$need_uefi" = 1 ] && [ ! -f "$OVMF_CODE" ]; then
    echo "boot-media: FAIL - UEFI modes requested but no firmware at $OVMF_CODE"
    echo "  install the 'ovmf' package, or set OVMF_CODE."
    # A missing firmware is a broken gate, not a passing one: refusing here is
    # what stops "we could not test UEFI" from reading as "UEFI works".
    exit 2
fi

fail=0
for mode in $MODES; do
    log="$EVID/$mode.log"
    : > "$log"
    args=(-m 512M -cpu qemu64 -display none -no-reboot -serial "file:$log")

    case "$mode" in
        bios-cd)   args+=(-cdrom "$ISO") ;;
        bios-disk) args+=(-drive "format=raw,file=$ISO,if=ide") ;;
        uefi-cd|uefi-disk)
            vars="$EVID/$mode-vars.fd"
            cp "$OVMF_VARS" "$vars"
            args+=(-machine q35
                   -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE"
                   -drive "if=pflash,format=raw,unit=1,file=$vars")
            if [ "$mode" = uefi-cd ]; then args+=(-cdrom "$ISO")
            else args+=(-drive "format=raw,file=$ISO,if=ide"); fi
            ;;
        *) echo "boot-media: unknown mode '$mode'"; exit 2 ;;
    esac

    timeout "$TIMEOUT" qemu-system-x86_64 "${args[@]}" >/dev/null 2>&1

    if grep -qa "$BANNER" "$log"; then
        echo "  [ OK ] $mode: the kernel came up"
    else
        fail=1
        echo "  [FAIL] $mode: no kernel banner on serial"
        # Name the GRUB failure when it is the one this gate exists for, so a
        # red run says WHICH way it broke rather than only that it did.
        if grep -qa "no server is specified\|you need to load the kernel first" "$log"; then
            echo "         GRUB could not load the kernel -- the root device did not resolve"
        fi
        echo "         evidence: $log"
        sed 's/\r/\n/g' "$log" | grep -a "error:" | head -3 | sed 's/^/         /'
    fi
done

if [ "$fail" != 0 ]; then
    echo "BOOT-MEDIA FAIL: transcripts kept in $EVID/"
    exit 1
fi
echo "BOOT-MEDIA PASS: $MODES"
