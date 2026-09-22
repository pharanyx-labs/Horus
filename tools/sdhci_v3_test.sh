#!/usr/bin/env bash
# An SDHCI 3.00 host shaped like the IdeaPad 1 14IGL05's, with a card behind it.
#
# WHY. The first real controller this driver met (Intel 8086:31cc, read off the
# machine on 2026-09-22) is an SDHCI 3.00 host with a 200 MHz base clock and
# 1.8 V as its only voltage: capabilities 0x546ec881. Every other SD gate boots
# QEMU's default 2.00 host with a 52 MHz clock, where the 2.00 power-of-two
# divider reaches 400 kHz comfortably. At 200 MHz it cannot (its slowest is
# base/256, 781 kHz), and a card must be identified at 400 kHz or less.
#
# THE CONTROLLER. `capareg=0x146ec881` is the laptop's value with bits 31:30
# (slot type: embedded) cleared, because QEMU refuses an embedded slot. The
# embedded-slot handling is therefore witnessed on the hardware, not here.
#
# TWO MODES:
#   SDHCI_V3_MODE=card  (default, runs in CI) a 64 MiB `sd-card`.
#   SDHCI_V3_MODE=emmc  (local only) a 64 GiB `emmc` device, which needs a QEMU
#                       that has one (QEMU 11 does; CI's 8.2.2 does not). Asserts
#                       the capacity from the extended CSD: an eMMC over 2 GiB
#                       states only a placeholder in its CSD, which reads as
#                       1024 MiB. A QEMU without the device is a FAILURE, never a
#                       skip: a gate that passes because it could not run is the
#                       defect this tree keeps finding.
#
# SDHCI_V3_EXPECT=fast is the clock arm: the identification clock must be ABOVE
# 400 kHz, which is what SDHCI_DIV_V2_ONLY=1 reproduces. SDHCI_V3_EXPECT=csd is
# the capacity arm: the eMMC must report the 1024 MiB placeholder, which is what
# SDHCI_EMMC_CSD_ONLY=1 reproduces.
#
# THE EVIDENCE IS KEPT ON THE FAILURE PATH. That is the only case anyone needs it.
set -u
ISO=${1:?usage: sdhci_v3_test.sh <iso>}
TIMEOUT=${SMOKE_TIMEOUT:-60}
MODE=${SDHCI_V3_MODE:-card}
EXPECT=${SDHCI_V3_EXPECT:-good}
# A DIRECTORY: .gitignore's catch-all for gate evidence is `.*-evidence*/`.
EVID=${SDHCI_V3_EVIDENCE:-.sdhci-v3-$MODE-evidence}
LOG="$EVID/serial.log"
IMG="$EVID/card.img"

fail() { echo "SDHCI_V3: FAIL $* (evidence: $EVID)"; exit 1; }

rm -rf "$EVID"; mkdir -p "$EVID"
if [ "$MODE" = emmc ]; then
    if ! qemu-system-x86_64 -device help 2>/dev/null | grep -q '"emmc"'; then
        fail "this QEMU has no emmc device; the eMMC gate cannot run here"
    fi
    truncate -s 64G "$IMG"
    CARD=(-device emmc,drive=c0,bus=sd-bus)
    WANT_SIZE="eMMC, 65536 MiB, block-addressed"
else
    truncate -s 64M "$IMG"
    CARD=(-device sd-card,drive=c0,bus=sd-bus)
    WANT_SIZE="SD card, 64 MiB"
fi

timeout "$TIMEOUT" qemu-system-x86_64 \
    -m 512M -machine q35 -smp 2 -display none \
    -serial "file:$LOG" -net none -no-reboot -no-shutdown \
    -device sdhci-pci,bus=pcie.0,addr=0x1c,sd-spec-version=3,capareg=0x146ec881 \
    -drive "if=none,id=c0,file=$IMG,format=raw" "${CARD[@]}" \
    -cdrom "$ISO" >/dev/null 2>"$EVID/qemu.err"

[ -s "$LOG" ] || fail "the guest produced no serial output at all -- a dead boot"
grep -qa "sdhci: host controller v3.0, base clock 200 MHz" "$LOG" \
    || fail "the controller did not come up as the 3.00, 200 MHz host it was given"

KHZ=$(grep -a -o "identification clock [0-9]* kHz" "$LOG" | head -1 | grep -o '[0-9][0-9]*')
[ -n "$KHZ" ] || fail "no identification clock was reported; the card was not reached"

case "$EXPECT" in
fast)
    [ "$KHZ" -gt 400 ] || fail "the arm identified at $KHZ kHz; SDHCI_DIV_V2_ONLY did not reproduce the defect"
    echo "SDHCI_V3: PASS the 2.00-only divider identifies a 200 MHz host at $KHZ kHz, over the 400 kHz ceiling"
    rm -rf "$EVID"; exit 0 ;;
csd)
    grep -qa "eMMC, 1024 MiB" "$LOG" \
        || fail "the arm did not report the CSD placeholder; SDHCI_EMMC_CSD_ONLY did not reproduce the defect"
    echo "SDHCI_V3: PASS without the extended CSD a 64 GiB eMMC reads as the 1024 MiB placeholder"
    rm -rf "$EVID"; exit 0 ;;
esac

[ "$KHZ" -gt 0 ] && [ "$KHZ" -le 400 ] \
    || fail "the card was identified at $KHZ kHz, over the 400 kHz ceiling"
grep -qa "$WANT_SIZE" "$LOG" || fail "the card did not report '$WANT_SIZE'"
grep -qa "sdhci-read block100:" "$LOG" || fail "the card came up but block 100 was not read"

rm -rf "$EVID"
echo "SDHCI_V3: PASS ($MODE) identified at $KHZ kHz; '$WANT_SIZE'; blocks read"
