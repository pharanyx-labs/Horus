#!/bin/bash
# Boot a machine that HAS an SD/eMMC host controller and require the kernel to
# say so.
#
# WHY A MACHINE OF ITS OWN. No other gate in this tree attaches an SD host
# controller, so "no SD/eMMC host controller" is the only answer any of them
# could observe -- and a probe that always said that would pass every one. This
# attaches an sdhci-pci controller with a card in it, which is the shape of the
# storage a budget laptop actually has: soldered eMMC behind a host controller,
# reached by neither ata.c nor ahci.c.
#
# THE BUS IS NAMED sd-bus, not sd.0. `-device sd-card,bus=sd.0` is refused with
# "Bus 'sd.0' not found", and `-drive if=sd` with "machine type does not support
# if=sd" -- both were tried on 2026-09-07 before `info qtree` settled it. Written
# down because the error messages point at the drive rather than at the bus name.
#
# WHAT IT REQUIRES, and why separately:
#   - the controller is recognised at all (a version line);
#   - a card is reported present AND STABLE -- the detect line settling is what
#     separates a card from one still being debounced, and reporting the latter
#     as storage would be reporting a race as a fact;
#   - the count line, which is what an installer would eventually act on.
#
# Usage: tools/sdhci_detect_test.sh [iso]
#   SDHCI_EXPECT=absent    require the probe to say NOTHING (the control arm)
#   SDHCI_EXPECT=empty     controller attached with NO card
#   SMOKE_TIMEOUT          seconds (default 60)
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-60}"
EXPECT="${SDHCI_EXPECT:-present}"
EVID="${SDHCI_EVIDENCE:-.sdhci-evidence}"

rm -rf "$EVID"; mkdir -p "$EVID"
[ -f "$ISO" ] || { echo "sdhci-detect: no such ISO: $ISO"; exit 2; }

CARD_MB="${SDHCI_CARD_MB:-128}"
CARD="$EVID/emmc.img"
qemu-img create -f raw "$CARD" "${CARD_MB}M" >/dev/null 2>&1 || \
    dd if=/dev/zero of="$CARD" bs=1M count=0 seek="$CARD_MB" status=none

# Known bytes at TWO blocks, and the second one is the point.
#
# Block 0 is address 0 whether the card is block-addressed or byte-addressed, so
# a driver with the addressing mode inverted reads it correctly and every other
# block from 512x the wrong place. Only a non-zero block can tell the two apart,
# and a high-capacity card is block-addressed -- which is what a laptop's eMMC is.
printf 'HORUS-B0' | dd of="$CARD" bs=1 seek=0 conv=notrunc status=none
printf 'HORUS100' | dd of="$CARD" bs=1 seek=$((100 * 512)) conv=notrunc status=none

LOG="$EVID/serial.log"
args=(-m 512M -cpu qemu64 -machine q35 -display none -no-reboot -cdrom "$ISO"
      -device sdhci-pci,id=sd -serial "file:$LOG")
if [ "$EXPECT" != empty ]; then
    args+=(-drive "id=mmc,file=$CARD,format=raw,if=none"
           -device sd-card,drive=mmc,bus=sd-bus)
fi

timeout "$TIMEOUT" qemu-system-x86_64 "${args[@]}" >/dev/null 2>&1

if [ ! -s "$LOG" ]; then
    echo "sdhci-detect: FAIL - the guest produced no serial output at all"
    exit 1
fi

dump() { grep -aE "sdhci|^\[[^]]*\] +\[" "$LOG" | sed 's/\r//' | sed 's/^/    /' || echo "    (nothing)"; }

if [ "$EXPECT" = absent ]; then
    if grep -qa "sdhci:" "$LOG"; then
        echo "CONTROL FAIL: the probe still reported, with SDHCI_PROBE_ABSENT=1:"
        dump; echo "  evidence: $LOG"; exit 1
    fi
    # The machine must still have BOOTED, or "said nothing about SD" would be
    # satisfied by a kernel that died before reaching the probe, and the arm
    # would pass for a reason unrelated to its defect.
    if ! grep -qa "kernel ready" "$LOG"; then
        echo "CONTROL FAIL: the probe was silent, but so was the boot -- the kernel"
        echo "  never reached 'kernel ready', so this witnesses nothing."
        echo "  evidence: $LOG"; exit 1
    fi
    echo "[sdhci] CONTROL PASS - the controller is there and the kernel says nothing about it"
    exit 0
fi

fail=0
check() {
    if grep -qa "$2" "$LOG"; then echo "  [ OK ] $1"; else echo "  [FAIL] $1"; fail=1; fi
}

if [ "$EXPECT" = empty ]; then
    check "the controller is recognised with no card" "sdhci: host controller v"
    check "the empty slot is reported as empty"       "sdhci: the slot is empty"
    check "the count is zero"                         "sdhci: 0 card(s) present"
else
    check "the controller is recognised"              "sdhci: host controller v"
    check "a card is present and the line is stable"  "a card is present and the detect line is stable"
    check "the card count is reported"                "sdhci: 1 card(s) present"
    # The card was brought up -- reset, power, clock divisor, CMD0, the op-cond
    # negotiation, CMD2/CMD3/CMD9/CMD7 -- and the CAPACITY is compared against
    # the image this script created. A driver that decoded the CSD from the
    # specification's own bit numbers reads a plausible number and a wrong one:
    # the first version of this reported a 128 MiB card as 30752 MiB, because a
    # 136-bit response is stored with the CRC byte dropped and every field sits
    # eight bits below its documented position. Only a size comparison catches
    # that.
    check "the card came up"                          "SD card, "
    check "the capacity is the card's own"            "SD card, ${CARD_MB} MiB"
    check "block 0 reads the bytes that are there"    "sdhci-read block0: HORUS-B0"
    # The one that catches an inverted addressing mode, which block 0 cannot.
    check "a non-zero block reads correctly"          "sdhci-read block100: HORUS100"
fi

if [ "$fail" != 0 ]; then
    echo "SDHCI-DETECT FAIL: what the guest actually said:"
    dump
    echo "  evidence: $LOG"
    exit 1
fi
echo "SDHCI-DETECT PASS ($EXPECT): the host controller answered"
