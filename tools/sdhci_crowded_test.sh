#!/usr/bin/env bash
# An SD/eMMC host controller AT THE END OF A CROWDED BUS must be found.
#
# WHY THIS IS A SEPARATE GATE. Every other SD gate boots a QEMU machine with
# half a dozen PCI functions, so the kernel's device table never came close to
# filling. It held IODEV_MAX = 16 entries until 2026-09-22: fourteen PCI
# functions once index 0 and the platform device are taken. A Gemini Lake laptop
# (the IdeaPad 1 14IGL05) has twenty-odd functions on bus 0 and its eMMC
# controller at 00:1c.0, near the end of the walk, and pci_add_function dropped
# everything past the table's end without a word. The only symptom was
# `sdhci: no SD/eMMC host controller` and a machine with nothing to install onto.
#
# THE TOPOLOGY IS THE TEST, so it is spelled out: 24 pci-testdev functions at
# 00:03.0 to 00:1a.0, all on bus 0 and all ahead of the controller, which sits at
# 00:1c.0 where the laptop's does. With q35's own functions that is about thirty
# on the bus, inside 64 and well past 16.
#
# THE ARM ASSERTS TWO THINGS, and needs both. IODEV_TABLE_16=1 must report the
# controller absent, which proves the controller really was past the end of a
# 16-entry table on this command line; and it must print the table-full line,
# which proves the absence came from the table rather than from a probe that
# died for some other reason. The base gate asserts the table-full line is NOT
# printed, so a table that is merely big enough for this machine cannot pass
# while still dropping something.
#
# THE EVIDENCE IS KEPT ON THE FAILURE PATH. That is the only case anyone needs it.
set -u
ISO=${1:?usage: sdhci_crowded_test.sh <iso>}
TIMEOUT=${SMOKE_TIMEOUT:-60}
EXPECT=${SDHCI_CROWDED_EXPECT:-found}
# A DIRECTORY, for the reason sdhci_bridge_test.sh gives: .gitignore's catch-all
# for gate evidence is `.*-evidence*/`, which matches directories only.
EVID=${SDHCI_CROWDED_EVIDENCE:-.sdhci-crowded-evidence}
LOG="$EVID/serial.log"

FILLERS=()
for slot in {3..26}; do   # one boot; the loop only builds the command line
    FILLERS+=(-device "pci-testdev,bus=pcie.0,addr=$(printf '0x%x' "$slot")")
done

rm -rf "$EVID"; mkdir -p "$EVID"
timeout "$TIMEOUT" qemu-system-x86_64 \
    -m 512M -machine q35 -smp 2 -display none \
    -serial "file:$LOG" -net none -no-reboot -no-shutdown \
    "${FILLERS[@]}" \
    -device sdhci-pci,bus=pcie.0,addr=0x1c \
    -cdrom "$ISO" >/dev/null 2>&1

if [ ! -s "$LOG" ]; then
    echo "SDHCI_CROWDED: FAIL the guest produced no serial output at all -- a dead"
    echo "               boot, which says nothing about the table (evidence: $EVID)"
    exit 1
fi

if grep -qa "sdhci: host controller v" "$LOG"; then
    GOT=found
elif grep -qa "sdhci: no SD/eMMC host controller" "$LOG"; then
    GOT=absent
else
    echo "SDHCI_CROWDED: FAIL neither sdhci marker appeared; the boot did not reach"
    echo "               the probe (evidence: $EVID)"
    exit 1
fi

FULL=no
grep -qa "iodev: table full, " "$LOG" && FULL=yes

if [ "$EXPECT" = found ]; then
    if [ "$GOT" != found ]; then
        echo "SDHCI_CROWDED: FAIL the controller at 00:1c.0 was NOT found behind 24"
        echo "               other functions -- the device table is too small (evidence: $EVID)"
        exit 1
    fi
    if [ "$FULL" = yes ]; then
        echo "SDHCI_CROWDED: FAIL the device table reported itself full on a bus of"
        echo "               about thirty functions (evidence: $EVID)"
        exit 1
    fi
else
    if [ "$GOT" != absent ]; then
        echo "SDHCI_CROWDED: FAIL the arm found the controller anyway; IODEV_TABLE_16"
        echo "               did not reproduce the defect (evidence: $EVID)"
        exit 1
    fi
    if [ "$FULL" != yes ]; then
        echo "SDHCI_CROWDED: FAIL the controller is absent but the table did not say it"
        echo "               was full, so the absence has some other cause (evidence: $EVID)"
        exit 1
    fi
fi

rm -rf "$EVID"
if [ "$EXPECT" = found ]; then
    echo "SDHCI_CROWDED: PASS the controller at the end of a crowded bus was found and brought up"
else
    echo "SDHCI_CROWDED: PASS the 16-entry table drops the controller and says it is full"
fi
