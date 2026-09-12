#!/usr/bin/env bash
# An SD/eMMC host controller BEHIND A PCI-TO-PCI BRIDGE must be found.
#
# WHY THIS IS A SEPARATE GATE FROM smoke-sdhci-detect. That one attaches
# `-device sdhci-pci` with no bus argument, so QEMU puts it on bus 0 -- where the
# enumeration has always looked. Every SD gate in this tree was therefore blind
# to the question of WHERE the controller is, and the enumeration walked bus 0
# and did not follow bridges. On an IdeaPad whose internal storage is eMMC that
# printed `sdhci: no SD/eMMC host controller` and the machine could not be
# installed onto (2026-09-12).
#
# THE TOPOLOGY IS THE TEST, so it is spelled out rather than left to QEMU's
# defaults: a pcie-pci-bridge at 00:03.0 with the controller behind it, which
# lands at 01:01.0. Measured that day: the shipping build found it and brought it
# up; PCI_BUS0_ONLY=1 printed `no SD/eMMC host controller` on the same command
# line.
#
# THE EVIDENCE IS KEPT ON THE FAILURE PATH. That is the only case anyone needs it.
set -u
ISO=${1:?usage: sdhci_bridge_test.sh <iso>}
TIMEOUT=${SMOKE_TIMEOUT:-60}
EXPECT=${SDHCI_BRIDGE_EXPECT:-found}
# A DIRECTORY, not a bare file, and that is the tree's convention rather than a
# preference: .gitignore's catch-all for gate evidence is `.*-evidence*/` with a
# trailing slash, so it matches directories only. A gate that dropped a plain
# file here would leave it untracked-but-not-ignored, which is how a 2.3 MB
# screendump reached main once already (see the note in .gitignore).
EVID=${SDHCI_BRIDGE_EVIDENCE:-.sdhci-bridge-evidence}
LOG="$EVID/serial.log"

rm -rf "$EVID"; mkdir -p "$EVID"
timeout "$TIMEOUT" qemu-system-x86_64 \
    -m 512M -machine q35 -smp 2 -display none \
    -serial "file:$LOG" -net none -no-reboot -no-shutdown \
    -device pcie-pci-bridge,id=br0,bus=pcie.0,addr=3 \
    -device sdhci-pci,bus=br0,addr=1 \
    -cdrom "$ISO" >/dev/null 2>&1

if [ ! -s "$LOG" ]; then
    echo "SDHCI_BRIDGE: FAIL the guest produced no serial output at all -- a dead"
    echo "              boot, which says nothing about the bus walk (evidence: $EVID)"
    exit 1
fi

# HOW WE KNOW THE CONTROLLER IS REALLY BEHIND THE BRIDGE, and not quietly placed
# on bus 0 by QEMU -- in which case 'found' would prove nothing about bridges.
# The answer is the CONTROL ARM, which is why this gate is worthless without it:
# PCI_BUS0_ONLY=1 walks bus 0 and nothing else, and on this same command line it
# reports the controller ABSENT. A device bus 0 cannot see is not on bus 0. The
# pair asserts the topology between them; neither half can do it alone, and a
# check here that grepped the shipping log for a bridge would find nothing,
# because the enumeration deliberately prints a count and not a listing.

if grep -qa "sdhci: host controller v" "$LOG"; then
    GOT=found
elif grep -qa "sdhci: no SD/eMMC host controller" "$LOG"; then
    GOT=absent
else
    echo "SDHCI_BRIDGE: FAIL neither sdhci marker appeared; the boot did not reach"
    echo "              the probe (evidence: $EVID)"
    exit 1
fi

if [ "$GOT" != "$EXPECT" ]; then
    if [ "$EXPECT" = found ]; then
        echo "SDHCI_BRIDGE: FAIL the controller behind the bridge was NOT found --"
        echo "              the bus walk is not following bridges (evidence: $EVID)"
    else
        echo "SDHCI_BRIDGE: FAIL the arm found the controller anyway; PCI_BUS0_ONLY"
        echo "              did not reproduce the defect (evidence: $EVID)"
    fi
    exit 1
fi

rm -rf "$EVID"
if [ "$EXPECT" = found ]; then
    echo "SDHCI_BRIDGE: PASS the controller behind the bridge was found and brought up"
else
    echo "SDHCI_BRIDGE: PASS the arm cannot see behind the bridge, as it must"
fi
