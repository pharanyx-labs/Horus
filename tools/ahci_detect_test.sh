#!/bin/bash
# Boot a machine that HAS a SATA controller and require the kernel to say so.
#
# WHY A MACHINE OF ITS OWN. Every other gate here boots QEMU's default i440fx,
# which has no AHCI at all -- so "no SATA controller" is the only answer any
# existing arm could ever observe, and a probe that always said that would pass
# every one of them. This boots q35, which is what a machine built this decade
# looks like, with a disk on its AHCI bus.
#
# WHAT IT REQUIRES, and why it is three things rather than one:
#   - the HBA is recognised at all (a version line);
#   - port 0 is reported as a SATA DISK, not merely as "something present" --
#     the signature is what separates a disk from the ATAPI device that the
#     boot CD-ROM itself presents on another port;
#   - the count line, which is what the installer would eventually act on.
# A probe that found the controller and misread every port would satisfy the
# first and fail the second, which is the point of asking separately.
#
# Usage: tools/ahci_detect_test.sh [iso]
#   AHCI_EXPECT=absent   require the probe to say NOTHING (the control arm)
#   SMOKE_TIMEOUT        seconds (default 60)
set -u

ISO="${1:-horus.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-60}"
EXPECT="${AHCI_EXPECT:-present}"
EVID="${AHCI_EVIDENCE:-.ahci-evidence}"

rm -rf "$EVID"; mkdir -p "$EVID"
[ -f "$ISO" ] || { echo "ahci-detect: no such ISO: $ISO"; exit 2; }

DISK_MB="${AHCI_DISK_MB:-128}"
DISK="$EVID/sata.img"
qemu-img create -f raw "$DISK" "${DISK_MB}M" >/dev/null 2>&1 || {
    # dd rather than failing: qemu-img is not in every toolchain list, and a
    # 64 MiB sparse file is all this needs.
    dd if=/dev/zero of="$DISK" bs=1M count=0 seek="$DISK_MB" status=none; }

LOG="$EVID/serial.log"
timeout "$TIMEOUT" qemu-system-x86_64 -m 512M -cpu qemu64 -machine q35 \
    -display none -no-reboot -cdrom "$ISO" \
    -drive "id=sata0,file=$DISK,format=raw,if=none" \
    -device ide-hd,drive=sata0,bus=ide.0 \
    -serial "file:$LOG" >/dev/null 2>&1

if [ ! -s "$LOG" ]; then
    echo "ahci-detect: FAIL - the guest produced no serial output at all"
    exit 1
fi

if [ "$EXPECT" = absent ]; then
    if grep -qa "^\[.*\] ahci:\|ahci: " "$LOG"; then
        echo "CONTROL FAIL: the probe still reported, with AHCI_PROBE_ABSENT=1:"
        grep -a "ahci:" "$LOG" | sed 's/\r//' | sed 's/^/    /'
        echo "  evidence: $LOG"
        exit 1
    fi
    # The machine must still have BOOTED -- otherwise "said nothing about AHCI"
    # would be satisfied by a kernel that died before it got there, and the arm
    # would pass for a reason that has nothing to do with the probe.
    if ! grep -qa "kernel ready" "$LOG"; then
        echo "CONTROL FAIL: the probe was silent, but so was the boot -- the"
        echo "  kernel never reached 'kernel ready', so this witnesses nothing."
        echo "  evidence: $LOG"
        exit 1
    fi
    echo "[ahci] CONTROL PASS - the controller is there and the kernel says nothing about it"
    exit 0
fi

fail=0
check() {  # $1 = description, $2 = pattern
    if grep -qa "$2" "$LOG"; then
        echo "  [ OK ] $1"
    else
        echo "  [FAIL] $1"
        fail=1
    fi
}

check "the HBA is recognised"             "ahci: HBA v"
check "port 0 is reported as a SATA disk"  "ahci: port 0: SATA disk"
check "the disk count is reported"         "ahci: 1 SATA disk"
# IDENTIFY: the drive answered a real command over DMA, not merely a link-status
# read. The MODEL comes from the drive; the CAPACITY is checked against the size
# this script created, so a driver that returned a plausible constant -- or read
# the right words from the wrong offset -- fails here rather than passing on a
# number nobody compared to anything.
check "the drive answered IDENTIFY"        "QEMU HARDDISK"
check "the capacity is the disk's own"     "QEMU HARDDISK, ${DISK_MB} MiB"

if [ "$fail" != 0 ]; then
    echo "AHCI-DETECT FAIL: what the guest actually said:"
    # The model/capacity line is INDENTED under its port and carries no "ahci:"
    # prefix, so a dump that grepped for that prefix alone hid the one line the
    # capacity check fails on -- which is the line anyone reading a red run needs.
    grep -aE "ahci:|^\[[^]]*\] +[A-Z]" "$LOG" | sed 's/\r//' | sed 's/^/    /' || echo "    (nothing)"
    echo "  evidence: $LOG"
    exit 1
fi
echo "AHCI-DETECT PASS: the SATA controller and its disk were both identified"
