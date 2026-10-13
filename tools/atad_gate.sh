#!/usr/bin/env bash
# One boot of the ring-3 IDE driver's gate (make smoke-atad): a scratch disk as
# the primary master, atad's own verdict, then the host's check of the disk.
#
#   tools/atad_gate.sh <iso> [MiB]
#
# THREE WITNESSES, one per thing the gate claims. The guest's ATADTEST: PASS
# says the driver identified the drive, read block 0 and the planted block at
# 0x010205 (whose address uses all three LBA registers), and read back what it
# wrote. The image, read on the host after QEMU exits, says the write landed at
# sectors 8-15 and nowhere else, and the capacity atad reported is the image's
# own: a driver that wrote to the wrong sectors, or decoded a plausible wrong
# capacity, passes every check made in the guest. That is
# tools/block_scratch.py verify ata.
#
# QEMU's default machine (i440fx), not q35: its PIIX IDE controller is the one
# every installer gate boots, and atad does no DMA, so there is nothing for an
# IOMMU to confine.
#
# The evidence is kept when it goes red and removed when it is green.
set -u
ISO=${1:?usage: atad_gate.sh <iso> [MiB]}
MIB=${2:-128}
# A DIRECTORY: .gitignore's catch-all for gate evidence is `.*-evidence*/`.
EVID=".atad-evidence-$MIB"
rm -rf "$EVID"; mkdir -p "$EVID"
IMG="$EVID/disk.img"
LOG="$EVID/serial.log"

python3 tools/block_scratch.py make ata "$IMG" "$MIB" || { echo "[atad] FAIL could not make the disk"; exit 1; }

if ! SMOKE_DISK="$IMG" SMOKE_BOOT_ORDER=d SMOKE_LOG="$LOG" \
     SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-90}" MARKER_ONLY=1 \
     REQUIRE_MARKER='ATADTEST: PASS' FAIL_MARKER='ATADTEST: FAIL' \
     tools/smoke_test.sh "$ISO"; then
    echo "[atad] FAIL ($MIB MiB) the guest did not pass; what atad said:"
    grep -a -E 'ATAD|ata:' "$LOG" | sed 's/\r//; s/^/    /'
    echo "  evidence: $EVID"
    exit 1
fi
grep -a -E 'ATAD:|ata:' "$LOG" | sed 's/\r//; s/^/    /'

if ! python3 tools/block_scratch.py verify ata "$IMG" "$LOG"; then
    echo "[atad] FAIL ($MIB MiB) the guest passed, and the disk on the host says otherwise"
    echo "  evidence: $EVID"
    exit 1
fi
rm -rf "$EVID"
echo "[atad] PASS ($MIB MiB) the drive came up, the write is on the image, and the capacity is the disk's own"
