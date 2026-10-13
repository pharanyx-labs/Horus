#!/usr/bin/env bash
# One boot of the block-driver protocol's gate (make smoke-blkproto): blktest as
# a ring-3 storage driver's supervisor and clients, then the host's check of the
# disk afterwards.
#
#   tools/blkproto_gate.sh <iso> <sd|nvme>
#
# TWO WITNESSES. The guest's BLKTEST: PASS says every rule blktest checks held:
# a client reaches only its extent, an unbound token and the supervisor's
# capability reach nothing, only the supervisor binds, and a bound frame is not
# bound again. The image, read on the host after QEMU exits, says the client's
# write landed at its extent's start (sector 2048) and nowhere else: a driver
# that ignored the start would have overwritten block 0 and still passed in the
# guest. That is tools/block_scratch.py verify blk.
#
# The evidence is kept when it goes red and removed when it is green.
set -u
ISO=${1:?usage: blkproto_gate.sh <iso> <sd|nvme>}
KIND=${2:?usage: blkproto_gate.sh <iso> <sd|nvme>}
EVID=".blkproto-evidence-$KIND"
rm -rf "$EVID"; mkdir -p "$EVID"
IMG="$EVID/disk.img"
LOG="$EVID/serial.log"

python3 tools/block_scratch.py make blk "$IMG" 64 || { echo "[blkproto] FAIL could not make the disk"; exit 1; }
case "$KIND" in
sd)   DISK=(SMOKE_SD="$IMG") ;;
nvme) DISK=(SMOKE_NVME="$IMG") ;;
*)    echo "[blkproto] FAIL kind must be sd or nvme"; exit 2 ;;
esac

# 'TEST: FAIL' matches the driver's own failure (SDHCIDTEST, NVMETEST) as well
# as blktest's, so a driver that never came up fails at once, not at the bound.
if ! env "${DISK[@]}" SMOKE_IOMMU=1 SMOKE_LOG="$LOG" SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-90}" \
     MARKER_ONLY=1 REQUIRE_MARKER='BLKTEST: PASS' FAIL_MARKER='TEST: FAIL' \
     tools/smoke_test.sh "$ISO"; then
    echo "[blkproto] FAIL ($KIND) the guest did not pass; what blktest and the driver said:"
    grep -a -E 'BLKTEST|SDHCID|NVMED|TEST: FAIL' "$LOG" | sed 's/\r//; s/^/    /'
    echo "  evidence: $EVID"
    exit 1
fi
grep -a -E 'BLKTEST:|serving the block protocol' "$LOG" | sed 's/\r//; s/^/    /'

if ! python3 tools/block_scratch.py verify blk "$IMG"; then
    echo "[blkproto] FAIL ($KIND) the guest passed, and the disk on the host says otherwise"
    echo "  evidence: $EVID"
    exit 1
fi
rm -rf "$EVID"
echo "[blkproto] PASS ($KIND) every client rule held, and the write is at its extent's start on the disk"
