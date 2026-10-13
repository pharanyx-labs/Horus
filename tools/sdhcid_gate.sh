#!/usr/bin/env bash
# One boot of the ring-3 SD/eMMC driver's gate (make smoke-sdhcid): a scratch
# card, the guest's verdict, and the host's check of the card afterwards.
#
#   tools/sdhcid_gate.sh <iso> <card|emmc> <MiB>
#
# THREE WITNESSES, because each catches what the others cannot:
#   1. the guest prints SDHCIDTEST: PASS -- it brought the card up, block 100
#      held this image's nonce (the addressing check), and its read-back of the
#      eight sectors it wrote matched;
#   2. the image, read on the host after QEMU exits, holds those sectors where
#      they belong (a write to the wrong place reads back fine in the guest);
#   3. the capacity the driver decoded equals the size of the image QEMU was
#      given (a CSD decoder off by eight bits reads a plausible wrong number).
# Two and three are tools/block_scratch.py verify sd.
#
# THE EVIDENCE IS KEPT WHEN IT GOES RED, which is the only time anyone needs it,
# and removed when it is green: the images are sparse but can be 64 GiB long.
set -u
ISO=${1:?usage: sdhcid_gate.sh <iso> <card|emmc> <MiB>}
KIND=${2:?usage: sdhcid_gate.sh <iso> <card|emmc> <MiB>}
MIB=${3:?usage: sdhcid_gate.sh <iso> <card|emmc> <MiB>}
# A DIRECTORY: .gitignore's catch-all for gate evidence is `.*-evidence*/`.
EVID=".sdhcid-evidence-$KIND-$MIB"
rm -rf "$EVID"; mkdir -p "$EVID"
IMG="$EVID/card.img"
LOG="$EVID/serial.log"

python3 tools/block_scratch.py make sd "$IMG" "$MIB" || { echo "[sdhcid] FAIL could not make the card"; exit 1; }

if ! SMOKE_SD="$IMG" SMOKE_SD_KIND="$KIND" SMOKE_IOMMU=1 SMOKE_LOG="$LOG" \
     SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-90}" MARKER_ONLY=1 \
     REQUIRE_MARKER='SDHCIDTEST: PASS' FAIL_MARKER='SDHCIDTEST: FAIL' \
     tools/smoke_test.sh "$ISO"; then
    echo "[sdhcid] FAIL ($KIND, $MIB MiB) the guest did not pass; what sdhcid said:"
    grep -a -E 'SDHCID|sdhci' "$LOG" | sed 's/\r//; s/^/    /'
    echo "  evidence: $EVID"
    exit 1
fi
grep -a -E 'SDHCID:' "$LOG" | sed 's/\r//; s/^/    /'

if ! python3 tools/block_scratch.py verify sd "$IMG" "$LOG"; then
    echo "[sdhcid] FAIL ($KIND, $MIB MiB) the guest passed, and the card on the host says otherwise"
    echo "  evidence: $EVID"
    exit 1
fi
rm -rf "$EVID"
echo "[sdhcid] PASS ($KIND, $MIB MiB) the card came up, the write is on the image, and the capacity is the card's own"
