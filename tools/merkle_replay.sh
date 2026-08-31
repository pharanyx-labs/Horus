#!/usr/bin/env bash
# Arm B of docs/design/meta-cache-merkle.md: replay a genuine past state of one
# metadata block and the level-0 node that recorded it, and require the volume to
# refuse the blocks that subtree covers.
#
# THE TAMPERING IS DONE HERE, ON THE HOST, with dd -- because that is what a
# physical attacker with the disk actually does, and because bytes restored from
# a copy of this very image are provably a real past state rather than something
# the kernel was talked into producing.
#
# WHY BOTH BLOCKS. Restoring the metadata block alone changes its content, so its
# leaf hash no longer matches the node above it and the leaf check refuses it --
# which proves nothing about the tree, because a design that MAC'd every block
# independently would refuse it too. Restoring the node WITH it makes the pair
# internally consistent: every hash checks out locally, and the only thing wrong
# is that the pair is old. Nothing but the chain to the current root can say so.
#
# Usage: MERKLE_EXPECT='<phase-3 marker>' tools/merkle_replay.sh boot.iso
set -euo pipefail

ISO=${1:-boot.iso}
IMG=${MERKLE_IMG:-merkle.img}
SNAP="${IMG%.img}-snap.img"
LOG="${IMG%.img}"
BS=${MERKLE_BS:?MERKLE_BS (filesystem block size) must be set}
NBLOCKS=${MERKLE_BLOCKS:?MERKLE_BLOCKS (volume blocks) must be set}
TMO=${MERKLE_TIMEOUT:-600}
EXPECT=${MERKLE_EXPECT:-'MERKLE: PASS stale node refused'}
# The marker that means boot 3 came out the OTHER way. Without it a run whose
# outcome flipped waits out the whole timeout before failing: measured 2026-08-31,
# `make smoke-merkle-replay MERKLE_NODE_TRUST_CACHED=1` reddened correctly and
# took 600 seconds to do it, because boot 3 was waiting for a marker the defect
# build never prints. Each target sets this to its counterpart's marker, so a
# regression fails in seconds and says which way it went.
OPPOSITE=${MERKLE_OPPOSITE:-'MERKLE: FAIL'}
# Which of the two blocks to restore. `both` is the replay the gates run: a
# metadata block AND the node recording it, so the pair is internally consistent
# and only the chain to the root can call it old.
#
# `meta` exists to MEASURE the other direction, and is not run by any gate. It
# restores the block without its node, so the block's own leaf hash no longer
# matches what the node records -- which even MERKLE_SKIP_PARENT_BIND=1 refuses.
# That is what supports the claim that the arm is aimed at the parent chain
# rather than at the MAC: the weakened build still catches a block whose content
# does not match its recorded hash, and fails only on the question of whether
# that hash is the current one.
RESTORE=${MERKLE_RESTORE:-both}

rm -f "$IMG" "$SNAP" "$LOG"-p1.log "$LOG"-p2.log "$LOG"-p3.log
# ONE BLOCK LONGER THAN THE VOLUME. The extra block carries the harness's phase
# counter: storage outside the filesystem, so nothing the tampering rewinds can
# take the phase with it, and nothing in a shipping layout has to reserve it.
truncate -s $(( NBLOCKS * BS )) "$IMG"

echo "[merkle] boot 1/3 - write set A, report the tamper targets"
SMOKE_TIMEOUT="$TMO" MARKER_ONLY=1 SMOKE_DISK="$IMG" \
    REQUIRE_MARKER='MERKLE: phase1 complete' FAIL_MARKER='MERKLE: FAIL' \
    tools/smoke_test.sh "$ISO" | tee "$LOG-p1.log"

meta=$(grep -oE 'meta_block=[0-9]+' "$LOG-p1.log" | head -1 | cut -d= -f2 || true)
node=$(grep -oE 'node_block=[0-9]+'  "$LOG-p1.log" | head -1 | cut -d= -f2 || true)
if [ -z "${meta:-}" ] || [ -z "${node:-}" ]; then
    echo "[merkle] FAIL: boot 1 reported no tamper targets; see $LOG-p1.log" >&2
    exit 1
fi
echo "[merkle] targets: metadata block $meta, level-0 node block $node"
cp "$IMG" "$SNAP"

echo "[merkle] boot 2/3 - write set B into the same metadata block"
SMOKE_TIMEOUT="$TMO" MARKER_ONLY=1 SMOKE_DISK="$IMG" \
    REQUIRE_MARKER='MERKLE: phase2 complete' FAIL_MARKER='MERKLE: FAIL' \
    tools/smoke_test.sh "$ISO" | tee "$LOG-p2.log"

# ANTI-VACUITY. If boot 2 did not actually change these two blocks, the restore
# below is a no-op and boot 3 would pass without anything having been replayed --
# the same shape as a crash gate whose working set fits its cache. Assert the
# change positively, before undoing it.
changed=0
for b in "$meta" "$node"; do
    if ! cmp -s -i $((b * BS)):$((b * BS)) -n "$BS" "$SNAP" "$IMG"; then
        changed=$((changed + 1))
    fi
done
if [ "$changed" -ne 2 ]; then
    echo "[merkle] FAIL: boot 2 changed $changed of the 2 target blocks;" \
         "the restore would replay nothing and boot 3 would test nothing" >&2
    exit 1
fi
echo "[merkle] both target blocks changed in boot 2 - the replay has something to undo"

echo "[merkle] restoring a genuine past state (restore=$RESTORE)"
dd if="$SNAP" of="$IMG" bs="$BS" skip="$meta" seek="$meta" count=1 conv=notrunc status=none
if [ "$RESTORE" = both ]; then
    dd if="$SNAP" of="$IMG" bs="$BS" skip="$node" seek="$node" count=1 conv=notrunc status=none
fi

echo "[merkle] boot 3/3 - read the replayed subtree back"
SMOKE_TIMEOUT="$TMO" MARKER_ONLY=1 SMOKE_DISK="$IMG" \
    REQUIRE_MARKER="$EXPECT" FAIL_MARKER="$OPPOSITE" \
    tools/smoke_test.sh "$ISO" | tee "$LOG-p3.log"

# The logs are kept on the failure path deliberately: a gate's evidence matters
# in exactly the case it goes red, and this tree has lost a red run's evidence
# to an rm on the failure path before.
rm -f "$IMG" "$SNAP" "$LOG"-p1.log "$LOG"-p2.log "$LOG"-p3.log
