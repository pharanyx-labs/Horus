#!/usr/bin/env bash
# S70: a whole-volume rollback is refused.
#
# THE TAMPERING IS A WHOLE-IMAGE RESTORE, done here on the host with `cp`,
# because that is exactly what the attack is: take an image of the disk, let the
# machine run on, put the image back. There is nothing for the kernel to
# simulate and nothing partial about it -- superblock, metadata region, Merkle
# tree and data all go back together, from one consistent moment. Every internal
# relationship in the restored volume holds, which is the whole point: the tree
# cannot see this, and no check inside the disk can.
#
# THE TPM STATE DIRECTORY IS KEPT ACROSS ALL THREE BOOTS. Without that the
# counter would be a fresh counter each time and the gate would be measuring
# nothing -- so it is created once, passed to every boot, and removed at the end.
#
# Usage: ROLLBACK_EXPECT='<boot-3 marker>' tools/rollback_replay.sh boot.iso
set -euo pipefail

ISO=${1:-boot.iso}
IMG=${ROLLBACK_IMG:-rollback.img}
SNAP="${IMG%.img}-snap.img"
LOG="${IMG%.img}"
BS=${ROLLBACK_BS:?ROLLBACK_BS must be set}
NBLOCKS=${ROLLBACK_BLOCKS:?ROLLBACK_BLOCKS must be set}
TMO=${ROLLBACK_TIMEOUT:-300}
EXPECT=${ROLLBACK_EXPECT:-'ROLLBACK: PASS a rolled-back volume was refused'}
OPPOSITE=${ROLLBACK_OPPOSITE:-'ROLLBACK: FAIL'}

# ABSOLUTE, deliberately. swtpm_setup and swtpm are handed this path and do not
# agree about a relative one -- with `rollback-tpmstate` the setup step fails
# silently (its output is discarded) and the emulator then starts on an empty
# state directory, so QEMU reports "TPM result for CMD_INIT: 0x9 operation
# failed" and the guest never boots. The symptom is a zero-length serial log,
# which reads exactly like a kernel that hung before its first print. It cost a
# round of looking at the wrong layer; the same harness worked when the image
# happened to be under /tmp.
TPMSTATE="$(cd "$(dirname "$IMG")" && pwd)/$(basename "${IMG%.img}")-tpmstate"
rm -rf "$TPMSTATE" "$IMG" "$SNAP" "$LOG"-p1.log "$LOG"-p2.log "$LOG"-p3.log
mkdir -p "$TPMSTATE"
truncate -s $(( NBLOCKS * BS )) "$IMG"

# SERIAL_OUT is the point of the log argument: run_with_swtpm.sh keeps the
# guest's serial output in a temporary file it deletes on exit, so without this
# a failed boot leaves nothing but "timed out without marker" -- which is what an
# infrastructure problem and a real regression look like in common. The logs are
# kept until the run succeeds.
boot() {   # boot <n> <require> <fail-marker> <logfile>
    KEEP_TPMSTATE="$TPMSTATE" SWTPM_TIMEOUT="$TMO" SMOKE_DISK="$IMG" \
        SERIAL_OUT="$4" REQUIRE_MARKER="$2" FAIL_MARKER="$3" \
        tools/run_with_swtpm.sh "$ISO"
}

echo "[rollback] boot 1/3 - format an anchored volume and write era 1"
boot 1 'ROLLBACK: found era 0 and wrote era 1' 'ROLLBACK: FAIL' "$LOG-p1.log"

echo "[rollback] the attacker images the disk"
cp "$IMG" "$SNAP"

echo "[rollback] boot 2/3 - the machine runs on; era 2 overwrites era 1"
boot 2 'ROLLBACK: found era 1 and wrote era 2' 'ROLLBACK: FAIL' "$LOG-p2.log"

# ANTI-VACUITY. If boot 2 left the image byte-identical there is nothing to roll
# back to and boot 3 would pass having replayed nothing -- the same shape as a
# crash gate whose working set fits its cache. Assert the change before undoing
# it, and assert POSITIVELY that the generation advanced, since that is the
# quantity the refusal is actually about.
if cmp -s "$SNAP" "$IMG"; then
    echo "[rollback] FAIL: boot 2 changed nothing; the restore would replay nothing" >&2
    exit 1
fi
g1=$(grep -oE 'ROLLBACK: gen=[0-9]+' "$LOG-p1.log" | head -1 | cut -d= -f2 || true)
g2=$(grep -oE 'ROLLBACK: gen=[0-9]+' "$LOG-p2.log" | head -1 | cut -d= -f2 || true)
if [ -z "${g1:-}" ] || [ -z "${g2:-}" ] || [ "$g2" -le "$g1" ]; then
    echo "[rollback] FAIL: the rollback generation did not advance ($g1 -> $g2);" \
         "the anchor is not moving and boot 3 would prove nothing" >&2
    exit 1
fi
echo "[rollback] the volume moved on: generation $g1 -> $g2"

echo "[rollback] restoring the ENTIRE earlier image"
cp "$SNAP" "$IMG"

echo "[rollback] boot 3/3 - the rolled-back volume is presented to the machine"
boot 3 "$EXPECT" "$OPPOSITE" "$LOG-p3.log"

# The logs are kept on the failure path deliberately: a gate's evidence matters
# in exactly the case it goes red.
rm -rf "$TPMSTATE" "$IMG" "$SNAP" "$LOG"-p1.log "$LOG"-p2.log "$LOG"-p3.log
