#!/usr/bin/env bash
# The witness for docs/LIMITATIONS.md 1.30 (SECURITY.md S143): metadata a volume
# keeps in the clear, edited on the disk behind the kernel's back, is refused.
#
# THE EDITING IS DONE HERE, ON THE HOST, because that is what a physical attacker
# with the disk does. Boot 1 reports byte positions on the image; this script
# first checks that inode A's owner cannot be read off it, then writes four small
# edits there, checks that each one changed the image, and boots
# again. Then it moves the superblock's inode table two blocks on and boots a
# third time.
#
#   edit 1  inode A's mode to 0777 and its owner to 0 (the inode table)
#   edit 2  a pointer entry of file B to the block that held an EARLIER version of
#           the same logical block (a pointer block in the data region). On a
#           volume whose pointer blocks are sealed the eight bytes land in
#           ciphertext, which is the point: the same edit, the same bytes.
#   edit 3  B's block-0 bit flipped in the block bitmap (cleared, in the clear)
#   edit 4  sb.inode_table_start + 2, before boot 3. Two blocks, not one: one
#           block on is A's table block, which edit 1 already spoiled, so a
#           build that accepted the move would still refuse inode 1 and the
#           confusion it exists to show would not appear. Two blocks on is a
#           table block nothing wrote: genuine, and some other inode's.
#
# Usage: SPAN_EXPECT2='<boot-2 marker>' [SPAN_EXPECT3='<boot-3 marker>'] \
#        tools/meta_span_tamper.sh horus.iso
# With SPAN_EXPECT3 empty the run ends after boot 2: the arms for edits 1 to 3
# have nothing to show in boot 3, since their boot 2 already failed.
set -euo pipefail

ISO=${1:-horus.iso}
IMG=${SPAN_IMG:-span.img}
LOG="${IMG%.img}"
BS=${SPAN_BS:?SPAN_BS (filesystem block size) must be set}
NBLOCKS=${SPAN_BLOCKS:?SPAN_BLOCKS (volume blocks) must be set}
TMO=${SPAN_TIMEOUT:-600}
EXPECT2=${SPAN_EXPECT2:-'SPAN: PASS inode, bitmap and pointer edits refused'}
OPPOSITE2=${SPAN_OPPOSITE2:-'SPAN: FAIL'}
EXPECT3=${SPAN_EXPECT3-'GEOM: PASS an edited superblock was refused at unlock'}
OPPOSITE3=${SPAN_OPPOSITE3:-'GEOM: FAIL'}

rm -f "$IMG" "$LOG"-p1.log "$LOG"-p2.log "$LOG"-p3.log "$LOG"-before.img
truncate -s $(( NBLOCKS * BS )) "$IMG"

echo "[span] boot 1/3 - two files, and where their metadata lives"
SMOKE_TIMEOUT="$TMO" MARKER_ONLY=1 SMOKE_DISK="$IMG" \
    REQUIRE_MARKER='SPAN: phase1 complete' FAIL_MARKER='SPAN: FAIL' \
    tools/smoke_test.sh "$ISO" | tee "$LOG-p1.log"

line=$(grep -m1 -oE 'SPAN: targets .*' "$LOG-p1.log" || true)
if [ -z "$line" ]; then
    echo "[span] FAIL: boot 1 reported no targets; see $LOG-p1.log" >&2
    exit 1
fi
val() { echo "$line" | grep -oE "$1=[0-9]+" | cut -d= -f2; }
mode_at=$(val mode_at); uid_at=$(val uid_at); ptr_at=$(val ptr_at)
old_block=$(val old_block); bit_at=$(val bit_at); bit_mask=$(val bit_mask)
geom_at=$(val geom_at); a_uid=$(val a_uid); a_gid=$(val a_gid)
for v in mode_at uid_at ptr_at old_block bit_at bit_mask geom_at a_uid a_gid; do
    if [ -z "${!v:-}" ]; then
        echo "[span] FAIL: boot 1 did not report $v; see $LOG-p1.log" >&2
        exit 1
    fi
done
echo "[span] targets: mode@$mode_at uid@$uid_at ptr@$ptr_at->$old_block bit@$bit_at/$bit_mask geom@$geom_at"

# CONFIDENTIALITY FIRST, before anything is edited (LIMITATIONS 1.35). Inode A's
# owner and group are eight bytes nothing else on the image spells; in the clear
# they sit side by side in A's slot. A sealed table must not show them anywhere,
# the journal included. SPAN_EXPECT_PLAIN=1 is an arm's direction: they must be
# found, which is what a table in the clear gives an attacker. With SPAN_PLAIN_ONLY=1
# as well the run ends there (the confidentiality arm); without it the run goes on
# to the edits (format v13's span, which is in the clear AND unchecked).
found=$(python3 -I -c '
import struct, sys
img, uid, gid = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
with open(img, "rb") as f:
    print(f.read().find(struct.pack("<II", uid, gid)))
' "$IMG" "$a_uid" "$a_gid")
if [ "${SPAN_EXPECT_PLAIN:-0}" = 1 ]; then
    if [ "$found" -lt 0 ]; then
        echo "[span] FAIL: the arm expected inode A's owner in the clear and it is not on the image" >&2
        exit 1
    fi
    echo "[span] CONTROL: inode A's owner and group are readable on the image at byte $found"
    if [ "${SPAN_PLAIN_ONLY:-0}" = 1 ]; then
        rm -f "$IMG" "$LOG"-p1.log
        exit 0
    fi
elif [ "$found" -ge 0 ]; then
    echo "[span] FAIL: inode A's owner and group are readable on the image at byte $found" >&2
    exit 1
else
    echo "[span] inode A's owner and group appear nowhere on the image"
fi

# One small Python step for the byte edits: dd cannot write a little-endian
# integer, and a printf | xxd pipeline is the kind of thing that silently writes
# the wrong width. -I: nothing on the path or in this directory is imported.
cp "$IMG" "$LOG-before.img"
python3 -I - "$IMG" "$mode_at" "$uid_at" "$ptr_at" "$old_block" "$bit_at" "$bit_mask" <<'EOF'
import struct, sys
img, mode_at, uid_at, ptr_at, old_block, bit_at, bit_mask = sys.argv[1], *map(int, sys.argv[2:])
with open(img, "r+b") as f:
    f.seek(mode_at); f.write(struct.pack("<I", 0o100777))
    f.seek(uid_at);  f.write(struct.pack("<I", 0))
    f.seek(ptr_at);  f.write(struct.pack("<Q", old_block))
    # FLIPPED, not cleared: on a sealed bitmap the byte is ciphertext, where
    # clearing a bit that happens to be 0 would edit nothing. On a bitmap in the
    # clear the bit is set (a live block), so the flip clears it all the same.
    f.seek(bit_at);  b = f.read(1)[0]; f.seek(bit_at); f.write(bytes([b ^ bit_mask]))
EOF

# ANTI-VACUITY. Each edit must have changed the image; an edit that wrote the
# bytes already there makes boot 2 test nothing.
changed=0
for at in "$mode_at" "$uid_at" "$ptr_at" "$bit_at"; do
    # Eight bytes from each position: the widest edit is eight, and the others
    # leave the rest of the window as it was.
    if ! cmp -s -i "$at:$at" -n 8 "$LOG-before.img" "$IMG"; then
        changed=$((changed + 1))
    fi
done
if [ "$changed" -ne 4 ]; then
    echo "[span] FAIL: $changed of the 4 edits changed the image; boot 2 would test nothing" >&2
    exit 1
fi
echo "[span] all four edits changed the image"

echo "[span] boot 2/3 - every edit must be refused"
SMOKE_TIMEOUT="$TMO" MARKER_ONLY=1 SMOKE_DISK="$IMG" \
    REQUIRE_MARKER="$EXPECT2" FAIL_MARKER="$OPPOSITE2" \
    tools/smoke_test.sh "$ISO" | tee "$LOG-p2.log"

if [ -n "$EXPECT3" ]; then
    python3 -I - "$IMG" "$geom_at" <<'EOF'
import struct, sys
img, at = sys.argv[1], int(sys.argv[2])
with open(img, "r+b") as f:
    f.seek(at); v = struct.unpack("<Q", f.read(8))[0]
    f.seek(at); f.write(struct.pack("<Q", v + 2))
EOF
    echo "[span] boot 3/3 - the superblock's inode table moved two blocks on"
    SMOKE_TIMEOUT="$TMO" MARKER_ONLY=1 SMOKE_DISK="$IMG" \
        REQUIRE_MARKER="$EXPECT3" FAIL_MARKER="$OPPOSITE3" \
        tools/smoke_test.sh "$ISO" | tee "$LOG-p3.log"
fi

# The logs are kept on the failure path deliberately (set -e leaves them): a
# gate's evidence matters in exactly the case it goes red.
rm -f "$IMG" "$LOG"-p1.log "$LOG"-p2.log "$LOG"-p3.log "$LOG"-before.img
