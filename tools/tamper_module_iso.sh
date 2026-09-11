#!/bin/sh
# Build a boot ISO whose kernel is untouched but one boot-module payload has been
# altered — the exact shape of audit finding A4's attack: the attacker cannot
# change the (reproducible, eventually signed) kernel image, but can rewrite what
# the ISO ships as /bin/<name>.
#
# Usage: tamper_module_iso.sh <out.iso> <kernel.elf> <grub.cfg> <file>:<dest> ...
#
# The FIRST pair's payload is corrupted (one byte flipped in place, so the size is
# unchanged and only the hash differs — the strongest form of the test, since a
# size check alone would not catch it). Everything else ships verbatim, so a
# correct kernel refuses exactly one module and boots normally on the rest.
set -eu

out=$1; kernel=$2; cfg=$3
shift 3
[ "$#" -gt 0 ] || { echo "tamper_module_iso: no modules given" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT INT TERM
mkdir -p "$stage/iso/boot/grub"
cp "$kernel" "$stage/iso/boot/kernel.elf"

: > "$stage/mods.txt"
first=1
for pair in "$@"; do
    f=${pair%%:*}
    dest=${pair##*:}
    base=$(basename "$f")
    cp "$f" "$stage/iso/boot/$base"
    if [ "$first" = 1 ]; then
        # Flip one byte in the middle of the payload: same length, different hash.
        sz=$(wc -c < "$f" | tr -d ' ')
        off=$((sz / 2))
        printf '\377' | dd of="$stage/iso/boot/$base" bs=1 seek="$off" \
            conv=notrunc status=none
        echo "tamper_module_iso: corrupted $base (dest $dest) at offset $off" >&2
        first=0
    fi
    printf '    module2 /boot/%s %s\n' "$base" "$dest" >> "$stage/mods.txt"
done

awk '/@HORUS_MODULES@/{while((getline l < "'"$stage"'/mods.txt")>0) print l; next} {print}' \
    "$cfg" > "$stage/grub.cfg"

# THE SAME MEASURED BOOT IMAGE THE REAL ISO GETS, since 2026-09-11 (S92). This
# used grub-mkrescue and staged grub.cfg onto the ISO, which stopped working the
# moment the config began checking a hash that lives in a memdisk INSIDE the
# boot image: with no memdisk the check finds no pin, fails, and the kernel
# never runs -- so this gate would have gone red asserting the absence of a
# marker its own ISO made unreachable, which looks exactly like the module check
# regressing. The kernel here is NOT tampered, so it matches its pin and boots;
# what is tampered is a module, which is this gate's subject.
GRUB_I386_DIR=${GRUB_I386_DIR:-/usr/lib/grub/i386-pc}
GRUB_DIR="$GRUB_I386_DIR" "$(dirname "$0")/mkbootimg.sh" \
    "$kernel" "$stage/grub.cfg" "$stage/iso/boot/grub/eltorito.img" >/dev/null \
    || { echo "tamper_module_iso: mkbootimg failed" >&2; exit 1; }

xorriso -as mkisofs -quiet -o "$out" \
    -b boot/grub/eltorito.img -no-emul-boot -boot-load-size 4 -boot-info-table \
    --grub2-boot-info --grub2-mbr "$GRUB_I386_DIR/boot_hybrid.img" \
    "$stage/iso" >/dev/null 2>&1 \
    || { echo "tamper_module_iso: xorriso failed" >&2; exit 1; }
