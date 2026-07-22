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
    "$cfg" > "$stage/iso/boot/grub/grub.cfg"

grub-mkrescue -o "$out" "$stage/iso" >/dev/null 2>&1 \
    || { echo "tamper_module_iso: grub-mkrescue failed" >&2; exit 1; }
