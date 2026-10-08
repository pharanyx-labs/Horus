#!/usr/bin/env bash
# Build the EFI system partition image an install writes to the disk (S115).
#
#   mkesp.sh <kernel.elf> <mods.txt> <module dir> <out esp.img>
#
# <mods.txt> holds the `module2 /boot/<file> <name>` lines the ISO rule built
# for this kernel, and <module dir> the files they name. The image is FAT32,
# because UEFI firmware is only required to read FAT32 from a fixed disk, and it
# holds exactly what the disk needs to start on its own:
#
#   /EFI/BOOT/BOOTX64.EFI  GRUB, with grub-installed.cfg and the kernel's pinned
#                          SHA-256 in its memdisk (tools/mkbootimg.sh), at the
#                          removable-media path firmware boots without an NVRAM
#                          entry; Horus cannot write those (no UEFI runtime).
#   /boot/kernel.elf       this kernel
#   /boot/<modules>        this kernel's boot modules, which it verifies itself
#                          against its embedded manifest (S96)
#
# The whole image is then pinned by the INSTALL MEDIA's GRUB config (the caller
# puts its hash on the install entry's command line), because the kernel cannot
# pin an image that contains it.
#
# 34 MiB is the smallest FAT32 that mformat will make with 512-byte clusters
# (FAT32 needs at least 65,525 of them); the ESP partition is 64 MiB, and the
# kernel zeroes the space past the image.
set -euo pipefail
KERNEL=${1:?usage: mkesp.sh <kernel.elf> <mods.txt> <module dir> <out esp.img>}
MODS=${2:?}
MODDIR=${3:?}
OUT=${4:?}
HERE=$(cd "$(dirname "$0")/.." && pwd)
GRUB_DIR=${GRUB_DIR:-/usr/lib/grub/i386-pc}
EFI_GRUB_DIR=${EFI_GRUB_DIR:-/usr/lib/grub/x86_64-efi}
ESP_SECTORS=69632

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

# The FAT serial is the first 32 bits of the kernel's SHA-256, and the config
# carries it as the fallback root (grub-installed.cfg): an ESP laid out from
# another build has another serial, so GRUB cannot settle on one.
SERIAL=$(sha256sum "$KERNEL" | cut -c1-8)
ESP_UUID="${SERIAL:0:4}-${SERIAL:4:4}"
awk -v mods="$MODS" '/@HORUS_MODULES@/{while((getline l < mods)>0) print l; next} {print}' \
    "$HERE/grub-installed.cfg" | sed "s/@HORUS_ESP_UUID@/$ESP_UUID/" > "$WORK/grub.cfg"
GRUB_DIR="$GRUB_DIR" EFI_GRUB_DIR="$EFI_GRUB_DIR" EFI_BIN_OUT="$WORK/BOOTX64.EFI" \
    "$HERE/tools/mkbootimg.sh" "$KERNEL" "$WORK/grub.cfg" "$WORK/unused-eltorito.img" >/dev/null

rm -f "$OUT"
# -F FAT32, -c 1 one sector per cluster, a serial (-N) fixed by the kernel, so the image is a
# function of its contents.
mformat -i "$OUT" -C -F -c 1 -T "$ESP_SECTORS" -h 64 -s 32 -N "$SERIAL" -v HORUSESP ::
mmd -i "$OUT" ::/EFI ::/EFI/BOOT ::/boot
mcopy -i "$OUT" "$WORK/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "$OUT" "$KERNEL" ::/boot/kernel.elf
while read -r _ path _; do
    f=$(basename "$path")
    mcopy -i "$OUT" "$MODDIR/$f" "::/boot/$f"
done < "$MODS"
echo "mkesp: $OUT ($(du -k "$OUT" | cut -f1) KiB on disk) holds GRUB, the kernel and $(wc -l < "$MODS") modules"
