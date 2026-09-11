#!/bin/sh
# tamper_kernel_iso.sh -- stage the S92 attack: a medium whose MEASURED BOOT
# IMAGE is genuine and whose KERNEL is not.
#
# Usage: tamper_kernel_iso.sh <out.iso> <kernel.elf> <grub.cfg> [mod:name ...]
#
# ---------------------------------------------------------------------------
# WHAT THIS REPRODUCES, AND WHY IT IS THE RIGHT SHAPE
#
# The attacker in S92 does not need to write to the victim's disk and does not
# need a key. Before 2026-09-11 they needed nothing at all beyond the ability to
# boot the machine: PCR[8] and PCR[9] were extended by the kernel from its own
# compiled-in manifest and command line, so a kernel of their own construction
# reproducing those two values satisfied PolicyPCR(8,9) exactly and the TPM
# released the sealed volume key to it. Measured that day: two kernels with
# different SHA-256, byte-identical PCR 0..9.
#
# So this builds the boot image around the REAL kernel -- the image is byte for
# byte the one a genuine build produces, and measures into PCR[4] identically --
# and then puts a DIFFERENT kernel on the medium beside it. That is the whole
# attack, staged honestly: everything the firmware measures is authentic, and
# only the thing nothing measured has changed.
#
# A tampered kernel rather than a second real build, and the difference matters
# for what the gate proves: GRUB refuses BEFORE executing anything, so whether
# the substituted image would itself have booted is not a property under test.
# The byte is flipped deep in the file, past every header, so the image stays a
# structurally valid ELF -- a corrupt header would be refused by the loader for
# a reason that has nothing to do with the pin, and a gate that passes for the
# wrong reason is worse than no gate.
# ---------------------------------------------------------------------------
set -eu

OUT=${1:?usage: tamper_kernel_iso.sh <out.iso> <kernel.elf> <grub.cfg> [mod:name ...]}
KERNEL=${2:?usage: tamper_kernel_iso.sh <out.iso> <kernel.elf> <grub.cfg> [mod:name ...]}
CFG=${3:?usage: tamper_kernel_iso.sh <out.iso> <kernel.elf> <grub.cfg> [mod:name ...]}
shift 3

GRUB_I386_DIR=${GRUB_I386_DIR:-/usr/lib/grub/i386-pc}

[ -f "$KERNEL" ] || { echo "tamper_kernel_iso: no kernel at '$KERNEL'" >&2; exit 1; }
[ -f "$CFG" ]    || { echo "tamper_kernel_iso: no grub config at '$CFG'" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

mkdir -p "$WORK/iso/boot/grub"

# The modules, and the config assembled the way the horus.iso rule assembles it,
# so the only difference between this medium and a genuine one is the kernel.
: > "$WORK/mods.txt"
for pair in "$@"; do
    f=${pair%%:*}; name=${pair##*:}; base=$(basename "$f")
    cp "$f" "$WORK/iso/boot/$base"
    printf '    module2 /boot/%s %s\n' "$base" "$name" >> "$WORK/mods.txt"
done
awk -v mods="$WORK/mods.txt" \
    '/@HORUS_MODULES@/{while((getline l < mods)>0) print l; next} {print}' \
    "$CFG" > "$WORK/grub.cfg"

# The control arm, applied here as well as in the horus.iso rule, because this
# medium's config is assembled here and the arm has to reach it. Same rewrite,
# same reason: it disables the CHECK rather than removing the pin, so what the
# arm reproduces is a bootable substituted kernel and not a different refusal.
if [ "${BOOT_PIN_UNCHECKED:-0}" = 1 ]; then
    sed -i 's|^    hashsum --hash sha256 --check .*$|    true|' "$WORK/grub.cfg"
fi

# THE BOOT IMAGE PINS THE REAL KERNEL. Built from the genuine binary, before it
# is tampered -- so the image, and therefore PCR[4], is exactly what a real
# build produces.
#
# BOTH images, so the attack is staged on the UEFI path as well as the BIOS one.
# A tampered medium carrying only the BIOS image would leave the UEFI refusal
# untested -- and an attacker picks the door, not us. Verified 2026-09-11 under
# OVMF: HASH MISMATCH, then REFUSED, on that path too.
GRUB_DIR="$GRUB_I386_DIR" EFI_GRUB_DIR="${GRUB_EFI_DIR:-/usr/lib/grub/x86_64-efi}" \
    EFI_OUT="$WORK/iso/boot/grub/efi.img" "$(dirname "$0")/mkbootimg.sh" \
    "$KERNEL" "$WORK/grub.cfg" "$WORK/iso/boot/grub/eltorito.img" >/dev/null

# THE MEDIUM CARRIES A DIFFERENT ONE. One byte, deep enough to be past the ELF
# and multiboot2 headers (see the note above), flipped rather than set so the
# tamper cannot silently be a no-op if that byte already held the value.
cp "$KERNEL" "$WORK/iso/boot/kernel.elf"
OFF=${TAMPER_OFFSET:-700000}
SZ=$(wc -c < "$WORK/iso/boot/kernel.elf")
[ "$SZ" -gt "$OFF" ] || { echo "tamper_kernel_iso: kernel is only $SZ bytes, cannot tamper at $OFF" >&2; exit 1; }
OLD=$(od -An -tu1 -j "$OFF" -N 1 "$WORK/iso/boot/kernel.elf" | tr -d ' ')
NEW=$(( OLD ^ 0xFF ))
printf "$(printf '\\%03o' "$NEW")" | \
    dd of="$WORK/iso/boot/kernel.elf" bs=1 seek="$OFF" conv=notrunc status=none

REAL=$(sha256sum "$KERNEL" | awk '{print $1}')
FAKE=$(sha256sum "$WORK/iso/boot/kernel.elf" | awk '{print $1}')
[ "$REAL" != "$FAKE" ] || { echo "tamper_kernel_iso: tamper was a no-op" >&2; exit 1; }

xorriso -as mkisofs -quiet -o "$OUT" \
    -b boot/grub/eltorito.img -no-emul-boot -boot-load-size 4 -boot-info-table \
    --grub2-boot-info --grub2-mbr "$GRUB_I386_DIR/boot_hybrid.img" \
    -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat \
    "$WORK/iso"

echo "tamper_kernel_iso: $OUT pins $REAL and carries $FAKE"
