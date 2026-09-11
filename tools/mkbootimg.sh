#!/bin/sh
# mkbootimg.sh -- build the El Torito boot image that MEASURES THE KERNEL IT BOOTS.
#
# Usage: mkbootimg.sh <kernel.elf> <assembled-grub.cfg> <out-eltorito.img> [out-efi.img]
#
# The fourth argument, when given, is a FAT EFI System Partition image carrying
# the SAME memdisk for the UEFI boot path. Both are built here, from one
# memdisk, so the two firmware paths cannot end up pinning different kernels.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS, AND WHY IT IS NOT grub-mkrescue
#
# Until 2026-09-11 the boot chain measured NOTHING about the kernel. PCR[8] and
# PCR[9] are extended by the kernel itself, from a tag, the command line and the
# module manifest compiled into it -- so every input to both was a value the
# kernel supplied about itself. Measured 2026-09-11, two kernels with different
# SHA-256 produced byte-identical PCR 0..9 on the same machine: a purpose-built
# kernel reproducing a released build's manifest and command line satisfied
# PolicyPCR(8,9) exactly, and the TPM handed it the sealed volume key.
#
# The repair needs a measurement the kernel cannot produce, and on this boot
# path there was none to be had:
#
#   * GRUB's `tpm` module, which measures loaded binaries into PCR 9, DOES NOT
#     EXIST for i386-pc in Debian's grub-pc-bin -- only for x86_64-efi. The ISO
#     ships both firmware paths (see the EFI half below), so that module is
#     available on ONE of the two -- which is exactly why it is not used: a
#     measurement that exists on the UEFI path and not the BIOS one would leave
#     the BIOS path unprotected, and an attacker chooses the path. The pin below
#     works identically on both.
#   * The firmware PCRs are no help by themselves. Measured the same day: two
#     ISOs differing ONLY in kernel.elf produce identical PCR 0..7, because
#     SeaBIOS measures the BOOT IMAGE (this file's output), not what that image
#     goes on to load. Binding the seal to PCR 4 alone would bind it to
#     something an attacker reproduces byte for byte.
#
# What IS true, and is the whole of the fix: SeaBIOS measures THIS IMAGE into
# PCR[4], and the measurement tracks its contents. Measured, both directions:
# two boot images differing only in their embedded module set gave different
# PCR[4]; two builds of identical input gave the SAME PCR[4] even though the
# two ISOs around them had different SHA-256, because grub-mkrescue's wall-clock
# UUID (docs/LIMITATIONS.md 5.3a) does not reach the boot image.
#
# So the kernel's expected hash is put INSIDE the measured image, in a memdisk,
# alongside the config that checks it. That makes the two halves inseparable:
#
#   * a substituted kernel fails the hash check and GRUB refuses to boot it;
#   * an attacker who edits the expected hash, or deletes the check, has changed
#     the boot image -- so PCR[4] changes, and the TPM refuses to unseal.
#
# Neither half is a control on its own, which is why they are built together
# here rather than in two places that could drift apart.
#
# NO SIGNING KEY, deliberately. A signature would say "some kernel this key
# vouched for", and PCR[4] would then be identical across every such kernel --
# which is precisely the property being removed. A pinned hash says "this
# kernel", and makes a kernel change a boot-image change and therefore a PCR[4]
# change. The cost is real and is stated in docs/LIMITATIONS.md: updating the
# kernel means rebuilding this image, and a TPM-sealed volume must be resealed.
#
# `SECURITY.md` **S92**.
# ---------------------------------------------------------------------------
set -eu

KERNEL=${1:?usage: mkbootimg.sh <kernel.elf> <grub.cfg> <out.img>}
CFG=${2:?usage: mkbootimg.sh <kernel.elf> <grub.cfg> <out.img>}
OUT=${3:?usage: mkbootimg.sh <kernel.elf> <grub.cfg> <out.img>}

GRUB_DIR=${GRUB_DIR:-/usr/lib/grub/i386-pc}

[ -f "$KERNEL" ] || { echo "mkbootimg: no kernel image at '$KERNEL'" >&2; exit 1; }
[ -f "$CFG" ]    || { echo "mkbootimg: no grub config at '$CFG'" >&2; exit 1; }
[ -d "$GRUB_DIR" ] || {
    echo "mkbootimg: no i386-pc GRUB modules at '$GRUB_DIR' (install grub-pc-bin)" >&2
    exit 1
}
command -v grub-mkimage >/dev/null 2>&1 || {
    echo "mkbootimg: grub-mkimage not found (install grub-common)" >&2; exit 1
}

# EVERY MODULE THE CONFIG CAN REACH IS EMBEDDED HERE, and that is a requirement
# rather than an optimisation. The prefix is inside the memdisk, so a module the
# config `insmod`s that is NOT embedded would be looked for in the memdisk and
# not found -- and, worse, a module loaded from the ISO would be a file outside
# the measured image participating in the boot.
#
# The part_* set is the one GRUB probes when it enumerates partitions, not a
# list the config names. Leaving them out does not fail loudly: device
# enumeration quietly comes up empty, `search` finds no root, and GRUB drops to
# a rescue prompt with the config never loaded. That cost an afternoon.
MODULES="memdisk tar hashsum gcry_sha256 \
         normal echo test configfile minicmd sleep halt reboot ls cat \
         iso9660 fat biosdisk ata \
         part_msdos part_gpt part_acorn part_amiga part_apple part_bsd \
         part_dfly part_dvh part_plan part_sun part_sunpc \
         multiboot2 all_video video video_fb vbe vga gfxterm \
         search search_fs_file search_fs_uuid search_label \
         serial terminal"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

mkdir -p "$WORK/md/boot/grub"

# The pin. `sha256sum`'s own output format, because that is what GRUB's
# `hashsum --check` reads -- one line, `<hex>  <name>`, resolved against the
# --prefix the config passes. The NAME is the bare basename: --prefix supplies
# the directory, and a path here would be resolved twice.
KHASH=$(sha256sum "$KERNEL" | awk '{print $1}')
printf '%s  kernel.elf\n' "$KHASH" > "$WORK/md/boot/grub/kernel.sha256"

cp "$CFG" "$WORK/md/boot/grub/grub.cfg"

# A tar, because that is the format `memdisk` reads. Built with a fixed order
# and no timestamps varying between builds of identical input, so the boot image
# -- and therefore PCR[4] -- is reproducible: a measurement that changed on
# every rebuild would make every sealed volume unopenable after a no-op build.
( cd "$WORK/md" && tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
      -cf "$WORK/memdisk.tar" boot )

# -m implies `-p (memdisk)/boot/grub`, which is what puts the config inside the
# measurement rather than beside it on the ISO.
grub-mkimage -O i386-pc-eltorito -d "$GRUB_DIR" -m "$WORK/memdisk.tar" \
             -o "$OUT" $MODULES

# ---------------------------------------------------------------------------
# THE UEFI PATH GETS THE SAME PIN, AND LEAVING IT OUT WAS A REGRESSION.
#
# The first version of this script built the BIOS image only, and the ISO rule
# dropped grub-mkrescue's EFI half with a comment claiming nothing in this tree
# had ever booted it. That was FALSE, and a gate one directory over said so:
# tools/boot_media_test.sh boots `uefi-cd` and `uefi-disk` on every CI run, and
# exists because those exact modes were measured BROKEN on 2026-09-06 and fixed.
# CI caught it on the first push. The claim was the kind this repository keeps
# paying for -- a confident sentence in a comment, contradicted by a test
# nobody re-read.
#
# So the EFI image is built here too, from the SAME memdisk. That is the point
# of building both in one place: two firmware paths that pinned different
# kernels, or one that pinned none, would be a hole shaped exactly like the one
# S92 closes -- an attacker picks the weaker door.
#
# What does NOT carry across is the measurement. PCR[4] is extended by the
# firmware, and OVMF and SeaBIOS do not measure the same bytes, so a volume
# sealed under one firmware does not unseal under the other. That is correct
# rather than unfortunate: a different boot chain IS a different boot chain.
# docs/LIMITATIONS.md 2.9a records it.
# ---------------------------------------------------------------------------
if [ -n "${EFI_OUT:-}" ]; then
    EFI_GRUB_DIR=${EFI_GRUB_DIR:-/usr/lib/grub/x86_64-efi}
    if [ ! -d "$EFI_GRUB_DIR" ]; then
        echo "mkbootimg: no x86_64-efi GRUB modules at '$EFI_GRUB_DIR' (install grub-efi-amd64-bin)" >&2
        exit 1
    fi
    # biosdisk and vga are i386-pc only; efi_gop/efi_uga are the EFI video path.
    EFI_MODULES=$(printf '%s\n' $MODULES | grep -vxE 'biosdisk|vga|vbe' | tr '\n' ' ')
    grub-mkimage -O x86_64-efi -d "$EFI_GRUB_DIR" -m "$WORK/memdisk.tar" \
                 -o "$WORK/BOOTX64.EFI" $EFI_MODULES efi_gop efi_uga

    # A FAT image sized from the payload rather than a constant: a fixed 1440K
    # floppy fits today's image and would fail the day a module is added, and
    # the failure would be an ISO that boots on BIOS and not on UEFI -- which
    # is the asymmetry this whole block exists to prevent.
    esz=$(( ( $(wc -c < "$WORK/BOOTX64.EFI") / 1024 ) + 512 ))
    rm -f "$EFI_OUT"
    mformat -i "$EFI_OUT" -C -f "$(( esz > 2880 ? esz : 2880 ))" -v HORUSEFI :: 2>/dev/null || {
        # mformat's -f takes a known geometry for small sizes; fall back to a
        # plain sized image with -T (sectors) for anything larger.
        dd if=/dev/zero of="$EFI_OUT" bs=1024 count="$esz" status=none
        mformat -i "$EFI_OUT" -v HORUSEFI ::
    }
    mmd -i "$EFI_OUT" ::/EFI ::/EFI/BOOT
    mcopy -i "$EFI_OUT" "$WORK/BOOTX64.EFI" ::/EFI/BOOT/BOOTX64.EFI
fi

echo "mkbootimg: boot image $OUT pins kernel sha256 $KHASH"
