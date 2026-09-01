#!/bin/bash
#
# Full rebuild, then boot Horus interactively against a PERSISTENT disk.
#
# THE DISK IS THE POINT OF THIS SCRIPT. `make run` boots the in-RAM vdisk, which
# formats itself on the way up under a per-boot throwaway key: nothing typed at
# that shell -- no file, no user account, no password -- exists after Ctrl-A X.
# This script boots `make run-ata` instead, which attaches $HORUS_DISK as a real
# IDE drive and builds the kernel with STORAGE_ATA=1 so it uses it.
#
# WHAT HAPPENS THE FIRST TIME. The image does not exist, so run-ata creates it
# blank. storage_init probes the drive, finds no volume and reports needs_format;
# ring-3 init sees that and runs the installer BEFORE any login prompt. The
# installer asks you to confirm by typing FORMAT, then asks for a root password
# twice -- and that one password does two things, because it has to: it seals the
# volume's encryption key AND becomes the password on the root account. They are
# different mechanisms with different salts, and a login needs the same typed
# string to satisfy both, so an installer that set only one produces a disk
# nobody can log into. Then it hands over to the login prompt.
#
# WHAT HAPPENS EVERY TIME AFTER. The image is there and holds a recognised
# volume, so init does not run the installer -- it goes straight to login, and
# the credentials are the ones you chose during the install. Not the compiled-in
# defaults: the account table lives on the volume you sealed. The script does not
# touch an existing image, because a truncate over it would destroy the volume
# and the password with it and look like an installer bug on the next boot.
#
# To start over: `make run-ata-wipe`, or delete the image by hand.
#
# NO TPM ON THIS PATH, and that is deliberate rather than an omission -- see the
# run-ata comment in the Makefile. A persistent volume seals its KEK under
# PolicyPCR(PCR8, PCR9) when a TPM is present, and PCR8 is the kernel's identity.
# This script rebuilds the kernel every run, so a TPM-sealed volume installed by
# one build could not be unsealed by the next: right password, intact disk, and
# the machine will not open it. `make run-tpm` is where measured boot is
# exercised, against a kernel that is not moving.

set -e

echo "=== Horus Full Rebuild & Run (persistent disk) ==="

if [ ! -f Makefile ]; then
  echo "Error: Makefile not found. Run from Horus root."
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Please install Rust toolchain."
  exit 1
fi

DISK=${HORUS_DISK:-horus.img}

if [ -f "$DISK" ]; then
  echo "[0/5] $DISK exists -- booting the volume already on it (log in with the password you installed)."
else
  echo "[0/5] $DISK does not exist -- it will be created blank, and this boot runs the installer."
fi

echo "[1/5] Cleaning Rust cache..."
make clean-rust

echo "[2/5] Full clean..."
make clean

echo "[3/5] Building userspace (shell.bin + others)..."
make BITS=64 STORAGE_ATA=1 userspace

echo "[4/5] Building kernel (Rust enabled, 64-bit, ATA storage)..."
SOURCE_DATE_EPOCH=1609459200 make BITS=64 STORAGE_ATA=1 \
  MINIMAL_SECURE=${MINIMAL_SECURE:-0} -j"$(nproc 2>/dev/null || echo 4)"

echo "[5/5] Launching QEMU (console on this terminal; Ctrl-A X to quit)..."

DEBUG=${DEBUG:-0} HORUS_DISK="$DISK" make BITS=64 run-ata || true
