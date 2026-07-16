#!/bin/bash

set -e

echo "=== Horus Full Rebuild & Run ==="

if [ ! -f Makefile ]; then
  echo "Error: Makefile not found. Run from Horus root."
  exit 1
fi


if ! command -v cargo >/dev/null 2>&1; then
  echo "Error: cargo not found. Please install Rust toolchain."
  exit 1
fi


echo "[1/5] Cleaning Rust cache..."
make clean-rust


echo "[2/5] Full clean..."
make clean


echo "[3/5] Building userspace (shell.bin + others)..."
make BITS=64 userspace


echo "[4/5] Building kernel (Rust enabled, 64-bit)..."
SOURCE_DATE_EPOCH=1609459200 make BITS=64 MINIMAL_SECURE=${MINIMAL_SECURE:-0} -j"$(nproc 2>/dev/null || echo 4)"


echo "[5/5] Launching QEMU (console on this terminal; Ctrl-A X to quit)..."

DEBUG=${DEBUG:-0} make BITS=64 run || true
