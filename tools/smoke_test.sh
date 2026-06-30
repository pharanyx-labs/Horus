#!/usr/bin/env bash
#
# Headless QEMU smoke-boot test.
#
# Boots the kernel under QEMU with no display and captures COM1 to a log.
# Success is observing the ring-3 shell's startup banner on the serial line,
# which proves the whole boot path works end to end: kernel init (paging,
# SMEP/SMAP, scheduler), the ELF/flat loader, per-task paging incl. the W^X
# stack, dropping to ring 3 and *executing* there, the syscall dispatch table
# servicing SYS_WRITE, and console output. Any page fault / CPU exception /
# panic on the serial line, or failing to reach the banner before the timeout,
# is a failure.
#
# Usage: tools/smoke_test.sh [boot.iso]
# Env:   SMOKE_TIMEOUT (seconds, default 40)
#
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-40}"

PASS_MARKER="Horus Secure Microkernel"   # printed by userspace/shell.c _start()
LOGIN_MARKER="horus login"               # reached the login prompt (do_login)
FAULT_RE='PAGE FAULT|Exception! Vector|PANIC|Rejected by validator'

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "SMOKE SKIP: qemu-system-x86_64 not found" >&2
    exit 2
fi
if [ ! -f "$ISO" ]; then
    echo "SMOKE FAIL: ISO '$ISO' not found (run 'make boot.iso' first)" >&2
    exit 1
fi

LOG="$(mktemp)"
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$LOG"
}
trap cleanup EXIT

# -accel tcg: GitHub runners have no /dev/kvm; force software emulation so the
#   run is deterministic instead of depending on host virtualization.
# -no-reboot: a triple fault halts QEMU instead of looping, so we detect it.
# isa-debug-exit: present for parity with `make run`; not relied on here.
qemu-system-x86_64 \
    -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap -accel tcg \
    -display none -no-reboot -no-shutdown \
    -device isa-debug-exit,iobase=0x604,iosize=0x04 \
    -serial file:"$LOG" -net none \
    -cdrom "$ISO" &
QEMU_PID=$!

status="timeout"
deadline=$(( SECONDS + TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -qE "$FAULT_RE" "$LOG" 2>/dev/null; then status="fault"; break; fi
    if grep -q "$PASS_MARKER" "$LOG" 2>/dev/null; then status="ok"; break; fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then status="exited"; break; fi
    sleep 0.5
done

echo "------------------- serial log -------------------"
cat "$LOG" 2>/dev/null || true
echo ""
echo "--------------------------------------------------"

case "$status" in
    ok)
        # A fault printed in the same instant as the banner still fails.
        if grep -qE "$FAULT_RE" "$LOG"; then
            echo "SMOKE FAIL: kernel fault/panic on serial"
            exit 1
        fi
        if grep -q "$LOGIN_MARKER" "$LOG"; then
            echo "SMOKE PASS: reached ring-3 shell banner and login prompt"
        else
            echo "SMOKE PASS: reached ring-3 shell banner"
        fi
        exit 0
        ;;
    fault)   echo "SMOKE FAIL: kernel fault/panic on serial"; exit 1 ;;
    exited)  echo "SMOKE FAIL: QEMU exited before the banner (triple fault?)"; exit 1 ;;
    timeout) echo "SMOKE FAIL: timed out after ${TIMEOUT}s before the shell banner"; exit 1 ;;
esac
