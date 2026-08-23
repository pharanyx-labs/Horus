#!/bin/sh
# Boot a Horus ISO under QEMU with an emulated TPM 2.0 (swtpm), headless, and
# capture COM1 to a log — the shared harness for the measured-boot smoke gates and
# for `RUN_TPM=1 make run`.
#
# Usage: run_with_swtpm.sh <iso> [extra qemu args...]
#
# Env:
#   SWTPM_TIMEOUT   seconds to wait for a marker (default 60)
#   REQUIRE_MARKER  string that must appear on serial for success
#   EXPECT_FAULT    string that inverts the fault verdict — the named fault is
#                   the success condition, and any OTHER fault still fails. Same
#                   contract as tools/smoke_test.sh, added 2026-08-23 for the
#                   fail-closed measured-boot arms, whose success condition IS a
#                   halt: their refusal says PANIC (deliberately, so a refusal
#                   reddens CI rather than scrolling past), and this script tests
#                   FAULT_RE before REQUIRE_MARKER, so the fault verdict always
#                   won first and no marker could ever be asserted on a halt.
#   FAIL_MARKER     string whose appearance is an immediate failure
#   PRINT_PCR       if "1", echo the guest's `tpm: PCR8=.. PCR9=..` line
#   KEEP_TPMSTATE   if set to a dir, reuse/persist swtpm state there instead of a
#                   throwaway one (for two-boot sealing tests that need the same
#                   TPM across reboots)
#
# The canonical wiring: QEMU's emulator tpmdev connects to swtpm's --ctrl unixio
# socket (NOT a --server socket). swtpm handles TPM2_Startup for the guest firmware
# (SeaBIOS), which measures into PCR 0..7; the Horus kernel owns PCR 8/9.
set -eu

ISO=${1:?usage: run_with_swtpm.sh <iso> [qemu args...]}
shift || true

TIMEOUT="${SWTPM_TIMEOUT:-60}"
REQUIRE_MARKER="${REQUIRE_MARKER:-}"
EXPECT_FAULT="${EXPECT_FAULT:-}"
FAIL_MARKER="${FAIL_MARKER:-}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "SWTPM SKIP: qemu-system-x86_64 not found" >&2; exit 0
fi
. "$(dirname "$0")/swtpm_lib.sh"
if ! swtpm_available; then
    echo "SWTPM SKIP: swtpm/swtpm_setup not found" >&2; exit 0
fi
if [ ! -f "$ISO" ]; then
    echo "SWTPM FAIL: ISO '$ISO' not found" >&2; exit 1
fi

# The lifecycle lives in swtpm_lib.sh -- one copy, shared with smoke_test.sh's
# TPM=1 mode. KEEP_TPMSTATE passes through unchanged.
swtpm_start "${KEEP_TPMSTATE:-}" || exit 1

LOG="$(mktemp)"
QEMU_PID=""

cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null || true
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null || true
    swtpm_stop
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

qemu-system-x86_64 \
    -m 512M -cpu qemu64,+aes,+rdrand,+smep,+smap,+umip -accel tcg \
    -display none -no-reboot -no-shutdown \
    -chardev socket,id=chrtpm,path="$SWTPM_SOCK" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -device isa-debug-exit,iobase=0x604,iosize=0x04 \
    -serial file:"$LOG" -net none \
    "$@" \
    -cdrom "$ISO" &
QEMU_PID=$!

status="timeout"
deadline=$(( $(date +%s) + TIMEOUT ))
FAULT_RE='PANIC|panic|Kernel panic|#PF|#GP|triple fault|CPU exception'
while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -qE "$FAULT_RE" "$LOG" 2>/dev/null; then
        # Under EXPECT_FAULT only the fault we NAMED ends the run; any other one
        # keeps going so it is reported as the wrong fault at the end rather than
        # being accepted as the expected refusal.
        if [ -n "$EXPECT_FAULT" ] && grep -qF "$EXPECT_FAULT" "$LOG" 2>/dev/null; then
            status="expected_fault"; break
        fi
        if [ -z "$EXPECT_FAULT" ]; then status="fault"; break; fi
    fi
    if [ -n "$FAIL_MARKER" ] && grep -qF "$FAIL_MARKER" "$LOG" 2>/dev/null; then status="marker_fail"; break; fi
    if [ -n "$REQUIRE_MARKER" ] && grep -qF "$REQUIRE_MARKER" "$LOG" 2>/dev/null; then status="ok"; break; fi
    sleep 1
done

echo "------------------- serial (tpm lines) -------------------"
grep -iE 'tpm|PCR|refused' "$LOG" 2>/dev/null || true
echo "----------------------------------------------------------"
[ "${PRINT_PCR:-}" = 1 ] && grep -F 'tpm: PCR8=' "$LOG" 2>/dev/null || true
# Hand the full captured serial to the caller (e.g. the PCR-comparison gate)
# before the throwaway log is removed on cleanup.
[ -n "${SERIAL_OUT:-}" ] && cp "$LOG" "$SERIAL_OUT" 2>/dev/null || true

case "$status" in
    ok)          echo "SWTPM PASS: marker '$REQUIRE_MARKER' observed"; exit 0 ;;
    expected_fault)
                 echo "SWTPM PASS: expected fault '$EXPECT_FAULT' observed"; exit 0 ;;
    marker_fail) echo "SWTPM FAIL: saw fail marker '$FAIL_MARKER'"; exit 1 ;;
    fault)       echo "SWTPM FAIL: kernel fault/panic on serial"; exit 1 ;;
    *)           if [ -n "$EXPECT_FAULT" ]; then
                     echo "SWTPM FAIL: timed out after ${TIMEOUT}s without the expected fault '$EXPECT_FAULT'"
                 else
                     echo "SWTPM FAIL: timed out after ${TIMEOUT}s without '$REQUIRE_MARKER'"
                 fi
                 exit 1 ;;
esac
