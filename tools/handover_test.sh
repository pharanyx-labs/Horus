#!/usr/bin/env bash
#
# "Does the console change hands only between lines?"  (docs/LIMITATIONS.md 2.30)
#
# The kernel hands COM1 to console_server when the server maps the display. A
# kernel line that began before that must finish before the new owner writes,
# or the two interleave. The HANDOVER_PROBE build makes the question
# deterministic: an AP prints a long, slowed line that the display-map syscall
# waits to see in flight before it changes the owner, and the AP then says so
# on COM4 (the precondition: a boot where the line was never in flight at the
# handover tests nothing, and is reported as inconclusive rather than scored).
#
#   MODE=whole  (base)  the probe line arrives whole on COM1, and so does
#                       console_server's first line after the handover.
#   MODE=split  (arm)   with CONSOLE_HANDOVER_UNLOCKED=1 the probe line does
#                       NOT arrive whole on COM1: console_server's output landed
#                       inside it. Ground-truthed against COM4, where the same
#                       line is whole in the same boot.
#
# One read per capture, after the guest is stopped, as smoke-kdiag learned.
set -u

ISO="${1:-horus.iso}"
TIMEOUT="${HANDOVER_TIMEOUT:-90}"
MODE="${MODE:-whole}"

PROBE="HANDOVERPROBE: a kernel line still being written when the console changes hands"
PREFIX="HANDOVERPROBE"
TAIL="when the console changes hands"      # the line's end, which survives a split
MET="HANDOVER: the probe line was in flight when the console changed hands"
FIRST="[console_server] input: "
READY="[console_server] ready"

LOG=$(mktemp); DIAG=$(mktemp); KCON=$(mktemp)
QEMU_PID=""; keep=0
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    if [ "$keep" = 1 ] || [ -n "${HANDOVER_KEEP:-}" ]; then echo "  captures kept: console=$LOG kcon=$KCON"; else rm -f "$LOG" "$DIAG" "$KCON"; fi
    return 0
}
trap cleanup EXIT

qemu-system-x86_64 \
    -m 512M -cpu "${QEMU_CPU:-qemu64,+aes,+rdrand,+smep,+smap,+umip}" -accel tcg \
    -display none -no-reboot -no-shutdown \
    -serial file:"$LOG" -serial none -serial file:"$DIAG" -serial file:"$KCON" -net none \
    -smp "${QEMU_SMP:-4}" -cdrom "$ISO" &
QEMU_PID=$!

counts() {
    python3 -I - "$@" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
cut = data.rfind(b'\n')
body = data[:cut + 1] if cut >= 0 else b''
print(' '.join(str(body.count(n.encode())) for n in sys.argv[2:]))
PY
}

deadline=$(( SECONDS + TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
    read -r met <<<"$(counts "$KCON" "$MET")"
    read -r ready <<<"$(counts "$LOG" "$READY")"
    [ "$met" -ge 1 ] && [ "$ready" -ge 1 ] && break
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 0.5
done
sleep 1
kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; QEMU_PID=

read -r whole prefix tail first ready <<<"$(counts "$LOG" "$PROBE" "$PREFIX" "$TAIL" "$FIRST" "$READY")"
read -r kwhole met <<<"$(counts "$KCON" "$PROBE" "$MET")"
echo "[handover] COM1: probe whole=$whole prefix=$prefix, console_server first line=$first ready=$ready;" \
     "COM4: probe whole=$kwhole, in flight at the handover=$met"

if [ "$met" -lt 1 ] || [ "$kwhole" -lt 1 ]; then
    keep=1
    echo "HANDOVER: Inconclusive - the probe line was never in flight at the handover; this boot tested nothing"
    exit 3
fi
case "$MODE" in
whole)
    if [ "$whole" -eq 1 ] && [ "$first" -ge 1 ] && [ "$ready" -ge 1 ]; then
        echo "HANDOVER PASS: the kernel line in flight at the handover arrived whole, and so did console_server's first lines"
        exit 0
    fi
    keep=1; echo "HANDOVER FAIL: a line was split at the handover (probe whole=$whole, first=$first, ready=$ready)"; exit 1 ;;
split)
    # POSITIVE: the line's end reached COM1 and the line did not arrive whole,
    # so it was written there and cut, not merely missing.
    if [ "$whole" -eq 0 ] && [ "$tail" -ge 1 ]; then
        echo "HANDOVER SPLIT: console_server wrote into the middle of the kernel's line (its end is on COM1, the whole line only on COM4)"
        exit 0
    fi
    keep=1; echo "HANDOVER: the probe line arrived whole; the split did not happen in this boot"; exit 1 ;;
*) echo "HANDOVER FAIL: unknown MODE=$MODE"; exit 1 ;;
esac
