#!/usr/bin/env bash
#
# "Is COM4 the kernel's console, whole, and nobody else's?"  (ROADMAP 5.3,
# docs/LIMITATIONS.md 2.6c)
#
# After the console handover a kernel print() reaches COM1 only through
# console_server, from ring 3, among everything else it writes, so a gate that
# reads a kernel line off COM1 is reading something a ring-3 task re-emitted. The
# kernel keeps its own copy on COM4 (terminal.c, g_kcon_present). This harness
# boots once with all four channels captured and asserts what that copy is:
#
#   MODE=channel (base)   the kernel's probe line, printed by print() on a timer
#                         tick after the handover while init writes forever
#                         (KDIAG_NOISE), reaches COM4 at least MIN times and every
#                         occurrence is whole; and nothing ring 3 writes is there:
#                         not console_server's own ready line, not init's noise.
#                         The handover is proved from COM1, where the ready line
#                         is console_server's own write.
#   MODE=ioport  (base)   console_server's write to 0x2E8 is REFUSED: it takes a
#                         #GP and its sentinel never reaches COM4.
#   MODE=grant   (arm)    with KCON_PORTS_GRANTABLE=1 the same write succeeds and
#                         the sentinel is on COM4: the port's absence from the
#                         platform device is the whole of the property.
#
# The channel arm (KCON_MIRROR_OFF=1) runs MODE=channel and must fail with the
# named reason that COM4 carried nothing; `make smoke-kcon-control` inverts it.
#
# The two lessons smoke-kdiag paid for are kept: the guest is stopped BEFORE it
# is measured, and every count for a capture comes from one read of it, so a
# line completing between two reads cannot manufacture a split.
set -u

ISO="${1:-horus.iso}"
TIMEOUT="${KCON_TIMEOUT:-90}"
MIN="${KCON_MIN:-6}"
MODE="${MODE:-channel}"

LINE="KCONPROBE: a kernel line printed after the console handover"
PREFIX="KCONPROBE"
RING3="KCONRING3"
NOISE="init: kdiag noise"
READY="[console_server] ready"
GPFAULT="'console_server' killed: ring-3 trap vector 13"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "KCON SKIP: qemu-system-x86_64 not found" >&2; exit 2
fi
[ -f "$ISO" ] || { echo "KCON FAIL: ISO '$ISO' not found" >&2; exit 1; }

LOG=$(mktemp); DIAG=$(mktemp); KCON=$(mktemp)
QEMU_PID=""
keep=0
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    # Evidence is kept when the verdict is a failure: that is the only time
    # anyone needs it.
    if [ "$keep" = 1 ] || [ -n "${KCON_KEEP:-}" ]; then
        echo "  captures kept: console=$LOG diag=$DIAG kcon=$KCON"
    else
        rm -f "$LOG" "$DIAG" "$KCON"
    fi
    return 0
}
trap cleanup EXIT

qemu-system-x86_64 \
    -m 512M -cpu "${QEMU_CPU:-qemu64,+aes,+rdrand,+smep,+smap,+umip}" -accel tcg \
    -display none -no-reboot -no-shutdown \
    -serial file:"$LOG" -serial none -serial file:"$DIAG" -serial file:"$KCON" -net none \
    -smp "${QEMU_SMP:-4}" \
    -cdrom "$ISO" &
QEMU_PID=$!

# Counts from ONE read of a capture, ignoring a trailing partial line.
counts() {   # counts <file> <needle>...
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
    case "$MODE" in
        channel) [ "$(counts "$KCON" "$PREFIX")" -ge "$MIN" ] && break ;;
        ioport)  [ "$(counts "$DIAG" "$GPFAULT")" -ge 1 ] && break ;;
        grant)   [ "$(counts "$KCON" "$RING3")" -ge 1 ] && break ;;
        *) echo "KCON FAIL: unknown MODE=$MODE"; exit 1 ;;
    esac
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 0.5
done
kill "$QEMU_PID" 2>/dev/null; wait "$QEMU_PID" 2>/dev/null; QEMU_PID=

read -r whole prefix ready_k noise_k ring3_k <<<"$(counts "$KCON" "$LINE" "$PREFIX" "$READY" "$NOISE" "$RING3")"
read -r ready_c <<<"$(counts "$LOG" "$READY")"
read -r gp <<<"$(counts "$DIAG" "$GPFAULT")"
kbytes=$(wc -c < "$KCON")
echo "[kcon] COM4: $kbytes bytes, probe lines whole=$whole prefix=$prefix;" \
     "ring-3 text on COM4: ready=$ready_k noise=$noise_k sentinel=$ring3_k;" \
     "handover on COM1: $ready_c; #GP: $gp"

fail() { keep=1; echo "KCON FAIL: $*"; exit 1; }

case "$MODE" in
channel)
    [ "$ready_c" -ge 1 ] || fail "the console was never handed over; nothing here says anything about it"
    [ "$kbytes" -gt 0 ] || fail "nothing reached the kernel console copy (COM4)"
    [ "$ready_k" -eq 0 ] && [ "$noise_k" -eq 0 ] && [ "$ring3_k" -eq 0 ] \
        || fail "ring-3 output reached COM4, which only the kernel may write"
    [ "$prefix" -ge "$MIN" ] || fail "only $prefix probe line(s) reached COM4 after the handover (want $MIN)"
    [ "$whole" -eq "$prefix" ] || fail "$prefix probe line(s) reached COM4 and only $whole arrived whole"
    echo "KCON PASS: $whole kernel lines from after the handover, all whole on COM4, and no ring-3 byte there"
    ;;
ioport)
    [ "$gp" -ge 1 ] || fail "console_server was not refused the write to 0x2E8"
    [ "$ring3_k" -eq 0 ] || fail "ring 3's sentinel reached COM4"
    echo "KCON PASS: ring 3's write to COM4 was refused with a #GP, and nothing of it reached the port"
    ;;
grant)
    [ "$ring3_k" -ge 1 ] || fail "the granted build's sentinel never reached COM4"
    echo "KCON GRANT: with 0x2E8 declared, ring 3 wrote $ring3_k sentinel(s) into the kernel's copy"
    ;;
esac
