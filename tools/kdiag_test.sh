#!/usr/bin/env bash
#
# "Can a kernel marker be split in half by a ring-3 task's output?"
#
# The kernel reports through a UART that a ring-3 console_server also owns
# (finding #126): the kernel writes it anyway, because a report that loses a
# race with a shell prompt is not a report. panic_str is a character loop, so
# another task's write can land BETWEEN TWO CHARACTERS of a single call. On
# 2026-09-02 that shredded smoke-kstack-park-control's panic into a miss and the
# gate reported "the defect did NOT reproduce" with the panic in its own
# evidence dump (docs/LIMITATIONS.md 2.6c). A gate whose marker can be destroyed
# by an unrelated task's output fails OPEN.
#
# COM3 is the repair: no capability names 0x3E8 (src/kernel/pci.c declares the
# platform device's ports and that is not among them), so the kernel is the only
# writer and contiguity stops being a race. This harness captures BOTH channels
# from ONE boot and compares them, which is what makes each arm's claim
# independent of whether the marker was emitted at all:
#
#   whole(f)  occurrences of the marker's full text in f
#   prefix(f) occurrences of "KDIAGPROBE" in f -- an emission that reached the
#             wire at all, whole or shredded
#
#   MODE=channel  (base)     prefix(diag) >= MIN and whole(diag) == prefix(diag)
#                            -- every marker the kernel emitted is contiguous
#                            on its own channel.
#   MODE=split    (control)  whole(console) < prefix(diag)
#                            -- the kernel provably emitted prefix(diag) markers
#                            (whole, on its own channel, same boot) and fewer
#                            than that arrived intact on the shared console.
#                            Ground-truthed against the diag channel rather than
#                            against the console's own prefix count, because the
#                            console count MISSES THE HARDEST REPRODUCTIONS: a
#                            write landing inside the word "KDIAGPROBE" leaves no
#                            prefix to count, so a boot that shredded 7 markers
#                            of 8 scored prefix=1 whole=1 and read as clean.
#                            That is CLAUDE.md's park worked-example -- a
#                            detector that counts occurrences is blind exactly
#                            where the defect fired hardest -- met again here.
#                            Without this arm, MODE=channel would pass on a
#                            system where splitting never happens and the channel
#                            would be protecting against nothing.
#   MODE=ioport   (base)     the ring-3 write is REFUSED: console_server takes a
#                            #GP (ring-3 trap vector 13) and no sentinel reaches
#                            the diagnostic channel. A positive marker for a
#                            refusal, not an absence test -- and its pair below
#                            shows the same instruction succeeding, so what is
#                            being measured is the port declaration and nothing
#                            else. Note this build emits no probe markers at all:
#                            the fault kills console_server, console ownership is
#                            released, and kdiag_probe_tick() stops firing. That
#                            is the refusal working, so this mode does not
#                            require them.
#   MODE=grant    (control)  the ring-3 sentinel appears in the diag capture
#                            -- with KDIAG_PORTS_GRANTABLE=1 the diagnostic port
#                            is declared among the platform device's, so
#                            console_server is granted it and writes a sentinel
#                            straight into the kernel's channel. The arm for the
#                            AUTHORITY half, and it asserts the sentinel rather
#                            than a count for the reason above: what is being
#                            witnessed is that ring 3 REACHED the channel, and a
#                            string it wrote says that with no arithmetic.
#
# Usage: tools/kdiag_test.sh [boot.iso]
# Env:   KDIAG_TIMEOUT   seconds to wait (default 90)
#        KDIAG_MIN       markers required before asserting (default 3)
#        MODE            channel | split | grant  (default channel)
#        KDIAG_LOG       keep the console capture here
#        KDIAG_DIAG_LOG  keep the COM3 capture here
#        QEMU_SMP        passed to -smp (default 4 -- the shape the 2026-09-02
#                        incident had; with one CPU the ring-3 writer and the
#                        kernel reporter cannot overlap at all)
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${KDIAG_TIMEOUT:-90}"
MIN="${KDIAG_MIN:-3}"
MODE="${MODE:-channel}"

MARKER="KDIAGPROBE: a kernel marker that must not be split"
PREFIX="KDIAGPROBE"
RING3="KDIAGRING3"      # the sentinel console_server writes under the ioport arms
GPFAULT="'console_server' killed: ring-3 trap vector 13"
# Informative only. It was the precondition until 2026-09-03, and the hazard
# under test ate it: on 1 boot in 5 a kernel marker landed inside
# "[console_server] ready" on the shared console, and a run whose markers prove
# the handover happened was reported as "console_server never took the console".
# A harness that reads its own precondition off the channel it is measuring
# inherits exactly the failure it exists to detect. The precondition is now the
# diagnostic channel itself: kdiag_probe_tick() emits only when
# console_hw_owned(), so ONE marker there is proof of the handover, and it is
# proof that cannot be shredded.
READY_LINE="[console_server] ready"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "KDIAG SKIP: qemu-system-x86_64 not found" >&2
    exit 2
fi
if [ ! -f "$ISO" ]; then
    echo "KDIAG FAIL: ISO '$ISO' not found (run 'make boot.iso' first)" >&2
    exit 1
fi

LOG="${KDIAG_LOG:-$(mktemp)}"
DIAG="${KDIAG_DIAG_LOG:-$(mktemp)}"
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    [ -z "${KDIAG_LOG:-}" ] && rm -f "$LOG"
    [ -z "${KDIAG_DIAG_LOG:-}" ] && rm -f "$DIAG"
    return 0
}
trap cleanup EXIT

# -serial none for COM2: leave it unassigned. An unassigned port floats and
# reads 0xFF, which is what smoke-passwd-probe-recv27-control depends on -- a
# backend there would turn that arm's refusal into a hang. COM3 is the third.
qemu-system-x86_64 \
    -m 512M -cpu "${QEMU_CPU:-qemu64,+aes,+rdrand,+smep,+smap,+umip}" -accel tcg \
    -display none -no-reboot -no-shutdown \
    -serial file:"$LOG" -serial none -serial file:"$DIAG" -net none \
    -smp "${QEMU_SMP:-4}" \
    -cdrom "$ISO" &
QEMU_PID=$!

# Count occurrences of a string in a capture, considering only COMPLETE lines.
#
# The trailing partial line is not evidence of anything. QEMU is killed when the
# assertion is ready, which lands mid-marker often enough that the first version
# of this harness scored its own truncation as a split -- whole=2 prefix=3 on
# the KERNEL-ONLY channel, where a split is impossible by construction. A
# detector that cannot tell "cut by another writer" from "the capture ended"
# reports the defect it exists to find on a boot that did not have it.
count() {
    python3 - "$1" "$2" <<'PYCOUNT'
import sys
data = open(sys.argv[1], 'rb').read()
cut = data.rfind(b'\n')
body = data[:cut + 1] if cut >= 0 else b''
print(body.count(sys.argv[2].encode()))
PYCOUNT
}

# Let the probes accumulate. Waiting for the count rather than a fixed sleep so
# a slow host lengthens the run instead of failing it. The console handover is a
# precondition, not the assertion -- before it the kernel's print() drives the
# hardware alone and there is no second writer, so a marker emitted then says
# nothing about the hazard -- and kdiag_probe_tick() gates itself on exactly
# that condition, which is why a marker on the diagnostic channel IS the proof.
deadline=$(( SECONDS + TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$MODE" = ioport ] || [ "$MODE" = grant ]; then
        # These two do not wait on markers: the refused build emits none by
        # design (see MODE=ioport above), and the granted build's evidence is
        # the sentinel, written once at startup.
        [ "$(count "$LOG" "$GPFAULT")" -ge 1 ] && break
        [ "$(count "$DIAG" "$RING3")" -ge 1 ] && break
    else
        dia_p=$(count "$DIAG" "$PREFIX")
        [ "$dia_p" -ge "$MIN" ] && break
    fi
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 0.5
done

con_whole=$(count "$LOG" "$MARKER");  con_prefix=$(count "$LOG" "$PREFIX")
dia_whole=$(count "$DIAG" "$MARKER"); dia_prefix=$(count "$DIAG" "$PREFIX")
dia_ring3=$(count "$DIAG" "$RING3");  con_ring3=$(count "$LOG" "$RING3")
gp=$(count "$LOG" "$GPFAULT")

# Evidence FIRST, and unconditionally. A gate that destroys its own capture on
# the failure path is one nobody can debug on the run that mattered -- the
# 2026-08-30 lesson from smoke-exec-reenter-control, which ran `rm -f` over the
# serial log exactly when it went red.
echo "---------------- console (COM1, shared) ----------------"
tail -c 4000 "$LOG" 2>/dev/null || true
echo ""
echo "---------------- diagnostic (COM3, kernel-only) --------"
tail -c 4000 "$DIAG" 2>/dev/null || true
echo ""
echo "--------------------------------------------------------"
ready_seen=$(count "$LOG" "$READY_LINE")
echo "mode: $MODE   console ready line intact on the shared console: $ready_seen"
echo "  (informative -- the handover is proven by any marker on the diag channel)"
echo "console : whole=$con_whole prefix=$con_prefix ring3=$con_ring3"
echo "diag    : whole=$dia_whole prefix=$dia_prefix ring3=$dia_ring3"
echo "ring-3 #GP on the diagnostic port: $gp"

if [ "$MODE" != ioport ] && [ "$MODE" != grant ] && [ "$dia_prefix" -lt 1 ]; then
    if [ "$con_prefix" -ge 1 ]; then
        # Nameable, not ambiguous: the kernel is reporting -- the markers are on
        # the console -- and the channel that cannot be shredded is silent. That
        # is exactly what KDIAG_LEGACY_COM1=1 builds, so say so rather than
        # reporting the generic "not a result" a broken boot gets. A control arm
        # whose verdict does not distinguish the defect from a broken runner is
        # how a reproduction gets filed as an infrastructure failure.
        echo "KDIAG FAIL: $con_prefix marker(s) on the shared console and NOTHING on the"
        echo "            diagnostic channel. The kernel is reporting only where ring 3"
        echo "            can cut it -- the pre-2026-09-03 reporter (KDIAG_LEGACY_COM1)."
        exit 1
    fi
    echo "KDIAG FAIL: not one marker reached either channel, so console_server never"
    echo "            took the console (the probe emits only after it does) or nothing"
    echo "            ran. Not a result either way."
    exit 1
fi

case "$MODE" in
channel)
    if [ "$dia_prefix" -lt "$MIN" ]; then
        echo "KDIAG FAIL: only $dia_prefix marker(s) on the diagnostic channel, wanted $MIN."
        echo "            Either the probe did not run or the channel carried nothing --"
        echo "            in both cases there is nothing to conclude about contiguity."
        exit 1
    fi
    if [ "$dia_whole" -ne "$dia_prefix" ]; then
        echo "KDIAG FAIL: $dia_prefix marker(s) reached the diagnostic channel and only"
        echo "            $dia_whole arrived whole. Something other than the kernel is"
        echo "            writing COM3, which is the one thing that channel is for."
        exit 1
    fi
    echo "KDIAG PASS: $dia_whole/$dia_prefix kernel markers contiguous on a channel"
    echo "            ring 3 cannot write"
    exit 0
    ;;
split)
    if [ "$dia_prefix" -lt "$MIN" ]; then
        echo "KDIAG FAIL (control): only $dia_prefix marker(s) emitted, wanted $MIN. The"
        echo "            run ended before there was anything to split. Inconclusive,"
        echo "            not a miss -- see the retry loop in the Makefile target."
        exit 2
    fi
    if [ "$con_whole" -lt "$dia_prefix" ]; then
        echo "KDIAG PASS (control): the kernel emitted $dia_prefix marker(s), whole on its"
        echo "            own channel, and only $con_whole arrived intact on the shared"
        echo "            console -- ring-3 output landed inside a kernel marker. That is"
        echo "            the hazard, and COM3 is where it does not happen."
        exit 0
    fi
    echo "KDIAG FAIL (control): all $dia_prefix marker(s) arrived intact on the shared"
    echo "            console too. The split did not reproduce, so this run says"
    echo "            nothing about whether the channel is needed."
    exit 1
    ;;
ioport)
    if [ "$dia_ring3" -ne 0 ]; then
        echo "KDIAG FAIL: a ring-3 sentinel reached the kernel's own channel"
        echo "            ($dia_ring3 occurrence(s)) in a build where 0x3E8 is declared"
        echo "            by no device. The channel is not kernel-only."
        exit 1
    fi
    if [ "$gp" -lt 1 ]; then
        echo "KDIAG FAIL: console_server was not refused. No #GP on the write to the"
        echo "            diagnostic port, and no sentinel either -- so either the probe"
        echo "            did not run or the fault was not reported, and an absence with"
        echo "            no refusal behind it witnesses nothing."
        exit 1
    fi
    echo "KDIAG PASS: the ring-3 write to 0x3E8 took a #GP and the kernel's channel is"
    echo "            clean. No capability names that port, so the grant console_server"
    echo "            does hold never opened it."
    exit 0
    ;;
grant)
    if [ "$gp" -ge 1 ]; then
        echo "KDIAG FAIL (control): console_server still took a #GP on the write, so the"
        echo "            port declaration did not take effect and the sentinel below"
        echo "            proves nothing about the grant."
        exit 1
    fi
    if [ "$dia_ring3" -ge 1 ]; then
        echo "KDIAG PASS (control): the ring-3 sentinel is in the kernel's own channel"
        echo "            ($dia_ring3 occurrence(s)). With 0x3E8 declared among the"
        echo "            platform device's ports, console_server was granted the"
        echo "            diagnostic channel and wrote into it. What keeps ring 3 out of"
        echo "            COM3 is that no capability names the port -- nothing else."
        exit 0
    fi
    echo "KDIAG FAIL (control): the sentinel never reached the diagnostic channel."
    echo "            Either the port declaration did not take effect, the grant was"
    echo "            refused, or console_server never wrote. In every case this arm"
    echo "            witnessed nothing."
    exit 1
    ;;
*)
    echo "KDIAG FAIL: unknown MODE '$MODE'"
    exit 1
    ;;
esac
