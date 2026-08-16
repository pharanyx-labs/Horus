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
# Env:   SMOKE_TIMEOUT  (seconds, default 40)
#        REQUIRE_MARKER (optional: an extra string that must also appear on
#                        serial for the run to pass — e.g. "ELF_SELFTEST: PASS")
#        FAIL_MARKER    (optional: a string whose appearance is an immediate
#                        failure — e.g. "ELF_SELFTEST: FAIL")
#        MARKER_ONLY    (optional: if "1", REQUIRE_MARKER alone signals success
#                        and the shell banner is NOT required — for self-tests
#                        that intentionally never boot the shell, e.g. the
#                        preemption test whose tasks run forever)
#        ABSENT_MARKER  (optional: a string that must NOT appear anywhere in the
#                        log. Checked at the end, on the full log, so it is a
#                        real assertion of absence rather than a race with
#                        whatever happened to have been printed by then.)
#        SMOKE_DISK_CACHE   (optional: QEMU cache mode for SMOKE_DISK; default
#                        writethrough — see the DRIVE_ARG comment)
#        SMOKE_DISK_BLKDEBUG (optional: path to a blkdebug config, layered over
#                        SMOKE_DISK. Used to inject FLUSH CACHE failures so the
#                        journal's durability barriers can be witnessed.)
#        SMOKE_TRACE    (optional: comma-separated QEMU trace events to enable.
#                        Written to SMOKE_TRACE_FILE. Fails closed if the QEMU
#                        build has no trace backend — never silently skipped.)
#        SMOKE_TRACE_FILE   (optional: where to write the trace; default a temp
#                        file discarded on exit)
#        WAIT_FOR_EXIT  (optional: if "1", the run ends by asking QEMU to quit
#                        over QMP once REQUIRE_MARKER appears, then WAITING for
#                        the process to exit — instead of shooting it the instant
#                        the marker is seen. Finding [I-11]: a signal on a string
#                        match makes "the guest finished" indistinguishable from
#                        "the harness was too quick", so a real regression and a
#                        race produced identical output. A QMP quit shuts the
#                        block backends down cleanly and exits 0, and a guest
#                        that then fails to leave becomes a timeout rather than a
#                        pass. Requires python3; fails closed without it.)
#
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${SMOKE_TIMEOUT:-40}"
REQUIRE_MARKER="${REQUIRE_MARKER:-}"
FAIL_MARKER="${FAIL_MARKER:-}"
MARKER_ONLY="${MARKER_ONLY:-}"
ABSENT_MARKER="${ABSENT_MARKER:-}"
WAIT_FOR_EXIT="${WAIT_FOR_EXIT:-}"

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
TRACE_FILE=""   # declared before the EXIT trap so cleanup() is safe under set -u
QMP_SOCK=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    rm -f "$LOG"
    # Only remove a trace file we created ourselves; when the caller named one
    # via SMOKE_TRACE_FILE it belongs to them and is usually the whole point.
    [ -n "$TRACE_FILE" ] && [ -z "${SMOKE_TRACE_FILE:-}" ] && rm -f "$TRACE_FILE"
    [ -n "$QMP_SOCK" ] && rm -f "$QMP_SOCK"
    return 0
}
trap cleanup EXIT

# -accel tcg: GitHub runners have no /dev/kvm; force software emulation so the
#   run is deterministic instead of depending on host virtualization.
# -no-reboot: a triple fault halts QEMU instead of looping, so we detect it.
# isa-debug-exit: present for parity with `make run`; not relied on here.
# Optional persistent ATA disk (SMOKE_DISK=<image>): attaches it as the primary
# IDE drive so a STORAGE_ATA=1 kernel has a real block device to format/mount.
DRIVE_ARG=""
if [ -n "${SMOKE_DISK:-}" ]; then
    # cache=writethrough (the default here): every guest write is committed to the
    # host image file immediately, so a two-boot persistence test (QEMU killed
    # after a marker, then re-launched on the same image) never loses the first
    # boot's writes to a writeback cache.
    #
    # Note what that means for anything testing DURABILITY: under writethrough
    # the emulator persists every write whether or not the guest ever issues
    # FLUSH CACHE, so a kernel with no flush at all passes identically to one
    # that flushes correctly. That is why the [I-10] gates do not simply switch
    # this to writeback — writeback would not distinguish them either, since
    # guest writes land in the HOST page cache and survive QEMU being killed.
    # They use SMOKE_DISK_BLKDEBUG to fail the flush instead, which is the one
    # configuration where issuing the command and checking its result are both
    # observable. See TESTS.md.
    #
    # Those gates DO pass SMOKE_DISK_CACHE=writeback, for a different reason than
    # durability: under writethrough QEMU may satisfy each write with a write plus
    # a flush, so an error injected on flush_to_disk fails ordinary writes as well
    # and the volume never even formats. Writeback keeps a write a write, leaving
    # the guest's explicit FLUSH CACHE as the only flush_to_disk event.
    CACHE_MODE="${SMOKE_DISK_CACHE:-writethrough}"
    if [ -n "${SMOKE_DISK_BLKDEBUG:-}" ]; then
        if [ ! -f "$SMOKE_DISK_BLKDEBUG" ]; then
            echo "SMOKE FAIL: SMOKE_DISK_BLKDEBUG '$SMOKE_DISK_BLKDEBUG' not found" >&2
            exit 1
        fi
        DRIVE_ARG="-drive file=blkdebug:$SMOKE_DISK_BLKDEBUG:$SMOKE_DISK,format=raw,if=ide,index=0,cache=$CACHE_MODE"
    else
        DRIVE_ARG="-drive file=$SMOKE_DISK,format=raw,if=ide,index=0,cache=$CACHE_MODE"
    fi
fi

# Optional QEMU tracing. Fails closed when the QEMU build has no trace backend:
# a trace-based assertion that silently observes nothing would pass vacuously,
# which is the exact defect class ([I-11]) these gates exist to retire.
TRACE_ARG=""
TRACE_FILE=""
if [ -n "${SMOKE_TRACE:-}" ]; then
    if ! qemu-system-x86_64 -trace help 2>/dev/null | grep -q .; then
        echo "SMOKE FAIL: SMOKE_TRACE requested but this QEMU has no trace backend" >&2
        exit 1
    fi
    for ev in $(echo "$SMOKE_TRACE" | tr ',' ' '); do
        if ! qemu-system-x86_64 -trace help 2>/dev/null | grep -qx "$ev"; then
            echo "SMOKE FAIL: SMOKE_TRACE event '$ev' unknown to this QEMU build" >&2
            exit 1
        fi
    done
    TRACE_FILE="${SMOKE_TRACE_FILE:-$(mktemp)}"
    # One -trace enable= per event; QEMU takes a pattern per option, not a list.
    for ev in $(echo "$SMOKE_TRACE" | tr ',' ' '); do
        TRACE_ARG="$TRACE_ARG -trace enable=$ev"
    done
    TRACE_ARG="$TRACE_ARG -trace file=$TRACE_FILE"
fi

# WAIT_FOR_EXIT needs a monitor to ask QEMU to leave through. Fail closed if the
# interpreter is missing: a run that silently fell back to signalling would be
# the [I-11] defect again, wearing the fix's name.
QMP_ARG=""
if [ "$WAIT_FOR_EXIT" = "1" ]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "SMOKE FAIL: WAIT_FOR_EXIT=1 needs python3 for the QMP quit" >&2
        exit 1
    fi
    if [ ! -x tools/qmp_quit.py ]; then
        echo "SMOKE FAIL: WAIT_FOR_EXIT=1 needs tools/qmp_quit.py to be executable" >&2
        exit 1
    fi
    QMP_SOCK="$(mktemp -u)"
    QMP_ARG="-qmp unix:${QMP_SOCK},server=on,wait=off"
fi

# SMP_CPUS=<n> boots the guest with n logical CPUs (for the SMP self-test).
# QEMU_SMP=<spec> overrides the whole -smp argument (e.g. a topology like
# "4,cores=2,threads=2" for the SMT sibling-parking test).
SMP_ARG=""
if [ -n "${QEMU_SMP:-}" ]; then
    SMP_ARG="-smp ${QEMU_SMP}"
elif [ -n "${SMP_CPUS:-}" ]; then
    SMP_ARG="-smp $SMP_CPUS"
fi

qemu-system-x86_64 \
    -m 512M -cpu "${QEMU_CPU:-qemu64,+aes,+rdrand,+smep,+smap,+umip}" -accel tcg \
    -display none -no-reboot -no-shutdown \
    -device isa-debug-exit,iobase=0x604,iosize=0x04 \
    -serial file:"$LOG" -net none \
    $DRIVE_ARG $SMP_ARG $TRACE_ARG $QMP_ARG \
    -cdrom "$ISO" &
QEMU_PID=$!

# Is QEMU still actually running?
#
# `kill -0` alone is NOT enough. QEMU is a background child of this script and is
# not reaped until the `wait` in cleanup(), so between its exit() and that wait
# it lingers as a ZOMBIE — and a zombie's PID still exists, so `kill -0` keeps
# reporting success indefinitely. WAIT_FOR_EXIT built on `kill -0` therefore hung
# until the timeout on a guest that had already exited cleanly, reporting a
# healthy two-boot run as a failure. Check the process state and treat Z as dead.
qemu_alive() {
    [ -n "$QEMU_PID" ] || return 1
    kill -0 "$QEMU_PID" 2>/dev/null || return 1
    if [ -r "/proc/$QEMU_PID/stat" ]; then
        # Field 3 of /proc/PID/stat is the state character. comm (field 2) can
        # contain spaces and parentheses, so anchor the parse after the final ')'.
        st=$(sed 's/.*) //' "/proc/$QEMU_PID/stat" 2>/dev/null | cut -d' ' -f1)
        [ "$st" != "Z" ] || return 1
    fi
    return 0
}

status="timeout"
quit_sent=0
deadline=$(( SECONDS + TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -qE "$FAULT_RE" "$LOG" 2>/dev/null; then status="fault"; break; fi
    if [ -n "$FAIL_MARKER" ] && grep -qF "$FAIL_MARKER" "$LOG" 2>/dev/null; then status="marker_fail"; break; fi
    # MARKER_ONLY: the required marker alone is success (no shell banner).
    if [ "$MARKER_ONLY" = "1" ] && [ -n "$REQUIRE_MARKER" ]; then
        if grep -qF "$REQUIRE_MARKER" "$LOG" 2>/dev/null; then
            # WAIT_FOR_EXIT ([I-11]). The marker says the guest reached the
            # point of interest; it does not say the run is over. Ask QEMU to
            # quit over QMP — once — and then WAIT for the process to go away,
            # so the end of the run is a process exit rather than a signal we
            # chose to send at a moment of our own picking. A guest that then
            # fails to leave is reported as a timeout instead of passing.
            #
            # Sending quit on the marker is safe by construction, not by luck:
            # the [I-10] barriers mean the journal write this test cares about
            # is on stable media BEFORE the marker is printed, and a QMP quit
            # closes QEMU's block backends cleanly rather than being shot while
            # holding them.
            if [ "$WAIT_FOR_EXIT" = "1" ]; then
                if [ "$quit_sent" != "1" ]; then
                    if tools/qmp_quit.py "$QMP_SOCK" 10; then
                        quit_sent=1
                    else
                        status="qmp_failed"; break
                    fi
                fi
                if ! qemu_alive; then status="ok"; break; fi
            else
                status="ok"; break
            fi
        fi
    # Otherwise the banner is the primary success signal; if an extra marker is
    # required, wait until both have appeared.
    elif grep -q "$PASS_MARKER" "$LOG" 2>/dev/null; then
        if [ -z "$REQUIRE_MARKER" ] || grep -qF "$REQUIRE_MARKER" "$LOG" 2>/dev/null; then
            status="ok"; break
        fi
    fi
    if ! qemu_alive; then
        # An exit we ASKED for is the successful end of a WAIT_FOR_EXIT run, not
        # a triple fault. quit_sent is only ever set after the required marker
        # appeared, so reaching here with it set means the guest got where it was
        # going and then left when told to. Without this distinction QEMU dying
        # between the inner and outer liveness checks — a window of microseconds,
        # hit reliably in practice — reported a clean shutdown as a crash.
        if [ "$quit_sent" = "1" ]; then status="ok"; else status="exited"; fi
        break
    fi
    sleep 0.5
done

echo "------------------- serial log -------------------"
cat "$LOG" 2>/dev/null || true
echo ""
echo "--------------------------------------------------"

case "$status" in
    ok)
        # A fault (or an explicit fail marker) alongside the banner still fails.
        if grep -qE "$FAULT_RE" "$LOG"; then
            echo "SMOKE FAIL: kernel fault/panic on serial"
            exit 1
        fi
        if [ -n "$FAIL_MARKER" ] && grep -qF "$FAIL_MARKER" "$LOG"; then
            echo "SMOKE FAIL: saw fail marker '$FAIL_MARKER'"
            exit 1
        fi
        # Absence is asserted here, over the COMPLETE log, rather than in the
        # poll loop where it would only ever mean "has not appeared yet".
        if [ -n "$ABSENT_MARKER" ] && grep -qF "$ABSENT_MARKER" "$LOG"; then
            echo "SMOKE FAIL: forbidden marker '$ABSENT_MARKER' appeared on serial"
            exit 1
        fi
        if [ "$MARKER_ONLY" = "1" ]; then
            echo "SMOKE PASS: required marker '$REQUIRE_MARKER' observed on serial"
            exit 0
        fi
        extra=""
        [ -n "$REQUIRE_MARKER" ] && extra=" + required marker '$REQUIRE_MARKER'"
        if grep -q "$LOGIN_MARKER" "$LOG"; then
            echo "SMOKE PASS: reached ring-3 shell banner and login prompt$extra"
        else
            echo "SMOKE PASS: reached ring-3 shell banner$extra"
        fi
        exit 0
        ;;
    marker_fail) echo "SMOKE FAIL: saw fail marker '$FAIL_MARKER' on serial"; exit 1 ;;
    qmp_failed)
        echo "SMOKE FAIL: could not ask QEMU to quit over QMP after the marker"
        echo "  (WAIT_FOR_EXIT=1; the run cannot be ended deterministically -- see [I-11])"
        exit 1 ;;
    fault)   echo "SMOKE FAIL: kernel fault/panic on serial"; exit 1 ;;
    exited)  echo "SMOKE FAIL: QEMU exited before the banner (triple fault?)"; exit 1 ;;
    timeout)
        if [ -n "$REQUIRE_MARKER" ] && ! grep -qF "$REQUIRE_MARKER" "$LOG"; then
            echo "SMOKE FAIL: timed out after ${TIMEOUT}s without required marker '$REQUIRE_MARKER'"
        else
            echo "SMOKE FAIL: timed out after ${TIMEOUT}s before the shell banner"
        fi
        exit 1 ;;
esac
