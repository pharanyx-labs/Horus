#!/usr/bin/env bash
#
# "Can the kernel be heard when it faults in its own code?"
#
# Every other harness in this tree treats a kernel fault as a failure. This one
# is the inverse: it boots a kernel built with KFAULT_INJECT=1, which takes a
# deliberate supervisor page fault on a timer tick AFTER the ring-3
# console_server owns the console, and asserts the kernel's report of it reaches
# the SERIAL LINE.
#
# The ordering is the whole test, not a detail. print() is klog-only once
# console_server takes the console, so a report emitted that way exists in a
# buffer nobody reads: G-8's supervisor fault killed a ring-3 task on every
# occurrence and the fault address, error code and faulting rip -- all of which
# the kernel computed -- never reached the wire. Requiring the report to appear
# AFTER the login prompt is what distinguishes "reported" from "reported while
# anyone could hear it".
#
# Usage: tools/kfault_test.sh [boot.iso]
# Env:   KFAULT_TIMEOUT   seconds to wait (default 60)
#        EXPECT_REPORT    1 (default): the report must appear after the login
#                         prompt. 0: it must NOT appear -- the control arm, for
#                         a KFAULT_LEGACY_PRINTLN=1 build, which reproduces the
#                         defect and must therefore fail to be heard.
#        REPORT_RE        which report to look for (default: the injected #PF).
#                         `make smoke-resume-guard*` overrides it to assert the
#                         resume-%rsp floor guard's PANIC line instead: the same
#                         question -- "is this report audible after the console
#                         handover" -- asked of a different reporter, so it is
#                         this harness rather than a second copy of it.
#        REPORT_LABEL     what to call it in the verdict (default "CPL-0 fault")
#        QEMU_SMP         passed through to -smp (default 1)
#        KFAULT_LOG       keep the serial log at this path
#
set -u

ISO="${1:-boot.iso}"
TIMEOUT="${KFAULT_TIMEOUT:-60}"
EXPECT_REPORT="${EXPECT_REPORT:-1}"

LOGIN_MARKER="horus login"
# The stable part of the report: address and decoded error code. Deliberately
# not the task name or rip -- which task a tick lands in varies, and rip moves
# with every build. What must never vary is that the kernel said WHAT happened.
REPORT_RE="${REPORT_RE:-PAGE FAULT at 0x94 err=0x0\\(not-present,read,supervisor\\)}"
REPORT_LABEL="${REPORT_LABEL:-CPL-0 fault}"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "KFAULT SKIP: qemu-system-x86_64 not found" >&2
    exit 2
fi
if [ ! -f "$ISO" ]; then
    echo "KFAULT FAIL: ISO '$ISO' not found (run 'make boot.iso' first)" >&2
    exit 1
fi

LOG="${KFAULT_LOG:-$(mktemp)}"
# COM3, the kernel's diagnostic channel. $LOG is the console, which ring 3 writes
# too, so a kernel marker in it can be split between two characters; nothing but
# the kernel can write COM3. REPORT_CHANNEL selects which one the assertion
# reads. See the note above kdiag_ch() in src/kernel/scheduler.c.
KDIAG="${KFAULT_KDIAG_LOG:-$(mktemp)}"
QEMU_PID=""
cleanup() {
    [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
    [ -n "$QEMU_PID" ] && wait "$QEMU_PID" 2>/dev/null
    [ -z "${KFAULT_LOG:-}" ] && rm -f "$LOG"
    [ -z "${KFAULT_KDIAG_LOG:-}" ] && rm -f "$KDIAG"
    return 0
}
trap cleanup EXIT

qemu-system-x86_64 \
    -m 512M -cpu "${QEMU_CPU:-qemu64,+aes,+rdrand,+smep,+smap,+umip}" -accel tcg \
    -display none -no-reboot -no-shutdown \
    -serial file:"$LOG" -serial none -serial file:"$KDIAG" -net none \
    -smp "${QEMU_SMP:-1}" \
    -cdrom "$ISO" &
QEMU_PID=$!

# Wait for the login prompt first and remember where it ended: everything the
# assertion looks at is what came after it.
login_at=""
deadline=$(( SECONDS + TIMEOUT ))
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -q "$LOGIN_MARKER" "$LOG" 2>/dev/null; then
        login_at=$(grep -n "$LOGIN_MARKER" "$LOG" | head -1 | cut -d: -f1)
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then break; fi
    sleep 0.5
done

if [ -z "$login_at" ]; then
    echo "------------------- serial log -------------------"
    cat "$LOG" 2>/dev/null || true
    echo "--------------------------------------------------"
    echo "KFAULT FAIL: never reached the login prompt, so the console handover"
    echo "             this test depends on never happened. Not a result."
    exit 1
fi

# Then wait for the injected fault to be reported (or for the timeout, which is
# the expected outcome for the control arm).
found=0
while [ "$SECONDS" -lt "$deadline" ]; do
    if tail -n +"$login_at" "$LOG" | grep -qE "$REPORT_RE" 2>/dev/null; then found=1; break; fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        tail -n +"$login_at" "$LOG" | grep -qE "$REPORT_RE" 2>/dev/null && found=1
        break
    fi
    sleep 0.5
done

echo "------------------- serial log -------------------"
cat "$LOG" 2>/dev/null || true
echo ""
echo "--------------------------------------------------"
echo "login prompt at line $login_at; looking for: $REPORT_RE"
echo "report after the prompt: $found"

if [ "$EXPECT_REPORT" = "1" ]; then
    if [ "$found" = "1" ]; then
        echo "KFAULT PASS: the kernel's $REPORT_LABEL report reached serial AFTER the"
        echo "             console handover -- audible where it matters"
        exit 0
    fi
    echo "KFAULT FAIL: the kernel hit the injected $REPORT_LABEL and said nothing on"
    echo "             the wire. That is the defect this gate exists for."
    exit 1
else
    if [ "$found" = "1" ]; then
        echo "KFAULT FAIL: the control arm was heard. Either the build flag that is"
        echo "             supposed to reproduce the defect did not take effect, or"
        echo "             the reporting path changed -- in both cases this gate is"
        echo "             measuring something other than what it claims."
        exit 1
    fi
    echo "KFAULT PASS (control): the $REPORT_LABEL report never reached serial,"
    echo "             which is the defect, reproduced on demand"
    exit 0
fi
