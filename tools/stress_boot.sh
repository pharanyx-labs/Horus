#!/usr/bin/env bash
#
# Boot the SAME ISO N times and report a pass/fail RATE.
#
# WHY THIS EXISTS
#
# Some kernel defects are races that only a fraction of boots hit. For those, a
# single green run is not evidence of anything: `smoke-console-smp` was failing
# roughly one boot in three while every individual run looked like an ordinary
# pass or an ordinary flake. Separating "I broke it" from "it was already broken"
# took eighteen boots across three builds, by hand. This makes that measurement a
# command instead of an afternoon.
#
# Two properties matter and neither is optional:
#
#   1. BUILD ONCE, BOOT MANY. `make smoke-*` does a full `clean` + rebuild per
#      invocation, so looping it spends almost all its time in the compiler. This
#      takes a prebuilt ISO and only pays for QEMU.
#
#   2. PIN THE CPUs. Under TCG each guest vCPU is a host thread. On an idle
#      many-core workstation a 4-vCPU guest has a core each and scheduling races
#      simply do not open; pinned to 2 host cores -- what CI runners actually
#      have -- the same build fails repeatedly. A stress run on an unpinned
#      workstation can report 20/20 green on a kernel that fails a third of the
#      time in CI, which is worse than not measuring at all.
#
# Usage: tools/stress_boot.sh [boot.iso]
# Env:   STRESS_RUNS    how many boots (default 20)
#        STRESS_CPUSET  host CPUs to pin QEMU to (default "0,1"; empty = no pinning)
#        SMP_CPUS       guest vCPUs (default 4)
#        SMOKE_TIMEOUT  per-boot timeout in seconds (default 40)
#        STRESS_MAX_FAIL exit non-zero above this many failures (default 0)
#        STRESS_GATE     "any" (default) or "marker" -- see the note above the exit
#                        logic; "marker" gates only on FAIL_MARKER hits, so an
#                        unrelated hang is reported without reddening the gate
#        plus everything tools/smoke_test.sh honours (REQUIRE_MARKER, FAIL_MARKER, ...)
#
set -u

ISO="${1:-boot.iso}"
RUNS="${STRESS_RUNS:-20}"
CPUSET="${STRESS_CPUSET-0,1}"
MAX_FAIL="${STRESS_MAX_FAIL:-0}"
STRESS_GATE="${STRESS_GATE:-any}"
# Consumed by smoke_test.sh via the environment; defaulted here too because this
# script now READS it to classify failures, and `set -u` aborts on an unset var.
FAIL_MARKER="${FAIL_MARKER:-}"
export SMP_CPUS="${SMP_CPUS:-4}"
export SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-40}"

HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ISO" ]; then
    echo "STRESS FAIL: ISO '$ISO' not found (build it first)" >&2
    exit 1
fi

# Pinning is a best-effort amplifier, not a requirement: without taskset the runs
# still happen, they are just less likely to expose a scheduling race. Say so
# loudly rather than silently reporting a weaker measurement as a strong one.
# Built as one array (never empty, so it needs no `set -u` gymnastics on bash < 4.4).
CMD=()
if [ -n "$CPUSET" ]; then
    if command -v taskset >/dev/null 2>&1; then
        CMD=(taskset -c "$CPUSET")
    else
        echo "STRESS WARN: taskset not found; running UNPINNED." >&2
        echo "STRESS WARN: a green result here is weak evidence -- scheduling races" >&2
        echo "STRESS WARN: need CPU oversubscription to surface." >&2
    fi
fi
CMD+=("$HERE/smoke_test.sh" "$ISO")

# A second QEMU on the same pinned cores starves this one into the timeout, and
# the run then reports failures that belong to the measurement, not the kernel.
# That is not hypothetical -- it invalidated a 20-boot run during the work that
# produced this script. Refuse to produce a number that cannot be trusted.
if command -v pgrep >/dev/null 2>&1; then
    # `pgrep -c` exits non-zero with no matches, so a naive `|| echo 0` appends a
    # second line and the test below dies on "0\n0". Count lines instead.
    others="$(pgrep -f qemu-system-x86_64 2>/dev/null | wc -l | tr -d ' ')"
    if [ "${others:-0}" -gt 0 ]; then
        echo "STRESS FAIL: $others other qemu-system-x86_64 process(es) already running." >&2
        echo "STRESS FAIL: they compete for the same pinned cores and would make this" >&2
        echo "STRESS FAIL: measurement meaningless. Stop them, or set STRESS_ALLOW_BUSY=1" >&2
        echo "STRESS FAIL: if you know they are pinned elsewhere." >&2
        [ -z "${STRESS_ALLOW_BUSY:-}" ] && exit 1
    fi
fi

echo "stress: $RUNS boots of '$ISO' (${SMP_CPUS} vCPUs, host cpus '${CPUSET:-all}', ${SMOKE_TIMEOUT}s each)"

pass=0
fail=0
fail_marker=0     # runs that tripped FAIL_MARKER -- the property under test broke
fail_other=0      # runs that died some other way (timeout/hang) before proving anything
failed_runs=""
for i in $(seq 1 "$RUNS"); do
    if out="$("${CMD[@]}" 2>&1)"; then
        pass=$((pass + 1))
        printf 'run %3d/%s: pass\n' "$i" "$RUNS"
    else
        fail=$((fail + 1))
        failed_runs="$failed_runs $i"
        kind="other"
        if [ -n "$FAIL_MARKER" ] && printf '%s' "$out" | grep -qF "$FAIL_MARKER"; then
            kind="marker"
            fail_marker=$((fail_marker + 1))
        else
            fail_other=$((fail_other + 1))
        fi
        printf 'run %3d/%s: FAIL (%s)\n' "$i" "$RUNS" "$kind"
        # PRINT it, do not merely save it. The first version wrote the serial log
        # to stress-first-failure.log and said so -- which is useless in CI, where
        # the workspace is destroyed with the runner. A gating job failed 1-in-30
        # on GitHub with the one artifact needed to diagnose it sitting in a file
        # nobody would ever read. Same defect the session soak had (it piped every
        # run to /dev/null); fixed here for the same reason.
        if [ "$fail" -eq 1 ]; then
            printf '%s\n' "$out" > stress-first-failure.log
            echo "----- first failure, last 30 lines (full log: stress-first-failure.log) -----"
            printf '%s\n' "$out" | tail -30
            echo "----------------------------------------------------------------------------"
        fi
    fi
done

echo "--------------------------------------------------"
echo "STRESS RESULT: $pass pass / $fail fail out of $RUNS"
[ "$fail" -gt 0 ] && echo "  of which: $fail_marker tripped '$FAIL_MARKER', $fail_other died otherwise"
[ -n "$failed_runs" ] && echo "failed runs:$failed_runs"

# STRESS_GATE selects WHAT the exit status is a statement about.
#
#   any     (default) -- any failed boot fails the run.
#   marker  -- only a FAIL_MARKER hit fails the run; a boot that hung or timed out
#              without tripping it is reported loudly and does not gate.
#
# `marker` exists because a stress job asserting "property P holds" must not
# inherit every unrelated intermittent in the system. The claim-invariant job
# gates on a PANIC from the checker; a boot that never reached the shell proves
# nothing about the invariant either way, and folding the two together silently
# converted a precise gate into a flaky one (finding G-8). Reported, not hidden --
# a run that ends "0 marker, 2 other" is a green gate and a loud signal.
if [ "$STRESS_GATE" = "marker" ]; then
    if [ "$fail_other" -gt 0 ]; then
        echo "STRESS NOTE: $fail_other boot(s) failed WITHOUT tripping '$FAIL_MARKER'."
        echo "STRESS NOTE: not gated here (see STRESS_GATE=marker); this is the G-8 signal."
    fi
    if [ "$fail_marker" -gt "$MAX_FAIL" ]; then
        echo "STRESS FAIL: $fail_marker marker failure(s) exceeds the permitted $MAX_FAIL"
        exit 1
    fi
    echo "STRESS PASS: $fail_marker marker failure(s) within the permitted $MAX_FAIL"
    exit 0
fi

if [ "$fail" -gt "$MAX_FAIL" ]; then
    echo "STRESS FAIL: $fail failure(s) exceeds the permitted $MAX_FAIL"
    exit 1
fi
echo "STRESS PASS: $fail failure(s) within the permitted $MAX_FAIL"
exit 0
