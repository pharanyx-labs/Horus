#!/bin/bash
# Boot horus.iso for make smoke-retype-race (and its arms), retrying a boot that
# tested nothing.
#
# The kernel holds each of retyperace's retype windows open until a sweep on
# another CPU has crossed it, for up to 2 s, and prints
#   RETYPETEST: INCONCLUSIVE no sweep ran inside a retype window
# when none did. That is a KERNEL line, read from the kernel console's own copy
# (COM4, SMOKE_KCON_LOG), where no ring-3 output can split it (LIMITATIONS 2.6c);
# the verdicts are retyperace's own, on the console. Such a boot is neither a pass nor a fail (CLAUDE.md §2): it is
# named, kept, and retried, up to RETYPE_RACE_BOOTS times. If every boot is
# inconclusive the gate fails AS inconclusive, so a harness that can no longer
# exercise the race is visible rather than green. Every boot's serial log is
# kept in .retype-race-evidence/.
#
# Everything else (REQUIRE_MARKER, FAIL_MARKER, EXPECT_FAULT, SMP_CPUS, ...) is
# passed straight to tools/smoke_test.sh.
set -u
iso="${1:?usage: retype_race_boot.sh horus.iso}"
boots="${RETYPE_RACE_BOOTS:-3}"
dir=.retype-race-evidence
# Start empty. A log file that already exists is not truncated by the boot, so
# a previous run's lines would sit at the top of this run's log and be scored as
# this run's (found 2026-10-17: a base gate read its own arm's PANIC). Every boot
# of THIS run is kept until the next run starts.
rm -rf "$dir"
mkdir -p "$dir"
for n in $(seq 1 "$boots"); do
    log="$dir/boot$n.log"
    kcon="$dir/boot$n.kcon"
    SMOKE_LOG="$log" SMOKE_KCON_LOG="$kcon" tools/smoke_test.sh "$iso"
    rc=$?
    if grep -aq 'RETYPETEST: INCONCLUSIVE' "$kcon"; then
        echo "RETYPE RACE: boot $n inconclusive (no sweep crossed a window); evidence $log"
        continue
    fi
    exit $rc
done
echo "RETYPE RACE: INCONCLUSIVE on all $boots boots; evidence in $dir/"
exit 1
