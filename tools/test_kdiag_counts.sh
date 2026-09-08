#!/bin/bash
# Falsify the counting fix in tools/kdiag_test.sh, deterministically.
#
# THE DEFECT. Until 2026-09-08 the verdict's counts came from separate reads of
# a capture QEMU was still writing:
#
#     dia_whole=$(count "$DIAG" "$MARKER"); dia_prefix=$(count "$DIAG" "$PREFIX")
#
# A marker completing between those two processes makes prefix exceed whole,
# which is exactly the shape of a split marker -- so the gate reports the defect
# it is looking for, from an artefact of its own measurement. It did, in CI run
# 34227134084, reddening a dependabot PR whose diff was three SHA pin bumps; the
# gate then printed an evidence dump containing all seven markers intact.
#
# The skew is ONE-DIRECTIONAL (whole is read first), so it can only manufacture a
# false RED, never a false green. That is why it survived: a gate that only ever
# fails wrongly looks like a flaky gate rather than a broken measurement.
#
# WHY THIS TEST EXISTS RATHER THAN A RETRY. The rate is about 1 job run in 35 --
# measured over the last 36 ci.yml runs, 33 pass / 2 fail with the other failure
# being a different step. Waiting for it is not a falsification. A live writer
# reproduces it on demand, in one second, every time.
set -u
cd "$(dirname "$0")/.."

MARKER="KDIAGPROBE: a kernel marker that must not be split"
PREFIX="KDIAGPROBE:"
RING3="KDIAGRING3:"
GPFAULT="general protection"

# The OLD helper, verbatim: one process per pattern, re-reading the file.
count() {
    python3 - "$1" "$2" <<'PYCOUNT'
import sys
data = open(sys.argv[1], 'rb').read()
cut = data.rfind(b'\n')
body = data[:cut + 1] if cut >= 0 else b''
print(body.count(sys.argv[2].encode()))
PYCOUNT
}

# The NEW helper, taken from the script it must match rather than retyped -- a
# copy here would let the two drift and this test would then be checking itself.
eval "$(sed -n '/^counts_for() {/,/^}/p' tools/kdiag_test.sh)"
if ! declare -f counts_for >/dev/null; then
    echo "FAIL: could not extract counts_for() from tools/kdiag_test.sh"; exit 1
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"; kill %1 2>/dev/null' EXIT
F="$TMP/diag.log"
: > "$F"

# A writer that keeps completing markers WHILE the sampling runs, standing in for
# the guest. The pace matters: a burst that finishes before the first sample
# leaves a static file, and a static file cannot skew -- the first version of this
# test wrote 4000 lines in a few milliseconds and reproduced nothing, which the
# check below reported as a broken experiment rather than as a pass.
( for i in $(seq 1 600); do
      printf '%s #%d\n' "$MARKER" "$i" >> "$F"
      python3 -c 'import time; time.sleep(0.01)'
  done ) &

sleep 0.05
old_skew=0; new_skew=0; N=40
for _ in $(seq 1 $N); do
    w=$(count "$F" "$MARKER"); p=$(count "$F" "$PREFIX")
    [ "$w" -ne "$p" ] && old_skew=$((old_skew + 1))
    read -r nw np _r _g <<EOF
$(counts_for "$F")
EOF
    [ "$nw" -ne "$np" ] && new_skew=$((new_skew + 1))
done
wait %1 2>/dev/null

echo "  two reads of a growing capture : $old_skew/$N samples disagreed (whole != prefix)"
echo "  one read of the same capture   : $new_skew/$N samples disagreed"

fail=0
if [ "$old_skew" -eq 0 ]; then
    echo "  [FAIL] the defect did not reproduce, so this test witnesses nothing."
    echo "         The writer may be too slow to complete a marker between two reads;"
    echo "         that is a broken experiment, not a passing gate."
    fail=1
else
    echo "  [ OK ] the two-read form miscounts a capture that is still being written"
fi
if [ "$new_skew" -ne 0 ]; then
    echo "  [FAIL] the one-read form ALSO disagreed with itself -- it cannot, since"
    echo "         both counts come from the same bytes. Something else is wrong."
    fail=1
else
    echo "  [ OK ] the one-read form cannot disagree with itself"
fi

[ "$fail" = 0 ] || { echo "KDIAG-COUNTS FAIL"; exit 1; }
echo "KDIAG-COUNTS PASS: counts for a capture come from one snapshot of it"
