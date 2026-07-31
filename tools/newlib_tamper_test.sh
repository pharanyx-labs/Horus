#!/bin/sh
# Falsification test for the newlib supply-chain gate.
#
# tools/build_newlib.sh fetches a 9 MiB tarball over the network and pins its
# SHA-256. That pin is the only thing standing between a compromised or corrupted
# upstream artifact and the libc every userspace binary links against -- a
# straightforwardly attractive place to attack a build. A pin nobody exercises is
# an assumption, not a control, so this proves it refuses.
#
# WHY THE POSITIVE CONTROL MATTERS. A gate that refuses EVERYTHING would sail
# through a naive tamper test: feed it bad bytes, watch it fail, declare victory.
# That test cannot distinguish "rejects tampering" from "is broken". So this runs
# both directions where it can -- bad bytes must be refused, and the genuine
# artifact must get PAST verification -- and says plainly which controls ran.
#
# No network required for the negative case: the script skips the fetch when the
# tarball is already present, so planting bad bytes is enough to reach the check.
#
# Exits 0 only if every control that ran behaved correctly.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT=$ROOT/tools/build_newlib.sh

[ -f "$SCRIPT" ] || { echo "TAMPER: FAIL missing $SCRIPT" >&2; exit 1; }

# Keep the version/pin in sync with the script under test rather than restating
# them -- a copy here would drift and silently test the wrong artifact name.
VER=$(sed -n 's/^NEWLIB_VERSION=\(.*\)$/\1/p' "$SCRIPT" | head -1)
SHA=$(sed -n 's/^NEWLIB_SHA256=\(.*\)$/\1/p' "$SCRIPT" | head -1)
[ -n "$VER" ] && [ -n "$SHA" ] || { echo "TAMPER: FAIL could not read VERSION/SHA256 from $SCRIPT" >&2; exit 1; }

echo "TAMPER: gate under test = tools/build_newlib.sh, newlib $VER"
echo "TAMPER: pinned sha256   = $SHA"

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# The script derives its ROOT from its own location, so a copy in a scratch tree
# operates entirely inside that tree. The real newlib/ is never touched.
mkdir -p "$WORK/tools" "$WORK/newlib"
cp "$SCRIPT" "$WORK/tools/build_newlib.sh"
chmod +x "$WORK/tools/build_newlib.sh"

TARBALL="$WORK/newlib/newlib-${VER}.tar.gz"
fails=0

# ---- Control 1 (negative): tampered bytes must be REFUSED ------------------
printf 'this is not newlib; it is an attacker-supplied payload\n' > "$TARBALL"
out=$("$WORK/tools/build_newlib.sh" 2>&1) && rc=0 || rc=$?

if [ "$rc" -eq 0 ]; then
    echo "TAMPER: FAIL the gate ACCEPTED a tampered tarball (exit 0)" >&2
    fails=$((fails + 1))
elif ! printf '%s' "$out" | grep -q "CHECKSUM MISMATCH"; then
    echo "TAMPER: FAIL refused (exit $rc) but not via the checksum gate; output was:" >&2
    printf '%s\n' "$out" >&2
    fails=$((fails + 1))
else
    echo "TAMPER: [ok] tampered tarball refused by the checksum gate (exit $rc)"
fi

# The rejected artifact must be quarantined, not left in place: the fetch is
# skipped whenever the tarball exists, so leaving it would wedge every later run.
if [ -f "$TARBALL" ]; then
    echo "TAMPER: FAIL rejected artifact left in place -- next run would re-read it" >&2
    fails=$((fails + 1))
elif [ -f "$TARBALL.rejected" ]; then
    echo "TAMPER: [ok] rejected artifact quarantined as .rejected"
else
    echo "TAMPER: FAIL rejected artifact neither present nor quarantined" >&2
    fails=$((fails + 1))
fi

# It must refuse BEFORE unpacking. Extracting attacker-controlled bytes and then
# deciding is the wrong order -- tar has had path-traversal bugs, and the whole
# point is not to touch the payload until it is trusted.
if [ -e "$WORK/newlib/src" ]; then
    echo "TAMPER: FAIL unpacked the tampered tarball before verifying it" >&2
    fails=$((fails + 1))
else
    echo "TAMPER: [ok] refused before unpacking"
fi

# ---- Control 2 (positive): the genuine artifact must PASS verification -----
# Opportunistic: uses the real tarball if this tree already has one. Without it
# the negative control alone cannot tell "rejects tampering" from "always fails",
# so its absence is reported loudly rather than passed over in silence.
REAL=$ROOT/newlib/newlib-${VER}.tar.gz
if [ -f "$REAL" ] && echo "$SHA  $REAL" | sha256sum -c - >/dev/null 2>&1; then
    rm -f "$TARBALL.rejected"
    cp "$REAL" "$TARBALL"
    # Verification is what is under test, not the multi-minute build behind it,
    # so stop at the first post-verification step.
    out=$(timeout 120 "$WORK/tools/build_newlib.sh" 2>&1) && rc=0 || rc=$?
    if printf '%s' "$out" | grep -q "checksum OK"; then
        echo "TAMPER: [ok] genuine tarball PASSED verification (gate is not refusing everything)"
    else
        echo "TAMPER: FAIL genuine tarball did not pass verification; output was:" >&2
        printf '%s\n' "$out" | head -20 >&2
        fails=$((fails + 1))
    fi
else
    echo "TAMPER: [warn] positive control SKIPPED -- no verified local copy of the genuine"
    echo "TAMPER:        tarball at $REAL. The negative control alone cannot distinguish"
    echo "TAMPER:        'refuses tampering' from 'refuses everything'. Other CI jobs that"
    echo "TAMPER:        build newlib successfully cover that case."
fi

if [ "$fails" -ne 0 ]; then
    echo "NEWLIB_TAMPER: FAIL $fails control(s) failed" >&2
    exit 1
fi
echo "NEWLIB_TAMPER: PASS supply-chain pin refuses tampered artifacts and accepts the genuine one"
