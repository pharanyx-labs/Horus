#!/usr/bin/env bash
# S85: a PERSISTENT volume that was never sealed is refused when measured boot is
# required (docs/LIMITATIONS.md 2.9).
#
# TWO BOOTS ON ONE DISK, AND TWO DIFFERENT KERNELS, because a password-only
# volume can only be MADE by a machine with no TPM. Boot 1 runs a kernel without
# the policy and without a TPM: the format takes the tpm_mode 0 path and leaves
# the disk exactly as an operator's would be. Boot 2 runs the policy kernel WITH
# a TPM, so measured boot itself succeeds -- `tpm: measured boot OK` is on the
# wire -- and the volume is the only thing wrong with the machine. That is the
# whole experiment: the requirement must not evaporate because someone presented
# a re-formatted disk.
#
# Booting boot 2 WITHOUT a TPM would be a different gate. The kernel halts at
# tpm_init long before it looks at a volume, which is what
# make smoke-measured-boot-required-control already asserts.
#
# THE TPM STATE DIRECTORY IS KEPT ACROSS BOTH BOOTS. The refusal arm does not
# need it; the sealed arm cannot work without it, since a secret sealed under
# PolicyPCR(8,9) in boot 1 has to be unsealable by the same TPM in boot 2.
#
# Env:
#   MP_ISO1 / MP_ISO2   the ISO for each boot (may be the same file)
#   MP_TPM1 / MP_TPM2   1 to attach the emulated TPM to that boot
#   MP_REQUIRE1         marker boot 1 must reach
#   MP_REQUIRE2         marker boot 2 must reach (omit if MP_EXPECT_FAULT2)
#   MP_EXPECT_FAULT2    fault boot 2 must take; any OTHER fault still fails
#   MP_ALSO2            strings that must ALSO appear in boot 2's log, `|`-separated
#   MP_FAIL             marker whose appearance fails either boot
#   MP_IMG              disk image (created blank here)
#   MP_BLOCKS / MP_BS   its size, in blocks of that many bytes
#   MP_TIMEOUT          per-boot budget
set -euo pipefail

ISO1=${MP_ISO1:?MP_ISO1 must be set}
ISO2=${MP_ISO2:?MP_ISO2 must be set}
IMG=${MP_IMG:-measured-persist.img}
BS=${MP_BS:?MP_BS must be set}
NBLOCKS=${MP_BLOCKS:?MP_BLOCKS must be set}
TMO=${MP_TIMEOUT:-300}
REQ1=${MP_REQUIRE1:?MP_REQUIRE1 must be set}
REQ2=${MP_REQUIRE2:-}
FAULT2=${MP_EXPECT_FAULT2:-}
ALSO2=${MP_ALSO2:-}
FAILM=${MP_FAIL:-MEASURED_PERSIST: FAIL}

if [ -z "$REQ2" ] && [ -z "$FAULT2" ]; then
    echo "[measured-persist] FAIL: boot 2 needs MP_REQUIRE2 or MP_EXPECT_FAULT2" >&2
    exit 2
fi

# ABSOLUTE, deliberately: swtpm_setup and swtpm resolve a relative --tpmstate
# differently and the disagreement is silent -- the emulator then starts on an
# empty state directory and the guest never boots, which reaches a harness as a
# zero-length serial log. tools/rollback_replay.sh paid for this lesson.
TPMSTATE="$(cd "$(dirname "$IMG")" && pwd)/$(basename "${IMG%.img}")-tpmstate"
LOG1="${IMG%.img}-b1.log"
LOG2="${IMG%.img}-b2.log"
rm -rf "$TPMSTATE" "$IMG" "$LOG1" "$LOG2"
mkdir -p "$TPMSTATE"
truncate -s $(( NBLOCKS * BS )) "$IMG"

boot() {   # boot <iso> <tpm 0|1> <logfile> [extra env assignments via env]
    SMOKE_TIMEOUT="$TMO" SMOKE_DISK="$IMG" SMOKE_LOG="$3" MARKER_ONLY=1 \
        TPM="$2" KEEP_TPMSTATE="$TPMSTATE" FAIL_MARKER="$FAILM" \
        "$(dirname "$0")/smoke_test.sh" "$1"
}

echo "[measured-persist] boot 1/2 - format the disk (tpm=${MP_TPM1:-0})"
REQUIRE_MARKER="$REQ1" boot "$ISO1" "${MP_TPM1:-0}" "$LOG1"

# ANTI-VACUITY. A boot that reached its marker without writing anything would
# leave boot 2 meeting a blank disk, which the selftest reports as "met a blank
# disk" and would then FORMAT under the policy -- sealing it, and passing the
# refusal arm by never having an unsealed volume at all.
if [ "$(tr -d '\0' < "$IMG" | head -c 1 | wc -c)" -eq 0 ]; then
    echo "[measured-persist] FAIL: boot 1 left the image blank; boot 2 would test nothing" >&2
    exit 1
fi

echo "[measured-persist] boot 2/2 - present it to the policy kernel (tpm=${MP_TPM2:-1})"
if [ -n "$FAULT2" ]; then
    EXPECT_FAULT="$FAULT2" boot "$ISO2" "${MP_TPM2:-1}" "$LOG2"
else
    REQUIRE_MARKER="$REQ2" boot "$ISO2" "${MP_TPM2:-1}" "$LOG2"
fi

# WHAT THE GUEST MET, checked separately from the verdict. Under MP_EXPECT_FAULT2
# the harness's verdict is the PANIC, and a PANIC is not evidence about the
# VOLUME: an arm that formatted a sealed volume by mistake, or ran on the
# ephemeral vdisk, would have to be caught here or not at all. The marker is
# printed BEFORE the unlock is attempted, so it is not in a race with the kill.
# Several strings, separated by `|` -- a make recipe hands each LINE to its own
# shell, so a newline-separated list cannot survive the trip, and no marker in
# this tree contains a pipe.
if [ -n "$ALSO2" ]; then
    old_ifs=$IFS; IFS='|'
    # shellcheck disable=SC2086
    set -- $ALSO2
    IFS=$old_ifs
    for want in "$@"; do
        [ -n "$want" ] || continue
        if ! grep -qF "$want" "$LOG2"; then
            echo "[measured-persist] FAIL: boot 2 never reported '$want'" >&2
            echo "--- boot 2 serial (MEASURED_PERSIST lines) ---" >&2
            grep -F 'MEASURED_PERSIST' "$LOG2" >&2 || echo "(none)" >&2
            exit 1
        fi
    done
fi

# The logs and the image are kept on the failure path deliberately: a gate's
# evidence matters in exactly the case it goes red.
rm -rf "$TPMSTATE" "$IMG" "$LOG1" "$LOG2"
