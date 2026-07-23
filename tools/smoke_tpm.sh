#!/bin/sh
# Measured-boot gate (roadmap 2.2): boot the ISO under an emulated TPM and assert
# the PCR[8]/PCR[9] the guest measured equal the values recomputed on the host
# from the reproducible boot-module manifest. A match proves the kernel measured
# exactly the manifest this image embeds — external verification, not the guest's
# own word.
#
# EXPECT_MISMATCH=1 flips the assertion for a tampered ISO: the boot must still
# complete, but the measured PCRs must DIFFER from the clean manifest (because a
# refused module drops out of PCR[9]) — proving the measurement reflects what
# actually loaded, not a baked-in constant.
#
# Usage: smoke_tpm.sh <iso> [manifest.h]
set -eu

ISO=${1:?usage: smoke_tpm.sh <iso> [manifest.h]}
MANIFEST=${2:-src/kernel/boot_module_manifest.h}
HERE=$(dirname "$0")

if ! command -v swtpm >/dev/null 2>&1; then
    echo "SMOKE-TPM SKIP: swtpm not installed"; exit 0
fi

EXPECTED=$(python3 "$HERE/tpm_expected_pcr.py" "$MANIFEST")
echo "expected (host, from manifest): $EXPECTED"

SERIAL=$(mktemp)
trap 'rm -f "$SERIAL"' EXIT INT TERM

SERIAL_OUT="$SERIAL" REQUIRE_MARKER='[tpm] measured boot OK' \
    FAIL_MARKER='[tpm] measured boot FAILED' \
    SWTPM_TIMEOUT="${SMOKE_TIMEOUT:-60}" \
    "$HERE/run_with_swtpm.sh" "$ISO"

# The guest's line: `[tpm] PCR8=<hex> PCR9=<hex>`
OBSERVED=$(grep -F '[tpm] PCR8=' "$SERIAL" | tail -1 | tr -d '\r' | sed 's/^.*\[tpm\] //')
echo "observed (guest, from TPM):     $OBSERVED"

if [ -z "$OBSERVED" ]; then
    echo "SMOKE-TPM FAIL: no PCR line on serial"; exit 1
fi

if [ "${EXPECT_MISMATCH:-}" = 1 ]; then
    # Falsification: a tampered module must be refused AND must change the PCRs.
    if ! grep -qF 'boot module refused' "$SERIAL"; then
        echo "SMOKE-TPM FAIL: tampered module was not refused (A4 regression)"; exit 1
    fi
    if [ "$OBSERVED" = "$EXPECTED" ]; then
        echo "SMOKE-TPM FAIL: tampered boot measured the CLEAN PCRs -- measurement is not load-bearing"; exit 1
    fi
    echo "SMOKE-TPM PASS: tampered module refused and diverged the measured PCRs"
    exit 0
fi

if [ "$OBSERVED" != "$EXPECTED" ]; then
    echo "SMOKE-TPM FAIL: guest PCRs do not match the reproducible manifest"; exit 1
fi
echo "SMOKE-TPM PASS: measured PCR[8]/PCR[9] match the reproducible manifest"
