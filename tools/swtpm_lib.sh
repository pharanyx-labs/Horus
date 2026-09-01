# swtpm_lib.sh -- the swtpm lifecycle, in one place. Sourced, never executed.
#
# WHY THIS EXISTS. Booting Horus under an emulated TPM needs the same twenty-odd
# lines every time: a state directory, swtpm_setup, a daemon on a control socket,
# a wait for that socket to appear, and a kill afterwards. `run_with_swtpm.sh`
# had the only copy; teaching `smoke_test.sh` to boot with a TPM was about to
# make it two, and two copies of a lifecycle is how one of them ends up leaking a
# daemon or reusing state it should have discarded.
#
# ---- SWTPM_REQUIRED, and why it is the important part ----------------------
#
# Both callers used to `exit 0` when swtpm was absent, on the reasonable ground
# that a developer without it should not be blocked. The consequence was not
# reasonable: `make smoke-tpm` printed "SKIP" and returned SUCCESS, and so did
# `smoke-tpm-seal` -- a REQUIRED merge-gating job carrying S11 and S12. Four
# security gates could report pass while measuring nothing, and the only thing
# standing between that and reality was an apt line in a workflow file that
# nothing verified.
#
# CI has in fact been installing swtpm all along -- checked, 2026-08-22, against
# a real run: the measured PCRs are in the log and they match the host-computed
# manifest. So this was latent rather than live. But "latent" here means a
# renamed package or a changed runner image turns four security gates into
# green no-ops with no signal at all, which is the same shape as every other
# can't-fail test this project has had to dig out.
#
# So: SWTPM_REQUIRED=1 makes a missing swtpm an ERROR. CI sets it. A developer
# without swtpm still gets the skip, because blocking them buys nothing.
#
# Sets, for the caller: SWTPM_SOCK, SWTPM_DIR, SWTPM_PIDFILE, SWTPM_OWN_STATE.

# Return 0 if swtpm is usable. Under SWTPM_REQUIRED=1, a missing one exits 1
# rather than returning non-zero, so no caller can accidentally treat it as a
# skip -- the failure mode this whole file exists to remove.
swtpm_available() {
    if command -v swtpm >/dev/null 2>&1 && command -v swtpm_setup >/dev/null 2>&1; then
        return 0
    fi
    if [ "${SWTPM_REQUIRED:-}" = 1 ]; then
        echo "SWTPM FAIL: swtpm/swtpm_setup not found and SWTPM_REQUIRED=1." >&2
        echo "  This gate measures a TPM; without one it would report success" >&2
        echo "  while measuring nothing. Install swtpm and swtpm-tools." >&2
        exit 1
    fi
    return 1
}

# swtpm_start [statedir]
#
# With a statedir: reuse or create persistent state there, and do NOT delete it.
# That is what a two-boot sealing test needs -- the same TPM across a reboot, so
# a secret sealed in boot 1 can be unsealed in boot 2. Without: a throwaway
# directory, removed by swtpm_stop.
# A FAILED SETUP MUST SAY SO. Both calls below discarded stdout AND stderr AND
# their exit status, so a swtpm_setup that did not produce a state file left the
# emulator to start on an empty directory -- QEMU then reports
# "tpm-emulator: TPM result for CMD_INIT: 0x9 operation failed" and the guest
# never boots, which reaches the harness as a ZERO-LENGTH SERIAL LOG. That is
# indistinguishable from a kernel hanging before its first print, and it sent one
# investigation to the wrong layer entirely (the cause was a relative --tpmstate
# path, which swtpm_setup and swtpm do not agree about).
#
# So: keep the output, and check both the status and the artifact. A setup that
# reports success without leaving a tpm2-00.permall is the same problem wearing a
# zero exit code.
_swtpm_setup_into() {
    _dir="$1"
    if ! _out="$(swtpm_setup --tpm2 --tpmstate "$_dir" --overwrite 2>&1)"; then
        echo "SWTPM FAIL: swtpm_setup failed for '$_dir'" >&2
        printf '%s\n' "$_out" >&2
        return 1
    fi
    if [ ! -f "$_dir/tpm2-00.permall" ]; then
        echo "SWTPM FAIL: swtpm_setup reported success but left no state in '$_dir'" >&2
        printf '%s\n' "$_out" >&2
        return 1
    fi
    return 0
}

swtpm_start() {
    _keep="${1:-}"
    if [ -n "$_keep" ]; then
        # ABSOLUTE, because swtpm_setup and swtpm resolve a relative --tpmstate
        # differently and the disagreement is silent.
        case "$_keep" in
            /*) : ;;
            *)  _keep="$(cd "$(dirname "$_keep")" 2>/dev/null && pwd)/$(basename "$_keep")" ;;
        esac
        SWTPM_DIR="$_keep"; mkdir -p "$SWTPM_DIR"; SWTPM_OWN_STATE=0
        # Only initialise once: re-running swtpm_setup --overwrite would discard
        # exactly the state a two-boot test is trying to carry across.
        [ -f "$SWTPM_DIR/tpm2-00.permall" ] || _swtpm_setup_into "$SWTPM_DIR" || return 1
    else
        SWTPM_DIR="$(mktemp -d)"; SWTPM_OWN_STATE=1
        _swtpm_setup_into "$SWTPM_DIR" || return 1
    fi

    SWTPM_SOCK="$SWTPM_DIR/swtpm-sock"
    SWTPM_PIDFILE="$SWTPM_DIR/swtpm.pid"

    # The canonical wiring: QEMU's emulator tpmdev connects to swtpm's --ctrl
    # unixio socket (NOT a --server socket). swtpm handles TPM2_Startup for the
    # guest firmware, which measures into PCR 0..7; the Horus kernel owns 8/9.
    rm -f "$SWTPM_SOCK"
    swtpm socket --tpm2 --tpmstate dir="$SWTPM_DIR" \
        --ctrl type=unixio,path="$SWTPM_SOCK" \
        --daemon --pid file="$SWTPM_PIDFILE"

    _i=0
    while [ ! -S "$SWTPM_SOCK" ] && [ "$_i" -lt 50 ]; do _i=$((_i + 1)); sleep 0.1; done
    if [ ! -S "$SWTPM_SOCK" ]; then
        echo "SWTPM FAIL: swtpm socket never appeared" >&2
        return 1
    fi
    return 0
}

# The QEMU arguments that attach the running swtpm. Kept beside the start so the
# socket path is named once.
swtpm_qemu_args() {
    printf -- '-chardev socket,id=chrtpm,path=%s -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0' "$SWTPM_SOCK"
}

swtpm_stop() {
    [ -n "${SWTPM_PIDFILE:-}" ] && [ -f "$SWTPM_PIDFILE" ] && \
        kill "$(cat "$SWTPM_PIDFILE")" 2>/dev/null || true
    [ "${SWTPM_OWN_STATE:-0}" = 1 ] && [ -n "${SWTPM_DIR:-}" ] && \
        rm -rf "$SWTPM_DIR" || true
}
