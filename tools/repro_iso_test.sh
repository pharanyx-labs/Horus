#!/bin/bash
# The ISO a release ships is the same bytes whoever builds it, wherever and
# whenever (LIMITATIONS 5.3a, SECURITY.md S17). Run from the repository root.
#
# Builds twice and compares:
#   A  this tree, serially (MAKEFLAGS cleared), first;
#   B  a copy of the tracked files at a different and longer path, with the
#      caller's MAKEFLAGS (CI's -j4), at least two seconds later.
# Two directories catch a build path leaking into an artifact; two times catch a
# clock; serial against parallel catches a Makefile race that changes an
# output. All three have happened: the libc carried its build directory, the EFI
# boot image a serial made from the clock (both 2026-10-12), and the race is why
# the `reproducible` job always built once serially and once in parallel.
#
# REPRO_ISO_ARTIFACTS picks what is compared:
#   full     kernel.elf and horus.iso from `make reproducible-build` (the gates'
#            image), then install.iso from `make install.iso` (the release's)
#   install  install.iso only; the control arms use it, since both leaks reach
#            the release image and building the other twice proves nothing more
#
# On a difference it says which artifact, lists the files inside the ISOs that
# differ (osirrox, when installed), and KEEPS both copies of every artifact under
# .repro-iso/ for whoever has to read them. It never deletes evidence of a
# failure; it deletes only the second tree, which is a copy of tracked files.
set -euo pipefail

MODE=${REPRO_ISO_ARTIFACTS:-full}
case "$MODE" in full|install) ;; *) echo "REPRO ISO: FAIL unknown REPRO_ISO_ARTIFACTS '$MODE'"; exit 2;; esac

ROOT=$(pwd)
[ -f "$ROOT/Makefile" ] && [ -d "$ROOT/.git" -o -f "$ROOT/.git" ] || {
    echo "REPRO ISO: FAIL run me from the repository root"; exit 2; }
EVID=$ROOT/.repro-iso
rm -rf "$EVID"; mkdir -p "$EVID/a" "$EVID/b"

# The second tree's path is deliberately a different LENGTH as well as a
# different name: a leaked path that is padded or truncated to a fixed width
# would hide behind two paths of equal length.
B=$(mktemp -u "${TMPDIR:-/tmp}/horus-repro-second-tree-XXXXXXXX")
cleanup() { git -C "$ROOT" worktree remove --force "$B" >/dev/null 2>&1 || rm -rf "$B"; }
trap cleanup EXIT

build() {   # $1 = tree, $2 = evidence dir, $3 = MAKEFLAGS for this tree
    local tree=$1 out=$2 mf=$3
    (
        cd "$tree"
        export MAKEFLAGS="$mf"
        if [ "$MODE" = full ]; then
            make --no-print-directory reproducible-build
            cp kernel.elf horus.iso "$out/"
        fi
        make --no-print-directory install.iso
        cp install.iso "$out/"
    )
}

echo "REPRO ISO: tree A $ROOT (serial)"
build "$ROOT" "$EVID/a" ""

# A git worktree of the same commit, with the working tree's uncommitted changes
# applied, so a local edit is tested rather than the last commit. It has to be a
# checkout: the source offer the install media carries names the commit, and a
# plain copy of the files reads "commit unknown" (the first run of this gate,
# 2026-10-12, failed on exactly that). Anyone rebuilding a release does so from a
# checkout of its tag. newlib's tarball is copied when present: it is pinned by
# hash (tools/build_newlib.sh verifies it again) and fetching it a second time
# tests the network, not the build.
git -C "$ROOT" worktree add --quiet --detach "$B" HEAD
( cd "$ROOT" && git diff HEAD --binary ) | ( cd "$B" && git apply --allow-empty )
( cd "$ROOT" && git ls-files -z --others --exclude-standard ) \
    | ( cd "$ROOT" && xargs -0 -r cp --parents -t "$B" )
if ls "$ROOT"/newlib/newlib-*.tar.gz >/dev/null 2>&1; then
    mkdir -p "$B/newlib" && cp "$ROOT"/newlib/newlib-*.tar.gz "$B/newlib/"
fi
sleep 2
echo "REPRO ISO: tree B $B (MAKEFLAGS='${MAKEFLAGS:-}')"
build "$B" "$EVID/b" "${MAKEFLAGS:-}"

if [ "$MODE" = full ]; then ARTS="kernel.elf horus.iso install.iso"; else ARTS="install.iso"; fi
fail=0
for a in $ARTS; do
    ha=$(sha256sum "$EVID/a/$a" | cut -d' ' -f1)
    hb=$(sha256sum "$EVID/b/$a" | cut -d' ' -f1)
    if [ "$ha" = "$hb" ]; then
        echo "REPRO ISO: $a identical, sha256 $ha"
        continue
    fi
    fail=1
    echo "REPRO ISO: FAIL $a differs between the two trees"
    echo "  A $ha"
    echo "  B $hb"
    case "$a" in *.iso)
        if command -v osirrox >/dev/null 2>&1; then
            for t in a b; do
                mkdir -p "$EVID/$t/${a%.iso}"
                osirrox -indev "$EVID/$t/$a" -extract / "$EVID/$t/${a%.iso}" >/dev/null 2>&1 || true
                chmod -R u+w "$EVID/$t/${a%.iso}"
            done
            diff <(cd "$EVID/a/${a%.iso}" && find . -type f | sort | xargs sha256sum) \
                 <(cd "$EVID/b/${a%.iso}" && find . -type f | sort | xargs sha256sum) \
                | awk '/^</ {print "  differs inside " a ": " $3}' a="$a" || true
        else
            echo "  (osirrox is not installed, so the files inside are not compared)"
        fi
    esac
done

if [ "$fail" -ne 0 ]; then
    echo "REPRO ISO: FAIL -- both copies of every artifact are kept in $EVID"
    exit 1
fi
echo "REPRO ISO: PASS $ARTS are the same bytes from two directories, two times, serial and parallel"
