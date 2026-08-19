#!/bin/sh
# Record the SHA-256 of every artifact a reproducible build must cover.
#
# This is a script rather than a line in the Makefile because the line it
# replaced could not fail:
#
#     sha256sum kernel.elf boot.iso > .build.sha 2>/dev/null || true
#
# Three separate mechanisms had to line up for that to be silent, and all three
# did. `reproducible-build` deletes boot.iso and then builds `all`, which is
# `all: kernel.elf` -- so boot.iso was never rebuilt. sha256sum therefore exited
# 1 on a missing operand, `2>/dev/null` discarded the message naming it, and
# `|| true` discarded the status. The target printed "Reproducible build
# recorded." over a .build.sha that had only ever held one line, for as long as
# the target has existed. The artifact a third party actually obtains -- the
# ISO -- was the one the supply-chain control did not cover.
#
# Fail closed, in both senses:
#
#   - a missing or unhashable artifact is an error, never a shorter file. The
#     caller names what the build must cover; this script does not get to
#     decide that a subset will do.
#   - .build.sha is written by rename from a temporary, and the previous one is
#     removed first, so a failed run leaves no file rather than a plausible
#     partial. A partial record is worse than none: nothing distinguishes it
#     from a complete record of a smaller build, which is exactly the reading
#     that let the old behaviour survive.
#
# Witness: `make smoke-repro-sha` (both directions), falsified by
# `make smoke-repro-sha-control` (REPRO_SHA_UNCHECKED=1). See TESTS.md.
set -eu

if [ "$#" -eq 0 ]; then
    echo "record_build_sha.sh: no artifacts named; refusing to record nothing" >&2
    exit 2
fi

out=${BUILD_SHA_FILE:-.build.sha}
tmp="${out}.tmp.$$"

# The record must describe THIS build. A stale file surviving a failed run is
# the same defect in a different costume.
rm -f "$out"

trap 'rm -f "$tmp"' EXIT INT TERM

# No 2>/dev/null. If sha256sum has something to say about a missing artifact,
# that message is the entire point of this script.
sha256sum "$@" > "$tmp"
mv "$tmp" "$out"
