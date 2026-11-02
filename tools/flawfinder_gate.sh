#!/bin/sh
# flawfinder at the level it documents for a continuous-integration gate.
#
# Measured on 2026-11-01 against flawfinder 2.0.19, the kernel, include/,
# and userspace/init.c, fs_server.c, console_server.c: 144 hits at level 2,
# none at level 4 or 5. --error-level=4 is the bar the tool's own help
# asks a CI script to use. The status used to be discarded by `head` and
# `|| true`. A planted gets() is level 5 and must fail. A file with no hit
# at level 4 or above must pass, so a scanner that rejects every input is
# not good enough.
#
# A missing flawfinder is a failure, not a clean scan.
set -eu
if ! command -v flawfinder >/dev/null 2>&1; then
  echo "flawfinder is NOT INSTALLED -- that is a broken scan, not a clean one" >&2
  exit 2
fi
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ "$#" -eq 0 ]; then
  set -- src include userspace/init.c userspace/fs_server.c userspace/console_server.c
fi
cd "$ROOT"
flawfinder --error-level=4 --quiet "$@"
