#!/bin/sh
# cppcheck of the ship configuration. The status is the tool's own.
#
# Measured on 2026-11-02 against two builds of the same tree:
# cppcheck 2.17.1, and 2.13.0, which is what Ubuntu 24.04 CI installs.
# The linker brackets in kshell.c are an integer distance, not a pointer
# subtraction: 2.13 calls that finding comparePointers and 2.17 calls it
# subtractPointers, so an inline suppression of either id is red on the
# other version. A planted subtraction of two different objects must still
# fail. There is no blanket suppression of that check. The nullPointer in
# console_server.c and the unknownMacro on HORUS_DEBUG_LABEL are inside
# configurations the ship build does not compile, and --max-configs=1
# does not report them. A planted null dereference must still fail.
#
# A missing cppcheck is a failure, not a clean scan.
set -eu
if ! command -v cppcheck >/dev/null 2>&1; then
  echo "cppcheck is NOT INSTALLED -- that is a broken scan, not a clean one" >&2
  exit 2
fi
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ "$#" -eq 0 ]; then
  set -- src include userspace/init.c userspace/fs_server.c userspace/console_server.c
fi
cd "$ROOT"
# toomanyconfigs is cppcheck reporting that --max-configs=1 did what it
# was told. It is not a finding. uninitvar is not suppressed: loader.c
# zeroes the segment arrays before a count of zero can pass them on.
cppcheck --error-exitcode=1 --quiet --max-configs=1 --inline-suppr \
  --suppress=missingIncludeSystem \
  --suppress=normalCheckLevelMaxBranches \
  --suppress=toomanyconfigs \
  "$@"
