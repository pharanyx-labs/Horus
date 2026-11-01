#!/bin/sh
# cppcheck of the ship configuration. The status is the tool's own.
#
# Measured on 2026-11-01 against cppcheck 2.17.1, --max-configs=1, the
# kernel and userspace/init.c, fs_server.c, console_server.c:
# two subtractPointers hits, both a linker image bracketed by two extern
# symbols in kshell.c, suppressed at those lines with the reason. The
# nullPointer in console_server.c and the unknownMacro on HORUS_DEBUG_LABEL
# are inside configurations the ship build does not compile, and
# --max-configs=1 does not report them. A planted null dereference must
# still fail. There is no blanket suppression of that check.
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
# was told. It is not a finding. uninitvar is not suppressed: the two
# false positives in loader.c are silenced at the call, with the reason.
cppcheck --error-exitcode=1 --quiet --max-configs=1 --inline-suppr \
  --suppress=missingIncludeSystem \
  --suppress=normalCheckLevelMaxBranches \
  --suppress=toomanyconfigs \
  "$@"
