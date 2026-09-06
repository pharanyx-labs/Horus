#!/usr/bin/env bash
# Falsify every rule of tools/check_abi_headers.py.
#
# A CHECKER'S FIRST RUN IS AGAINST A TREE SOMEBODY JUST FIXED, so it passes, and
# passing proves nothing about whether it can fail. This mutates the userspace
# header once per rule and requires the checker to catch each one -- plus one arm
# asserting the UNMUTATED tree passes, because three "is it caught" arms are all
# satisfied by a checker that rejects everything.
#
# The header is restored from a backup rather than with `git checkout`: that would
# discard unrelated uncommitted work in the same file.
set -uo pipefail
cd "$(dirname "$0")/.."

USER_H=include/syscall.h
BAK="$(mktemp)"
cp "$USER_H" "$BAK"
restore() { cp "$BAK" "$USER_H"; }
trap 'restore; rm -f "$BAK"' EXIT

fails=0

expect_fail() {
    local what="$1" needle="$2"
    # THE OUTPUT IS CAPTURED BEFORE IT IS SEARCHED, and that is not style. Under
    # `set -o pipefail` a pipeline reports the failure of ANY stage, and the
    # checker exits 1 on purpose here -- so `checker | grep -q` is non-zero even
    # when grep matched, and every arm scored itself a miss while the checker was
    # working perfectly. Three rules "could not fail" for a reason that had
    # nothing to do with the rules.
    local out
    out="$(python3 tools/check_abi_headers.py 2>&1 || true)"
    if printf '%s' "$out" | grep -q -- "$needle"; then
        echo "  ok   - $what"
    else
        echo "  FAIL - $what (the checker did not catch it)"
        fails=$((fails + 1))
    fi
    restore
}

echo "falsifying tools/check_abi_headers.py:"

# Rule 1: a syscall number that disagrees.
sed -i 's/^#define SYS_STORAGE_DEVICE   113/#define SYS_STORAGE_DEVICE   119/' "$USER_H"
expect_fail "rule 1: a syscall number that disagrees" "is 113 in kernel.h and 119 in syscall.h"

# Rule 2: a struct field on one side only. THE SILENT ONE: both headers compile,
# and copy_to_user writes the kernel's sizeof into the caller's smaller buffer.
python3 - <<'PY'
import pathlib
p = pathlib.Path("include/syscall.h"); s = p.read_text()
s = s.replace("    uint32_t device_index;\n};", "    uint32_t device_index;\n    uint32_t sneaked_in;\n};", 1)
p.write_text(s)
PY
expect_fail "rule 2: a struct field on one side only" "struct storage_info differs"

# Rule 3: a shared constant that moved. Rule 2 cannot see this one -- the field
# text is identical on both sides and the layout is not.
sed -i 's/^#define IODEV_MAX_MMIO      8/#define IODEV_MAX_MMIO      16/' "$USER_H"
expect_fail "rule 3: a shared constant that moved" "IODEV_MAX_MMIO is 8 in kernel.h and 16 in syscall.h"

# And the direction the three above cannot establish.
if python3 tools/check_abi_headers.py >/dev/null 2>&1; then
    echo "  ok   - an unmutated tree PASSES"
else
    echo "  FAIL - an unmutated tree does not pass"
    fails=$((fails + 1))
fi

if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails of the checker's rules could not fail"
    exit 1
fi
echo "PASS: every rule of check_abi_headers.py catches its own defect"
