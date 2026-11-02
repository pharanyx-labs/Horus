#!/bin/sh
# Falsify the shared-kernel checks.
#
# tools/check_shared_kernel.py refuses an image whose hash or stamp is not the
# one this build asked for. tools/check_shared_kernel_jobs.py refuses a workflow
# that lets a default-kernel job build its own image, or that takes the hash
# from anywhere but the producing job's output. Each arm plants one of those
# and must go red for that reason. The unmutated tree must pass, and the count
# of jobs it names must not be zero: a checker that matches nothing is not a pass.
#
# Nothing here edits the kernel, and nothing is planted into the tree.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
FILE="$ROOT/tools/check_shared_kernel.py"
JOBS="$ROOT/tools/check_shared_kernel_jobs.py"
PASSES=0
FAILS=0

pass() { echo "  $1: $2"; PASSES=$((PASSES + 1)); }
fail() { echo "  $1: $2"; FAILS=$((FAILS + 1)); }

_rmtree() {
  case "${1:-}" in
    /tmp/*|/var/tmp/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}': not a temp directory" >&2
       exit 1 ;;
  esac
}

# $1 id, $2 expect (pass|fail), $3 description, $4 setup, $5 needle.
# Setup runs in a temp dir and writes args, one checker argument per line.
file_arm() {
  id=$1
  expect=$2
  desc=$3
  setup=$4
  needle=$5
  d=$(mktemp -d)
  if ! (cd "$d" && "$setup"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  set --
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    set -- "$@" "$line"
  done < "$d/args"
  out=$(python3 "$FILE" "$@" 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT: $desc"
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "caught, but not for the right reason: $desc"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "caught: $desc"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc): $desc"
      printf '%s\n' "$out" | head -8
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "passed for the wrong reason: $desc"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "passed: $desc"
    fi
  fi
  _rmtree "$d"
}

write_pair() {
  printf 'cflags\nasflags\nkernel-id\n' > stamp
  printf 'cflags\nasflags\nkernel-id\n' > expect-stamp
  printf 'kernel-bytes\n' > kernel
}

s_match() {
  write_pair
  # A sibling hash file is not authority. Wrong contents must not matter.
  printf 'not-the-authority\n' > kernel.sha256
  hash=$(sha256sum kernel | awk 'NR==1 { print $1 }')
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash "$hash" > args
}

s_stamp() {
  write_pair
  printf 'KSP_GUARD_INJECT\n' >> stamp
  hash=$(sha256sum kernel | awk 'NR==1 { print $1 }')
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash "$hash" > args
}

s_hash() {
  write_pair
  hash=$(sha256sum kernel | awk 'NR==1 { print $1 }')
  printf 'other-bytes\n' > kernel
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash "$hash" > args
}

s_missing() {
  write_pair
  rm -f kernel
  hash=$(printf 'kernel-bytes\n' | sha256sum | awk 'NR==1 { print $1 }')
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash "$hash" > args
}

s_empty() {
  write_pair
  : > kernel
  hash=$(sha256sum kernel | awk 'NR==1 { print $1 }')
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash "$hash" > args
}

s_malformed() {
  write_pair
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash 'ABCDEF' > args
}

s_empty_stamp() {
  write_pair
  : > stamp
  hash=$(sha256sum kernel | awk 'NR==1 { print $1 }')
  printf '%s\n' --kernel "$(pwd)/kernel" --stamp "$(pwd)/stamp" \
    --expect-stamp "$(pwd)/expect-stamp" --expect-hash "$hash" > args
}

echo "file checker"
file_arm F1 pass "stamp and hash match, sibling hash file ignored" s_match "shared-kernel: ok"
file_arm F2 fail "stamp carries another flag, elf hash unchanged" s_stamp "shared-kernel: stamp"
file_arm F3 fail "elf bytes changed, expected hash unchanged" s_hash "shared-kernel: hash"
file_arm F4 fail "kernel file missing" s_missing "shared-kernel: missing"
file_arm F5 fail "kernel file empty" s_empty "shared-kernel: empty"
file_arm F6 fail "expected hash is not 64 lowercase hex digits" s_malformed "shared-kernel: hash"
file_arm F7 fail "stamp file empty" s_empty_stamp "shared-kernel: empty"

snapshot() {
  d=$(mktemp -d)
  mkdir -p "$d/.github/workflows" "$d/.github/actions/shared-kernel"
  cp "$ROOT/Makefile" "$d/Makefile"
  cp "$ROOT/.github/workflows/ci.yml" "$d/.github/workflows/ci.yml"
  cp "$ROOT/.github/actions/shared-kernel/action.yml" "$d/.github/actions/shared-kernel/action.yml"
  printf '%s\n' "$d"
}

# $1 id, $2 description, $3 needle, $4 python that edits ci.yml in the temp root.
job_arm() {
  id=$1
  desc=$2
  needle=$3
  edit=$4
  d=$(snapshot)
  if ! (cd "$d" && python3 -c "$edit"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  out=$(python3 "$JOBS" --root "$d" 2>&1)
  rc=$?
  if [ "$rc" -eq 0 ]; then
    fail "$id" "NOT CAUGHT: $desc"
  elif ! printf '%s\n' "$out" | grep -q "$needle"; then
    fail "$id" "caught, but not for the right reason: $desc"
    printf '%s\n' "$out" | head -12
  else
    pass "$id" "caught: $desc"
  fi
  _rmtree "$d"
}

echo "jobs checker"
job_arm J1 "the smoke job drops the action" "shared-kernel-jobs: action" '
import pathlib, re
p = pathlib.Path(".github/workflows/ci.yml")
text = p.read_text()
key = "  smoke:\n"
start = text.index(key)
m = re.search(r"(?m)^  [A-Za-z0-9-]+:[ \t]*$", text[start + len(key):])
end = len(text) if m is None else start + len(key) + m.start()
block = text[start:end]
old = """      - name: Take the default kernel this job asked for
        uses: ./.github/actions/shared-kernel
        with:
          sha256: ${{ needs.kernel.outputs.sha256 }}
"""
if old not in block:
    raise SystemExit("action block missing")
block = block.replace(old, "", 1)
p.write_text(text[:start] + block + text[end:])
'

job_arm J2 "the smoke job takes the hash from a file" "shared-kernel-jobs: hash" '
import pathlib, re
p = pathlib.Path(".github/workflows/ci.yml")
text = p.read_text()
key = "  smoke:\n"
start = text.index(key)
m = re.search(r"(?m)^  [A-Za-z0-9-]+:[ \t]*$", text[start + len(key):])
end = len(text) if m is None else start + len(key) + m.start()
block = text[start:end]
old = "          sha256: ${{ needs.kernel.outputs.sha256 }}\n"
new = "          sha256: ${{ hashFiles('\''kernel.sha256'\'') }}\n"
if old not in block:
    raise SystemExit("sha256 line missing")
block = block.replace(old, new, 1)
p.write_text(text[:start] + block + text[end:])
'

job_arm J3 "the smoke job takes a literal hash" "shared-kernel-jobs: hash" '
import pathlib, re
p = pathlib.Path(".github/workflows/ci.yml")
text = p.read_text()
key = "  smoke:\n"
start = text.index(key)
m = re.search(r"(?m)^  [A-Za-z0-9-]+:[ \t]*$", text[start + len(key):])
end = len(text) if m is None else start + len(key) + m.start()
block = text[start:end]
old = "          sha256: ${{ needs.kernel.outputs.sha256 }}\n"
new = "          sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
if old not in block:
    raise SystemExit("sha256 line missing")
block = block.replace(old, new, 1)
p.write_text(text[:start] + block + text[end:])
'

job_arm J4 "the smoke job does not need the kernel job" "shared-kernel-jobs: needs" '
import pathlib, re
p = pathlib.Path(".github/workflows/ci.yml")
text = p.read_text()
key = "  smoke:\n"
start = text.index(key)
m = re.search(r"(?m)^  [A-Za-z0-9-]+:[ \t]*$", text[start + len(key):])
end = len(text) if m is None else start + len(key) + m.start()
block = text[start:end]
old = "    needs: kernel\n"
if old not in block:
    raise SystemExit("needs line missing")
block = block.replace(old, "", 1)
p.write_text(text[:start] + block + text[end:])
'

job_arm J5 "altconfigs takes the shared image" "shared-kernel-jobs: altconfigs" '
import pathlib, re
p = pathlib.Path(".github/workflows/ci.yml")
text = p.read_text()
key = "  altconfigs:\n"
start = text.index(key)
m = re.search(r"(?m)^  [A-Za-z0-9-]+:[ \t]*$", text[start + len(key):])
end = len(text) if m is None else start + len(key) + m.start()
block = text[start:end]
needle = "actions/checkout@"
at = block.index(needle)
nl = block.index("\n", at) + 1
insert = """      - name: Take the default kernel this job asked for
        uses: ./.github/actions/shared-kernel
        with:
          sha256: ${{ needs.kernel.outputs.sha256 }}
"""
block = block[:nl] + insert + block[nl:]
p.write_text(text[:start] + block + text[end:])
'

job_arm J6 "the refuse step is deleted" "shared-kernel-jobs: witness" '
import pathlib, re
p = pathlib.Path(".github/workflows/ci.yml")
text = p.read_text()
key = "  smoke:\n"
start = text.index(key)
m = re.search(r"(?m)^  [A-Za-z0-9-]+:[ \t]*$", text[start + len(key):])
end = len(text) if m is None else start + len(key) + m.start()
block = text[start:end]
old = """      - name: A kernel stamped for another flag is refused
        run: make smoke-shared-kernel-refuse
"""
if old not in block:
    raise SystemExit("refuse step missing")
block = block.replace(old, "", 1)
p.write_text(text[:start] + block + text[end:])
'

echo "  J7: zero consumer jobs"
d=$(mktemp -d)
mkdir -p "$d/.github/workflows" "$d/.github/actions/shared-kernel"
cp "$ROOT/.github/actions/shared-kernel/action.yml" "$d/.github/actions/shared-kernel/action.yml"
cat > "$d/Makefile" << 'EOF'
all:
	@echo hi
EOF
cat > "$d/.github/workflows/ci.yml" << 'EOF'
name: CI
on: [push]
jobs:
  kernel:
    runs-on: ubuntu-latest
    outputs:
      sha256: ${{ steps.kernel-hash.outputs.sha256 }}
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - id: kernel-hash
        run: |
          cp .build-flags kernel.build-flags
          printf '%s\n' abc > kernel.sha256
          echo "sha256=abc" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@0000000000000000000000000000000000000000
        with:
          name: horus-default-kernel
          path: |
            kernel.elf
            kernel.build-flags
            kernel.sha256
          if-no-files-found: error
      - run: make
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - run: make smoke-captest
EOF
out=$(python3 "$JOBS" --root "$d" 2>&1)
rc=$?
if [ "$rc" -eq 0 ]; then
  fail J7 "NOT CAUGHT: a workflow with no default-kernel consumer"
elif ! printf '%s\n' "$out" | grep -q "shared-kernel-jobs: none"; then
  fail J7 "caught, but not for having no consumer"
  printf '%s\n' "$out" | head -12
else
  pass J7 "caught: a workflow with no default-kernel consumer"
fi
_rmtree "$d"

echo "  J8: the unmutated tree"
out=$(python3 "$JOBS" --root "$ROOT" 2>&1)
rc=$?
count=$(printf '%s\n' "$out" | sed -n 's/^shared-kernel-jobs: ok \([0-9][0-9]*\) jobs$/\1/p')
if [ "$rc" -ne 0 ]; then
  fail J8 "the unmutated tree was refused (rc=$rc)"
  printf '%s\n' "$out" | head -20
elif [ -z "$count" ] || [ "$count" -eq 0 ]; then
  fail J8 "the unmutated tree did not name a non-zero job count"
  printf '%s\n' "$out" | head -20
else
  pass J8 "the unmutated tree, $count jobs"
fi

echo
echo "$PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
