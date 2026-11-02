#!/bin/sh
# Falsify tools/check_ct_compare.py. One arm per way the compare check can lie.
#
# The mutations are applied to a copy. Nothing here touches the working tree.
set -u
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
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

mktree() {
  mkdir -p "$1/src/kernel" "$1/rust/src" "$1/tools"
  cp "$ROOT/src/kernel/kusers.c" "$1/src/kernel/"
  cp "$ROOT/rust/src/lib.rs" "$ROOT/rust/src/aead.rs" "$1/rust/src/"
  cp "$ROOT/tools/check_ct_compare.py" "$1/tools/"
}

# $1 id, $2 expect (fail|pass), $3 description, $4 mutation, $5 needle
arm() {
  id=$1
  expect=$2
  desc=$3
  mut=$4
  needle=$5
  d=$(mktemp -d)
  mktree "$d"
  if ! (cd "$d" && eval "$mut"); then
    fail "$id" "MUTATION FAILED ($desc)"
    _rmtree "$d"
    return
  fi
  out=$(cd "$d" && python3 tools/check_ct_compare.py 2>&1)
  rc=$?
  if [ "$expect" = fail ]; then
    if [ "$rc" -eq 0 ]; then
      fail "$id" "NOT CAUGHT ($desc)"
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "caught, but not as $needle ($desc)"
      printf '%s\n' "$out" | head -8
    else
      pass "$id" "caught ($desc)"
    fi
  else
    if [ "$rc" -ne 0 ]; then
      fail "$id" "WRONGLY CAUGHT (rc=$rc) ($desc)"
      printf '%s\n' "$out" | head -8
    elif ! printf '%s\n' "$out" | grep -q "$needle"; then
      fail "$id" "passed without $needle ($desc)"
    else
      pass "$id" "passed ($desc)"
    fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_ct_compare.py:"

arm U pass "the unmutated copy" "true" "ct-compare: ok"

arm C1 pass "a comment that mentions memcmp is not a compare" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = 'static int verify_user_password(const char *name, const char *password) {\n'
new = old + '    /* memcmp would time the hash. This comment must not. */\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "ct-compare: ok"

arm N1 pass "strcmp on the username is not the hash compare" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = '''static int verify_user_password(const char *name, const char *password) {
    struct user_account *u = NULL;
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].valid) {
            int match = 1;
            for (size_t j = 0; j < 32 && name[j]; j++) {
                if (users[i].name[j] != name[j]) { match = 0; break; }
'''
new = old + '                strcmp(users[i].name, name);\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "ct-compare: ok"

arm P1 fail "memcmp replaces rust_ct_eq on the hash" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = 'rust_ct_eq(computed, expect, PASS_HASH_LEN)'
new = 'memcmp(computed, expect, PASS_HASH_LEN)'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "password path: memcmp is a variable-time compare"

arm P2 fail "the hash compare returns on the first differing byte" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = 'int eq = rust_ct_eq(computed, expect, PASS_HASH_LEN);'
new = '''int eq = 1;
    for (size_t k = 0; k < PASS_HASH_LEN; k++) {
        if (computed[k] != expect[k]) { eq = 0; break; }
    }'''
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "password path: indexed hash compare"

arm P3 fail "memcmp sits beside rust_ct_eq" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = 'int eq = rust_ct_eq(computed, expect, PASS_HASH_LEN);'
new = 'memcmp(computed, expect, PASS_HASH_LEN);\n    int eq = rust_ct_eq(computed, expect, PASS_HASH_LEN);'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "password path: memcmp is a variable-time compare"

arm L1 fail "rust_ct_eq compares fewer bytes than the hash" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = 'rust_ct_eq(computed, expect, PASS_HASH_LEN)'
new = 'rust_ct_eq(computed, expect, 4)'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "password path: rust_ct_eq arguments are not the hash and PASS_HASH_LEN"

arm R1 fail "rust_ct_eq returns on the first differing byte" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/lib.rs')
t = p.read_text()
old = '''    for i in 0..len {
        diff |= sa[i] ^ sb[i];
    }'''
new = '''    for i in 0..len {
        if sa[i] != sb[i] {
            return 0;
        }
    }'''
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "rust_ct_eq: returns early"

arm R2 fail "rust_ct_eq stops after the first byte" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/lib.rs')
t = p.read_text()
old = 'for i in 0..len {'
new = 'for i in 0..1 {'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "rust_ct_eq: not an xor accumulate over the whole input"

arm A1 fail "tags_equal is a slice equality" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/aead.rs')
t = p.read_text()
old = '''fn tags_equal(a: &[u8; AEAD_TAG_LEN], b: &[u8; AEAD_TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..AEAD_TAG_LEN {
        diff |= a[i] ^ b[i];
    }
    // Keep the accumulator opaque so the compiler can't reintroduce a branch.
    core::hint::black_box(diff) == 0
}'''
new = '''fn tags_equal(a: &[u8; AEAD_TAG_LEN], b: &[u8; AEAD_TAG_LEN]) -> bool {
    a == b
}'''
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "tags_equal: slice equality"

arm A2 fail "tags_equal returns on the first differing byte" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/aead.rs')
t = p.read_text()
old = '''    for i in 0..AEAD_TAG_LEN {
        diff |= a[i] ^ b[i];
    }'''
new = '''    for i in 0..AEAD_TAG_LEN {
        if a[i] != b[i] {
            return false;
        }
        diff |= a[i] ^ b[i];
    }'''
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "tags_equal: returns early"

arm A3 fail "open compares the tag with ==" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/aead.rs')
t = p.read_text()
old = 'if !tags_equal(&expect, tag) {'
new = 'if expect == *tag {'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "open: does not call tags_equal"

arm A4 fail "rust_aead_open compares the tag with ==" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/aead.rs')
t = p.read_text()
old = 'if open(&ek, &mk, &nc, aad_s, buf_s, &tg) {'
new = 'if tg == ek { return -1; }\n    if open(&ek, &mk, &nc, aad_s, buf_s, &tg) {'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "rust_aead_open: compares the tag in variable time"

arm B1 fail "tags_equal drops black_box" "python3 - <<'PY'
from pathlib import Path
p = Path('rust/src/aead.rs')
t = p.read_text()
old = 'core::hint::black_box(diff) == 0'
new = 'diff == 0'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "tags_equal: black_box does not cover the accumulator"

arm M1 fail "verify_user_password is gone" "python3 - <<'PY'
from pathlib import Path
p = Path('src/kernel/kusers.c')
t = p.read_text()
old = 'static int verify_user_password('
new = 'static int verify_user_password_gone('
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, new, 1))
PY" "verify_user_password: not found"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "ct-compare harness: $PASSES passed"
else
  echo "ct-compare harness: $PASSES passed, $FAILS failed"
  exit 1
fi
