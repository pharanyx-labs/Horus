#!/usr/bin/env bash
# Falsify tools/check_shared_object.py -- one arm per rule, plus the silent
# direction.
#
# WHY THIS CHECKER EXISTS AT ALL: shlib_init refuses an object it cannot fully
# relocate, and a refusal at boot is correct behaviour with a terrible
# diagnostic. The library is simply not there, and the first symptom is a task
# faulting on a call into an address nothing mapped. These properties are
# decidable by reading the object, so they are decided before it ships.
#
# THE FIXTURES ARE REAL SHARED OBJECTS, built here with the host toolchain. They
# have to be: the checker shells out to readelf and nm, so a synthetic text file
# would test nothing. Each arm builds the smallest object that breaks one rule.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK="$ROOT/tools/check_shared_object.py"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

for t in gcc readelf nm; do
  command -v "$t" >/dev/null 2>&1 || { echo "SKIP: $t not found"; exit 0; }
done

arm () {  # $1 rule, $2 desc, $3 builder(writes lib.so in $d), $4 expect, $5 must-say
  local rule="$1" desc="$2" build="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  cp "$ROOT/userspace/shlib.ld" "$d/" 2>/dev/null || true
  if ! ( cd "$d" && eval "$build" ) >/dev/null 2>&1; then
    echo "  $rule: FIXTURE FAILED -- $desc"; FAILS=$((FAILS+1)); _rmtree "$d"; return
  fi
  out="$(python3 "$CHECK" "$d/lib.so" 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not say $want -- $desc"; grep -E "^ " <<<"$out" | head -2 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep -E "^ " <<<"$out" | head -3 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_shared_object.py:"

# ---- THE SILENT DIRECTION. An object the loader would accept: self-contained,
#      -Bsymbolic so intra-object calls do not go through the PLT, and nothing
#      undefined for the kernel to fail to resolve by name.
GOOD='printf "int v = 7;\nint get(void){return v;}\nint call(void){return get();}\n" > a.c
      gcc -shared -fPIC -m64 -ffreestanding -nostdlib -fno-stack-protector -fno-plt -fvisibility=hidden -Wl,--build-id=none -Wl,-T,shlib.ld -O2 -o lib.so a.c'
arm "1" "an object the loader accepts" "$GOOD" clean

# ---- RULE 2: undefined symbols. The kernel resolves NOTHING by name, so there
#      is no later at which these could be satisfied -- the object is simply
#      unloadable, and the fault happens on the first call into it.
arm "2" "an object with an undefined symbol" \
    'printf "extern int somewhere_else(void);\nint call(void){return somewhere_else();}\n" > a.c
     gcc -shared -fPIC -m64 -ffreestanding -nostdlib -fno-stack-protector -fno-plt -fvisibility=hidden -Wl,--build-id=none -Wl,-T,shlib.ld -O2 -o lib.so a.c' \
    caught "undefined symbol"

# ---- RULE 1: a relocation type shlib_init does not implement. Anything but
#      R_X86_64_RELATIVE fails the load, and the whole object is refused rather
#      than the one symbol -- which is why this is worth catching statically.
#
#      IT ASSERTS THE RELOCATION MESSAGE SPECIFICALLY, and that is not pedantry.
#      The smallest object that produces an R_X86_64_64 also has an undefined
#      symbol, so this arm trips rule 2 as well -- and would still report
#      "caught" with the relocation rule deleted entirely. Naming the message is
#      what makes it a test of the rule it claims to test.
arm "3" "a relocation type other than R_X86_64_RELATIVE" \
    'printf "extern int elsewhere(void);\nint (*fp)(void) = elsewhere;\nint call(void){return fp();}\n" > a.c
     gcc -shared -fPIC -m64 -ffreestanding -nostdlib -fno-stack-protector -fno-plt -fvisibility=hidden -Wl,--build-id=none -Wl,-T,shlib.ld -O2 -o lib.so a.c' \
    caught "R_X86_64_64"

# ---- RULE 3: the page budget. shlib_init refuses an object bigger than
#      SHLIB_MAX_PAGES, so an object that grew past it is a library that silently
#      stops being there.
arm "4" "an object larger than the page budget" \
    'printf "int v = 1;\nchar big[900000] = {1};\nint get(void){return v + big[0];}\n" > a.c
     gcc -shared -fPIC -m64 -ffreestanding -nostdlib -fno-stack-protector -fno-plt -fvisibility=hidden -Wl,--build-id=none -Wl,-T,shlib.ld -O2 -o lib.so a.c' \
    caught "SHLIB_MAX_PAGES"

# ---- THE ARGUMENT GUARD. Called with no object at all it must not report
#      success on having examined nothing.
printf '  5: '
if python3 "$CHECK" >/dev/null 2>&1; then
  echo "NOT CAUGHT -- no object named"; FAILS=$((FAILS+1))
else
  echo "caught -- no object named"; PASSES=$((PASSES+1))
fi

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
