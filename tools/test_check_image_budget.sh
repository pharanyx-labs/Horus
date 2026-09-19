#!/usr/bin/env bash
# Falsify tools/check_image_budget.py: one arm per rule, both directions of the
# exact budget, the silent direction, and every input the checker must refuse to
# do without.
#
# THE ELF IS A FIXTURE, AND THAT IS SAFE HERE, unlike for the ring-0 harness. This
# checker reads three symbol VALUES and nothing else, so an object file holding
# exactly those symbols (absolute, via `.set`) is the whole of its ELF input, and
# no arm needs a kernel build. The TREE is real: the budget file, linker64.ld and
# kernel.h are mutated in place and restored on exit, because R2 is a relation
# between the real files.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILES=(.github/image-budget.yml linker64.ld src/include/kernel.h)
WORK="$(mktemp -d)"
for f in "${FILES[@]}"; do mkdir -p "$WORK/bak/$(dirname "$f")"; cp "$ROOT/$f" "$WORK/bak/$f"; done
restore () { for f in "${FILES[@]}"; do cp "$WORK/bak/$f" "$ROOT/$f"; done; }
trap 'restore; rm -rf "$WORK"' EXIT
PASSES=0; FAILS=0

VMA=0xffffffff80000000
BUDGET=$(sed -n 's/^bss_bytes:[[:space:]]*\([0-9]*\)[[:space:]]*$/\1/p' "$ROOT/.github/image-budget.yml")
[ -n "$BUDGET" ] || { echo "cannot read bss_bytes from the budget file"; exit 1; }

# mkelf <out> <bss_start_offset> <bss_bytes> [omit-symbol]
mkelf () {
  local out="$1" start=$(( VMA + $2 )) size="$3" omit="${4:-}" src=""
  for pair in "__bss_start:$start" "__bss_end:$(( start + size ))" "__kernel_vma_from_linker:$(( VMA ))"; do
    local name="${pair%%:*}" val="${pair#*:}"
    [ "$name" = "$omit" ] && continue
    src+=$(printf '.globl %s\n.set %s, 0x%x\n' "$name" "$name" "$(( val & 0xFFFFFFFFFFFFFFFF ))")
    src+=$'\n'
  done
  printf '%s' "$src" | as --64 -o "$out" - || { echo "as failed building a fixture"; exit 1; }
}

arm () {  # $1 rule, $2 desc, $3 mutation (eval'd in ROOT), $4 elf, $5 expect(caught|clean), $6 must-name
  local rule="$1" desc="$2" mut="$3" elf="$4" expect="$5" want="${6:-}" out rc
  restore
  ( cd "$ROOT" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); restore; return; }
  out="$(cd "$ROOT" && python3 tools/check_image_budget.py "$elf" 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -ne 1 ]; then echo "  $rule: NOT CAUGHT (rc=$rc): $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF -- "$want" <<<"$out"; then
      echo "  $rule: caught but did not name '$want': $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught: $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT: $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly: $desc"; PASSES=$((PASSES+1)); fi
  fi
  restore
}

# The image the budget describes: .bss at the offset the real kernel uses.
mkelf "$WORK/exact.o"   0x1d1000 "$BUDGET"
mkelf "$WORK/over.o"    0x1d1000 $(( BUDGET + 4096 ))
mkelf "$WORK/under.o"   0x1d1000 $(( BUDGET - 4096 ))
# .bss exactly on budget, but starting so late that the image crosses 16 MiB:
# R3 must catch what R1 cannot see.
mkelf "$WORK/past.o"    $(( 0x1000000 - BUDGET + 4096 )) "$BUDGET"
mkelf "$WORK/nostart.o" 0x1d1000 "$BUDGET" __bss_start

echo "Falsifying tools/check_image_budget.py:"

# ---- THE SILENT DIRECTION. An image exactly on budget, below the pool, in the
#      real tree, must pass; a checker that flags it would be turned off.
arm "S"  "an image exactly on budget, ending below USER_PHYS_BASE" ":" "$WORK/exact.o" clean

# ---- R1, both directions of an exact budget.
arm "R1a" ".bss one page over its budget" ":" "$WORK/over.o" caught "over its budget"
arm "R1b" ".bss one page under its budget (slack must be banked)" ":" "$WORK/under.o" caught "under its budget"

# ---- R2, from each side: the linker's literal and the header's define.
arm "R2a" "linker64.ld's ASSERT raised to 0x2000000, kernel.h left alone" \
    "sed -i 's/^\(\s*ASSERT(__bss_end - KERNEL_VMA <= \)0x1000000,/\10x2000000,/' linker64.ld" \
    "$WORK/exact.o" caught "R2:"
arm "R2b" "USER_PHYS_BASE raised to 0x02000000, linker64.ld left alone" \
    "sed -i 's/^\(#define USER_PHYS_BASE[[:space:]]*\)0x01000000/\10x02000000/' src/include/kernel.h" \
    "$WORK/exact.o" caught "R2:"

# ---- R3, the ASSERT's own condition, checked from the ELF.
arm "R3" ".bss on budget but the image ends past USER_PHYS_BASE" ":" "$WORK/past.o" caught "R3:"

# ---- Fail closed on every input. Each of these used to be a way for a checker
#      like this one to pass by reading nothing.
arm "F1" "an ELF that defines no __bss_start" ":" "$WORK/nostart.o" caught "defines no __bss_start"
arm "F2" "an ELF that does not exist" ":" "$WORK/absent.o" caught "nm could not read"
arm "F3" "linker64.ld without the .bss ASSERT" \
    "sed -i '/^\s*ASSERT(__bss_end - KERNEL_VMA <= /d' linker64.ld" \
    "$WORK/exact.o" caught "could not find the"
arm "F4" "a budget file without bss_bytes" \
    "sed -i 's/^bss_bytes:/bss_budget:/' .github/image-budget.yml" \
    "$WORK/exact.o" caught "could not find bss_bytes"
arm "F5" "kernel.h without USER_PHYS_BASE" \
    "sed -i 's/^#define USER_PHYS_BASE\b/#define USER_PHYS_BASE_RENAMED/' src/include/kernel.h" \
    "$WORK/exact.o" caught "could not find #define USER_PHYS_BASE"

echo
echo "arms passed: $PASSES, failed: $FAILS"
[ "$FAILS" -eq 0 ]
