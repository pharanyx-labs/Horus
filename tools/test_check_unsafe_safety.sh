#!/usr/bin/env bash
# Falsify tools/check_unsafe_safety.py -- one arm per thing it claims to do.
#
# A checker is a predicate, and a predicate nobody has seen REJECT anything is
# indistinguishable from `return 0`. This repository has been bitten by that
# exactly: of the first three rules in an earlier checker, two silently could not
# fail. This one is especially easy to get wrong in the passing direction,
# because it went green on its first run against a tree that had just been fixed
# by hand -- so the interesting question is not whether it passes but whether it
# CAN fail, and on the right line.
#
# Four arms:
#   A1  an undocumented `unsafe` in production is caught, and named
#   A2  the same `unsafe` inside a test module is IGNORED, because a test that
#       constructs a malformed cspace exercises the boundary rather than crossing
#       it, and requiring a clause there would train people to paste one
#   A3  an item cannot inherit its NEIGHBOUR's clause -- the defect the first
#       version of the checker had, found by arm A1 failing on its first run
#   A4  an `unsafe { }` block is reported when its ENCLOSING item loses its
#       clause, since that is where a block's obligation is discharged
#
# Mutations are applied to a COPY. Nothing here touches the working tree -- a
# checker's own test must not be able to leave the repository modified, least of
# all one that runs in CI. (Learned the hard way on 2026-08-29, when a
# `git checkout` used to undo a test edit silently reverted an unrelated fix in
# the same file.)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {           # $1 = scratch dir
  mkdir -p "$1/tools" "$1/rust/src"
  cp "$ROOT/tools/check_unsafe_safety.py" "$1/tools/"
  cp "$ROOT"/rust/src/*.rs "$1/rust/src/"
  return 0
}

# $1 = arm, $2 = description, $3 = mutation, $4 = expect ("caught"|"ignored"),
# $5 = substring the report must name when expecting "caught"
arm () {
  local name="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d"
  ( cd "$d" && eval "$mut" ) || { echo "  $name: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); rm -rf "$d"; return; }
  out="$(cd "$d" && python3 tools/check_unsafe_safety.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then
      echo "  $name: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $name: caught, but did not name $want -- $desc"
      grep '^  - ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else
      echo "  $name: caught -- $desc"; PASSES=$((PASSES+1))
    fi
  else
    if [ $rc -ne 0 ]; then
      echo "  $name: WRONGLY CAUGHT -- $desc"
      grep '^  - ' <<<"$out" | head -3; FAILS=$((FAILS+1))
    else
      echo "  $name: ignored, correctly -- $desc"; PASSES=$((PASSES+1))
    fi
  fi
  rm -rf "$d"
}

echo "Falsifying tools/check_unsafe_safety.py:"

# A1. The whole point. An FFI function that states no obligation must be named,
# with its file and line, or the report is not actionable.
#
# NOTE the mutation INSERTS rather than appends. Every one of these files ends
# with its `#[cfg(test)] mod tests`, so `>>` lands inside the test module and the
# checker ignores it -- correctly. The first version of this arm did exactly that
# and reported NOT CAUGHT, which was the harness testing itself rather than the
# checker. Worth keeping as a comment: an arm that appends to a file whose tail
# is exempt measures nothing.
arm A1 "an undocumented production unsafe is caught and named" \
  "python3 - <<'P'
p='rust/src/memory.rs'
s=open(p).read()
a='#[cfg(test)]'
assert s.count(a)==1
s=s.replace(a, 'pub unsafe extern \"C\" fn planted_ffi(q: *const u32) -> u32 { *q }\n\n'+a, 1)
open(p,'w').write(s)
P" \
  caught "planted_ffi"

# A2. The exemption. Test code crosses this boundary deliberately and constantly;
# requiring a clause there would produce ritual, not thought.
arm A2 "an undocumented unsafe inside a test module is ignored" \
  "printf '\n#[cfg(test)]\nmod planted_tests {\n    fn t() { unsafe { core::ptr::read(core::ptr::null::<u8>()) }; }\n}\n' >> rust/src/memory.rs" \
  ignored

# A3. The inheritance case, and the reason this harness exists at all.
#
# The first version of the checker looked back a fixed 30 lines. Under it, an
# undocumented function placed just below a documented one INHERITED its
# neighbour's clause and passed -- which is how arm A1 above failed on its first
# run, and why the rule became "walk up to the enclosing item" instead. This arm
# keeps that fixed: it removes ONE function's clause and leaves its neighbours
# intact, so a checker that ever drifts back to a line-window will read the
# neighbour's clause as this item's and go green here.
arm A3 "an item cannot inherit its neighbour's # Safety clause" \
  "awk 'BEGIN{d=0} {if(!d && \$0 ~ /\\/\\/\\/ # Safety/){sub(/# Safety/,"NOTE"); d=1} print}' rust/src/memory.rs > .m && mv .m rust/src/memory.rs" \
  caught "rust_page_refcounts_register"

# A4. The block case. An `unsafe { }` inside a function body is satisfied by the
# ENCLOSING item's clause, because the obligation is discharged by the
# surrounding code rather than by a caller: with_rng's block is sound because
# RNG_LOCK is held two lines above. Strip that function's clause and the block
# must be reported. Without this arm a checker that only ever inspected
# `unsafe fn` lines would pass, and every reasoned-about block in the tree could
# lose its reasoning silently.
arm A4 "an unsafe block whose enclosing item loses its clause is caught" \
  "awk 'BEGIN{d=0} {if(!d && \$0 ~ /\\/\\/\\/ # Safety/){sub(/# Safety/,"NOTE"); d=1} print}' rust/src/rng.rs > .m && mv .m rust/src/rng.rs" \
  caught "rust/src/rng.rs"

echo
if [ "$FAILS" -ne 0 ]; then
  echo "FAIL: $FAILS arm(s) did not behave as required ($PASSES passed)"
  exit 1
fi
echo "PASS: $PASSES arms -- the checker catches what it must and ignores what it must"
