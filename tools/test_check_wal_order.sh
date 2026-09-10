#!/usr/bin/env bash
# Falsify tools/check_wal_order.sh -- one arm per rule, the silent direction, and
# the claim its own comment makes about collapsing.
#
# The property is the write-ahead ORDER of a journal commit, read from a QEMU IDE
# trace: data write, barrier, commit header, barrier. smoke-fs-wal-flush already
# proves a FLUSH CACHE is issued and its result checked; it cannot prove the flush
# happens in the right PLACE, and place is the whole property. A flush after the
# commit header instead of before it looks identical from the return codes and
# still loses the rule -- recovery would find a valid, correctly-HMAC'd
# transaction whose data sectors never reached the platter, and redo it from
# garbage.
#
# Fixtures are synthetic traces, so these arms test the RULE rather than whatever
# a boot happened to emit.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECK="$ROOT/tools/check_wal_order.sh"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

cmd () { printf 'ide: addr 0x1f7 (Command); val %s\n' "$1"; }

# One logical block write is EIGHT consecutive sector writes at the 4 KiB block
# size, which is exactly what the collapsing exists to absorb.
block () { for _ in 1 2 3 4 5 6 7 8; do cmd 0x30; done; }

arm () {  # $1 rule, $2 desc, $3 trace-producer, $4 expect(caught|clean), $5 must-say
  local rule="$1" desc="$2" gen="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  eval "$gen" > "$d/trace.txt"
  out="$(bash "$CHECK" "$d/trace.txt" 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not say $want -- $desc"; head -1 <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; head -1 <<<"$out" | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_wal_order.sh:"

# ---- THE SILENT DIRECTION FIRST, because every arm below is a mutation of it:
#      data -> barrier A -> commit header -> barrier B, with a realistic
#      eight-sector block write.
arm "1" "a correct commit sequence" \
    'block; cmd 0xe7; cmd 0x30; cmd 0xe7' clean

# ---- THE DEFECT: the flush lands AFTER the commit header instead of before it.
#      Same commands, same count, same return codes -- only the order differs,
#      which is precisely why a return-code test cannot see it.
arm "2" "the barrier after the commit header instead of before it" \
    'block; cmd 0x30; cmd 0xe7; cmd 0xe7' caught "commit sequence ends"

# ---- THE CLAIM THE CHECKER'S OWN COMMENT MAKES: collapsing runs cannot hide a
#      missing barrier, because two logical writes with no flush between them
#      collapse to a SINGLE 0x30 and the tail stops matching. Asserted here
#      rather than trusted -- it is the reasoning that makes the collapse safe.
arm "3" "two block writes with no barrier between them" \
    'block; block; cmd 0xe7' caught "commit sequence ends"

# ---- ... and the other half of the same claim: collapsing must still ACCEPT a
#      correct sequence however many sectors each logical write decomposes into.
#      This is what broke when the block size stopped being one sector.
arm "3b" "a correct sequence survives however many sectors a block write takes" \
    'for _ in $(seq 1 40); do cmd 0x30; done; cmd 0xe7; cmd 0x30; cmd 0xe7' clean

# ---- NO FLUSH AT ALL. A separate message from a wrong order, because the two
#      are different defects: one is a journal that is not durable, the other is
#      a journal that is durable in the wrong sequence.
arm "4" "a trace with no FLUSH CACHE anywhere" \
    'block; cmd 0x30' caught "no FLUSH CACHE"

# ---- THE THREE "NOTHING WAS MEASURED" GUARDS. Each must FAIL rather than pass,
#      because a check that ran against nothing is the one answer that must never
#      read as PASS.
arm "5a" "an empty trace file" 'true' caught "trace file is empty"

arm "5b" "a trace with no IDE command writes in it at all" \
    'printf "ide: addr 0x1f0 (Data); val 0x00\nsome other event\n"' \
    caught "no IDE command-register writes"

printf '  5c: '
if bash "$CHECK" /tmp/definitely-not-a-trace-$$ >/dev/null 2>&1; then
  echo "NOT CAUGHT -- a missing trace file"; FAILS=$((FAILS+1))
else
  echo "caught -- a missing trace file"; PASSES=$((PASSES+1))
fi

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
