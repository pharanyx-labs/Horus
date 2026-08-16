#!/usr/bin/env bash
#
# Assert the write-ahead ORDERING of the journal commit, from a QEMU IDE trace.
#
# smoke-fs-wal-flush proves the kernel issues FLUSH CACHE and checks its result.
# It does not prove the flush happens in the right PLACE, and place is the whole
# property: a flush issued after the commit header instead of before it looks
# identical to an error-injection test and still loses the write-ahead rule.
# Recovery would find a valid, correctly-HMAC'd transaction whose data sectors
# never reached the platter, and redo it from garbage.
#
# So this reads the command register writes out of the trace and asserts the tail
# of the sequence is exactly:
#
#     0x30   write the last journal data sector
#     0xe7   BARRIER A -- data durable BEFORE the record that commits it
#     0x30   write the commit header (the commit point)
#     0xe7   BARRIER B -- commit point durable before home is touched
#
# The WAL_CRASHTEST build halts immediately after barrier B, which is what makes
# the tail a stable thing to assert against rather than a moving target.
#
# Usage: tools/check_wal_order.sh <trace-file>
set -u

TRACE="${1:-}"
if [ -z "$TRACE" ] || [ ! -f "$TRACE" ]; then
    echo "WAL_ORDER: FAIL no trace file '$TRACE'" >&2
    exit 1
fi

# An empty trace means tracing silently did nothing -- fail rather than "pass"
# on an assertion that never ran.
if [ ! -s "$TRACE" ]; then
    echo "WAL_ORDER: FAIL trace file is empty (tracing produced no events)" >&2
    exit 1
fi

CMDS="$(grep -oE '0x1f7 \(Command\); val 0x[0-9a-f]+' "$TRACE" | sed 's/.*val //')"
if [ -z "$CMDS" ]; then
    echo "WAL_ORDER: FAIL no IDE command-register writes in the trace" >&2
    exit 1
fi

FLUSHES="$(printf '%s\n' "$CMDS" | grep -c '^0xe7$')"
if [ "$FLUSHES" -eq 0 ]; then
    echo "WAL_ORDER: FAIL no FLUSH CACHE (0xe7) was ever issued -- the journal is not durable" >&2
    exit 1
fi

TAIL="$(printf '%s\n' "$CMDS" | tail -4 | tr '\n' ' ' | sed 's/ $//')"
EXPECT="0x30 0xe7 0x30 0xe7"
if [ "$TAIL" != "$EXPECT" ]; then
    echo "WAL_ORDER: FAIL commit sequence ends '$TAIL', expected '$EXPECT'" >&2
    echo "  (data write -> barrier A -> commit header -> barrier B)" >&2
    echo "  last 12 commands: $(printf '%s\n' "$CMDS" | tail -12 | tr '\n' ' ')" >&2
    exit 1
fi

echo "WAL_ORDER: PASS $FLUSHES flushes; commit tail '$TAIL' (data -> A -> header -> B)"
exit 0
