#!/usr/bin/env bash
# Falsify tools/check_kernel_markers.py: one arm per rule, each a mutation of the
# real tree that the checker must catch, and the clean tree, which it must pass.
set -u
pass=0; fail=0
OUT=$(mktemp)
cp Makefile /tmp/kmk.Makefile.orig
cp .github/kernel-markers.yml /tmp/kmk.yml.orig
restore() { cp /tmp/kmk.Makefile.orig Makefile; cp /tmp/kmk.yml.orig .github/kernel-markers.yml; rm -f tools/zz_kmk_probe.sh; }
trap restore EXIT

try() { # name, want(0|1), rule-tag, setup
  local name="$1" want="$2" tag="$3" setup="$4"
  eval "$setup"
  python3 tools/check_kernel_markers.py >"$OUT" 2>&1; got=$?
  restore
  if [ "$got" = "$want" ] && { [ "$want" = 0 ] || grep -q "^  - $tag" "$OUT"; }; then
    echo "  PASS  $name (exit $got)"; pass=$((pass+1))
  else
    echo "  FAIL  $name (exit $got, wanted $want with $tag)"; sed -n '1,8p' "$OUT"; fail=$((fail+1))
  fi
}

echo "R1 -- a gate moved back to reading its kernel marker off the console must be CAUGHT"
try "smoke-cpu without MARKER_CHANNEL=kcon" 1 R1 \
 "python3 -c \"
import re;p='Makefile';s=open(p).read()
i=s.index('\nsmoke-cpu:');j=s.index('\n\n',i)
s=s[:i]+s[i:j].replace('MARKER_CHANNEL=kcon ','')+s[j:];open(p,'w').write(s)\""

echo "R2 -- a listed gate that no longer reads a kernel marker off the console must be CAUGHT"
try "a stale console: entry" 1 R2 \
 "sed -i 's/^console:$/console:\n  smoke-cpu: exposed/' .github/kernel-markers.yml; sed -i 's/^exposed_count: 0$/exposed_count: 1/' .github/kernel-markers.yml"

echo "R3 -- the ratchet's count must match the exposed entries"
try "exposed_count raised with nothing exposed" 1 R3 \
 "sed -i 's/^exposed_count: 0$/exposed_count: 3/' .github/kernel-markers.yml"

echo "R4 -- a userspace marker read from COM4 must be CAUGHT"
try "kcon on a marker init prints" 1 R4 \
 "python3 -c \"
p='Makefile';s=open(p).read()
s=s.replace('\nsmoke-cpu:','\nsmoke-zz-kmk:\n\t@MARKER_CHANNEL=kcon REQUIRE_MARKER=\'init: console_server launched\' tools/smoke_test.sh horus.iso\n\nsmoke-cpu:',1)
open(p,'w').write(s)\""

echo "R4 -- a print()ed marker read from COM3 must be CAUGHT"
try "kdiag on a marker print() writes" 1 R4 \
 "python3 -c \"
p='Makefile';s=open(p).read()
i=s.index('\nsmoke-cpu:');j=s.index('\n\n',i)
s=s[:i]+s[i:j].replace('MARKER_CHANNEL=kcon','MARKER_CHANNEL=kdiag')+s[j:];open(p,'w').write(s)\""

echo "R5 -- a new harness that boots the guest itself and is not listed must be CAUGHT"
try "an unlisted QEMU harness" 1 R5 \
 "printf '#!/bin/sh\nqemu-system-x86_64 -cdrom horus.iso\n' > tools/zz_kmk_probe.sh"

echo "R5 -- a listed harness that is gone must be CAUGHT"
try "a stale scripts: entry" 1 R5 \
 "sed -i 's#^scripts:\$#scripts:\n  tools/zz_gone.sh: \"unmoved: nothing\"#' .github/kernel-markers.yml"

echo "R6 -- a control arm moved back to expecting a kernel fault on the console must be CAUGHT"
try "smoke-spawn-window-control without EXPECT_FAULT_CHANNEL" 1 R6 \
 "python3 -c \"
p='Makefile';s=open(p).read()
i=s.index('\nsmoke-spawn-window-control:');j=s.index('\n\n',i)
s=s[:i]+s[i:j].replace('EXPECT_FAULT_CHANNEL=kdiag ','')+s[j:];open(p,'w').write(s)\""

echo "R6 -- a short kernel string the checker cannot place, on the console, must be CAUGHT"
try "an expected fault of 'task 1' on the console" 1 R6 \
 "python3 -c \"
p='Makefile';s=open(p).read()
s=s.replace('\nsmoke-cpu:','\nsmoke-zz-kmk:\n\t@EXPECT_FAULT=\'task 1\' tools/smoke_test.sh horus.iso\n\nsmoke-cpu:',1)
open(p,'w').write(s)\""

echo "R7 -- a print()ed fault read from COM3 must be CAUGHT"
try "kdiag on the shootdown panic print() writes" 1 R7 \
 "python3 -c \"
p='Makefile';s=open(p).read()
i=s.index('\nsmoke-shootdown-unacked:');j=s.index('\n\n',i)
s=s[:i]+s[i:j].replace('EXPECT_FAULT_CHANNEL=kcon','EXPECT_FAULT_CHANNEL=kdiag')+s[j:];open(p,'w').write(s)\""

echo "R7 -- a reporter's fault read from COM4 must be CAUGHT"
try "kcon on a panic_str fault" 1 R7 \
 "python3 -c \"
p='Makefile';s=open(p).read()
i=s.index('\nsmoke-spawn-window-control:');j=s.index('\n\n',i)
s=s[:i]+s[i:j].replace('EXPECT_FAULT_CHANNEL=kdiag','EXPECT_FAULT_CHANNEL=kcon')+s[j:];open(p,'w').write(s)\""

echo "clean -- the unmutated tree must PASS (a checker that rejects everything satisfies every arm above)"
try "clean tree" 0 none "true"

rm -f "$OUT"
echo
echo "falsification: $pass passed, $fail failed"
[ "$fail" = 0 ]
