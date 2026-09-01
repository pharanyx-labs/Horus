#!/usr/bin/env bash
# Falsify tools/check_split_markers.py in every direction it claims to cover.
set -u
pass=0; fail=0
try() { # name, expected(0|1), setup, teardown
  local name="$1" want="$2" setup="$3" teardown="$4"
  eval "$setup"
  python3 tools/check_split_markers.py >/tmp/split_out.txt 2>&1; got=$?
  eval "$teardown"
  if [ "$got" = "$want" ]; then echo "  PASS  $name (exit $got)"; pass=$((pass+1));
  else echo "  FAIL  $name (exit $got, wanted $want)"; sed -n '1,6p' /tmp/split_out.txt; fail=$((fail+1)); fi
}

cp userspace/captest.c /tmp/cap.orig
cp src/kernel/main.c   /tmp/main.orig

echo "R1 -- a gated userspace marker split into two writes must be CAUGHT"
try "captest fail() reverted to 3 writes" 1 \
 "python3 - <<'PY'
import pathlib,re
p=pathlib.Path('userspace/captest.c');s=p.read_text()
i=s.index('static void fail(const char *what) {')
j=s.index('}',s.index('for (;;) { }',i))+1
s=s[:i]+'static void fail(const char *what) {\n    out(\"CAPTEST: FAIL \");\n    out(what);\n    out(\"\\\\n\");\n    sys_exit();\n    for (;;) { }\n}'+s[j:]
p.write_text(s)
PY" \
 "cp /tmp/cap.orig userspace/captest.c"

echo "R2 -- a gated KERNEL marker split into two writes must be CAUGHT"
try "DEFECT FLAGS reverted to 3 writes" 1 \
 "python3 - <<'PY'
import pathlib
p=pathlib.Path('src/kernel/main.c');s=p.read_text()
i=s.index('    {\n        char line[128];')
j=s.index('    }\n}',i)+len('    }\n}')
s=s[:i]+'    kmsg_begin();\n    print(\"DEFECT FLAGS: \");\n    print(DEFECT_FLAGS_STR);\n    print(\"\\\\n\");\n}'+s[j:]
p.write_text(s)
PY" \
 "cp /tmp/main.orig src/kernel/main.c"

echo "R3 -- an UNGATED split marker must NOT be flagged (no churn)"
try "ungated two-write info line" 0 \
 "printf '\nstatic void zz_probe(void){ out(\"ZZINFO: nobody gates this \"); out(\"tail\"); }\n' >> userspace/captest.c" \
 "cp /tmp/cap.orig userspace/captest.c"

echo "R4 -- the unmutated tree must PASS (a checker that rejects everything satisfies R1-R2)"
try "clean tree" 0 "true" "true"

echo
echo "falsification: $pass passed, $fail failed"
[ "$fail" = "0" ]
