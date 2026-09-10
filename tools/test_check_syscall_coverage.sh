#!/usr/bin/env bash
# Falsify tools/check_syscall_coverage.py -- one arm per rule, the silent
# direction, and the guard that refuses to measure nothing.
#
# WHAT IT MEASURES: which syscall HANDLER BODIES a tracked workload actually
# entered, read from `SYSCOV <n>` lines a SYSCALL_COVERAGE=1 kernel emits on first
# entry, and diffed against .github/syscall-coverage.yml. "Entered" and not
# "succeeded", for the reason the manifest's own header gives: captest asserts
# capability REFUSALS, which return before the handler runs, so a syscall can be
# named by the suite and have its body never execute -- which is how issue #176
# hid behind 100 passing checks.
#
# THE FIXTURE IS A COPY OF THE TREE plus a SYNTHESISED LOG. The log is built from
# the manifest itself -- one SYSCOV line per declared-covered syscall -- so the
# baseline passes by construction and every arm below is a single deliberate
# divergence from it. That is the only way to test the RULES rather than whatever
# last night's boot happened to enter.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2; exit 1 ;;
  esac
}

mktree () {
  local dst="$1"
  mkdir -p "$dst/tools" "$dst/.github" "$dst/src/kernel" "$dst/src/include" "$dst/include" || return 1
  cp "$ROOT/tools/check_syscall_coverage.py" "$dst/tools/" || return 1
  cp "$ROOT/.github/syscall-coverage.yml" "$dst/.github/" || return 1
  cp "$ROOT/src/kernel/syscall.c" "$dst/src/kernel/" || return 1
  cp "$ROOT/include/syscall.h" "$dst/include/" || return 1
  # The checker reads this too. A fixture assembled by guessing which files it
  # needs is a fixture that fails for its own reasons, which teaches nothing --
  # the lesson tools/test_check_claude_md.sh records, met again here.
  cp "$ROOT/src/include/kernel.h" "$dst/src/include/" || return 1
  # The log every declared-covered syscall would produce.
  ( cd "$dst" && python3 - <<'PY'
import yaml, re, pathlib
man = yaml.safe_load(open(".github/syscall-coverage.yml"))
hdr = pathlib.Path("include/syscall.h").read_text()
num = {m.group(1): int(m.group(2))
       for m in re.finditer(r"^#define\s+(SYS_[A-Z_0-9]+)\s+(\d+)", hdr, re.M)}
with open("serial.log", "w") as f:
    f.write("Horus secure microkernel (x86_64) booting\n")
    for name in (man.get("covered") or []):
        if name in num:
            f.write(f"SYSCOV {num[name]}\n")
PY
  ) || return 1
}

run () { ( cd "$1" && python3 tools/check_syscall_coverage.py serial.log 2>&1 ); }

arm () {  # $1 rule, $2 desc, $3 mutation, $4 expect, $5 must-say
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"
  mktree "$d" || { echo "  $rule: FIXTURE FAILED"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  ( cd "$d" && eval "$mut" ) >/dev/null 2>&1 || { echo "  $rule: MUTATION FAILED -- $desc"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(run "$d")"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not say $want -- $desc"; grep -E "^(FAIL|  )" <<<"$out" | head -2 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep -E "^(FAIL|  )" <<<"$out" | head -3 | sed 's/^/      /'; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_syscall_coverage.py:"

# ---- THE SILENT DIRECTION. The synthesised log matches the manifest exactly.
arm "1" "a log that enters every declared-covered syscall" "true" clean

# ---- THE REGRESSION IT EXISTS FOR: a syscall the manifest says is covered, whose
#      handler no workload entered. This is the shape of a test suite that stopped
#      exercising something without anyone noticing.
arm "2" "a covered syscall the workload never entered" \
    'head -n -1 serial.log > t && mv t serial.log' \
    caught "declared covered but its handler never ran"

# ---- THE OTHER DIRECTION: a syscall declared uncovered that WAS entered. Good
#      news, and still a manifest that no longer describes the tree -- an
#      exemption that has quietly stopped being needed.
arm "3" "an uncovered syscall that the workload did enter" \
    'python3 - <<PY
import yaml, re, pathlib
man = yaml.safe_load(open(".github/syscall-coverage.yml"))
name = sorted(man.get("uncovered") or {})[0]
hdr = pathlib.Path("include/syscall.h").read_text()
n = int(re.search(r"^#define\s+" + name + r"\s+(\d+)", hdr, re.M).group(1))
open("serial.log", "a").write(f"SYSCOV {n}\n")
PY' \
    caught "uncovered"

# ---- A SYSCALL IN BOTH LISTS. Ambiguous classification is not classification.
arm "4" "a syscall declared both covered and uncovered" \
    'python3 - <<PY
import yaml
p = ".github/syscall-coverage.yml"
man = yaml.safe_load(open(p))
name = (man.get("covered") or [])[0]
man.setdefault("uncovered", {})[name] = "planted by the falsification suite, a long enough reason to pass"
yaml.safe_dump(man, open(p, "w"))
PY' \
    caught "both"

# ---- A TOKEN REASON. Otherwise `uncovered` becomes a place to park a syscall
#      rather than an argument for not exercising it.
arm "5" "an uncovered entry with a token reason" \
    'python3 - <<PY
import yaml
p = ".github/syscall-coverage.yml"
man = yaml.safe_load(open(p))
name = sorted(man.get("uncovered") or {})[0]
man["uncovered"][name] = "later"
yaml.safe_dump(man, open(p, "w"))
PY' \
    caught "reason"

# ---- THE GUARD THAT REFUSES TO MEASURE NOTHING. A log with no SYSCOV lines is
#      not a boot with no coverage -- it is a boot that was not built with
#      SYSCALL_COVERAGE=1, or never got far enough to run one syscall. Reporting
#      88 spurious regressions would bury the one fact that matters.
arm "6a" "a log with no SYSCOV lines at all" \
    'printf "Horus secure microkernel (x86_64) booting\nnothing else\n" > serial.log' \
    caught "no SYSCOV lines"

printf '  6b: '
d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
if ( cd "$d" && python3 tools/check_syscall_coverage.py /nonexistent-log-$$ ) >/dev/null 2>&1; then
  echo "NOT CAUGHT -- an unreadable log"; FAILS=$((FAILS+1))
else
  echo "caught -- an unreadable log"; PASSES=$((PASSES+1))
fi
_rmtree "$d"

printf '  6c: '
d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
if ( cd "$d" && python3 tools/check_syscall_coverage.py ) >/dev/null 2>&1; then
  echo "NOT CAUGHT -- called with no log at all"; FAILS=$((FAILS+1))
else
  echo "caught -- called with no log at all"; PASSES=$((PASSES+1))
fi
_rmtree "$d"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
