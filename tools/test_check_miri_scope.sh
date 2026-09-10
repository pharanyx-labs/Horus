#!/usr/bin/env bash
# Falsify tools/check_miri_scope.py -- one arm per rule, the silent direction,
# the --print-skip-args contract, and the self-check.
#
# WHY RULE 1 HAS NO ARM OF ITS OWN. The docstring's first rule -- every test
# module is run under Miri or listed in `skip` -- cannot be violated, because
# `run` is computed as (modules with tests) minus (skip), and the CI job builds
# its command from `--print-skip-args` rather than repeating the list. The two
# cannot drift because only one of them exists. That is a design property, not
# an unchecked one, and arm 4 is what holds it: if --print-skip-args stopped
# agreeing with the manifest, the derivation would be a second list after all.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASSES=0; FAILS=0

mktree () {
  mkdir -p "$1/tools" "$1/rust/src" "$1/.github"
  cp "$ROOT/tools/check_miri_scope.py" "$1/tools/"
  cp "$ROOT/.github/miri-scope.yml" "$1/.github/"
  cp "$ROOT"/rust/src/*.rs "$1/rust/src/"
}

# Refuse to delete anything that is not a fresh temp directory.
#
# On 2026-09-10 a sibling suite's fixture helper used `d` as a for-loop variable
# -- the same name `arm` uses for its temp dir, and not declared local -- so the
# loop left d=tools, and this cleanup ran `rm -rf tools` at the REPOSITORY ROOT.
# 87 tracked files, restored from HEAD; the uncommitted work in them was not.
# A harness that can delete a real directory is a hazard whatever the bug that
# points it there, so the guard is on the deletion rather than on that variable.
_rmtree () {
  case "${1:-}" in
    /tmp/*|/var/tmp/*|/var/folders/*) rm -rf "$1" ;;
    *) echo "REFUSING to rm -rf '${1:-<empty>}' -- not a temp directory" >&2
       exit 1 ;;
  esac
}

arm () {
  local rule="$1" desc="$2" mut="$3" expect="$4" want="${5:-}" d out rc
  d="$(mktemp -d)"; mktree "$d" >/dev/null 2>&1
  ( cd "$d" && eval "$mut" ) || { echo "  $rule: MUTATION FAILED ($desc)"; FAILS=$((FAILS+1)); _rmtree "$d"; return; }
  out="$(cd "$d" && python3 tools/check_miri_scope.py 2>&1)"; rc=$?
  if [ "$expect" = caught ]; then
    if [ $rc -eq 0 ]; then echo "  $rule: NOT CAUGHT -- $desc"; FAILS=$((FAILS+1))
    elif [ -n "$want" ] && ! grep -qF "$want" <<<"$out"; then
      echo "  $rule: caught but did not name $want -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: caught -- $desc"; PASSES=$((PASSES+1)); fi
  else
    if [ $rc -ne 0 ]; then echo "  $rule: WRONGLY CAUGHT -- $desc"; grep '^  - ' <<<"$out" | head -2; FAILS=$((FAILS+1))
    else echo "  $rule: clean, correctly -- $desc"; PASSES=$((PASSES+1)); fi
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_miri_scope.py:"

# ---- RULE 2a: a skip entry that has rotted -- the module is gone, or never had
#      tests. An entry like that excuses nothing while making the manifest look
#      more complete than it is.
arm "1a" "a skip entry naming a module that does not exist" \
    "python3 - <<'PY'
import pathlib, yaml
p = pathlib.Path('.github/miri-scope.yml'); d = yaml.safe_load(p.read_text())
d['skip']['no_such_module'] = 'a reason long enough to satisfy the substantive check, easily'
p.write_text(yaml.safe_dump(d))
PY" \
    caught "no_such_module"

arm "1b" "a skip entry naming a module that exists but has no tests" \
    "printf 'pub fn untested_thing() -> u32 { 7 }\n' > rust/src/untested.rs
     python3 - <<'PY'
import pathlib, yaml
p = pathlib.Path('.github/miri-scope.yml'); d = yaml.safe_load(p.read_text())
d['skip']['untested'] = 'a reason long enough to satisfy the substantive check, easily'
p.write_text(yaml.safe_dump(d))
PY" \
    caught "untested"

# ---- RULE 2b: excused with a token reason. Otherwise `skip:` becomes a place to
#      park a module rather than an argument for leaving it outside Miri.
arm "2" "a skip entry with a token reason" \
    "python3 - <<'PY'
import pathlib, yaml
p = pathlib.Path('.github/miri-scope.yml'); d = yaml.safe_load(p.read_text())
m = sorted(d['skip'])[0]
d['skip'][m] = 'too slow'
p.write_text(yaml.safe_dump(d))
PY" \
    caught "no substantive reason"

# ---- THE SILENT DIRECTION. A new module WITH tests and NOT in skip is the
#      normal, correct case: it is simply run under Miri. Reporting it would make
#      adding a tested module impossible.
arm "3" "a new tested module not in skip is run, not reported" \
    "printf 'pub fn f() -> u32 { 1 }\n#[cfg(test)]\nmod tests {\n#[test]\nfn t() { assert_eq!(super::f(), 1); }\n}\n' > rust/src/newmod.rs" \
    clean

# ---- THE CONTRACT RULE 1 RESTS ON. The CI job runs
#      `cargo miri test -- $(check_miri_scope.py --print-skip-args)`, so if that
#      output stopped matching the manifest the derivation would be a second
#      list -- exactly what it exists to prevent. Checked directly.
printf '  4: '
if ( cd "$ROOT" && python3 - <<'PYEOF'
import importlib.util, subprocess, sys, yaml, pathlib
man = yaml.safe_load(pathlib.Path(".github/miri-scope.yml").read_text())
want = " ".join(f"--skip {m}::" for m in sorted(man["skip"]))
got = subprocess.run([sys.executable, "tools/check_miri_scope.py", "--print-skip-args"],
                     capture_output=True, text=True).stdout.strip()
sys.exit(0 if got == want else 1)
PYEOF
); then echo "clean, correctly -- --print-skip-args matches the manifest exactly"; PASSES=$((PASSES+1))
else echo "WRONG -- the CI job's skip list has drifted from the manifest"; FAILS=$((FAILS+1)); fi

# ---- THE SELF-CHECK. If the #[test] pattern stops matching, no module is seen
#      to have tests -- and every skip entry then reads as rotted, so this fails
#      loudly rather than reporting a clean crate. An accident worth asserting,
#      because it is what stands between this checker and a silent pass.
arm "5" "a #[test] regex that matches nothing does not report a clean crate" \
    "python3 - <<'PY'
import pathlib
p = pathlib.Path('tools/check_miri_scope.py'); s = p.read_text()
a = r'#\[test\]'
assert s.count(a) == 1, 'anchor moved'
p.write_text(s.replace(a, r'#\[NOPE\]'))
PY
     grep -q 'NOPE' tools/check_miri_scope.py" \
    caught "has rotted"

echo
echo "arms passed: $PASSES   failed: $FAILS"
[ "$FAILS" -eq 0 ]
