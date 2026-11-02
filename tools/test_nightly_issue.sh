#!/bin/sh
# Falsify the nightly-issue workflow check, and the opener's one-issue rule.
#
# The mutations and the fake gh are applied to a copy. Nothing here touches
# the working tree, and no issue is opened on GitHub.
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
  mkdir -p "$1/.github/workflows" "$1/tools" "$1/bin"
  cp "$ROOT/.github/workflows/nightly-issue.yml" "$1/.github/workflows/"
  cp "$ROOT/.github/workflows/fuzz.yml" "$1/.github/workflows/"
  cp "$ROOT/.github/workflows/kani-arms.yml" "$1/.github/workflows/"
  cp "$ROOT/tools/check_nightly_issue.py" "$1/tools/"
  cp "$ROOT/tools/nightly_issue.py" "$1/tools/"
  cp "$ROOT/tools/open_nightly_issue.sh" "$1/tools/"
  cat > "$1/bin/gh" <<'EOF'
#!/bin/sh
if [ "$1" = "issue" ] && [ "$2" = "list" ]; then
  if [ "${NIGHTLY_LIST_RC:-0}" != "0" ]; then
    exit "$NIGHTLY_LIST_RC"
  fi
  printf '%s' "${NIGHTLY_FIXTURE:-[]}"
  exit 0
fi
if [ "$1" = "issue" ] && [ "$2" = "create" ]; then
  echo create >> "${NIGHTLY_LOG:?}"
  exit 0
fi
echo "unexpected gh: $*" >> "${NIGHTLY_LOG:?}"
exit 1
EOF
  chmod +x "$1/bin/gh"
}

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
  out=$(cd "$d" && python3 tools/check_nightly_issue.py 2>&1)
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

# $1 id, $2 fixture json, $3 list rc, $4 workflow, $5 url, $6 run id,
# $7 expect script rc, $8 expect creates (0|1), $9 description
run_opener() {
  id=$1
  fixture=$2
  list_rc=$3
  workflow=$4
  url=$5
  run_id=$6
  expect_rc=$7
  expect_creates=$8
  desc=$9
  d=$(mktemp -d)
  mktree "$d"
  log="$d/gh.log"
  : > "$log"
  out=$(cd "$d" && \
    NIGHTLY_FIXTURE="$fixture" NIGHTLY_LIST_RC="$list_rc" NIGHTLY_LOG="$log" \
    PATH="$d/bin:$PATH" \
    GH_TOKEN=test WORKFLOW_NAME="$workflow" RUN_URL="$url" RUN_ID="$run_id" \
    GITHUB_REPOSITORY=pharanyx-labs/Horus \
    sh tools/open_nightly_issue.sh 2>&1)
  rc=$?
  creates=$(grep -c '^create$' "$log" || true)
  if [ "$rc" -ne "$expect_rc" ] || [ "$creates" -ne "$expect_creates" ]; then
    fail "$id" "rc=$rc creates=$creates, wanted rc=$expect_rc creates=$expect_creates ($desc)"
    printf '%s\n' "$out" | head -8
  else
    pass "$id" "$desc"
  fi
  _rmtree "$d"
}

echo "Falsifying tools/check_nightly_issue.py:"

arm U pass "the unmutated copy" "true" "nightly-issue: ok"

arm W1 fail "issues: write is dropped" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/nightly-issue.yml')
t = p.read_text()
old = '  issues: write\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '', 1))
PY" "issues: write is missing"

arm W2 fail "contents may be written" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/nightly-issue.yml')
t = p.read_text()
old = '  contents: read\n'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '  contents: write\n', 1))
PY" "permission is wider than issues"

arm W3 fail "a success may open an issue" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/nightly-issue.yml')
t = p.read_text()
old = \"conclusion == 'failure'\"
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, \"conclusion == 'success'\", 1))
PY" "does not require a failure conclusion"

arm W4 fail "Fuzz is no longer subscribed" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/nightly-issue.yml')
t = p.read_text()
old = 'workflows: [\"Fuzz\", \"Kani control arms\"]'
if old not in t:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, 'workflows: [\"Kani control arms\"]', 1))
PY" "does not subscribe to Fuzz and Kani control arms"

arm W5 fail "the opener script is not run" "python3 - <<'PY'
from pathlib import Path
p = Path('.github/workflows/nightly-issue.yml')
t = p.read_text()
old = 'sh tools/open_nightly_issue.sh'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, 'true', 1))
PY" "does not run tools/open_nightly_issue.sh"

arm S0 fail "the opener no longer asks for open issues" "python3 - <<'PY'
from pathlib import Path
p = Path('tools/open_nightly_issue.sh')
t = p.read_text()
old = '--state open'
if t.count(old) != 1:
    raise SystemExit('anchor missing')
p.write_text(t.replace(old, '--state all', 1))
PY" "opener script lost --state open"

echo "Opener, with a fake gh:"

URL="https://github.com/pharanyx-labs/Horus/actions/runs/41384454527"
run_opener S1 '[]' 0 "Fuzz" "$URL" 41384454527 0 1 \
  "no open issue, so one is created"
run_opener S2 '[{"title":"Nightly failed: Fuzz","state":"open"}]' 0 "Fuzz" \
  "$URL" 41384454527 0 0 \
  "an open issue for this workflow blocks a second"
run_opener S3 '[{"title":"Nightly failed: Kani control arms","state":"open"}]' 0 \
  "Fuzz" "$URL" 41384454527 0 1 \
  "an open issue for the other workflow does not block"
run_opener S4 '[{"title":"Nightly failed: Fuzz","state":"closed"}]' 0 "Fuzz" \
  "$URL" 41384454527 0 1 \
  "a closed issue does not block"
run_opener S5 '[]' 1 "Fuzz" "$URL" 41384454527 1 0 \
  "a failed issue list creates nothing"
run_opener S6 '[]' 0 "Fuzz" "https://example.invalid/runs/41384454527" \
  41384454527 1 0 \
  "a foreign run url creates nothing"
run_opener S7 '[]' 0 "not-a-workflow" "$URL" 41384454527 1 0 \
  "an unknown workflow creates nothing"

echo "nightly-issue harness: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
