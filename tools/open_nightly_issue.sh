#!/bin/sh
# Open one issue for a red nightly, unless that workflow already has one open.
#
# The decision is tools/nightly_issue.py. A list that cannot be read, a
# workflow this script does not know, or a run URL that is not this
# repository is a refusal: no issue is created.
set -eu

if [ -z "${GH_TOKEN:-}" ] || [ -z "${WORKFLOW_NAME:-}" ] || [ -z "${RUN_URL:-}" ] \
    || [ -z "${RUN_ID:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ]; then
  echo "nightly-issue: refuse" >&2
  exit 1
fi

if ! list=$(gh issue list --repo "$GITHUB_REPOSITORY" --state open --limit 100 \
    --json title,state --search "Nightly failed in:title"); then
  echo "nightly-issue: refuse" >&2
  exit 1
fi

if ! decision=$(printf '%s' "$list" | python3 tools/nightly_issue.py decide \
    --workflow "$WORKFLOW_NAME"); then
  echo "nightly-issue: refuse" >&2
  exit 1
fi

printf '%s\n' "$decision"
case "$decision" in
  "nightly-issue: already open")
    exit 0
    ;;
  "nightly-issue: open")
    ;;
  *)
    echo "nightly-issue: refuse" >&2
    exit 1
    ;;
esac

if ! title=$(python3 tools/nightly_issue.py title --workflow "$WORKFLOW_NAME"); then
  echo "nightly-issue: refuse" >&2
  exit 1
fi
tmp=$(mktemp)
if ! python3 tools/nightly_issue.py body --workflow "$WORKFLOW_NAME" \
    --run-url "$RUN_URL" --run-id "$RUN_ID" > "$tmp"; then
  rm -f "$tmp"
  echo "nightly-issue: refuse" >&2
  exit 1
fi
gh issue create --repo "$GITHUB_REPOSITORY" --title "$title" --body-file "$tmp"
rc=$?
rm -f "$tmp"
exit "$rc"
