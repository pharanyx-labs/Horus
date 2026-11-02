#!/usr/bin/env python3
"""A red Fuzz or Kani control-arms run opens one issue, and only one.

`.github/workflows/nightly-issue.yml` subscribes to those two workflows by
the names in their files, runs only after a failed schedule or manual run in
this repository, and calls `tools/open_nightly_issue.sh`. The token can read
contents and open an issue. Any wider write permission is a refusal.

Success prints `nightly-issue: ok`.
"""

import sys
from pathlib import Path

WORKFLOW = Path(".github/workflows/nightly-issue.yml")
OPENER = Path("tools/open_nightly_issue.sh")
SOURCES = (
    Path(".github/workflows/fuzz.yml"),
    Path(".github/workflows/kani-arms.yml"),
)
SCRIPT_NEEDLES = (
    "--state open",
    "nightly_issue.py decide",
    "issue create",
    "Nightly failed",
)


def fail(msg):
    print(f"nightly-issue: {msg}")
    return 1


def top_name(path):
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, f"cannot read {path.as_posix()}"
    for line in text.splitlines():
        if line.startswith("name:"):
            name = line.split(":", 1)[1].strip().strip('"').strip("'")
            if not name:
                return None, f"{path.as_posix()} has an empty name"
            return name, None
    return None, f"{path.as_posix()} has no name"


def main():
    names = []
    for path in SOURCES:
        name, error = top_name(path)
        if error:
            return fail(error)
        names.append(name)
    expected = 'workflows: ["' + '", "'.join(names) + '"]'
    try:
        text = WORKFLOW.read_text(encoding="utf-8")
    except OSError:
        return fail("cannot read .github/workflows/nightly-issue.yml")
    try:
        script = OPENER.read_text(encoding="utf-8")
    except OSError:
        return fail("cannot read tools/open_nightly_issue.sh")
    if "workflow_run:" not in text:
        return fail("does not run on workflow_run")
    if "pull_request:" in text:
        return fail("runs on a pull request")
    if expected not in text:
        return fail("workflow_run does not subscribe to Fuzz and Kani control arms")
    for line in text.splitlines():
        stripped = line.strip()
        if ": write" in stripped and stripped != "issues: write":
            return fail(f"permission is wider than issues: {stripped}")
    if "contents: read" not in text:
        return fail("contents is not read")
    if "issues: write" not in text:
        return fail("issues: write is missing")
    if "conclusion == 'failure'" not in text:
        return fail("does not require a failure conclusion")
    if "event == 'schedule'" not in text or "event == 'workflow_dispatch'" not in text:
        return fail("does not limit the triggering event")
    if "head_repository.full_name == github.repository" not in text:
        return fail("does not require this repository")
    if "tools/open_nightly_issue.sh" not in text:
        return fail("does not run tools/open_nightly_issue.sh")
    if "continue-on-error" in text:
        return fail("continue-on-error would hide a missed issue")
    for needle in SCRIPT_NEEDLES:
        if needle not in script:
            return fail(f"opener script lost {needle}")
    print("nightly-issue: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
