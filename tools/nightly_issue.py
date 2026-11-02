#!/usr/bin/env python3
"""Decide whether a red nightly opens an issue.

The allowed workflows are the names of `fuzz.yml` and `kani-arms.yml`. Any
other name is a refusal. An issue already open for that workflow means this
run opens none. A closed issue does not count. The body carries the run URL
and the run id, and nothing taken from the log.

`decide` reads a JSON issue list on stdin. Success prints
`nightly-issue: open` or `nightly-issue: already open`.
"""

import json
import sys
from pathlib import Path

WORKFLOWS = (
    Path(".github/workflows/fuzz.yml"),
    Path(".github/workflows/kani-arms.yml"),
)
RUN_PREFIX = "https://github.com/pharanyx-labs/Horus/actions/runs/"


def refuse(msg):
    print(f"nightly-issue: refuse: {msg}")
    raise SystemExit(1)


def workflow_names():
    found = []
    for path in WORKFLOWS:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            refuse(f"cannot read {path.as_posix()}")
        name = ""
        for line in text.splitlines():
            if line.startswith("name:"):
                name = line.split(":", 1)[1].strip().strip('"').strip("'")
                break
        if not name:
            refuse(f"{path.as_posix()} has no name")
        found.append(name)
    return found


def title_for(workflow):
    allowed = workflow_names()
    if workflow not in allowed:
        refuse(f"unknown workflow {workflow}")
    return f"Nightly failed: {workflow}"


def body_for(workflow, run_url, run_id):
    title_for(workflow)
    if not run_id.isdigit():
        refuse("run id is not digits")
    if not run_url.startswith(RUN_PREFIX):
        refuse("run url is not this repository's run")
    if run_url[len(RUN_PREFIX):].split("/")[0] != run_id:
        refuse("run url is not this repository's run")
    return (
        f"The workflow {workflow} finished red.\n"
        "\n"
        f"Run: {run_url}\n"
        f"Run id: {run_id}\n"
        "\n"
        "The log and any saved input stay on that run. "
        "This issue is the single open report for this workflow until it is closed.\n"
    )


def decide(workflow, raw):
    marker = title_for(workflow)
    if raw.strip() == "":
        refuse("issue list is empty input")
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        refuse("issue list is not json")
    if not isinstance(items, list):
        refuse("issue list is not a list")
    for item in items:
        if not isinstance(item, dict) or "title" not in item or "state" not in item:
            refuse("issue list entry has no title and state")
        if not isinstance(item["title"], str) or not isinstance(item["state"], str):
            refuse("issue list entry has no title and state")
        if item["state"] == "open" and item["title"] == marker:
            print("nightly-issue: already open")
            return
    print("nightly-issue: open")


def main(argv):
    if len(argv) < 2:
        refuse("no command")
    cmd = argv[1]
    if cmd == "decide":
        if argv[2:3] != ["--workflow"] or len(argv) != 4:
            refuse("decide needs --workflow")
        decide(argv[3], sys.stdin.read())
        return
    if cmd == "title":
        if argv[2:3] != ["--workflow"] or len(argv) != 4:
            refuse("title needs --workflow")
        print(title_for(argv[3]))
        return
    if cmd == "body":
        if (len(argv) != 8 or argv[2] != "--workflow"
                or argv[4] != "--run-url" or argv[6] != "--run-id"):
            refuse("body needs --workflow, --run-url and --run-id")
        sys.stdout.write(body_for(argv[3], argv[5], argv[7]))
        return
    refuse("unknown command")


if __name__ == "__main__":
    main(sys.argv)
