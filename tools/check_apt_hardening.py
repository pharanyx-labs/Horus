#!/usr/bin/env python3
"""Fail the build if a workflow installs packages without the hardened path.

WHAT WENT WRONG. `apt-get update` exits non-zero when ANY configured repository
fails, including ones this project has never used. GitHub's runner image ships
vendor lists for Microsoft, Google and others. On 2026-08-30 packages.microsoft.com
answered 403 for a few minutes, and `main` went red in a job that installs binutils
and QEMU from the Ubuntu archive and nothing else.

WHY IT WAS ABLE TO. 87 of the workflow's 101 jobs ran a bare `sudo apt-get update`,
so any one of them could redden the whole run. That is a fleet-wide fragility rather
than a flake: with N independent jobs each carrying a small probability p of hitting
a transient vendor failure, the run reddens at 1-(1-p)^N, and N was 87.

WHY IT RECURRED. The `security` job had already been given a retry loop, carrying a
comment that "the apt step in this repo's CI has flaked twice in one day". The fix
was applied in the job where it was noticed and never carried to the other 86, which
is the failure mode this repository has recorded before: a lesson learned in one arm
and not swept to its siblings.

WHAT THIS CHECKS. Every package install in every workflow goes through
`.github/actions/apt`, which strips the vendor lists and retries. A raw `apt-get` in
a workflow is refused, so an eighty-eighth job cannot reintroduce the fragility by
copying an older one, which is exactly how the first 86 came to look alike.

WHAT IT DOES NOT CHECK: that the action itself is correct. It checks that nothing
bypasses it. The action carries no `|| true` and is the only thing that installs.

Exit 0 if every install is hardened, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTION = ROOT / ".github" / "actions" / "apt" / "action.yml"

# The one job allowed to run apt inline: its installs are pinned by version and
# checksum, so they cannot move to a shared action that takes a package list. It
# must still strip the vendor lists, and that is checked rather than trusted.
INLINE_ALLOWED = {"security"}


def main():
    problems = []

    if not ACTION.exists():
        print(f"FAIL: {ACTION.relative_to(ROOT)} is missing; nothing is hardened")
        return 1
    action = ACTION.read_text(encoding="utf-8")
    if "sources.list.d" not in action:
        problems.append(f"{ACTION.relative_to(ROOT)}: does not strip the vendor "
                        f"repository lists, which is the whole point")
    if "retry" not in action:
        problems.append(f"{ACTION.relative_to(ROOT)}: does not retry")
    if re.search(r"apt-get[^\n]*\|\|\s*true", action):
        problems.append(f"{ACTION.relative_to(ROOT)}: tolerates an apt failure with "
                        f"`|| true`; an install that reports success having "
                        f"installed nothing is worse than a red build")

    for wf in WORKFLOWS:
        text = wf.read_text(encoding="utf-8")
        rel = wf.relative_to(ROOT)
        # Attribute each apt line to the job it sits in, so the exemption is
        # per-job rather than per-file.
        job = None
        for n, line in enumerate(text.split("\n"), 1):
            m = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
            if m:
                job = m.group(1)
            if "apt-get" not in line or line.lstrip().startswith("#"):
                continue
            if job in INLINE_ALLOWED:
                continue
            problems.append(f"{rel}:{n}: job `{job}` runs apt-get directly; use "
                            f"`uses: ./.github/actions/apt` instead")

    # The exempted job must still strip, or the exemption is a hole.
    for wf in WORKFLOWS:
        text = wf.read_text(encoding="utf-8")
        for jobname in INLINE_ALLOWED:
            m = re.search(r"^  " + re.escape(jobname) + r":\s*$(.*?)(?=^  [a-zA-Z0-9_-]+:\s*$|\Z)",
                          text, re.S | re.M)
            if not m:
                continue
            if "apt-get" in m.group(1) and "sources.list.d" not in m.group(1):
                problems.append(f"{wf.relative_to(ROOT)}: job `{jobname}` is exempt "
                                f"from the shared action but does not strip the "
                                f"vendor lists either")

    uses = sum(t.count("uses: ./.github/actions/apt")
               for t in (w.read_text(encoding="utf-8") for w in WORKFLOWS))
    print(f"workflows scanned      : {len(WORKFLOWS)}")
    print(f"jobs using the action  : {uses}")
    print(f"inline, by exemption   : {len(INLINE_ALLOWED)}")

    if problems:
        print("\nFAIL: a package install can be broken by a repository this project does not use\n")
        for p in problems:
            print(f"  - {p}")
        return 1

    print("\nPASS: every package install goes through the hardened path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
