#!/usr/bin/env python3
"""Require every CI job that boots the default kernel to use the stamped image.

A job that compiles the default kernel for itself can pass on a different
kernel from the one the run's kernel job built. The kernel job publishes one
image and the hash of that image. A consumer downloads it and the Makefile
refuses the image unless the hash is that output and the `.build-flags` stamp
matches the flags this build would use. A job that passes any other flag keeps
its own build. altconfigs, the reproducible job and its arms build their own
on purpose: handing them the shared image would make those gates unable to
see the kernel they are supposed to build.

Classification of a Makefile target is what the recipe runs, not the target's
name. A line counts only when, after simple variable expansion, it starts with
`$(MAKE)` or `make`. `$(MAKE) clean` does not. `$(MAKE)` with no goal, or with
`all`, `kernel.elf`, `horus.iso` or `iso`, does. An assignment other than
SMOKE_TIMEOUT, SOAK_RUNS, SHARED_KERNEL or SHARED_KERNEL_SHA256 means the line
builds a different kernel. An unset name expands to empty, which is what make does when a control arm's
variable is not passed. A `$(VAR)` this parser cannot finish (a function call,
or a value that still contains `$` after the depth limit) means the line is
not treated as the default kernel: those lines are printed by `--audit`,
because a real default boot that this file calls flagged is a job that never
checks the shared image.

The expected hash in the workflow is `needs.kernel.outputs.sha256`. A hash
read from a file that travelled with the artifact is the hole this check
exists to close.

Exit 0 only when at least one consumer is wired, the kernel job publishes the
hash and the three files, and no own-build job uses the action. Zero consumers
is a failure.
"""
import argparse
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit("check_shared_kernel_jobs: PyYAML is required (pip install pyyaml)")

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI_REL = pathlib.Path(".github/workflows/ci.yml")
ACTION_USES = "./.github/actions/shared-kernel"
# What a consumer passes into the action. It is the producing job's output,
# not a file that travelled with the artifact.
HASH_EXPR = "${{ needs.kernel.outputs.sha256 }}"
# What the kernel job publishes. The step id is the only place the hash is
# computed; the output is that step, not a second calculation.
KERNEL_OUTPUT = "${{ steps.kernel-hash.outputs.sha256 }}"
DOWNLOAD_PIN = "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131"
ARTIFACT = "horus-default-kernel"
ARTIFACT_FILES = ("kernel.elf", "kernel.build-flags", "kernel.sha256")
KERNEL_GOALS = {"all", "kernel.elf", "horus.iso", "iso"}
IGNORED_ASSIGN = {"SMOKE_TIMEOUT", "SOAK_RUNS", "SHARED_KERNEL", "SHARED_KERNEL_SHA256"}
PRODUCER = "kernel"
# These jobs build a kernel of their own, or compare two builds. Classifying
# one of them as a consumer is a parser bug, and wiring the action would hide
# the bug by making the job boot somebody else's image.
OWN_BUILD = {"altconfigs", "reproducible", "reproducible-arms"}
WITNESS_JOB = "smoke"
WITNESS_GOALS = ("smoke-shared-kernel-refuse", "smoke-shared-kernel")
MAKE_FLAGS = {"--no-print-directory", "-s", "--silent", "--quiet"}

ASSIGN_RE = re.compile(
    r"^(?:export\s+|override\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*(\?=|\+=|::=|:=|=)\s*(.*)$"
)
SIMPLE_VAR = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
TARGET_RE = re.compile(r"^([A-Za-z0-9_./+-]+)(?:\s+([A-Za-z0-9_./+-]+(?:\s+[A-Za-z0-9_./+-]+)*))?\s*:(?!:)\s*(.*)$")


def join_continuations(text):
    lines = text.split("\n")
    out = []
    buf = None
    for line in lines:
        if buf is None:
            buf = line
        else:
            buf += " " + line.lstrip()
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()
            continue
        out.append(buf)
        buf = None
    if buf is not None:
        out.append(buf)
    return out


def make_env(text):
    """Simple assignments. `+=` appends. `?=` keeps the first value."""
    env = {}
    for line in join_continuations(text):
        if line.startswith("\t") or line.lstrip().startswith("#"):
            continue
        m = ASSIGN_RE.match(line.strip())
        if not m:
            continue
        name, op, value = m.group(1), m.group(2), m.group(3).strip()
        if op == "+=":
            env[name] = (env.get(name, "") + " " + value).strip()
        elif op == "?=":
            env.setdefault(name, value)
        else:
            env[name] = value
    return env


def expand(text, env, depth=0):
    """Expand simple variables. An unset name is empty, which is what make does.

    `$(MAKE)` stays. It is how a recipe names the recursive build, and it is not
    an assignment in this Makefile. A name whose value still contains `$` is
    expanded again, up to a fixed depth, and then left alone: a line this
    function cannot finish is not treated as the default kernel.
    """
    if depth > 8 or "$" not in text:
        return text

    def repl(m):
        name = m.group(1) or m.group(2)
        if name == "MAKE":
            return m.group(0)
        if name not in env:
            return ""
        return expand(env[name], env, depth + 1)

    return SIMPLE_VAR.sub(repl, text)


def recipe_map(text):
    """Last recipe wins, which is what GNU make runs."""
    env = make_env(text)
    recipes = {}
    current = []
    in_define = False
    for line in join_continuations(text):
        stripped = line.strip()
        if in_define:
            if stripped == "endef":
                in_define = False
            continue
        if stripped.startswith("define ") or stripped == "define":
            in_define = True
            current = []
            continue
        if line.startswith("\t"):
            body = line[1:]
            if body.lstrip().startswith("#"):
                continue
            if current:
                for name in current:
                    recipes.setdefault(name, []).append(body)
            continue
        # Make drops comments before it decides where a recipe ends, so a
        # comment between a target and its recipe still belongs to that target.
        # A blank line ends it. A conditional does not start a new target.
        if stripped.startswith("#"):
            continue
        if not stripped:
            current = []
            continue
        if stripped.split(None, 1)[0] in {
            "ifeq", "ifneq", "ifdef", "ifndef", "else", "endif",
        }:
            continue
        if ASSIGN_RE.match(stripped):
            current = []
            continue
        m = TARGET_RE.match(stripped)
        if not m or "%" in m.group(1) or m.group(1).startswith("."):
            current = []
            continue
        names = [m.group(1)]
        if m.group(2):
            names.extend(m.group(2).split())
        # A new target line replaces any recipe already recorded. make keeps
        # the last recipe and only warns about the first.
        current = []
        for name in names:
            recipes[name] = []
            current.append(name)
    return env, recipes


def _make_tokens(command):
    """Classify one shell command that begins with make or $(MAKE)."""
    s = command.strip()
    if s.startswith("@"):
        s = s[1:].strip()
    if s.startswith("$(MAKE)"):
        s = s[len("$(MAKE)"):].strip()
    elif s.startswith("${MAKE}"):
        s = s[len("${MAKE}"):].strip()
    elif re.match(r"^make\b", s):
        s = s[4:].strip()
    else:
        return None
    # Redirections are not separators. `make 2>&1 | tee` is a bare make; the
    # `&` in `2>&1` must not be cut as a background operator first.
    s = re.sub(r"\d*>&\d+", " ", s)
    s = re.sub(r"\d*[<>][^\s]+", " ", s)
    s = re.split(r"[;&|`]", s, maxsplit=1)[0]
    foreign = False
    dynamic = False
    goals = []
    for tok in s.split():
        if tok in MAKE_FLAGS or tok.startswith("-j") or tok.startswith("--jobs"):
            continue
        if tok.startswith("-"):
            dynamic = True
            continue
        if "=" in tok:
            name, _val = tok.split("=", 1)
            if name not in IGNORED_ASSIGN:
                foreign = True
            elif "$" in tok:
                dynamic = True
            continue
        if "$" in tok:
            dynamic = True
            continue
        goals.append(tok)
    return foreign, dynamic, goals


def default_targets(makefile_text):
    env, recipes = recipe_map(makefile_text)
    expanded = {}
    for name, lines in recipes.items():
        expanded[name] = [expand(line, env) for line in lines]

    direct = set(KERNEL_GOALS)
    edges = {name: set() for name in expanded}
    for name, lines in expanded.items():
        for line in lines:
            s = line.strip()
            if s.startswith("@"):
                s = s[1:].strip()
            for seg in s.split(";"):
                seg = seg.strip()
                if not (seg.startswith("$(MAKE)") or seg.startswith("${MAKE}")
                        or re.match(r"^make\b", seg)):
                    continue
                classified = _make_tokens(seg)
                if classified is None:
                    continue
                foreign, dynamic, goals = classified
                if foreign or dynamic:
                    continue
                if not goals or all(g in KERNEL_GOALS for g in goals):
                    direct.add(name)
                else:
                    edges[name].update(goals)

    default = set(direct)
    changed = True
    while changed:
        changed = False
        for name, goals in edges.items():
            if name in default:
                continue
            if any(g in default for g in goals):
                default.add(name)
                changed = True
    # Virtual goals are not Makefile target names a job asks for by accident
    # beyond the four kernel goals, which the caller tests separately.
    return {n for n in default if n not in KERNEL_GOALS}, expanded, env


def make_invocations(script):
    """Each `make` command in a workflow run, cut at a shell separator."""
    if not isinstance(script, str):
        return
    for raw in script.splitlines():
        line = raw
        pos = 0
        while pos < len(line):
            m = re.search(r"(?:^|[;&|])\s*make\b", line[pos:])
            if not m:
                break
            start = pos + m.end()
            rest = line[start:]
            cut_m = re.search(r"[;&|`]", rest)
            cut = rest if cut_m is None else rest[:cut_m.start()]
            yield cut
            if cut_m is None:
                break
            pos = start + cut_m.start() + 1


def invocation_uses_default(argument_text, targets):
    classified = _make_tokens("make " + argument_text.strip())
    if classified is None:
        return False
    foreign, dynamic, goals = classified
    if foreign or dynamic:
        return False
    if not goals:
        return True
    return any(g in KERNEL_GOALS or g in targets for g in goals)


def job_invocations(job):
    found = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        script = step.get("run")
        for args in make_invocations(script):
            found.append((step, args))
    return found


def uses_default_kernel(job, targets):
    return any(invocation_uses_default(args, targets) for _step, args in job_invocations(job))


def needs_kernel(job):
    needs = job.get("needs")
    if needs is None:
        return False
    if isinstance(needs, str):
        return needs == PRODUCER
    if isinstance(needs, list):
        return PRODUCER in needs
    return False


def action_step(step):
    if not isinstance(step, dict):
        return False
    return step.get("uses") == ACTION_USES


def step_is_checkout(step):
    if not isinstance(step, dict):
        return False
    uses = step.get("uses") or ""
    return "actions/checkout@" in uses


def upload_paths(step):
    if not isinstance(step, dict):
        return None, []
    uses = step.get("uses") or ""
    if "actions/upload-artifact@" not in uses:
        return None, []
    with_ = step.get("with") or {}
    name = with_.get("name")
    raw = with_.get("path") or ""
    paths = [p.strip() for p in str(raw).splitlines() if p.strip()]
    return name, paths


def kernel_job_problems(job):
    problems = []
    outputs = job.get("outputs") or {}
    if outputs.get("sha256") != KERNEL_OUTPUT:
        problems.append(
            "shared-kernel-jobs: kernel output sha256 is not "
            "steps.kernel-hash.outputs.sha256"
        )
    hash_steps = [s for s in (job.get("steps") or [])
                  if isinstance(s, dict) and s.get("id") == "kernel-hash"]
    if len(hash_steps) != 1:
        problems.append("shared-kernel-jobs: kernel job has no kernel-hash step")
    else:
        script = hash_steps[0].get("run") or ""
        for needle in ("kernel.build-flags", "kernel.sha256", "GITHUB_OUTPUT"):
            if needle not in script:
                problems.append(
                    f"shared-kernel-jobs: kernel-hash step does not write {needle}"
                )
    found = False
    for step in job.get("steps") or []:
        name, paths = upload_paths(step)
        if name != ARTIFACT:
            continue
        found = True
        missing = [f for f in ARTIFACT_FILES if f not in paths]
        if missing:
            problems.append(
                "shared-kernel-jobs: kernel artifact is missing " + ", ".join(missing)
            )
        with_ = step.get("with") or {}
        if with_.get("if-no-files-found") != "error":
            problems.append(
                "shared-kernel-jobs: kernel artifact upload does not fail when empty"
            )
    if not found:
        problems.append(
            f"shared-kernel-jobs: kernel job does not upload {ARTIFACT}"
        )
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        uses = step.get("uses") or ""
        if uses == ACTION_USES or "actions/download-artifact@" in uses:
            problems.append(
                "shared-kernel-jobs: kernel job downloads an image it is supposed to build"
            )
            break
    return problems


def consumer_problems(name, job):
    problems = []
    if not needs_kernel(job):
        problems.append(f"shared-kernel-jobs: needs {name} does not need kernel")
    steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
    checkout_at = None
    action_at = None
    for i, step in enumerate(steps):
        if checkout_at is None and step_is_checkout(step):
            checkout_at = i
        if action_step(step):
            action_at = i
            with_ = step.get("with") or {}
            if with_.get("sha256") != HASH_EXPR:
                problems.append(
                    f"shared-kernel-jobs: hash {name} is not the producing job's output"
                )
    if action_at is None:
        problems.append(f"shared-kernel-jobs: action {name} does not take the shared kernel")
    elif checkout_at is None:
        problems.append(f"shared-kernel-jobs: action {name} has no checkout before the download")
    elif action_at != checkout_at + 1:
        problems.append(
            f"shared-kernel-jobs: action {name} is not the step after checkout"
        )
    for i, step in enumerate(steps):
        inv = list(make_invocations(step.get("run")))
        if inv and (action_at is None or i < action_at):
            problems.append(
                f"shared-kernel-jobs: action {name} runs make before the image is checked"
            )
            break
    return problems


def witness_problems(job, targets):
    problems = []
    seen = set()
    for _step, args in job_invocations(job):
        classified = _make_tokens("make " + args.strip())
        if classified is None:
            continue
        foreign, dynamic, goals = classified
        if foreign or dynamic:
            continue
        for goal in goals:
            if goal in WITNESS_GOALS:
                seen.add(goal)
    for goal in WITNESS_GOALS:
        if goal not in seen:
            problems.append(
                f"shared-kernel-jobs: witness {goal} is not run by the smoke job"
            )
        elif goal == "smoke-shared-kernel" and goal not in targets:
            problems.append(
                "shared-kernel-jobs: witness smoke-shared-kernel is not a default-kernel target"
            )
    return problems


def action_file_problems(root):
    path = root / ".github/actions/shared-kernel/action.yml"
    if not path.is_file():
        return ["shared-kernel-jobs: action file is missing"]
    text = path.read_text(encoding="utf-8")
    problems = []
    if DOWNLOAD_PIN not in text:
        problems.append("shared-kernel-jobs: action does not pin download-artifact v7")
    if ARTIFACT not in text:
        problems.append("shared-kernel-jobs: action does not download the default kernel artifact")
    if "SHARED_KERNEL" not in text or "SHARED_KERNEL_SHA256" not in text:
        problems.append("shared-kernel-jobs: action does not export the image it checked")
    # The sibling hash file must not be what the action trusts. The input is.
    if "inputs.sha256" not in text:
        problems.append("shared-kernel-jobs: action does not check the hash it was given")
    return problems


def analyse(root):
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    workflow = yaml.safe_load((root / CI_REL).read_text(encoding="utf-8")) or {}
    jobs = workflow.get("jobs") or {}
    targets, _expanded, _env = default_targets(makefile)
    would = {name for name, job in jobs.items()
             if isinstance(job, dict) and uses_default_kernel(job, targets)}
    return jobs, targets, would


def problems_for(root):
    jobs, targets, would = analyse(root)
    problems = []
    problems.extend(action_file_problems(root))
    if PRODUCER not in jobs:
        problems.append("shared-kernel-jobs: kernel job is missing")
    else:
        if PRODUCER not in would:
            problems.append(
                "shared-kernel-jobs: kernel job does not build the default kernel"
            )
        problems.extend(kernel_job_problems(jobs[PRODUCER]))
    leaked = sorted(would & OWN_BUILD)
    for name in leaked:
        problems.append(
            f"shared-kernel-jobs: {name} was classified as a default-kernel job"
        )
    consumers = would - {PRODUCER} - OWN_BUILD
    if not consumers:
        problems.append("shared-kernel-jobs: none")
    if WITNESS_JOB not in consumers:
        problems.append(
            "shared-kernel-jobs: smoke is not classified as a default-kernel job"
        )
    for name in sorted(consumers):
        problems.extend(consumer_problems(name, jobs[name]))
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
        uses_action = any(action_step(s) for s in steps)
        if uses_action and name not in consumers:
            problems.append(
                f"shared-kernel-jobs: altconfigs {name} is not a default-kernel job"
                if name == "altconfigs"
                else f"shared-kernel-jobs: action {name} is not a default-kernel job"
            )
    if WITNESS_JOB in jobs and isinstance(jobs[WITNESS_JOB], dict):
        problems.extend(witness_problems(jobs[WITNESS_JOB], targets))
    return problems, consumers


def audit(root):
    """Print make lines this checker did not treat as the default kernel."""
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    workflow = yaml.safe_load((root / CI_REL).read_text(encoding="utf-8")) or {}
    jobs = workflow.get("jobs") or {}
    targets, expanded, _env = default_targets(makefile)
    print(f"default targets: {len(targets)}")
    suspicious = []
    for name, lines in sorted(expanded.items()):
        if name in targets:
            continue
        for line in lines:
            if "$(MAKE)" in line or re.search(r"(^|[^A-Za-z0-9_])make\b", line):
                suspicious.append((name, line.strip()[:160]))
                break
    print(f"recipes that mention make and are not default targets: {len(suspicious)}")
    for name, line in suspicious:
        print(f"  target {name}: {line}")
    print("workflow make lines that are not the default kernel:")
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for _step, args in job_invocations(job):
            if invocation_uses_default(args, targets):
                continue
            text = "make " + args.strip()
            if len(text) > 160:
                text = text[:160]
            print(f"  job {name}: {text}")


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--root", type=pathlib.Path, default=ROOT)
    p.add_argument("--list", action="store_true",
                   help="print consumer jobs and do not require them to be wired")
    p.add_argument("--audit", action="store_true",
                   help="print make lines that were not classified as the default kernel")
    args = p.parse_args(argv)
    root = args.root
    if args.audit:
        audit(root)
        return 0
    if args.list:
        _jobs, _targets, would = analyse(root)
        consumers = sorted(would - {PRODUCER} - OWN_BUILD)
        for name in consumers:
            print(name)
        print(f"shared-kernel-jobs: list {len(consumers)}", file=sys.stderr)
        return 0 if consumers else 1
    problems, consumers = problems_for(root)
    if problems:
        for item in problems:
            print(item)
        return 1
    print(f"shared-kernel-jobs: ok {len(consumers)} jobs")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
