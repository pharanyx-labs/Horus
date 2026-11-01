#!/usr/bin/env python3
"""Run the vendored Semgrep ruleset, and fail when it matches.

The rules live in `.semgrep/horus.yml`. They describe traps this tree has
already shipped. A registry ruleset is not used here: those rules are not
this repository's, and they change with no commit.

Semgrep's C parser does not know which `#ifdef` the ship build compiles, so
a control arm (`#ifdef LEGACY_SYSCALLS_PRESENT` and the rest of
`check_dispatch_gates.SHIP_ABSENT`) looks like live code. This runner blanks
a region only when every identifier in its condition is one of those macros
and the condition is false for the ship build. A condition it cannot decide
is left in place, so an unknown guard cannot hide a hit. `#ifndef` of an
absent macro is the ship build, and is kept.

A missing `semgrep` is a failure. A scan that found nothing because the tool
was not there used to look like a clean tree.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / ".semgrep" / "horus.yml"

DEFAULT_PATHS = [
    "src",
    "include",
    "userspace/init.c",
    "userspace/fs_server.c",
    "userspace/console_server.c",
]

_DIRECTIVE = re.compile(r"^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$")


def _ship_absent() -> set[str]:
    path = ROOT / "tools" / "check_dispatch_gates.py"
    spec = importlib.util.spec_from_file_location("check_dispatch_gates", path)
    if spec is None or spec.loader is None:
        sys.exit("semgrep_horus: cannot load check_dispatch_gates.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    absent = getattr(mod, "SHIP_ABSENT", None)
    if not isinstance(absent, set) or not absent:
        sys.exit("semgrep_horus: SHIP_ABSENT is missing or empty")
    return set(absent)


def _split_top(expr: str, op: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and expr.startswith(op, i):
            parts.append(expr[start:i])
            i += len(op)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return parts


def _eval_expr(expr: str, absent: set[str]) -> bool | None:
    """True if the ship build compiles the region, False if it does not.

    None means the condition names a macro this runner does not know, so the
    region stays. That is the failure direction: an unknown guard is not a
    licence to hide the body.
    """
    s = expr.strip()
    if not s:
        return None
    parts = _split_top(s, "||")
    if len(parts) > 1:
        vals = [_eval_expr(p, absent) for p in parts]
        if any(v is True for v in vals):
            return True
        if all(v is False for v in vals):
            return False
        return None
    parts = _split_top(s, "&&")
    if len(parts) > 1:
        vals = [_eval_expr(p, absent) for p in parts]
        if any(v is False for v in vals):
            return False
        if all(v is True for v in vals):
            return True
        return None
    s = s.strip()
    if s.startswith("!"):
        val = _eval_expr(s[1:], absent)
        if val is None:
            return None
        return not val
    if len(s) >= 2 and s[0] == "(" and s[-1] == ")":
        return _eval_expr(s[1:-1], absent)
    defined = re.fullmatch(r"defined\s*\(\s*([A-Za-z_][A-Za-z0-9]*)\s*\)", s)
    if defined:
        return False if defined.group(1) in absent else None
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9]*", s):
        return False if s in absent else None
    if s == "0":
        return False
    if s == "1":
        return True
    return None


def _condition(kind: str, rest: str, absent: set[str]) -> bool | None:
    rest = rest.strip()
    if kind == "ifdef":
        name = rest.split()[0] if rest else ""
        return False if name in absent else None
    if kind == "ifndef":
        name = rest.split()[0] if rest else ""
        # An absent macro's ifndef body is what the ship build compiles.
        return True if name in absent else None
    if kind in ("if", "elif"):
        return _eval_expr(rest, absent)
    return None


def blank_ship_absent(text: str, absent: set[str]) -> str:
    """Blank lines the ship build does not compile. Line count is unchanged."""
    out: list[str] = []
    # skip: this branch is not in the ship build.
    # taken: a definite branch of this frame was kept.
    # unknown: the condition could not be decided, so every branch is kept.
    stack: list[dict[str, bool]] = []

    def skipping() -> bool:
        return any(frame["skip"] for frame in stack)

    for line in text.splitlines(keepends=True):
        nl = "\n" if line.endswith("\n") else ""
        body = line[:-1] if nl else line
        match = _DIRECTIVE.match(body)
        if not match:
            if skipping():
                out.append("\n" if nl else "")
            else:
                out.append(line)
            continue
        kind, rest = match.group(1), match.group(2)
        if kind in ("if", "ifdef", "ifndef"):
            parent = skipping()
            cond = _condition(kind, rest, absent)
            if parent:
                frame = {"skip": True, "taken": False, "unknown": False, "parent": True}
            elif cond is False:
                frame = {"skip": True, "taken": False, "unknown": False, "parent": False}
            elif cond is True:
                frame = {"skip": False, "taken": True, "unknown": False, "parent": False}
            else:
                frame = {"skip": False, "taken": False, "unknown": True, "parent": False}
            stack.append(frame)
            out.append(nl if frame["skip"] else line)
            continue
        if kind == "elif" and stack:
            frame = stack[-1]
            cond = _condition("elif", rest, absent)
            if frame["parent"] or frame["taken"]:
                frame["skip"] = True
            elif frame["unknown"] or cond is None:
                frame["unknown"] = True
                frame["skip"] = False
            elif cond is True:
                frame["skip"] = False
                frame["taken"] = True
                frame["unknown"] = False
            else:
                frame["skip"] = True
            out.append(nl if frame["skip"] else line)
            continue
        if kind == "else" and stack:
            frame = stack[-1]
            if frame["parent"] or frame["taken"]:
                frame["skip"] = True
            elif frame["unknown"]:
                frame["skip"] = False
            else:
                frame["skip"] = False
                frame["taken"] = True
            out.append(nl if frame["skip"] else line)
            continue
        if kind == "endif" and stack:
            frame = stack.pop()
            out.append(nl if frame["skip"] else line)
            continue
        out.append("\n" if skipping() else line)
    return "".join(out)


def _sources(paths: list[str]) -> list[Path]:
    found: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if not path.is_absolute():
            path = ROOT / path
        if path.is_file() and path.suffix in {".c", ".h"}:
            found.append(path)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file() and child.suffix in {".c", ".h"}:
                    found.append(child)
        else:
            sys.exit(f"semgrep_horus: not a C file or directory: {raw}")
    if not found:
        sys.exit("semgrep_horus: no C files to scan")
    return found


def main(argv: list[str]) -> int:
    if shutil.which("semgrep") is None:
        print("semgrep is NOT INSTALLED -- that is a broken scan, not a clean one", file=sys.stderr)
        return 2
    if not RULES.is_file():
        print(f"semgrep_horus: rules missing: {RULES}", file=sys.stderr)
        return 2
    absent = _ship_absent()
    paths = argv if argv else DEFAULT_PATHS
    sources = _sources(paths)
    with tempfile.TemporaryDirectory(prefix="horus-semgrep-") as tmp:
        staged = Path(tmp)
        for src in sources:
            try:
                rel = src.relative_to(ROOT)
            except ValueError:
                rel = Path(src.name)
            dest = staged / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(blank_ship_absent(src.read_text(errors="replace"), absent))
        proc = subprocess.run(
            [
                "semgrep",
                "--metrics=off",
                "--disable-version-check",
                "--error",
                "--quiet",
                "--config",
                str(RULES),
                str(staged),
            ],
            check=False,
        )
        return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
