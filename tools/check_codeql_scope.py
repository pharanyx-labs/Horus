#!/usr/bin/env python3
"""The CodeQL job traces the trusted userspace, and does not call itself advisory.

CodeQL analyse is a required check. The workflow header used to say the job
was advisory and not a merge gate. That sentence was false, and a false
sentence on a required check is how a reader learns to ignore it.

`make`, the build step, links kernel.elf. kernel.elf needs $(OBJS), which
starts with src/boot/multiboot.o, and that object lists userspace/init.bin,
fs_server.bin and console_server.bin. Those three are in SHIPPED_PIE_BINS,
whose recipe is the static-PIE path from userspace/%.c via $(CC). So the
default `make` compiles init, fs_server and console_server, which is the
trusted userspace, and CodeQL's tracer sees that compile. A build step that
names some other target, or a Makefile that drops one of the three, fails
here. This does not add a second ISO build: the ISO's extra programs are
outside the trusted computing base, and the three that are inside it are
already on the kernel link.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRUSTED = (
    "userspace/init.bin",
    "userspace/fs_server.bin",
    "userspace/console_server.bin",
)
FALSE_CLAIMS = (
    "Advisory by design",
    "NOT one of the merge hard-gates",
    "does NOT gate merges",
)


def fail(msg: str) -> None:
    print(f"check_codeql_scope: {msg}", file=sys.stderr)
    sys.exit(1)


def build_step(workflow: str) -> str:
    """The run block of the step that builds the kernel CodeQL traces."""
    marker = "- name: Build kernel.elf"
    at = workflow.find(marker)
    if at < 0:
        fail("codeql.yml has no 'Build kernel.elf' step")
    rest = workflow[at + len(marker):]
    nxt = rest.find("\n      - name:")
    block = rest if nxt < 0 else rest[:nxt]
    match = re.search(r"\n        run:\s*(.*)", block)
    if not match:
        fail("the Build kernel.elf step has no run key")
    return match.group(1).strip()


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT
    workflow_path = root / ".github" / "workflows" / "codeql.yml"
    makefile_path = root / "Makefile"
    if not workflow_path.is_file() or not makefile_path.is_file():
        fail(f"missing codeql.yml or Makefile under {root}")
    workflow = workflow_path.read_text()
    makefile = makefile_path.read_text()
    for claim in FALSE_CLAIMS:
        if claim in workflow:
            fail(f"codeql.yml still says {claim!r}. The job is a required check.")
    step = build_step(workflow)
    # A block scalar (`run: |`) is not this step today. The one line is `make`.
    if step in {"|", ">", "|-", ">-"}:
        fail("the Build kernel.elf step's run block is not a single command")
    if step not in {"make", "make all", "make kernel.elf"}:
        fail(
            f"the Build kernel.elf step runs {step!r}, not the default make "
            "that compiles the trusted userspace"
        )
    if not makefile.startswith("OBJS = src/boot/multiboot.o") and \
            "\nOBJS = src/boot/multiboot.o" not in makefile:
        fail("OBJS does not start with src/boot/multiboot.o")
    if "kernel.elf: $(RUST_LIB) $(OBJS)" not in makefile:
        fail("kernel.elf does not depend on $(OBJS)")
    dep_line = next(
        (ln for ln in makefile.splitlines() if ln.startswith("src/boot/multiboot.o:")),
        "",
    )
    for name in TRUSTED:
        if name not in dep_line:
            fail(f"{name} is not a prerequisite of src/boot/multiboot.o")
    assign = re.search(r"SHIPPED_PIE_BINS\s*=(.*?)(?=\n\S)", makefile, re.S)
    if not assign:
        fail("SHIPPED_PIE_BINS is missing")
    for name in TRUSTED:
        if name not in assign.group(1):
            fail(f"{name} is not in SHIPPED_PIE_BINS, so make does not compile it for the kernel")
    if "userspace/%.o: userspace/%.c" not in makefile or "$(CC) $(USERSPACE_CFLAGS)" not in makefile:
        fail("userspace/%.c is not compiled with $(CC)")
    print("check_codeql_scope: the CodeQL build traces init, fs_server and console_server")


if __name__ == "__main__":
    main()
