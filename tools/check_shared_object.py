#!/usr/bin/env python3
"""check_shared_object.py -- the two properties src/kernel/shlib.c requires.

WHY THIS IS A STATIC GATE AND NOT A BOOT TEST.

`shlib_init` refuses an object it cannot fully relocate: anything but
`R_X86_64_RELATIVE` fails the load, and so does an object whose segments do not
fit. A refusal at boot is the correct behaviour and a terrible diagnostic --
the library simply is not there, and the first symptom is a task faulting on a
call into an address nothing mapped.

The properties are decidable by reading the object, so they are read here, in
milliseconds, at build time, where the error names the cause.

WHAT IT CHECKS, AND WHY EACH ONE HAS BITTEN

  1. Only R_X86_64_RELATIVE.  Measured while building the shared libc: linking
     without the port's syscall glue leaves 10 undefined symbols and 10
     R_X86_64_JUMP_SLOT; without -Bsymbolic, intra-library calls become
     GLOB_DAT; and ONE weak-undefined symbol (`__on_exit_args`) is enough to
     emit a GLOB_DAT on its own unless -z nodynamic-undefined-weak is passed.
     Three separate ways to produce an object the kernel will not load, none of
     which is a link error.

  2. No undefined symbols.  A shared object here is loaded by a kernel that
     resolves nothing by name. An undefined symbol is not a link-time
     convenience to be satisfied later; there IS no later.

  3. It fits SHLIB_MAX_PAGES.  Read from src/include/kernel.h rather than
     written down, so the two cannot drift.

  4. Exactly one writable PT_LOAD, page-aligned away from the read-only ones.
     S50 gives each task a private copy of the writable segment, at page
     granularity. A writable segment sharing a page with a read-only one cannot
     be made private without also privatising shared text.

Usage: check_shared_object.py <object.so> [<object.so> ...]
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = 4096


def kernel_max_pages() -> int:
    """SHLIB_MAX_PAGES, read from the header rather than duplicated here."""
    hdr = (ROOT / "src/include/kernel.h").read_text()
    m = re.search(r"#define\s+SHLIB_MAX_PAGES\s+(\d+)", hdr)
    if not m:
        sys.exit("check_shared_object: SHLIB_MAX_PAGES not found in src/include/kernel.h")
    return int(m.group(1))


def readelf(*args: str) -> str:
    try:
        return subprocess.run(["readelf", *args], capture_output=True, text=True,
                              check=True).stdout
    except FileNotFoundError:
        sys.exit("check_shared_object: readelf not found")
    except subprocess.CalledProcessError as e:
        sys.exit(f"check_shared_object: readelf failed: {e.stderr.strip()}")


def check(path: Path, max_pages: int) -> list[str]:
    problems: list[str] = []

    # ---- 1. relocation types ------------------------------------------------
    types: dict[str, int] = {}
    for line in readelf("-rW", str(path)).splitlines():
        f = line.split()
        if len(f) > 2 and f[2].startswith("R_"):
            types[f[2]] = types.get(f[2], 0) + 1
    bad = {t: n for t, n in types.items() if t != "R_X86_64_RELATIVE"}
    if bad:
        detail = ", ".join(f"{n}x {t}" for t, n in sorted(bad.items()))
        problems.append(
            f"{path}: {detail} -- shlib_init accepts only R_X86_64_RELATIVE and "
            f"refuses the whole object. Usually a missing -Wl,-Bsymbolic, an "
            f"unlinked glue object, or a weak-undefined symbol needing "
            f"-Wl,-z,nodynamic-undefined-weak")

    # ---- 2. undefined symbols ----------------------------------------------
    #
    # `nm --undefined-only` over the .so: the kernel resolves nothing by name,
    # so there is no later at which these could be satisfied.
    try:
        out = subprocess.run(["nm", "--undefined-only", str(path)],
                             capture_output=True, text=True, check=False).stdout
        undef = [l.split()[-1] for l in out.splitlines() if l.strip()]
    except FileNotFoundError:
        sys.exit("check_shared_object: nm not found")
    if undef:
        shown = ", ".join(undef[:8]) + (" ..." if len(undef) > 8 else "")
        problems.append(
            f"{path}: {len(undef)} undefined symbol(s): {shown} -- nothing "
            f"resolves these at load time; link the object that defines them in")

    # ---- 3/4. segments ------------------------------------------------------
    loads = []
    for line in readelf("-lW", str(path)).splitlines():
        f = line.split()
        if not f or f[0] != "LOAD":
            continue
        # type offset vaddr paddr filesz memsz flags... align
        vaddr, memsz = int(f[2], 16), int(f[5], 16)
        flags = "".join(f[6:-1])
        loads.append((vaddr, memsz, flags))
    if not loads:
        problems.append(f"{path}: no PT_LOAD segments")
        return problems

    hi = max(v + m for v, m, _ in loads)
    pages = (hi + PAGE - 1) // PAGE
    if pages > max_pages:
        problems.append(
            f"{path}: needs {pages} pages, SHLIB_MAX_PAGES is {max_pages} -- "
            f"shlib_init refuses it")

    writable = [(v, m) for v, m, fl in loads if "W" in fl]
    if len(writable) != 1:
        problems.append(
            f"{path}: {len(writable)} writable PT_LOAD(s), expected exactly 1 -- "
            f"S50 instantiates the writable segment per task and needs one to name")
    else:
        wv, wm = writable[0]
        if wv % PAGE != 0:
            problems.append(
                f"{path}: writable segment starts at 0x{wv:x}, not page-aligned -- "
                f"it would share a page with read-only data, which cannot then be "
                f"made per-task without privatising shared text too")
        wpages = set(range((wv) // PAGE, (wv + max(wm, 1) - 1) // PAGE + 1))
        for v, m, fl in loads:
            if "W" in fl or m == 0:
                continue
            ro = set(range(v // PAGE, (v + m - 1) // PAGE + 1))
            if ro & wpages:
                problems.append(
                    f"{path}: read-only and writable segments share page(s) "
                    f"{sorted(ro & wpages)} -- see above")
                break

    return problems


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    max_pages = kernel_max_pages()
    problems: list[str] = []
    for arg in sys.argv[1:]:
        p = Path(arg)
        if not p.is_file():
            problems.append(f"{p}: not found")
            continue
        problems += check(p, max_pages)

    if problems:
        print("\nFAIL: an object the kernel's shared-library loader would refuse\n")
        for p in problems:
            print(f"  - {p}")
        print("\nThe loader is the truth; fix the link, not this checker.")
        return 1

    n = len(sys.argv) - 1
    print(f"objects checked : {n}")
    print(f"SHLIB_MAX_PAGES : {max_pages}")
    print("\nPASS: every shared object is one the kernel's loader accepts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
