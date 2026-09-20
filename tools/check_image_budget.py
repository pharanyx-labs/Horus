#!/usr/bin/env python3
"""The kernel's .bss is exactly its budget, and the image stays below the page pool.

Audit F2 (2026-09-19). linker64.ld asserts that the image ends below
USER_PHYS_BASE, because the physical page pool starts there. The assert fails
only when the line is crossed. Everything before that is silent, and the room
it guards is in use: GRUB stages the boot modules there, upward from the end of
the image. This makes growth a decision somebody writes down.

Three rules, each falsified by tools/test_check_image_budget.sh:

  R1  .bss (__bss_end - __bss_start) equals `bss_bytes` in
      .github/image-budget.yml EXACTLY. Larger: raise the budget and say why.
      Smaller: lower it, so the room is banked rather than left as slack. The
      budget is on .bss and not on the end of the image because the end moves
      with the compiler (12 KiB between CI and a Void build of the same tree)
      and .bss does not; the budget file has the measurement.

  R2  The literal in linker64.ld's .bss ASSERT equals USER_PHYS_BASE in
      src/include/kernel.h. A linker script cannot include a header, so the
      value is written twice, and until now the only thing keeping the two in
      step was a comment asking the reader to. Static; needs no ELF.

  R3  The image ends at or below USER_PHYS_BASE, read from the ELF: the
      linker ASSERT's own condition, checked independently of it, so deleting
      the ASSERT does not also delete the check. KERNEL_VMA comes from the
      image's own __kernel_vma_from_linker, not from a copy.

Every value this needs that cannot be found is a FAILURE, never a skip: a
checker that passes because it could not read its inputs is the vacuous gate
CLAUDE.md section 8 forbids.

Usage: check_image_budget.py <kernel.elf>
Exit 0 pass, 1 a rule failed, 2 usage.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUDGET_YML = ROOT / ".github/image-budget.yml"
LINKER = ROOT / "linker64.ld"
KERNEL_H = ROOT / "src/include/kernel.h"

SYMBOLS = ("__bss_start", "__bss_end", "__kernel_vma_from_linker")


def read_symbols(elf):
    """Map name -> value for the symbols this checker needs, via nm."""
    try:
        out = subprocess.run(["nm", "-P", str(elf)], capture_output=True,
                             text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        return None, f"nm could not read {elf}: {e}"
    syms = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] in SYMBOLS:
            syms[parts[0]] = int(parts[2], 16)
    missing = [s for s in SYMBOLS if s not in syms]
    if missing:
        return None, f"{elf} defines no {', '.join(missing)}"
    return syms, None


def read_int(path, pattern, what):
    m = re.search(pattern, path.read_text(), re.M)
    if not m:
        return None, f"could not find {what} in {path.relative_to(ROOT)}"
    return int(m.group(1), 0), None


def main(argv):
    if len(argv) != 2:
        print("usage: check_image_budget.py <kernel.elf>", file=sys.stderr)
        return 2
    elf = Path(argv[1])
    problems = []

    budget, err = read_int(BUDGET_YML, r"^bss_bytes:\s*(\d+)\s*$", "bss_bytes")
    if err:
        problems.append(err)
    user_phys_base, err = read_int(
        KERNEL_H, r"^#define\s+USER_PHYS_BASE\s+(0x[0-9A-Fa-f]+|\d+)\b",
        "#define USER_PHYS_BASE")
    if err:
        problems.append(err)
    linker_line, err = read_int(
        LINKER, r"^\s*ASSERT\(\s*__bss_end\s*-\s*KERNEL_VMA\s*<=\s*(0x[0-9A-Fa-f]+|\d+)\s*,",
        "the `__bss_end - KERNEL_VMA <= ...` ASSERT")
    if err:
        problems.append(err)
    syms, err = read_symbols(elf)
    if err:
        problems.append(err)

    # R2 needs only the two sources; report it even when the ELF is unreadable.
    if user_phys_base is not None and linker_line is not None \
            and linker_line != user_phys_base:
        problems.append(
            f"R2: linker64.ld's ASSERT stops the image at {linker_line:#x}, but "
            f"USER_PHYS_BASE in src/include/kernel.h is {user_phys_base:#x}. The "
            f"page pool starts at USER_PHYS_BASE, so the ASSERT is guarding the "
            f"wrong line. Change the two together.")

    if syms is not None:
        bss = syms["__bss_end"] - syms["__bss_start"]
        image_end = syms["__bss_end"] - syms["__kernel_vma_from_linker"]
        if budget is not None and bss != budget:
            delta = bss - budget
            if delta > 0:
                problems.append(
                    f"R1: .bss is {bss} bytes, {delta} over its budget of {budget}. "
                    f"Every byte comes out of the room below USER_PHYS_BASE, where "
                    f"GRUB stages the boot modules. If the growth is meant, raise "
                    f"bss_bytes in .github/image-budget.yml and say why in the commit.")
            else:
                problems.append(
                    f"R1: .bss is {bss} bytes, {-delta} under its budget of {budget}. "
                    f"Lower bss_bytes in .github/image-budget.yml to {bss}, so the "
                    f"room is banked rather than left for the next growth to absorb.")
        if user_phys_base is not None and image_end > user_phys_base:
            problems.append(
                f"R3: the image ends at physical {image_end:#x}, past "
                f"USER_PHYS_BASE ({user_phys_base:#x}): it overlaps the page pool.")

    if problems:
        print("FAIL: check_image_budget")
        for p in problems:
            print(f"  - {p}")
        return 1

    headroom = user_phys_base - image_end
    print(f".bss            : {bss} bytes ({bss // 1024} KiB), budget {budget}")
    print(f"image ends at   : {image_end:#x}, {headroom} bytes "
          f"({headroom / (1 << 20):.2f} MiB) below USER_PHYS_BASE {user_phys_base:#x}")
    print("PASS: .bss is exactly its budget, and the image stays below the page pool")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
