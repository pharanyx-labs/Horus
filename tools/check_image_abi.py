#!/usr/bin/env python3
"""check_image_abi.py -- the `.bin` container format has exactly one declaration.

WHY THIS FILE EXISTS.

Until 2026-09-03 the Horus program-image container was written down FOUR times
and no two copies were connected (docs/LIMITATIONS.md 2.18):

  - `struct program_header` in src/include/kernel.h -- an ELF program header with
    four Horus fields appended, 104 bytes, `magic` at offset 96;
  - `struct program_header` in include/syscall.h -- the staging header alone, 44
    bytes, `magic` at offset 0. Same name, different layout, no compiler seeing
    both;
  - a private copy inside tools/mkheadered.c, the tool that writes every `.bin`
    and therefore the only one of the four that actually DEFINED the format;
  - and the two readers in src/kernel/loader.c used none of them, assembling the
    fields from the literals 0, 4, 8, 12 and 44 with 0x55524F48 spelled out at
    each site.

The three copies that mattered -- one writer, two parsers -- agreed only because
somebody kept them in step by hand. S71 had already proved what that costs one
subsystem over, and include/block_size.h had proved it before that: 512 was not a
constant but an assumption repeated in six places.

They are one declaration now (include/program_abi.h, `struct horus_image_header`)
and this file is what stops a second one appearing. The runtime half is
`make smoke-image-abi`, which arms a real boot module and requires every field to
survive the round trip; that proves the bytes on disk came from the declaration,
which no amount of static checking can. This proves there is only one to come
from.

WHAT IT DOES NOT CHECK. Not every use of the number 44 -- a checker that fired on
an unrelated `44` would be noise, and noise is how a gate gets ignored. The two
rules here are precise: nobody else declares this struct, and nobody else spells
the magic. A parser written against the format has to do one or the other.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ABI_HEADER = ROOT / "include" / "program_abi.h"

# Where the format is allowed to be named. Only these two, and the second only
# because it is the file that explains why the first exists.
MAGIC_ALLOWED = {"include/program_abi.h"}
STRUCT_ALLOWED = {"include/program_abi.h"}

# Source we own. Vendored trees carry their own formats and are not ours to gate.
SEARCH_DIRS = ["src", "include", "userspace", "tools"]
SKIP_PARTS = {"ports", "newlib", "third_party", "vendor"}
SUFFIXES = {".c", ".h"}

MAGIC = re.compile(r"0x55524F48", re.I)
# A struct definition whose body declares the container's four fields, whatever
# it is called -- a rename is not an escape, because the defect was never the
# name. Non-greedy to the first closing brace at column 0 or `};`.
STRUCT_BODY = re.compile(r"(?:typedef\s+)?struct\s+(\w+)\s*\{(.*?)\}", re.S)
FIELDS = ("magic", "entry", "size", "name")


def sources():
    for d in SEARCH_DIRS:
        for p in sorted((ROOT / d).rglob("*")):
            if p.suffix not in SUFFIXES or not p.is_file():
                continue
            if SKIP_PARTS & set(p.relative_to(ROOT).parts):
                continue
            yield p


def strip_comments(text):
    """Block and line comments out, so prose describing the old layout is not a
    finding. This file's own history is written up in several comments that name
    the magic and the fields; a checker that flagged them would make recording
    the defect impossible, which is the opposite of the point."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def main():
    problems = []

    # SELF-CHECK FIRST. Both rules below are satisfied trivially if this file
    # stops finding the declaration it is protecting -- a renamed header, a moved
    # struct, a regex that no longer matches. That failure would be silent and
    # would look exactly like success.
    if not ABI_HEADER.exists():
        print(f"FAIL: {ABI_HEADER.relative_to(ROOT)} does not exist.")
        print("      A checker whose subject is missing passes everything.")
        return 1
    abi_src = ABI_HEADER.read_text(encoding="utf-8")
    if not re.search(r"struct\s+horus_image_header\s*\{", abi_src):
        problems.append(
            "include/program_abi.h no longer defines `struct horus_image_header`. "
            "If the container was renamed or moved, teach this file where it went "
            "-- both rules below compare against it and are vacuous without it")
    if not MAGIC.search(abi_src):
        problems.append(
            "include/program_abi.h no longer spells 0x55524F48. The magic must be "
            "defined exactly once, and this is where")

    scanned = 0
    for p in sources():
        rel = p.relative_to(ROOT).as_posix()
        scanned += 1
        body = strip_comments(p.read_text(encoding="utf-8", errors="replace"))

        # RULE 1: the magic is spelled in one place.
        if MAGIC.search(body) and rel not in MAGIC_ALLOWED:
            problems.append(
                f"{rel}: spells the container magic 0x55524F48. It is defined once, as "
                f"HORUS_IMAGE_MAGIC in include/program_abi.h -- a second spelling is a "
                f"second parser, which is what docs/LIMITATIONS.md 2.18 was about")

        # RULE 2: nobody re-declares the container, under any name.
        if rel in STRUCT_ALLOWED:
            continue
        for name, fields in STRUCT_BODY.findall(body):
            decl = {f for f in FIELDS if re.search(r"\b" + f + r"\s*(\[|;)", fields)}
            if len(decl) == len(FIELDS):
                problems.append(
                    f"{rel}: `struct {name}` declares {', '.join(FIELDS)} -- that is the "
                    f"`.bin` container redeclared. Include include/program_abi.h and use "
                    f"`struct horus_image_header`; a rename is not a fix, because the "
                    f"defect was four copies rather than four names")

    if problems:
        print("FAIL: check_image_abi")
        for pr in problems:
            print("  - " + pr)
        return 1

    print(f"files scanned             : {scanned}")
    print(f"declarations of the format: 1 (include/program_abi.h)")
    print(f"spellings of the magic    : 1 (HORUS_IMAGE_MAGIC)")
    print("\nPASS: the .bin container has exactly one declaration")
    return 0


if __name__ == "__main__":
    sys.exit(main())
