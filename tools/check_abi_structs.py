#!/usr/bin/env python3
"""Fail the build if an ABI struct differs between the two headers.

Structs cross the ring-3 boundary written down TWICE -- once in
`src/include/kernel.h` for the kernel and once in `include/syscall.h` for
userspace -- because the two headers are compiled into different worlds and
neither includes the other.

THE LIST IS DISCOVERED, NOT TYPED. It used to be a fixed enumeration, and a
fixed enumeration is a list that goes stale silently: a struct added to both
headers after it was written is a struct nothing compares. Every name defined in
both headers is now found and must be enrolled in `SHARED` or in `UNRESOLVED`
with a written finding, so a new one fails the build rather than slipping past.
That is the gate that would have caught S71.

Nothing compared them at all before 2026-08-30, and that audit found the seven
that existed then in agreement, so this began as a latent risk rather than a live
defect -- and that is the moment to gate it,
because the failure mode is silent and the tree already knows the shape:
`check_capslots.py` exists because the cspace slot map is written twice and
drifted, and `CAPSLOT_DEBUG` was added as a number `CAPSLOT_UNTYPED` already
held.

WHAT DRIFT WOULD DO HERE. Every one of these structs is filled by the kernel and
copied to a user buffer with `copy_to_user`, sized by the KERNEL's definition. If
userspace's copy is shorter, the kernel writes past the end of a ring-3 buffer
that ring 3 sized correctly against the header it was given. If a field moves,
the caller reads a different field than the kernel wrote -- and for `dev_info`
that is the MMIO ranges a driver is about to map, while for `cap_info` it is the
rights and serial a supervisor is about to make a decision on. Neither shows up
as a compile error, because neither compiler sees both files.

The comparison is on the sequence of (type, name) pairs, which catches a field
added, removed, renamed, retyped or reordered. It deliberately does NOT check
sizeof or offsets: those are properties of a compilation, not of a header, and
the two are compiled with different flags. A `_Static_assert` on `sizeof` in each
header would be the stronger check and is worth having; it is not what this is.

THE LIST WAS HAND-MAINTAINED, AND THAT IS HOW IT MISSED THE ONE THAT HAD DRIFTED.
On 2026-09-01 `struct audit_event` turned out to be the eighth struct crossing this
boundary -- 256 bytes in kernel.h, 72 in syscall.h, one name -- and `h_read_audit`
copied the kernel's size at the kernel's stride into an array ring 3 had sized
with the other. Exactly the failure this file describes, in a struct this file did
not know about, while it passed on the seven it did. It was never enrolled because
enrolling is a thing somebody has to remember; the seven came from an audit sweep
and the eighth was not in that sweep's output.

So the declared list is no longer the whole check. `main()` now also DISCOVERS
every struct defined in both headers and fails on one that is in neither `SHARED`
nor `UNRESOLVED` -- the question "is this struct enrolled?" is asked by the tool
rather than by whoever last added one. The declared list stays, because discovery
alone cannot notice a struct DISAPPEARING from one header, which is its own kind
of drift. The two rules catch opposite mistakes and both are needed.

Discovery found four more that were simply never enrolled and do agree (`fs_stat`,
`task_info`, `irq_policy_info`, `irq_policy_site_info`), and one that does not:
see `UNRESOLVED`.

Exit 0 if every shared struct agrees and every discovered one is enrolled, 1
otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL_H = ROOT / "src" / "include" / "kernel.h"
SYSCALL_H = ROOT / "include" / "syscall.h"

# Declared rather than discovered, so that a struct DISAPPEARING from one header
# is a failure too. Discovery would silently start checking nothing.
SHARED = [
    "dev_info",
    "storage_info",
    "shlib_info",
    "untyped_info",
    "cap_info",
    "horus_timespec",
    "boot_module_info",
    "task_exit_info",
    # Found by the discovery rule below on 2026-09-01, not by anyone noticing.
    # All four agree and always have; they were simply never enrolled, which is
    # the failure mode `audit_event` turned into a defect.
    "fs_stat",
    "task_info",
    "irq_policy_info",
    "irq_policy_site_info",
]

# Structs defined in BOTH headers that do NOT agree, each with the finding that
# records it. This is an exemption list and it is deliberately uncomfortable to
# add to: an entry here is an open defect, not a naming convention, and the
# checker fails if one of these starts AGREEING -- at which point it belongs in
# SHARED and the finding is closed.
UNRESOLVED = {
    "program_header": (
        "docs/LIMITATIONS.md 2.18. The kernel's is an ELF program header with "
        "four Horus staging fields appended (104 bytes); ring 3's is the staging "
        "header alone (44). h_receive_program copies the kernel's size, so the "
        "shell's `receive` would overrun its own 44-byte stack object by 60 "
        "bytes -- except that the SUCCESS PATH IS UNREACHABLE: "
        "loader_receive_to_staging reads sizeof(hdr) = 104 bytes off serial "
        "where the uploader sends 44 plus payload, so `magic` is tested against "
        "payload bytes and the transfer answers 'Bad magic' every time. Broken "
        "rather than dangerous, and a transport decision rather than a struct "
        "rename, so it is filed rather than fixed here."
    ),
}

FIELD = re.compile(r"^\s+((?:const\s+)?[A-Za-z_][A-Za-z_0-9]*)\s+([A-Za-z_][A-Za-z_0-9]*)\s*(\[[^\]]*\])?\s*;")


def fields(path, name):
    """The (type, name, array) triples of `struct name`, or None if absent."""
    text = path.read_text(encoding="utf-8")
    # `typedef struct X {` as well as `struct X {`. Anchoring on the latter
    # alone silently returned None for a typedef'd struct, which for a DISCOVERED
    # struct would have looked like "not defined in this header" -- the checker
    # excusing itself from the comparison. program_header is declared that way.
    m = re.search(r"^(?:typedef\s+)?struct\s+" + re.escape(name) + r"\s*\{(.*?)^\}",
                  text, re.S | re.M)
    if not m:
        return None
    out = []
    for line in m.group(1).split("\n"):
        # Skip comment-only lines; a trailing comment after a field is fine
        # because the regex anchors on the semicolon.
        if line.strip().startswith(("/*", "*", "//")):
            continue
        f = FIELD.match(line)
        if f:
            out.append((f.group(1), f.group(2), f.group(3) or ""))
    return out


STRUCT_DEF = re.compile(r"^(?:typedef\s+)?struct\s+([A-Za-z_]\w*)\s*\{", re.M)


def defined_in_both():
    """Struct names defined in BOTH headers -- the ones that cross the boundary."""
    k = set(STRUCT_DEF.findall(KERNEL_H.read_text(encoding="utf-8")))
    s = set(STRUCT_DEF.findall(SYSCALL_H.read_text(encoding="utf-8")))
    return k & s


def main():
    problems = []
    checked = 0

    # RULE 2, and the one that would have caught audit_event: no struct crosses
    # this boundary without being enrolled. Asked of the headers rather than of
    # whoever last edited them.
    discovered = defined_in_both()
    for name in sorted(discovered - set(SHARED) - set(UNRESOLVED)):
        problems.append(
            f"struct {name}: defined in BOTH headers and enrolled in neither "
            f"SHARED nor UNRESOLVED. Every struct that crosses this boundary is "
            f"copied by the kernel at the KERNEL's size; add it to SHARED, or to "
            f"UNRESOLVED with the finding that records why it disagrees")
    for name in sorted(set(SHARED) | set(UNRESOLVED)):
        if name not in discovered:
            problems.append(
                f"struct {name}: enrolled, but no longer defined in both headers. "
                f"If it stopped crossing the boundary, remove it from the list on "
                f"purpose -- an enrolled name that compares nothing is a check "
                f"that cannot fail")

    # RULE 3: an UNRESOLVED entry is an open defect. If it starts agreeing, the
    # defect is fixed and it belongs in SHARED -- say so rather than letting an
    # exemption outlive its reason.
    for name, why in sorted(UNRESOLVED.items()):
        k = fields(KERNEL_H, name)
        s = fields(SYSCALL_H, name)
        if k is not None and s is not None and k == s:
            problems.append(
                f"struct {name}: listed UNRESOLVED but the two headers now AGREE. "
                f"Move it to SHARED and close the finding. Its reason was: {why}")

    for name in SHARED:
        k = fields(KERNEL_H, name)
        s = fields(SYSCALL_H, name)
        if k is None:
            problems.append(f"struct {name}: not found in {KERNEL_H.relative_to(ROOT)}")
            continue
        if s is None:
            problems.append(f"struct {name}: not found in {SYSCALL_H.relative_to(ROOT)}")
            continue
        checked += 1
        if k != s:
            problems.append(f"struct {name}: the two headers disagree")
            for i in range(max(len(k), len(s))):
                a = k[i] if i < len(k) else None
                b = s[i] if i < len(s) else None
                if a != b:
                    fmt = lambda t: "(absent)" if t is None else f"{t[0]} {t[1]}{t[2]}"
                    problems.append(f"    field {i}: kernel.h has {fmt(a)}, "
                                    f"syscall.h has {fmt(b)}")

    print(f"structs in both headers : {len(discovered)}")
    print(f"  enrolled SHARED       : {len(SHARED)}")
    print(f"  compared              : {checked}")
    print(f"  UNRESOLVED (open)     : {len(UNRESOLVED)}")
    for name in sorted(UNRESOLVED):
        print(f"      {name}: known to disagree, see the reason in this file")

    if problems:
        print("\nFAIL: an ABI struct is not the same in both headers\n")
        for p in problems:
            print(f"  - {p}")
        print("\nThe kernel fills these and copies them to a ring-3 buffer sized by "
              "the OTHER definition. Neither compiler sees both files.")
        return 1

    print("\nPASS: every struct crossing the boundary is enrolled, and every "
          "enrolled-as-shared one is identical in both headers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
