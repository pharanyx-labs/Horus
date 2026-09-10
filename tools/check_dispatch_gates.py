#!/usr/bin/env python3
"""check_dispatch_gates.py -- no ship-build syscall is gated on the [C-1] decoy.

WHY THIS FILE EXISTS.

`create_task` installs a `CAP_FRAME` in cspace slot 3 of EVERY task, with
exactly `READ|WRITE|EXEC`, naming a fixed window, asked for by nobody. A
dispatch row that reads

    [SYS_SOMETHING] = { handler, 3, CAP_RIGHT_WRITE|CAP_RIGHT_EXEC, SC_ANYTYPE }

is therefore not gated at all: it is satisfied by a capability every task is
born holding. That is finding [C-1]'s shape, and by S28 a gate every task passes
is not a gate.

IT HAS BEEN SWEPT THREE TIMES AND MISSED ROWS EVERY TIME, which is the argument
for a checker rather than a fourth sweep:

  - [H-3] (2026-08-22) removed SYS_OPEN, SYS_RAMFS_CREATE and SYS_RAMFS_LIST,
    and the comment it left in the table calls those "the last three".
  - #201 (2026-08-23) found a FOURTH, SYS_EXEC_LEGACY, which had escaped by
    being written `[14]` -- a bare index matching none of the `[SYS_NAME]`
    patterns every audit grep is built on.
  - Audit 4.1 (2026-08-30) moved the five task-creating syscalls to CAP_UNTYPED
    (S57), and its comment says the gate "was vacuous".

None of the three enumerated SYS_EXEC (19) or SYS_RECEIVE_PROGRAM (27), which
carried the identical row in the SHIP build until 2026-09-03. The fact was not
even unknown: `.github/syscall-coverage.yml` had recorded it in prose against
both since 2026-08-20 -- "the slot-3 check does not stop a caller, and a
successful call arms an image". Nothing asserted it, so nothing failed while it
stayed true, and a fact in a reason field is not a gate.

So this is a RATCHET, not a sweep. It reads the table the compiler reads and
fails the build on any row that gates on slot 3 and is present in the ship
kernel. Restoring one deliberately (a control arm) stays possible, because a row
inside `#ifdef LEGACY_SYSCALLS_PRESENT` is not in the ship build -- but the
guarding macro has to be one this file knows is absent there, so a slot-3 row
cannot be smuggled back in behind an unrelated conditional.

WHAT THIS DOES NOT CHECK. Slot 3 specifically, not fixed slots generally: rows
gating on CAPSLOT_AUDIT, CAPSLOT_KERNEL_LOG and friends are legitimate, because
those slots hold capabilities `init` delegates rather than ones the kernel hands
everybody. `SC_ANYTYPE` is likewise not the defect on its own -- the type field
is a separate question, enforced since S60 inside cap_lookup. The decoy is what
makes slot 3 different from every other number that appears in this column.

RULE 3, ADDED 2026-09-10: THE TABLE IS NOT THE ONLY PLACE A GATE LIVES. Rules 1
and 2 read the dispatch table, and a handler BODY is one file over from it --
which is where two survivors were found. `src/kernel/kshell.c` gated its `clear`
and `load` commands on `cap_lookup(CAPSLOT_FRAME, CAP_FRAME, ...)`: slot 3, so
neither could fail for anybody, and `load` then called has_console_cap() anyway,
so the decoy test's only effect was to print "need FRAME cap slot 3" -- naming a
requirement that did not exist.

Adding the type argument (S60) had made those lines read MORE like enforcement
while changing nothing, because the decoy HAS that type. S28 is about which
capability, not which type.

And it was not ring-0-only, which is what makes it worth a rule rather than a
comment: SYS_DEBUG_EXEC (7) is SC_NONE and reaches process_user_command from
ring 3 in any DEBUG_SHELL build, resolving against the CALLER's cspace -- a task
that always holds slot 3.

So rule 3 requires every literal slot-3 cap_lookup in src/kernel/ to be either
behind a macro this file knows is absent from the ship build, or declared in
.github/slot3-lookups.yml with a reason. Declared, because a static rule cannot
tell a refusal from a snapshot: sys_ipc_send and sys_ipc_recv both resolve slot 3
deliberately and never refuse on the result, and only intent separates them from
the two this rule was written for. Comments are stripped before matching -- a
symbol named in prose is not a call site, the lesson S86's checker learned the
same week.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYSCALL_C = ROOT / "src" / "kernel" / "syscall.c"

# The slot create_task fills in every task. THE one number that is not authority.
DECOY_SLOT = "3"

# Macros that are not defined in the ship build, so a row guarded by one of them
# is not a ship-build row. Each is a defect flag or a documented development
# build; adding to this list means asserting that `make` does not define it.
SHIP_ABSENT = {
    "LEGACY_SYSCALLS_PRESENT",  # retired syscalls, restored for their control arms
    "RAMFS_SLOT3_GATE",         # the four [H-3] gates, restored for smoke-passwd-probe-control
    "DEBUG_SHELL",              # in-kernel debug shell; documented dev-only surface (CLAUDE.md 6)
    # Rule 3's two. Both are DEFECT_FLAGS members with a row in
    # docs/BUILDING.md and `?= 0` in the Makefile, and `make
    # print-defect-flags` answers "none" for a default build -- which is the
    # check this list's own comment asks for, run rather than assumed.
    "GETLINE_SLOT3_FALLBACK",   # h_get_line's pre-2026-08-24 slot-3 fallback (S28)
    "SPAWN_SLOT3_DECOY_GATE",   # the pre-2026-08-30 spawn gate (S57)
}

SLOT3_LOOKUPS = ROOT / ".github" / "slot3-lookups.yml"
KERNEL_DIR = ROOT / "src" / "kernel"

# A literal slot-3 resolve, either spelling. CAPSLOT_FRAME is 3.
SLOT3_CALL = re.compile(r"cap_lookup\s*\(\s*(?:3|CAPSLOT_FRAME)\s*,")

# A function definition at column 0: `static void h_foo(` / `int bar(`.
FUNC_DEF = re.compile(r"^[A-Za-z_][\w \t*]*?([A-Za-z_]\w*)\s*\([^;]*$")

ROW = re.compile(
    r"^\s*\[\s*(SYS_[A-Z_0-9]+)\s*\]\s*=\s*\{\s*([A-Za-z_0-9]+)\s*,\s*([A-Za-z_0-9]+)\s*,")
IF = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b(.*)$")
ELIF = re.compile(r"^\s*#\s*elif\b(.*)$")
ELSE = re.compile(r"^\s*#\s*else\b")
ENDIF = re.compile(r"^\s*#\s*endif\b")
IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


def table_rows():
    """Every (syscall, handler, slot, guards) in the dispatch table.

    `guards` is the list of macro names of the enclosing #if conditions, so a row
    with an empty list is one the ship build compiles.
    """
    text = SYSCALL_C.read_text(encoding="utf-8")
    m = re.search(r"^static const syscall_desc_t syscall_table\[[^\]]*\]\s*=\s*\{(.*?)^\};",
                  text, re.S | re.M)
    if not m:
        return None
    rows, stack = [], []
    for line in m.group(1).split("\n"):
        if IF.match(line):
            expr = IF.match(line).group(2)
            # Every identifier in the condition. `#if defined(A) || defined(B)`
            # yields both, and a row inside it is absent from the ship build if
            # ANY of them is -- which is the direction that keeps this honest:
            # a guard is only an excuse when the ship build fails to satisfy it.
            stack.append([i for i in IDENT.findall(expr) if i != "defined"])
            continue
        if ENDIF.match(line):
            if stack:
                stack.pop()
            continue
        if ELSE.match(line) or ELIF.match(line):
            # The #else arm of a guard is compiled when the macro is NOT defined,
            # so it IS a ship-build arm. Recorded as unguarded rather than
            # guessed at -- a slot-3 row written into an #else is exactly the
            # shape this file must not wave through.
            if stack:
                stack[-1] = []
            continue
        r = ROW.match(line)
        if r:
            guards = [g for frame in stack for g in frame]
            rows.append((r.group(1), r.group(2), r.group(3), guards))
    return rows


def _strip_comments(text):
    """Comments are prose. A slot-3 lookup named in one is not a call site --
    including this checker's own explanation of the sites it retired.

    LINE NUMBERING IS PRESERVED, and it has to be: a block comment replaced by a
    single space collapses every line it spanned, which both misreports the
    location AND resolves the site against the wrong #ifdef stack, since guards
    are counted by line. The first draft did exactly that and put a kspawn.c
    site 149 lines from where it lives."""
    def blank(m):
        return "\n" * m.group(0).count("\n")
    text = re.sub(r"/\*.*?\*/", blank, text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _guards_at(lines, upto):
    """The macro guards open at line index `upto`, innermost last."""
    stack = []
    for line in lines[:upto]:
        if IF.match(line):
            stack.append(set(IDENT.findall(IF.match(line).group(2))))
        elif ELIF.match(line):
            if stack:
                stack[-1] = set(IDENT.findall(ELIF.match(line).group(1)))
        elif ELSE.match(line):
            if stack:
                stack[-1] = set()      # the #else arm is NOT guarded by the macro
        elif ENDIF.match(line):
            if stack:
                stack.pop()
    out = set()
    for frame in stack:
        out |= frame
    return out


def _enclosing_symbol(lines, upto):
    """The function a line sits in: nearest preceding definition at column 0."""
    for i in range(upto, -1, -1):
        m = FUNC_DEF.match(lines[i])
        if m:
            return m.group(1)
    return "?"


def slot3_lookup_sites():
    """Literal slot-3 cap_lookup call sites in src/kernel/, with guards and the
    function each sits in."""
    sites = []
    for path in sorted(KERNEL_DIR.rglob("*.c")):
        # Strip comments but KEEP line numbering, so guards resolve correctly.
        lines = _strip_comments(path.read_text(errors="replace")).splitlines()
        for i, line in enumerate(lines):
            if SLOT3_CALL.search(line):
                sites.append((path.relative_to(ROOT).as_posix(), i + 1,
                              _guards_at(lines, i), _enclosing_symbol(lines, i)))
    return sites


def declared_exemptions():
    """(file, symbol) pairs, NOT bare files.

    A per-file exemption would silently permit the next slot-3 lookup added to
    that file -- and syscall_ipc.c, the only file with an entry, is precisely
    where a new one would be plausible. Naming the function keeps the exemption
    the size of the thing that was actually reasoned about."""
    if not SLOT3_LOOKUPS.exists():
        return set()
    data = yaml.safe_load(SLOT3_LOOKUPS.read_text()) or {}
    return {(e["file"], e["symbol"])
            for e in (data.get("exempt") or [])
            if e.get("reason") and e.get("symbol")}


def main():
    rows = table_rows()
    if rows is None:
        print("FAIL: could not find `syscall_table` in " + str(SYSCALL_C))
        print("      A checker that parses nothing passes everything. If the table")
        print("      moved or was renamed, teach this file where it went.")
        return 1

    problems = []

    # SELF-CHECK, and the reason it is here: the two rules below are satisfied
    # trivially by an empty list. A regex that stops matching after a
    # reformatting of the table would turn this whole file into a check that
    # cannot fail, silently, and the first sign would be a reopened door.
    if len(rows) < 80:
        problems.append(
            f"parsed only {len(rows)} dispatch rows, which is fewer than this table has "
            f"ever had. The row regex has probably stopped matching -- fix it rather "
            f"than lowering this bound, because every rule below is vacuous without it")

    decoy = [r for r in rows if r[2] == DECOY_SLOT]

    for name, handler, _slot, guards in decoy:
        # RULE 1: not in the ship build.
        if not guards:
            problems.append(
                f"{name} (handler {handler}) gates on cspace slot {DECOY_SLOT} and is in the "
                f"SHIP build. Slot {DECOY_SLOT} holds the CAP_FRAME create_task installs in "
                f"every task, so this row authorises every ring-3 task -- finding [C-1]'s "
                f"shape, and not a gate (S28). Give it a capability the caller had to be "
                f"granted, or retire the syscall as 5, 6, 7, 14, 19 and 27 were")
            continue
        # RULE 2: guarded by something known to be absent there, not just guarded.
        if not any(g in SHIP_ABSENT for g in guards):
            problems.append(
                f"{name} (handler {handler}) gates on cspace slot {DECOY_SLOT} behind "
                f"{' / '.join(guards)}, and this file cannot confirm any of those is absent "
                f"from the ship build. A slot-{DECOY_SLOT} row is only excusable when it is "
                f"provably not shipped: add the macro to SHIP_ABSENT if `make` really does "
                f"not define it, on purpose and with a reason")

    # RULE 3: a handler BODY is one file over from the table, and that is where
    # kshell.c's `clear` and `load` were found. Every literal slot-3 cap_lookup
    # in src/kernel/ must be provably unshipped, or declared with a reason.
    exempt_files = declared_exemptions()
    sites = slot3_lookup_sites()
    if not sites:
        problems.append(
            "found no literal slot-3 cap_lookup call sites at all. Three are "
            "expected behind control-arm macros, so SLOT3_CALL has probably "
            "stopped matching -- fix it rather than accepting the silence, "
            "because rule 3 is vacuous without it")
    for path, lineno, guards, symbol in sites:
        if guards & SHIP_ABSENT:
            continue
        if (path, symbol) in exempt_files:
            continue
        problems.append(
            f"{path}:{lineno} (in {symbol}) resolves cspace slot {DECOY_SLOT} and is in the SHIP "
            f"build. `create_task` installs a CAP_FRAME there in EVERY task, so "
            f"this lookup cannot fail for anybody -- S28. If it gates something, "
            f"gate it on a capability the caller had to be granted; if it is not "
            f"a gate (a snapshot, a diagnostic), declare it in "
            f".github/slot3-lookups.yml with the reason it never refuses")

    if problems:
        print("FAIL: check_dispatch_gates")
        for p in problems:
            print("  - " + p)
        return 1

    print(f"dispatch rows parsed      : {len(rows)}")
    print(f"rows gating on slot {DECOY_SLOT}     : {len(decoy)}")
    for name, handler, _slot, guards in decoy:
        print(f"  {name} ({handler}) -- restored only under {' / '.join(guards)}")
    print(f"slot-3 cap_lookup sites   : {len(sites)} "
          f"({len([1 for _, _, g, _s in sites if g & SHIP_ABSENT])} behind a control arm, "
          f"{len([1 for pth, _, _, sym in sites if (pth, sym) in exempt_files])} declared non-gates)")
    print("\nPASS: no ship-build syscall or handler is gated on the slot-3 decoy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
