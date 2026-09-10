#!/usr/bin/env python3
"""The kernel's lock order is declared, and no path violates it.

WHY THIS EXISTS. Nine locks, and the order between them lived in five comments in
four files -- with no registry, no diagram, and nothing that could fail. Two of
those comments were in the SAME file and disagreed:

  * `sys_ipc_send` mints under the IPC lock and says "cap_lock nesting inside
    endpoint_lock is a NEW lock order, and it is safe because it is the only
    one: no path in the tree takes an IPC lock while holding cap_lock. Keep it
    that way." (2026-08-11)
  * `sys_ipc_recv` mints after unlocking and says taking cap_lock underneath
    endpoint_lock "would create a second lock order between two locks that are
    otherwise unrelated." (2026-08-10)

Both describe the same pair. The second was written one day before the first and
has been stale ever since: the locks are not "otherwise unrelated", because the
path above relates them. "Keep it that way" is an instruction with no addressee
and no enforcement -- which is what this file is.

WHAT IT CHECKS, AND THE DIRECTION THAT MATTERS. A nesting is not a defect; a
CYCLE is. So there are two rules:

  1. A nesting that is not declared in .github/lock-order.yml fails. New
     relationships between locks have to be argued for, once, in writing.
  2. The REVERSE of a declared nesting fails. This is the rule with teeth: a
     declared `endpoint_lock -> page_lock` is safe precisely because no
     page_lock holder ever enters IPC, and that argument -- the 2026-08-30
     audit's, in section 5 of docs/AUDIT.md -- is exactly what stops being true
     the moment somebody adds the other direction. It was checked by hand once.

HOW IT WORKS, AND WHAT IT CANNOT SEE. Function bodies are recovered lexically,
each function's directly-taken locks are read from `spin_lock(&X)` (and the
`ipc_lock()` alias for endpoint_lock), and that set is closed transitively over
calls, so a call to `cap_install_object` counts as taking `cap_lock`. Then, for
every region where a lock is held, any call reaching another lock is a nesting.

That last part is the point: the interesting case is ACROSS a call boundary.
`ipc_publish_pending_block` never writes `spin_lock(&cap_lock)` -- it calls
`cap_install_reply_for`, which does. A checker that only looked for two
`spin_lock` calls in one function would miss every nesting this kernel actually
has, and would pass while seeing nothing.

Limits, stated because a static checker that overstates itself is worse than
none: this is lexical, not a parse; it matches callees by name; it does not model
conditional locking, function pointers, or interrupt context; and it is not a
runtime lockdep. `spin_lock` records nesting depth and saved IF but NO lock
identity, so a runtime order check would need a per-lock id and a per-CPU held
stack -- a new subsystem on the hottest path in a kernel whose last four SMP
defects were found by hanging. This is the half that can be gated today.

Carries S88. Exit 0 if every nesting is declared and no reverse appears, 1 otherwise.
"""
import collections
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
KERNEL = ROOT / "src" / "kernel"
ORDER_YML = ROOT / ".github" / "lock-order.yml"

FUNC = re.compile(r"^[A-Za-z_][\w \t*]*?([A-Za-z_]\w*)\s*\([^;]*$")
# A whole definition on ONE line: `static inline void ut_lock(void) { ... }`.
# The pattern above cannot match these -- it requires no `;` between the open
# paren and end of line, and a one-line body has them. That blind spot hid the
# only site taking scheduler_lock AND the ut_lock wrapper through which
# untyped.c takes its lock everywhere, so two of nine locks were invisible.
# Found by this file's own per-lock self-check on its first run.
FUNC_ONELINE = re.compile(
    r"^[A-Za-z_][\w \t*]*?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{.*\}\s*$")
TAKE = re.compile(r"\bspin_lock\s*\(\s*&?(\w+)")
DROP = re.compile(r"\bspin_unlock\s*\(\s*&?(\w+)")
IPC_TAKE = re.compile(r"\bipc_lock\s*\(")
IPC_DROP = re.compile(r"\bipc_unlock\s*\(")
CALL = re.compile(r"\b([a-z_]\w*)\s*\(")
LOCK_PRIMITIVES = {"spin_lock", "spin_unlock", "ipc_lock", "ipc_unlock"}


def strip_comments(text):
    """Comments are prose. Line numbering is preserved so bodies stay aligned."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"),
                  text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def function_bodies():
    """{name: [body, ...]} recovered by brace counting. Lexical, not a parse."""
    out = collections.defaultdict(list)
    for path in sorted(KERNEL.glob("*.c")):
        cur, buf, depth, opened = None, [], 0, False
        for line in strip_comments(path.read_text(errors="replace")).splitlines():
            if cur is None:
                one = FUNC_ONELINE.match(line)
                if one:
                    out[one.group(1)].append(line)
                    continue
                m = FUNC.match(line)
                if m:
                    cur, buf = m.group(1), [line]
                    depth, opened = line.count("{") - line.count("}"), "{" in line
                continue
            buf.append(line)
            depth += line.count("{") - line.count("}")
            opened = opened or "{" in line
            if opened and depth <= 0:
                out[cur].append("\n".join(buf))
                cur, buf, opened = None, [], False
    return out


def locks_taken(bodies, known):
    """Locks each function takes, closed transitively over calls by name."""
    takes = collections.defaultdict(set)
    for fn, blist in bodies.items():
        for body in blist:
            for m in TAKE.finditer(body):
                if m.group(1) in known:
                    takes[fn].add(m.group(1))
            if IPC_TAKE.search(body):
                takes[fn].add("endpoint_lock")
    for _ in range(8):                      # small graph; converges immediately
        changed = False
        for fn, blist in bodies.items():
            acc = set(takes[fn])
            for body in blist:
                for callee in set(CALL.findall(body)):
                    if callee != fn and callee in takes:
                        acc |= takes[callee]
            if acc != takes[fn]:
                takes[fn], changed = acc, True
        if not changed:
            break
    return takes


def nestings(bodies, takes, known):
    """{(outer, inner): {"caller -> callee", ...}}."""
    found = collections.defaultdict(set)
    for fn, blist in bodies.items():
        for body in blist:
            held = []
            for line in body.splitlines():
                for m in TAKE.finditer(line):
                    if m.group(1) in known:
                        # A SECOND spin_lock while one is held is a nesting in
                        # its own right. The first version only recorded
                        # nestings reached through a CALL, because that is the
                        # shape every real one in this kernel has -- and so it
                        # was blind to the plainest possible way to write the
                        # same defect. Its own falsification arm found that.
                        if held:
                            found[(held[-1], m.group(1))].add(f"{fn} (directly)")
                        held.append(m.group(1))
                if IPC_TAKE.search(line):
                    if held and held[-1] != "endpoint_lock":
                        found[(held[-1], "endpoint_lock")].add(f"{fn} (via ipc_lock)")
                    held.append("endpoint_lock")
                if held:
                    for callee in CALL.findall(line):
                        if callee in LOCK_PRIMITIVES:
                            continue
                        for lock in takes.get(callee, ()):
                            if lock not in held:
                                found[(held[-1], lock)].add(f"{fn} -> {callee}")
                for m in DROP.finditer(line):
                    if held and m.group(1) in known:
                        held.pop()
                if IPC_DROP.search(line) and held:
                    held.pop()
    return found


def main():
    spec = yaml.safe_load(ORDER_YML.read_text()) or {}
    known = set(spec.get("locks") or [])
    declared = {}
    for entry in spec.get("nesting") or []:
        if entry.get("reason"):
            declared[(entry["outer"], entry["inner"])] = entry["reason"]

    problems = []
    if not known:
        problems.append("no locks declared in .github/lock-order.yml")

    bodies = function_bodies()
    takes = locks_taken(bodies, known)
    holders = sorted(fn for fn, v in takes.items() if v)

    # SELF-CHECK, per lock rather than in total. Counting lock-taking FUNCTIONS
    # was too weak to fail: with the spin_lock regex deliberately broken, the
    # surviving ipc_lock() alias still spread endpoint_lock across hundreds of
    # callers through the transitive closure, so the total stayed far above any
    # threshold while eight of the nine locks had become invisible. Requiring
    # EVERY declared lock to have a taker is the version its own arm can fail.
    seen = {lock for v in takes.values() for lock in v}
    for lock in sorted(known - seen):
        problems.append(
            f"no function is seen to take {lock}, though it is declared. The body "
            f"or lock regex has probably stopped matching -- fix that rather than "
            f"removing the lock, because every rule here is vacuous for a lock "
            f"nobody is seen to take")

    found = nestings(bodies, takes, known)

    for (outer, inner), sites in sorted(found.items()):
        if (outer, inner) in declared:
            continue
        problems.append(
            f"UNDECLARED nesting {outer} -> {inner}, at "
            f"{', '.join(sorted(sites)[:3])}. A new relationship between two locks "
            f"is an argument somebody has to make once, in "
            f".github/lock-order.yml, with the reason it cannot cycle")

    for (outer, inner) in sorted(declared):
        if (inner, outer) in found:
            problems.append(
                f"CYCLE: {outer} -> {inner} is declared, and the REVERSE "
                f"{inner} -> {outer} now exists at "
                f"{', '.join(sorted(found[(inner, outer)])[:3])}. A declared "
                f"nesting is safe only while the other direction does not exist; "
                f"together they are a deadlock")

    if problems:
        print("FAIL: check_lock_order")
        for p in problems:
            print("  - " + p)
        return 1

    print(f"locks declared        : {len(known)}")
    print(f"lock-taking functions : {len(holders)}")
    print(f"nestings found        : {len(found)} (all declared)")
    for (outer, inner), sites in sorted(found.items()):
        print(f"  {outer} -> {inner}  ({len(sites)} site(s))")
    print("\nPASS: every lock nesting is declared, and no reverse exists")
    return 0


if __name__ == "__main__":
    sys.exit(main())
