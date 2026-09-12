#!/usr/bin/env python3
"""Every write to a capability slot is a declared write, and the declaration says
what makes it safe.

WHY THIS EXISTS. A capability in this kernel is six fields -- type, rights,
object, badge, serial, generation -- and a C assignment writes them one at a
time. rust_cap_revoke_global's sweep reads every live cspace and decides, from
what it finds, which capabilities belong to a revoked lineage and which kernel
objects no capability names any more. It is documented to depend on cap_lock
making those cspaces QUIESCENT; the comment at the kobj_gc call inside cap_revoke
says so in as many words: "cap-writes are field-by-field, so running it unlocked
would let it observe a slot mid-install -- type already written, `object` still
stale -- and conclude a live object is unreachable."

That guarantee is not a property of cap_lock. It is a property of the SET OF
WRITERS THAT TAKE IT, and on 2026-09-12 five did not: SYS_PIPE installed two
pipe-end capabilities with a raw store, SYS_PIPE_CLOSE and the teardown backstop
nulled slots the same way, do_spawn's stdio wiring struct-copied a capability out
of the spawner's cspace into the child's, and every spawn and fork installed an
unaccounted CAP_TCB. cap_install_object's own header had already diagnosed the
class for SYS_CONNECT_FS_SERVER -- "rather than a raw, unsynchronised cspace store
that races a concurrent rust_cap_revoke_global sweep under SMP and never counts
against MAX_CAPS_PER_TASK" -- and the repair was made at that one site and not
swept to its siblings.

WHY IT IS A CHECKER AND NOT A TEST. The defect is a data race between a cap-write
and a sweep on another CPU, inside a twelve-field store. A runtime arm for it
would be probabilistic at a rate nobody has measured and would gate nothing on
the boots it missed. The property is static, so the gate is static: a cap-write
either sits in a function that holds cap_lock, or it is declared -- with a reason
that a reader can disagree with -- in .github/cap-write-sites.yml.

WHY DECLARED RATHER THAN DERIVED. Three of the sites are legitimately lock-free
and for three different reasons (boot before any second CPU exists; a cspace no
other CPU can reach yet; a control arm that exists to BE the defect). "Holds the
lock" is checkable; "cannot be reached by another CPU" is a claim about the
program somebody has to make and sign. So the manifest records the claim and this
script checks the half that is mechanical, the same bargain .github/gate-pairs.yml
makes for control arms.
"""
import re
import sys
import pathlib

try:
    import yaml
except ImportError:                                    # pragma: no cover
    print("check_cap_writes: PyYAML is required", file=sys.stderr)
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".github" / "cap-write-sites.yml"
SRC = ROOT / "src" / "kernel"

FIELD = r"(?:type|rights|object|badge|serial|generation)"
# A write to ONE capability field through an indexed cspace-like lvalue. The
# lvalue names are the ones this tree actually uses for a capability array; a new
# name is caught by rule 1 the first time it is written to, because the function
# it appears in will not be declared.
CSPACE = r"(?:cspace|cs|ccs|pcs|caps|root_cnode|dest|dst)"
PAT_FIELD = re.compile(r"(?:" + CSPACE + r")\s*\[[^;]*\]\s*\.\s*" + FIELD + r"\s*=(?!=)")
# And a whole-struct assignment into such a slot, which writes all six at once.
#
# A NARROWER NAME SET for this one, deliberately. `dst[i] = src[i]` is a byte copy
# and appears in four string/framebuffer helpers; including `dst` and `dest` here
# reported all four as capability writes on the first run. The names left are ones
# this tree only ever uses for a capability array, and the cost of the omission is
# bounded: a whole-struct cap assignment through a pointer named `dst` would be
# missed by THIS pattern, but every field-wise store through it is still caught by
# PAT_FIELD above, and a capability built by struct assignment still has to come
# from somewhere a reviewer reads.
CSPACE_STRUCT = r"(?:cspace|ccs|pcs|root_cnode)"
PAT_STRUCT = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_\.\[\]\->]*)?(?:" + CSPACE_STRUCT + r")\s*\[[^;]*\]\s*=\s*[^=]")

FUNC = re.compile(r"^(?:static\s+)?(?:[A-Za-z_][A-Za-z0-9_ \*]*?)\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*$")
NOT_A_FUNC = ("if", "for", "while", "switch", "return", "}", "else", "#")

VALID_STATUS = {"locked", "boot-single-cpu", "unreachable-until-published",
                "control-arm", "invisible-to-the-sweep", "unlocked"}

# A site exempted on "the sweep cannot act on anything this function writes" is
# making a claim about OTHER code -- the guards inside the sweep that make it
# true. Those guards are what rots. So such a site must name them, and rule 5
# checks they are still there.
NEEDS_DEPENDS_ON = {"invisible-to-the-sweep"}


def enclosing_functions(path):
    """Map every line number in `path` to the function it sits in."""
    out, cur = {}, "<file scope>"
    for n, line in enumerate(path.read_text().split("\n"), 1):
        stripped = line.lstrip()
        m = FUNC.match(line)
        if m and not stripped.startswith(NOT_A_FUNC):
            cur = m.group("name")
        out[n] = cur
    return out


def function_bodies(path):
    """Crude per-function source text, enough to ask whether cap_lock is taken.

    Brace-accurate parsing is not worth it here and would be a second C parser to
    maintain: the question is only "does this function mention spin_lock(&cap_lock)
    anywhere", and a function that does not is one whose `locked:` claim is false
    regardless of where the braces are. A function that takes the lock and then
    writes OUTSIDE the locked region is NOT caught by this, and that limit is
    stated in the manifest header rather than left for a reader to discover.
    """
    bodies, cur, buf = {}, None, []
    for line in path.read_text().split("\n"):
        m = FUNC.match(line)
        if m and not line.lstrip().startswith(NOT_A_FUNC):
            if cur:
                bodies.setdefault(cur, "")
                bodies[cur] += "\n".join(buf)
            cur, buf = m.group("name"), []
        buf.append(line)
    if cur:
        bodies.setdefault(cur, "")
        bodies[cur] += "\n".join(buf)
    return bodies


def find_sites():
    sites = {}
    for path in sorted(SRC.glob("*.c")):
        funcs = enclosing_functions(path)
        for n, line in enumerate(path.read_text().split("\n"), 1):
            code = line.split("/*")[0].split("//")[0]
            if PAT_FIELD.search(code) or PAT_STRUCT.search(code):
                key = (path.relative_to(ROOT).as_posix(), funcs[n])
                sites.setdefault(key, []).append(n)
    return sites


def main():
    if not MANIFEST.exists():
        print(f"check_cap_writes: missing {MANIFEST.relative_to(ROOT)}")
        return 1
    spec = yaml.safe_load(MANIFEST.read_text()) or {}
    declared = {}
    for entry in spec.get("sites") or []:
        for field in ("file", "function", "status", "reason"):
            if field not in entry:
                print(f"check_cap_writes: a site entry is missing `{field}`: {entry}")
                return 1
        declared[(entry["file"], entry["function"])] = entry

    sites = find_sites()
    errors = []

    # RULE 1: every cap-write site is declared. This is the one that catches the
    # next raw store, wherever somebody puts it.
    for key, lines in sorted(sites.items()):
        if key not in declared:
            errors.append(
                f"UNDECLARED capability-slot write: {key[0]} in {key[1]}() "
                f"at line{'s' if len(lines) > 1 else ''} "
                f"{', '.join(str(n) for n in lines[:6])}"
                f"{' ...' if len(lines) > 6 else ''}\n"
                f"      Route it through one of capability.c's locked primitives, or "
                f"declare it in .github/cap-write-sites.yml with what makes it safe.")

    # RULE 2: every declaration still describes a real site. A stale entry is an
    # exemption nobody granted on purpose, left behind by a refactor.
    for key, entry in sorted(declared.items()):
        if key not in sites:
            errors.append(
                f"STALE declaration: {key[0]} in {key[1]}() declares a "
                f"capability-slot write that is no longer there "
                f"(status: {entry['status']}). Remove the entry.")

    # RULE 3: a site that claims the lock must take it.
    bodies_cache = {}
    for key, entry in sorted(declared.items()):
        if entry["status"] != "locked" or key not in sites:
            continue
        path = ROOT / key[0]
        if key[0] not in bodies_cache:
            bodies_cache[key[0]] = function_bodies(path)
        body = bodies_cache[key[0]].get(key[1], "")
        if "spin_lock(&cap_lock)" not in body:
            errors.append(
                f"FALSE `locked` claim: {key[0]} in {key[1]}() is declared "
                f"`locked` but never takes cap_lock.")

    # RULE 5: a site exempted because the revocation sweep cannot act on what it
    # writes must NAME THE GUARDS that make that true, and they must still exist.
    #
    # WHY THIS RULE EXISTS, and it is the reason the whole status was added. On
    # 2026-09-12 `create_task` was declared `unlocked` with a finding, on the
    # reasoning that a sweep could see its cspace mid-build and let `kobj_gc`
    # destroy the reply endpoint it was about to install a capability to. Checked
    # against the code rather than reasoned from the shape, that was WRONG: every
    # capability create_task installs carries `badge = 0`, which `revoke_subtree`
    # skips outright, and names an object outside every range `mark_cap` can
    # reclaim. The site is safe -- but it is safe BECAUSE OF CODE SOMEWHERE ELSE,
    # and an exemption resting on a guard nobody re-checks is an exemption that
    # expires silently. Remove `mark_cap`'s empty-slot return, or let
    # `revoke_subtree` stop skipping badge 0, and this site becomes a live defect
    # with nothing reporting it.
    #
    # Matched on WHITESPACE-NORMALISED text, so reindenting a guard does not fail
    # the build while deleting it does.
    for key, entry in sorted(declared.items()):
        if entry["status"] not in NEEDS_DEPENDS_ON:
            continue
        deps = entry.get("depends_on") or []
        if not deps:
            errors.append(
                f"UNPINNED exemption: {key[0]} in {key[1]}() is declared "
                f"`{entry['status']}` but names no `depends_on:` guards. The claim "
                f"rests on code elsewhere; name it, or the exemption expires silently.")
            continue
        for dep in deps:
            for field in ("file", "contains", "because"):
                if field not in dep:
                    errors.append(
                        f"INCOMPLETE depends_on for {key[0]} in {key[1]}(): "
                        f"an entry is missing `{field}`: {dep}")
                    break
            else:
                dpath = ROOT / dep["file"]
                if not dpath.exists():
                    errors.append(
                        f"MISSING guard file for {key[0]} in {key[1]}(): "
                        f"{dep['file']} does not exist")
                    continue
                hay = " ".join(dpath.read_text().split())
                needle = " ".join(str(dep["contains"]).split())
                if needle not in hay:
                    errors.append(
                        f"GUARD GONE: {key[0]} in {key[1]}() is exempted because "
                        f"{dep['because']}\n"
                        f"      but {dep['file']} no longer contains: {needle}\n"
                        f"      Either the guard moved (update the declaration) or it "
                        f"was removed, and this site is now a live defect.")

    # RULE 4: a status must be one this file knows, and an `unlocked` site -- a
    # KNOWN OPEN DEFECT -- must name the finding that tracks it. An exemption
    # with no finding is how one stops being tracked.
    for key, entry in sorted(declared.items()):
        if entry["status"] not in VALID_STATUS:
            errors.append(
                f"UNKNOWN status `{entry['status']}` for {key[0]} in {key[1]}(). "
                f"One of: {', '.join(sorted(VALID_STATUS))}.")
        if entry["status"] == "unlocked" and not entry.get("finding"):
            errors.append(
                f"UNTRACKED open defect: {key[0]} in {key[1]}() is declared "
                f"`unlocked` with no `finding:` naming it.")

    if errors:
        print("FAIL: capability-slot writes are not all accounted for\n")
        for e in errors:
            print(f"  - {e}")
        print(f"\n{MANIFEST.relative_to(ROOT)} declares what each cap-write site is and "
              f"why it is safe.\nA capability is six fields and a C store writes them one "
              f"at a time; rust_cap_revoke_global\nreads every cspace and is documented to "
              f"need them quiescent under cap_lock.")
        return 1

    by_status = {}
    for entry in declared.values():
        by_status[entry["status"]] = by_status.get(entry["status"], 0) + 1
    total_writes = sum(len(v) for v in sites.values())
    pinned = sum(len(e.get("depends_on") or []) for e in declared.values())
    print(f"capability-slot write sites : {len(sites)} functions, {total_writes} stores")
    print(f"guards pinned by exemptions : {pinned}")
    for status in sorted(by_status):
        print(f"  {status:<28}: {by_status[status]}")
    print("\nPASS: every capability-slot write is declared, and every `locked` one takes cap_lock")
    return 0


if __name__ == "__main__":
    sys.exit(main())
