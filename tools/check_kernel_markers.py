#!/usr/bin/env python3
"""Fail the build if a gate reads a kernel marker off the shared console without
saying why (ROADMAP 5.3, docs/LIMITATIONS.md 2.6c).

THE HAZARD. Once console_server owns the console, a kernel print() reaches COM1
only through it: the bytes go to the klog and the server forwards them from
ring 3, among everything else it writes. A gate that waits for a kernel marker
on COM1 is waiting for something a ring-3 task re-emitted, and another task's
output can land inside it. It has: `kdiag` and the SD installer gates went red
in CI with the marker printed and split. tools/check_split_markers.py cannot
help, because the kernel's message IS one call.

THE REPAIR. The kernel keeps its own copy of everything it prints on COM4, which
no capability names (S144, `make smoke-kcon`), and tools/smoke_test.sh looks for
REQUIRE_MARKER there when a gate sets MARKER_CHANNEL=kcon. It is per gate, not a
default, because a gate whose point is that a kernel line reaches the user's
console must keep reading the console.

WHAT THIS CHECKS, for every tools/smoke_test.sh and tools/run_with_swtpm.sh
invocation in a smoke-* target (both honour MARKER_CHANNEL):

  R1  a REQUIRE_MARKER only the kernel prints, read off the console, makes its
      target an entry in .github/kernel-markers.yml `console:`, either
      `exposed` (not moved yet) or `console: <reason>` (reading the console is
      the point). Nothing reads a kernel marker off COM1 silently.
  R2  every entry there is still such a target. A stale entry is how a list that
      should shrink stops meaning anything.
  R3  the number of `exposed` entries equals `exposed_count`, so the list only
      shrinks by someone writing the smaller number down. It is a ratchet.
  R4  a MARKER_CHANNEL=kcon invocation requires a marker the kernel print()s,
      and MARKER_CHANNEL=kdiag one the kernel's diagnostic reporter
      (panic_str, kfault_str) writes, which goes to COM3 and never to COM4. A
      marker on the wrong channel never arrives, so such a gate could only
      time out.
  R6  an EXPECT_FAULT read off the console (EXPECT_FAULT_CHANNEL unset or
      console) is a string ring 3 prints. Anything else, a kernel line or one
      this checker cannot place, names the kernel channel it is written on:
      EXPECT_FAULT_CHANNEL=kdiag (COM3) or kcon (COM4). A control arm that
      waits for a kernel fault on COM1 can be handed it split, and can be handed
      it by any task that prints the same words; there is no list of exceptions.
  R7  EXPECT_FAULT_CHANNEL=kcon names a fault the kernel print()s, and kdiag one
      its diagnostic reporter writes, wherever the checker can place it. One too
      short to place is accepted on either: only the kernel writes there, and
      the wrong one can only time the arm out, red.
  R5  every harness under tools/ that boots the guest itself (it names
      qemu-system, smoke_test.sh or run_with_swtpm.sh) is listed under
      `scripts:`, and every listed one still exists. The checker cannot read
      their markers, so the list is how the rest of the hazard stays written
      down instead of unknown.

WHO PRINTS A MARKER is decided from the string literals of the kernel sources
(src/, rust/src/) and of userspace (userspace/): the longest prefix of the
marker found inside a literal, at least MIN_PREFIX characters or the whole
marker, so `X: found era 1` matches the literal `X: found era ` it is printed
from. A marker both sides print is not the kernel's alone and is not counted.

WHAT IT DOES NOT SEE: markers a harness script passes to smoke_test.sh from its
own environment (tools/*_replay.sh and the like) and harnesses that read the
console themselves. R5 requires each of them to be listed, with what it reads,
in the yml's `scripts:` section.

Exit 0 if every rule holds, 1 otherwise.
"""
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(os.environ.get("KMARKER_ROOT") or pathlib.Path(__file__).resolve().parent.parent)
YML = ROOT / ".github" / "kernel-markers.yml"
MIN_PREFIX = 12

LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')
# The kernel's diagnostic reporters: they write COM3 and COM1 directly and never
# go through print(), so a marker they emit is on COM3 and NOT on COM4.
# A literal is the reporter's when it sits inside one of these calls, still
# open: directly after the parenthesis, or as an arm of a conditional there
# (`kfault_str(allowed ? "..." : "...")`), so no `;` or `)` comes between.
DIAG_EMIT = re.compile(r"\b(panic_str|kfault_str|kdiag_str|panic_line|sched_claim_panic|sched_runq_panic)\s*\([^;()]*$")


def literals(globs, diag=None):
    """Every string literal in the files, joined. With `diag` a list, literals
    passed straight to a diagnostic reporter go there instead."""
    out = []
    for g in globs:
        for p in ROOT.glob(g):
            if not p.is_file():
                continue
            t = p.read_text(errors="ignore")
            for m in LITERAL.finditer(t):
                s = m.group(1)
                s = s.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")
                if not s:
                    continue
                if diag is not None and DIAG_EMIT.search(t[max(0, m.start() - 160):m.start()]):
                    diag.append(s)
                else:
                    out.append(s)
    return "\x00".join(out)


def printed_in(marker, blob):
    if marker in blob:
        return True
    for n in range(len(marker) - 1, MIN_PREFIX - 1, -1):
        if marker[:n] in blob:
            return True
    return False


def targets():
    """{target: [command, ...]} for every smoke-* recipe, continuations joined."""
    lines = (ROOT / "Makefile").read_text(errors="ignore").split("\n")
    out, cur = {}, None
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"^(smoke-[A-Za-z0-9_-]+):(?!=)", ln)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            i += 1
            continue
        if ln.startswith("\t") and cur:
            cmd = ln
            while cmd.endswith("\\") and i + 1 < len(lines):
                i += 1
                cmd = cmd[:-1] + " " + lines[i]
            out[cur].append(cmd)
        elif ln.strip() and not ln.startswith("\t") and not ln.startswith("#"):
            cur = None
        i += 1
    return out


def load_yml():
    console, scripts, count = {}, {}, None
    if not YML.exists():
        return console, scripts, count, ["%s is missing" % YML.relative_to(ROOT)]
    errs, section = [], None
    for raw in YML.read_text().split("\n"):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            key, _, val = line.partition(":")
            section = key.strip()
            if section == "exposed_count":
                try:
                    count = int(val.strip())
                except ValueError:
                    errs.append("exposed_count is not a number")
            elif section not in ("console", "scripts"):
                errs.append("unknown section %r" % section)
            continue
        k, _, v = line.strip().partition(":")
        v = v.strip().strip('"')
        if section == "console":
            if v != "exposed" and not re.match(r"(early|console-is-the-point): \S", v):
                errs.append("%s: the value must be `exposed`, `early: <why>` or "
                            "`console-is-the-point: <why>`" % k)
            console[k.strip()] = v
        elif section == "scripts":
            if not v:
                errs.append("scripts: %s needs a reason" % k)
            scripts[k.strip()] = v
    if count is None:
        errs.append("exposed_count is missing")
    return console, scripts, count, errs


def main():
    diag_l = []
    kern = literals(["src/**/*.c", "src/**/*.h", "src/**/*.S", "rust/src/**/*.rs"], diag_l)
    kdiag = "\x00".join(diag_l)
    user = literals(["userspace/**/*.c", "userspace/**/*.h", "include/**/*.h"])
    console, scripts, count, errs = load_yml()

    reading = {}          # target -> [kernel markers it reads off the console]
    for tgt, cmds in targets().items():
        for cmd in cmds:
            if "tools/smoke_test.sh" not in cmd and "tools/run_with_swtpm.sh" not in cmd:
                continue
            chan = re.search(r"\bMARKER_CHANNEL=(\w+)", cmd)
            chan = chan.group(1) if chan else "console"
            for m in re.finditer(r"\bREQUIRE_MARKER=(['\"])(.+?)\1", cmd):
                mk = m.group(2)
                if "$" in mk:
                    continue       # a variable: the harness decides it, not the recipe
                k, d, u = printed_in(mk, kern), printed_in(mk, kdiag), printed_in(mk, user)
                if chan == "kcon" and not (k and not u):
                    errs.append("R4 %s: MARKER_CHANNEL=kcon but %r is not print()ed by the kernel alone, "
                                "so it can never reach COM4%s" % (tgt, mk,
                                " (it is a diagnostic report: use kdiag)" if d else ""))
                if chan == "kdiag" and not (d and not u):
                    errs.append("R4 %s: MARKER_CHANNEL=kdiag but %r is not written by the kernel's "
                                "diagnostic reporter, so it can never reach COM3" % (tgt, mk))
                if (k or d) and not u and chan == "console":
                    reading.setdefault(tgt, []).append(mk)
            fchan = re.search(r"\bEXPECT_FAULT_CHANNEL=(\w+)", cmd)
            fchan = fchan.group(1) if fchan else "console"
            for m in re.finditer(r"\bEXPECT_FAULT=(['\"])(.+?)\1", cmd):
                mk = m.group(2)
                if "$" in mk:
                    continue
                k, d, u = printed_in(mk, kern), printed_in(mk, kdiag), printed_in(mk, user)
                if fchan == "console" and not u:
                    errs.append("R6 %s expects the fault %r on the shared console, and it is not a line "
                                "ring 3 prints. Set EXPECT_FAULT_CHANNEL=kdiag (panic_str, kfault_str) "
                                "or kcon (print)" % (tgt, mk))
                if fchan == "kcon" and (d or u) and not k:
                    errs.append("R7 %s: EXPECT_FAULT_CHANNEL=kcon but %r is not print()ed by the kernel, "
                                "so it can never reach COM4%s" % (tgt, mk, " (use kdiag)" if d else ""))
                if fchan == "kdiag" and (k or u) and not d:
                    errs.append("R7 %s: EXPECT_FAULT_CHANNEL=kdiag but %r is not written by the kernel's "
                                "diagnostic reporter, so it can never reach COM3%s" % (tgt, mk, " (use kcon)" if k else ""))

    for tgt, mks in sorted(reading.items()):
        if tgt not in console:
            errs.append("R1 %s reads the kernel marker %r off the shared console. Set "
                        "MARKER_CHANNEL=kcon, or list it in .github/kernel-markers.yml" % (tgt, mks[0]))
    for tgt in sorted(console):
        if tgt not in reading:
            errs.append("R2 %s is listed in .github/kernel-markers.yml but no longer reads a kernel "
                        "marker off the console: remove it" % tgt)
    harness = set()
    for p in sorted(list((ROOT / "tools").glob("*.sh")) + list((ROOT / "tools").glob("*.py"))):
        if re.match(r"(smoke_test\.sh|check_\w+\.py|test_check_\w+\.sh)$", p.name):
            continue
        if re.search(r"qemu-system|smoke_test\.sh|run_with_swtpm\.sh", p.read_text(errors="ignore")):
            harness.add("tools/" + p.name)
    for h in sorted(harness - set(scripts)):
        errs.append("R5 %s boots the guest itself and is not listed under `scripts:` in "
                    ".github/kernel-markers.yml: say what it reads" % h)
    for h in sorted(set(scripts) - harness):
        errs.append("R5 %s is listed under `scripts:` but is no longer a harness here: remove it" % h)

    exposed = sum(1 for v in console.values() if v == "exposed")
    if count is not None and exposed != count:
        errs.append("R3 %d targets are `exposed` and exposed_count says %d. The list only shrinks: "
                    "write the new number down" % (exposed, count))

    print("kernel markers read off the console: %d targets (%d exposed, %d by design); "
          "%d harness scripts listed" % (len(reading), exposed, len(console) - exposed, len(scripts)))
    if errs:
        print("FAIL: check_kernel_markers")
        for e in errs:
            print("  - " + e)
        return 1
    print("PASS: every kernel marker a gate reads off the console is accounted for")
    return 0


if __name__ == "__main__":
    sys.exit(main())
