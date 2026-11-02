#!/usr/bin/env python3
"""Syscall and interrupt stack depth, from -fstack-usage. Roadmap 4.18.

The per-CPU stack the scheduler hands a task is KERNEL_STACK_SIZE of usable
bytes. The guard page is the unmapped page below that region: an AP's idle
slot is one page plus KERNEL_STACK_SIZE, and the mapper covers only the
KERNEL_STACK_SIZE bytes. "Minus the guard" is that layout. Subtracting
another page from KERNEL_STACK_SIZE would count the guard twice.

The bytes the C compiler reports are not the whole frame. isr_common_stub64
pushes the general registers on top of the hardware interrupt frame and the
vector slot, and those words are still there while the C handler runs. The
reserve is counted from that stub. A parse that finds no pushes fails closed:
a reserve of zero would make the budget larger than the stack.

Direct calls come from the .ci files -fcallgraph-info writes. That graph is
not enough on its own. syscall_handler reaches every handler through d->fn,
which the compiler records as __indirect_call, and a sum that stops there
says the syscall path is a few dozen bytes. The ship table is read back from
the preprocessed source and each handler that the default build compiles
becomes an edge. The same treatment is given to a block device's
read_block, write_block, flush and fill_uniform: the callees are the
functions the default build actually assigns.

A function that calls itself is unbounded unless the source shows the bound.
The pointer walks compare a depth against FSCK_MAX_DEPTH and pass depth - 1.
free_user_table passes level - 1 and stops at level 1, and the only call from
outside passes a constant. A self-edge that exists only because a function
pointer was resolved back to the same function, with no syntactic recursive
call, is the partition view: one view, whose parent is the disk. That edge
is counted twice, not dropped and not treated as infinite.

A cycle through two or more functions is counted twice only when some
function on it calls spin_lock and the compiled spin_lock takes the lock
with a compare-and-swap from zero. The second entry on the same CPU spins
inside the lock and cannot enter a third time. do_block_read's re-entry
while a Merkle node is loaded is that second copy. Any other cycle is
unbounded and fails the build. Ignoring it would report a short path on a
kernel whose storage calls do re-enter.

Rust exports have no .su line. Each export's frame is the arrays in its own
call tree, plus a small spill on every function of that tree. An export the
scan cannot see fails the build. A header inline the compiler already folded
into its caller has no .su line either, and it counts as zero because its
bytes are in the caller's line. Counting them again would double the frame.

The depth is an upper bound: a strongly connected piece costs the sum of its
frames times the bound above, and the longest path in the resulting dag is
the depth. Over the limit fails. An empty report set fails. The checker does
not delete a frame or a warning to go green.
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
DROP = {"__indirect_call", "__stack_chk_fail"}
MEMBERS = ("read_block", "write_block", "flush", "fill_uniform")
# Saved registers and the return slot a Rust function uses and an array scan
# does not see. Added once per Rust function on the export's call tree.
RUST_SPILL = 64
# Below this many resolved handlers the table parse did not see the ship
# dispatch. The harness requires the same order of magnitude.
SYSCALL_EDGE_FLOOR = 50
# A path this short is the indirect call being dropped. The measured walk is
# several times this on its own.
DEPTH_FLOOR = 8192

GCC_BASE = [
    "gcc", "-E", "-P", "-m64", "-ffreestanding", "-fno-pic", "-fno-pie",
    "-std=gnu99", "-mcmodel=kernel",
    "-I", "src/include", "-I", "include",
]


def resolve_name(name, frames):
    while name not in frames and name.endswith(".0"):
        shorter = name[:-2]
        if shorter not in frames and not shorter.endswith(".0"):
            break
        name = shorter
    return name


def short(name):
    return name.split(":")[-1]


def load_reports(report_root):
    frames = {}
    kinds = {}
    edges = defaultdict(set)
    indirect_at = set()
    su_files = list(pathlib.Path(report_root).rglob("*.su"))
    if not su_files:
        return None, None, None, ["stack-budget: no .su reports under %s" % report_root]
    problems = []
    for path in su_files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "\t" not in line:
                continue
            left, nbytes, kind = line.split("\t", 2)
            name = left.rsplit(":", 1)[-1]
            frames[name] = int(nbytes)
            kinds[name] = kind.strip()
    raw_edges = defaultdict(set)
    for path in pathlib.Path(report_root).rglob("*.ci"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"edge:\s*\{(.*?)\}", text, re.S):
            body = m.group(1)
            s = re.search(r'sourcename:\s*"([^"]*)"', body)
            t = re.search(r'targetname:\s*"([^"]*)"', body)
            if not s or not t:
                continue
            src, dst = short(s.group(1)), short(t.group(1))
            if dst == "__indirect_call":
                indirect_at.add(src)
                continue
            if dst in DROP or src in DROP:
                continue
            raw_edges[src].add(dst)
    for src, dsts in raw_edges.items():
        rs = resolve_name(src, frames)
        for dst in dsts:
            rd = resolve_name(dst, frames)
            edges[rs].add(rd)
    for name in list(frames):
        resolved = resolve_name(name, frames)
        if resolved != name and resolved in frames:
            # The .ci name with a trailing .0 is the same function as the
            # .su name. Keep the .su bytes.
            frames.setdefault(resolved, frames[name])
    return frames, kinds, edges, problems, indirect_at, raw_edges


def gcc_preprocess(path):
    proc = subprocess.run(
        GCC_BASE + [str(path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip().splitlines()
        tail = err[-1] if err else "gcc failed"
        return None, "stack-budget: could not preprocess %s (%s)" % (path, tail)
    return proc.stdout, None


def extract_body(text, name):
    """First column-0 definition of name, braces included. None if absent."""
    needle = re.compile(r"\b%s\s*\(" % re.escape(name))
    for m in needle.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start] in " \t#":
            continue
        paren = text.find("(", m.start())
        depth = 0
        i = paren
        while i < len(text):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        j = i + 1
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text) or text[j] != "{":
            continue
        depth = 0
        k = j
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    return text[m.start():k + 1]
            k += 1
    return None


def source_name(name):
    out = name
    changed = True
    while changed:
        changed = False
        for suffix in (".constprop", ".isra", ".part"):
            # foo.part.0.constprop -> peel trailing .<kind> or .<kind>.<digits>
            m = re.search(r"\.%s(?:\.\d+)?$" % suffix[1:], out)
            if m:
                out = out[:m.start()]
                changed = True
    return out


def macro_values():
    values = {}
    for path in list((ROOT / "src").rglob("*.c")) + list((ROOT / "src").rglob("*.h")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^#define\s+([A-Za-z_]\w*)\s+(\d+)\b", text, re.M):
            values[m.group(1)] = int(m.group(2))
    return values


def const_of(token, macros):
    if token.isdigit():
        return int(token)
    return macros.get(token)


def recursion_bound(name, macros, texts):
    """How many times name may sit on one stack, or None if the source
    does not show a bound. 1 means no self-call to bound."""
    src = source_name(name)
    body = None
    owner = None
    for path, text in texts:
        body = extract_body(text, src)
        if body is not None:
            owner = text
            break
    if body is None:
        return None
    if not re.search(r"\b%s\s*\(" % re.escape(src), body[body.find("{") + 1:]):
        return 1
    dec = re.search(r"\b([A-Za-z_]\w*)\s*-\s*1\b", body)
    if not dec:
        return None
    ident = dec.group(1)
    # The comparison is the whole condition in the pointer walks, and one
    # arm of `ptr_blk == 0 || depth >= FSCK_MAX_DEPTH` in the free.
    guard = re.search(
        r"\b%s\s*>=\s*([A-Za-z_]\w*|\d+)\b" % re.escape(ident),
        body,
    )
    if guard:
        value = const_of(guard.group(1), macros)
        return value
    base = re.search(r"\b%s\s*==\s*(\d+)\b" % re.escape(ident), body)
    if not base or owner is None:
        return None
    stop = int(base.group(1))
    # Calls from outside the body. A non-constant argument is not a bound.
    rest = owner.replace(body, "\n", 1)
    highest = None
    for m in re.finditer(r"\b%s\s*\(([^;]*)\)" % re.escape(src), rest):
        args = split_args(m.group(1))
        if not args:
            return None
        last = args[-1].strip()
        if not re.fullmatch(r"\d+", last):
            return None
        highest = int(last) if highest is None else max(highest, int(last))
    if highest is None:
        return None
    return highest - stop + 1


def split_args(text):
    args = []
    buf = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        args.append("".join(buf))
    return args


def syscall_handlers(preprocessed):
    m = re.search(
        r"syscall_desc_t\s+syscall_table\s*\[[^\]]*\]\s*=\s*\{(.*?)\n\};",
        preprocessed,
        re.S,
    )
    if not m:
        return None
    return re.findall(r"\{\s*([A-Za-z_]\w*)\s*,", m.group(1))


def assignments(preprocessed):
    found = defaultdict(set)
    for member in MEMBERS:
        for m in re.finditer(
            r"\.%s\s*=\s*([A-Za-z_]\w*)" % member, preprocessed
        ):
            found[member].add(m.group(1))
    return found


def members_called(body):
    called = set()
    for member in MEMBERS:
        if re.search(r"->%s\s*\(" % member, body):
            called.add(member)
    return called


def asm_reserve(text):
    """Bytes occupied before interrupt_handler64's own frame."""
    common = re.search(
        r"^isr_common_stub64:$(.*)^(?:\s*call\s+interrupt_handler64)\b",
        text,
        re.M | re.S,
    )
    entry = re.search(
        r"^isr128:$(.*)^\s*jmp\s+isr_common_stub64\b",
        text,
        re.M | re.S,
    )
    if not common or not entry:
        return None, "stack-budget: lowlevel64.S has no isr128 stub to measure"
    pushes = len(re.findall(r"^\s*pushq\b", common.group(1), re.M))
    pushes += len(re.findall(r"^\s*pushq\b", entry.group(1), re.M))
    if pushes < 15:
        return None, "stack-budget: the ISR stub shows %d pushes, which is not the entry" % pushes
    # RIP, CS, RFLAGS, RSP, SS. The vector and the error-code slot are the
    # pushes already counted in isr128 (a no-error vector pushes both; an
    # error vector is pushed one by the CPU and one by the stub).
    hardware = 5 * 8
    return hardware + pushes * 8, None


def asm_roots(text):
    roots = []
    regions = []
    for start, stop in (
        (r"^isr_common_stub64:", r"^\s*iretq\b"),
        (r"^syscall_entry:", r"^\s*sysretq\b"),
    ):
        m = re.search(start + r"(.*)" + stop, text, re.M | re.S)
        if m:
            regions.append(m.group(1))
    for region in regions:
        for name in re.findall(r"^\s*call\s+([A-Za-z_]\w*)", region, re.M):
            if name not in roots:
                roots.append(name)
    return roots


def kernel_stack_size():
    text = (ROOT / "src" / "include" / "kernel.h").read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^#define\s+KERNEL_STACK_SIZE\s+(\d+)\b", text, re.M)
    if not m:
        return None
    return int(m.group(1))


def strip_rust_noise(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//.*?$", " ", text, flags=re.M)
    out = []
    i = 0
    while True:
        j = text.find("#[cfg(test)]", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = text.find("{", j)
        if k < 0:
            break
        depth = 0
        p = k
        while p < len(text):
            if text[p] == "{":
                depth += 1
            elif text[p] == "}":
                depth -= 1
                if depth == 0:
                    p += 1
                    break
            p += 1
        i = p
    return "".join(out)


def rust_function_frames():
    """export name -> upper bound of that export's own call tree."""
    sizes = {"u8": 1, "i8": 1, "bool": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4,
             "u64": 8, "i64": 8, "usize": 8, "isize": 8}
    consts = {}
    aliases = {}
    fn_frame = {}
    fn_calls = defaultdict(set)
    exports = set()
    array_re = re.compile(
        r"(?<![&])\[\s*(u8|i8|bool|u16|i16|u32|i32|u64|i64|usize|isize)\s*;\s*(\d+|[A-Za-z_]\w*)\s*\]"
    )
    src_dir = ROOT / "rust" / "src"
    blobs = []
    for path in sorted(src_dir.glob("*.rs")):
        blobs.append(strip_rust_noise(path.read_text(encoding="utf-8", errors="replace")))
    whole = "\n".join(blobs)
    for m in re.finditer(r"\bconst\s+([A-Z_]\w*)\s*:\s*usize\s*=\s*(\d+)", whole):
        consts[m.group(1)] = int(m.group(2))
    for m in re.finditer(
        r"\btype\s+([A-Za-z_]\w*)\s*=\s*\[\s*(u8|u16|u32|u64|usize)\s*;\s*(\d+|[A-Z_]\w*)\s*\]",
        whole,
    ):
        n = m.group(3)
        count = int(n) if n.isdigit() else consts.get(n)
        if count is None:
            continue
        aliases[m.group(1)] = sizes[m.group(2)] * count

    # Function items. A body is the brace that follows the signature.
    for m in re.finditer(r"\bfn\s+([A-Za-z_]\w*)\s*(?:<[^;{]*>)?\s*\(", whole):
        name = m.group(1)
        if name in fn_frame:
            continue
        paren = whole.find("(", m.end() - 1)
        depth = 0
        i = paren
        while i < len(whole):
            if whole[i] == "(":
                depth += 1
            elif whole[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        j = i + 1
        while j < len(whole) and whole[j] in " \t\r\n":
            j += 1
        if j < len(whole) and whole[j:j + 5] == "where":
            brace = whole.find("{", j)
        else:
            brace = j if j < len(whole) and whole[j] == "{" else whole.find("{", j)
        if brace < 0 or whole[brace] != "{":
            continue
        # An extern export is the fn whose keyword sits just before `fn`.
        prefix = whole[max(0, m.start() - 40):m.start()]
        if 'extern "C"' in prefix:
            exports.add(name)
        depth = 0
        k = brace
        while k < len(whole):
            if whole[k] == "{":
                depth += 1
            elif whole[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        body = whole[brace:k + 1]
        frame = 0
        for am in array_re.finditer(body):
            n = am.group(2)
            count = int(n) if n.isdigit() else consts.get(n)
            if count is None:
                continue
            frame += sizes[am.group(1)] * count
        for alias, nbytes in aliases.items():
            if re.search(r":\s*%s\b" % re.escape(alias), body):
                frame += nbytes
        fn_frame[name] = frame
        for cm in re.finditer(r"(?<![\.:\w])([A-Za-z_]\w*)\s*\(", body):
            callee = cm.group(1)
            if callee != name:
                fn_calls[name].add(callee)

    def tree(export):
        seen = set()
        def walk(fn):
            if fn in seen or fn not in fn_frame:
                return 0
            seen.add(fn)
            best = fn_frame[fn] + RUST_SPILL
            child = 0
            for callee in fn_calls.get(fn, ()):
                if callee in fn_frame:
                    child = max(child, walk(callee))
            return best + child
        return walk(export)

    return {name: tree(name) for name in exports if name in fn_frame}, exports


def lock_is_nonreentrant(texts):
    for _path, text in texts:
        body = extract_body(text, "spin_lock")
        if body and re.search(
            r"__sync_bool_compare_and_swap\s*\(\s*&lock->locked\s*,\s*0",
            body,
        ):
            return True
    return False


def build_graph(frames, edges, extra_edges):
    graph = defaultdict(set)
    nodes = set(frames)
    for src, dsts in edges.items():
        nodes.add(src)
        for dst in dsts:
            nodes.add(dst)
            graph[src].add(dst)
    for src, dsts in extra_edges.items():
        nodes.add(src)
        for dst in dsts:
            nodes.add(dst)
            graph[src].add(dst)
    return graph, nodes


def scc_bound(comp, graph, direct_self, source_bounds, nonreentrant, calls_lock):
    if len(comp) == 1:
        node = comp[0]
        if node not in graph.get(node, ()):
            return 1
        # A self-edge that the compiler did not emit, added only when a
        # function pointer was resolved, is not syntactic recursion.
        if node not in direct_self:
            return 2
        bound = source_bounds.get(node)
        if bound is None or bound <= 1:
            return None
        return bound
    if nonreentrant and any(node in calls_lock for node in comp):
        return 2
    return None


def longest(graph, nodes, weight):
    """weight(node) is an int, or None when the node is unbounded.
    Returns (depth, path of scc ids) per component id, with None for unbounded."""
    index = 0
    stack = []
    on = set()
    idx = {}
    low = {}
    comp_of = {}
    comps = []

    def strong(v):
        nonlocal index
        idx[v] = low[v] = index
        index += 1
        stack.append(v)
        on.add(v)
        for w in graph.get(v, ()):
            if w not in idx:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            cid = len(comps)
            comps.append(comp)
            for w in comp:
                comp_of[w] = cid

    for v in list(nodes):
        if v not in idx:
            strong(v)
    return comps, comp_of


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reports", type=pathlib.Path, default=None)
    ap.add_argument("--no-source", action="store_true")
    ap.add_argument("--root", action="append", default=None)
    ap.add_argument("--budget", type=int, default=None)
    ap.add_argument("--asm-reserve", type=int, default=None)
    args = ap.parse_args()

    problems = []
    limit = None
    report_root = args.reports if args.reports is not None else ROOT / "src"
    loaded = load_reports(report_root)
    if loaded[0] is None:
        for p in loaded[3]:
            print(p)
        return 1
    frames, kinds, edges, problems, indirect_at, raw_edges = loaded
    for name, kind in kinds.items():
        resolved = resolve_name(name, frames)
        if kind == "dynamic":
            problems.append("stack-budget: %s has an unbounded dynamic frame" % resolved)

    direct_self = {src for src, dsts in edges.items() if src in dsts}
    extra = defaultdict(set)
    syscall_count = 0
    source_bounds = {}
    calls_lock = set()
    nonreentrant = False
    rust_frames = {}

    if not args.no_source:
        macros = macro_values()
        c_texts = []
        for path in sorted((ROOT / "src").rglob("*.c")):
            c_texts.append((path, path.read_text(encoding="utf-8", errors="replace")))
        nonreentrant = lock_is_nonreentrant(c_texts)
        if not nonreentrant:
            problems.append(
                "stack-budget: spin_lock is not the compare-and-swap from zero, so a cycle has no bound"
            )
        # Bounds for every direct self-call.
        for src in list(direct_self):
            bound = recursion_bound(resolve_name(src, frames), macros, c_texts)
            source_bounds[resolve_name(src, frames)] = bound
        # Also functions that are self-recursive only after name resolution.
        for src in list(edges):
            if src in edges.get(src, ()):
                if src not in source_bounds:
                    source_bounds[src] = recursion_bound(src, macros, c_texts)
        if os.environ.get("STACK_BUDGET_DEBUG"):
            for name, bound in sorted(source_bounds.items()):
                print("stack-budget: bound %s %s" % (name, bound))

        pre_syscall, err = gcc_preprocess(ROOT / "src" / "kernel" / "syscall.c")
        if err:
            problems.append(err)
            handlers = []
        else:
            handlers = syscall_handlers(pre_syscall)
            if handlers is None:
                problems.append("stack-budget: syscall_table did not preprocess")
                handlers = []
        for handler in handlers:
            resolved = resolve_name(handler, frames)
            if resolved not in frames:
                problems.append("stack-budget: ship handler %s has no stack frame" % handler)
                continue
            extra["syscall_handler"].add(resolved)
            syscall_count += 1

        # Device and other member calls. Preprocess only the files that assign
        # or call the members; the preprocessor drops the branches the default
        # build does not compile.
        want = []
        member_use = re.compile(
            r"(?:->|\.)(?:%s)\b" % "|".join(MEMBERS)
        )
        for path in sorted((ROOT / "src").rglob("*.c")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if member_use.search(text):
                want.append(path)
        pre_blobs = []
        for path in want:
            blob, err = gcc_preprocess(path)
            if err:
                problems.append(err)
                continue
            pre_blobs.append((path, blob))
        assigned = defaultdict(set)
        for _path, blob in pre_blobs:
            for member, names in assignments(blob).items():
                assigned[member] |= names
        for _path, blob in pre_blobs:
            # Walk definitions in the preprocessed text by the same extractor,
            # limited to functions the call graph says make an indirect call.
            for fn in list(indirect_at):
                resolved = resolve_name(fn, frames)
                if resolved == "syscall_handler":
                    continue
                body = extract_body(blob, source_name(resolved))
                if body is None:
                    continue
                for member in members_called(body):
                    for target in assigned.get(member, ()):
                        extra[resolved].add(resolve_name(target, frames))

        rust_frames, exports = rust_function_frames()
        for src, dsts in list(edges.items()):
            for dst in dsts:
                if dst.startswith("rust_") and dst not in frames:
                    if dst not in rust_frames:
                        problems.append("stack-budget: %s has no Rust frame estimate" % dst)
                    else:
                        frames[dst] = rust_frames[dst]
        for src, dsts in extra.items():
            for dst in dsts:
                if dst.startswith("rust_") and dst not in frames and dst in rust_frames:
                    frames[dst] = rust_frames[dst]

        for src, dsts in edges.items():
            if "spin_lock" in dsts:
                calls_lock.add(src)
        # A lock the compiler inlined has no edge. The call in the body is
        # the same fact.
        for _path, text in c_texts:
            for name in re.findall(r"(?m)^[A-Za-z_].*\b([A-Za-z_]\w*)\s*\(", text):
                body = extract_body(text, name)
                if body and re.search(r"\bspin_lock\s*\(", body):
                    calls_lock.add(name)

    if args.root:
        roots = args.root
    elif args.no_source:
        problems.append("stack-budget: a fixture must name --root")
        roots = []
    else:
        asm = (ROOT / "src" / "kernel" / "lowlevel64.S").read_text(encoding="utf-8", errors="replace")
        roots = asm_roots(asm)
        if "interrupt_handler64" not in roots:
            problems.append("stack-budget: interrupt_handler64 is not a root")
        reserve, err = asm_reserve(asm)
        if err:
            problems.append(err)
            reserve = None
        if args.asm_reserve is not None:
            reserve = args.asm_reserve
        if args.budget is not None:
            limit = args.budget
        else:
            size = kernel_stack_size()
            if size is None or reserve is None:
                problems.append("stack-budget: KERNEL_STACK_SIZE or the ISR reserve is missing")
                limit = None
            else:
                limit = size - reserve
    if args.no_source:
        if args.budget is None:
            problems.append("stack-budget: a fixture must name --budget")
            limit = None
        else:
            limit = args.budget
        reserve = args.asm_reserve or 0

    # Frames the graph will use. An unknown non-Rust callee is a header
    # inline already counted in its caller.
    graph, nodes = build_graph(frames, edges, extra)

    # Multiplicity per node from its SCC, computed after the graph is closed.
    comps, comp_of = longest(graph, nodes, None)
    multi = {}
    unbounded = set()
    for comp in comps:
        # direct_self is in resolved names, matching graph nodes.
        bound = scc_bound(comp, graph, direct_self, source_bounds, nonreentrant or False, calls_lock)
        if bound is None:
            for node in comp:
                unbounded.add(node)
            if os.environ.get("STACK_BUDGET_DEBUG"):
                print("stack-budget: unbounded-scc %d %s" % (len(comp), " ".join(sorted(comp)[:24])))
            continue
        for node in comp:
            multi[node] = bound

    # One bound for the whole component. Multiplying each frame and then
    # the sum would count the recursion twice.
    cost = []
    for comp in comps:
        if any(node in unbounded for node in comp):
            cost.append(None)
            continue
        bound = multi.get(comp[0], 1)
        cost.append(sum(frames.get(node, 0) for node in comp) * bound)

    dag = defaultdict(set)
    for src, dsts in graph.items():
        for dst in dsts:
            if comp_of.get(src) != comp_of.get(dst):
                dag[comp_of[src]].add(comp_of[dst])

    memo = {}

    def depth_of(cid):
        if cid in memo:
            return memo[cid]
        if cost[cid] is None:
            memo[cid] = None
            return None
        best = 0
        for nxt in dag.get(cid, ()):
            d = depth_of(nxt)
            if d is None:
                memo[cid] = None
                return None
            best = max(best, d)
        memo[cid] = cost[cid] + best
        return memo[cid]

    if problems:
        for p in problems:
            print(p)
        return 1
    if limit is None:
        print("stack-budget: no limit")
        return 1

    if not args.no_source:
        print("stack-budget: syscall-edges %d" % syscall_count)
        if syscall_count < SYSCALL_EDGE_FLOOR:
            print("stack-budget: the ship table resolved %d handlers" % syscall_count)
            return 1

    over = False
    for root in roots:
        resolved = resolve_name(root, frames)
        if resolved not in comp_of and root not in comp_of:
            print("stack-budget: root %s is not in the call graph" % root)
            return 1
        cid = comp_of.get(resolved, comp_of.get(root))
        d = depth_of(cid)
        if d is None:
            print("stack-budget: %s is unbounded" % root)
            over = True
            continue
        print("stack-budget: %s %d of %d" % (root, d, limit))
        if not args.no_source and root == "interrupt_handler64" and d < DEPTH_FLOOR:
            print("stack-budget: interrupt path is %d bytes, which is not the syscall path" % d)
            return 1
        if d >= limit:
            over = True
    if over:
        print("stack-budget: over")
        return 1
    print("stack-budget: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
