#!/usr/bin/env python3
"""Add the C <-> Rust FFI edges that AST-per-language extraction cannot see.

WHY THIS EXISTS

graphify extracts each language separately, so a C function calling a
`#[no_mangle] pub extern "C"` Rust function produces no edge: the call site is in
a C file, the definition is in a Rust file, and nothing relates them. The result
is not a missing detail, it is a WRONG ANSWER to the question the graph is asked
first. On 2026-08-30, `graphify explain rust_cap_lookup` listed only unit tests
and Kani harnesses as callers, and the reasonable conclusion -- that the function
is not on a live path -- is false: `cap_lookup` in src/kernel/capability.c calls
it on every capability check in the kernel. A raw grep is what caught it.

That matters more here than in most repositories, because CLAUDE.md makes
graphify MANDATORY orientation before reading any source. A blind spot in it is
not a gap in a convenience, it is a confident wrong answer at the exact moment
nobody has looked at the code yet.

WHAT IT DOES

Two directions, both derived from the tree rather than declared by hand:

  C -> Rust   every `#[no_mangle] pub extern "C" fn NAME` in rust/src, and every
              C function whose body calls NAME.
  Rust -> C   every `extern "C" { fn NAME(...); }` imported by Rust, and the C
              function of that name.

Edges are written with `_origin: "ffi"` so a re-run replaces exactly its own
edges and nothing else. Running it twice is the same as running it once.

Call sites inside comments are skipped: the kernel's comments quote code
constantly (src/kernel/syscall.c has a worked example of a removed fallback
written as `c = cap_lookup(8, CAP_RIGHT_READ);`), and an edge derived from a
comment is a claim about code that does not exist.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRAPH = ROOT / "graphify-out" / "graph.json"
RUST_DIRS = [ROOT / "rust" / "src"]
C_DIRS = [ROOT / "src", ROOT / "userspace"]

EXPORT_RE = re.compile(
    r"#\[no_mangle\][^}]*?pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.S)
IMPORT_BLOCK_RE = re.compile(r'extern\s+"C"\s*\{(.*?)\}', re.S)
IMPORT_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")


def strip_comments(text):
    """Blank out /* */ and // spans, preserving line structure and offsets."""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text[i] in "\"'":
            q = text[i]
            j = i + 1
            while j < n and text[j] != q:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join(c if c == "\n" else " " for c in text[i:j]))
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def rust_exports():
    syms = {}
    for d in RUST_DIRS:
        for f in d.rglob("*.rs"):
            for m in EXPORT_RE.finditer(f.read_text(errors="ignore")):
                syms[m.group(1)] = f.relative_to(ROOT).as_posix()
    return syms


def rust_imports():
    syms = {}
    for d in RUST_DIRS:
        for f in d.rglob("*.rs"):
            txt = f.read_text(errors="ignore")
            for blk in IMPORT_BLOCK_RE.finditer(txt):
                for m in IMPORT_FN_RE.finditer(blk.group(1)):
                    syms[m.group(1)] = f.relative_to(ROOT).as_posix()
    return syms


def c_sources():
    for d in C_DIRS:
        for pat in ("*.c", "*.h"):
            for f in d.rglob(pat):
                yield f


def index_nodes(graph):
    """label -> [node], and source_file -> [(line, node_id)] for callables."""
    by_label, by_file = {}, {}
    for nd in graph["nodes"]:
        by_label.setdefault(nd.get("label"), []).append(nd)
        if nd.get("_callable") and nd.get("source_file"):
            loc = str(nd.get("source_location") or "")
            m = re.match(r"L(\d+)", loc)
            if m:
                by_file.setdefault(nd["source_file"], []).append(
                    (int(m.group(1)), nd["id"]))
    for v in by_file.values():
        v.sort()
    return by_label, by_file


def enclosing(by_file, relpath, line):
    """The callable whose definition starts nearest above `line`."""
    spans = by_file.get(relpath)
    if not spans:
        return None
    best = None
    for start, nid in spans:
        if start <= line:
            best = nid
        else:
            break
    return best


def _label_of(by_label, node_id):
    for lbl, nds in by_label.items():
        for nd in nds:
            if nd["id"] == node_id:
                return lbl
    return None


def node_for(by_label, name, want_prefix):
    """Callable labels carry a trailing `()` in the graph ("cap_lookup()"), so a
    bare-name match silently finds nothing. That cost the first run of this tool
    every one of its 133 edges, reported as "no enclosing callable node" because
    the diagnostic below could not tell the two causes apart -- the same defect
    this repository keeps finding in its own gates."""
    for cand in (name, f"{name}()"):
        for nd in by_label.get(cand, []):
            if (nd.get("source_file") or "").startswith(want_prefix):
                return nd["id"]
    return None


def selftest():
    """Assert the tool can still SEE the FFI, with no graph required.

    The injector's worst failure is silence: if the export regex goes stale --
    the FFI moves file, gains an attribute, changes spelling -- it finds nothing,
    injects nothing, and the graph quietly returns to answering "no callers" for
    every Rust function the kernel calls. That is the original defect, restored,
    with no error anywhere. This runs in CI, where there is no graph to check
    against, and asserts the tree-reading half still works.
    """
    exports = rust_exports()
    problems = []
    if len(exports) < 10:
        problems.append(f"only {len(exports)} extern \"C\" exports found in rust/src; "
                        f"the export pattern has probably gone stale")
    for must in ("rust_cap_lookup", "rust_cap_grant_into"):
        if must not in exports:
            problems.append(f"{must} is not among the detected exports")
    if problems:
        print("FAIL: tools/ffi_edges.py can no longer see the FFI boundary")
        for pr in problems:
            print(f"  - {pr}")
        return 1
    print(f"PASS: {len(exports)} extern \"C\" exports detected, including the "
          f"capability entry points")
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    check = "--check" in sys.argv
    if not GRAPH.exists():
        print(f"no graph at {GRAPH}; run `graphify update .` first", file=sys.stderr)
        return 2
    graph = json.loads(GRAPH.read_text())
    by_label, by_file = index_nodes(graph)

    exports = rust_exports()
    imports = rust_imports()
    if not exports:
        print("no #[no_mangle] extern \"C\" exports found -- has the FFI moved?",
              file=sys.stderr)
        return 2

    prior = sum(1 for e in graph["links"] if e.get("_origin") == "ffi")
    kept = [e for e in graph["links"] if e.get("_origin") != "ffi"]
    added, unresolved = [], []
    seen = set()

    # ---- C -> Rust -------------------------------------------------------
    for f in c_sources():
        rel = f.relative_to(ROOT).as_posix()
        body = strip_comments(f.read_text(errors="ignore"))
        lines = body.split("\n")
        for i, line in enumerate(lines, 1):
            for sym in exports:
                if not re.search(rf"\b{re.escape(sym)}\s*\(", line):
                    continue
                # A PROTOTYPE IS NOT A CALL, and neither "the line ends in ;"
                # nor "the statement ends in ;" separates them -- an ordinary
                # call statement ends in `;` too, and testing that threw away
                # 94 real edges. What distinguishes them is what sits IMMEDIATELY
                # BEFORE the symbol:
                #
                #   struct capability *p = rust_cap_lookup(...)   `=`      call
                #   if (!rust_validate_page_fault(...))           `!`      call
                #   return rust_cow_copy_required(...)            return   call
                #   rust_handle_command(buf);                     (start)  call
                #   bool rust_cap_mint(capability_t *dest, ...    `bool`   declaration
                #   capability_t *rust_cap_lookup(...);           `*`      declaration
                #
                # A declarator is preceded by a type token or a `*`; a call is
                # preceded by an operator, a keyword, or nothing. Judging by line
                # shape instead fabricated 22 edges from kernel.h's multi-line
                # prototypes, each attributed to whatever callable sat nearest
                # above -- a STRUCT, mostly. A tool built to stop the graph
                # giving wrong answers was inventing them.
                before = line[:re.search(rf"\b{re.escape(sym)}\s*\(", line).start()].rstrip()
                if before and not re.search(r"(?:[=(,!&|?:;{}\[]|\breturn|\bsizeof)$", before):
                    continue
                tgt = node_for(by_label, sym, "rust/")
                src = enclosing(by_file, rel, i)
                if not tgt:
                    unresolved.append((rel, i, sym, "no Rust node for the symbol"))
                    continue
                if not src:
                    unresolved.append((rel, i, sym, "no enclosing callable node"))
                    continue
                # The enclosing node must be a FUNCTION. Graph labels end in
                # "()" for callables; a struct or typedef nearest-above is how
                # the fabricated header edges got their source.
                if not any(nd["id"] == src and str(nd.get("label", "")).endswith("()")
                           for nd in by_label.get(_label_of(by_label, src), [])):
                    unresolved.append((rel, i, sym, "enclosing node is not a function"))
                    continue
                key = (src, tgt)
                if key in seen:
                    continue
                seen.add(key)
                added.append({
                    "relation": "calls", "context": "call",
                    "confidence": "EXTRACTED", "source_file": rel,
                    "source_location": f"L{i}", "weight": 1.0,
                    "_origin": "ffi", "source": src, "target": tgt,
                    "confidence_score": 1.0,
                })

    # ---- Rust -> C -------------------------------------------------------
    for sym, rel in imports.items():
        tgt = node_for(by_label, sym, "src/") or node_for(by_label, sym, "userspace/")
        src = node_for(by_label, sym.replace("_", ""), "rust/")
        if not tgt:
            continue
        for nd in by_label.get(sym, []):
            if (nd.get("source_file") or "").startswith("rust/"):
                src = nd["id"]
        if src and src != tgt and (src, tgt) not in seen:
            seen.add((src, tgt))
            added.append({
                "relation": "calls", "context": "call",
                "confidence": "EXTRACTED", "source_file": rel,
                "weight": 1.0, "_origin": "ffi",
                "source": src, "target": tgt, "confidence_score": 1.0,
            })

    if check:
        # Assert against the CONCRETE case that went wrong, not just a count: a
        # schema change upstream would leave the count plausible and the answer
        # wrong, which is the failure mode this whole tool exists for.
        problems = []
        if prior == 0:
            problems.append("the graph carries no FFI edges at all "
                            "(run tools/graph_refresh.sh, not `graphify update .`)")
        want = {(e["source"], e["target"]) for e in added}
        have = {(e["source"], e["target"]) for e in graph["links"]
                if e.get("_origin") == "ffi"}
        missing = want - have
        if missing:
            problems.append(f"{len(missing)} FFI edge(s) the tree implies are absent "
                            f"from the graph, e.g. {sorted(missing)[0]}")
        canon = [e for e in graph["links"] if e.get("_origin") == "ffi"
                 and e["target"].endswith("rust_cap_lookup")]
        if not canon:
            problems.append("no edge reaches rust_cap_lookup -- the exact query "
                            "that returned a wrong answer on 2026-08-30")
        if problems:
            print("FAIL: the code graph cannot see the C <-> Rust boundary")
            for pr in problems:
                print(f"  - {pr}")
            return 1
        print(f"PASS: {prior} FFI edges present, including the C callers of rust_cap_lookup")
        return 0

    graph["links"] = kept + added
    GRAPH.write_text(json.dumps(graph))

    print(f"FFI symbols exported by Rust : {len(exports)}")
    print(f"FFI symbols imported by Rust : {len(imports)}")
    print(f"edges injected               : {len(added)} (replaced {prior} from a previous run)")
    if unresolved:
        print(f"unresolved call sites        : {len(unresolved)}")
        for rel, i, sym, why in unresolved[:6]:
            print(f"  {rel}:{i} -> {sym} ({why})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
