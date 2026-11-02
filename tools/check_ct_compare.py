#!/usr/bin/env python3
"""The password compare and the AEAD tag compare are the constant-time ones.

Roadmap 4.20. Two call sites are the check, and each callee is checked too,
because a call to a function that returns on the first differing byte is
still a variable-time compare.

  * verify_user_password (src/kernel/kusers.c) hashes, then calls rust_ct_eq
    on the two PASS_HASH_LEN buffers. The loop above that call compares
    usernames and is not this check: a name is not a secret in the way the
    hash is, and the function already spends the same Argon2id work whether
    or not the account exists.
  * open (rust/src/aead.rs) calls tags_equal. tags_equal xors the whole tag
    into one accumulator and only then compares it. rust_aead_open is the
    only caller of open from C, so a compare planted beside that call is the
    same path.

rust_ct_eq and tags_equal are an xor accumulate over every byte. A return,
a break, a byte compare, or a shortened range inside the loop is a
variable-time compare. tags_equal keeps the accumulator opaque with
black_box; without that, the compiler has put a data-dependent branch back
in front of a compare that was written not to have one.

This does not audit ChaCha20, SHA-256, BLAKE2b, Argon2id or the AEAD, and
it does not replace them. Limitation 5.4 stays the status. A file that
cannot be read, or a function that cannot be found, fails closed.
"""

import re
import sys
from pathlib import Path

KUSERS = Path("src/kernel/kusers.c")
LIB = Path("rust/src/lib.rs")
AEAD = Path("rust/src/aead.rs")

# Byte compares. strcmp stays legal in the username loop; it is not legal
# on the hash, which is the suffix after strong_password_hash.
BYTECMP = ("memcmp", "bcmp", "timingsafe_bcmp")
STRCMP = ("strcmp", "strncmp")

PROBLEMS = []


def fail(msg):
    PROBLEMS.append(msg)


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        fail(f"{path}: cannot be read ({e})")
        return None


def _skip_string(text, i, quote):
    n = len(text)
    i += 1
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        if text[i] == "\n" and quote == '"':
            return i
        i += 1
    return n


def _skip_trivia(text, i):
    """Advance past one comment, string, or char literal. Else return i."""
    n = len(text)
    if text.startswith("//", i):
        j = text.find("\n", i)
        return n if j < 0 else j
    if text.startswith("/*", i):
        j = text.find("*/", i + 2)
        return n if j < 0 else j + 2
    if text[i] == '"':
        return _skip_string(text, i, '"')
    if text[i] == "'":
        # A char literal closes within a few columns. A lifetime ('static)
        # does not. Only the literal is trivia.
        j = i + 1
        if j < n and text[j] == "\\":
            j += 2
        else:
            j += 1
        if j < n and text[j] == "'":
            return j + 1
    return i


def mask(text):
    """Comments and literals become spaces. Newlines stay, so positions match."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        j = _skip_trivia(text, i)
        if j != i:
            out.append("".join("\n" if c == "\n" else " " for c in text[i:j]))
            i = j
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def extract_body(text, open_brace):
    """Interior of the brace that starts at open_brace. None if it does not close."""
    depth = 0
    i = open_brace
    n = len(text)
    start = None
    while i < n:
        j = _skip_trivia(text, i)
        if j != i:
            i = j
            continue
        if text[i] == "{":
            depth += 1
            if depth == 1:
                start = i + 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return None


def _prev_token(text, start):
    """The identifier or operator immediately before start."""
    i = start - 1
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    if i < 0:
        return ""
    if not (text[i].isalnum() or text[i] == "_"):
        return text[i]
    j = i
    while j >= 0 and (text[j].isalnum() or text[j] == "_"):
        j -= 1
    return text[j + 1:i + 1]


def find_def(text, name):
    """Body of the function definition `name`, not of a call to it.

    A definition is preceded by `fn` (Rust) or by a C type (`int` here).
    A call is not, including `if tags_equal(...) {`, whose brace belongs
    to the if and would otherwise look like a second body. Zero
    definitions and more than one are both refusals.
    """
    # Mask the whole file once. A match whose text disappeared was inside
    # a comment or a literal, and is not a definition. Masking only the
    # match span cannot see the comment that contains it.
    masked_file = mask(text)
    bodies = []
    for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text):
        if masked_file[m.start():m.end()] != text[m.start():m.end()]:
            continue
        prev = _prev_token(text, m.start())
        if prev not in ("fn", "int", "void", "bool", "char"):
            continue
        paren = m.end() - 1
        depth = 0
        i = paren
        n = len(text)
        closed = None
        while i < n:
            j = _skip_trivia(text, i)
            if j != i:
                i = j
                continue
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    closed = i + 1
                    break
            i += 1
        if closed is None:
            continue
        k = closed
        while k < n and text[k] in " \t\r\n":
            k += 1
        if text.startswith("->", k):
            brace = None
            while k < n:
                j = _skip_trivia(text, k)
                if j != k:
                    k = j
                    continue
                if text[k] == "{":
                    brace = k
                    break
                if text[k] == ";":
                    break
                k += 1
        elif k < n and text[k] == "{":
            brace = k
        else:
            brace = None
        if brace is None:
            continue
        body = extract_body(text, brace)
        if body is not None:
            bodies.append(body)
    return bodies


def calls(masked):
    """(name, args-text) for each call in already-masked code."""
    found = []
    i = 0
    keywords = {"if", "for", "while", "switch", "return", "sizeof", "catch"}
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", masked):
        name = m.group(1)
        if name in keywords:
            continue
        paren = m.end() - 1
        depth = 0
        k = paren
        n = len(masked)
        while k < n:
            if masked[k] == "(":
                depth += 1
            elif masked[k] == ")":
                depth -= 1
                if depth == 0:
                    found.append((name, masked[paren + 1:k]))
                    break
            k += 1
    return found


def split_args(args):
    parts = []
    depth = 0
    start = 0
    for i, c in enumerate(args):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(args[start:i].strip())
            start = i + 1
    tail = args[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def rust_loops(body):
    """(header, inner, start, end) for each `for` loop. end is past the brace."""
    masked = mask(body)
    loops = []
    i = 0
    while True:
        m = re.search(r"\bfor\b", masked[i:])
        if not m:
            break
        abs_i = i + m.start()
        k = abs_i
        brace = None
        n = len(body)
        while k < n:
            j = _skip_trivia(body, k)
            if j != k:
                k = j
                continue
            if body[k] == "{":
                brace = k
                break
            k += 1
        if brace is None:
            break
        inner = extract_body(body, brace)
        if inner is None:
            break
        end = brace + 1 + len(inner) + 1
        loops.append((body[abs_i:brace], inner, abs_i, end))
        i = end
    return loops


def xor_loop(header, inner, left, right, end_tok):
    """The loop covers end_tok and its body is only an xor accumulate."""
    hm = mask(header)
    if not re.search(
            r"\bfor\s+[A-Za-z_]\w*\s+in\s+0\s*\.\.\s*" + re.escape(end_tok) + r"\b",
            hm):
        return "range"
    im = mask(inner)
    if re.search(r"\b(return|break|continue|if|match|while)\b", im):
        return "early"
    if "!=" in im or "==" in im:
        return "early"
    if (left + "[") not in im or (right + "[") not in im:
        return "shape"
    if "^" not in im or "|=" not in im:
        return "shape"
    return None


def check_xor_fn(text, name, left, right, end_tok, require_black_box):
    bodies = find_def(text, name)
    if len(bodies) != 1:
        fail(f"{name}: not found" if not bodies else f"{name}: more than one definition")
        return
    body = bodies[0]
    loops = rust_loops(body)
    if len(loops) != 1:
        # A slice equality (`a == b`) has no loop. Say so: that is the plant.
        if "==" in mask(body):
            fail(f"{name}: slice equality")
        else:
            fail(f"{name}: not an xor accumulate over the whole input")
        return
    header, inner, _start, end = loops[0]
    why = xor_loop(header, inner, left, right, end_tok)
    if why == "early":
        fail(f"{name}: returns early")
        return
    if why is not None:
        fail(f"{name}: not an xor accumulate over the whole input")
        return
    after = mask(body[end:])
    before = mask(body[:loops[0][2]])
    if "!=" in after or (left + "[") in after or (right + "[") in after:
        fail(f"{name}: the result is not the accumulator")
        return
    if "diff" not in after or "==" not in after or not re.search(r"==\s*0\b", after):
        fail(f"{name}: the result is not the accumulator")
        return
    if require_black_box and "black_box" not in after:
        fail(f"{name}: black_box does not cover the accumulator")
        return
    # A return before the loop is the null/empty refusal in rust_ct_eq.
    # A return after the loop is fine when the value is the accumulator,
    # which the checks above already required. A second early-exit shape
    # before the loop (a byte compare) is not that refusal.
    if (left + "[") in before or "!=" in before:
        fail(f"{name}: returns early")


def check_password(text):
    bodies = find_def(text, "verify_user_password")
    if len(bodies) != 1:
        fail("verify_user_password: not found" if not bodies
             else "verify_user_password: more than one definition")
        return
    body = bodies[0]
    masked = mask(body)
    m = re.search(r"\bstrong_password_hash\s*\(", masked)
    if not m:
        fail("password path: does not hash before the compare")
        return
    hash_at = m.start()
    prefix, suffix = masked[:hash_at], masked[hash_at:]
    for name, _args in calls(masked):
        if name in BYTECMP:
            fail(f"password path: {name} is a variable-time compare")
    for name, _args in calls(suffix):
        if name in STRCMP:
            fail(f"password path: {name} is a variable-time compare")
    ct = [(name, args) for name, args in calls(suffix) if name == "rust_ct_eq"]
    if calls_named(prefix, "rust_ct_eq"):
        fail("password path: rust_ct_eq is not the hash compare")
    if len(ct) != 1:
        fail("password path: rust_ct_eq is not the hash compare")
    else:
        args = split_args(ct[0][1])
        if (len(args) != 3
                or {args[0], args[1]} != {"computed", "expect"}
                or args[2] != "PASS_HASH_LEN"):
            fail("password path: rust_ct_eq arguments are not the hash and PASS_HASH_LEN")
    if re.search(r"\b(computed|expect|pass_hash)\s*\[", suffix):
        fail("password path: indexed hash compare")
    if re.search(r"\bbreak\b", suffix) or "!=" in suffix:
        fail("password path: indexed hash compare")


def calls_named(masked, name):
    return any(n == name for n, _a in calls(masked))


def check_open(text):
    bodies = find_def(text, "open")
    if len(bodies) != 1:
        fail("open: not found" if not bodies else "open: more than one definition")
        return
    masked = mask(bodies[0])
    if not calls_named(masked, "tags_equal"):
        fail("open: does not call tags_equal")
    for name, _args in calls(masked):
        if name in BYTECMP or name in STRCMP:
            fail(f"open: {name} is a variable-time compare")
    # The zeroing loop and the tags_equal call contain no byte equality.
    # `==` or `!=` here is a compare of the tag, or of something that was
    # not in the function when this check was written. Either is a refusal.
    if "==" in masked or "!=" in masked:
        fail("open: compares the tag in variable time")


def check_ffi_open(text):
    bodies = find_def(text, "rust_aead_open")
    if len(bodies) != 1:
        fail("rust_aead_open: not found" if not bodies
             else "rust_aead_open: more than one definition")
        return
    masked = mask(bodies[0])
    opens = [args for name, args in calls(masked) if name == "open"]
    if len(opens) != 1:
        fail("rust_aead_open: does not call open")
    for name, _args in calls(masked):
        if name in BYTECMP or name in STRCMP:
            fail(f"rust_aead_open: {name} is a variable-time compare")
    # Length tests (`len == 0`, `len != 0`) are not a tag compare.
    for m in re.finditer(r"([A-Za-z0-9_\]]+)\s*(==|!=)\s*([A-Za-z0-9_\]]+)", masked):
        if m.group(1) != "0" and m.group(3) != "0":
            fail("rust_aead_open: compares the tag in variable time")
            break


def main():
    kusers = read(KUSERS)
    lib = read(LIB)
    aead = read(AEAD)
    if kusers is not None:
        check_password(kusers)
    if lib is not None:
        check_xor_fn(lib, "rust_ct_eq", "sa", "sb", "len", require_black_box=False)
    if aead is not None:
        check_xor_fn(aead, "tags_equal", "a", "b", "AEAD_TAG_LEN",
                     require_black_box=True)
        check_open(aead)
        check_ffi_open(aead)
    if PROBLEMS:
        for p in PROBLEMS:
            print(f"ct-compare: {p}")
        return 1
    print("ct-compare: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
