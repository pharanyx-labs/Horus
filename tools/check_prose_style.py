#!/usr/bin/env python3
"""Carries the CLAUDE.md section 3 writing rules: the docs and the website are in
British English and use no em dashes, in any form.

Fail the build if the prose of the documentation set breaks either rule.

The set is the one section 3 names as documentation: README.md, site/index.html,
everything under docs/, SECURITY.md, TESTS.md, CHANGES.md, CONTRIBUTING.md and
rust/KANI.md. The rules were first written down as a request, and a request is
what the tree ignored: by 2026-09-21 the set carried over two thousand dashes.
A rule that only a reviewer remembers is a rule that comes back, so this checker
is what keeps them out.

Six rules, each reported with its file and line:

  1. no em dash character (U+2014)
  2. no em dash entity in HTML (`&mdash;`, `&#8212;`, `&#x2014;`)
  3. no spaced double hyphen, the ASCII stand-in for an em dash
  4. no en dash used as a dash: an en dash is for ranges (`0–3`, `P1–P5`),
     so one with whitespace on either side is a dash in disguise
  5. no American spelling from the list in `SPELLING` (the words section 3 names,
     and the ones the tree has actually carried)
  6. no table cell that holds only a comma: the mark a mechanical dash
     replacement leaves when an em dash stood for "not applicable" in a cell
     (PR #249 left 21 of them)

What is not prose, and so not checked: fenced code blocks and inline code spans
in Markdown; `pre`, `code`, `script` and `style` elements, tag attributes and
comments in HTML; and text inside double quotation marks. The last one is
deliberate. The docs quote source comments and printed output verbatim, and a
quotation that has been re-punctuated is no longer a quotation. Identifiers keep
their spelling for the same reason, and they live in code spans.

`license` is not on the spelling list. British English spells the noun `licence`
and the verb `license`, and telling the two apart needs a parser rather than a
regex; a rule that cannot be right is not added.

Exit 0 if clean, 1 otherwise.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

TOP_LEVEL = ("README.md", "SECURITY.md", "TESTS.md", "CHANGES.md",
             "CONTRIBUTING.md", "rust/KANI.md", "site/index.html")

# American stem or word -> the British spelling to use. Matched as a whole word,
# ignoring case. An entry ending in `*` also matches any suffix, so `authoriz*`
# covers authorized and authorization; `unauthoriz*` needs its own entry
# because a word boundary never falls inside a word.
SPELLING = {
    "authoriz*": "authoris-", "unauthoriz*": "unauthoris-",
    "behavior*": "behaviour", "color": "colour", "colors": "colours",
    "colored": "coloured", "defense": "defence", "defenses": "defences",
    "initializ*": "initialis-", "organiz*": "organis-", "analyz*": "analys-",
    "center": "centre", "centers": "centres", "centered": "centred",
    "catalog": "catalogue", "catalogs": "catalogues",
    "serializ*": "serialis-", "sanitiz*": "sanitis-", "realiz*": "realis-",
    "generaliz*": "generalis-", "normaliz*": "normalis-", "minimiz*": "minimis-",
    "maximiz*": "maximis-", "prioritiz*": "prioritis-", "optimiz*": "optimis-",
    "recogniz*": "recognis-", "summariz*": "summaris-", "finaliz*": "finalis-",
    "utiliz*": "utilis-", "synchroniz*": "synchronis-", "categoriz*": "categoris-",
    "emphasiz*": "emphasis-", "randomiz*": "randomis-", "specializ*": "specialis-",
    "standardiz*": "standardis-", "virtualiz*": "virtualis-",
    "customiz*": "customis-",
    "modeled": "modelled", "modeling": "modelling", "labeled": "labelled",
    "labeling": "labelling", "canceled": "cancelled", "canceling": "cancelling",
    "signaled": "signalled", "signaling": "signalling", "traveled": "travelled",
    "theater": "theatre", "favor*": "favour", "honor*": "honour",
    "neighbor*": "neighbour",
}


def _spelling_re():
    alts = []
    for word in SPELLING:
        if word.endswith("*"):
            alts.append(re.escape(word[:-1]) + r"\w*")
        else:
            alts.append(re.escape(word))
    return re.compile(r"\b(?:%s)\b" % "|".join(alts), re.I)


SPELLING_RE = _spelling_re()


def lookup_spelling(found):
    low = found.lower()
    for word, brit in SPELLING.items():
        if word.endswith("*") and low.startswith(word[:-1]):
            return brit
        if low == word:
            return brit
    return "?"


RULES = (
    ("1", "em dash", re.compile("—")),
    ("2", "em dash entity", re.compile(r"&mdash;|&#8212;|&#x2014;", re.I)),
    ("3", "spaced double hyphen", re.compile(r"(?<=\s)--(?=\s)")),
    ("4", "en dash used as a dash",
     re.compile(r"(?<=\s)(?:–|&ndash;|&#8211;)|(?:–|&ndash;|&#8211;)(?=\s)")),
)

# Run on the raw text, not the prose: masking a cell's code spans leaves only
# the commas between them, and `frame_slot`, `vaddr` is not a mangled dash.
CELL_RULE = ("6", "table cell holding only a comma", re.compile(r"\|[ \t]*,[ \t]*(?=\|)"))


def doc_set(root):
    files = [root / f for f in TOP_LEVEL if (root / f).is_file()]
    files += sorted(p for p in (root / "docs").rglob("*")
                    if p.is_file() and p.suffix in (".md", ".html"))
    return files


# What masked text is replaced with. Not a space: an en dash between two code
# spans (`isr34`–`isr47`) is a range, and blanking the spans to spaces would
# make it look like a spaced dash. Not a word character either, so a masked
# span next to a word does not change where the word begins.
FILL = "\x00"


def _blank(out, start, end):
    # Keep newlines, so offsets and line numbers survive.
    for i in range(start, end):
        if out[i] != "\n":
            out[i] = FILL


def _mask_quotes(text, out):
    # A quotation stays on one paragraph and is short; the bounds stop an
    # unmatched quotation mark from hiding the rest of a file.
    cur = "".join(out)
    for m in re.finditer(r'"[^"\n]*(?:\n(?!\s*\n)[^"\n]*){0,4}"|“[^”]{0,400}”', cur):
        if "\n\n" not in m.group(0) and len(m.group(0)) <= 400:
            _blank(out, m.start(), m.end())


def mask_markdown(text):
    out = list(text)
    for m in re.finditer(r"^([ \t]*)(```|~~~).*?^\1\2[^\n]*$", text, re.M | re.S):
        _blank(out, m.start(), m.end())
    # Pair backticks one paragraph at a time. A code span cannot cross a blank
    # line, and pairing across the whole file lets one stray backtick swap code
    # and prose for everything after it.
    cur = "".join(out)
    for para in re.finditer(r"(?:[^\n]|\n(?![ \t]*\n))+", cur):
        for m in re.finditer(r"(`+)(?:(?!\1).)*?\1", para.group(0), re.S):
            _blank(out, para.start() + m.start(), para.start() + m.end())
    _mask_quotes(text, out)
    return "".join(out)


def mask_html(text):
    out = list(text)
    for m in re.finditer(r"<!--.*?-->", text, re.S):
        _blank(out, m.start(), m.end())
    for tag in ("style", "script", "pre", "code"):
        for m in re.finditer(r"<%s\b.*?</%s>" % (tag, tag), text, re.S | re.I):
            _blank(out, m.start(), m.end())
    cur = "".join(out)
    for m in re.finditer(r"<[^>]*>", cur, re.S):
        _blank(out, m.start(), m.end())
    _mask_quotes(text, out)
    return "".join(out)


def check_file(path, root):
    text = path.read_text(encoding="utf-8")
    prose = mask_html(text) if path.suffix == ".html" else mask_markdown(text)
    rel = path.relative_to(root)
    found = []

    def line_of(pos):
        return prose.count("\n", 0, pos) + 1

    for rule, name, pat in RULES:
        for m in pat.finditer(prose):
            found.append((line_of(m.start()), rule, name))
    rule, name, pat = CELL_RULE
    for m in pat.finditer(text):
        found.append((line_of(m.start()), rule, name))
    for m in SPELLING_RE.finditer(prose):
        found.append((line_of(m.start()), "5",
                      f"American spelling '{m.group(0)}' (use {lookup_spelling(m.group(0))})"))
    return [(str(rel), ln, rule, name) for ln, rule, name in sorted(found)]


def main(argv):
    root = ROOT
    files = doc_set(root)
    problems = []
    for f in files:
        problems += check_file(f, root)

    print(f"documentation files checked: {len(files)}")
    if problems:
        print(f"\nFAIL: {len(problems)} breach(es) of the CLAUDE.md section 3 writing rules\n")
        for rel, ln, rule, name in problems:
            print(f"  - {rel}:{ln}: rule {rule}: {name}")
        return 1
    print("\nPASS: no em dash in any form, no en dash as a dash, no listed American spelling")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
