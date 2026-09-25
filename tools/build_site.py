#!/usr/bin/env python3
"""Build the website: site-src/ in, site/ out. Python standard library only.

WHY A BUILD STEP AT ALL. The site used to be one 2,800-line page, so every part of
it could share one header by being in one file. Spread across pages, the header,
the menu, the footer and the contents rail would otherwise be copied into every
page by hand, and a copy edited in one place and not the others is the drift this
repository keeps a checker for everywhere else. So each page is written once, in
site-src/pages/, and the chrome around it is written once, in site-src/layout.html.

WHY THE OUTPUT IS COMMITTED. The site is meant to be readable offline from a
checkout, with no build and no network. So site/ holds the built pages, and
tools/check_site.py (required job `site`) fails when they are not exactly what this
script produces from site-src/. Edit site-src/, run this, commit both.

A page is an HTML fragment whose first line is a JSON header in a comment:

    <!--page {"title": "Status", "nav": "Status", "order": 5,
              "description": "...", "lede": "...", "layout": "doc"} -->

`layout` is "doc" (contents rail, title, lede, pager) or "home" (the fragment is the
whole body). `nav` is the label in the menu; `order` is its position and the
reading order the previous/next links follow; `"nav_hidden": true` keeps a page
(the home page) out of the menu but in the reading order. A heading may carry
`data-toc="Short label"` for the contents rail and search.

Usage: tools/build_site.py            build site/ from site-src/
       tools/build_site.py --check    exit 1 if site/ differs from a fresh build
"""
import html
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "site-src"
OUT = ROOT / "site"

HEADER = re.compile(r"\A<!--page\s+(\{.*?\})\s*-->\s*\n", re.S)
HEADING = re.compile(r"<(h[23])((?:\s+[^>]*)?)>(.*?)</\1>", re.S)


def text_of(fragment):
    """The visible text of an HTML fragment, whitespace collapsed."""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", fragment)).split())


def slugify(text):
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:60].rstrip("-") or "section"


def load_pages():
    pages = []
    for path in sorted((SRC / "pages").glob("*.html")):
        raw = path.read_text()
        m = HEADER.match(raw)
        if not m:
            sys.exit(f"build_site: {path.relative_to(ROOT)} has no <!--page {{...}} --> header")
        meta = json.loads(m.group(1))
        for key in ("title", "nav", "order", "description", "layout"):
            if key not in meta:
                sys.exit(f"build_site: {path.relative_to(ROOT)} header lacks `{key}`")
        meta["slug"] = path.stem
        meta["file"] = "index.html" if path.stem == "index" else f"{path.stem}.html"
        meta["body"] = raw[m.end():]
        pages.append(meta)
    pages.sort(key=lambda p: p["order"])
    return pages


def add_heading_ids(body):
    """Give every h2 and h3 an id (keeping any it has) and return the outline."""
    used, outline = set(), []

    def fix(m):
        tag, attrs, inner = m.group(1), m.group(2) or "", m.group(3)
        idm = re.search(r'\sid="([^"]+)"', attrs)
        if idm:
            hid = idm.group(1)
        else:
            base = slugify(text_of(inner))
            hid, n = base, 2
            while hid in used:
                hid, n = f"{base}-{n}", n + 1
            attrs = f' id="{hid}"' + attrs
        used.add(hid)
        if "data-toc-skip" not in attrs:
            # A long headline can carry a short label for the contents rail and the
            # search index: <h2 data-toc="Capabilities">A capability can be ...</h2>
            short = re.search(r'\sdata-toc="([^"]+)"', attrs)
            outline.append((tag, hid, html.unescape(short.group(1)) if short else text_of(inner)))
        return f"<{tag}{attrs}>{inner}</{tag}>"

    return HEADING.sub(fix, body), outline


def nav_links(pages, current):
    items = []
    for p in pages:
        if p.get("nav_hidden"):          # the home page: the logo is its link
            continue
        cur = ' aria-current="page"' if p["slug"] == current["slug"] else ""
        items.append(f'<a href="{p["file"]}"{cur}>{html.escape(p["nav"])}</a>')
    return "\n        ".join(items)


def toc_html(outline):
    """The contents rail: h2 entries, each with its h3s nested beneath it."""
    out, item_open, sub_open = ['<ol class="toc__list">'], False, False
    for tag, hid, text in outline:
        link = f'<a href="#{hid}">{html.escape(text)}</a>'
        if tag == "h2":
            if sub_open:
                out.append("</ol>")
                sub_open = False
            if item_open:
                out.append("</li>")
            out.append(f"<li>{link}")
            item_open = True
        else:
            if not item_open:
                out.append("<li>")
                item_open = True
            if not sub_open:
                out.append('<ol class="toc__sub">')
                sub_open = True
            out.append(f"<li>{link}</li>")
    if sub_open:
        out.append("</ol>")
    if item_open:
        out.append("</li>")
    out.append("</ol>")
    return "\n".join(out)


def pager_html(pages, i):
    reading = pages
    idx = next(k for k, p in enumerate(reading) if p["slug"] == pages[i]["slug"])
    parts = ['<nav class="pager" aria-label="Previous and next page">']
    if idx > 0:
        p = reading[idx - 1]
        parts.append(f'<a class="pager__prev" href="{p["file"]}"><span>Previous</span>{html.escape(p["title"])}</a>')
    else:
        parts.append("<span></span>")
    if idx + 1 < len(reading):
        p = reading[idx + 1]
        parts.append(f'<a class="pager__next" href="{p["file"]}"><span>Next</span>{html.escape(p["title"])}</a>')
    parts.append("</nav>")
    return "\n".join(parts)


def build():
    layout = (SRC / "layout.html").read_text()
    pages = load_pages()
    files, index = {}, []
    for i, p in enumerate(pages):
        body, outline = add_heading_ids(p["body"])
        index.append({"t": p["title"], "p": p["title"], "u": p["file"], "k": 1})
        for tag, hid, text in outline:
            index.append({"t": text, "p": p["title"], "u": f'{p["file"]}#{hid}',
                          "k": 2 if tag == "h2" else 3})
        if p["layout"] == "doc":
            lede = f'\n      <p class="lede">{p["lede"]}</p>' if p.get("lede") else ""
            body = (
                '<div class="doc">\n'
                '  <aside class="toc" aria-labelledby="toc-title">\n'
                '    <p class="toc__title" id="toc-title">On this page</p>\n'
                f'    {toc_html(outline)}\n'
                '  </aside>\n'
                '  <main id="main" class="doc__main">\n'
                '    <header class="doc__head">\n'
                f'      <h1>{html.escape(p["title"])}</h1>{lede}\n'
                '    </header>\n'
                f'{body.rstrip()}\n'
                f'    {pager_html(pages, i)}\n'
                '  </main>\n'
                '</div>'
            )
        elif p["layout"] != "home":
            sys.exit(f'build_site: {p["slug"]}: unknown layout {p["layout"]!r}')
        page = (layout
                .replace("{{title}}", html.escape(p["title"] if p["slug"] == "index"
                                                  else f'Horus: {p["title"]}'))
                .replace("{{description}}", html.escape(p["description"], quote=True))
                .replace("{{slug}}", p["slug"])
                .replace("{{nav}}", nav_links(pages, p))
                .replace("{{body}}", body.rstrip()))
        files[OUT / p["file"]] = page
    files[OUT / "assets" / "search-index.js"] = (
        "/* Generated by tools/build_site.py from every page's headings. Do not edit. */\n"
        "window.HORUS_SEARCH = " + json.dumps(index, ensure_ascii=False, indent=0) + ";\n")
    for asset in sorted((SRC / "assets").glob("*")):
        files[OUT / "assets" / asset.name] = asset.read_text()
    return files


def main():
    files = build()
    if "--check" in sys.argv:
        bad = []
        for path, want in sorted(files.items()):
            if not path.exists():
                bad.append(f"missing: {path.relative_to(ROOT)}")
            elif path.read_text() != want:
                bad.append(f"differs from a fresh build: {path.relative_to(ROOT)}")
        built = set(files)
        for path in sorted(OUT.rglob("*")):
            if path.is_file() and path not in built and path.name != "CNAME":
                bad.append(f"not produced by the build: {path.relative_to(ROOT)}")
        for b in bad:
            print(b)
        return 1 if bad else 0
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"build_site: wrote {len(files)} files to {OUT.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
