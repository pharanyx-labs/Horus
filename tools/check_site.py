#!/usr/bin/env python3
"""The website is what its sources say, its links go somewhere, and it fetches
nothing from anywhere else.

The site is built from site-src/ into site/ by tools/build_site.py, and the built
pages are committed so the site reads offline from a checkout. That arrangement has
four ways to go wrong quietly, and this checker has a rule for each:

  R1  site/ is exactly what a fresh build of site-src/ produces. Otherwise an edit
      made to a built page, or a source edit nobody rebuilt, ships as the site.
  R2  every internal link resolves: the page exists, and so does the #anchor on it.
      A multi-page site's commonest defect is a link to a section that moved.
  R3  nothing loads from another origin. No remote script, stylesheet, image, font,
      frame or CSS url(): the site argues about supply-chain provenance, and a page
      that pulls bytes from a CDN, or phones an analytics host, contradicts it. Plain
      <a href="https://..."> links are fine; following one is the reader's choice.
  R4  every page has exactly one h1, a <title> and a meta description, and every
      page except the home page is reachable from the primary navigation.

Falsified by tools/test_check_site.sh, one arm per rule.
Exit 0 if sound, 1 otherwise.
"""
import html
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"

SUBRESOURCE = re.compile(
    r"<(script|img|iframe|source|video|audio|embed|object|link)\b[^>]*?"
    r"\s(src|href|data|srcset)\s*=\s*\"([^\"]*)\"", re.I | re.S)
CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)", re.I)
CSS_IMPORT = re.compile(r"@import\s+(?:url\()?\s*['\"]?([^'\");]+)", re.I)
HREF = re.compile(r"<a\b[^>]*?\shref=\"([^\"]*)\"", re.I | re.S)
IDS = re.compile(r"\sid=\"([^\"]+)\"")


def remote(url):
    u = url.strip().lower()
    return u.startswith(("http:", "https:", "//", "ftp:"))


def main():
    problems = []

    # R1: built output matches the sources.
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_site.py"), "--check"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        for line in (r.stdout + r.stderr).strip().splitlines():
            problems.append(f"R1 site/ is not what site-src/ builds to: {line}")
        problems.append("R1 run tools/build_site.py and commit site/ with the sources")

    pages = sorted(SITE.glob("*.html"))
    texts = {p.name: p.read_text() for p in pages}
    ids = {name: set(IDS.findall(t)) for name, t in texts.items()}

    for name, t in texts.items():
        # R2: internal links resolve.
        for href in HREF.findall(t):
            href = html.unescape(href)
            if remote(href) or href.startswith(("mailto:", "data:")):
                continue
            target, _, frag = href.partition("#")
            page = target or name
            if page not in texts:
                problems.append(f"R2 {name}: link to a page that does not exist: {href}")
                continue
            if frag and frag not in ids[page]:
                problems.append(f"R2 {name}: link to an anchor that does not exist: {href}")

        # R3: no subresource from another origin.
        for tag, attr, url in SUBRESOURCE.findall(t):
            if tag.lower() == "link":
                rel = re.search(r'<link\b[^>]*\brel="([^"]*)"[^>]*\b' + attr + r'="' + re.escape(url), t, re.I)
                if rel and not re.search(r"stylesheet|icon|preload|prefetch|modulepreload|manifest", rel.group(1), re.I):
                    continue
            if remote(url):
                problems.append(f"R3 {name}: <{tag} {attr}> loads from another origin: {url}")
        for block in re.findall(r"<style\b[^>]*>(.*?)</style>", t, re.S | re.I):
            for url in CSS_URL.findall(block) + CSS_IMPORT.findall(block):
                if remote(url):
                    problems.append(f"R3 {name}: inline CSS loads from another origin: {url}")

        # R4: one h1, a title, a description.
        n_h1 = len(re.findall(r"<h1\b", t, re.I))
        if n_h1 != 1:
            problems.append(f"R4 {name}: has {n_h1} h1 elements; a page has exactly one")
        if not re.search(r"<title>[^<]+</title>", t):
            problems.append(f"R4 {name}: has no <title>")
        if not re.search(r'<meta name="description" content="[^"]+"', t):
            problems.append(f"R4 {name}: has no meta description")

    for css in sorted((SITE / "assets").glob("*.css")):
        c = css.read_text()
        for url in CSS_URL.findall(c) + CSS_IMPORT.findall(c):
            if remote(url):
                problems.append(f"R3 assets/{css.name}: loads from another origin: {url}")

    # R4: every page but the home page is in the primary navigation.
    home = texts.get("index.html", "")
    nav = re.search(r'<nav class="primary"[^>]*>(.*?)</nav>', home, re.S)
    listed = set(HREF.findall(nav.group(1))) if nav else set()
    for name in texts:
        if name != "index.html" and name not in listed:
            problems.append(f"R4 {name}: is not in the primary navigation, so no menu reaches it")

    print(f"pages checked: {len(texts)}")
    if problems:
        print("FAIL: the website is not sound\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("PASS: site/ matches its sources, every internal link resolves, and nothing loads from another origin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
