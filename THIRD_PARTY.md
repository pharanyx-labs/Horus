# Third-party material

Everything in this repository is MIT-licensed work of Pharanyx Labs unless it is
listed here. This file exists because a shipped asset with no stated origin is a
licence question nobody can answer later, and one was found in the tree on
2026-09-08 -- see the console fonts below.

The build also *fetches* third-party source that is not vendored here; those are
listed separately at the end, because "what we ship" and "what we build against"
are different questions and only the first is a redistribution.

---

## Vendored assets

### `include/console_font.h` — `font_8x16`

**Authored for Horus.** MIT, with the rest of the tree. Not derived from any
existing font.

It was written rather than adopted, deliberately. The obvious alternative was to
take a permissively licensed console font -- there are several, and one would
have been less work -- but reproducing another font's glyphs from memory and
attributing them to it would be a provenance claim that could not be checked,
which is the exact defect the entry below records. A font whose origin is "we
drew it" is one whose licence needs no research.

Metrics and design notes are in the header beside the table. The glyphs were
judged by rendering them, not by reading the bytes: an earlier draft constrained
every glyph to six of the eight columns and `smp` rendered as `snp`, because
lowercase `m` and `n` became indistinguishable at that width. `M N W m w` use
the full cell as a result.

### `include/console_font.h` — `font_8x8`

**Provenance unknown, and this is the honest state rather than a placeholder.**

It has been in the tree since before the current history's console work and
carries no attribution, no upstream, and no licence statement. It is ASCII-only,
draws seven pixels wide in an eight-pixel cell, and is uploaded into the VGA font
plane at `0xA0000` by `vga_initialize_text_mode_80x50` -- so it is *shipped* and
*rendered*, not merely present.

It resembles the many small 8x8 bitmap fonts that circulated with early PC
graphics code, several of which are public domain and several of which are not.
Resemblance is not provenance and no attempt is made here to guess.

**Why it is still here.** The 80x50 VGA text mode is an 8x8 cell by definition of
the mode; the hardware renders from the font plane and needs glyphs of that size.
The framebuffer console does not, and uses the authored 8x16 above. Replacing the
8x8 as well is the remaining work, and is tracked in `docs/LIMITATIONS.md`.
Until then this entry is the record that the question is open, which is worth
more than a confident citation nobody verified.

---

## Fetched at build time, not vendored

### newlib

Fetched by `tools/build_newlib.sh`, not committed. Version and SHA-256 are pinned
in that script and verified on every invocation; the tarball is downloaded from
sourceware.org, falling back to `mirrors.kernel.org` if that host is unavailable.
Licensing is newlib's own (a collection of BSD-style licences); it is linked into
userspace programs, not into the kernel.

### GitHub Actions

Every action used by `.github/workflows/` is pinned by commit SHA, and the pins
are updated by Dependabot. Each remains under its own licence; none is vendored.
