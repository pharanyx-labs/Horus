# Third-party material

Everything in this repository is MIT-licensed work of Pharanyx Labs unless it is
listed here. A shipped asset with no stated origin is a licence question nobody can
answer later, which is why this file exists.

The build also *fetches* third-party source that is not vendored here; that is
listed separately at the end, because what the tree contains and what the build
downloads are different questions.

---

## Vendored source

### `userspace/ports/coreutils/`: GNU coreutils 9.5

Eleven programs (`echo`, `true`, `false`, `basename`, `dirname`, `cat`, `head`, `seq`, `wc`,
`printf`, `tail`) and `wc.h`, **byte-identical** to coreutils 9.5, under the **GNU GPL version 3
or later**, with the licence text in `COPYING` beside them. The glue in `port/` is written for
Horus and is MIT. Details in [`userspace/ports/coreutils/README.md`](userspace/ports/coreutils/README.md).

### `userspace/ports/tcc/`: TinyCC 0.9.27

The x86-64 subset of the Tiny C Compiler, **byte-identical** to 0.9.27, under the **GNU LGPL
version 2.1**, with the licence text in `COPYING` beside it. The glue in `port/` is written for
Horus and is MIT. Details in [`userspace/ports/tcc/README.md`](userspace/ports/tcc/README.md).

Both are separate programs aggregated with the MIT kernel, not linked into it. They are built
as boot modules only in development builds (`make run`); the install media carries neither.

## Vendored assets

### `include/console_font.h` — `font_8x16`

**Authored for Horus.** MIT, with the rest of the tree. Not derived from any
existing font.

It was written rather than adopted, deliberately. The obvious alternative was to
take a permissively licensed console font, there are several, and one would
have been less work, but reproducing another font's glyphs from memory and
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
carries no attribution, no upstream, and no licence statement. Its ASCII half
draws seven pixels wide in an eight-pixel cell, and the table is uploaded into the
VGA font plane at `0xA0000` by `vga_initialize_text_mode_80x50`, so it is *shipped*
and *rendered*, not merely present.

The unknown provenance is the ASCII half only. The code points above `0x7F` (line
drawing, blocks, shades, arrows and marks, added 2026-09-25) are authored for
Horus under the tree's MIT licence: the lines, blocks and shades are rows sampled
from the 8x16 above, and the rest were drawn at 8x8 for this table.

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
