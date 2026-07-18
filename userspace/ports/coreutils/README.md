# GNU coreutils port

Real, unmodified GNU coreutils source running as a ring-3 program on Horus.

## Licence — read this first

**This subtree is GPLv3, not MIT.** Horus itself is MIT (see the repository
[LICENSE](../../../LICENSE)); the files listed as *upstream* below are copyright
the Free Software Foundation and licensed under the GNU General Public License
version 3 or later, whose text is in [COPYING](COPYING) here.

| File | Origin | Licence |
|---|---|---|
| `echo.c` | coreutils 9.5, `src/echo.c`, **byte-identical** | GPLv3+ |
| `COPYING` | coreutils 9.5 | GPLv3 text |
| `port/*` | written for Horus | MIT (as the rest of the tree) |

The port glue in `port/` is Horus code and stays MIT. Nothing in `port/` is
derived from coreutils; it is a from-scratch implementation of the small
interface the upstream sources expect.

Shipping GPLv3 programs alongside an MIT kernel is ordinary aggregation — the
same arrangement every Linux distribution uses — and the two remain separate
works. The distinction is kept explicit here so it stays obvious to anyone
reading or redistributing the tree.

## Why a shim instead of the real build system

Upstream builds with autoconf + gnulib. Neither survives the trip to a
freestanding target here:

- **No `configure` run is possible.** There is no `x86_64-elf` cross toolchain in
  this tree (userspace is built with the host gcc plus `-ffreestanding` and the
  newlib headers), and `configure`'s feature probes compile *and run* test
  programs, which a bare-metal target cannot do.
- **gnulib is a large dependency.** Every utility includes coreutils'
  `src/system.h` — 822 lines pulling in ~25 further headers (`xalloc.h`,
  `idx.h`, `gettext.h`, `timespec.h`, …) backed by 478 `.c` files in `lib/`.

So the port supplies what upstream would have generated or linked:

- `port/config.h` — replaces the `configure`-generated header (package identity,
  plus `nullptr`/`FALLTHROUGH`, since coreutils 9.5 is C23 and this tree builds
  `-std=gnu99`).
- `port/system.h` — replaces coreutils' `src/system.h` with just the surface the
  ported utilities use.
- `port/assure.h`, `port/c-ctype.h` — replace the two gnulib headers `echo.c`
  includes directly.
- `port/port.c` — implements the gnulib routines called at runtime
  (`set_program_name`, `version_etc`, `close_stdout`, `emit_ancillary_info`).

**The upstream `.c` files are never edited.** `echo.c` is byte-identical to the
9.5 tarball, which is what makes this a port rather than a rewrite: it is the
real implementation — option parsing, `\0NNN`/`\xHH` escape handling, the V9
`-e`/`-E` semantics — running against Horus's newlib, POSIX fd layer, and ELF
loader.

## Building and running

Gated, so the shipped kernel does not carry it:

```sh
make smoke-coreutils    # builds COREUTILS_SELFTEST=1 and asserts on the output
```

That embeds `echo` as a spawn-by-name binary and runs a self-test that drives it
through `argv` — plain arguments, `-n`, and `-e` with escape sequences — checking
what it writes to the console.

## Updating

Re-copy the upstream file byte-for-byte from the matching tarball and re-run the
gate; do not patch it in place. If a newer coreutils needs more of `system.h`,
extend `port/system.h` rather than the vendored source.
