# GNU coreutils port

Real, unmodified GNU coreutils source running as a ring-3 program on Horus.

## Licence — read this first

**This subtree is GPLv3, not MIT.** Horus itself is MIT (see the repository
[LICENSE](../../../LICENSE)); the files listed as *upstream* below are copyright
the Free Software Foundation and licensed under the GNU General Public License
version 3 or later, whose text is in [COPYING](COPYING) here.

| File | Origin | Licence |
|---|---|---|
| `echo.c` `true.c` `false.c` `basename.c` `dirname.c` `cat.c` `head.c` `seq.c` `wc.c` | coreutils 9.5 `src/`, **byte-identical** | GPLv3+ |
| `wc.h` | coreutils 9.5 `src/` | GPLv3+ |
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
- `port/port.c` — the gnulib routines the utilities call at runtime
  (`set_program_name`, `version_etc`, `close_stdout`, `error`, `quote*`, the
  `dirname` module, `full_read`/`full_write`/`safe_read`, `xalignalloc`).
- `port/gnulib.c` — the larger gnulib *modules* the text/number utilities need:
  the `xalloc` family, `inttostr`, `xstrtol`/`xstrtoumax`, `xdectoint`,
  `cl-strtod`/`xstrtod`, `argmatch`, `argv-iter`, `readtokens0`, `physmem`, and
  C-locale `mbrtoc32`/`c32width`. Where a check is security-relevant it is real,
  not elided — the `x*alloc` size multiply is overflow-checked (`ckd_mul`), and a
  malformed numeric argument is rejected rather than guessed.
- `port/*.h` — the matching gnulib headers, plus `assure.h`, `c-ctype.h`,
  `stat-size.h`, `uchar.h`, and the getopt `--help`/`--version` boilerplate.

**The upstream `.c` files are never edited.** Each is byte-identical to the 9.5
tarball, which is what makes this a port rather than a rewrite: `wc`'s real
word/line/byte counting, `seq`'s long-double sequence generator, `head`'s
line/byte eliding, all running against Horus's newlib, POSIX fd layer, and ELF
loader.

## Building and running

Two gated build+test paths (the shipped kernel carries neither the binaries nor
any GPLv3-derived code):

```sh
make smoke-coreutils        # COREUTILS_SELFTEST=1: spawn utilities directly
                            #   with a staged argv and assert on their output
make smoke-coreutils-shell  # COREUTILS_SHELL=1: drive head/seq/wc through the
                            #   REAL shell over serial, on real files
```

`smoke-coreutils` embeds `echo`/`basename`/`dirname`/`seq` and asserts on output
made by upstream's own code — the marker only appears if `echo` joins its argv
and expands `\x20`/`\x21`, and `seq 1 2 5` prints `1 3 5` only because its real
long-double generator ran. `smoke-coreutils-shell` embeds `head`/`seq`/`wc`, then
logs into the shell, creates a file with `echo > file`, and runs `head`/`wc`/`seq`
on it — exercising the full user path (the shell parsing a line, spawning the
utility with argv, the utility opening the file over its own fs_server
connection). A ported utility shadows the shell's lighter builtin of the same
name when it is embedded.

Only a subset is embedded per build: nine newlib-linked binaries at once overrun
the kernel image's 16 MiB budget, so `CU_EMBED_<name>` (driven by the Makefile)
selects the ones a given test drives. `--gc-sections` at link time keeps each
binary to what it actually references.

Adding another utility is a matter of dropping its unmodified `.c` here, adding
its name to `COREUTILS_PROGS` (and the relevant `CU_EMBED` set) in the Makefile,
and extending `port/` with whatever gnulib surface it still needs.

## Updating

Re-copy the upstream file byte-for-byte from the matching tarball and re-run the
gate; do not patch it in place. If a newer coreutils needs more of `system.h`,
extend `port/system.h` rather than the vendored source.
