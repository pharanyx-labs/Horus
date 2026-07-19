# GNU coreutils port

Real, unmodified GNU coreutils source running as a ring-3 program on Horus.

## Licence — read this first

**This subtree is GPLv3, not MIT.** Horus itself is MIT (see the repository
[LICENSE](../../../LICENSE)); the files listed as *upstream* below are copyright
the Free Software Foundation and licensed under the GNU General Public License
version 3 or later, whose text is in [COPYING](COPYING) here.

| File | Origin | Licence |
|---|---|---|
| `echo.c` `true.c` `false.c` `basename.c` `dirname.c` `cat.c` `head.c` `seq.c` `wc.c` `printf.c` `tail.c` | coreutils 9.5 `src/`, **byte-identical** | GPLv3+ |
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
  `cl-strtod`/`xstrtod`, `argmatch`, `argv-iter`, `readtokens0`, `physmem`,
  C-locale `mbrtoc32`/`c32width`, `xprintf` (printf(1)'s error-checked output),
  `unicodeio` (its `\u` UTF-8 escapes), and tail(1)'s follow shims (`isapipe`,
  `posix2_version`, `iopoll`, `xnanosleep`). Where a check is security-relevant it
  is real, not elided — the `x*alloc` size multiply is overflow-checked
  (`ckd_mul`), and a malformed numeric argument is rejected rather than guessed.
- `port/*.h` — the matching gnulib headers, plus `assure.h`, `c-ctype.h`,
  `stat-size.h`, `uchar.h`, `quotearg.h`, `xprintf.h`, `unicodeio.h`,
  `stat-time.h`, and tail's `fcntl--.h`/`iopoll.h`/`isapipe.h`/`posixver.h`/
  `xnanosleep.h`/`fs.h`/`fs-is-local.h` stubs, and the getopt `--help`/`--version`
  boilerplate.

**tail's follow (`-f`) is best-effort.** Horus has no inotify, no `poll(2)`, no
pipes and no wall-clock sleep exposed to ring 3, so `tail -f` falls back to a
stat-polling loop paced by a bounded busy-spin rather than a real timer. `tail`
by line/byte (`-n`, `-c`) is fully upstream behaviour; the follow path runs but
does not pace to a clock.

**The upstream `.c` files are never edited.** Each is byte-identical to the 9.5
tarball, which is what makes this a port rather than a rewrite: `wc`'s real
word/line/byte counting, `seq`'s long-double sequence generator, `head`'s
line/byte eliding, all running against Horus's newlib, POSIX fd layer, and ELF
loader.

## Building and running

The utilities are **not baked into the kernel image**. They ship as GRUB
multiboot2 *modules* (`module2` lines the `boot.iso` rule writes onto the ISO),
which GRUB loads into RAM outside the kernel. At boot the kernel records each
module from the multiboot2 tags, the `fs_server` copies it to its destination path
in the encrypted store (`provision_boot_modules()`), and the shell runs it from
there: typing a bare name resolves `/bin/<name>`, the shell loads the ~400–610 KiB
image over the `fs_server`, and spawns it. A `/bin/<name>` shadows the shell's
lighter builtin of the same name. Because a module costs nothing against the kernel
image's 16 MiB budget, that budget no longer limits the utilities — a full build
can ship every one. The shipped default carries no module, so the default ISO
holds no GPLv3-derived binary.

Each utility also ships its **man page** — a plain-text file in `userspace/man/`
routed as its own module to `usr/share/man/<name>` (plus `hier(7)`, the filesystem
layout). `man <name>` reads it from `/usr/share/man`; a module's cmdline is its
store destination path (`bin/<name>`, `usr/share/man/<name>`), so the one transport
places binaries and their docs. `make run` ships all of this by default so an
interactive session has `/bin` populated and `man` working.

Two gated build+test paths (`COREUTILS_MODULES=1`):

```sh
make smoke-modules          # ship ALL the utilities + man pages; assert the
                            #   directory skeleton, that every one is provisioned
                            #   into /bin, that /usr/share/man is populated and
                            #   `man tail`/`man hier` read from it, and run printf+tail
make smoke-coreutils-shell  # ship head/seq/wc as modules; create a file with the
                            #   shell's echo, then run head/wc/seq on it
```

Both drive the full user path — the kernel recording the module, the fs_server
provisioning it, the shell resolving `/bin/<name>`, loading the image over the
fs_server, spawning it with argv, the utility opening files over its own fs_server
connection — and assert on output produced by upstream's own code (`printf`'s
format engine, `tail`'s byte/line selection, `seq`'s long-double generator, `wc`'s
counting).

**All the utilities fit in `/bin` at once.** The encrypted store volume is 16 MiB
(~14 MiB usable): a multi-block data-allocation bitmap lifted the old 4096-block
(2 MiB) cap, the RAM vdisk's backing store moved off `.bss`, and the metadata
rollback-MAC became hierarchical so provisioning a large binary block-by-block is
not slowed by the bigger volume. `make smoke-modules` ships the full set and
asserts none is dropped. The `fs_server` still installs modules in order and skips
anything that would not fit, but on this volume nothing does.

Adding another utility is a matter of dropping its unmodified `.c` here, adding
its name to `COREUTILS_PROGS` in the Makefile, and extending `port/` with whatever
gnulib surface it still needs. `--gc-sections` at link time keeps each binary to
what it actually references.

## Updating

Re-copy the upstream file byte-for-byte from the matching tarball and re-run the
gate; do not patch it in place. If a newer coreutils needs more of `system.h`,
extend `port/system.h` rather than the vendored source.
