# TCC (Tiny C Compiler) port

The unmodified TinyCC 0.9.27 x86-64 compiler, built to run as a ring-3 program on Horus, a
native C compiler on the machine, no cross-toolchain required.

## Licence: read this first

**This subtree is LGPL 2.1, not MIT.** Horus itself is MIT (see the repository [LICENSE](../../../LICENSE)); the files listed as *upstream* below are copyright Fabrice Bellard and the TinyCC contributors and licensed under the GNU Lesser General Public License version 2.1, whose text is in [COPYING](COPYING) here.

| File | Origin | Licence |
|---|---|---|
| `libtcc.c` `tccpp.c` `tccgen.c` `tccelf.c` `tccasm.c` `tcctools.c` `x86_64-gen.c` `x86_64-link.c` `i386-asm.c` `tcc.c` | TinyCC 0.9.27, **byte-identical** | LGPL 2.1 |
| `*.h`, `stab.def`, `config.h` | TinyCC 0.9.27 | LGPL 2.1 |
| `COPYING` | TinyCC 0.9.27 | LGPL 2.1 text |
| `port/*` | written for Horus | MIT (as the rest of the tree) |

The port glue in `port/` is Horus code and stays MIT; nothing in it is derived from TinyCC.
Shipping an LGPL program alongside an MIT kernel is ordinary aggregation; the two remain
separate works.

## What is vendored, and what is not

Only the **x86-64 subset** is vendored: the 9 core translation units above plus the headers they
need. The other-architecture back-ends (`arm*`, `c67*`, `i386-gen`, `il-*`), the PE/COFF targets
(`tccpe.c`, `tcccoff.c`), and (deliberately) **`tccrun.c`** (the in-process `-run` JIT) are
omitted.

`-run` needs writable-and-executable (RWX) memory, which Horus's W^X policy forbids by construction, so the JIT can never work here; compile-to-file is the model. Its exported symbols (`tcc_run`, `tcc_run_free`, `tcc_set_num_callers`, `tcc_backtrace`) are stubbed fail-closed in `port/horus_glue.c`.

## How it builds

TCC needs no `configure` and no gnulib (unlike the coreutils port). The units compile directly against Horus's newlib and link with the same `crt0` + `newlib_glue` + `malloc` as every other newlib program, into a Horus static-PIE (`ET_DYN`, `R_X86_64_RELATIVE` only) that the kernel's loader accepts. See the `TCC_*` rules in the top-level `Makefile`.

Two non-obvious flags:
- **`-DCONFIG_TCC_STATIC`** drops TCC's `<dlfcn.h>` include (no dynamic loading on Horus).
- **No `-I include`.** TCC must resolve `<errno.h>`/`<stdio.h>` to *newlib*, not the kernel's `include/errno.h` (which defines the `SYS_ERR_*` set, not the C `errno` variable). This is the same reason the coreutils port omits it.

`port/horus_glue.c` supplies only what neither newlib nor Horus's POSIX layer provides:
`gettimeofday`, `execvp` (no external assembler/linker; TCC's are built in), the `dl*`/`mmap`
family (unreachable, `-run` excluded), and the excluded-`tccrun` symbols. `getcwd` and file I/O
come from `userspace/posix.c` + `userspace/newlib_glue*.c`.

## Building and running

Not baked into the kernel image. `TCC_MODULE=1` ships `tcc` as a GRUB multiboot2 module the `fs_server` provisions into `/bin`, alongside its man page (`usr/share/man/tcc`). `make run` ships it by default (`RUN_MODULES=1`); the release ISO stays module-free.

```sh
make smoke-tcc        # boot Horus, provision /bin/tcc, run `tcc -v` through the
                      #   real ring-3 shell, assert on tcc's own version banner
```

The shell runs it by name: `tcc` resolves `/bin/tcc`, the ~1 MiB image loads over the `fs_server`, and it spawns as a child. `tcc -v`, usage/option output, and preprocessing/compiling a self-contained translation unit to an object (`tcc -c`) work from the store today.

## Not yet: compiling a full program on Horus

`tcc hello.c -o hello` for arbitrary programs additionally needs the C **headers and library**
(and a C runtime) provisioned onto the filesystem under `/usr/include` and `/usr/lib`, plus
`libtcc1.a` (TCC's tiny runtime) built for Horus. That provisioning (and growing the store
volume to hold it) is the tracked follow-up. This session lands `/bin/tcc` runnable with a man
page.

## Updating

Re-copy each upstream file byte-for-byte from the matching TinyCC tarball; do not patch it in place. If a newer TCC needs another unit or header, add it to `TCC_UNITS` / vendor the header rather than editing the vendored source.
