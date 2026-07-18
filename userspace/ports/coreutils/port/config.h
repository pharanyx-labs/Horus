/* config.h — Horus port shim for GNU coreutils.
 *
 * Upstream coreutils generates this with autoconf. Horus has no `configure` for
 * the target (there is no x86_64-elf cross toolchain here, and configure's
 * feature probes run test programs on the host), so this is a hand-written
 * substitute declaring exactly what the ported sources need.
 *
 * This file is Horus port glue, not coreutils code — it is MIT-licensed like the
 * rest of the tree. The vendored upstream sources next to it stay GPLv3 and
 * unmodified; see ../README.md.
 */
#ifndef HORUS_COREUTILS_CONFIG_H
#define HORUS_COREUTILS_CONFIG_H

/* Identity strings normally supplied by configure. */
#define PACKAGE            "coreutils"
#define PACKAGE_NAME       "GNU coreutils"
#define PACKAGE_VERSION    "9.5"
#define Version            PACKAGE_VERSION
#define PACKAGE_BUGREPORT  "bug-coreutils@gnu.org"
#define PACKAGE_URL        "https://www.gnu.org/software/coreutils/"
#define LOCALEDIR          "/usr/share/locale"

/* coreutils 9.5 is written against C23 and uses `nullptr`. The userspace build
 * is -std=gnu99, so provide it rather than patch the vendored source. */
#if !defined(__cplusplus) && __STDC_VERSION__ < 202311L
# ifndef nullptr
#  define nullptr ((void *) 0)
# endif
#endif

/* gnulib's fallthrough attribute (used in echo.c's octal-escape parser). */
#ifndef FALLTHROUGH
# if defined __GNUC__ && 7 <= __GNUC__
#  define FALLTHROUGH __attribute__ ((__fallthrough__))
# else
#  define FALLTHROUGH ((void) 0)
# endif
#endif

#endif /* HORUS_COREUTILS_CONFIG_H */
