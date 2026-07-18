/* system.h — Horus port shim for GNU coreutils.
 *
 * Upstream coreutils includes its own src/system.h, an 822-line header that
 * pulls in ~25 more (gnulib's xalloc.h, idx.h, gettext.h, timespec.h, …) and
 * behind them 478 gnulib .c files. Horus has neither gnulib nor a configure run,
 * so this declares just the surface the ported utilities actually use, keeping
 * the vendored upstream .c files unmodified.
 *
 * This file is Horus port glue, not coreutils code — MIT-licensed like the rest
 * of the tree. The vendored upstream sources stay GPLv3; see ../README.md.
 */
#ifndef HORUS_COREUTILS_SYSTEM_H
#define HORUS_COREUTILS_SYSTEM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <locale.h>
#include <unistd.h>
#include <errno.h>

/* ---- gettext: Horus ships no message catalogues, so translation is identity.
 * N_() marks a string for extraction without translating it; _() would look one
 * up at runtime. Both pass the string through unchanged. */
#define _(msgid)  (msgid)
#define N_(msgid) (msgid)
#define bindtextdomain(domain, dir) ((void) 0)
#define textdomain(domain)          ((void) 0)

/* ---- string comparison helper used throughout coreutils. */
#define STREQ(a, b) (strcmp (a, b) == 0)

/* ---- program identity.
 * set_program_name() is gnulib's; it records argv[0] (stripping any directory
 * prefix and a libtool "lt-" prefix upstream — neither occurs on Horus, where a
 * task's argv[0] is a bare name) for diagnostics and --version output. */
extern char const *program_name;
void set_program_name (char const *argv0);

/* ---- per-program startup hook. Upstream this handles platform quirks (e.g.
 * DJGPP argv globbing); Horus needs nothing, so it is a no-op. */
#define initialize_main(argcp, argvp) ((void) 0)

/* ---- --help / --version boilerplate. */
#define HELP_OPTION_DESCRIPTION \
  "      --help        display this help and exit\n"
#define VERSION_OPTION_DESCRIPTION \
  "      --version     output version information and exit\n"

/* Upstream warns that the shell may provide its own builtin of the same name. */
#define USAGE_BUILTIN_WARNING \
  "\nNOTE: your shell may have its own version of %s, which usually supersedes\n" \
  "the version described here.  Please refer to your shell's documentation\n" \
  "for details about the options it supports.\n"

/* Author-name passthrough. Upstream may transliterate names when the locale
 * cannot represent them; with no catalogues the name is used as-is. */
#define proper_name(name) (name)

/* Print the trailing "GNU coreutils online help: ..." block. */
void emit_ancillary_info (char const *program);

/* gnulib's version_etc(): the --version banner. The argument list is a
 * NULL-terminated sequence of author names. */
void version_etc (FILE *stream, char const *command_name,
                  char const *package, char const *version, ...);

/* gnulib's close_stdout(): flush stdout at exit and report a write error rather
 * than exiting successfully on a silently truncated stream. Registered with
 * atexit() by the utilities. */
void close_stdout (void);

#endif /* HORUS_COREUTILS_SYSTEM_H */
