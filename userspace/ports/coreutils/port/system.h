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
#include <strings.h>   /* bzero, used by wc's multibyte path */
#include <stdbool.h>
#include <locale.h>
#include <wctype.h>    /* iswspace / iswprint, used (C-locale-unreached) by wc */
#include <unistd.h>
/* <sys/errno.h>, NOT <errno.h>: the userspace build puts Horus's own include/
 * ahead of newlib's, and Horus has an errno.h of its own carrying the SYS_ERR_*
 * syscall codes -- no errno, no ENOENT. newlib's real one is reachable only by
 * its sys/ path. (newlib_glue.c includes it the same way for the same reason.) */
#include <sys/errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>

/* gnulib's idx_t: a *signed* index type, deliberately not size_t. Signedness is
 * the point — overflow in an index calculation is then undefined rather than
 * silently wrapping to a huge positive length, so the compiler's overflow checks
 * can see it and a wrapped value cannot become an enormous allocation or copy. */
typedef ptrdiff_t idx_t;

/* ---- gnulib's attribute.h, mapped onto GCC's __attribute__ ----------------
 * These are optimisation/diagnostic hints, so mapping an unknown one to nothing
 * only loses a hint, never correctness. The ones defined map to their real GCC
 * form so the hint is kept. */
#define ATTRIBUTE_PURE        __attribute__ ((__pure__))
#define ATTRIBUTE_CONST       __attribute__ ((__const__))
#define ATTRIBUTE_MALLOC      __attribute__ ((__malloc__))
#define ATTRIBUTE_UNUSED      __attribute__ ((__unused__))
#define MAYBE_UNUSED          __attribute__ ((__unused__))
#define _GL_ATTRIBUTE_PURE    __attribute__ ((__pure__))
#define _GL_ATTRIBUTE_CONST   __attribute__ ((__const__))
#define _GL_ATTRIBUTE_MALLOC  __attribute__ ((__malloc__))
#define _GL_UNUSED            __attribute__ ((__unused__))
#define _GL_ATTRIBUTE_FORMAT(spec) __attribute__ ((__format__ spec))
#define ATTRIBUTE_NONNULL(...)
#define _GL_ATTRIBUTE_NONNULL(...)

/* C11 static_assert under gnu99: GCC provides _Static_assert as an extension. */
#ifndef static_assert
# define static_assert _Static_assert
#endif

/* gnulib wraps a utility's final exit so a build can hook it; plain exit here. */
#ifndef main_exit
# define main_exit(status) exit (status)
#endif

/* C23's unreachable() marks a point the program can never reach, letting the
 * compiler drop the impossible path. GCC's builtin is the real thing; a plain
 * fallback would still be correct (it just would not optimise). */
#ifndef unreachable
# define unreachable() __builtin_unreachable ()
#endif

/* Zero an mbstate_t (gnulib's mbszero). A fresh state is the C-locale initial
 * conversion state, so memset to zero is exactly right. */
#ifndef mbszero
# define mbszero(ps) memset ((ps), 0, sizeof *(ps))
#endif

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

/* --help / --version as long options. The option characters are below CHAR_MIN
 * so they cannot collide with any real short option a utility defines. */
#include <limits.h>
#include <getopt.h>

#define GETOPT_HELP_CHAR    (CHAR_MIN - 2)
#define GETOPT_VERSION_CHAR (CHAR_MIN - 3)

#define GETOPT_HELP_OPTION_DECL \
  "help", no_argument, NULL, GETOPT_HELP_CHAR
#define GETOPT_VERSION_OPTION_DECL \
  "version", no_argument, NULL, GETOPT_VERSION_CHAR

#define case_GETOPT_HELP_CHAR \
  case GETOPT_HELP_CHAR: \
    usage (EXIT_SUCCESS); \
    break;

#define case_GETOPT_VERSION_CHAR(Program_name, Authors) \
  case GETOPT_VERSION_CHAR: \
    version_etc (stdout, Program_name, PACKAGE_NAME, Version, Authors, \
                 (char *) NULL); \
    exit (EXIT_SUCCESS); \
    break;

/* The note utilities print above their option list. */
#define emit_mandatory_arg_note()                                        \
  fputs ("\nMandatory arguments to long options are mandatory for short " \
         "options too.\n", stdout)

/* Upstream warns that the shell may provide its own builtin of the same name. */
#define USAGE_BUILTIN_WARNING \
  "\nNOTE: your shell may have its own version of %s, which usually supersedes\n" \
  "the version described here.  Please refer to your shell's documentation\n" \
  "for details about the options it supports.\n"

/* Author-name passthrough. Upstream may transliterate names when the locale
 * cannot represent them; with no catalogues the name is used as-is. */
#define proper_name(name) (name)

/* proper_name_lite(ascii, utf8): upstream picks the UTF-8 spelling of an
 * author's name when the locale can render it, else the ASCII fallback. Horus
 * has only the C locale, so the ASCII form is the correct choice. */
#define proper_name_lite(ascii, utf8) (ascii)

/* C23 checked arithmetic (gnulib's stdckdint.h). These must be REAL overflow
 * checks -- callers use them to size allocations, so a version that always
 * reported "no overflow" would turn a wrapped length into an undersized buffer.
 * GCC's builtins do exactly what C23 specifies: store the result and return
 * true if it overflowed. */
#ifndef ckd_mul
# define ckd_mul(r, a, b) __builtin_mul_overflow ((a), (b), (r))
#endif
#ifndef ckd_add
# define ckd_add(r, a, b) __builtin_add_overflow ((a), (b), (r))
#endif
#ifndef ckd_sub
# define ckd_sub(r, a, b) __builtin_sub_overflow ((a), (b), (r))
#endif

/* gnulib's xalloc_die(): the single exit point for an allocation failure in the
 * x*alloc family. Never returns -- a caller that has just failed to get memory
 * cannot carry on, and returning would leave it dereferencing null. */
void xalloc_die (void) __attribute__ ((__noreturn__));

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

/* "Try 'PROG --help' for more information." — what a utility prints instead of
 * dumping full usage at someone who mistyped an option. */
void emit_try_help (void);

/* The standard note about reading stdin when no FILE is given, or FILE is '-'. */
void emit_stdin_note (void);

/* Report a failed write to stdout and exit non-zero. Utilities call this the
 * moment a write fails rather than pressing on: continuing would produce
 * truncated output *and* a success status, which is the outcome a caller
 * piping this into something else can least afford. */
void write_error (void) __attribute__ ((__noreturn__));

/* glibc/gnulib error(): print "prog: message[: strerror(errnum)]" to stderr and
 * exit with `status` when it is non-zero. Utilities pass status 0 to report and
 * continue (cat does this per-file, so one unreadable file does not abandon the
 * rest of the command line). */
void error (int status, int errnum, char const *format, ...)
    __attribute__ ((__format__ (__printf__, 3, 4)));

/* quotef(): quote a file name for a diagnostic. Upstream's variant elides the
 * quotes when the name has nothing that needs them; the escaping of anything
 * non-printable is the part that matters and is kept. Uses its own rotating
 * slot so it can appear alongside a quote() in the same call. */
char const *quotef (char const *arg);

/* quoteaf(): as quotef(), but the quotes are always shown even when the name
 * would not strictly need them. Own slot again, so quote/quotef/quoteaf can all
 * appear in one call. */
char const *quoteaf (char const *arg);

/* Path splitting (gnulib's dirname module). Upstream's system.h pulls this in
 * for every utility, so basename(1)/dirname(1) get it without an include. */
#include "dirname.h"

/* copy_file_range(2) is a Linux zero-copy fast path: it moves bytes between two
 * descriptors inside the kernel, skipping the trip through userspace. Horus has
 * no such syscall, and cat is written to cope -- it probes once and falls back
 * to its own read/write loop when the kernel says unsupported. So this reports
 * ENOSYS rather than pretending: the fallback is the real implementation here,
 * and it is the same path cat takes on any system lacking the call. */
ssize_t copy_file_range (int infd, off_t *inoff, int outfd, off_t *outoff,
                         size_t length, unsigned int flags);

/* Whether an errno means "this operation is not supported here". Two spellings
 * exist and may be distinct values, so both are checked. */
static inline bool is_ENOTSUP (int err) {
    return err == ENOTSUP
#if defined EOPNOTSUPP && EOPNOTSUPP != ENOTSUP
        || err == EOPNOTSUPP
#endif
        || err == ENOSYS;
}

/* SIZE_MAX / SSIZE_MAX: newlib's <stdint.h> defines SIZE_MAX, but SSIZE_MAX is a
 * <limits.h> POSIX addition it does not carry. Derive it from ssize_t's width
 * rather than assuming 64-bit. */
#include <stdint.h>
#ifndef SSIZE_MAX
# define SSIZE_MAX ((ssize_t) (SIZE_MAX / 2))
#endif

#ifndef MIN
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
# define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* ---- small classification / type-bound helpers upstream's system.h carries.
 *
 * ISDIGIT is locale-independent by construction (a range test on the byte),
 * which is the point: option and count parsing must not change meaning under a
 * different LC_CTYPE. to_uchar avoids the sign-extension trap of passing a
 * possibly-negative char straight to a <ctype.h> function or an array index. */
#define ISDIGIT(c) ((unsigned int) (c) - '0' <= 9)
#define to_uchar(c) ((unsigned char) (c))

/* Maximum / minimum value of an integer TYPE, computed from its width without
 * assuming a specific size. TYPE_SIGNED is true for a signed type. */
#define TYPE_SIGNED(t)  (! ((t) 0 < (t) -1))
#define TYPE_MAXIMUM(t) \
  ((t) (TYPE_SIGNED (t) \
        ? (((((t) 1 << (sizeof (t) * CHAR_BIT - 2)) - 1) * 2) + 1) \
        : (t) -1))
#define TYPE_MINIMUM(t) ((t) (TYPE_SIGNED (t) ? - TYPE_MAXIMUM (t) - 1 : (t) 0))

#ifndef OFF_T_MAX
# define OFF_T_MAX TYPE_MAXIMUM (off_t)
#endif
#ifndef OFF_T_MIN
# define OFF_T_MIN TYPE_MINIMUM (off_t)
#endif
#ifndef UINTMAX_MAX
# define UINTMAX_MAX TYPE_MAXIMUM (uintmax_t)
#endif

/* st_size is only meaningful for a regular file (or a symlink's target length);
 * for anything else -- a pipe, a device -- it says nothing, and a utility that
 * trusted it would compute a wrong length. */
#define usable_st_size(sb) (S_ISREG ((sb)->st_mode) || S_ISLNK ((sb)->st_mode))

/* STP_BLKSIZE takes a *pointer* to a struct stat (the "p" is for pointer),
 * unlike ST_BLKSIZE which takes the struct by value. head passes a pointer. */
#ifndef STP_BLKSIZE
# define STP_BLKSIZE(sbp) \
    (((sbp)->st_blksize > 0 && (sbp)->st_blksize <= 1024 * 1024) \
     ? (size_t) (sbp)->st_blksize : (size_t) 512)
#endif

/* The x*alloc family and inttostr, which upstream's system.h pulls in for every
 * utility -- so a source that uses xmalloc()/umaxtostr() without including them
 * directly (head does) still resolves. Placed at the end so the types and
 * xalloc_die() they reference above are already declared. */
#include "xalloc.h"
#include "inttostr.h"

#endif /* HORUS_COREUTILS_SYSTEM_H */
