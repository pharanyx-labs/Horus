/* xdectoint.h — Horus port shim for gnulib's xdectoint module.
 *
 * Parse a decimal integer argument, or die with a diagnostic. This is the
 * "there is no sensible default, a bad value must stop the program" wrapper the
 * utilities use for counts that come straight off the command line: on any parse
 * error it prints `err_string` naming the bad option and exits, rather than
 * returning a value the caller would have to (and might forget to) check.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XDECTOINT_H
#define HORUS_COREUTILS_XDECTOINT_H

#include <stdint.h>
#include <inttypes.h>

/* Parse S as a decimal in [MIN,MAX] with the given valid suffix letters. On any
 * error, print `err` + the offending string and exit `err_exit` (or EXIT_FAILURE
 * when 0). Returns the parsed value on success. */
uintmax_t xdectoumax (char const *s, uintmax_t min, uintmax_t max,
                      char const *suffixes, char const *err, int err_exit);
intmax_t  xdectoimax (char const *s, intmax_t min, intmax_t max,
                      char const *suffixes, char const *err, int err_exit);

#endif
