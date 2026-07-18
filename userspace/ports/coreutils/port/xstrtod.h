/* xstrtod.h — Horus port shim for gnulib's xstrtod module.
 *
 * Parse a floating-point string in full, via a caller-supplied conversion
 * function (cl_strtod / cl_strtold above), and report success as a bool: true
 * only if the whole string -- or the whole string up to *ptr -- was a valid
 * number. seq uses this so a bad bound like "seq 1 x 10" is rejected outright
 * rather than silently truncated to a partial parse.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XSTRTOD_H
#define HORUS_COREUTILS_XSTRTOD_H

#include <stdbool.h>

bool xstrtod  (char const *str, char const **ptr, double *result,
               double (*convert) (char const *, char **));
bool xstrtold (char const *str, char const **ptr, long double *result,
               long double (*convert) (char const *, char **));

#endif
