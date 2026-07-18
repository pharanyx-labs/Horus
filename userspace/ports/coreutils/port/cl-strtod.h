/* cl-strtod.h — Horus port shim for gnulib's cl-strtod module.
 *
 * "Command-line strtod": parse a floating-point number the way a utility should
 * accept one from argv, using the C locale (so the decimal point is always '.'
 * regardless of the process locale) rather than the locale-sensitive strtod.
 * That locale-independence is the point -- `seq 0.5 …` must mean the same thing
 * everywhere, not depend on LC_NUMERIC. Horus runs only the C locale, so this
 * delegates straight to newlib's strtod/strtold.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_CL_STRTOD_H
#define HORUS_COREUTILS_CL_STRTOD_H

double      cl_strtod  (char const *nptr, char **endptr);
long double cl_strtold (char const *nptr, char **endptr);

#endif
