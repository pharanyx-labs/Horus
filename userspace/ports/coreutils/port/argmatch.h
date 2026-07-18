/* argmatch.h — Horus port shim for gnulib's argmatch module.
 *
 * Match a user-supplied option argument against a fixed list of accepted
 * keywords, allowing an unambiguous abbreviation, and return the corresponding
 * value -- or, for XARGMATCH, print a diagnostic listing the valid choices and
 * exit. The value-lookup is what maps "always"/"never"/"auto" to an enum.
 *
 * ARGMATCH_VERIFY is a compile-time assertion that the keyword array and the
 * value array have matching lengths; a no-op here (the arrays are fixed in the
 * vendored source), so a mismatch would be an upstream bug, not ours to catch.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_ARGMATCH_H
#define HORUS_COREUTILS_ARGMATCH_H

#include <stddef.h>
#include "system.h"   /* quote(), error() */

/* Index of ARG in ARGLIST (a NULL-terminated array), allowing an unambiguous
 * prefix. Returns -1 if unmatched, -2 if an ambiguous prefix. */
ptrdiff_t argmatch (char const *arg, char const *const *arglist,
                    void const *vallist, size_t valsize);

/* Report an invalid argument and the valid choices. */
void argmatch_invalid (char const *context, char const *value, ptrdiff_t problem);
void argmatch_valid (char const *const *arglist, void const *vallist, size_t valsize);

/* Match ARG or die: returns the matched value (of the element type). */
#define XARGMATCH(Context, Arg, Arglist, Vallist) \
  ((Vallist)[__xargmatch_internal (Context, Arg, Arglist, \
                                   (void const *) (Vallist), \
                                   sizeof *(Vallist))])

ptrdiff_t __xargmatch_internal (char const *context, char const *arg,
                                char const *const *arglist,
                                void const *vallist, size_t valsize);

/* Compile-time length check: no-op (the vendored arrays are fixed). */
#define ARGMATCH_VERIFY(Arglist, Vallist) \
  _Static_assert (sizeof (Arglist) / sizeof *(Arglist) \
                  == sizeof (Vallist) / sizeof *(Vallist) + 1, \
                  "argmatch arrays out of sync")

#endif
