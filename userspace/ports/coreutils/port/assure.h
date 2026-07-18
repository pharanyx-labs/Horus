/* assure.h — Horus port shim for gnulib's assure.h.
 *
 * gnulib defines affirm(E) as an assertion that is checked even when NDEBUG is
 * set (unlike assert), because the condition is one the program's logic
 * genuinely relies on. echo.c uses it to state that usage() is only ever called
 * with EXIT_SUCCESS.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_ASSURE_H
#define HORUS_COREUTILS_ASSURE_H

#include <stdio.h>
#include <stdlib.h>

/* Checked unconditionally — that is the point of affirm() over assert(). */
#define affirm(E)                                                   \
  ((E) ? (void) 0                                                   \
       : (fprintf (stderr, "%s:%d: assertion failed: %s\n",         \
                   __FILE__, __LINE__, #E),                         \
          abort ()))

#endif /* HORUS_COREUTILS_ASSURE_H */
