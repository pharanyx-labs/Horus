/* c-ctype.h — Horus port shim for gnulib's c-ctype.h.
 *
 * gnulib's c_is* functions classify characters in the C locale specifically,
 * independent of the process locale, so parsing never changes meaning under a
 * different LC_CTYPE. echo.c uses c_isxdigit() for \xHH escapes. Horus has only
 * the C locale, but these are written against ASCII directly rather than
 * delegating to <ctype.h>, which keeps the C-locale guarantee explicit.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_C_CTYPE_H
#define HORUS_COREUTILS_C_CTYPE_H

#include <stdbool.h>

static inline bool c_isdigit (int c) { return '0' <= c && c <= '9'; }
static inline bool c_islower (int c) { return 'a' <= c && c <= 'z'; }
static inline bool c_isupper (int c) { return 'A' <= c && c <= 'Z'; }
static inline bool c_isalpha (int c) { return c_islower (c) || c_isupper (c); }
static inline bool c_isalnum (int c) { return c_isalpha (c) || c_isdigit (c); }

static inline bool
c_isxdigit (int c)
{
  return c_isdigit (c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}

static inline bool
c_isspace (int c)
{
  return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}

#endif /* HORUS_COREUTILS_C_CTYPE_H */
