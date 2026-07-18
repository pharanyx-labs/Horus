/* uchar.h — Horus port shim for C11 <uchar.h> (newlib lacks it).
 *
 * char32_t and mbrtoc32, used by wc's multibyte counting path. That path only
 * runs when MB_CUR_MAX > 1, i.e. in a multibyte locale; Horus runs only the C
 * locale, so it is compiled but never taken. The C-locale-correct behaviour --
 * one byte is one character -- is what mbrtoc32 below implements, so even if it
 * were reached it would be right rather than a stub.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_UCHAR_H
#define HORUS_COREUTILS_UCHAR_H

#include <stdint.h>
#include <wchar.h>   /* mbstate_t */

typedef uint_least16_t char16_t;
typedef uint_least32_t char32_t;

size_t mbrtoc32 (char32_t *pc32, const char *s, size_t n, mbstate_t *ps);
size_t c32rtomb (char *s, char32_t c32, mbstate_t *ps);

/* Display width of a char32_t, and a single-byte -> char32_t conversion.
 * gnulib groups these with the char32 modules; wc uses both on its (C-locale-
 * unreached) multibyte path. */
int c32width (char32_t c);
char32_t btoc32 (int c);

#endif
