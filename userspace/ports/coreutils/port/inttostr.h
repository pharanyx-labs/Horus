/* inttostr.h — Horus port shim for gnulib's inttostr module.
 *
 * Convert an integer to decimal into a caller-provided buffer, returning a
 * pointer to the first digit (the conversion is written right-aligned at the end
 * of the buffer, which is why the return value is not `buf`). Used where the
 * utilities format an offset or count into a fixed on-stack buffer sized with
 * INT_BUFSIZE_BOUND below.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_INTTOSTR_H
#define HORUS_COREUTILS_INTTOSTR_H

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

/* A safe OVER-estimate of the characters a value of a type may print to. These
 * size on-stack buffers, so an over-estimate wastes a byte or two but an
 * under-estimate is a stack overflow -- err high. 302/1000 > log10(2), so
 * bits*302/1000 + 1 covers every decimal digit; +2 adds the sign and NUL. */
#define INT_STRLEN_BOUND(t)  ((int) (sizeof (t) * CHAR_BIT * 302 / 1000 + 1))
#define INT_BUFSIZE_BOUND(t) (INT_STRLEN_BOUND (t) + 2)

char *umaxtostr (uintmax_t i, char *buf);
char *imaxtostr (intmax_t i, char *buf);
char *offtostr  (off_t i, char *buf);
char *uinttostr (unsigned int i, char *buf);
char *inttostr  (int i, char *buf);

#endif
