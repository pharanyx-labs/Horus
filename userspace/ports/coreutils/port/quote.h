/* quote.h — Horus port shim for gnulib's quote.h.
 *
 * quote(s) returns s wrapped for display in a diagnostic — upstream's default
 * style surrounds it with single quotes and escapes non-printables, so a file
 * name containing spaces, newlines or control characters cannot forge or
 * misrepresent the surrounding message. That escaping is the security-relevant
 * part and is kept here: a name is never echoed raw into a diagnostic.
 *
 * Upstream returns storage from a rotating set of slots so a caller can pass two
 * quote() calls to one printf; the same rotation is provided. A name too long
 * for a slot is truncated with an ellipsis rather than overrunning.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_QUOTE_H
#define HORUS_COREUTILS_QUOTE_H

char const *quote (char const *arg);
char const *quote_n (int n, char const *arg);

#endif
