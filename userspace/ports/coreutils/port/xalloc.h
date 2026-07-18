/* xalloc.h — Horus port shim for gnulib's xalloc module.
 *
 * The x*alloc family is malloc/realloc that never returns NULL: on failure it
 * calls xalloc_die(), which reports "memory exhausted" and exits. Coreutils uses
 * it pervasively precisely so a utility body never has to check an allocation --
 * the check is centralised here, once, and cannot be forgotten at a call site.
 *
 * The xnmalloc / xnrealloc / xreallocarray variants take a count and an element
 * size and multiply them with an OVERFLOW CHECK, so an attacker-influenced count
 * cannot wrap the product to a small number and get an undersized buffer that a
 * later loop then walks off the end of. That check is the security-relevant part
 * and is real here (ckd_mul), not elided.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XALLOC_H
#define HORUS_COREUTILS_XALLOC_H

#include <stddef.h>
#include "system.h"   /* idx_t, xalloc_die, ckd_mul */

void *xmalloc (size_t size);
void *xrealloc (void *p, size_t size);
void *xcalloc (size_t n, size_t s);

/* count * size with overflow -> xalloc_die, never a wrapped small buffer. */
void *xnmalloc (size_t n, size_t s);
void *xnrealloc (void *p, size_t n, size_t s);
void *xreallocarray (void *p, size_t n, size_t s);

/* gnulib's growth helper: enlarge *PA (holding *PN items of size S) so it has
 * room for at least one more, growing geometrically. Updates *PN. Used by the
 * utilities' dynamic buffers (env's argv, seq's format scan, ...). */
void *x2nrealloc (void *p, size_t *pn, size_t s);
void *xpalloc (void *pa, idx_t *pn, idx_t n_incr_min, ptrdiff_t n_max, idx_t s);

char *xstrdup (char const *s);
void *xmemdup (void const *p, size_t s);

#endif
