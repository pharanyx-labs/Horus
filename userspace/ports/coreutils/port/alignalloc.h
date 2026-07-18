/* alignalloc.h — Horus port shim for gnulib's alignalloc.h.
 *
 * Upstream returns memory aligned to a caller-chosen boundary, which matters for
 * O_DIRECT I/O where the kernel requires page-aligned buffers. Horus has no
 * O_DIRECT and its read/write path imposes no alignment, so alignment here is a
 * performance hint with nothing to optimise: over-allocate and align by hand,
 * keeping the original pointer so alignfree() can return it.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_ALIGNALLOC_H
#define HORUS_COREUTILS_ALIGNALLOC_H

#include <stddef.h>

void *xalignalloc (size_t alignment, size_t size);
void  alignfree (void *ptr);

#endif
