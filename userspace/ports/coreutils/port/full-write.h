/* full-write.h — Horus port shim for gnulib's full-write.h.
 *
 * write(2) may write fewer bytes than asked; full_write loops until the whole
 * buffer is out or an error is hit, returning the count written (a short return
 * means the error is in errno). This is the real behaviour, not a passthrough --
 * a plain write() here would silently truncate output.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_FULL_WRITE_H
#define HORUS_COREUTILS_FULL_WRITE_H

#include <stddef.h>

size_t full_write (int fd, const void *buf, size_t count);

#endif
