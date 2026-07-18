/* safe-read.h / safe-write.h — Horus port shim for gnulib's.
 *
 * A single read(2)/write(2) that retries on EINTR and caps the request at
 * INT_MAX, so a caller never has to distinguish "interrupted" from a real error.
 * Returns the byte count, or SAFE_READ_ERROR ((size_t) -1) on failure.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_SAFE_READ_H
#define HORUS_COREUTILS_SAFE_READ_H

#include <stddef.h>

#define SAFE_READ_ERROR ((size_t) -1)
#define SAFE_WRITE_ERROR ((size_t) -1)

size_t safe_read (int fd, void *buf, size_t count);
size_t safe_write (int fd, const void *buf, size_t count);

#endif
