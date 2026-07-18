/* full-read.h — Horus port shim for gnulib's full-read.h.
 *
 * The read-side counterpart of full_write: loop until `count` bytes are read,
 * end-of-file, or an error. A short return with errno == 0 means EOF.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_FULL_READ_H
#define HORUS_COREUTILS_FULL_READ_H

#include <stddef.h>

size_t full_read (int fd, void *buf, size_t count);

#endif
