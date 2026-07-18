/* ioblksize.h — Horus port shim for gnulib's ioblksize.h.
 *
 * Upstream picks a copy-buffer size from the file's st_blksize, clamped into a
 * range benchmarked to beat the syscall overhead. Horus's object store serves
 * 512-byte blocks over IPC to the fs_server, so each read is an IPC round trip
 * and a larger buffer is a straightforward win; IO_BUFSIZE is the same 128 KiB
 * default upstream uses.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_IOBLKSIZE_H
#define HORUS_COREUTILS_IOBLKSIZE_H

#include <sys/stat.h>
#include <stddef.h>

enum { IO_BUFSIZE = 128 * 1024 };

static inline size_t io_blksize (struct stat const *sb) {
    (void) sb;
    return IO_BUFSIZE;
}

#endif
