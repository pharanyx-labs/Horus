/* xbinary-io.h — Horus port shim for gnulib's xbinary-io.h.
 *
 * The text/binary stream distinction exists for platforms that translate line
 * endings (DOS, Windows). Horus, like every POSIX system, does not, so setting
 * the mode is a no-op with no behaviour lost.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XBINARY_IO_H
#define HORUS_COREUTILS_XBINARY_IO_H

#include <fcntl.h>

#ifndef O_BINARY
# define O_BINARY 0
#endif
#ifndef O_TEXT
# define O_TEXT 0
#endif

static inline void xset_binary_mode (int fd, int mode) { (void) fd; (void) mode; }

#endif
