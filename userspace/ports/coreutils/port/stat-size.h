/* stat-size.h — Horus port shim for gnulib's stat-size.h.
 *
 * Upstream abstracts over platforms whose struct stat spells the block fields
 * differently or omits them. Horus's newlib struct stat has st_blksize and
 * st_blocks, and the fs layer reports both, so these resolve directly. The
 * fallbacks upstream needs for exotic hosts are not reproduced.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_STAT_SIZE_H
#define HORUS_COREUTILS_STAT_SIZE_H

#include <sys/stat.h>

#define DEV_BSIZE 512

/* Preferred I/O block size, clamped to something sane: a zero or absurd
 * st_blksize from a bad stat must not become a buffer size. */
#define ST_BLKSIZE(statbuf)                                          \
  (((statbuf).st_blksize > 0 && (statbuf).st_blksize <= 1024 * 1024)  \
   ? (size_t) (statbuf).st_blksize : (size_t) DEV_BSIZE)

#define ST_NBLOCKSIZE DEV_BSIZE
#define ST_NBLOCKS(statbuf) ((statbuf).st_blocks)

#endif
