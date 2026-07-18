/* stat-time.h — Horus port shim for gnulib's stat-time / timespec modules.
 *
 * Extracts the high-resolution timestamps from a struct stat and compares two
 * timespecs. tail(1) uses get_stat_mtime() + timespec_cmp() to detect that a
 * followed file changed. newlib's struct stat already carries st_mtim as a
 * struct timespec, so these are thin accessors.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_STAT_TIME_H
#define HORUS_COREUTILS_STAT_TIME_H

#include <sys/stat.h>
#include <time.h>

static inline struct timespec get_stat_atime (struct stat const *st) { return st->st_atim; }
static inline struct timespec get_stat_mtime (struct stat const *st) { return st->st_mtim; }
static inline struct timespec get_stat_ctime (struct stat const *st) { return st->st_ctim; }

/* Sign of a - b, comparing whole seconds then nanoseconds. */
static inline int timespec_cmp (struct timespec a, struct timespec b)
{
  if (a.tv_sec  < b.tv_sec)  return -1;
  if (a.tv_sec  > b.tv_sec)  return  1;
  if (a.tv_nsec < b.tv_nsec) return -1;
  if (a.tv_nsec > b.tv_nsec) return  1;
  return 0;
}

#endif
