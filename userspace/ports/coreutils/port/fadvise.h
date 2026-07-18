/* fadvise.h — Horus port shim for gnulib's fadvise.h.
 *
 * posix_fadvise() is purely advisory: it tells the page cache what access
 * pattern to expect. Horus has no page cache to advise, so these are no-ops --
 * which is a complete implementation of an advisory interface, not a stub that
 * loses behaviour.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_FADVISE_H
#define HORUS_COREUTILS_FADVISE_H

#include <stdio.h>

typedef enum {
    FADVISE_NORMAL, FADVISE_SEQUENTIAL, FADVISE_NOREUSE,
    FADVISE_DONTNEED, FADVISE_WILLNEED, FADVISE_RANDOM
} fadvice_t;

static inline void fdadvise (int fd, off_t off, off_t len, fadvice_t adv)
    { (void) fd; (void) off; (void) len; (void) adv; }
static inline void fadvise (FILE *fp, fadvice_t adv)
    { (void) fp; (void) adv; }

#endif
