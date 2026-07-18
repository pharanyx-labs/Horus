/* xstrtol.h — Horus port shim for gnulib's xstrtol / xstrtoumax modules.
 *
 * Parse a human-written integer -- optionally with a size suffix (K, M, G, ...,
 * and the block suffix `b`) -- into a fixed-width integer, distinguishing the
 * ways it can fail: not a number, trailing garbage, out of range, or a bad
 * suffix. The utilities use this for `-n 50`, `-c 1K`, `head`/`tail` line and
 * byte counts.
 *
 * Returning a specific error rather than a sentinel is what lets a utility say
 * *why* an argument was rejected instead of silently treating "-c 1Q" as some
 * default -- the security-relevant property being that a malformed count is
 * refused, never guessed.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XSTRTOL_H
#define HORUS_COREUTILS_XSTRTOL_H

#include <stdint.h>
#include <inttypes.h>

typedef enum {
    LONGINT_OK = 0,
    LONGINT_OVERFLOW = 1,
    LONGINT_INVALID_SUFFIX_CHAR = 2,
    LONGINT_INVALID_SUFFIX_CHAR_WITH_OVERFLOW = 3,   /* OVERFLOW | SUFFIX */
    LONGINT_INVALID = 4
} strtol_error;

/* `valid_suffixes` is the set of accepted multiplier letters (NULL = none).
 * On LONGINT_OK, *val holds the parsed value; *ptr (if non-NULL) points past the
 * consumed text. */
strtol_error xstrtoumax (char const *s, char **ptr, int base,
                         uintmax_t *val, char const *valid_suffixes);
strtol_error xstrtoimax (char const *s, char **ptr, int base,
                         intmax_t *val, char const *valid_suffixes);

#endif
