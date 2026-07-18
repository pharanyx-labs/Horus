/* dirname.h — Horus port shim for gnulib's dirname module.
 *
 * Path-component splitting used by basename(1) and dirname(1). POSIX's own
 * basename()/dirname() may modify their argument and may return static storage,
 * which is why gnulib supplies these instead; the same non-destructive contract
 * is kept here.
 *
 * Horus has a single '/' separator and no drive letters or UNC prefixes, so the
 * multi-separator and DOS-path handling upstream carries is not reproduced.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_DIRNAME_H
#define HORUS_COREUTILS_DIRNAME_H

#include <stddef.h>
#include <stdbool.h>

#define ISSLASH(C) ((C) == '/')
#define FILE_SYSTEM_PREFIX_LEN(P) 0
#define IS_ABSOLUTE_FILE_NAME(P) ISSLASH ((P)[0])
#define IS_RELATIVE_FILE_NAME(P) (! IS_ABSOLUTE_FILE_NAME (P))

/* Length of the directory part of FILE, excluding any trailing separator.
 * dir_len("/a/b") == 2, dir_len("b") == 0, dir_len("/b") == 1. */
size_t dir_len (char const *file);

/* The last component of FILE, as a pointer INTO file (no allocation). Trailing
 * slashes are not stripped -- callers pair this with strip_trailing_slashes. */
char *last_component (char const *file);

/* Malloc'd copy of the last component of FILE. */
char *base_name (char const *file);

/* Malloc'd copy of the directory part of FILE ("." when there is none). */
char *dir_name (char const *file);

/* Remove trailing separators from FILE in place; returns true if any went.
 * A file name that is all slashes keeps one, so "/" does not become "". */
bool strip_trailing_slashes (char *file);

#endif
