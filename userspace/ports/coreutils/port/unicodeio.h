/* unicodeio.h — Horus port shim for gnulib's unicodeio module.
 *
 * gnulib's unicodeio converts a Unicode code point to the locale's multibyte
 * encoding and writes it, falling back to a "\uXXXX"-style notation when the
 * locale cannot represent it. coreutils' printf(1) uses print_unicode_char() for
 * the \u / \U escapes. Horus runs a single UTF-8-capable C locale, so this
 * encodes the code point as UTF-8 directly.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_UNICODEIO_H
#define HORUS_COREUTILS_UNICODEIO_H

#include <stddef.h>
#include <stdio.h>

/* Encode `code` as UTF-8 into `buf` (needs >= 4 bytes); returns the byte count,
 * or 0 for an out-of-range code point. */
long unicode_to_mb (unsigned int code,
                    long (*success) (const char *buf, size_t buflen, void *callback_arg),
                    long (*failure) (unsigned int code, const char *msg, void *callback_arg),
                    void *callback_arg);

/* Write `code` to `stream` as UTF-8. `quote` is accepted for interface
 * compatibility and ignored (Horus never needs the quoted fallback form). */
void print_unicode_char (FILE *stream, unsigned int code, int quote);

long fwrite_success_callback (const char *buf, size_t buflen, void *callback_arg);

#endif
