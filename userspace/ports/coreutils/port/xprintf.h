/* xprintf.h — Horus port shim for gnulib's xprintf module.
 *
 * gnulib's xprintf is printf(3) with the output-error check hoisted in: it
 * writes to stdout and, on a write error, reports it and exits rather than
 * silently dropping output. coreutils' printf(1) routes every conversion through
 * it. Horus runs a single C locale over newlib stdio, so this is a thin wrapper
 * over vprintf plus the same error()-on-failure behaviour.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XPRINTF_H
#define HORUS_COREUTILS_XPRINTF_H

#include <stdarg.h>
#include <stdio.h>

int xprintf (char const *format, ...);
int xvprintf (char const *format, va_list args);
int xfprintf (FILE *stream, char const *format, ...);
int xvfprintf (FILE *stream, char const *format, va_list args);

#endif
