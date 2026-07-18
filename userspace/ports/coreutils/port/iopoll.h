/* iopoll.h — Horus port shim for gnulib's iopoll module.
 *
 * iopoll() waits for input readiness or output breakage on descriptors; tail(1)
 * uses it once, to notice when its stdout consumer has gone away
 * (IOPOLL_BROKEN_OUTPUT) so `tail -f` can stop. Horus has no poll(2) and no
 * pipe consumers to break, so this reports "keep going" (0) — tail follows until
 * killed, which is the correct behaviour when the output can never break.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_IOPOLL_H
#define HORUS_COREUTILS_IOPOLL_H
#include <stdbool.h>
#define IOPOLL_ERROR          (-1)
#define IOPOLL_BROKEN_OUTPUT  (-2)
int iopoll (int fdin, int fdout, bool block);
bool iopoll_input_ok (int fdin);
#endif
