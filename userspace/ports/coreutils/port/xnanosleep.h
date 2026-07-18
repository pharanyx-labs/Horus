/* xnanosleep.h — Horus port shim for gnulib's xnanosleep module.
 *
 * xnanosleep(seconds) sleeps for a fractional number of seconds, aborting on an
 * unexpected error. It is used only by tail -f's follow loop. Horus exposes no
 * wall-clock sleep syscall to userspace, so this yields the CPU a bounded number
 * of times and returns — enough that -f makes progress and stays preemptible,
 * but without true timed pacing (documented as best-effort follow).
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_XNANOSLEEP_H
#define HORUS_COREUTILS_XNANOSLEEP_H
int xnanosleep (double seconds);
#endif
