/* isapipe.h — Horus port shim for gnulib's isapipe module.
 *
 * isapipe(fd) reports whether fd is a pipe/FIFO. Horus has no pipes, so it is
 * always 0 — tail(1) uses this only to decide whether an input can grow while it
 * is not the tail's own file, which never applies here.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_ISAPIPE_H
#define HORUS_COREUTILS_ISAPIPE_H
int isapipe (int fd);
#endif
