/* fcntl--.h — Horus port shim for gnulib's fcntl-- module.
 *
 * Upstream's fcntl-- redefines open()/creat() to always set O_CLOEXEC, so a
 * descriptor never leaks across an exec. Horus has no exec-that-inherits-fds
 * model (a spawned task gets a fresh fd table), so there is nothing to close on
 * exec; this is just <fcntl.h>.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_FCNTL_DASHDASH_H
#define HORUS_COREUTILS_FCNTL_DASHDASH_H
#include <fcntl.h>
#endif
