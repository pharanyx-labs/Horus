/* fs.h — Horus port shim for gnulib's fs.h.
 *
 * Upstream fs.h carries the Linux filesystem-type magic numbers tail(1) uses to
 * tell a local filesystem from a remote (NFS/…) one, so it can prefer inotify
 * over polling. On Horus that whole path is compiled out — HAVE_FSTATFS and
 * HAVE_STRUCT_STATFS_F_TYPE are undefined, so fremote() never consults these — and
 * tail keeps its conservative poll-by-default behaviour. This header exists only
 * to satisfy the unconditional #include in tail.c's __linux__ block.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_FS_H
#define HORUS_COREUTILS_FS_H
#endif
