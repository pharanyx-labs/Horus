/* fs-is-local.h — Horus port shim for gnulib's fs-is-local.h.
 *
 * Upstream defines is_local_fs_type() over the fs.h magic numbers. tail(1) calls
 * it only inside the HAVE_FSTATFS block, which Horus does not compile, so nothing
 * references it. Empty by design; see fs.h.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_FS_IS_LOCAL_H
#define HORUS_COREUTILS_FS_IS_LOCAL_H
#endif
