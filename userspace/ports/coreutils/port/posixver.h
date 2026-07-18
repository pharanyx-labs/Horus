/* posixver.h — Horus port shim for gnulib's posixver module.
 *
 * posix2_version() reports the POSIX version the utility should obey, which
 * selects between the obsolete `tail -10` and modern `tail -n 10` argument
 * syntaxes. Horus has no _POSIX2_VERSION environment influence, so this always
 * returns the modern 200809L.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_POSIXVER_H
#define HORUS_COREUTILS_POSIXVER_H
int posix2_version (void);
#endif
