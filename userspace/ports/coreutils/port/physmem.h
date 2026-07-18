/* physmem.h — Horus port shim for gnulib's physmem module.
 *
 * physmem_total()/physmem_available() report RAM, which upstream uses only as a
 * sizing HEURISTIC (e.g. wc decides whether to slurp a --files0-from list into
 * memory). Horus does not expose a per-process memory query to ring 3, so this
 * returns a fixed conservative figure -- large enough that the heuristic behaves
 * the same for the small inputs Horus deals with, and it only ever affects a
 * buffering choice, never correctness.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_PHYSMEM_H
#define HORUS_COREUTILS_PHYSMEM_H

double physmem_total (void);
double physmem_available (void);

#endif
