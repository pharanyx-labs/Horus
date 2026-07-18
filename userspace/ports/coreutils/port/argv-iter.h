/* argv-iter.h — Horus port shim for gnulib's argv-iter module.
 *
 * Iterate a sequence of names from one of two sources with a single interface:
 * a plain argv[] array, or a readtokens0 token set (for --files0-from). wc uses
 * it so the same processing loop handles both, and so it can count how many
 * names it has actually seen (argv_iter_n_args).
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_ARGV_ITER_H
#define HORUS_COREUTILS_ARGV_ITER_H

#include "readtokens0.h"

enum argv_iter_err { AI_ERR_OK = 1, AI_ERR_EOF, AI_ERR_MEM, AI_ERR_READ };

struct argv_iterator;

struct argv_iterator *argv_iter_init_argv (char **argv);
struct argv_iterator *argv_iter_init_stream (FILE *fp);
char *argv_iter (struct argv_iterator *ai, enum argv_iter_err *err);
size_t argv_iter_n_args (struct argv_iterator *ai);
void argv_iter_free (struct argv_iterator *ai);

#endif
