/* readtokens0.h — Horus port shim for gnulib's readtokens0 module.
 *
 * Read an entire stream of NUL-separated tokens (as produced by `find -print0`)
 * into an array. wc uses it for --files0-from. The tokens are held in one
 * growing buffer with a pointer array into it, so a token may contain any byte
 * except NUL -- which is exactly why NUL separation exists: a file name with a
 * newline or space in it is still one token.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_READTOKENS0_H
#define HORUS_COREUTILS_READTOKENS0_H

#include <stdio.h>
#include <stddef.h>

struct Tokens {
    size_t n_tok;       /* number of tokens */
    char **tok;         /* the tokens (NULL-terminated array) */
    size_t *tok_len;    /* each token's length */
    char *buf;          /* backing storage for all token bytes */
    size_t n_alloc;
    size_t buf_alloc;
};

void readtokens0_init (struct Tokens *t);
void readtokens0_free (struct Tokens *t);
bool readtokens0 (FILE *in, struct Tokens *t);

#endif
