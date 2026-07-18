/* gnulib.c — Horus port shim: implementations of the gnulib modules the ported
 * coreutils utilities link against (xalloc, inttostr, xstrtol, xdectoint, ...).
 *
 * Upstream these live as separate files under gnulib's lib/, each with its own
 * portability scaffolding. The behaviour a utility actually depends on is small
 * and reproduced here; where a check is security-relevant (allocation-size
 * overflow, a rejected numeric argument) it is real, not elided.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3, unmodified.
 * See ../README.md.
 */
#include "config.h"
#include "system.h"

#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>

#include "xalloc.h"
#include "inttostr.h"
#include "xstrtol.h"
#include "xdectoint.h"
#include "cl-strtod.h"
#include "xstrtod.h"
#include "physmem.h"
#include "argmatch.h"
#include "readtokens0.h"
#include "argv-iter.h"
#include "uchar.h"
#include "quote.h"

/* ===== xalloc ============================================================ */

void *
xmalloc (size_t size)
{
  void *p = malloc (size ? size : 1);   /* malloc(0) is allowed to return NULL */
  if (!p)
    xalloc_die ();
  return p;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *p = realloc (ptr, size ? size : 1);
  if (!p)
    xalloc_die ();
  return p;
}

/* count * size, but the multiply cannot silently wrap to a small buffer that a
 * later loop overruns -- ckd_mul reports the overflow and we die instead. */
void *
xnmalloc (size_t n, size_t s)
{
  size_t bytes;
  if (ckd_mul (&bytes, n, s))
    xalloc_die ();
  return xmalloc (bytes);
}

void *
xnrealloc (void *ptr, size_t n, size_t s)
{
  size_t bytes;
  if (ckd_mul (&bytes, n, s))
    xalloc_die ();
  return xrealloc (ptr, bytes);
}

void *
xreallocarray (void *ptr, size_t n, size_t s)
{
  return xnrealloc (ptr, n, s);
}

void *
xcalloc (size_t n, size_t s)
{
  void *p = xnmalloc (n, s);
  memset (p, 0, n * s);   /* n*s already checked non-overflowing above */
  return p;
}

/* Geometric growth: enlarge *PA (currently *PN items of size S) to hold at least
 * one more, roughly 1.5x, so repeated appends amortise. */
void *
x2nrealloc (void *pa, size_t *pn, size_t s)
{
  size_t n = *pn;
  if (!pa)
    n = n ? n : (64 / (s ? s : 1)) + 1;    /* sensible first allocation */
  else
    {
      if (n > (SIZE_MAX / 3) / (s ? s : 1))   /* 1.5x would overflow */
        xalloc_die ();
      n += (n >> 1) + 1;
    }
  *pn = n;
  return xnrealloc (pa, n, s);
}

/* gnulib's xpalloc: like x2nrealloc but with a signed idx_t count, a caller
 * minimum increment, and an optional maximum. Used by env/tail's buffers. */
void *
xpalloc (void *pa, idx_t *pn, idx_t n_incr_min, ptrdiff_t n_max, idx_t s)
{
  idx_t n0 = *pn;
  idx_t half = n0 >> 1;
  idx_t incr = half > n_incr_min ? half : n_incr_min;
  if (incr < 1)
    incr = 1;

  if (n_max >= 0 && n_max - n0 < incr)
    incr = (idx_t) n_max - n0;
  if (incr <= 0)
    xalloc_die ();

  idx_t n = n0 + incr;
  *pn = n;
  return xnrealloc (pa, (size_t) n, (size_t) s);
}

char *
xstrdup (char const *s)
{
  size_t n = strlen (s) + 1;
  char *r = xmalloc (n);
  memcpy (r, s, n);
  return r;
}

void *
xmemdup (void const *p, size_t s)
{
  void *r = xmalloc (s ? s : 1);
  if (s)
    memcpy (r, p, s);
  return r;
}

/* ===== inttostr =========================================================
 *
 * Write the decimal form RIGHT-aligned at the end of `buf` and return a pointer
 * to its first digit. Callers size `buf` with INT_BUFSIZE_BOUND, so this never
 * runs past the front. */

static char *
umax_to (uintmax_t i, char *buf_end)
{
  char *p = buf_end;
  *--p = '\0';
  do
    *--p = (char) ('0' + (int) (i % 10)), i /= 10;
  while (i);
  return p;
}

char *
umaxtostr (uintmax_t i, char *buf)
{
  /* The caller passes the START of an INT_BUFSIZE_BOUND buffer; find its end. */
  char *end = buf + INT_BUFSIZE_BOUND (uintmax_t) - 1;
  char *p = umax_to (i, end + 1);
  /* Shift so the result starts at buf, matching gnulib (return value == buf). */
  size_t len = (size_t) (end + 1 - p);
  memmove (buf, p, len);
  return buf;
}

char *
imaxtostr (intmax_t i, char *buf)
{
  if (i >= 0)
    return umaxtostr ((uintmax_t) i, buf);
  /* -i as unsigned avoids overflow at INTMAX_MIN. */
  uintmax_t mag = (uintmax_t) - (i + 1) + 1;
  char tmp[INT_BUFSIZE_BOUND (uintmax_t)];
  umaxtostr (mag, tmp);
  buf[0] = '-';
  strcpy (buf + 1, tmp);
  return buf;
}

char *offtostr  (off_t i, char *buf)        { return imaxtostr ((intmax_t) i, buf); }
char *uinttostr (unsigned int i, char *buf) { return umaxtostr ((uintmax_t) i, buf); }
char *inttostr  (int i, char *buf)          { return imaxtostr ((intmax_t) i, buf); }

/* ===== xstrtol / xstrtoumax =============================================
 *
 * Parse an integer with an optional multiplier suffix, distinguishing every way
 * it can fail so the caller can report which. The suffix table is the coreutils
 * set: b=512, KB=1000, K/KiB=1024, and so on up through the SI and binary
 * prefixes. */

static int
suffix_multiplier (char c, char after, uintmax_t *mult)
{
  /* Returns 1 and sets *mult on a known suffix, else 0. `after` is the byte
   * following `c`, so KB (1000) can be told from K (1024). */
  uintmax_t base = (after == 'B') ? 1000 : 1024;
  switch (c)
    {
    case 'b': *mult = 512;  return 1;    /* always 512, ignores B */
    case 'K': case 'k': *mult = base; return 1;
    case 'M': *mult = base * base; return 1;
    case 'G': *mult = base * base * base; return 1;
    case 'T': *mult = base * base * base * base; return 1;
    case 'P': *mult = base * base * base * base * base; return 1;
    default: return 0;
    }
}

strtol_error
xstrtoumax (char const *s, char **ptr, int base,
            uintmax_t *val, char const *valid_suffixes)
{
  char *end;
  strtol_error err = LONGINT_OK;

  errno = 0;
  while (*s == ' ' || *s == '\t')
    s++;
  if (*s == '-')                       /* an unsigned parse rejects a sign */
    return LONGINT_INVALID;

  uintmax_t n = strtoumax (s, &end, base);
  if (end == s)
    return LONGINT_INVALID;            /* no digits */
  if (errno == ERANGE)
    err = LONGINT_OVERFLOW;

  if (end[0] && valid_suffixes)
    {
      uintmax_t mult;
      char *suf = strchr ((char *) valid_suffixes, end[0]);
      if (suf && suffix_multiplier (end[0], end[1], &mult))
        {
          /* Overflow in the scaling is a real overflow, not silent wraparound. */
          if (n != 0 && mult > UINTMAX_MAX / n)
            err |= LONGINT_OVERFLOW;
          else
            n *= mult;
          end++;
          if (end[0] == 'B' || end[0] == 'i')   /* consume KB / KiB tails */
            {
              end++;
              if (end[0] == 'B') end++;
            }
        }
      else
        err |= LONGINT_INVALID_SUFFIX_CHAR;
    }
  else if (end[0])
    err |= LONGINT_INVALID_SUFFIX_CHAR;

  if (ptr)
    *ptr = end;
  *val = n;
  return err;
}

strtol_error
xstrtoimax (char const *s, char **ptr, int base,
            intmax_t *val, char const *valid_suffixes)
{
  int negative = 0;
  char const *p = s;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '-') { negative = 1; p++; }
  else if (*p == '+') p++;

  uintmax_t u;
  strtol_error err = xstrtoumax (p, ptr, base, &u, valid_suffixes);
  if (negative)
    {
      if (u > (uintmax_t) INTMAX_MAX + 1)
        err |= LONGINT_OVERFLOW;
      *val = (intmax_t) (- u);
    }
  else
    {
      if (u > (uintmax_t) INTMAX_MAX)
        err |= LONGINT_OVERFLOW;
      *val = (intmax_t) u;
    }
  return err;
}

/* ===== xdectoint =========================================================
 *
 * Parse a decimal argument in [min,max], or die naming the bad option. This is
 * the "no default is acceptable" path: a malformed count must stop the program,
 * never be guessed. */

static void
xdectoint_die (char const *err, char const *s, int err_exit)
{
  error (err_exit ? err_exit : EXIT_FAILURE, 0, "%s: %s", err ? err : "invalid number", s);
}

uintmax_t
xdectoumax (char const *s, uintmax_t min, uintmax_t max,
            char const *suffixes, char const *err, int err_exit)
{
  uintmax_t v;
  strtol_error e = xstrtoumax (s, NULL, 10, &v, suffixes);
  if (e != LONGINT_OK || v < min || v > max)
    xdectoint_die (err, s, err_exit);
  return v;
}

intmax_t
xdectoimax (char const *s, intmax_t min, intmax_t max,
            char const *suffixes, char const *err, int err_exit)
{
  intmax_t v;
  strtol_error e = xstrtoimax (s, NULL, 10, &v, suffixes);
  if (e != LONGINT_OK || v < min || v > max)
    xdectoint_die (err, s, err_exit);
  return v;
}

/* ===== cl-strtod / xstrtod ==============================================
 *
 * C-locale float parsing. Horus runs only the C locale, so cl_strtod is just
 * strtod -- the "command-line" distinction (a fixed '.' decimal point,
 * independent of LC_NUMERIC) is already what newlib's strtod does here. */

double
cl_strtod (char const *nptr, char **endptr)
{
  return strtod (nptr, endptr);
}

long double
cl_strtold (char const *nptr, char **endptr)
{
  return strtold (nptr, endptr);
}

bool
xstrtod (char const *str, char const **ptr, double *result,
         double (*convert) (char const *, char **))
{
  char *terminator;
  errno = 0;
  double val = convert (str, &terminator);

  /* Valid only if at least one character was consumed, and -- when the caller
   * does not want a tail (ptr == NULL) -- nothing but the number is left. */
  bool ok = (terminator != str
             && (ptr != NULL || *terminator == '\0'));
  if (ptr)
    *ptr = terminator;
  *result = val;
  return ok;
}

bool
xstrtold (char const *str, char const **ptr, long double *result,
          long double (*convert) (char const *, char **))
{
  char *terminator;
  errno = 0;
  long double val = convert (str, &terminator);

  bool ok = (terminator != str
             && (ptr != NULL || *terminator == '\0'));
  if (ptr)
    *ptr = terminator;
  *result = val;
  return ok;
}

/* ===== physmem ==========================================================
 *
 * Ring 3 has no memory-query syscall on Horus, and upstream uses these only as
 * a buffering heuristic (never for correctness), so report a fixed, ample
 * figure. wc's one use -- "is this --files0-from list small enough to slurp?"
 * -- then behaves as it would on a machine with this much RAM. */
double physmem_total (void)     { return 64.0 * 1024 * 1024; }
double physmem_available (void) { return 64.0 * 1024 * 1024; }

/* ===== argmatch =========================================================
 *
 * Match ARG against ARGLIST allowing an unambiguous abbreviation -- "al" for
 * "always" is fine, but a prefix that fits two keywords is rejected as
 * ambiguous rather than silently resolved to the first. That refusal is the
 * point: a caller's intent must not be guessed. */

ptrdiff_t
argmatch (char const *arg, char const *const *arglist,
          void const *vallist, size_t valsize)
{
  (void) vallist; (void) valsize;
  size_t arglen = strlen (arg);
  ptrdiff_t matchind = -1;

  for (ptrdiff_t i = 0; arglist[i]; i++)
    {
      if (strncmp (arglist[i], arg, arglen) == 0)
        {
          if (strlen (arglist[i]) == arglen)
            return i;                       /* exact match wins outright */
          if (matchind == -1)
            matchind = i;                   /* first prefix hit */
          else
            matchind = -2;                  /* a second prefix: ambiguous */
        }
    }
  return matchind;
}

void
argmatch_invalid (char const *context, char const *value, ptrdiff_t problem)
{
  error (0, 0, "%s: invalid argument %s for %s",
         program_name, quote (value), quote (context));
  (void) problem;
}

void
argmatch_valid (char const *const *arglist, void const *vallist, size_t valsize)
{
  (void) vallist; (void) valsize;
  fputs ("Valid arguments are:", stderr);
  for (ptrdiff_t i = 0; arglist[i]; i++)
    fprintf (stderr, "\n  - %s", quote (arglist[i]));
  fputc ('\n', stderr);
}

ptrdiff_t
__xargmatch_internal (char const *context, char const *arg,
                      char const *const *arglist,
                      void const *vallist, size_t valsize)
{
  ptrdiff_t i = argmatch (arg, arglist, vallist, valsize);
  if (i >= 0)
    return i;
  argmatch_invalid (context, arg, i);
  argmatch_valid (arglist, vallist, valsize);
  exit (EXIT_FAILURE);               /* an unmatched option must stop the program */
}

/* ===== readtokens0 ======================================================
 *
 * Read a whole stream of NUL-separated tokens into one growing buffer, with a
 * pointer array into it. NUL separation is what lets a token hold any other
 * byte -- a file name with a space or newline is still one token, which is the
 * entire reason --files0-from exists. */

void
readtokens0_init (struct Tokens *t)
{
  t->n_tok = 0;
  t->tok = NULL;
  t->tok_len = NULL;
  t->buf = NULL;
  t->n_alloc = 0;
  t->buf_alloc = 0;
}

void
readtokens0_free (struct Tokens *t)
{
  free (t->tok);
  free (t->tok_len);
  free (t->buf);
}

/* Record the token [start,len) as the next entry. */
static void
save_token (struct Tokens *t, size_t start, size_t len)
{
  if (t->n_tok + 2 > t->n_alloc)     /* +1 for this, +1 for the NULL terminator */
    {
      t->n_alloc = t->n_alloc ? t->n_alloc * 2 : 8;
      t->tok = xnrealloc (t->tok, t->n_alloc, sizeof *t->tok);
      t->tok_len = xnrealloc (t->tok_len, t->n_alloc, sizeof *t->tok_len);
    }
  t->tok[t->n_tok] = t->buf + start;
  t->tok_len[t->n_tok] = len;
  t->n_tok++;
}

bool
readtokens0 (FILE *in, struct Tokens *t)
{
  size_t used = 0;
  int c;
  size_t tok_start = 0;

  for (;;)
    {
      c = getc (in);
      if (used + 1 > t->buf_alloc)
        {
          t->buf_alloc = t->buf_alloc ? t->buf_alloc * 2 : 256;
          char *nb = xrealloc (t->buf, t->buf_alloc);
          /* buf moved: rebuild the token pointers into the new storage. */
          if (nb != t->buf)
            {
              ptrdiff_t shift = nb - t->buf;
              for (size_t i = 0; i < t->n_tok; i++)
                t->tok[i] += shift;
              t->buf = nb;
            }
        }
      if (c == EOF)
        break;
      t->buf[used] = (char) c;
      if (c == '\0')
        {
          save_token (t, tok_start, used - tok_start);
          tok_start = used + 1;
        }
      used++;
    }

  /* A trailing token with no final NUL is still a token. */
  if (used > tok_start)
    {
      if (used + 1 > t->buf_alloc)
        {
          t->buf_alloc += 1;
          char *nb = xrealloc (t->buf, t->buf_alloc);
          ptrdiff_t shift = nb - t->buf;
          for (size_t i = 0; i < t->n_tok; i++)
            t->tok[i] += shift;
          t->buf = nb;
        }
      t->buf[used++] = '\0';
      save_token (t, tok_start, used - 1 - tok_start);
    }

  if (t->tok)
    t->tok[t->n_tok] = NULL;             /* NULL-terminate the pointer array */
  return ! ferror (in);
}

/* ===== argv-iter ========================================================
 *
 * One iteration interface over either a plain argv[] or a readtokens0 stream,
 * so a utility's processing loop does not care which the names came from. */

struct argv_iterator {
  char **argv;              /* argv mode: the array, or */
  char **p;
  FILE *fp;                 /* stream mode: a NUL-token stream, buffered here */
  struct Tokens tok;
  size_t tok_i;
  int mode;                 /* 0 = argv, 1 = stream */
  size_t n_args;            /* how many names handed out */
};

struct argv_iterator *
argv_iter_init_argv (char **argv)
{
  struct argv_iterator *ai = xmalloc (sizeof *ai);
  ai->mode = 0;
  ai->argv = argv;
  ai->p = argv;
  ai->n_args = 0;
  return ai;
}

struct argv_iterator *
argv_iter_init_stream (FILE *fp)
{
  struct argv_iterator *ai = xmalloc (sizeof *ai);
  ai->mode = 1;
  ai->fp = fp;
  readtokens0_init (&ai->tok);
  ai->tok_i = 0;
  ai->n_args = 0;
  /* Read the whole stream up front: simpler than incremental, and the inputs
   * here are small. A read error is reported on the first argv_iter call. */
  ai->argv = NULL;
  if (readtokens0 (fp, &ai->tok))
    ai->argv = (char **) ai->tok.tok;      /* NULL-terminated */
  return ai;
}

char *
argv_iter (struct argv_iterator *ai, enum argv_iter_err *err)
{
  if (ai->mode == 0)
    {
      if (*ai->p == NULL) { *err = AI_ERR_EOF; return NULL; }
      *err = AI_ERR_OK;
      ai->n_args++;
      return *ai->p++;
    }
  /* stream mode */
  if (ai->argv == NULL) { *err = AI_ERR_READ; return NULL; }
  if (ai->tok_i >= ai->tok.n_tok) { *err = AI_ERR_EOF; return NULL; }
  *err = AI_ERR_OK;
  ai->n_args++;
  return ai->tok.tok[ai->tok_i++];
}

size_t
argv_iter_n_args (struct argv_iterator *ai)
{
  return ai->n_args;
}

void
argv_iter_free (struct argv_iterator *ai)
{
  if (ai->mode == 1)
    readtokens0_free (&ai->tok);
  free (ai);
}

/* ===== uchar (char32) ===================================================
 *
 * C-locale multibyte conversion. wc only reaches this when MB_CUR_MAX > 1,
 * which never happens in the C locale Horus runs; the implementations are
 * nonetheless C-locale-correct (one byte is one character) rather than stubs. */

size_t
mbrtoc32 (char32_t *pc32, const char *s, size_t n, mbstate_t *ps)
{
  (void) ps;
  if (s == NULL)
    return 0;                          /* state reset: C locale is stateless */
  if (n == 0)
    return (size_t) -2;                /* incomplete: no bytes available */
  unsigned char c = (unsigned char) s[0];
  if (pc32)
    *pc32 = c;
  return c ? 1 : 0;                    /* 0 for the NUL character, per the spec */
}

size_t
c32rtomb (char *s, char32_t c32, mbstate_t *ps)
{
  (void) ps;
  if (s == NULL)
    return 1;
  if (c32 > 0xFF)
    { errno = EILSEQ; return (size_t) -1; }   /* not representable in C locale */
  s[0] = (char) c32;
  return 1;
}

int
c32width (char32_t c)
{
  /* C-locale ASCII widths: control characters have no width, everything else
   * one column. This path is compile-only on Horus (see the header). */
  if (c == 0)
    return 0;
  if (c < 0x20 || c == 0x7f)
    return -1;
  return 1;
}

char32_t
btoc32 (int c)
{
  return (c == EOF) ? (char32_t) -1 : (char32_t) (unsigned char) c;
}

/* ---- xprintf (gnulib xprintf module) --------------------------------------
 * printf/fprintf with the write-error check hoisted in: on a stdio error the
 * utility reports it and exits, matching gnulib's behaviour, so a failed write
 * to a full pipe or disk is never silently dropped. coreutils printf(1) routes
 * every conversion through xprintf(). */
#include <stdarg.h>
#include "xprintf.h"
#include "unicodeio.h"

int
xvfprintf (FILE *stream, char const *format, va_list args)
{
  int retval = vfprintf (stream, format, args);
  if (retval < 0 && ! ferror (stream))
    error (EXIT_FAILURE, errno, "cannot perform formatted output");
  return retval;
}

int
xfprintf (FILE *stream, char const *format, ...)
{
  va_list args;
  va_start (args, format);
  int retval = xvfprintf (stream, format, args);
  va_end (args);
  return retval;
}

int
xvprintf (char const *format, va_list args)
{
  return xvfprintf (stdout, format, args);
}

int
xprintf (char const *format, ...)
{
  va_list args;
  va_start (args, format);
  int retval = xvfprintf (stdout, format, args);
  va_end (args);
  return retval;
}

/* ---- unicodeio (gnulib unicodeio module) ----------------------------------
 * Encode a Unicode code point as UTF-8 and write it. Horus runs a UTF-8-capable
 * C locale, so there is no unrepresentable-character fallback to a \uXXXX form:
 * every scalar value encodes directly. */
static int
utf8_encode (unsigned int code, char out[4])
{
  if (code < 0x80)     { out[0] = (char) code; return 1; }
  if (code < 0x800)    { out[0] = (char) (0xC0 | (code >> 6));
                         out[1] = (char) (0x80 | (code & 0x3F)); return 2; }
  if (code < 0x10000)  { out[0] = (char) (0xE0 | (code >> 12));
                         out[1] = (char) (0x80 | ((code >> 6) & 0x3F));
                         out[2] = (char) (0x80 | (code & 0x3F)); return 3; }
  if (code < 0x110000) { out[0] = (char) (0xF0 | (code >> 18));
                         out[1] = (char) (0x80 | ((code >> 12) & 0x3F));
                         out[2] = (char) (0x80 | ((code >> 6) & 0x3F));
                         out[3] = (char) (0x80 | (code & 0x3F)); return 4; }
  return 0;                                       /* out of range */
}

long
fwrite_success_callback (const char *buf, size_t buflen, void *callback_arg)
{
  fwrite (buf, 1, buflen, (FILE *) callback_arg);
  return 0;
}

long
unicode_to_mb (unsigned int code,
               long (*success) (const char *buf, size_t buflen, void *callback_arg),
               long (*failure) (unsigned int code, const char *msg, void *callback_arg),
               void *callback_arg)
{
  char buf[4];
  int n = utf8_encode (code, buf);
  if (n == 0)
    return failure (code, "code out of range", callback_arg);
  return success (buf, (size_t) n, callback_arg);
}

void
print_unicode_char (FILE *stream, unsigned int code, int quote)
{
  (void) quote;
  char buf[4];
  int n = utf8_encode (code, buf);
  if (n > 0)
    fwrite (buf, 1, (size_t) n, stream);
}

/* ---- tail(1) support shims (iopoll / isapipe / posixver / xnanosleep) ------
 * The follow (-f) machinery upstream leans on OS facilities Horus does not have
 * (inotify, poll, pipes, a wall-clock sleep). tail's non-follow paths (-n / -c
 * line and byte selection) use none of these; the shims below let the byte-
 * identical source link and run, with -f degrading to a preemptible poll loop. */
#include <unistd.h>
#include "iopoll.h"
#include "isapipe.h"
#include "posixver.h"
#include "xnanosleep.h"

/* Horus has no pipes/FIFOs. */
int
isapipe (int fd)
{
  (void) fd;
  return 0;
}

/* Always select the modern (POSIX.1-2008) argument syntax. */
int
posix2_version (void)
{
  return 200809;
}

/* No poll(2) and no breakable output consumer: report "keep going". tail -f then
 * follows until the task is killed, which is correct when output cannot break. */
int
iopoll (int fdin, int fdout, bool block)
{
  (void) fdin; (void) fdout; (void) block;
  return 0;
}

bool
iopoll_input_ok (int fdin)
{
  (void) fdin;
  return true;
}

/* Best-effort sleep: Horus exposes no timed sleep to ring 3, so busy-spin a
 * bounded amount (scaled loosely by the requested seconds) and return. The timer
 * preempts the spin, so other tasks still run; tail -f therefore polls promptly
 * rather than pacing to a real clock. Returns 0 (success), as gnulib's
 * xnanosleep does. The counter is volatile so the loop is not optimised away. */
int
xnanosleep (double seconds)
{
  double s = seconds > 0.0 ? seconds : 0.0;
  unsigned long iters = (unsigned long) (s * 2000000.0) + 100000UL;
  if (iters > 200000000UL) iters = 200000000UL;
  for (volatile unsigned long i = 0; i < iters; i++)
    ;
  return 0;
}
