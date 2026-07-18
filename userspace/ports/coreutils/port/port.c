/* port.c — Horus port shim for GNU coreutils: the handful of gnulib routines
 * the vendored utilities call at runtime.
 *
 * Upstream these live across gnulib (progname.c, version-etc.c, closeout.c) and
 * carry dependencies Horus has no use for (obstack, error.c, quotearg, …). The
 * behaviour that matters to a ported utility is small and reproduced here.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3, unmodified.
 * See ../README.md.
 */
#include "config.h"
#include "system.h"

#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "safe-read.h"
#include "full-write.h"
#include "full-read.h"
#include "alignalloc.h"
#include "quote.h"
#include "dirname.h"

/* gnulib's progname.c exports this; utilities print it in diagnostics. */
char const *program_name = "?";

void
set_program_name (char const *argv0)
{
  if (!argv0)
    {
      program_name = "?";
      return;
    }

  /* Upstream strips a leading directory and a libtool "lt-"/".libs/" prefix. A
   * Horus task's argv[0] is the bare name it was spawned with, but strip any
   * directory anyway so `run /bin/echo` still reports "echo". */
  char const *base = argv0;
  for (char const *p = argv0; *p; p++)
    if (*p == '/')
      base = p + 1;

  program_name = (*base != '\0') ? base : argv0;
}

void
emit_ancillary_info (char const *program)
{
  printf ("\nGNU coreutils online help: <%s>\n", PACKAGE_URL);
  printf ("Full documentation <%s%s>\n", PACKAGE_URL, program);
}

/* gnulib's version_etc(): the --version banner, then a NULL-terminated author
 * list. Upstream formats 1..9 authors with specific phrasing ("Written by A and
 * B.", Oxford commas, …); the shape is reproduced here for any count. */
void
version_etc (FILE *stream, char const *command_name,
             char const *package, char const *version, ...)
{
  if (command_name)
    fprintf (stream, "%s (%s) %s\n", command_name, package, version);
  else
    fprintf (stream, "%s %s\n", package, version);

  fputs ("\
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n\
This is free software: you are free to change and redistribute it.\n\
There is NO WARRANTY, to the extent permitted by law.\n\n",
         stream);

  va_list ap;
  va_start (ap, version);

  char const *authors[10];
  int n = 0;
  for (char const *a = va_arg (ap, char const *);
       a != NULL && n < (int) (sizeof authors / sizeof authors[0]);
       a = va_arg (ap, char const *))
    authors[n++] = a;
  va_end (ap);

  if (n == 0)
    return;
  if (n == 1)
    {
      fprintf (stream, "Written by %s.\n", authors[0]);
      return;
    }
  if (n == 2)
    {
      fprintf (stream, "Written by %s and %s.\n", authors[0], authors[1]);
      return;
    }

  fputs ("Written by ", stream);
  for (int i = 0; i < n; i++)
    {
      if (i == n - 1)
        fprintf (stream, "and %s.\n", authors[i]);
      else
        fprintf (stream, "%s, ", authors[i]);
    }
}

/* gnulib's close_stdout(): registered with atexit() so a write error on stdout
 * is reported and turned into a failing exit status, rather than the program
 * exiting 0 having silently truncated its output. */
void
close_stdout (void)
{
  if (fflush (stdout) != 0 || ferror (stdout))
    {
      fprintf (stderr, "%s: write error\n", program_name);
      _exit (EXIT_FAILURE);
    }
}

/* ---- gnulib I/O helpers ------------------------------------------------
 *
 * These carry real behaviour, not passthroughs: a bare read()/write() may
 * transfer fewer bytes than asked, and a caller that ignores that silently
 * truncates. Horus's read/write never return EINTR today (there is no
 * interruptible slow path in the fd layer), but the retry is kept because the
 * callers are written against the guarantee, not against this kernel. */

size_t
safe_read (int fd, void *buf, size_t count)
{
  for (;;)
    {
      ssize_t n = read (fd, buf, count);
      if (n >= 0)
        return (size_t) n;
      if (errno == EINTR)
        continue;
      return SAFE_READ_ERROR;
    }
}

size_t
safe_write (int fd, const void *buf, size_t count)
{
  for (;;)
    {
      ssize_t n = write (fd, (void *) buf, count);
      if (n >= 0)
        return (size_t) n;
      if (errno == EINTR)
        continue;
      return SAFE_WRITE_ERROR;
    }
}

/* Loop until the whole buffer is written. A short return means the error is in
 * errno; callers compare the result against the requested count. */
size_t
full_write (int fd, const void *buf, size_t count)
{
  size_t total = 0;
  const char *p = buf;
  while (total < count)
    {
      size_t n = safe_write (fd, p + total, count - total);
      if (n == SAFE_WRITE_ERROR)
        break;
      if (n == 0)
        {
          errno = ENOSPC;   /* no progress and no error: treat as full */
          break;
        }
      total += n;
    }
  return total;
}

/* Loop until `count` bytes are read, EOF, or an error. A short return with
 * errno == 0 is end-of-file; with errno set it is a failure. */
size_t
full_read (int fd, void *buf, size_t count)
{
  size_t total = 0;
  char *p = buf;
  errno = 0;
  while (total < count)
    {
      size_t n = safe_read (fd, p + total, count - total);
      if (n == SAFE_READ_ERROR)
        break;
      if (n == 0)
        break;            /* EOF; errno left as-is (0) */
      total += n;
    }
  return total;
}

/* ---- aligned allocation ------------------------------------------------
 *
 * Upstream aligns for O_DIRECT, which Horus does not have; the alignment is
 * honoured anyway so the contract holds if a caller ever depends on it.
 * Over-allocate, align up, and stash the original pointer immediately below the
 * returned address so alignfree() can hand the right one back to free(). */
void *
xalignalloc (size_t alignment, size_t size)
{
  if (alignment < sizeof (void *))
    alignment = sizeof (void *);

  size_t slack = alignment - 1 + sizeof (void *);
  if (size > (size_t) -1 - slack)       /* would overflow the raw request */
    {
      fprintf (stderr, "%s: memory exhausted\n", program_name);
      exit (EXIT_FAILURE);
    }

  char *raw = malloc (size + slack);
  if (!raw)
    {
      fprintf (stderr, "%s: memory exhausted\n", program_name);
      exit (EXIT_FAILURE);   /* the 'x' in xalignalloc: allocation must not fail */
    }

  char *aligned = raw + sizeof (void *);
  size_t rem = (size_t) (uintptr_t) aligned % alignment;
  if (rem)
    aligned += alignment - rem;
  ((void **) aligned)[-1] = raw;
  return aligned;
}

void
alignfree (void *ptr)
{
  if (ptr)
    free (((void **) ptr)[-1]);
}

/* ---- quoting for diagnostics -------------------------------------------
 *
 * Wrap a string in single quotes and escape anything non-printable, so a file
 * name carrying spaces, newlines or control characters cannot break out of the
 * message it appears in or forge extra output. Storage rotates over a few slots
 * so two quote() calls can appear in one printf, as upstream allows. */

#define QUOTE_SLOTS 4
#define QUOTE_SLOT_SZ 256

char const *
quote_n (int n, char const *arg)
{
  static char slots[QUOTE_SLOTS][QUOTE_SLOT_SZ];
  if (n < 0 || n >= QUOTE_SLOTS)
    n = 0;
  char *out = slots[n];
  size_t o = 0;

  if (!arg)
    arg = "(null)";

  out[o++] = '\'';
  for (char const *p = arg; *p; p++)
    {
      unsigned char c = (unsigned char) *p;
      /* Leave room for the worst-case escape (\ooo), the closing quote, the
       * ellipsis and the NUL. */
      if (o + 4 + 1 + 3 + 1 >= QUOTE_SLOT_SZ)
        {
          out[o++] = '.'; out[o++] = '.'; out[o++] = '.';
          break;
        }
      if (c == '\'')
        {
          /* Close, emit an escaped quote, reopen — the shell-safe form. */
          out[o++] = '\''; out[o++] = '\\'; out[o++] = '\''; out[o++] = '\'';
        }
      else if (c == '\\')
        {
          out[o++] = '\\'; out[o++] = '\\';
        }
      else if (c >= 0x20 && c < 0x7f)
        {
          out[o++] = (char) c;
        }
      else
        {
          /* Non-printable: emit \ooo rather than the byte itself. */
          out[o++] = '\\';
          out[o++] = (char) ('0' + ((c >> 6) & 7));
          out[o++] = (char) ('0' + ((c >> 3) & 7));
          out[o++] = (char) ('0' + (c & 7));
        }
    }
  out[o++] = '\'';
  out[o] = '\0';
  return out;
}

char const *
quote (char const *arg)
{
  return quote_n (0, arg);
}

/* ---- usage / diagnostic boilerplate ------------------------------------ */

void
emit_try_help (void)
{
  fprintf (stderr, "Try '%s --help' for more information.\n", program_name);
}

void
emit_stdin_note (void)
{
  fputs ("\nWith no FILE, or when FILE is -, read standard input.\n", stdout);
}

void
write_error (void)
{
  /* strerror(errno), then a failing status. Not a return: a utility that keeps
   * writing after a failed write emits truncated output and still exits 0. */
  fprintf (stderr, "%s: write error: %s\n", program_name, strerror (errno));
  exit (EXIT_FAILURE);
}

/* Quote a file name for a diagnostic. Slot 1 so it does not clobber a quote()
 * used in the same printf. */
char const *
quotef (char const *arg)
{
  return quote_n (1, arg);
}

char const *
quoteaf (char const *arg)
{
  return quote_n (2, arg);
}

void
xalloc_die (void)
{
  error (EXIT_FAILURE, 0, "memory exhausted");
  /* error() with a non-zero status does not return, but the compiler cannot see
   * that through the function pointer, and this is declared noreturn. */
  abort ();
}

/* No in-kernel copy path on Horus: report it unsupported so the caller uses its
 * own read/write loop. Failing here is correct, not a stub -- cat probes for
 * this exactly so it can fall back. */
ssize_t
copy_file_range (int infd, off_t *inoff, int outfd, off_t *outoff,
                 size_t length, unsigned int flags)
{
  (void) infd; (void) inoff; (void) outfd; (void) outoff;
  (void) length; (void) flags;
  errno = ENOSYS;
  return -1;
}

/* ---- path splitting (gnulib's dirname module) --------------------------
 *
 * Non-destructive, unlike POSIX basename()/dirname(): these never write through
 * their argument and never hand back shared static storage, which is why
 * coreutils uses them rather than the libc versions. */

char *
last_component (char const *name)
{
  char const *base = name;
  char const *p;
  bool saw_slash = false;

  while (ISSLASH (*base))
    base++;

  for (p = base; *p; p++)
    {
      if (ISSLASH (*p))
        saw_slash = true;
      else if (saw_slash)
        {
          base = p;
          saw_slash = false;
        }
    }

  return (char *) base;
}

size_t
dir_len (char const *file)
{
  size_t length;

  /* Everything before the last component, minus the separators joining them. */
  for (length = (size_t) (last_component (file) - file); length; length--)
    if (! ISSLASH (file[length - 1]))
      break;

  /* An absolute name whose directory part is all slashes keeps one, so
   * dir_name("/foo") is "/" and not "". */
  if (length == 0 && ISSLASH (file[0]))
    return 1;

  return length;
}

bool
strip_trailing_slashes (char *file)
{
  char *base = last_component (file);
  char *p;
  bool had_slash;

  /* Never strip a name down to nothing: "/" and "///" stay "/". */
  if (! *base)
    base = file;

  p = base + strlen (base);
  while (base < p && ISSLASH (p[-1]))
    p--;

  had_slash = (*p != '\0');
  *p = '\0';
  return had_slash;
}

char *
base_name (char const *file)
{
  char const *base = last_component (file);
  size_t length;

  /* A name that is entirely slashes has "/" as its base. */
  if (! *base)
    {
      char *r = malloc (2);
      if (!r) { fprintf (stderr, "%s: memory exhausted\n", program_name); exit (EXIT_FAILURE); }
      r[0] = ISSLASH (*file) ? '/' : '.';
      r[1] = '\0';
      return r;
    }

  length = strlen (base);
  while (length && ISSLASH (base[length - 1]))
    length--;

  char *r = malloc (length + 1);
  if (!r) { fprintf (stderr, "%s: memory exhausted\n", program_name); exit (EXIT_FAILURE); }
  memcpy (r, base, length);
  r[length] = '\0';
  return r;
}

char *
dir_name (char const *file)
{
  size_t length = dir_len (file);
  bool append_dot = (length == 0);
  char *r = malloc (length + append_dot + 1);

  if (!r) { fprintf (stderr, "%s: memory exhausted\n", program_name); exit (EXIT_FAILURE); }
  memcpy (r, file, length);
  if (append_dot)
    r[length++] = '.';        /* no directory part: the current one */
  r[length] = '\0';
  return r;
}

void
error (int status, int errnum, char const *format, ...)
{
  /* stdout is flushed first so an error never appears out of order with the
   * output it refers to — they are different streams with different buffering. */
  fflush (stdout);

  fprintf (stderr, "%s: ", program_name);

  va_list ap;
  va_start (ap, format);
  vfprintf (stderr, format, ap);
  va_end (ap);

  if (errnum)
    fprintf (stderr, ": %s", strerror (errnum));
  fputc ('\n', stderr);

  /* status 0 means "report and carry on" -- cat uses it so one unreadable file
   * does not abandon the rest of the command line. */
  if (status)
    exit (status);
}
