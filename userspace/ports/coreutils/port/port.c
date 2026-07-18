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
