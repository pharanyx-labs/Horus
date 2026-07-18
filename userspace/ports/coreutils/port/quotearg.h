/* quotearg.h — Horus port shim for gnulib's quotearg module.
 *
 * gnulib's quotearg quotes a string for safe display in a diagnostic under a
 * selectable style. The utilities here only ever ask for the shell-escape style
 * (printf(1) quoting an invalid argument in an error), so this provides the enum
 * and quotearg_style(), delegating to the same shell-safe escaping quote() uses
 * — the security-relevant part is that a hostile argument cannot forge or inject
 * output into the message, which the escaping guarantees.
 *
 * Horus port glue (MIT); the vendored upstream sources stay GPLv3.
 */
#ifndef HORUS_COREUTILS_QUOTEARG_H
#define HORUS_COREUTILS_QUOTEARG_H

/* Value order matches gnulib's enum so any incidental comparison stays correct. */
enum quoting_style
{
  literal_quoting_style,
  shell_quoting_style,
  shell_always_quoting_style,
  shell_escape_quoting_style,
  shell_escape_always_quoting_style,
  c_quoting_style,
  c_maybe_quoting_style,
  escape_quoting_style,
  locale_quoting_style,
  clocale_quoting_style,
  custom_quoting_style
};

char *quotearg_style (enum quoting_style style, char const *arg);
char *quotearg_n_style (int n, enum quoting_style style, char const *arg);

#endif
