/* crt0_shared.c -- C runtime zero for a program whose libc is the shared one.
 *
 * The static crt0.c calls posix_init() and main() directly, because both are
 * linked into the program. Neither is, here: main is, but every libc entry point
 * is a stub that jumps through the shared library's export table, and that table
 * does not exist until shlib_bind() fills it in.
 *
 * SO THE ORDER IS THE WHOLE FILE. shlib_bind() first, before anything that could
 * call a stub -- and note that "anything" includes the parts of this file that
 * look innocent: sys_get_argv is a raw syscall and is fine, but posix_init is a
 * stub, exit is a stub, and main is entirely made of them.
 *
 * A bind failure cannot be reported through libc, for the same reason. It writes
 * a fixed string with a raw syscall and exits: a program that carried on here
 * would fault somewhere inside a stub, at an address that explains nothing about
 * what actually went wrong.
 */

#include "../include/posix.h"
#include "../include/syscall.h"

extern int main(int argc, char **argv, char **envp);
extern void exit(int status);          /* stub -> the library's exit */
extern void posix_init(void);          /* stub -> the library's posix_init */
/* The program's OWN environment vector, and not the library's.
 *
 * `environ` is data, so a reference to the library's copy cannot be redirected
 * by a tail jump -- the same limit that keeps optarg/optind out of the table. It
 * is also not exported, so referencing it would simply fail to link.
 *
 * Defining an empty one here is correct rather than a workaround: the library's
 * environ is empty too (newlib_glue.c), this system has no environment to
 * inherit, and getenv() goes through a stub to the library, which reads the
 * library's copy. Both are empty, so there is nothing for the two to disagree
 * about -- and if that ever changes, this is the line that has to change with
 * it, which is why it is spelled out rather than shared. */
static char *empty_environ[] = { (char *)0 };

int shlib_bind(void);                  /* userspace/shlib_start.c */

static char *no_argv[] = { (char *)"horus", (char *)0 };

static void die(const char *s) {
    unsigned n = 0;
    while (s[n]) n++;
    sys_write(2, s, n);
    sys_exit();
}

void _start(void) {
    /* Before this returns 0, this program has no libc at all. */
    if (shlib_bind() != 0)
        die("crt0_shared: could not bind the shared libc\n");

    posix_init();

    char **argv = 0;
    int argc = sys_get_argv(&argv);
    if (argc <= 0 || !argv) {
        argc = 1;
        argv = no_argv;
    }

    exit(main(argc, argv, empty_environ));
}
