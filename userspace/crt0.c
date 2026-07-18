/* userspace/crt0.c — C runtime zero for newlib-linked Horus programs.
 *
 * Provides _start → posix_init() → main(argc, argv, envp) → exit(rc).
 * Compiled without newlib headers (no -I newlib/include) to keep it
 * independent of the newlib build, so the few libc entry points it needs are
 * declared here rather than included.
 */

#include "../include/posix.h"
#include "../include/syscall.h"

/* Provided by the newlib-linked user program. */
extern int main(int argc, char **argv, char **envp);

/* newlib's exit(): runs atexit handlers (which is how stdio gets flushed), then
 * calls _exit() — our newlib_glue wrapper around SYS_EXIT. Declared rather than
 * included, per the note above. */
extern void exit(int status);

/* The (empty) environment vector, defined in newlib_glue.c. */
extern char **environ;

/* argv[0] when the task was spawned without an argument vector. POSIX programs
 * assume argv[0] exists — coreutils' set_program_name() dereferences it
 * immediately — so a null argv is not something callers defend against. */
static char *no_argv[] = { (char *)"horus", (char *)0 };

void _start(void) {
    posix_init();

    /* Collect the argument vector the kernel marshalled onto this task's stack
     * at spawn (SYS_SPAWN / SYS_EXEC_NAMED stage it; SYS_GET_ARGV reports it).
     * This used to pass argc=0/argv=NULL unconditionally, so a spawned program
     * could not see its arguments at all and any program touching argv[0]
     * faulted on the null. */
    char **argv = 0;
    int argc = sys_get_argv(&argv);
    if (argc <= 0 || !argv) {
        argc = 1;
        argv = no_argv;
    }

    /* exit(), not sys_exit(): returning from main must run the atexit handlers,
     * and for a libc program that is what flushes stdio. Calling SYS_EXIT
     * directly discarded every buffered byte a program had printed. */
    exit(main(argc, argv, environ));
    __builtin_unreachable();
}
