/* userspace/crt0.c — C runtime zero for newlib-linked Horus programs.
 *
 * Provides _start → posix_init() → main() → sys_exit().
 * Compiled without newlib headers (no -I newlib/include) to keep it
 * independent of the newlib build.
 */

#include "../include/posix.h"
#include "../include/syscall.h"

/* Provided by the newlib-linked user program. */
extern int main(int argc, char **argv, char **envp);

void _start(void) {
    posix_init();
    /* argc=0, argv=NULL, envp=NULL until SYS_SPAWN passes arguments. */
    int rc = main(0, (char **)0, (char **)0);
    (void)rc;
    sys_exit();
    __builtin_unreachable();
}
