/* shlibprobe.c -- a program that never asked for the shared libc, asking whether
 * it holds it anyway.
 *
 * The negative half of make smoke-shlib-inherit. A spawned child inherits the
 * library's text capabilities only when its own image asks (DT_NEEDED
 * "libc.so", docs/design/shared-libc.md §4). This image links newlib statically,
 * exactly as the shipped coreutils do today, so it has no DT_NEEDED at all, and
 * the shell that spawns it holds the library and must pass it NOTHING.
 *
 * SYS_SHLIB_INFO is the question: it answers only a caller presenting a
 * capability over one of the library's own text frames, at the slot every holder
 * keeps them in. A refusal is the property; an answer means the capability
 * arrived without being asked for, which is authority spreading to a task that
 * never needed it. Under SHLIB_INHERIT_ANY_IMAGE=1 that is exactly what happens,
 * and the gate goes red on this line.
 */
#include <stdio.h>

#include "../include/syscall.h"

int main(void) {
    struct shlib_info si;
    if (sys_shlib_info(CAPSLOT_LIBC_FIRST, &si) == 0)
        printf("SHLIBPROBE: HOLDS the library, though its image never asked\n");
    else
        printf("SHLIBPROBE: holds no library capability\n");
    return 0;
}
