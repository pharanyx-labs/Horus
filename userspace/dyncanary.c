/* dyncanary.c -- a program that references a name the shared libc does not
 * export, and so must never reach main (make smoke-shlib-link).
 *
 * __horus_link_canary is in the link stub (userspace/libc_link.so) and nowhere
 * in the library, so this links and must be REFUSED by crt0's linker with the
 * name. Under DYNLINK_UNKNOWN_ZERO=1 the name resolves to zero instead and this
 * runs, which is the arm.
 */
#include <stdio.h>

extern void __horus_link_canary(void);

int main(void) {
    void (*volatile f)(void) = __horus_link_canary;
    printf("DYNCANARY: ran with an unresolved name (%p)\n", (void *)f);
    return 1;
}
