/* dynstale.c -- a program built against a DIFFERENT library, and so must never
 * reach main (make smoke-shlib-link).
 *
 * It is linked with dynlink_stale.o, the linker compiled to expect a table hash
 * no library has, which is what a program built against last week's library
 * looks like. crt0 must refuse it. Under DYNLINK_ABI_UNCHECKED=1 the hash is not
 * compared and this runs, which is the arm.
 */
#include <stdio.h>

int main(void) {
    printf("DYNSTALE: ran against a library it was not built for\n");
    return 1;
}
