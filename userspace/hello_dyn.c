/* hello_dyn.c -- a program LINKED against the shared libc, as an ordinary
 * program is (docs/design/shared-libc.md §8, make smoke-shlib-link).
 *
 *   hello_dyn -n NAME ARG...   parses its options with getopt_long and prints
 *                              optarg and optind. Those two are the library's
 *                              DATA, which the stub archive could never share:
 *                              a program-local copy desynchronises from the
 *                              getopt that writes it. Through the GOT they are
 *                              the library's own, in this task's private copy.
 *   hello_dyn seal             writes one slot of its own resolved table back
 *                              with the value it already holds. crt0 sealed the
 *                              table (S107), so the write must fault, and the
 *                              handler says so. A write that returns means the
 *                              table was left writable.
 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/syscall.h"

extern char __horus_relro_start[] __attribute__((visibility("hidden")));

static const char fault_msg[] = "HELLODYN: the resolved table refused a write\n";

/* Realigned and strlen-free: the kernel enters a handler on the interrupted
 * stack with no alignment promised (see userspace/sealprobe.c). */
__attribute__((force_align_arg_pointer))
static void on_fault(void) {
    (void)write(1, fault_msg, sizeof(fault_msg) - 1);
    sys_exit();
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "seal") == 0) {
        volatile uint64_t *slot = (volatile uint64_t *)(uintptr_t)__horus_relro_start;
        uint64_t v = *slot;
        if (sys_signal((uintptr_t)&on_fault) != 0) { printf("HELLODYN: FAIL no handler\n"); return 1; }
        *slot = v;                            /* the same value: harmless if it lands */
        printf("HELLODYN: FAIL the resolved table took a write\n");
        return 1;
    }

    static const struct option opts[] = { { "name", required_argument, 0, 'n' }, { 0, 0, 0, 0 } };
    const char *name = "(none)";
    int c;
    while ((c = getopt_long(argc, argv, "n:", opts, 0)) != -1) {
        if (c == 'n') name = optarg;
        else { printf("HELLODYN: FAIL unexpected option\n"); return 1; }
    }
    printf("HELLODYN: name=%s optind=%d of argc=%d\n", name, optind, argc);
    char *p = malloc(32);
    if (!p) { printf("HELLODYN: FAIL malloc\n"); return 1; }
    sprintf(p, "%.20s-%d", name, 42);
    printf("HELLODYN: %s\n", p);
    free(p);
    printf("HELLODYN: PASS\n");
    return 0;
}
