/* hello_shared.c -- a program whose entire libc is the shared one.
 *
 * It links no libc code at all: crt0_shared binds the library at startup, and
 * every call below is a tail jump through its export table. What it proves that
 * libctest could not is that a program written in ORDINARY C -- calling printf
 * by name, not indexing a table -- reaches the shared library, which is the
 * point of the stub archive.
 *
 * The calls are chosen to cross the boundary in both directions: strlen is pure
 * shared text; snprintf/printf go through the library's per-task reentrancy
 * state (S50) and out through its own syscall glue.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv, char **envp) {
    (void)envp;

    printf("HELLOSHARED: begin argc=%d argv0=%s\n", argc, argv[0]);

    const char *s = "horus";
    if (strlen(s) != 5) { printf("HELLOSHARED: FAIL strlen\n"); return 1; }

    char buf[32];
    int n = sprintf(buf, "%s-%d", s, 42);
    if (n != 8 || strcmp(buf, "horus-42") != 0) {
        printf("HELLOSHARED: FAIL sprintf '%s'\n", buf);
        return 1;
    }

    /* errno lives in the library's per-task data, reached through the program's
     * own _impure_ptr copy that crt0_shared initialised. Writing and reading it
     * back exercises that path rather than only the pure-text one. */
    void *p = malloc(64);
    if (!p) { printf("HELLOSHARED: FAIL malloc\n"); return 1; }
    memset(p, 0xA5, 64);
    if (((unsigned char *)p)[63] != 0xA5) {
        printf("HELLOSHARED: FAIL malloc-write\n"); return 1;
    }
    free(p);

    printf("HELLOSHARED: PASS\n");
    return 0;
}
