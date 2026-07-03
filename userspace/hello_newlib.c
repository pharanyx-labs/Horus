/* userspace/hello_newlib.c — smoke test for newlib on Horus.
 *
 * Exercises the key newlib paths:
 *   printf / sprintf   → _write → posix_write → console
 *   malloc / free      → _sbrk → SYS_SBRK
 *   string functions   → newlib's own implementations
 *   fgets from stdin   NOT exercised (smoke test is headless)
 *
 * Prints "NEWLIB_SELFTEST: PASS" on success so `make smoke-newlib` can assert.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Direct kernel write bypassing newlib stdio for tracing */
#include "../include/syscall.h"

static void kwrite(const char *s) {
    uint32_t len = 0;
    while (s[len]) len++;
    sys_write(1, s, (size_t)len);
}

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    kwrite("A\n");   /* reached main */
    puts("P1");
    kwrite("B\n");   /* puts returned */
    /* --- printf / formatted output ---------------------------------- */
    printf("newlib: printf OK\n");
    kwrite("C\n");   /* printf returned */

    /* --- sprintf ----------------------------------------------------- */
    char buf[64];
    int n = sprintf(buf, "sprintf: 2+2=%d", 2 + 2);
    if (n != 14 || strcmp(buf, "sprintf: 2+2=4") != 0) {
        printf("NEWLIB_SELFTEST: FAIL sprintf\n");
        return 1;
    }
    printf("%s OK\n", buf);

    /* --- malloc / free ----------------------------------------------- */
    char *p = (char *)malloc(256);
    if (!p) {
        printf("NEWLIB_SELFTEST: FAIL malloc returned NULL\n");
        return 1;
    }
    memset(p, 0xAB, 256);
    int ok = 1;
    for (int i = 0; i < 256; i++) {
        if ((unsigned char)p[i] != 0xAB) { ok = 0; break; }
    }
    free(p);
    if (!ok) {
        printf("NEWLIB_SELFTEST: FAIL memset/memcmp\n");
        return 1;
    }
    printf("malloc/memset/free OK\n");

    /* --- string functions -------------------------------------------- */
    char s[32];
    strcpy(s, "Hello");
    strcat(s, ", Horus!");
    if (strcmp(s, "Hello, Horus!") != 0) {
        printf("NEWLIB_SELFTEST: FAIL strcpy/strcat/strcmp\n");
        return 1;
    }
    printf("string ops OK\n");

    /* --- integer arithmetic in printf -------------------------------- */
    long sum = 0;
    for (int i = 1; i <= 100; i++) sum += i;
    printf("sum 1..100 = %ld (expect 5050)\n", sum);
    if (sum != 5050) {
        printf("NEWLIB_SELFTEST: FAIL sum\n");
        return 1;
    }

    printf("NEWLIB_SELFTEST: PASS\n");
    return 0;
}
