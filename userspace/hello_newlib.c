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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
/* <sys/errno.h>, not <errno.h>: -I include precedes the newlib headers, so
 * <errno.h> would resolve to the project's SYS_ERR_* header (no errno/ENOENT).
 * newlib_glue.c includes it the same way for the same reason. */
#include <sys/errno.h>

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

    /* --- filesystem: real newlib open()/write()/unlink() over the fs_server ---
     * The kernel launched an fs_server alongside us and delegated an endpoint
     * cap; the RAM store is auto-unlocked and we run as kernel-attested uid 0,
     * so these libc calls exercise unlink() → posix_unlink() → FS_OP_DELETE
     * end-to-end, plus the path-resolution and errno-mapping paths. */
    {
        const char *path = "/unlinkme";

        int fd = open(path, O_CREAT | O_RDWR, 0644);
        if (fd < 0)                 { printf("NEWLIB_SELFTEST: FAIL fs-open-create\n"); return 1; }
        if (write(fd, "bye", 3) != 3) { printf("NEWLIB_SELFTEST: FAIL fs-write\n");     return 1; }

        /* fstat on the open fd: the fs_server reports the real inode metadata
         * (a new file is a regular file, mode 0644, owned by our uid 0). */
        struct stat fsb;
        if (fstat(fd, &fsb) != 0)         { printf("NEWLIB_SELFTEST: FAIL fs-fstat\n");      return 1; }
        if (!S_ISREG(fsb.st_mode))        { printf("NEWLIB_SELFTEST: FAIL fs-fstat-type\n"); return 1; }
        if ((fsb.st_mode & 0777) != 0644) { printf("NEWLIB_SELFTEST: FAIL fs-fstat-mode\n"); return 1; }
        if (fsb.st_uid != 0)              { printf("NEWLIB_SELFTEST: FAIL fs-fstat-uid\n");  return 1; }
        if (fsb.st_size != 3)             { printf("NEWLIB_SELFTEST: FAIL fs-fstat-size\n"); return 1; }
        close(fd);

        /* stat by path returns the same real metadata. */
        struct stat sb;
        if (stat(path, &sb) != 0)         { printf("NEWLIB_SELFTEST: FAIL fs-stat\n");       return 1; }
        if (!S_ISREG(sb.st_mode))         { printf("NEWLIB_SELFTEST: FAIL fs-stat-type\n");  return 1; }
        if ((sb.st_mode & 0777) != 0644)  { printf("NEWLIB_SELFTEST: FAIL fs-stat-mode\n");  return 1; }
        if (sb.st_uid != 0)               { printf("NEWLIB_SELFTEST: FAIL fs-stat-uid\n");   return 1; }
        if (sb.st_size != 3)              { printf("NEWLIB_SELFTEST: FAIL fs-stat-size\n");  return 1; }

        /* It exists now: a plain open must succeed. */
        int rfd = open(path, O_RDONLY);
        if (rfd < 0)                { printf("NEWLIB_SELFTEST: FAIL fs-precheck\n");     return 1; }
        close(rfd);

        /* Remove it: expect success. */
        if (unlink(path) != 0)      { printf("NEWLIB_SELFTEST: FAIL unlink\n");          return 1; }

        /* Gone now: open must fail. */
        if (open(path, O_RDONLY) >= 0) { printf("NEWLIB_SELFTEST: FAIL unlink-verify\n"); return 1; }

        /* Unlinking a missing name: -1 with errno ENOENT. */
        errno = 0;
        if (unlink(path) != -1 || errno != ENOENT) { printf("NEWLIB_SELFTEST: FAIL unlink-missing\n"); return 1; }

        /* Unlinking through a missing intermediate directory exercises
         * path_parent's intermediate-component lookup: -1 with errno ENOENT. */
        errno = 0;
        if (unlink("/nope/x") != -1 || errno != ENOENT) { printf("NEWLIB_SELFTEST: FAIL unlink-badpath\n"); return 1; }

        printf("fs open/write/stat/unlink OK\n");
    }

    /* --- rename() + O_TRUNC over the fs_server ----------------------------
     * These are the two BFD-critical primitives (ar/ld/as write to a temp file
     * then rename it over the target, and rewrite output with O_TRUNC). The
     * O_TRUNC case also guards a stale-data-disclosure bug: after truncating to
     * 0 and growing the file again with a hole, the freed range must read as
     * zeros, not the old bytes. */
    {
        const char *a = "/rn_a", *b = "/rn_b";

        int fd = open(a, O_CREAT | O_RDWR, 0644);
        if (fd < 0 || write(fd, "hello world", 11) != 11) { printf("NEWLIB_SELFTEST: FAIL rn-setup\n"); return 1; }
        close(fd);

        /* rename a -> b: the old name disappears, the new one holds the data. */
        if (rename(a, b) != 0)      { printf("NEWLIB_SELFTEST: FAIL rename\n");          return 1; }
        if (open(a, O_RDONLY) >= 0) { printf("NEWLIB_SELFTEST: FAIL rename-old-present\n"); return 1; }
        fd = open(b, O_RDONLY);
        char rb[16];
        if (fd < 0 || read(fd, rb, 11) != 11 || memcmp(rb, "hello world", 11) != 0) {
            printf("NEWLIB_SELFTEST: FAIL rename-content\n"); return 1;
        }
        close(fd);

        /* O_TRUNC empties the file to 0. */
        fd = open(b, O_WRONLY | O_TRUNC);
        if (fd < 0)                 { printf("NEWLIB_SELFTEST: FAIL trunc-open\n");  return 1; }
        struct stat tb;
        if (stat(b, &tb) != 0 || tb.st_size != 0) { printf("NEWLIB_SELFTEST: FAIL trunc-size\n"); return 1; }

        /* Grow it with a hole: write 'Z' at offset 5. Bytes 0..4 MUST read back
         * as zeros — if the server had only set the size and left the old block,
         * they would still be "hello" (stale-data leak). */
        if (lseek(fd, 5, SEEK_SET) != 5 || write(fd, "Z", 1) != 1) { printf("NEWLIB_SELFTEST: FAIL trunc-write\n"); return 1; }
        close(fd);
        fd = open(b, O_RDONLY);
        char hb[8];
        if (fd < 0 || read(fd, hb, 6) != 6) { printf("NEWLIB_SELFTEST: FAIL trunc-read\n"); return 1; }
        for (int i = 0; i < 5; i++) if (hb[i] != 0) { printf("NEWLIB_SELFTEST: FAIL trunc-stale\n"); return 1; }
        if (hb[5] != 'Z')           { printf("NEWLIB_SELFTEST: FAIL trunc-hole\n"); return 1; }
        close(fd);

        unlink(b);
        printf("fs rename/O_TRUNC OK\n");
    }

    printf("NEWLIB_SELFTEST: PASS\n");
    return 0;
}
