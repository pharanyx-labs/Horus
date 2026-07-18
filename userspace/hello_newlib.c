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
#include <signal.h>
#include <sys/stat.h>
#include <dirent.h>
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

    /* --- O_APPEND ---------------------------------------------------------
     * O_APPEND was previously accepted by open() and then ignored by write(),
     * so an "append" silently overwrote the file from byte 0. The flag now
     * sends FS_OP_APPEND and the server places the write at the end. */
    {
        const char *path = "/appendme";
        char ab[16];

        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd < 0 || write(fd, "AAA", 3) != 3) { printf("NEWLIB_SELFTEST: FAIL ap-setup\n"); return 1; }
        close(fd);

        /* The regression: this must extend the file, not overwrite it. */
        fd = open(path, O_WRONLY | O_APPEND);
        if (fd < 0)                   { printf("NEWLIB_SELFTEST: FAIL ap-open\n");  return 1; }
        if (write(fd, "BBB", 3) != 3) { printf("NEWLIB_SELFTEST: FAIL ap-write\n"); return 1; }
        close(fd);

        fd = open(path, O_RDONLY);
        if (fd < 0 || read(fd, ab, sizeof ab) != 6 || memcmp(ab, "AAABBB", 6) != 0) {
            printf("NEWLIB_SELFTEST: FAIL ap-content\n"); return 1;
        }
        close(fd);

        /* O_APPEND must beat the file position: seeking to 0 and writing still
         * lands at the end. This is what separates a real append from a
         * client-side "seek to the end, then write". */
        fd = open(path, O_WRONLY | O_APPEND);
        if (fd < 0 || lseek(fd, 0, SEEK_SET) != 0) { printf("NEWLIB_SELFTEST: FAIL ap-seek\n");   return 1; }
        if (write(fd, "C", 1) != 1)                { printf("NEWLIB_SELFTEST: FAIL ap-write2\n"); return 1; }
        close(fd);

        fd = open(path, O_RDONLY);
        if (fd < 0 || read(fd, ab, sizeof ab) != 7 || memcmp(ab, "AAABBBC", 7) != 0) {
            printf("NEWLIB_SELFTEST: FAIL ap-seek-content\n"); return 1;
        }
        close(fd);

        /* An append longer than one FS_IO_MAX chunk still concatenates. */
        fd = open(path, O_WRONLY | O_APPEND);
        char big[200];
        memset(big, 'Z', sizeof big);
        if (fd < 0 || write(fd, big, sizeof big) != (int)sizeof big) {
            printf("NEWLIB_SELFTEST: FAIL ap-big\n"); return 1;
        }
        close(fd);
        struct stat asb;
        if (stat(path, &asb) != 0 || asb.st_size != 7 + (off_t)sizeof big) {
            printf("NEWLIB_SELFTEST: FAIL ap-big-size\n"); return 1;
        }

        unlink(path);
        printf("fs O_APPEND OK\n");
    }

    /* --- directory enumeration: opendir/readdir/closedir over FS_OP_READDIR ---
     * newlib provides no dirent backend for this port; the whole API is our own
     * (include/dirent.h + newlib_glue.c) over the fs_server. Create two files in
     * the root, enumerate the directory, and assert both turn up. */
    {
        int fd = open("/dent_a", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) { printf("NEWLIB_SELFTEST: FAIL dir-setup-a\n"); return 1; }
        close(fd);
        fd = open("/dent_b", O_CREAT | O_WRONLY, 0644);
        if (fd < 0) { printf("NEWLIB_SELFTEST: FAIL dir-setup-b\n"); return 1; }
        close(fd);

        DIR *dp = opendir("/");
        if (!dp) { printf("NEWLIB_SELFTEST: FAIL opendir\n"); return 1; }
        int saw_a = 0, saw_b = 0, count = 0;
        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            count++;
            if (strcmp(de->d_name, "dent_a") == 0) saw_a = 1;
            if (strcmp(de->d_name, "dent_b") == 0) saw_b = 1;
        }
        closedir(dp);
        if (!saw_a || !saw_b) { printf("NEWLIB_SELFTEST: FAIL readdir-missing\n"); return 1; }
        if (count < 2)        { printf("NEWLIB_SELFTEST: FAIL readdir-count\n");   return 1; }

        /* opendir on a regular file → ENOTDIR; on a missing path → ENOENT. */
        errno = 0;
        if (opendir("/dent_a") != NULL || errno != ENOTDIR) {
            printf("NEWLIB_SELFTEST: FAIL opendir-notdir\n"); return 1;
        }
        errno = 0;
        if (opendir("/nope_dir") != NULL || errno != ENOENT) {
            printf("NEWLIB_SELFTEST: FAIL opendir-noent\n"); return 1;
        }

        unlink("/dent_a");
        unlink("/dent_b");
        printf("fs opendir/readdir OK\n");
    }

    /* --- working directory: mkdir/chdir/getcwd + relative resolution -------
     * mkdir/chdir/getcwd are all new to this port. Build /wd_a/wd_b, cd into it,
     * confirm getcwd, confirm a relative create lands under the cwd, then walk
     * back out with "..". */
    {
        char cwd[64];

        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/") != 0) {
            printf("NEWLIB_SELFTEST: FAIL getcwd-root\n"); return 1;
        }
        if (mkdir("/wd_a", 0755) != 0)      { printf("NEWLIB_SELFTEST: FAIL mkdir-a\n"); return 1; }
        if (mkdir("/wd_a/wd_b", 0755) != 0) { printf("NEWLIB_SELFTEST: FAIL mkdir-b\n"); return 1; }

        if (chdir("/wd_a/wd_b") != 0) { printf("NEWLIB_SELFTEST: FAIL chdir-abs\n"); return 1; }
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/wd_a/wd_b") != 0) {
            printf("NEWLIB_SELFTEST: FAIL getcwd-abs\n"); return 1;
        }

        /* A relative create resolves under the cwd. */
        int fd = open("rel", O_CREAT | O_WRONLY, 0644);
        if (fd < 0 || write(fd, "x", 1) != 1) { printf("NEWLIB_SELFTEST: FAIL rel-create\n"); return 1; }
        close(fd);
        struct stat rsb;
        if (stat("/wd_a/wd_b/rel", &rsb) != 0 || rsb.st_size != 1) {
            printf("NEWLIB_SELFTEST: FAIL rel-resolve\n"); return 1;
        }

        /* ".." climbs one level. */
        if (chdir("..") != 0) { printf("NEWLIB_SELFTEST: FAIL chdir-dotdot\n"); return 1; }
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/wd_a") != 0) {
            printf("NEWLIB_SELFTEST: FAIL getcwd-dotdot\n"); return 1;
        }

        /* chdir to a missing path fails and leaves the cwd unchanged. */
        if (chdir("/wd_a/nope") == 0) { printf("NEWLIB_SELFTEST: FAIL chdir-missing\n"); return 1; }
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, "/wd_a") != 0) {
            printf("NEWLIB_SELFTEST: FAIL chdir-missing-cwd\n"); return 1;
        }

        /* Tidy up (leaf first: DELETE refuses a non-empty directory). */
        chdir("/");
        unlink("/wd_a/wd_b/rel");
        unlink("/wd_a/wd_b");
        unlink("/wd_a");
        printf("fs cwd mkdir/chdir/getcwd OK\n");
    }

    /* --- environment, fcntl, and kill: the last libc-surface items ---------
     * environ is an empty vector (Horus passes no environment) so getenv finds
     * nothing; fcntl validates the fd and no-ops the flag words; kill() forwards
     * to SYS_SIGNAL under the capability model — a pid we hold no CAP_TCB for (or
     * that does not exist) is refused rather than delivered. */
    {
        extern char **environ;
        if (environ == NULL || environ[0] != NULL) {
            printf("NEWLIB_SELFTEST: FAIL environ-not-empty\n"); return 1;
        }
        if (getenv("PATH") != NULL) {
            printf("NEWLIB_SELFTEST: FAIL getenv-nonempty\n"); return 1;
        }

        /* A valid fd's flag words no-op to 0; a bad fd is EBADF; an unsupported
         * command is EINVAL rather than a silent success. */
        if (fcntl(1, F_GETFL) != 0) {
            printf("NEWLIB_SELFTEST: FAIL fcntl-getfl\n"); return 1;
        }
        errno = 0;
        if (fcntl(-1, F_GETFL) != -1 || errno != EBADF) {
            printf("NEWLIB_SELFTEST: FAIL fcntl-badfd\n"); return 1;
        }
        errno = 0;
        if (fcntl(1, F_DUPFD, 10) != -1 || errno != EINVAL) {
            printf("NEWLIB_SELFTEST: FAIL fcntl-badcmd\n"); return 1;
        }

        /* The null signal is a best-effort success; a signal to a task we cannot
         * name (a pid far out of range) is refused with ESRCH, never delivered. */
        if (kill(getpid(), 0) != 0) {
            printf("NEWLIB_SELFTEST: FAIL kill-null\n"); return 1;
        }
        errno = 0;
        if (kill(1 << 20, SIGTERM) != -1 || errno != ESRCH) {
            printf("NEWLIB_SELFTEST: FAIL kill-nosuch\n"); return 1;
        }
        printf("libc environ/fcntl/kill OK\n");
    }

    /* --- temp files: mkstemp works; tmpfile is deferred --------------------
     * mkstemp creates and opens a uniquely-named file we can round-trip; it
     * never unlinks while open, so it needs nothing the object store lacks.
     * tmpfile does need unlinked-but-open inodes (blocked on store refcounts,
     * like link()), so it fails cleanly with ENOSYS rather than returning a
     * silently broken stream. */
    {
        char tmpl[] = "/tmp_mkstempXXXXXX";
        int tfd = mkstemp(tmpl);
        if (tfd < 0) { printf("NEWLIB_SELFTEST: FAIL mkstemp-open\n"); return 1; }
        const char *msg = "tmp!";
        if (write(tfd, msg, 4) != 4) {
            printf("NEWLIB_SELFTEST: FAIL mkstemp-write\n"); return 1;
        }
        if (lseek(tfd, 0, SEEK_SET) != 0) {
            printf("NEWLIB_SELFTEST: FAIL mkstemp-seek\n"); return 1;
        }
        char rb[4] = { 0 };
        if (read(tfd, rb, 4) != 4 || memcmp(rb, msg, 4) != 0) {
            printf("NEWLIB_SELFTEST: FAIL mkstemp-readback\n"); return 1;
        }
        close(tfd);
        unlink(tmpl);                     /* mkstemp leaves the name behind */

        errno = 0;
        if (tmpfile() != NULL || errno != ENOSYS) {
            printf("NEWLIB_SELFTEST: FAIL tmpfile-not-enosys\n"); return 1;
        }
        printf("libc mkstemp OK, tmpfile deferred (ENOSYS)\n");
    }

    printf("NEWLIB_SELFTEST: PASS\n");
    return 0;
}
