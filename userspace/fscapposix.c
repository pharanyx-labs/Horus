/* Capability-walking POSIX client self-test (FSCAPPOSIX_SELFTEST builds only).
 *
 * The client half of `make smoke-fs-cap-posix`: phase 1b step 2 of
 * docs/design/filesystem.md, through newlib's ordinary calls against the real
 * fs_server. It prints FSCAPPOSIX: PASS <n> checks, or FSCAPPOSIX: FAIL <name>
 * naming the first check that did not hold.
 *
 * THE SET-UP. The kernel harness gives this task one untokened capability to
 * fs_server's endpoint with MINT (SLOT_PLAIN), standing in for init. From it the
 * task mints the root directory's capability twice: READ-ONLY into
 * CAPSLOT_FS_ROOT, which makes posix_init choose the capability path for the
 * whole process, and with every right into SLOT_RW, mounted at /rw. So "/d/f"
 * and "/rw/d/f" are the same file, reached through a read-only and a writable
 * capability.
 *
 * WHAT IT PROVES:
 *   - open, read, write, stat, mkdir, opendir/readdir, chdir/getcwd, rename and
 *     unlink work through capabilities, with no uid path at all (this task never
 *     connects to it);
 *   - through the read-only root nothing can be created, written, removed or
 *     renamed, by any call (`readonly-*`);
 *   - a rename whose two parents are different directories is EXDEV;
 *   - ".." is resolved by the client and stops at the root;
 *   - CLOSING GIVES THE CAPABILITY BACK: 40 opens and closes, more than the 32
 *     slots of the pool, all succeed (`close-kept-capability` is the check the
 *     control arm POSIX_CLOSE_KEEPS_CAP=1 must turn red). A file closed but
 *     still held is authority kept past its use, and the pool running dry is
 *     how it shows;
 *   - A CHILD IS HANDED A NARROWED COPY (decision 10): given this task's
 *     writable root narrowed to read and lookup, fscapchild can read but not
 *     create, write or remove anything (`child-wrote` is the check the control
 *     arm HVFS_GRANT_UNNARROWED=1 must turn red). */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/errno.h>   /* not <errno.h>: -I include finds the kernel's SYS_ERR_* one first */
#include <sys/stat.h>
#include <dirent.h>

#include "../include/syscall.h"
#include "../include/fs_proto.h"
#include "../include/libhorus.h"
#include "../include/posix.h"

#define SLOT_PLAIN 30
#define SLOT_RW    26

static int checks;

static void fail(const char *what)
{
    kput_marker("FSCAPPOSIX: FAIL ", what);
    sys_exit();
}

#define CHECK(cond, name) do { if (!(cond)) fail(name); } while (0)

static int read_all(const char *path, char *buf, int n)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int got = (int)read(fd, buf, (size_t)n);
    close(fd);
    return got;
}

static int test_main(void);
extern void exit(int status);

/* THE ENTRY, in place of crt0's. crt0 runs posix_init before main, and
 * posix_init is where the mode is chosen, so the roots must be in their slots
 * before it: the order a spawner that grants them produces, done here by the
 * task itself because the harness cannot mint a tokened capability into it. */
void _start(void)
{
    uint32_t kern = CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_REVOKE | CAP_RIGHT_MINT;
    if (sys_cap_mint_token(SLOT_RW, SLOT_PLAIN, kern | FS_R_ALL, fs_token(0, 0)) != 0)
        fail("mint-root-rw");
    if (sys_cap_mint_token(CAPSLOT_FS_ROOT, SLOT_PLAIN, kern | FS_R_READ | FS_R_LOOKUP,
                           fs_token(0, 0)) != 0)
        fail("mint-root-readonly");

    /* The server may not be serving yet, and posix_init's mount probe is one
     * stat: a slow server would put the task on the uid path. So wait for a
     * stat through the root to answer first. */
    struct fs_request rq;
    struct fs_response rp;
    int up = 0;
    for (int i = 0; i < 2000 && !up; i++) {
        memset(&rq, 0, sizeof(rq));
        rq.op = FS_OP_STAT;
        if (hvfs_rpc(CAPSLOT_FS_ROOT, &rq, &rp) == 0) up = 1; else sys_yield();
    }
    if (!up) fail("server-never-answered");

    posix_init();
    exit(test_main());
}

static int test_main(void)
{
    {
        struct stat st;
        CHECK(stat("/", &st) == 0 && S_ISDIR(st.st_mode), "stat-root");
    }
    CHECK(hvfs_mount_cap("/rw", SLOT_RW) == 0, "mount-rw");
    checks++;

    /* WRITE THROUGH THE WRITABLE ROOT, READ THROUGH THE READ-ONLY ONE. */
    CHECK(mkdir("/rw/d", 0755) == 0, "mkdir");
    int fd = open("/rw/d/f", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0, "create");
    CHECK(write(fd, "hello", 5) == 5, "write");
    CHECK(close(fd) == 0, "close");
    char buf[16];
    memset(buf, 0, sizeof(buf));
    CHECK(read_all("/d/f", buf, 5) == 5 && memcmp(buf, "hello", 5) == 0, "read-through-readonly");
    {
        struct stat st;
        CHECK(stat("/d/f", &st) == 0 && st.st_size == 5 && S_ISREG(st.st_mode), "stat-file");
    }
    checks++;

    /* NOTHING CHANGES THROUGH THE READ-ONLY ROOT. */
    CHECK(open("/d/g", O_CREAT | O_WRONLY, 0644) < 0, "readonly-created");
    fd = open("/d/f", O_WRONLY);
    if (fd >= 0) {
        CHECK(write(fd, "X", 1) < 0, "readonly-wrote");
        close(fd);
    }
    CHECK(unlink("/d/f") != 0, "readonly-unlinked");
    CHECK(mkdir("/d/e", 0755) != 0, "readonly-mkdir");
    CHECK(rename("/d/f", "/d/f9") != 0, "readonly-renamed");
    memset(buf, 0, sizeof(buf));
    CHECK(read_all("/rw/d/f", buf, 5) == 5 && memcmp(buf, "hello", 5) == 0, "readonly-changed-it");
    checks++;

    /* A DIRECTORY STREAM. */
    {
        DIR *dp = opendir("/d");
        CHECK(dp != 0, "opendir");
        int seen = 0;
        struct dirent *de;
        while ((de = readdir(dp)) != 0) if (strcmp(de->d_name, "f") == 0) seen = 1;
        CHECK(closedir(dp) == 0, "closedir");
        CHECK(seen, "readdir-missed-entry");
    }
    checks++;

    /* THE WORKING DIRECTORY, and ".." resolved here and stopped at the root. */
    CHECK(chdir("/rw/d") == 0, "chdir");
    memset(buf, 0, sizeof(buf));
    CHECK(read_all("f", buf, 5) == 5, "relative-read");
    {
        char cwd[64];
        CHECK(getcwd(cwd, sizeof(cwd)) != 0 && strcmp(cwd, "/rw/d") == 0, "getcwd");
        CHECK(chdir("..") == 0 && getcwd(cwd, sizeof(cwd)) != 0 && strcmp(cwd, "/rw") == 0, "chdir-dotdot");
    }
    memset(buf, 0, sizeof(buf));
    CHECK(read_all("/../../d/f", buf, 5) == 5, "dotdot-above-root");
    checks++;

    /* RENAME: within one directory, and EXDEV across two. */
    CHECK(rename("/rw/d/f", "/rw/d/f2") == 0, "rename");
    CHECK(rename("/rw/d/f2", "/rw/f3") != 0 && errno == EXDEV, "rename-across-dirs");
    checks++;

    /* CLOSING GIVES THE CAPABILITY BACK. */
    for (int i = 0; i < 40; i++) {
        fd = open("/d/f2", O_RDONLY);
        if (fd < 0) fail("close-kept-capability");
        close(fd);
    }
    checks++;

    CHECK(unlink("/rw/d/f2") == 0, "unlink");
    {
        struct stat st;
        CHECK(stat("/d/f2", &st) != 0, "unlinked-still-there");
    }
    checks++;

    /* A CHILD GETS A NARROWED COPY (decision 10). fscapchild is spawned
     * suspended and handed this task's WRITABLE root narrowed to read and
     * lookup, with /kid as its working directory; it reports its own checks
     * (FSCAPPOSIX: FAIL child-*). Its copies descend from the narrowed copies
     * hvfs_grant_fs minted, and those from `rw` and `kid`, so all of them are
     * kept until the child is gone. */
    CHECK(mkdir("/rw/kid", 0755) == 0, "mkdir-kid");
    fd = open("/rw/kid/k", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0 && write(fd, "kid", 3) == 3, "write-kid");
    close(fd);
    {
        struct hvfs_obj rw = { SLOT_RW, 0, 1, 0, 0 };
        struct hvfs_obj kid;
        char last[FS_NAME_MAX];
        CHECK(hvfs_lookup("/rw/kid", &rw, 0, &kid, last) == 0 && kid.cap, "walk-kid");
        int pid = sys_spawn_named("fscapchild");
        CHECK(pid > 0, "spawn-child");
        struct hvfs_grant g;
        CHECK(hvfs_grant_fs(pid, &rw, &kid, FS_R_READ | FS_R_LOOKUP, &g) == 0, "grant-child");
        CHECK(sys_task_resume(pid) == 0, "resume-child");
        while (sys_wait(pid) == SYS_ERR_INTR) { }
        hvfs_grant_release(&g);
        hvfs_release(&kid);
    }
    memset(buf, 0, sizeof(buf));
    CHECK(read_all("/rw/kid/k", buf, 3) == 3 && memcmp(buf, "kid", 3) == 0, "child-changed-it");
    checks++;

    char n[12];
    int v = checks, k = 0;
    char d[12];
    do { d[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    int j = 0;
    while (k) n[j++] = d[--k];
    n[j] = 0;
    char line[32];
    const char *t = " checks";
    unsigned m = 0;
    for (unsigned i = 0; n[i]; i++) line[m++] = n[i];
    for (unsigned i = 0; t[i]; i++) line[m++] = t[i];
    line[m] = 0;
    kput_marker("FSCAPPOSIX: PASS ", line);
    sys_exit();
    return 0;
}
