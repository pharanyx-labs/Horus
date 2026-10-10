/* The child half of smoke-fs-cap-posix's grant check (FSCAPPOSIX_SELFTEST).
 *
 * fscapposix spawns this suspended and hands it its filesystem with
 * hvfs_grant_fs (design decision 10): a copy of a WRITABLE root narrowed to
 * read and lookup, and the directory /kid below it as its working directory.
 * This is an ordinary newlib program with the ordinary crt0, so posix_init sees
 * the granted root and walks by capability, which is the path a real child of
 * the shell takes.
 *
 * It reports through its parent's marker, FSCAPPOSIX: FAIL child-<name>, so the
 * gate fails on it; the parent waits for it before printing PASS. `child-wrote`
 * is the check the control arm HVFS_GRANT_UNNARROWED=1 must turn red: the
 * parent's own writable capability granted as it stands. */

#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "../include/syscall.h"
#include "../include/libhorus.h"

static void fail(const char *what)
{
    kput_marker("FSCAPPOSIX: FAIL child-", what);
    sys_exit();
}

int main(void)
{
    char buf[8];

    /* It can read, relative to the granted working directory and absolutely. */
    memset(buf, 0, sizeof(buf));
    int fd = open("k", O_RDONLY);
    if (fd < 0 || read(fd, buf, 3) != 3 || memcmp(buf, "kid", 3) != 0) fail("cannot-read-cwd");
    close(fd);
    fd = open("/kid/k", O_RDONLY);
    if (fd < 0) fail("cannot-read-root");
    close(fd);

    /* And it can change nothing, anywhere. */
    fd = open("k", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "X", 1) >= 0) fail("wrote");
        close(fd);
    }
    if (open("/kid/new", O_CREAT | O_WRONLY, 0644) >= 0) fail("created");
    if (unlink("/kid/k") == 0) fail("unlinked");

    /* It was never told the working directory's name. */
    if (getcwd(buf, sizeof(buf)) != 0) fail("named-its-cwd");

    kput_marker("FSCAPPOSIX: ", "child held to read-only");
    sys_exit();
    return 0;
}
