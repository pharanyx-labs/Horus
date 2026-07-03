/* userspace/newlib_glue.c — Horus OS interface for newlib.
 *
 * Compiled with -I newlib/include so types come from the real newlib headers;
 * this guarantees that struct stat, off_t, etc. match whatever libc.a was
 * built against — no manual ABI matching needed.
 *
 * In newlib 4.x the reentrant wrappers (_write_r, _read_r, …) call the
 * plain non-underscore names (write, read, …).  We provide those here and
 * route them through posix.c (fd table + fs_server IPC) or direct syscalls.
 * _exit() keeps its underscore prefix — exit() in libc calls _exit() after
 * running atexit handlers.
 *
 * Security:
 *  - errno is set on every error path (newlib reads it for strerror/perror).
 *  - No user pointer is dereferenced here; all dereferences are in posix.c or
 *    the kernel's copy_from_user / copy_to_user.
 *  - _exit() calls sys_exit() unconditionally — no atexit fallback that
 *    could be hijacked via a stale function pointer.
 */

/* sys/stat.h must come before reent.h so that the #define stat64 stat macro
 * fires before reent.h declares _fstat64_r/_stat64_r with struct stat64 *. */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/times.h>
#include <reent.h>
#include <sys/errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#include "../include/posix.h"
#include "../include/syscall.h"

/* errno is a macro defined in <sys/errno.h> as (*__errno()).
 * newlib's libc.a provides __errno() backed by the reent struct; we must not
 * duplicate it.  Just use the errno macro directly in the stubs below. */

/* ---- helpers ---------------------------------------------------------- */

static void _fill_stat(struct stat *st, const posix_stat_t *ps) {
    char *p = (char *)st;
    for (size_t i = 0; i < sizeof(*st); i++) p[i] = 0;

    st->st_ino     = (ino_t)ps->ino;
    st->st_mode    = (mode_t)ps->mode;
    st->st_nlink   = 1;
    st->st_size    = (off_t)ps->size;
    st->st_blksize = (blksize_t)ps->blksize;
    st->st_blocks  = (blkcnt_t)ps->blocks;
}

/* ---- OS syscall stubs called by newlib reentrant wrappers ------------- */

int write(int fd, const void *buf, size_t len) {
    posix_init();
    if ((ssize_t)len < 0) { errno = EINVAL; return -1; }
    int r = posix_write(fd, buf, len);
    if (r < 0) { errno = EIO; return -1; }
    return r;
}

int read(int fd, void *buf, size_t len) {
    posix_init();
    if ((ssize_t)len < 0) { errno = EINVAL; return -1; }
    int r = posix_read(fd, buf, len);
    if (r < 0) { errno = EIO; return -1; }
    return r;
}

int open(const char *path, int flags, ...) {
    posix_init();
    int fd = posix_open(path, flags, 0);
    if (fd < 0) { errno = ENOENT; return -1; }
    return fd;
}

int close(int fd) {
    posix_init();
    if (fd < 3) { errno = EBADF; return -1; }
    if (posix_close(fd) < 0) { errno = EBADF; return -1; }
    return 0;
}

off_t lseek(int fd, off_t offset, int whence) {
    posix_init();
    int r = posix_lseek(fd, (int32_t)offset, whence);
    if (r < 0) { errno = EINVAL; return (off_t)-1; }
    return (off_t)r;
}

int fstat(int fd, struct stat *st) {
    posix_init();
    if (!st) { errno = EFAULT; return -1; }
    posix_stat_t ps;
    if (posix_fstat(fd, &ps) < 0) { errno = EBADF; return -1; }
    _fill_stat(st, &ps);
    return 0;
}

int isatty(int fd) {
    posix_init();
    return posix_isatty(fd);
}

int stat(const char *path, struct stat *st) {
    posix_init();
    if (!st || !path) { errno = EFAULT; return -1; }
    posix_stat_t ps;
    if (posix_stat(path, &ps) < 0) { errno = ENOENT; return -1; }
    _fill_stat(st, &ps);
    return 0;
}

void _exit(int code) {
    (void)code;
    sys_exit();
    for (;;) { }
}

int getpid(void) {
    return sys_getpid();
}

void *sbrk(ptrdiff_t incr) {
    void *p = sys_sbrk((intptr_t)incr);
    if (p == (void *)(intptr_t)-1) {
        errno = ENOMEM;
        return (void *)-1;
    }
    return p;
}

/* ---- stubs for syscalls Horus doesn't implement yet ------------------- */

int kill(int pid, int sig) {
    (void)pid; (void)sig;
    errno = EINVAL;
    return -1;
}

int link(const char *old, const char *new) {
    (void)old; (void)new;
    errno = ENOSYS;
    return -1;
}

int unlink(const char *path) {
    (void)path;
    errno = ENOSYS;
    return -1;
}

clock_t times(struct tms *buf) {
    if (buf) {
        buf->tms_utime  = 0;
        buf->tms_stime  = 0;
        buf->tms_cutime = 0;
        buf->tms_cstime = 0;
    }
    return (clock_t)-1;
}
