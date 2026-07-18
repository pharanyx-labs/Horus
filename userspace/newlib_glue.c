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
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "../include/posix.h"
#include "../include/syscall.h"
#include "../include/dirent.h"

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
    st->st_uid     = (uid_t)ps->uid;
    st->st_gid     = (gid_t)ps->gid;
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

/* ---- directory streams (opendir/readdir/closedir) --------------------
 * newlib ships no dirent implementation for this port (its <sys/dirent.h> is
 * the "#error not supported" stub), so we provide the whole API here over the
 * fs_server's FS_OP_READDIR (via posix_diropen / posix_readdir). A small static
 * pool avoids depending on malloc from inside the glue; DIR is opaque to
 * callers (declared in include/dirent.h). */
#define HORUS_NDIRS 8

struct __horus_dir {
    int           inuse;
    uint32_t      ino;      /* directory inode */
    uint32_t      index;    /* next entry to read */
    struct dirent ent;      /* storage returned by readdir() */
};

static struct __horus_dir g_dirs[HORUS_NDIRS];

DIR *opendir(const char *path) {
    posix_init();
    if (!path) { errno = EFAULT; return (DIR *)0; }

    uint32_t ino;
    int r = posix_diropen(path, &ino);
    if (r == -2) { errno = ENOTDIR; return (DIR *)0; }
    if (r < 0)   { errno = ENOENT;  return (DIR *)0; }

    for (int i = 0; i < HORUS_NDIRS; i++) {
        if (!g_dirs[i].inuse) {
            g_dirs[i].inuse = 1;
            g_dirs[i].ino   = ino;
            g_dirs[i].index = 0;
            return (DIR *)&g_dirs[i];
        }
    }
    errno = EMFILE;             /* directory-stream pool exhausted */
    return (DIR *)0;
}

struct dirent *readdir(DIR *dirp) {
    posix_init();
    struct __horus_dir *d = (struct __horus_dir *)dirp;
    if (!d || !d->inuse) { errno = EBADF; return (struct dirent *)0; }

    char     name[32];
    uint32_t eino, etype;
    if (posix_readdir(d->ino, d->index, name, &eino, &etype) != 1)
        return (struct dirent *)0;   /* end of directory (errno unchanged) */

    d->index++;
    d->ent.d_ino  = eino;
    d->ent.d_type = (etype == 2 /* FS_TYPE_DIR */) ? DT_DIR : DT_REG;
    size_t i = 0;
    for (; name[i] && i < sizeof(d->ent.d_name) - 1; i++) d->ent.d_name[i] = name[i];
    d->ent.d_name[i] = '\0';
    return &d->ent;
}

void rewinddir(DIR *dirp) {
    struct __horus_dir *d = (struct __horus_dir *)dirp;
    if (d && d->inuse) d->index = 0;
}

int closedir(DIR *dirp) {
    struct __horus_dir *d = (struct __horus_dir *)dirp;
    if (!d || !d->inuse) { errno = EBADF; return -1; }
    d->inuse = 0;
    return 0;
}

/* ---- working directory ------------------------------------------------ */

int chdir(const char *path) {
    posix_init();
    if (!path) { errno = EFAULT; return -1; }
    if (posix_chdir(path) < 0) { errno = ENOENT; return -1; }  /* missing / not a dir */
    return 0;
}

char *getcwd(char *buf, size_t size) {
    posix_init();
    if (!buf || size == 0) { errno = EINVAL; return (char *)0; }
    if (posix_getcwd(buf, (uint32_t)size) < 0) { errno = ERANGE; return (char *)0; }
    return buf;
}

int mkdir(const char *path, mode_t mode) {
    posix_init();
    if (!path) { errno = EFAULT; return -1; }
    int rc = posix_mkdir(path, (int)mode);
    if (rc == 0) return 0;
    switch (rc) {
        case SYS_ERR_PERM:  errno = EACCES; break;   /* no write on parent dir */
        case SYS_ERR_NOENT: errno = ENOENT; break;   /* bad path / missing parent */
        case SYS_ERR_INVAL: errno = EEXIST; break;   /* name exists / bad name */
        default:            errno = EIO;    break;   /* transport / other */
    }
    return -1;
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

/* ---- process control, fcntl, environment, and remaining stubs --------- */

/* kill(2) — deliver signal `sig` to task `pid`, wired onto SYS_SIGNAL.
 *
 * The authority is the capability model's, not POSIX's ambient one. SYS_SIGNAL
 * requires the caller to hold a CAP_TCB for the target — the per-child cap every
 * spawner receives — or CAP_USER admin, and signalling yourself is always
 * allowed. So kill() reaches your own descendants and yourself; a pid you have
 * no capability for is EPERM, never delivered. This is the "descendants-only"
 * answer to the pid->capability question: no ambient pid namespace is exposed,
 * so there is nothing to broker.
 *
 * Signal numbers already agree with newlib's <sys/signal.h> for the set that
 * matters (SIGKILL=9, SIGSEGV=11, SIGTERM=15, SIGILL=4), so `sig` passes through
 * unchanged; SIGKILL is uncatchable and always terminates. The null signal
 * (sig 0) is POSIX's existence/permission probe — Horus has no syscall that
 * checks reachability without delivering, so it is a documented best-effort
 * success rather than a fabricated answer about one pid. */
int kill(int pid, int sig) {
    if (sig < 0 || sig > SIG_MAX) { errno = EINVAL; return -1; }
    if (sig == 0) return 0;                       /* null signal: no probe syscall */
    int rc = sys_send_signal(pid, (uint32_t)sig);
    if (rc == 0) return 0;
    switch (rc) {
        case SYS_ERR_PERM:  errno = EPERM; break; /* no CAP_TCB for the target */
        case SYS_ERR_INVAL: errno = ESRCH; break; /* no such task (sig pre-checked) */
        default:            errno = EIO;   break;
    }
    return -1;
}

/* fcntl(2) — only the flag-word commands are meaningful on Horus's fd layer,
 * which has no O_NONBLOCK, close-on-exec, or advisory-lock machinery. The fd is
 * validated (EBADF otherwise); F_GETFL/F_GETFD report no flags set and their
 * setters accept-and-ignore, which keeps the common get-modify-set idiom
 * harmless. Any other command is EINVAL rather than a silent success, so a
 * caller that actually depends on fcntl behaviour finds out instead of being
 * lied to. */
int fcntl(int fd, int cmd, ...) {
    posix_init();
    posix_stat_t st;
    if (posix_fstat(fd, &st) < 0) { errno = EBADF; return -1; }
    switch (cmd) {
        case F_GETFL:
        case F_SETFL:
        case F_GETFD:
        case F_SETFD:
            return 0;
        default:
            errno = EINVAL;
            return -1;
    }
}

/* environ — Horus passes no environment to a task, so this is a valid but empty
 * vector (just the NULL terminator). newlib's getenv()/setenv() in libc.a walk
 * this global; providing the symbol is what lets them link and return "not
 * found" rather than dereference a null environ. */
static char *__horus_environ[1] = { NULL };
char **environ = __horus_environ;

int link(const char *old, const char *new) {
    (void)old; (void)new;
    errno = ENOSYS;
    return -1;
}

/* tmpfile(3) — not implementable on the current object store. newlib's tmpfile
 * opens a file under P_tmpdir and immediately unlink()s it, relying on Unix
 * "unlinked-but-open" semantics: the inode survives, reachable through the open
 * fd, until the last close. Horus's fs_server frees an inode and its data blocks
 * the moment its link count reaches zero (FS_OP_DELETE -> sys_fs_inode_free),
 * with no open-fd refcount, so a write after that unlink would hit a freed inode.
 * This needs the same open-inode refcount link() is blocked on (ROADMAP Phase 4),
 * so fail cleanly here rather than ship libc's version and hand back a silently
 * broken stream. mkstemp(), which returns a *named* fd and never unlinks while
 * open, works and is the portable substitute. */
FILE *tmpfile(void) {
    errno = ENOSYS;
    return NULL;
}

int unlink(const char *path) {
    posix_init();
    if (!path) { errno = EFAULT; return -1; }
    int rc = posix_unlink(path);
    if (rc == 0) return 0;
    switch (rc) {
        case SYS_ERR_PERM:  errno = EACCES;  break;  /* no write on parent dir */
        case SYS_ERR_NOENT: errno = ENOENT;  break;  /* no such entry */
        case SYS_ERR_INVAL: errno = ENOTEMPTY; break; /* non-empty directory */
        default:            errno = EIO;     break;  /* transport / other */
    }
    return -1;
}

/* rename(2). We define the non-underscore name directly: it satisfies the
 * reference so newlib's default renamer.o (which would try link()+unlink(), and
 * link() is ENOSYS here) is never pulled from libc.a. */
int rename(const char *oldpath, const char *newpath) {
    posix_init();
    if (!oldpath || !newpath) { errno = EFAULT; return -1; }
    int rc = posix_rename(oldpath, newpath);
    if (rc == 0) return 0;
    switch (rc) {
        case SYS_ERR_PERM:  errno = EACCES; break;   /* no write on a parent dir */
        case SYS_ERR_NOENT: errno = ENOENT; break;   /* source missing / bad path */
        case SYS_ERR_INVAL: errno = EINVAL; break;   /* bad name / illegal dir move */
        default:            errno = EIO;    break;   /* transport / other */
    }
    return -1;
}

int ftruncate(int fd, off_t length) {
    posix_init();
    if (length < 0) { errno = EINVAL; return -1; }
    if (posix_ftruncate(fd, (uint32_t)length) < 0) { errno = EINVAL; return -1; }
    return 0;
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
