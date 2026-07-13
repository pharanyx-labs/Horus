#ifndef HORUS_POSIX_H
#define HORUS_POSIX_H

#include <stdint.h>
#include <stddef.h>

/* ---- open(2) flags ----
 * These MUST match the newlib <fcntl.h> values, because posix.c is the fd layer
 * *for* newlib: posix.c is compiled with -I include (not the newlib headers) and
 * so sees these fallbacks, while its newlib callers (open() in newlib_glue.c,
 * and application code) are compiled against newlib's <fcntl.h>. If the two
 * disagree, a caller's O_CREAT arrives as some other bit here (newlib O_CREAT
 * 0x200 == a stale O_TRUNC), so the flag is silently lost. Values below are
 * newlib's sys/_default_fcntl.h. The #ifndef lets newlib's header win when it is
 * included first (belt-and-braces — the values are identical either way). */
#ifndef O_RDONLY
#define O_RDONLY   0x0000
#define O_WRONLY   0x0001
#define O_RDWR     0x0002
#define O_ACCMODE  0x0003
#define O_APPEND   0x0008
#define O_CREAT    0x0200
#define O_TRUNC    0x0400
#define O_EXCL     0x0800
#endif

/* ---- lseek(2) whence ---- */
#ifndef SEEK_SET
#define SEEK_SET   0
#define SEEK_CUR   1
#define SEEK_END   2
#endif

/* ---- stat mode bits (skipped if newlib's sys/stat.h already defined them) */
#ifndef S_IFMT
#define S_IFMT     0170000u
#define S_IFREG    0100000u
#define S_IFDIR    0040000u
#define S_IFCHR    0020000u
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_IRWXU  0700u
#define S_IRUSR  0400u
#define S_IWUSR  0200u
#define S_IXUSR  0100u
#define S_IRGRP  0040u
#define S_IWGRP  0020u
#define S_IROTH  0004u
#endif /* S_IFMT */

/* ---- per-file stat info returned by posix_fstat / posix_stat ----
 * Uses unambiguous fixed-width types so newlib_glue.c can adapt to
 * whatever struct stat layout the linked newlib was built with.      */
typedef struct {
    uint32_t ino;
    uint32_t mode;   /* S_IFREG / S_IFDIR / S_IFCHR | permission bits */
    uint32_t size;
    uint32_t blksize;
    uint32_t blocks;
    uint32_t uid;    /* owning user  (0 for console fds) */
    uint32_t gid;    /* owning group (0 for console fds) */
} posix_stat_t;

/* ---- fd table ---- */
#define POSIX_MAX_FDS  32   /* max open files per process */

/* Call once before any posix_* (idempotent after first call). */
void posix_init(void);

int  posix_open  (const char *path, int flags, int mode);
int  posix_read  (int fd, void *buf, size_t len);
int  posix_write (int fd, const void *buf, size_t len);
int  posix_close (int fd);
/* Returns new offset on success, -1 on error. */
int  posix_lseek (int fd, int32_t offset, int whence);
int  posix_fstat (int fd, posix_stat_t *st);
int  posix_stat  (const char *path, posix_stat_t *st);
/* Remove a directory entry. Returns 0 on success, or a negative SYS_ERR_*
 * (the fs_server enforces write permission on the parent directory). */
int  posix_unlink(const char *path);
/* Rename oldpath -> newpath (replacing an existing target file). Returns 0 or a
 * negative SYS_ERR_* (the server enforces write on both parent directories). */
int  posix_rename(const char *oldpath, const char *newpath);
/* Truncate the file open on `fd` to `length` bytes. Returns 0 or a negative
 * SYS_ERR_*. */
int  posix_ftruncate(int fd, uint32_t length);
int  posix_isatty(int fd);

#endif /* HORUS_POSIX_H */
