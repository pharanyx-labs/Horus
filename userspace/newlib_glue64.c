/* userspace/newlib_glue64.c — 64-bit reentrant stubs for newlib on Horus.
 *
 * On 32-bit Horus, struct stat64 == struct stat and off64_t == off_t in
 * practice.  We deliberately do NOT include <reent.h> here to avoid the
 * conflicting forward declaration of struct stat64 that reent.h emits for
 * non-Cygwin targets.  We instead forward-declare _reent and define the
 * #define ourselves so the struct tags line up with the caller's ABI.
 *
 * These stubs satisfy the references from newlib's stdio64.o (_lseek64_r)
 * and from any future 64-bit fstat64/stat64/open64 callers.
 */

#include <sys/stat.h>    /* struct stat */
#include <sys/types.h>
#include <fcntl.h>       /* open() */
#include <unistd.h>
#include <sys/errno.h>
#include <stddef.h>

/* Make struct stat64 an alias for struct stat (32-bit Horus). */
#define stat64 stat
typedef long long _off64_t;

/* Forward-declare _reent rather than pulling in all of <reent.h>. */
struct _reent;

_off64_t _lseek64_r(struct _reent *ptr, int fd, _off64_t offset, int whence) {
    (void)ptr;
    return (_off64_t)lseek(fd, (off_t)offset, whence);
}

int _fstat64_r(struct _reent *ptr, int fd, struct stat64 *st) {
    (void)ptr;
    return fstat(fd, st);
}

int _stat64_r(struct _reent *ptr, const char *path, struct stat64 *st) {
    (void)ptr;
    return stat(path, st);
}

int _open64_r(struct _reent *ptr, const char *path, int flags, int mode) {
    (void)ptr; (void)mode;
    return open(path, flags);
}
