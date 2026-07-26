/*
 * Horus port glue for TCC.
 *
 * TCC is vendored byte-for-byte from the 0.9.27 tarball (see ../README.md); this
 * file is Horus code (MIT) supplying the handful of symbols TCC references that
 * neither newlib nor Horus's POSIX glue provides.
 *
 * What is NOT here, on purpose:
 *   - file I/O (open/read/write/close/lseek/fstat/stat/unlink/...) comes from
 *     userspace/newlib_glue*.c over the Horus syscall layer;
 *   - getcwd comes from userspace/posix.c (a real per-process cwd);
 *   - malloc/free come from userspace/malloc.o + newlib.
 *
 * The stubs below back paths Horus deliberately does not implement. TCC's
 * assembler and linker are *integrated* (no external `as`/`ld`), so execvp is
 * never taken; the in-process `-run` JIT is excluded (tccrun.c is not built),
 * so tcc_run / dlopen / mmap are unreachable at runtime. They exist only to
 * satisfy the linker and fail closed if a code path ever reaches them.
 */
#include <stddef.h>
#include <sys/time.h>

/* Timing: TCC uses this only for `-vv` build-time reporting. */
int gettimeofday(struct timeval *tv, void *tz)
{
    (void)tz;
    if (tv) { tv->tv_sec = 0; tv->tv_usec = 0; }
    return 0;
}

/* No external assembler/linker to exec — TCC's are built in. */
int execvp(const char *file, char *const argv[])
{
    (void)file; (void)argv;
    return -1;
}

/* No dynamic loading on Horus (W^X, no runtime relocation of foreign objects). */
void *dlopen(const char *filename, int flag) { (void)filename; (void)flag; return NULL; }
void *dlsym(void *handle, const char *symbol) { (void)handle; (void)symbol; return NULL; }
int   dlclose(void *handle) { (void)handle; return -1; }

/* No mmap/mprotect: the `-run` JIT (which needs RWX pages) is excluded. */
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off)
{
    (void)addr; (void)len; (void)prot; (void)flags; (void)fd; (void)off;
    return (void *)-1; /* MAP_FAILED */
}
int munmap(void *addr, size_t len) { (void)addr; (void)len; return -1; }
int mprotect(void *addr, size_t len, int prot) { (void)addr; (void)len; (void)prot; return -1; }

/* Excluded -run / backtrace entry points (tccrun.c is not built). Called only
 * by `tcc -run`, which Horus does not support; compile-to-file is the model. */
int  tcc_run(void *s, int argc, char **argv) { (void)s; (void)argc; (void)argv; return -1; }
void tcc_run_free(void *s) { (void)s; }
void tcc_set_num_callers(int n) { (void)n; }
int  tcc_backtrace(const char *fmt, ...) { (void)fmt; return 0; }
