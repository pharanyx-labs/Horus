/*
 * Minimal <sys/mman.h> for the TCC port. Horus's newlib build ships no
 * <sys/mman.h>; TCC references the mmap family only on the excluded in-process
 * `-run` path (tccrun.c is not built), so these are prototypes for the
 * fail-closed stubs in horus_glue.c, present purely so the vendored sources
 * that `#include <sys/mman.h>` compile unmodified.
 */
#ifndef _HORUS_TCC_SYS_MMAN_H
#define _HORUS_TCC_SYS_MMAN_H

#include <stddef.h>

#define PROT_NONE   0x0
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#define MAP_ANON    0x20
#define MAP_ANONYMOUS MAP_ANON
#define MAP_FAILED  ((void *)-1)

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int   munmap(void *addr, size_t len);
int   mprotect(void *addr, size_t len, int prot);

#endif /* _HORUS_TCC_SYS_MMAN_H */
