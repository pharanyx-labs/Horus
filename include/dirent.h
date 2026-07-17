#ifndef HORUS_DIRENT_H
#define HORUS_DIRENT_H

/* Minimal <dirent.h> for the Horus newlib port.
 *
 * This newlib configuration ships NO dirent support: its own <sys/dirent.h> is
 * the stub that does `#error "<dirent.h> not supported"`, and libc.a provides no
 * opendir/readdir/closedir. We supply the directory API ourselves, backed by the
 * userspace fs_server's FS_OP_READDIR op (see posix_diropen / posix_readdir in
 * userspace/posix.c and the opendir/readdir/closedir stubs in newlib_glue.c).
 *
 * Userspace objects are compiled with `-I include` BEFORE `-I <newlib inc>`
 * (see NEWLIB_CFLAGS in the Makefile), so a program's `#include <dirent.h>`
 * resolves to THIS header and never reaches newlib's #error stub. We claim
 * newlib's include guard (_DIRENT_H_) as well, belt-and-braces, so nothing can
 * pull the broken header in behind us.
 */

#include <stdint.h>
#include <stddef.h>

#ifndef _DIRENT_H_
#define _DIRENT_H_
#endif

/* d_type values (subset of the BSD/Linux set we can actually represent). */
#define DT_UNKNOWN  0
#define DT_DIR      4
#define DT_REG      8

/* Entry name field matches the fs_server's on-disk dirent name width
 * (FS_DIRENT_NAME = 24 in include/fs_proto.h); a byte of headroom keeps the
 * NUL. Kept independent of fs_proto.h so this header stays includable by plain
 * libc programs. */
struct dirent {
    uint32_t d_ino;              /* entry inode number */
    uint8_t  d_type;            /* DT_REG / DT_DIR / DT_UNKNOWN */
    char     d_name[32];        /* NUL-terminated file name */
};

/* Opaque directory stream; the concrete struct lives in newlib_glue.c. */
typedef struct __horus_dir DIR;

DIR           *opendir (const char *path);
struct dirent *readdir (DIR *dirp);
int            closedir(DIR *dirp);
void           rewinddir(DIR *dirp);

#endif /* HORUS_DIRENT_H */
