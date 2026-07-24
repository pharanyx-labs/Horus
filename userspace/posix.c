/* userspace/posix.c — per-process POSIX fd table for Horus.
 *
 * fds 0/1/2 are hardwired to the console (SYS_READ / SYS_WRITE).
 * fds 3+ are regular files routed through the userspace fs_server over IPC
 * using the fs_proto.h protocol (same as fsclient.c / userspace/shell.c).
 *
 * All IPC is blocking via sys_ipc_call().  Large reads/writes that exceed
 * FS_IO_MAX are split into multiple round-trips transparently.
 *
 * Security properties:
 *  - Every fd access validates bounds + type (use-after-close safe).
 *  - Access-mode is enforced: O_RDONLY fds reject writes and vice-versa.
 *  - Path component length is clamped to FS_NAME_MAX-1 (no overrun into IPC buf).
 *  - Traversal depth is limited to prevent excessive IPC call chains.
 *  - Offset arithmetic is checked for uint32_t overflow.
 *  - IPC reply magic is verified before trusting the response.
 *  - O_APPEND is placed by the server at the end of file (FS_OP_APPEND), so an
 *    append cannot land on top of a concurrent writer's data. Note the limit: a
 *    write longer than FS_IO_MAX is split into several appends, each atomic on
 *    its own, so POSIX's atomicity-per-write() holds only up to FS_IO_MAX bytes.
 */

#include "../include/posix.h"
#include "../include/syscall.h"
#include "../include/console_proto.h"
#include "fs_proto.h"

/* ----- internal helpers ----------------------------------------------- */

static void _umemset(void *p, int c, uint32_t n) {
    unsigned char *b = (unsigned char *)p;
    while (n--) *b++ = (unsigned char)c;
}

static void _umemcpy(void *dst, const void *src, uint32_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
}

static uint32_t _ustrlen(const char *s) {
    uint32_t n = 0;
    while (s[n]) n++;
    return n;
}

/* ----- fd table ------------------------------------------------------- */

#define FD_FREE         0u
#define FD_CONSOLE_IN   1u   /* fd 0: console read  */
#define FD_CONSOLE_OUT  2u   /* fd 1/2: console write */
#define FD_FS           3u   /* regular fs_server file */
#define FD_PIPE         4u   /* a pipe end (ino = the CAP_PIPE cspace slot) */

typedef struct {
    uint8_t  type;     /* FD_FREE / FD_CONSOLE_IN / FD_CONSOLE_OUT / FD_FS / FD_PIPE */
    uint8_t  _pad[3];
    int      flags;    /* O_RDONLY / O_WRONLY / O_RDWR | O_APPEND etc. */
    uint32_t ino;      /* fs inode, or (FD_PIPE) the pipe-end cspace slot */
    uint32_t offset;
} fd_entry_t;

static fd_entry_t  g_fdt[POSIX_MAX_FDS];
static int         g_inited       = 0;
static int         g_fs_connected = 0;

/* ----- fd allocation -------------------------------------------------- */

/* Return 1 if the fd is open and of the expected type (or FD_FREE=0 to skip
 * type check).  Always validates bounds. */
static int fd_valid(int fd) {
    if ((unsigned)fd >= POSIX_MAX_FDS) return 0;
    return g_fdt[fd].type != FD_FREE;
}

static int fd_alloc(void) {
    for (int i = 3; i < POSIX_MAX_FDS; i++) {
        if (g_fdt[i].type == FD_FREE)
            return i;
    }
    return -1;   /* EMFILE */
}

static void fd_free(int fd) {
    _umemset(&g_fdt[fd], 0, sizeof(g_fdt[fd]));
}

/* ----- fs_server IPC -------------------------------------------------- */

/* ep slot for the fs_server capability (must be >= 4 per kernel rule). */
#define FSS_CAP_SLOT 20u

static void fs_connect(void) {
    if (g_fs_connected) return;
    /* Mint a badge cap so the kernel knows we're authorised.  Failure is
     * tolerated — the first RPC will fail with a non-magic reply instead. */
    sys_connect_fs_server(FSS_CAP_SLOT, CAP_R_W);
    g_fs_connected = 1;
}

/* Single round-trip to the fs_server.  Returns rp->rc on success, -1 on
 * transport failure (bad magic or sys_ipc_call error). */
static int fss_rpc(struct fs_request *rq, struct fs_response *rp) {
    fs_connect();
    rq->magic = FS_PROTO_MAGIC;
    _umemset(rp, 0, sizeof(*rp));

    int r = sys_ipc_call(FS_EP_REQ, FS_EP_REP,
                         (const void *)rq, (uint32_t)sizeof(*rq),
                         (void *)rp);
    if (r < 0)                        return -1;
    if (rp->magic != FS_PROTO_MAGIC)  return -1;
    return rp->rc;
}

/* ----- current working directory -------------------------------------- */

#define POSIX_PATH_MAX 256

/* The process cwd: its inode (for relative-path resolution) and its canonical
 * absolute path string (for getcwd). Initialised to the root, "/". */
static uint32_t g_cwd_ino  = 0;
static char     g_cwd_path[POSIX_PATH_MAX] = "/";

/* ----- path resolution ------------------------------------------------- */

#define MAX_PATH_DEPTH 16

/* Walk `path` component-by-component from the root inode (0).
 *
 * On success: *out_ino is the resolved inode, return 0.
 * On "last component not found": *out_ino is the PARENT inode and
 *   *out_name is the last component name, return 1.
 * On any other error: return -1.
 *
 * out_name must point to a buffer of at least FS_NAME_MAX bytes.
 */
static int path_walk(const char *path,
                     uint32_t   *out_ino,
                     char       *out_name) {
    if (!path || path[0] == '\0') return -1;

    /* Absolute paths start at the root; relative paths start at the cwd. */
    uint32_t dir_ino = (path[0] == '/') ? 0u : g_cwd_ino;
    const char *p = path;
    if (*p == '/') p++;            /* skip leading slash */

    char comp[FS_NAME_MAX];
    int  depth = 0;

    out_name[0] = '\0';

    while (*p) {
        /* Extract next component. */
        uint32_t clen = 0;
        while (p[clen] && p[clen] != '/') clen++;

        if (clen == 0)          { p++; continue; }  /* double slash */
        if (clen >= FS_NAME_MAX) return -1;          /* component too long */
        if (++depth > MAX_PATH_DEPTH) return -1;

        _umemcpy(comp, p, clen);
        comp[clen] = '\0';
        p += clen;
        if (*p == '/') p++;

        /* If more path follows, we must look this up now. */
        if (*p != '\0') {
            struct fs_request rq;
            struct fs_response rp;
            _umemset(&rq, 0, sizeof(rq));
            rq.op      = FS_OP_LOOKUP;
            rq.dir_ino = dir_ino;
            _umemcpy(rq.name, comp, clen + 1u);

            int rc = fss_rpc(&rq, &rp);
            if (rc != 0) return -1;   /* intermediate component missing */
            dir_ino = rp.ino;
        } else {
            /* Last component: copy name out so the caller can CREATE if needed. */
            _umemcpy(out_name, comp, clen + 1u);

            /* Try to look it up. */
            struct fs_request rq;
            struct fs_response rp;
            _umemset(&rq, 0, sizeof(rq));
            rq.op      = FS_OP_LOOKUP;
            rq.dir_ino = dir_ino;
            _umemcpy(rq.name, comp, clen + 1u);

            int rc = fss_rpc(&rq, &rp);
            if (rc == 0) {
                *out_ino = rp.ino;
                return 0;            /* found */
            }
            /* Not found — let caller decide (create or error). */
            *out_ino = dir_ino;      /* return parent on not-found */
            return 1;
        }
    }

    /* Reached here only if path was all slashes → root */
    *out_ino = dir_ino;
    out_name[0] = '\0';
    return 0;
}

/* Resolve the PARENT directory of `path` and copy the final path component
 * into out_name (a buffer of at least FS_NAME_MAX bytes). Intermediate
 * components are looked up; the final one is NOT (so this works whether or not
 * the final component exists). Uses the same component/slash semantics as
 * path_walk.
 *
 * On success: *out_ino is the parent inode, out_name is the final component,
 *   return 0. A path with no final component ("/" or all slashes) yields an
 *   empty out_name — the caller must reject that.
 * On error (bad path, component too long, too deep, missing intermediate):
 *   return -1.
 */
static int path_parent(const char *path,
                       uint32_t   *out_ino,
                       char       *out_name) {
    if (!path || path[0] == '\0') return -1;

    /* Absolute paths start at the root; relative paths start at the cwd. */
    uint32_t dir_ino = (path[0] == '/') ? 0u : g_cwd_ino;
    const char *p = path;
    if (*p == '/') p++;            /* skip leading slash */

    char comp[FS_NAME_MAX];
    int  depth = 0;

    out_name[0] = '\0';

    while (*p) {
        uint32_t clen = 0;
        while (p[clen] && p[clen] != '/') clen++;

        if (clen == 0)          { p++; continue; }   /* double slash */
        if (clen >= FS_NAME_MAX) return -1;           /* component too long */
        if (++depth > MAX_PATH_DEPTH) return -1;

        _umemcpy(comp, p, clen);
        comp[clen] = '\0';
        p += clen;
        if (*p == '/') p++;

        if (*p != '\0') {
            /* Intermediate component: look it up and descend. */
            struct fs_request rq;
            struct fs_response rp;
            _umemset(&rq, 0, sizeof(rq));
            rq.op      = FS_OP_LOOKUP;
            rq.dir_ino = dir_ino;
            _umemcpy(rq.name, comp, clen + 1u);

            if (fss_rpc(&rq, &rp) != 0) return -1;   /* missing intermediate */
            dir_ino = rp.ino;
        } else {
            /* Final component: hand back the parent and the name. */
            _umemcpy(out_name, comp, clen + 1u);
            *out_ino = dir_ino;
            return 0;
        }
    }

    /* Path was all slashes → root, no final component. */
    *out_ino = dir_ino;
    out_name[0] = '\0';
    return 0;
}

/* ----- public API ------------------------------------------------------- */

void posix_init(void) {
    if (g_inited) return;
    _umemset(g_fdt, 0, sizeof(g_fdt));
    g_fdt[0].type  = FD_CONSOLE_IN;
    g_fdt[0].flags = O_RDONLY;
    g_fdt[1].type  = FD_CONSOLE_OUT;
    g_fdt[1].flags = O_WRONLY;
    g_fdt[2].type  = FD_CONSOLE_OUT;
    g_fdt[2].flags = O_WRONLY;

    /* If the spawner wired our stdin/stdout to a pipe (a shell pipeline stage),
     * bind fd 0/1 to the pipe end it granted at STDIN/STDOUT_PIPE_SLOT instead of
     * the console. stderr (fd 2) always stays on the console. */
    int sio = sys_stdio_info();
    if (sio & 0x1) { g_fdt[0].type = FD_PIPE; g_fdt[0].ino = STDIN_PIPE_SLOT;  g_fdt[0].flags = O_RDONLY; }
    if (sio & 0x2) { g_fdt[1].type = FD_PIPE; g_fdt[1].ino = STDOUT_PIPE_SLOT; g_fdt[1].flags = O_WRONLY; }

    g_inited = 1;
}

#define ENSURE_INIT() do { if (!g_inited) posix_init(); } while (0)

int posix_open(const char *path, int flags, int mode) {
    ENSURE_INIT();
    (void)mode;

    uint32_t ino;
    char     last[FS_NAME_MAX];
    int      walk = path_walk(path, &ino, last);

    if (walk < 0) return -1;   /* bad path / intermediate missing */

    if (walk == 1) {
        /* Last component not found. */
        if (!(flags & O_CREAT)) return -1;    /* ENOENT */

        /* Create the file in parent directory (ino is the parent). */
        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op      = FS_OP_CREATE;
        rq.dir_ino = ino;
        uint32_t nlen = _ustrlen(last);
        if (nlen == 0 || nlen >= FS_NAME_MAX) return -1;
        _umemcpy(rq.name, last, nlen + 1u);
        if (fss_rpc(&rq, &rp) != 0) return -1;
        ino = rp.ino;
    } else {
        /* File already exists. */
        if ((flags & O_CREAT) && (flags & O_EXCL)) return -1;  /* EEXIST */

        /* O_TRUNC on an existing file opened for writing empties it to 0. The
         * server zeroes any allocated tail so a later grow reads a clean hole. */
        if ((flags & O_TRUNC) && (flags & O_ACCMODE) != O_RDONLY) {
            struct fs_request rq;
            struct fs_response rp;
            _umemset(&rq, 0, sizeof(rq));
            rq.op     = FS_OP_TRUNCATE;
            rq.ino    = ino;
            rq.offset = 0;
            if (fss_rpc(&rq, &rp) != 0) return -1;
        }
    }

    int fd = fd_alloc();
    if (fd < 0) return -1;   /* EMFILE */

    g_fdt[fd].type   = FD_FS;
    g_fdt[fd].flags  = flags;
    g_fdt[fd].ino    = ino;
    g_fdt[fd].offset = 0;
    return fd;
}

int posix_read(int fd, void *buf, size_t len) {
    ENSURE_INIT();
    if (!fd_valid(fd))   return -1;
    if (len == 0)        return 0;

    fd_entry_t *e = &g_fdt[fd];

    /* Access mode check: can't read a write-only fd. */
    if ((e->flags & O_ACCMODE) == O_WRONLY) return -1;

    if (e->type == FD_CONSOLE_IN) {
        int r = sys_read(0, buf, len);
        return r;
    }

    if (e->type == FD_PIPE) {
        /* Block until at least one byte or EOF: retry SYS_ERR_AGAIN after yielding
         * so a slow upstream stage gets to run. Returns available bytes (may be <
         * len, like a real pipe), 0 at EOF (all writers closed), or a negative. */
        for (;;) {
            int n = sys_pipe_read(e->ino, buf, (uint32_t)len);
            if (n == SYS_ERR_AGAIN) { sys_yield(); continue; }
            return n;
        }
    }

    if (e->type != FD_FS) return -1;

    unsigned char *dst   = (unsigned char *)buf;
    uint32_t       total = 0;

    while (total < (uint32_t)len) {
        uint32_t chunk = (uint32_t)len - total;
        if (chunk > FS_IO_MAX) chunk = FS_IO_MAX;

        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op     = FS_OP_READ;
        rq.ino    = e->ino;
        rq.offset = e->offset;
        rq.len    = chunk;

        int got = fss_rpc(&rq, &rp);
        if (got < 0) return (int)total > 0 ? (int)total : -1;
        if (got == 0) break;   /* EOF */
        if ((uint32_t)got > FS_IO_MAX) got = FS_IO_MAX;  /* clamp: trust but verify */

        _umemcpy(dst + total, rp.data, (uint32_t)got);

        /* Overflow-safe offset update. */
        if (e->offset > 0xFFFFFFFFu - (uint32_t)got)
            e->offset = 0xFFFFFFFFu;
        else
            e->offset += (uint32_t)got;

        total += (uint32_t)got;
        if ((uint32_t)got < chunk) break;   /* short read → EOF */
    }

    return (int)total;
}

/* Emit `len` bytes to the ring-3 console_server (CON_OP_WRITE, well-known
 * endpoint CON_EP_REQ) so console output stays single-writer under SMP: while the
 * server owns the hardware the kernel's own fd-1 path is hands-off, so a program's
 * stdout must go through the server or it never reaches the screen. Chunked to the
 * protocol's CON_IO_MAX; returns bytes written, or -1 if the server is unreachable
 * (the caller then falls back to the kernel path). Static buffers keep the 212+136
 * byte request/response off the (small) libc stack; a program is single-threaded
 * over its own fds, so sharing them across calls is safe. */
static struct con_request  g_con_rq;
static struct con_response g_con_rp;
static int con_server_write(const void *buf, size_t len) {
    const unsigned char *s = (const unsigned char *)buf;
    size_t off = 0;
    while (off < len) {
        unsigned n = (unsigned)(len - off);
        if (n > CON_IO_MAX) n = CON_IO_MAX;
        g_con_rq.magic = CON_PROTO_MAGIC;
        g_con_rq.op    = CON_OP_WRITE;
        g_con_rq.len   = n;
        for (unsigned i = 0; i < n; i++) g_con_rq.data[i] = s[off + i];

        int rc = -1;
        for (int tries = 0; tries < 20000; tries++) {
            rc = sys_ipc_call(CON_EP_REQ, CON_EP_REP,
                              &g_con_rq, sizeof(g_con_rq), &g_con_rp);
            if (rc >= 0) break;
            sys_yield();          /* mailbox full: yield and retry */
        }
        if (rc < 0 || g_con_rp.magic != CON_PROTO_MAGIC || g_con_rp.rc != (int)n)
            return (off > 0) ? (int)off : -1;
        off += n;
    }
    return (int)off;
}

int posix_write(int fd, const void *buf, size_t len) {
    ENSURE_INIT();
    if (!fd_valid(fd))  return -1;
    if (len == 0)       return 0;

    fd_entry_t *e = &g_fdt[fd];

    /* Access mode check: can't write a read-only fd. */
    if ((e->flags & O_ACCMODE) == O_RDONLY) return -1;

    if (e->type == FD_PIPE) {
        /* Write all len bytes, yielding on back-pressure (full pipe, reader still
         * open) so the downstream stage drains it; stop early on SYS_ERR_PIPE (the
         * reader is gone), returning what got through, or the error if none did. */
        const unsigned char *src = (const unsigned char *)buf;
        uint32_t total = 0;
        while (total < (uint32_t)len) {
            int n = sys_pipe_write(e->ino, src + total, (uint32_t)len - total);
            if (n == SYS_ERR_AGAIN) { sys_yield(); continue; }
            if (n < 0) return total > 0 ? (int)total : n;
            total += (uint32_t)n;
        }
        return (int)total;
    }

    if (e->type == FD_CONSOLE_OUT) {
        /* Keep the console single-writer: while a ring-3 console_server owns the
         * hardware, the kernel's fd-1 path stays hands-off, so route stdout through
         * the server. When no server owns it (early boot, or selftest images with
         * no console_server), the kernel drives the console directly — take that
         * path so those images don't block on an IPC nobody answers. */
        if (sys_console_owned()) {
            int n = con_server_write(buf, len);
            if (n >= 0) return n;
            /* server unreachable: fall through to the in-kernel path */
        }
        return sys_write(fd, buf, len);
    }

    if (e->type != FD_FS) return -1;

    const unsigned char *src    = (const unsigned char *)buf;
    uint32_t             total  = 0;
    /* O_APPEND sends FS_OP_APPEND, which makes the *server* pick the offset (the
     * current end of file) under its own serialisation. Resolving the end here
     * instead — stat, then write at what it said — would race any other client
     * extending the file in between, and silently overwrite their data. */
    const int            append = (e->flags & O_APPEND) != 0;

    while (total < (uint32_t)len) {
        uint32_t chunk = (uint32_t)len - total;
        if (chunk > FS_IO_MAX) chunk = FS_IO_MAX;

        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op     = append ? FS_OP_APPEND : FS_OP_WRITE;
        rq.ino    = e->ino;
        rq.offset = e->offset;      /* ignored by the server when appending */
        rq.len    = chunk;
        _umemcpy(rq.data, src + total, chunk);

        int written = fss_rpc(&rq, &rp);
        if (written <= 0) return (int)total > 0 ? (int)total : -1;
        if ((uint32_t)written > chunk) written = (int)chunk;  /* clamp */

        if (append) {
            /* Only the server knows where it appended; it reports the end of the
             * write. Reject a nonsensical answer rather than let our position
             * desync from the file. */
            if (rp.size < (uint32_t)written) return (int)total > 0 ? (int)total : -1;
            e->offset = rp.size;
        } else if (e->offset > 0xFFFFFFFFu - (uint32_t)written) {
            e->offset = 0xFFFFFFFFu;
        } else {
            e->offset += (uint32_t)written;
        }

        total += (uint32_t)written;
        if ((uint32_t)written < chunk) break;   /* partial write */
    }

    return (int)total;
}

int posix_close(int fd) {
    ENSURE_INIT();
    if (!fd_valid(fd))         return -1;
    /* A pipe end can be closed at any fd (including a redirected fd 0/1): drop the
     * kernel end so the peer sees EOF/EPIPE promptly, then free the table slot. */
    if (g_fdt[fd].type == FD_PIPE) {
        sys_pipe_close(g_fdt[fd].ino);
        fd_free(fd);
        return 0;
    }
    if (fd < 3)                return -1;   /* never close stdin/stdout/stderr */
    fd_free(fd);
    return 0;
}

int posix_lseek(int fd, int32_t offset, int whence) {
    ENSURE_INIT();
    if (!fd_valid(fd))         return -1;

    fd_entry_t *e = &g_fdt[fd];
    if (e->type != FD_FS)     return -1;   /* can't seek on console */

    uint32_t new_off;

    switch (whence) {
    case SEEK_SET:
        if (offset < 0) return -1;
        new_off = (uint32_t)offset;
        break;

    case SEEK_CUR:
        if (offset < 0) {
            uint32_t delta = (uint32_t)(-offset);
            if (delta > e->offset) return -1;   /* would underflow */
            new_off = e->offset - delta;
        } else {
            if (e->offset > 0xFFFFFFFFu - (uint32_t)offset) return -1;
            new_off = e->offset + (uint32_t)offset;
        }
        break;

    case SEEK_END: {
        /* Query file size via STAT. */
        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op  = FS_OP_STAT;
        rq.ino = e->ino;
        if (fss_rpc(&rq, &rp) != 0) return -1;
        uint32_t fsz = rp.size;

        if (offset < 0) {
            uint32_t delta = (uint32_t)(-offset);
            if (delta > fsz) return -1;
            new_off = fsz - delta;
        } else {
            if (fsz > 0xFFFFFFFFu - (uint32_t)offset) return -1;
            new_off = fsz + (uint32_t)offset;
        }
        break;
    }

    default:
        return -1;
    }

    e->offset = new_off;
    return (int)new_off;
}

int posix_fstat(int fd, posix_stat_t *st) {
    ENSURE_INIT();
    if (!st)             return -1;
    if (!fd_valid(fd))   return -1;

    fd_entry_t *e = &g_fdt[fd];

    if (e->type == FD_CONSOLE_IN || e->type == FD_CONSOLE_OUT || e->type == FD_PIPE) {
        /* A pipe is a non-seekable stream, like the console — report it as a
         * character/FIFO device with size 0 so tools (wc, cat) treat it as a
         * stream and read to EOF rather than fstat-ing a file size or erroring. */
        _umemset(st, 0, sizeof(*st));
        st->mode    = S_IFCHR | S_IRWXU;
        st->blksize = 1;
        st->links   = 1;
        return 0;
    }

    if (e->type != FD_FS) return -1;

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op  = FS_OP_STAT;
    rq.ino = e->ino;
    if (fss_rpc(&rq, &rp) != 0) return -1;

    _umemset(st, 0, sizeof(*st));
    st->ino  = e->ino;
    st->size = rp.size;
    /* Real metadata from the server: the type bit from rp.type
     * (1 = FS_TYPE_FILE, 2 = FS_TYPE_DIR) OR'd with the actual permission bits
     * (rp.mode is st.mode & 07777), plus the owning uid/gid. */
    st->mode    = ((rp.type == 2) ? S_IFDIR : S_IFREG) | (rp.mode & 07777u);
    st->uid     = rp.uid;
    st->gid     = rp.gid;
    st->links   = rp.links ? rp.links : 1u;
    st->blksize = 512;
    st->blocks  = (rp.size + 511u) / 512u;
    return 0;
}

int posix_stat(const char *path, posix_stat_t *st) {
    ENSURE_INIT();
    if (!st || !path) return -1;

    uint32_t ino;
    char     last[FS_NAME_MAX];
    if (path_walk(path, &ino, last) != 0) return -1;   /* not found */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op  = FS_OP_STAT;
    rq.ino = ino;
    if (fss_rpc(&rq, &rp) != 0) return -1;

    _umemset(st, 0, sizeof(*st));
    st->ino     = ino;
    st->size    = rp.size;
    st->mode    = ((rp.type == 2) ? S_IFDIR : S_IFREG) | (rp.mode & 07777u);
    st->uid     = rp.uid;
    st->gid     = rp.gid;
    st->links   = rp.links ? rp.links : 1u;
    st->blksize = 512;
    st->blocks  = (rp.size + 511u) / 512u;
    return 0;
}

/* Resolve `path` to a directory inode for enumeration.
 * Returns 0 and sets *out_ino on success, -1 if the path does not resolve,
 * -2 if it resolves to something that is not a directory (ENOTDIR). */
int posix_diropen(const char *path, uint32_t *out_ino) {
    ENSURE_INIT();
    if (!path || !out_ino) return -1;

    uint32_t ino;
    char     last[FS_NAME_MAX];
    if (path_walk(path, &ino, last) != 0) return -1;   /* not found */

    /* Confirm it is a directory before handing back an inode the caller will
     * readdir — a READDIR on a regular file would just error per entry. */
    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op  = FS_OP_STAT;
    rq.ino = ino;
    if (fss_rpc(&rq, &rp) != 0) return -1;
    if (rp.type != 2 /* FS_TYPE_DIR */) return -2;

    *out_ino = ino;
    return 0;
}

/* Read the directory entry at `index` (0-based) of directory inode `dir_ino`.
 * Returns 1 and fills the non-NULL out params on success, 0 at/after the end of
 * the directory (or on any error — readdir(3) reports end-of-dir as a NULL
 * return with errno unchanged, so the two are indistinguishable to the caller,
 * which matches POSIX). The name is copied NUL-terminated into name_out, which
 * must be at least FS_NAME_MAX bytes. */
int posix_readdir(uint32_t dir_ino, uint32_t index,
                  char *name_out, uint32_t *ino_out, uint32_t *type_out) {
    ENSURE_INIT();

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_READDIR;
    rq.dir_ino = dir_ino;
    rq.offset  = index;                 /* entry index, per fs_proto.h */

    /* Server returns rc 0 with the entry, or a negative SYS_ERR_* past the end
     * (NOENT) or on a permission/transport failure — all "no more entries". */
    if (fss_rpc(&rq, &rp) != 0) return 0;

    if (name_out) {
        uint32_t i = 0;
        for (; rp.name[i] && i < FS_NAME_MAX - 1u; i++) name_out[i] = rp.name[i];
        name_out[i] = '\0';
    }
    if (ino_out)  *ino_out  = rp.ino;
    if (type_out) *type_out = rp.type;
    return 1;
}

/* Compose `arg` against the current cwd into a normalized ABSOLUTE path in
 * out[POSIX_PATH_MAX]. Resolves ".", "..", a leading "/", and collapses
 * repeated slashes — pure string work, so it never depends on on-disk "."/".."
 * entries (the object store has none). Returns 0 on success, -1 on overflow. */
static int cwd_normalize(const char *arg, char *out) {
    char comps[MAX_PATH_DEPTH][FS_NAME_MAX];
    int  ncomp = 0;

    /* Relative arg inherits the cwd's components as a starting stack. */
    if (arg[0] != '/') {
        const char *q = g_cwd_path;
        while (*q == '/') q++;
        while (*q) {
            int c = 0;
            while (*q && *q != '/' && c < FS_NAME_MAX - 1) comps[ncomp][c++] = *q++;
            comps[ncomp][c] = '\0';
            while (*q == '/') q++;
            if (c > 0) { if (ncomp >= MAX_PATH_DEPTH) return -1; ncomp++; }
        }
    }

    /* Fold in the argument's components. */
    const char *p = arg;
    while (*p == '/') p++;
    while (*p) {
        char comp[FS_NAME_MAX];
        int  c = 0;
        while (*p && *p != '/' && c < FS_NAME_MAX - 1) comp[c++] = *p++;
        comp[c] = '\0';
        while (*p == '/') p++;
        if (c == 0) continue;
        if (comp[0] == '.' && comp[1] == '\0') continue;                    /* "."  */
        if (comp[0] == '.' && comp[1] == '.' && comp[2] == '\0') {         /* ".." */
            if (ncomp > 0) ncomp--;
            continue;
        }
        if (ncomp >= MAX_PATH_DEPTH) return -1;
        _umemcpy(comps[ncomp], comp, (uint32_t)c + 1u);
        ncomp++;
    }

    /* Rebuild "/a/b/c" (or "/" when the stack is empty). */
    int o = 0;
    if (ncomp == 0) { out[0] = '/'; out[1] = '\0'; return 0; }
    for (int i = 0; i < ncomp; i++) {
        int l = (int)_ustrlen(comps[i]);
        if (o + 1 + l >= POSIX_PATH_MAX) return -1;
        out[o++] = '/';
        _umemcpy(out + o, comps[i], (uint32_t)l);
        o += l;
    }
    out[o] = '\0';
    return 0;
}

/* Change the cwd to `path` (relative to the current cwd, or absolute). Verifies
 * the target exists and is a directory. Returns 0 on success, -1 otherwise. */
int posix_chdir(const char *path) {
    ENSURE_INIT();
    if (!path || path[0] == '\0') return -1;

    char norm[POSIX_PATH_MAX];
    if (cwd_normalize(path, norm) != 0) return -1;

    uint32_t ino;
    if (posix_diropen(norm, &ino) < 0) return -1;   /* missing or not a dir */

    g_cwd_ino = ino;
    uint32_t i = 0;
    for (; norm[i] && i < POSIX_PATH_MAX - 1u; i++) g_cwd_path[i] = norm[i];
    g_cwd_path[i] = '\0';
    return 0;
}

/* Copy the canonical cwd path into buf. Returns 0 on success, -1 if it does not
 * fit (ERANGE) or on bad args. */
int posix_getcwd(char *buf, uint32_t size) {
    ENSURE_INIT();
    if (!buf || size == 0) return -1;
    uint32_t n = _ustrlen(g_cwd_path);
    if (n + 1u > size) return -1;                   /* ERANGE */
    _umemcpy(buf, g_cwd_path, n + 1u);
    return 0;
}

/* Create a directory at `path` (relative to the cwd, or absolute). Returns 0 or
 * a negative SYS_ERR_* (the server enforces write on the parent directory). */
int posix_mkdir(const char *path, int mode) {
    ENSURE_INIT();
    (void)mode;
    if (!path) return SYS_ERR_INVAL;

    uint32_t parent;
    char     name[FS_NAME_MAX];
    if (path_parent(path, &parent, name) != 0) return SYS_ERR_NOENT;
    if (name[0] == '\0') return SYS_ERR_INVAL;      /* refuse "/" */

    uint32_t nlen = _ustrlen(name);
    if (nlen == 0 || nlen >= FS_NAME_MAX) return SYS_ERR_INVAL;

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_MKDIR;
    rq.dir_ino = parent;
    _umemcpy(rq.name, name, nlen + 1u);
    return fss_rpc(&rq, &rp);
}

int posix_unlink(const char *path) {
    ENSURE_INIT();
    if (!path) return -1;

    uint32_t parent;
    char     name[FS_NAME_MAX];
    /* A path we can't resolve (bad path, missing intermediate directory, or "/"
     * itself) is a missing target — report it as SYS_ERR_NOENT so the libc
     * wrapper maps it to ENOENT rather than a transport error. */
    if (path_parent(path, &parent, name) != 0) return SYS_ERR_NOENT;
    if (name[0] == '\0') return SYS_ERR_NOENT;    /* refuse to unlink "/" */

    uint32_t nlen = _ustrlen(name);
    if (nlen == 0 || nlen >= FS_NAME_MAX) return SYS_ERR_NOENT;

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_DELETE;
    rq.dir_ino = parent;
    _umemcpy(rq.name, name, nlen + 1u);

    /* Propagate the server's rc: 0 on success, a negative SYS_ERR_* on a
     * permission / not-found / non-empty-directory refusal, or -1 on a
     * transport failure. The server is the reference monitor — it enforces
     * write permission on the parent directory against our kernel-attested
     * uid, so no client-side permission check is needed (or trusted). */
    return fss_rpc(&rq, &rp);
}

int posix_ftruncate(int fd, uint32_t length) {
    ENSURE_INIT();
    if (!fd_valid(fd))                       return -1;
    fd_entry_t *e = &g_fdt[fd];
    if (e->type != FD_FS)                    return -1;   /* not a regular file */
    if ((e->flags & O_ACCMODE) == O_RDONLY)  return -1;   /* need write access */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op     = FS_OP_TRUNCATE;
    rq.ino    = e->ino;
    rq.offset = length;
    return fss_rpc(&rq, &rp) == 0 ? 0 : -1;
}

int posix_rename(const char *oldpath, const char *newpath) {
    ENSURE_INIT();
    if (!oldpath || !newpath) return SYS_ERR_INVAL;

    uint32_t old_parent, new_parent;
    char     oldname[FS_NAME_MAX], newname[FS_NAME_MAX];
    if (path_parent(oldpath, &old_parent, oldname) != 0) return SYS_ERR_NOENT;
    if (path_parent(newpath, &new_parent, newname) != 0) return SYS_ERR_NOENT;
    if (oldname[0] == '\0' || newname[0] == '\0') return SYS_ERR_INVAL;   /* refuse "/" */

    uint32_t olen = _ustrlen(oldname), nlen = _ustrlen(newname);
    if (olen == 0 || olen >= FS_NAME_MAX || nlen == 0 || nlen >= FS_NAME_MAX)
        return SYS_ERR_INVAL;

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_RENAME;
    rq.dir_ino = old_parent;                 /* old parent */
    rq.ino     = new_parent;                 /* new parent */
    _umemcpy(rq.name, oldname, olen + 1u);   /* old name */
    _umemcpy(rq.data, newname, nlen + 1u);   /* new name */
    return fss_rpc(&rq, &rp);
}

int posix_link(const char *oldpath, const char *newpath) {
    ENSURE_INIT();
    if (!oldpath || !newpath) return SYS_ERR_INVAL;

    /* Resolve the source to an existing inode (path_walk returns 0 only when the
     * final component is found). The server re-checks it is a regular file. */
    uint32_t src_ino;
    char     src_leaf[FS_NAME_MAX];
    if (path_walk(oldpath, &src_ino, src_leaf) != 0) return SYS_ERR_NOENT;

    /* Resolve the new name's parent directory + leaf. */
    uint32_t new_parent;
    char     newname[FS_NAME_MAX];
    if (path_parent(newpath, &new_parent, newname) != 0) return SYS_ERR_NOENT;
    if (newname[0] == '\0') return SYS_ERR_INVAL;        /* refuse "/" as a target */
    uint32_t nlen = _ustrlen(newname);
    if (nlen == 0 || nlen >= FS_NAME_MAX) return SYS_ERR_INVAL;

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_LINK;
    rq.ino     = src_ino;                    /* source file inode */
    rq.dir_ino = new_parent;                 /* new parent dir */
    _umemcpy(rq.name, newname, nlen + 1u);   /* new name */
    return fss_rpc(&rq, &rp);
}

int posix_isatty(int fd) {
    ENSURE_INIT();
    if (!fd_valid(fd)) return 0;
    return (g_fdt[fd].type == FD_CONSOLE_IN ||
            g_fdt[fd].type == FD_CONSOLE_OUT) ? 1 : 0;
}
