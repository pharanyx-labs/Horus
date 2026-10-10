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
#include <sys/termios.h>
#include "fs_proto.h"
#include "block_size.h"
#include "libhorus.h"   /* hvfs: the mount table and the one path walker */

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
#define FD_DIR          5u   /* an open directory stream (posix_diropen) */

typedef struct {
    uint8_t  type;     /* FD_FREE / FD_CONSOLE_IN / FD_CONSOLE_OUT / FD_FS / FD_PIPE */
    uint8_t  _pad[3];
    int      flags;    /* O_RDONLY / O_WRONLY / O_RDWR | O_APPEND etc. */
    uint32_t ino;      /* (FD_PIPE) the pipe-end cspace slot */
    uint32_t offset;
    struct hvfs_obj obj;   /* (FD_FS, FD_DIR) what requests are sent through */
} fd_entry_t;

static fd_entry_t  g_fdt[POSIX_MAX_FDS];
static int         g_inited       = 0;
static int         g_fs_connected = 0;
/* THE MODE, CHOSEN ONCE (filesystem phase 1b step 2). A task that holds a root
 * directory capability in CAPSLOT_FS_ROOT walks by capability and never touches
 * the uid path: it does not even connect to it, so no request of its can fall
 * back there when a capability refuses. A task that holds none uses the uid
 * path, as before, until step 6 removes it. Never decided per request. */
static int         g_capmode      = 0;

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
    /* A file's or directory's own capability goes with it (hvfs_release
     * revokes it; a uid-path object owns nothing). */
#ifndef POSIX_CLOSE_KEEPS_CAP
    if (g_fdt[fd].type == FD_FS || g_fdt[fd].type == FD_DIR) hvfs_release(&g_fdt[fd].obj);
#endif
    /* POSIX_CLOSE_KEEPS_CAP=1 is the control arm for make
     * smoke-fs-cap-posix-close-control: a closed file's capability stays, so
     * the authority outlives the descriptor and the pool runs dry. Never ship. */
    _umemset(&g_fdt[fd], 0, sizeof(g_fdt[fd]));
}

/* ----- fs_server IPC -------------------------------------------------- */

/* ep slot for the fs_server capability (must be >= 4 per kernel rule). */
#define FSS_CAP_SLOT CAPSLOT_FS_EP

static void fs_connect(void) {
    if (g_fs_connected || g_capmode) return;
    /* Acquire a (WRITE-only) capability to the fs service.
     *
     * Retry until it succeeds. Since IPC became capability-addressed (finding
     * C-1) this is the ONLY way a client reaches the server: there is no ambient
     * endpoint capability to fall back on, so a failed connect is not a
     * degraded-but-working state, it is no filesystem at all. And the call can
     * legitimately fail for a moment — SYS_CONNECT_FS_SERVER needs the server to
     * have registered, and a client spawned early (or scheduled first on another
     * core under SMP) can run before that. Both parties therefore wait for each
     * other rather than racing: the server retries its registration, the client
     * retries its connect. Bounded, with a yield so the server actually gets the
     * CPU on a single core. */
    for (int attempt = 0; attempt < 2000; attempt++) {
        if (sys_connect_fs_server(FSS_CAP_SLOT, CAP_R_W) == 0) {
            g_fs_connected = 1;
            return;
        }
        sys_yield();
    }
    /* Give up after a bounded wait: the first RPC then fails with a non-magic
     * reply, which callers already handle, rather than spinning forever. */
    g_fs_connected = 1;
}

/* Single round-trip to the fs_server about object `o`: through its capability
 * on the capability path, through the endpoint on the uid path. Returns rp->rc
 * on success, -1 on transport failure (bad magic or sys_ipc_call error). */
static int fss_rpc(const struct hvfs_obj *o, struct fs_request *rq, struct fs_response *rp) {
    fs_connect();
    rq->magic = FS_PROTO_MAGIC;
    _umemset(rp, 0, sizeof(*rp));
    if (o->slot < 0) return -1;

    int r = sys_ipc_call((uint32_t)o->slot, 0,
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
/* The working directory as an object, and what g_cwd_path is relative to: the
 * root, or (capability path) the directory capability the spawner granted at
 * CAPSLOT_FS_CWD, whose name this task is never told. Then g_cwd_path is the
 * path below it, ".." stops there, and getcwd cannot answer. */
static struct hvfs_obj g_root;
static struct hvfs_obj g_cwd;
static struct hvfs_obj g_cwd_base;
static int             g_cwd_named = 1;

/* ----- path resolution ------------------------------------------------- */

#define MAX_PATH_DEPTH 16

/* Path resolution is `hvfs_walk` (userspace/hvfs.c), not a copy of it.
 *
 * Until 2026-08-23 this file carried its own `path_walk` and `path_parent`,
 * shell.c carried `sh_walk_abs_dir`, and fsclient.c looked names up by hand.
 * Three walkers, one protocol, and they had already drifted: only the shell's
 * caller resolved ".." at all, and it did so by rewriting the STRING before
 * walking, so a ".." arriving through open(), stat() or rename() -- which is
 * every path a libc program passes -- was looked up as a literal component
 * name. The kernel-side namespace landed in #195 with nothing calling it; this
 * is that migration, and the drift is the argument for it.
 *
 * The contract is unchanged, which is why the call sites below did not move:
 * 0 = resolved, 1 = everything but the leaf resolved (*out_ino is the parent),
 * -1 = bad path or a missing intermediate.
 *
 * The mount is installed in posix_init: "/" on CAPSLOT_FS_EP, root inode 0.
 * That is the whole namespace a newlib program starts with -- one entry, the
 * filesystem it was already talking to. A program that needs a second mount
 * calls hvfs_mount itself, over a capability it already holds.
 */
#ifdef POSIX_LEGACY_WALK
/* CONTROL ARM: the private walker as it stood until 2026-08-23, restored.
 *
 * It is a faithful copy, not a weakened one -- which is the point. It resolves
 * neither "." nor "..": both are looked up as literal directory entries, and
 * `fs_server` creates no such entries, so every libc path containing one fails
 * with ENOENT. `make smoke-newlib` must go red under this flag. */
#define LEGACY_MAX_PATH_DEPTH 16
static int legacy_walk(const char *path, uint32_t *out_ino, char *out_name,
                       int want_parent) {
    if (!path || path[0] == '\0') return -1;
    uint32_t dir_ino = (path[0] == '/') ? 0u : g_cwd_ino;
    const char *p = path;
    if (*p == '/') p++;
    char comp[FS_NAME_MAX];
    int  depth = 0;
    out_name[0] = '\0';
    while (*p) {
        uint32_t clen = 0;
        while (p[clen] && p[clen] != '/') clen++;
        if (clen == 0)           { p++; continue; }
        if (clen >= FS_NAME_MAX) return -1;
        if (++depth > LEGACY_MAX_PATH_DEPTH) return -1;
        _umemcpy(comp, p, clen);
        comp[clen] = '\0';
        p += clen;
        if (*p == '/') p++;
        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op      = FS_OP_LOOKUP;
        rq.dir_ino = dir_ino;
        _umemcpy(rq.name, comp, clen + 1u);
        if (*p != '\0') {
            if (fss_rpc(&g_root, &rq, &rp) != 0) return -1;
            dir_ino = rp.ino;
        } else {
            _umemcpy(out_name, comp, clen + 1u);
            if (want_parent) { *out_ino = dir_ino; return 0; }
            if (fss_rpc(&g_root, &rq, &rp) == 0) { *out_ino = rp.ino; return 0; }
            *out_ino = dir_ino;
            return 1;
        }
    }
    *out_ino = dir_ino;
    out_name[0] = '\0';
    return 0;
}
#endif

/* Resolve `path` to an object (want_parent: the directory holding its last
 * component). The contract is hvfs_walk's, 0, 1 or -1. An object that comes
 * back owned holds a capability minted for it, which the caller gives back with
 * hvfs_release, on every path out. */
static int path_obj_at(const char *path, const struct hvfs_obj *cwd, int want_parent,
                       struct hvfs_obj *out, char *out_name) {
#ifdef POSIX_LEGACY_WALK
    uint32_t ino;
    (void)cwd;
    int r = legacy_walk(path, &ino, out_name, want_parent);
    *out = g_root;
    out->ino = ino;
    return r;
#else
    return hvfs_lookup(path, cwd, want_parent, out, out_name);
#endif
}

static int path_obj(const char *path, int want_parent, struct hvfs_obj *out, char *out_name) {
    return path_obj_at(path, &g_cwd, want_parent, out, out_name);
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

    /* The namespace this process starts with: one mount, "/" on the fs_server
     * endpoint. fs_connect() first, because hvfs_mount PROBES the slot with the
     * weakest legal request and refuses one holding no usable capability -- so
     * mounting before the connect would be refused for the right reason at the
     * wrong time. A refusal here is not fatal and is not silently ignored
     * either: every path operation then fails at hvfs_resolve with nothing
     * mounted, which is the same fail-closed answer as a missing endpoint. */
    /* A root directory capability, if the spawner granted one, decides it: the
     * mount probe is a stat through it, so an empty slot is refused and the
     * task stays on the uid path. With a root, the working directory is the one
     * granted at CAPSLOT_FS_CWD if that answers, else the root. */
    if (hvfs_mount_cap("/", CAPSLOT_FS_ROOT) == 0) {
        g_capmode = 1;
        g_root.slot = CAPSLOT_FS_ROOT; g_root.ino = 0; g_root.cap = 1; g_root.owned = 0;
        g_cwd_base = g_root;
        {
            struct fs_request rq;
            struct fs_response rp;
            struct hvfs_obj cwd = { CAPSLOT_FS_CWD, 0, 1, 0 };
            _umemset(&rq, 0, sizeof(rq));
            rq.op = FS_OP_STAT;
            if (fss_rpc(&cwd, &rq, &rp) == 0 && rp.type == FS_TYPE_DIR) {
                g_cwd_base = cwd;
                g_cwd_named = 0;
            }
        }
    } else {
        fs_connect();
        (void)hvfs_mount("/", CAPSLOT_FS_EP, 0u);
        g_root.slot = CAPSLOT_FS_EP; g_root.ino = 0; g_root.cap = 0; g_root.owned = 0;
        g_cwd_base = g_root;
    }
    g_cwd = g_cwd_base;

    g_inited = 1;
}

#define ENSURE_INIT() do { if (!g_inited) posix_init(); } while (0)

int posix_open(const char *path, int flags, int mode) {
    ENSURE_INIT();
    (void)mode;

    struct hvfs_obj o;
    char     last[FS_NAME_MAX];
    int      walk = path_obj(path, 0, &o, last);

    if (walk < 0) return -1;   /* bad path / intermediate missing */

    if (walk == 1) {
        /* Last component not found; `o` is the parent. */
        if (!(flags & O_CREAT)) { hvfs_release(&o); return -1; }    /* ENOENT */

        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op      = FS_OP_CREATE;
        rq.dir_ino = o.ino;
        uint32_t nlen = _ustrlen(last);
        if (nlen == 0 || nlen >= FS_NAME_MAX) { hvfs_release(&o); return -1; }
        _umemcpy(rq.name, last, nlen + 1u);
        int rc = fss_rpc(&o, &rq, &rp);
        hvfs_release(&o);
        if (rc != 0) return -1;
        if (o.cap) {
            /* ONE CAPABILITY PER OPEN FILE, DERIVED FROM WHERE THE WALK STARTED.
             * One minted by the create would be the parent's child and go when
             * the parent's is given back, so the file is walked to afresh. */
            if (path_obj(path, 0, &o, last) != 0) { hvfs_release(&o); return -1; }
        } else {
            o.ino = rp.ino;
        }
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
            rq.ino    = o.ino;
            rq.offset = 0;
            if (fss_rpc(&o, &rq, &rp) != 0) { hvfs_release(&o); return -1; }
        }
    }

    int fd = fd_alloc();
    if (fd < 0) { hvfs_release(&o); return -1; }   /* EMFILE */

    g_fdt[fd].type   = FD_FS;
    g_fdt[fd].flags  = flags;
    g_fdt[fd].obj    = o;
    g_fdt[fd].offset = 0;
    return fd;
}

/* ---- raw ("full-screen") console mode -------------------------------------- */
/* The console is a real VT/ANSI terminal on the serial line. A curses program
 * puts it into raw mode via tcsetattr() (canonical + echo off); we track that as
 * a single flag and route console read()/write() through the console_server's
 * raw ops, so key bytes arrive un-edited and escape sequences pass through.
 * Declared here (before posix_read/posix_write use them); defined below. */
static int g_console_raw = 0;
static struct termios g_con_tio = {
    .c_iflag = ICRNL | IXON, .c_oflag = OPOST | ONLCR,
    .c_cflag = CS8 | CREAD | CLOCAL, .c_lflag = ISIG | ICANON | ECHO | IEXTEN,
    .c_ispeed = B38400, .c_ospeed = B38400,
};
static int con_server_read_raw(void *buf, size_t len);
static int con_server_write_raw(const void *buf, size_t len);

int posix_read(int fd, void *buf, size_t len) {
    ENSURE_INIT();
    if (!fd_valid(fd))   return -1;
    if (len == 0)        return 0;

    fd_entry_t *e = &g_fdt[fd];

    /* Access mode check: can't read a write-only fd. */
    if ((e->flags & O_ACCMODE) == O_WRONLY) return -1;

    if (e->type == FD_CONSOLE_IN) {
        /* Raw mode: a full-screen app reads un-edited key bytes from the server
         * that owns the hardware. Cooked mode keeps the kernel line-read path. */
        if (g_console_raw && sys_console_owned())
            return con_server_read_raw(buf, len);
        return sys_read(0, buf, len);
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
        rq.ino    = e->obj.ino;
        rq.offset = e->offset;
        rq.len    = chunk;

        int got = fss_rpc(&e->obj, &rq, &rp);
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
            rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0,
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

/* One raw read: up to `len` bytes, no echo/edit; blocks in the server for the
 * first byte, returns the immediately-available burst (so a multi-byte key like
 * an arrow comes back whole). */
static int con_server_read_raw(void *buf, size_t len) {
    unsigned n = (unsigned)len;
    if (n > CON_LINE_MAX - 1) n = CON_LINE_MAX - 1;
    g_con_rq.magic = CON_PROTO_MAGIC;
    g_con_rq.op    = CON_OP_READ_RAW;
    g_con_rq.len   = n;
    int rc = -1;
    for (int tries = 0; tries < 20000; tries++) {
        rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &g_con_rq, sizeof(g_con_rq), &g_con_rp);
        if (rc >= 0) break;
        sys_yield();
    }
    if (rc < 0 || g_con_rp.magic != CON_PROTO_MAGIC || g_con_rp.rc < 0) return -1;
    int got = g_con_rp.rc;
    if (got > (int)n) got = (int)n;
    for (int i = 0; i < got; i++) ((unsigned char *)buf)[i] = g_con_rp.data[i];
    return got;
}

/* Verbatim write (no '\n'->'\r\n'), for escape sequences and screen output. */
static int con_server_write_raw(const void *buf, size_t len) {
    const unsigned char *s = (const unsigned char *)buf;
    size_t off = 0;
    while (off < len) {
        unsigned n = (unsigned)(len - off);
        if (n > CON_IO_MAX) n = CON_IO_MAX;
        g_con_rq.magic = CON_PROTO_MAGIC;
        g_con_rq.op    = CON_OP_WRITE_RAW;
        g_con_rq.len   = n;
        for (unsigned i = 0; i < n; i++) g_con_rq.data[i] = s[off + i];
        int rc = -1;
        for (int tries = 0; tries < 20000; tries++) {
            rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &g_con_rq, sizeof(g_con_rq), &g_con_rp);
            if (rc >= 0) break;
            sys_yield();
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
            int n = g_console_raw ? con_server_write_raw(buf, len)
                                  : con_server_write(buf, len);
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
        rq.ino    = e->obj.ino;
        rq.offset = e->offset;      /* ignored by the server when appending */
        rq.len    = chunk;
        _umemcpy(rq.data, src + total, chunk);

        int written = fss_rpc(&e->obj, &rq, &rp);
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
        rq.ino = e->obj.ino;
        if (fss_rpc(&e->obj, &rq, &rp) != 0) return -1;
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
    rq.ino = e->obj.ino;
    if (fss_rpc(&e->obj, &rq, &rp) != 0) return -1;

    _umemset(st, 0, sizeof(*st));
    /* Through a capability the client never named the inode, so the server's
     * report is the only one; on the uid path the walked inode is, since not
     * every server reports it (dev_server does not). */
    st->ino  = e->obj.cap ? rp.ino : e->obj.ino;
    st->size = rp.size;
    /* Real metadata from the server: the type bit from rp.type
     * (1 = FS_TYPE_FILE, 2 = FS_TYPE_DIR) OR'd with the actual permission bits
     * (rp.mode is st.mode & 07777), plus the owning uid/gid. */
    st->mode    = ((rp.type == 2) ? S_IFDIR : S_IFREG) | (rp.mode & 07777u);
    st->uid     = rp.uid;
    st->gid     = rp.gid;
    st->links   = rp.links ? rp.links : 1u;
    st->blksize = HORUS_BLOCK_SIZE;
    st->blocks  = (rp.size + (HORUS_BLOCK_SIZE - 1u)) / HORUS_BLOCK_SIZE;
    return 0;
}

int posix_stat(const char *path, posix_stat_t *st) {
    ENSURE_INIT();
    if (!st || !path) return -1;

    struct hvfs_obj o;
    char     last[FS_NAME_MAX];
    if (path_obj(path, 0, &o, last) != 0) { hvfs_release(&o); return -1; }   /* not found */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op  = FS_OP_STAT;
    rq.ino = o.ino;
    int rc = fss_rpc(&o, &rq, &rp);
    hvfs_release(&o);
    if (rc != 0) return -1;

    _umemset(st, 0, sizeof(*st));
    st->ino     = o.cap ? rp.ino : o.ino;     /* as in posix_fstat */
    st->size    = rp.size;
    st->mode    = ((rp.type == 2) ? S_IFDIR : S_IFREG) | (rp.mode & 07777u);
    st->uid     = rp.uid;
    st->gid     = rp.gid;
    st->links   = rp.links ? rp.links : 1u;
    st->blksize = HORUS_BLOCK_SIZE;
    st->blocks  = (rp.size + (HORUS_BLOCK_SIZE - 1u)) / HORUS_BLOCK_SIZE;
    return 0;
}

/* Resolve `path` to a directory inode for enumeration.
 * Returns 0 and sets *out_ino on success, -1 if the path does not resolve,
 * -2 if it resolves to something that is not a directory (ENOTDIR). */
/* Resolve `path` to a directory, as an object the caller releases. 0, -1 when
 * it is missing, -2 when it is not a directory. Confirmed before a caller
 * readdirs it: a READDIR on a regular file would just error per entry. */
static int dir_obj_at(const char *path, const struct hvfs_obj *cwd, struct hvfs_obj *o) {
    char last[FS_NAME_MAX];
    if (path_obj_at(path, cwd, 0, o, last) != 0) { hvfs_release(o); return -1; }   /* not found */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op  = FS_OP_STAT;
    rq.ino = o->ino;
    if (fss_rpc(o, &rq, &rp) != 0) { hvfs_release(o); return -1; }
    if (rp.type != FS_TYPE_DIR)    { hvfs_release(o); return -2; }
    return 0;
}

static int dir_obj(const char *path, struct hvfs_obj *o) {
    return dir_obj_at(path, &g_cwd, o);
}

/* A directory stream is a descriptor of its own (FD_DIR), because through a
 * capability the directory IS a capability, held until posix_dirclose gives it
 * back. *out_h is the handle posix_readdir and posix_dirclose take. */
int posix_diropen(const char *path, uint32_t *out_h) {
    ENSURE_INIT();
    if (!path || !out_h) return -1;

    struct hvfs_obj o;
    int r = dir_obj(path, &o);
    if (r < 0) return r;
    int fd = fd_alloc();
    if (fd < 0) { hvfs_release(&o); return -1; }
    g_fdt[fd].type  = FD_DIR;
    g_fdt[fd].flags = O_RDONLY;
    g_fdt[fd].obj   = o;
    *out_h = (uint32_t)fd;
    return 0;
}

int posix_dirclose(uint32_t h) {
    ENSURE_INIT();
    if (!fd_valid((int)h) || g_fdt[h].type != FD_DIR) return -1;
    fd_free((int)h);
    return 0;
}

/* Read the directory entry at `index` (0-based) of directory stream `h`.
 * Returns 1 and fills the non-NULL out params on success, 0 at/after the end of
 * the directory, and the server's negative SYS_ERR_* on a failure.
 *
 * THE THIRD CASE USED TO BE THE SECOND ONE. This returned 0 for end-of-directory
 * "or on any error", defended as matching POSIX because readdir(3) reports the
 * end as a NULL return. That defence is half the rule: POSIX distinguishes the
 * two through errno, which this could not do while it discarded the reason. So a
 * refused directory, a missing one, and an RPC that never reached the server all
 * became "the directory is empty" for every newlib program. readdir() in
 * newlib_glue.c maps the negative case to errno and is where the POSIX shape is
 * actually produced. The name is copied NUL-terminated into name_out, which must
 * be at least FS_NAME_MAX bytes. */
int posix_readdir(uint32_t h, uint32_t index,
                  char *name_out, uint32_t *ino_out, uint32_t *type_out) {
    ENSURE_INIT();
    if (!fd_valid((int)h) || g_fdt[h].type != FD_DIR) return SYS_ERR_INVAL;
    const struct hvfs_obj *o = &g_fdt[h].obj;

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_READDIR;
    rq.dir_ino = o->ino;
    rq.offset  = index;                 /* entry index, per fs_proto.h */

    /* END OF DIRECTORY IS ONE OUTCOME; A FAILURE IS ANOTHER.
     *
     * This used to read "a negative SYS_ERR_* past the end (NOENT) or on a
     * permission/transport failure — all 'no more entries'", and it did exactly
     * that: opendir/readdir reported an empty directory when the caller had been
     * refused, when the directory did not exist, and when the RPC had not
     * reached the server at all. POSIX distinguishes these -- readdir() returns
     * NULL for both, and the caller tells them apart with errno -- so collapsing
     * them here made that impossible for every newlib program.
     *
     * FS_RC_ENDDIR is the ordinary end and clears errno; anything else negative
     * is a failure, reported through errno with the walk stopped. See
     * include/fs_proto.h. */
    int rc = fss_rpc(o, &rq, &rp);
    if (rc == FS_RC_ENDDIR) return 0;      /* the ordinary end of the walk */
    if (rc != 0)            return rc;     /* a reason, for the caller to report */

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

    /* g_cwd_path is relative to g_cwd_base. An absolute path starts again from
     * the root, which also makes the working directory one this task can name;
     * a relative one stays below the base, ".." stopping there. */
    char norm[POSIX_PATH_MAX];
    if (cwd_normalize(path, norm) != 0) return -1;
    struct hvfs_obj base = (path[0] == '/') ? g_root : g_cwd_base;

    /* The new directory is walked from the base, never from the current
     * working directory, so the old one's capability can be given back without
     * taking the new one with it. */
    struct hvfs_obj nd;
    if (base.slot == g_root.slot) {
        if (dir_obj_at(norm, &g_root, &nd) < 0) return -1;            /* missing or not a dir */
    } else {
        if (dir_obj_at(norm[1] ? norm + 1 : ".", &base, &nd) < 0) return -1;
    }

    hvfs_release(&g_cwd);
    g_cwd      = nd;
    g_cwd_base = base;
    if (base.slot == g_root.slot) g_cwd_named = 1;
    g_cwd_ino  = nd.ino;
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
    if (!g_cwd_named) return -1;     /* below a granted directory whose name we were never told */
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

    struct hvfs_obj parent;
    char     name[FS_NAME_MAX];
    if (path_obj(path, 1, &parent, name) != 0) { hvfs_release(&parent); return SYS_ERR_NOENT; }

    uint32_t nlen = _ustrlen(name);
    if (nlen == 0 || nlen >= FS_NAME_MAX) { hvfs_release(&parent); return SYS_ERR_INVAL; }   /* refuse "/" */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_MKDIR;
    rq.dir_ino = parent.ino;
    _umemcpy(rq.name, name, nlen + 1u);
    int rc = fss_rpc(&parent, &rq, &rp);
    hvfs_release(&parent);
    return rc;
}

int posix_unlink(const char *path) {
    ENSURE_INIT();
    if (!path) return -1;

    struct hvfs_obj parent;
    char     name[FS_NAME_MAX];
    /* A path we can't resolve (bad path, missing intermediate directory, or "/"
     * itself) is a missing target — report it as SYS_ERR_NOENT so the libc
     * wrapper maps it to ENOENT rather than a transport error. */
    if (path_obj(path, 1, &parent, name) != 0) { hvfs_release(&parent); return SYS_ERR_NOENT; }

    uint32_t nlen = _ustrlen(name);
    if (nlen == 0 || nlen >= FS_NAME_MAX) { hvfs_release(&parent); return SYS_ERR_NOENT; }  /* refuse "/" */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_DELETE;
    rq.dir_ino = parent.ino;
    _umemcpy(rq.name, name, nlen + 1u);

    /* Propagate the server's rc: 0 on success, a negative SYS_ERR_* on a
     * permission / not-found / non-empty-directory refusal, or -1 on a
     * transport failure. The server is the reference monitor: it checks the
     * request against the parent's capability, or on the uid path against our
     * kernel-attested uid, so no client-side check is needed (or trusted). */
    int rc = fss_rpc(&parent, &rq, &rp);
    hvfs_release(&parent);
    return rc;
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
    rq.ino    = e->obj.ino;
    rq.offset = length;
    return fss_rpc(&e->obj, &rq, &rp) == 0 ? 0 : -1;
}

/* The inode `o` names, as the server reports it, or 0xFFFFFFFF when it will not
 * say. Only for comparing; a request never carries it through a capability. */
static uint32_t obj_id(const struct hvfs_obj *o) {
    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op  = FS_OP_STAT;
    rq.ino = o->ino;
    return fss_rpc(o, &rq, &rp) == 0 ? rp.ino : 0xFFFFFFFFu;
}

int posix_rename(const char *oldpath, const char *newpath) {
    ENSURE_INIT();
    if (!oldpath || !newpath) return SYS_ERR_INVAL;

    struct hvfs_obj op, np;
    char     oldname[FS_NAME_MAX], newname[FS_NAME_MAX];
    if (path_obj(oldpath, 1, &op, oldname) != 0) { hvfs_release(&op); return SYS_ERR_NOENT; }
    if (path_obj(newpath, 1, &np, newname) != 0) { hvfs_release(&op); hvfs_release(&np); return SYS_ERR_NOENT; }

    uint32_t olen = _ustrlen(oldname), nlen = _ustrlen(newname);
    int rc;
    if (olen == 0 || olen >= FS_NAME_MAX || nlen == 0 || nlen >= FS_NAME_MAX) {
        rc = SYS_ERR_INVAL;                                   /* refuse "/" */
    } else if (op.cap && obj_id(&op) != obj_id(&np)) {
        /* THROUGH CAPABILITIES A RENAME STAYS IN ONE DIRECTORY (S121): the
         * request goes through the old parent's capability and names no second
         * one, so two parents that are different directories are the server's
         * EXDEV, said without asking it, and the mover copies. Two walks to one
         * directory hold two capabilities, so the directories are compared by
         * the inode each reports, never by slot. */
        rc = SYS_ERR_XDEV;
    } else {
        struct fs_request rq;
        struct fs_response rp;
        _umemset(&rq, 0, sizeof(rq));
        rq.op      = FS_OP_RENAME;
        rq.dir_ino = op.ino;                     /* old parent */
        rq.ino     = np.ino;                     /* new parent (0, the same, through a capability) */
        _umemcpy(rq.name, oldname, olen + 1u);   /* old name */
        _umemcpy(rq.data, newname, nlen + 1u);   /* new name */
        rc = fss_rpc(&op, &rq, &rp);
    }
    hvfs_release(&op);
    hvfs_release(&np);
    return rc;
}

int posix_link(const char *oldpath, const char *newpath) {
    ENSURE_INIT();
    if (!oldpath || !newpath) return SYS_ERR_INVAL;
    /* A link names its source by inode, which a capability never does, so the
     * capability path has none (design §11.1, step 5 as built). */
    if (g_capmode) return SYS_ERR_XDEV;

    /* Resolve the source to an existing inode (path_obj returns 0 only when the
     * final component is found). The server re-checks it is a regular file. */
    struct hvfs_obj src, np;
    char     src_leaf[FS_NAME_MAX];
    if (path_obj(oldpath, 0, &src, src_leaf) != 0) return SYS_ERR_NOENT;

    /* Resolve the new name's parent directory + leaf. */
    char     newname[FS_NAME_MAX];
    if (path_obj(newpath, 1, &np, newname) != 0) return SYS_ERR_NOENT;
    uint32_t nlen = _ustrlen(newname);
    if (nlen == 0 || nlen >= FS_NAME_MAX) return SYS_ERR_INVAL;   /* refuse "/" as a target */

    struct fs_request rq;
    struct fs_response rp;
    _umemset(&rq, 0, sizeof(rq));
    rq.op      = FS_OP_LINK;
    rq.ino     = src.ino;                    /* source file inode */
    rq.dir_ino = np.ino;                     /* new parent dir */
    _umemcpy(rq.name, newname, nlen + 1u);   /* new name */
    return fss_rpc(&np, &rq, &rp);
}

int posix_isatty(int fd) {
    ENSURE_INIT();
    if (!fd_valid(fd)) return 0;
    return (g_fdt[fd].type == FD_CONSOLE_IN ||
            g_fdt[fd].type == FD_CONSOLE_OUT) ? 1 : 0;
}

/* ---- termios / ioctl (console raw-mode control) ---------------------------- */
/* A curses program calls tcsetattr() with canonical input and echo turned off to
 * enter full-screen mode; that is the only distinction Horus's serial console
 * makes, so we record it as g_console_raw and let read()/write() route through the
 * raw console ops. The termios struct is otherwise stored and handed back intact. */
int tcgetattr(int fd, struct termios *t) {
    ENSURE_INIT();
    if (!posix_isatty(fd) || !t) return -1;
    *t = g_con_tio;
    return 0;
}
int tcsetattr(int fd, int actions, const struct termios *t) {
    (void)actions;
    ENSURE_INIT();
    if (!posix_isatty(fd) || !t) return -1;
    g_con_tio = *t;
    g_console_raw = ((t->c_lflag & (ICANON | ECHO)) == 0) ? 1 : 0;
    return 0;
}
int tcflush(int fd, int queue) { (void)queue; return posix_isatty(fd) ? 0 : -1; }
void cfmakeraw(struct termios *t) {
    if (!t) return;
    t->c_iflag &= ~(ICRNL | INLCR | IXON | ISTRIP | BRKINT | IGNBRK);
    t->c_oflag &= ~OPOST;
    t->c_lflag &= ~(ICANON | ECHO | ECHOE | ECHONL | ISIG | IEXTEN);
    t->c_cflag |= CS8;
    t->c_cc[VMIN] = 1;
    t->c_cc[VTIME] = 0;
}
speed_t cfgetispeed(const struct termios *t) { return t->c_ispeed; }
speed_t cfgetospeed(const struct termios *t) { return t->c_ospeed; }
int cfsetispeed(struct termios *t, speed_t s) { t->c_ispeed = s; return 0; }
int cfsetospeed(struct termios *t, speed_t s) { t->c_ospeed = s; return 0; }

/* Console geometry for ioctl(TIOCGWINSZ). The single ioctl() entry point lives in
 * newlib_glue.c; it calls this for the winsize request. Returns the server's
 * reported size, or the conventional fallback if the server is unreachable. */
int posix_console_winsize(unsigned short *rows, unsigned short *cols) {
    ENSURE_INIT();
    if (!rows || !cols) return -1;
    int rc = -1;
    if (sys_console_owned()) {
        g_con_rq.magic = CON_PROTO_MAGIC;
        g_con_rq.op    = CON_OP_WINSZ;
        g_con_rq.len   = 0;
        for (int tries = 0; tries < 20000; tries++) {
            rc = sys_ipc_call(CAPSLOT_CONSOLE_EP, 0, &g_con_rq, sizeof(g_con_rq), &g_con_rp);
            if (rc >= 0) break;
            sys_yield();
        }
    }
    if (rc >= 0 && g_con_rp.magic == CON_PROTO_MAGIC && g_con_rp.rc > 0) {
        *rows = (unsigned short)((g_con_rp.rc >> 16) & 0xFFFF);
        *cols = (unsigned short)(g_con_rp.rc & 0xFFFF);
    } else {
        *rows = CON_ROWS;           /* fallback: the console's conventional size */
        *cols = CON_COLS;
    }
    return 0;
}
