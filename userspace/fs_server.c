/* Horus userspace filesystem server (Phase 2).
 *
 * A ring-3 server that implements a hierarchical, persistent filesystem on top
 * of the kernel's *encrypted* object store. All filesystem semantics — names,
 * directories, path structure — live here in userspace; the kernel only
 * provides inode allocation and encrypted (ino, block) I/O (SYS_FS_INODE_ALLOC/
 * FREE, SYS_FBLOCK_READ/WRITE, SYS_FS_STAT), keeping every AEAD key in the TCB.
 *
 * Directories are ordinary file inodes whose data is an array of `fs_dirent`
 * records (16 per 512-byte block); the root directory is inode 0. Clients reach
 * the server over IPC (endpoint slot 4) using the protocol in <fs_proto.h>.
 *
 * Limitations this increment (documented): one in-flight request at a time
 * (single-slot mailbox), and per-file ACLs are not yet enforced — access is
 * gated at the service boundary (a client must hold an endpoint capability to
 * reach the server, and only the server holds the storage capability).
 */

#include "syscall.h"
#include "fs_proto.h"

#define BLK        512u
#define DIRENTS_PER_BLK (BLK / sizeof(struct fs_dirent))   /* 16 */

/* Console output goes through SYS_WRITE (fd 1); SYS_PRINT is not dispatched. */
static void println(const char *s) { unsigned n = 0; while (s[n]) n++; sys_write(1, s, n); sys_write(1, "\n", 1); }

/* Busy-wait in ring 3 between non-blocking IPC polls so the timer can preempt
 * us and run the peer (the cooperative yield() cannot switch two ring-3 tasks). */
static void spin_delay(void) { for (volatile unsigned i = 0; i < 40000u; i++) { } }

static void umemset(void *d, int v, unsigned n) { uint8_t *p = d; while (n--) *p++ = (uint8_t)v; }
static void umemcpy(void *d, const void *s, unsigned n) { uint8_t *a = d; const uint8_t *b = s; while (n--) *a++ = *b++; }
static unsigned uslen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static int ustreq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void ustrncpy(char *d, const char *s, unsigned n) { unsigned i = 0; for (; i + 1 < n && s[i]; i++) d[i] = s[i]; d[i] = 0; }

/* Number of data blocks a directory inode currently spans. */
static unsigned dir_nblocks(uint32_t dir_ino) {
    struct fs_stat st;
    if (sys_fs_stat(dir_ino, &st) != 0) return 0;
    return (unsigned)((st.size + BLK - 1) / BLK);
}

/* Find `name` in directory `dir_ino`. On hit, fill out_ino and out_type and
 * return 1; on miss return 0. */
static int dir_find(uint32_t dir_ino, const char *name, uint32_t *out_ino, uint32_t *out_type) {
    unsigned nb = dir_nblocks(dir_ino);
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < nb; b++) {
        if (sys_fblock_read(dir_ino, b, blk) != (int)BLK) continue;
        struct fs_dirent *de = (struct fs_dirent *)blk;
        for (unsigned i = 0; i < DIRENTS_PER_BLK; i++) {
            if (de[i].ino != 0 && ustreq(de[i].name, name)) {
                if (out_ino)  *out_ino  = de[i].ino;
                if (out_type) *out_type = de[i].type;
                return 1;
            }
        }
    }
    return 0;
}

/* Insert (name, ino, type) into directory `dir_ino`, reusing a free slot or
 * appending a new block. Returns 0 on success, negative on failure. */
static int dir_add(uint32_t dir_ino, const char *name, uint32_t ino, uint32_t type) {
    unsigned nb = dir_nblocks(dir_ino);
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < nb; b++) {
        if (sys_fblock_read(dir_ino, b, blk) != (int)BLK) continue;
        struct fs_dirent *de = (struct fs_dirent *)blk;
        for (unsigned i = 0; i < DIRENTS_PER_BLK; i++) {
            if (de[i].ino == 0) {
                de[i].ino = ino; de[i].type = type;
                ustrncpy(de[i].name, name, FS_DIRENT_NAME);
                return sys_fblock_write(dir_ino, b, blk, BLK) == (int)BLK ? 0 : SYS_ERR_IO;
            }
        }
    }
    /* No free slot: append a fresh block and grow the directory's logical size
     * so dir_nblocks (and thus lookup/readdir) sees the new block. */
    umemset(blk, 0, BLK);
    struct fs_dirent *de = (struct fs_dirent *)blk;
    de[0].ino = ino; de[0].type = type;
    ustrncpy(de[0].name, name, FS_DIRENT_NAME);
    if (sys_fblock_write(dir_ino, nb, blk, BLK) != (int)BLK) return SYS_ERR_IO;
    sys_fs_set_size(dir_ino, (nb + 1) * BLK);
    return 0;
}

/* Clear the entry named `name` from directory `dir_ino`. Returns the removed
 * inode number (>0) or 0 if not found. */
static uint32_t dir_remove(uint32_t dir_ino, const char *name) {
    unsigned nb = dir_nblocks(dir_ino);
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < nb; b++) {
        if (sys_fblock_read(dir_ino, b, blk) != (int)BLK) continue;
        struct fs_dirent *de = (struct fs_dirent *)blk;
        for (unsigned i = 0; i < DIRENTS_PER_BLK; i++) {
            if (de[i].ino != 0 && ustreq(de[i].name, name)) {
                uint32_t victim = de[i].ino;
                de[i].ino = 0; de[i].type = 0; de[i].name[0] = 0;
                if (sys_fblock_write(dir_ino, b, blk, BLK) != (int)BLK) return 0;
                return victim;
            }
        }
    }
    return 0;
}

/* Return the `index`-th non-empty entry of `dir_ino` (fills ino, type, name);
 * return 1 if present, 0 past the end. */
static int dir_get(uint32_t dir_ino, uint32_t index, uint32_t *ino, uint32_t *type, char *name) {
    unsigned nb = dir_nblocks(dir_ino);
    static uint8_t blk[BLK];
    uint32_t seen = 0;
    for (unsigned b = 0; b < nb; b++) {
        if (sys_fblock_read(dir_ino, b, blk) != (int)BLK) continue;
        struct fs_dirent *de = (struct fs_dirent *)blk;
        for (unsigned i = 0; i < DIRENTS_PER_BLK; i++) {
            if (de[i].ino == 0) continue;
            if (seen == index) {
                *ino = de[i].ino; *type = de[i].type;
                ustrncpy(name, de[i].name, FS_NAME_MAX);
                return 1;
            }
            seen++;
        }
    }
    return 0;
}

static void handle(const struct fs_request *rq, struct fs_response *rp) {
    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;

    if (rq->magic != FS_PROTO_MAGIC) { rp->rc = SYS_ERR_INVAL; return; }

    switch (rq->op) {
    case FS_OP_LOOKUP: {
        uint32_t ino, type;
        if (dir_find(rq->dir_ino, rq->name, &ino, &type)) { rp->rc = 0; rp->ino = ino; rp->type = type; }
        else rp->rc = SYS_ERR_NOENT;
        break;
    }
    case FS_OP_CREATE:
    case FS_OP_MKDIR: {
        if (rq->name[0] == 0 || uslen(rq->name) >= FS_DIRENT_NAME) { rp->rc = SYS_ERR_INVAL; break; }
        if (dir_find(rq->dir_ino, rq->name, 0, 0)) { rp->rc = SYS_ERR_INVAL; break; }  /* exists */
        uint32_t type = (rq->op == FS_OP_MKDIR) ? FS_TYPE_DIR : FS_TYPE_FILE;
        int ino = sys_fs_inode_alloc(type);
        if (ino < 0) { rp->rc = ino; break; }
        int rc = dir_add(rq->dir_ino, rq->name, (uint32_t)ino, type);
        if (rc != 0) { sys_fs_inode_free((uint32_t)ino); rp->rc = rc; break; }
        rp->rc = 0; rp->ino = (uint32_t)ino; rp->type = type;
        break;
    }
    case FS_OP_DELETE: {
        uint32_t ino, type;
        if (!dir_find(rq->dir_ino, rq->name, &ino, &type)) { rp->rc = SYS_ERR_NOENT; break; }
        /* Refuse to delete a non-empty directory. */
        if (type == FS_TYPE_DIR) {
            uint32_t cino, ctype; char cname[FS_NAME_MAX];
            if (dir_get(ino, 0, &cino, &ctype, cname)) { rp->rc = SYS_ERR_INVAL; break; }
        }
        if (dir_remove(rq->dir_ino, rq->name) == 0) { rp->rc = SYS_ERR_NOENT; break; }
        sys_fs_inode_free(ino);
        rp->rc = 0;
        break;
    }
    case FS_OP_READDIR: {
        uint32_t ino, type; char name[FS_NAME_MAX];
        if (dir_get(rq->dir_ino, rq->offset, &ino, &type, name)) {
            rp->rc = 0; rp->ino = ino; rp->type = type;
            ustrncpy(rp->name, name, FS_NAME_MAX);
        } else rp->rc = SYS_ERR_NOENT;   /* past end */
        break;
    }
    case FS_OP_STAT: {
        struct fs_stat st;
        if (sys_fs_stat(rq->ino, &st) != 0) { rp->rc = SYS_ERR_NOENT; break; }
        rp->rc = 0; rp->type = st.type; rp->size = (uint32_t)st.size;
        break;
    }
    case FS_OP_READ: {
        struct fs_stat st;
        if (sys_fs_stat(rq->ino, &st) != 0) { rp->rc = SYS_ERR_NOENT; break; }
        if (rq->offset >= st.size) { rp->rc = 0; rp->size = 0; break; }   /* EOF */
        uint32_t blk = rq->offset / BLK, boff = rq->offset % BLK;
        static uint8_t tmp[BLK];
        if (sys_fblock_read(rq->ino, blk, tmp) != (int)BLK) { rp->rc = SYS_ERR_IO; break; }
        uint32_t avail = (uint32_t)st.size - rq->offset;
        uint32_t n = rq->len;
        if (n > FS_IO_MAX) n = FS_IO_MAX;
        if (n > BLK - boff) n = BLK - boff;
        if (n > avail) n = avail;
        umemcpy(rp->data, tmp + boff, n);
        rp->rc = (int32_t)n; rp->size = n;
        break;
    }
    case FS_OP_WRITE: {
        uint32_t len = rq->len;
        if (len > FS_IO_MAX) len = FS_IO_MAX;
        uint32_t blk = rq->offset / BLK, boff = rq->offset % BLK;
        if (boff + len > BLK) len = BLK - boff;   /* one block per request */
        static uint8_t tmp[BLK];
        /* Read-modify-write to preserve the rest of the block (hole => zeros). */
        if (sys_fblock_read(rq->ino, blk, tmp) != (int)BLK) umemset(tmp, 0, BLK);
        umemcpy(tmp + boff, rq->data, len);
        if (sys_fblock_write(rq->ino, blk, tmp, BLK) != (int)BLK) { rp->rc = SYS_ERR_IO; break; }
        /* Extend the logical file size if this write went past the old end
         * (the kernel only stores fixed-size blocks; size is ours to track). */
        struct fs_stat st;
        uint32_t end = rq->offset + len;
        if (sys_fs_stat(rq->ino, &st) == 0 && end > (uint32_t)st.size) sys_fs_set_size(rq->ino, end);
        rp->rc = (int32_t)len;
        break;
    }
    default:
        rp->rc = SYS_ERR_NOSYS;
        break;
    }
}

void _start(void) {
    println("[fs_server] userspace FS server starting (encrypted object store).");

    /* Registration is best-effort: it publishes the service for clients that
     * discover it via sys_connect_fs_server, but the request/reply endpoints
     * themselves are the well-known FS_EP_REQ / FS_EP_REP. */
    if (sys_register_fs_server(FS_EP_REQ) == 0) {
        println("[fs_server] registered; serving on endpoints 4 (req) / 5 (rep).");
    } else {
        println("[fs_server] warning: registration failed; serving anyway.");
    }

    struct fs_request  rq;
    struct fs_response rp;
    for (;;) {
        int r = sys_ipc_recv(FS_EP_REQ, (char *)&rq, sizeof(rq));
        if (r < 0) { spin_delay(); continue; }          /* no request yet */
        handle(&rq, &rp);
        while (sys_ipc_reply(FS_EP_REP, (const char *)&rp, sizeof(rp)) < 0) spin_delay();
    }
}
