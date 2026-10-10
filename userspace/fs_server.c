/* Horus userspace filesystem server (Phase 2).
 *
 * A ring-3 server that implements a hierarchical, persistent filesystem on top
 * of the kernel's *encrypted* object store. All filesystem semantics — names,
 * directories, path structure — live here in userspace; the kernel only
 * provides inode allocation and encrypted (ino, block) I/O (SYS_FS_INODE_ALLOC/
 * FREE, SYS_FBLOCK_READ/WRITE, SYS_FS_STAT), keeping every AEAD key in the TCB.
 *
 * Directories are ordinary file inodes whose data is an array of `fs_dirent`
 * records (BLK/32 per block); the root directory is inode 0. Clients reach
 * the server over IPC (endpoint slot 4) using the protocol in <fs_proto.h>.
 *
 * Access control: this server is the filesystem reference monitor. Every request
 * is checked against the caller's KERNEL-ATTESTED identity — the uid/gid the
 * kernel recorded for the sending task at login (SYS_IPC_SENDER), not anything
 * the client puts in the message — using POSIX owner/group/other permission bits
 * and ownership stamped on the creator; root (uid 0) is the only ambient
 * authority. A client cannot forge who it is, cannot reach the store directly
 * (only this server holds the storage capability), and cannot bypass the checks.
 *
 * Limitations this increment (documented): one in-flight request at a time
 * (single-slot mailbox).
 */

#include "syscall.h"
#include "fs_proto.h"
#include "libhorus.h"

#include "block_size.h"
/* NOT a private constant: the kernel hands back HORUS_BLOCK_SIZE bytes from
 * SYS_FBLOCK_READ, so a local guess here is a buffer overrun waiting for the
 * kernel to change. It did, on 2026-08-31. */
#define BLK        HORUS_BLOCK_SIZE
#define DIRENTS_PER_BLK (BLK / sizeof(struct fs_dirent))   /* 16 */

/* Console output goes through SYS_WRITE (fd 1); SYS_PRINT is not dispatched. */

/* Busy-wait in ring 3 between non-blocking IPC polls so the timer can preempt
 * us and run the peer (the cooperative yield() cannot switch two ring-3 tasks). */


/* A DIRECTORY OPERAND MUST BE A DIRECTORY (S113, [HORUS-20261008-01]).
 *
 * A directory here is an array of fs_dirent records in ordinary inode data, and
 * a regular file's bytes are written by its owner. So the only thing that makes
 * a block of bytes a set of directory entries is the inode's TYPE, and until
 * 2026-10-08 nothing checked it: LOOKUP, CREATE, MKDIR, DELETE, READDIR and
 * RENAME each checked the caller's permission on the operand and then read it
 * as dirents. A user who owns a file (any user, in their home) could write a
 * forged entry {ino = root's /bin/ls, type = FILE} into it, pass the file as the
 * directory, and DELETE the entry: this server then freed root's inode, since
 * the kernel honours SYS_FS_INODE_FREE from the store's holder for any inode but
 * the root. The forged FILE type also skipped the not-empty check, so /bin
 * itself could be freed; the lowest-free allocator then gave its number to the
 * user's next mkdir, which root's dirent "bin" still named.
 *
 * Checked twice, on purpose. Each request refuses a non-directory operand with
 * SYS_ERR_INVAL, after its permission check so the refusal tells no one the type
 * of an inode they may not look at. And the dirent helpers below refuse one
 * themselves, so a caller added later cannot read a file as a directory by
 * forgetting: by construction, not by remembering.
 *
 * FS_DIR_OPERAND_UNCHECKED=1 restores the unchecked server, both places; it is
 * the control arm for make smoke-fs-dir-operand. FS_OP_LINK's own type check
 * predates this and is not part of the arm. */
static int is_dir(const struct fs_stat *st) {
#ifdef FS_DIR_OPERAND_UNCHECKED
    (void)st;
    return 1;
#else
    return st->type == FS_TYPE_DIR;
#endif
}

/* Number of data blocks a directory inode currently spans, or -1 if `dir_ino`
 * cannot be read or is not a directory (see is_dir). */
static int dir_nblocks(uint32_t dir_ino) {
    struct fs_stat st;
    if (sys_fs_stat(dir_ino, &st) != 0) return -1;
    if (!is_dir(&st)) return -1;
    return (int)((st.size + BLK - 1) / BLK);
}

/* Find `name` in directory `dir_ino`. On hit, fill out_ino and out_type and
 * return 1; on miss return 0. */
static int dir_find(uint32_t dir_ino, const char *name, uint32_t *out_ino, uint32_t *out_type) {
    int nb = dir_nblocks(dir_ino);
    if (nb < 0) return 0;                              /* not a directory: no entries */
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < (unsigned)nb; b++) {
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
    int nb = dir_nblocks(dir_ino);
    if (nb < 0) return SYS_ERR_INVAL;                  /* never write a dirent into a file */
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < (unsigned)nb; b++) {
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
    if (sys_fblock_write(dir_ino, (unsigned)nb, blk, BLK) != (int)BLK) return SYS_ERR_IO;
    sys_fs_set_size(dir_ino, ((unsigned)nb + 1) * BLK);
    return 0;
}

/* Clear the entry named `name` from directory `dir_ino`. Returns the removed
 * inode number (>0) or 0 if not found. */
static uint32_t dir_remove(uint32_t dir_ino, const char *name) {
    int nb = dir_nblocks(dir_ino);
    if (nb < 0) return 0;                              /* not a directory: nothing removed */
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < (unsigned)nb; b++) {
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

/* Does directory `dir_ino` hold an entry naming inode `ino`? */
static int dir_holds(uint32_t dir_ino, uint32_t ino) {
    int nb = dir_nblocks(dir_ino);
    if (nb < 0) return 0;
    static uint8_t blk[BLK];
    for (unsigned b = 0; b < (unsigned)nb; b++) {
        if (sys_fblock_read(dir_ino, b, blk) != (int)BLK) continue;
        struct fs_dirent *de = (struct fs_dirent *)blk;
        for (unsigned i = 0; i < DIRENTS_PER_BLK; i++)
            if (de[i].ino == ino) return 1;
    }
    return 0;
}

/* ---- cross-directory moves (S121; docs/design/filesystem.md §5.5, decision 11) ----
 *
 * Rights come from the path, so moving an object changes who may do what to it:
 * a task holding DELETE on /etc and write on its own home could move a file out
 * of /etc and write to it. §5.5's rule needs every object's back-references,
 * which arrive with the v12 format in phase 3. Until then a rename or link that
 * would give an object a name in a second directory is refused with EXDEV, on
 * every path, and a mover copies instead: a copy is a new object made with
 * rights the mover already held. True when the request crosses directories. */
static int fs_xdev(int crosses) {
#ifdef FS_XDEV_UNCHECKED
    /* CONTROL ARM, never ship (smoke-fs-cap-xdev-control): a move across
     * directories goes through. */
    (void)crosses;
    return 0;
#else
    return crosses;
#endif
}

/* Return the `index`-th non-empty entry of `dir_ino` (fills ino, type, name);
 * return 1 if present, 0 past the end. */
static int dir_get(uint32_t dir_ino, uint32_t index, uint32_t *ino, uint32_t *type, char *name) {
    int nb = dir_nblocks(dir_ino);
    if (nb < 0) return 0;                              /* not a directory: no entries */
    static uint8_t blk[BLK];
    uint32_t seen = 0;
    for (unsigned b = 0; b < (unsigned)nb; b++) {
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

/* Truncate file `ino` from `oldlen` to `newlen` bytes. On a shrink we must zero
 * the truncated range in the blocks that are still allocated: h_fs_set_size only
 * rewrites the inode's size field, so without this a later grow (a write past
 * newlen) would read-modify-write a block still holding the old bytes and leak
 * them back — a correctness AND stale-data-disclosure bug. Unallocated blocks
 * (holes) are left as holes. Returns 0 or a negative SYS_ERR_*. */
static int file_truncate(uint32_t ino, uint32_t newlen, uint32_t oldlen) {
    if (newlen < oldlen) {
        static uint8_t tmp[BLK];
        uint32_t fb = newlen / BLK;              /* first block touched */
        uint32_t lb = (oldlen - 1) / BLK;        /* last allocated block (oldlen>=1 here) */
        for (uint32_t b = fb; b <= lb; b++) {
            if (sys_fblock_read(ino, b, tmp) != (int)BLK) continue;   /* hole: nothing to clear */
            uint32_t z0 = (b == fb) ? (newlen % BLK) : 0;             /* zero from here to block end */
            umemset(tmp + z0, 0, BLK - z0);
            if (sys_fblock_write(ino, b, tmp, BLK) != (int)BLK) return SYS_ERR_IO;
        }
    }
    return sys_fs_set_size(ino, newlen) == 0 ? 0 : SYS_ERR_IO;
}

/* Permission bits (owner/group/other rwx). */
#define P_R 4u
#define P_X 1u
#define P_W 2u

/* POSIX owner/group/other check of `want` (an rwx mask) against the caller's
 * KERNEL-ATTESTED (cuid, cgid) — never an identity from the request. Root
 * (uid 0) always passes; this is the only ambient authority, matching the rest
 * of the kernel's uid==0 admin model. */
/* Set while a CAPABILITY-ADDRESSED request is being served (cap_request): its
 * rights were already checked against the invoking capability, which the kernel
 * attests, so the uid check below has nothing to add (docs/design/filesystem.md
 * §5, phase 1b step 1). The uid path is untouched for every other request. */
static int g_by_cap;

static int perm_ok(const struct fs_stat *st, uint32_t cuid, uint32_t cgid, unsigned want) {
    if (g_by_cap) return 1;                        /* the capability already said */
    if (cuid == 0) return 1;                       /* superuser */
    unsigned bits;
    if      (cuid == st->uid) bits = (unsigned)(st->mode >> 6) & 7u;   /* owner */
    else if (cgid == st->gid) bits = (unsigned)(st->mode >> 3) & 7u;   /* group */
    else                      bits = (unsigned)(st->mode) & 7u;        /* other */
    return (bits & want) == want;
}

/* ---- token generations (docs/design/filesystem.md §5.2) --------------------
 *
 * A capability names an inode by number and generation. Inode numbers are reused
 * on this format, so every time a name to an inode is removed its generation goes
 * up, and a capability minted before that no longer matches: it is refused NOENT
 * and never falls through to whatever now occupies the number. Kept in memory,
 * since capabilities do not outlive a boot. An inode whose generation would wrap
 * is retired (FS_GEN_RETIRED) and refused on this path until the next boot. */
#define FS_GEN_INODES   (1u << 17)          /* a 16 GiB volume has 131072 inodes */
#define FS_GEN_RETIRED  0x80000000u
static uint32_t g_gen[FS_GEN_INODES];

static void fs_retire(uint32_t ino)
{
    if (ino >= FS_GEN_INODES || (g_gen[ino] & FS_GEN_RETIRED)) return;
    if (g_gen[ino] >= FS_TOKEN_GEN_MASK) g_gen[ino] = FS_GEN_RETIRED;
    else g_gen[ino]++;
}

/* Every free goes through here, so no path can drop a name without staling the
 * capabilities that named it. */
static void fs_ino_free(uint32_t ino)
{
    sys_fs_inode_free(ino);
    fs_retire(ino);
}

/* ---- the system trees (S116) ---------------------------------------------
 *
 * /bin, /sbin, /lib, /usr, /usr/share, /usr/share/man and /usr/share/doc hold
 * EXACTLY the boot modules the kernel verified against the manifest pinned in
 * its measured image (S96): provision_boot_modules rebuilds them from those
 * modules at every boot, replacing any file whose bytes differ and removing
 * anything that is not a module, and from then until the next boot no client
 * may change them -- root included, because authority by identity is what the
 * system exists not to grant (the maintainer's answer, 2026-10-08). An update
 * is new install media, not a write.
 *
 * WHY HERE AND NOT IN THE LOADER. The roadmap's rule is that running programs
 * from the disk must never exist without a manifest check. The kernel cannot
 * make that check yet: it is handed a program's bytes, not its path, and a
 * user's own programs under /home may run (filesystem decision 8). So the
 * guarantee is placed where it can be kept today: what the system trees HOLD.
 * A task can still spawn bytes it has from anywhere; docs/LIMITATIONS.md says
 * so, and exec by file capability (filesystem phase 1b) is what closes it.
 *
 * BY INODE, NOT BY PATH. Requests name inodes, so the trees' inodes are what is
 * recorded, at provisioning, and every request that would change one of them,
 * or a directory entry inside one, is refused before its permission check
 * (system_tree_refuses). A hard link out of a tree is refused too: the inode
 * behind it is rebuilt at the next boot, and a second name would dangle. */
#define SYS_INODES_MAX 512
static uint32_t g_sys_ino[SYS_INODES_MAX];
static unsigned g_sys_n;

static void sys_mark(uint32_t ino) {
    for (unsigned i = 0; i < g_sys_n; i++) if (g_sys_ino[i] == ino) return;
    if (g_sys_n < SYS_INODES_MAX) g_sys_ino[g_sys_n++] = ino;
}
static int is_sys(uint32_t ino) {
    for (unsigned i = 0; i < g_sys_n; i++) if (g_sys_ino[i] == ino) return 1;
    return 0;
}
/* The entry `name` in `dir`, if it is a system inode. */
static int entry_is_sys(uint32_t dir, const char *name) {
    uint32_t ino, type;
    return dir_find(dir, name, &ino, &type) && is_sys(ino);
}

/* Would this request change a system tree? Checked before every permission
 * check, so the answer is the same for every caller. */
static int system_tree_refuses(const struct fs_request *rq) {
#ifdef SYSTEM_TREES_WRITABLE
    /* CONTROL ARM -- never ship. The trees are as writable as their modes say,
     * which for root is entirely. See make smoke-system-trees-control. */
    (void)rq;
    return 0;
#else
    switch (rq->op) {
    case FS_OP_CREATE:
    case FS_OP_MKDIR:
        return is_sys(rq->dir_ino);
    case FS_OP_DELETE:
        return is_sys(rq->dir_ino) || entry_is_sys(rq->dir_ino, rq->name);
    case FS_OP_LINK:
        return is_sys(rq->dir_ino) || is_sys(rq->ino);
    case FS_OP_RENAME: {
        char newname[FS_DIRENT_NAME];
        ustrncpy(newname, (const char *)rq->data, FS_DIRENT_NAME);
        return is_sys(rq->dir_ino) || is_sys(rq->ino) ||
               entry_is_sys(rq->dir_ino, rq->name) || entry_is_sys(rq->ino, newname);
    }
    case FS_OP_WRITE:
    case FS_OP_APPEND:
    case FS_OP_TRUNCATE:
    case FS_OP_CHMOD:
    case FS_OP_CHOWN:
        return is_sys(rq->ino);
    default:
        return 0;            /* lookup, read, stat, readdir: reading is not changing */
    }
#endif
}

/* Enforce access to an already-existing object, then dispatch. cuid/cgid are the
 * caller's kernel-attested identity; the request body carries none. */
static void handle(const struct fs_request *rq, struct fs_response *rp,
                   uint32_t cuid, uint32_t cgid) {
    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;

    if (rq->magic != FS_PROTO_MAGIC) { rp->rc = SYS_ERR_INVAL; return; }
    if (system_tree_refuses(rq))     { rp->rc = SYS_ERR_PERM;  return; }   /* S116 */

    struct fs_stat st;

    switch (rq->op) {
    case FS_OP_LOOKUP: {
        if (sys_fs_stat(rq->dir_ino, &st) != 0)      { rp->rc = SYS_ERR_NOENT; break; }
        if (!perm_ok(&st, cuid, cgid, P_X))          { rp->rc = SYS_ERR_PERM;  break; }  /* search the dir */
        if (!is_dir(&st))                            { rp->rc = SYS_ERR_INVAL; break; }  /* see is_dir */
        uint32_t ino, type;
        if (dir_find(rq->dir_ino, rq->name, &ino, &type)) { rp->rc = 0; rp->ino = ino; rp->type = type; }
        else rp->rc = SYS_ERR_NOENT;
        break;
    }
    case FS_OP_CREATE:
    case FS_OP_MKDIR: {
        if (sys_fs_stat(rq->dir_ino, &st) != 0)      { rp->rc = SYS_ERR_NOENT; break; }
        if (!perm_ok(&st, cuid, cgid, P_W))          { rp->rc = SYS_ERR_PERM;  break; }  /* modify the dir */
        if (!is_dir(&st))                            { rp->rc = SYS_ERR_INVAL; break; }  /* see is_dir */
        if (rq->name[0] == 0 || uslen(rq->name) >= FS_DIRENT_NAME) { rp->rc = SYS_ERR_INVAL; break; }
        /* EXIST, not INVAL. The code is the only thing a client can report a
         * reason from, and a name that is taken is not a name that is malformed:
         * collapsing the two left the shell unable to say which, so it said
         * both and hedged. See fs_reason() in userspace/shell.c. */
        if (dir_find(rq->dir_ino, rq->name, 0, 0))   { rp->rc = SYS_ERR_EXIST; break; }  /* exists */
        uint32_t type = (rq->op == FS_OP_MKDIR) ? FS_TYPE_DIR : FS_TYPE_FILE;
        int ino = sys_fs_inode_alloc(type);
        if (ino < 0) { rp->rc = ino; break; }
        /* Stamp ownership on the kernel-attested creator with default perms
         * (dir 0755, file 0644). The inode is not yet linked into any directory,
         * so this brief window is invisible to other clients. */
        sys_fs_set_meta((uint32_t)ino, (type == FS_TYPE_DIR) ? 0755u : 0644u, cuid, cgid);
        int rc = dir_add(rq->dir_ino, rq->name, (uint32_t)ino, type);
        if (rc != 0) { fs_ino_free((uint32_t)ino); rp->rc = rc; break; }
        rp->rc = 0; rp->ino = (uint32_t)ino; rp->type = type;
        break;
    }
    case FS_OP_DELETE: {
        if (sys_fs_stat(rq->dir_ino, &st) != 0)      { rp->rc = SYS_ERR_NOENT; break; }
        if (!perm_ok(&st, cuid, cgid, P_W))          { rp->rc = SYS_ERR_PERM;  break; }  /* modify the dir */
        if (!is_dir(&st))                            { rp->rc = SYS_ERR_INVAL; break; }  /* see is_dir */
        uint32_t ino, type;
        if (!dir_find(rq->dir_ino, rq->name, &ino, &type)) { rp->rc = SYS_ERR_NOENT; break; }
        /* Refuse to delete a non-empty directory. */
        if (type == FS_TYPE_DIR) {
            uint32_t cino, ctype; char cname[FS_NAME_MAX];
            /* BUSY: a directory with children is not an invalid argument, it is
             * a directory in use. POSIX spells this ENOTEMPTY; the shared table
             * has no such code, and BUSY is the one that lets a client say
             * something true rather than something generic. */
            if (dir_get(ino, 0, &cino, &ctype, cname)) { rp->rc = SYS_ERR_BUSY; break; }
        }
        if (dir_remove(rq->dir_ino, rq->name) == 0) { rp->rc = SYS_ERR_NOENT; break; }
        fs_ino_free(ino);     /* drops one link; frees only when the last name is gone */
        rp->rc = 0;
        break;
    }
    case FS_OP_LINK: {
        /* Hard-link: give the existing regular file `rq->ino` a second name
         * `rq->name` in dir `rq->dir_ino`. Needs write on the new parent dir; the
         * caller must own the source (or be root), since a link bumps the file's
         * on-disk link count — an owner-or-root gate keeps a client from pinning
         * or exposing an inode it has no claim to by guessing its number. A later
         * unlink of either name only frees the file once the last name is gone. */
        if (sys_fs_stat(rq->dir_ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
        if (st.type != FS_TYPE_DIR)                      { rp->rc = SYS_ERR_INVAL; break; }
        if (!perm_ok(&st, cuid, cgid, P_W))              { rp->rc = SYS_ERR_PERM;  break; }  /* modify the dir */
        if (rq->name[0] == 0 || uslen(rq->name) >= FS_DIRENT_NAME) { rp->rc = SYS_ERR_INVAL; break; }
        if (dir_find(rq->dir_ino, rq->name, 0, 0))       { rp->rc = SYS_ERR_EXIST; break; }  /* name exists */
        struct fs_stat sst;
        if (sys_fs_stat(rq->ino, &sst) != 0)             { rp->rc = SYS_ERR_NOENT; break; }  /* source inode */
        if (sst.type != FS_TYPE_FILE)                    { rp->rc = SYS_ERR_INVAL; break; }  /* no dir/other links */
        if (!(cuid == 0 || cuid == sst.uid))             { rp->rc = SYS_ERR_PERM;  break; }  /* owner or root */
        /* The second name goes beside a name the file already has, never into
         * another directory (decision 11). v11 keeps no back-references, so
         * "the directory it is in" can only be answered this way. */
        if (fs_xdev(!dir_holds(rq->dir_ino, rq->ino)))   { rp->rc = SYS_ERR_XDEV;  break; }
        if (sys_fs_inode_link(rq->ino) != 0)             { rp->rc = SYS_ERR_IO;    break; }  /* ++links */
        int rc = dir_add(rq->dir_ino, rq->name, rq->ino, FS_TYPE_FILE);
        if (rc != 0) { fs_ino_free(rq->ino); rp->rc = rc; break; }   /* undo the ++links */
        rp->rc = 0; rp->ino = rq->ino; rp->type = FS_TYPE_FILE;
        break;
    }
    case FS_OP_READDIR: {
        /* THE REASON IS PASSED THROUGH, NOT FLATTENED TO NOENT.
         *
         * This read `!= 0 -> SYS_ERR_NOENT`, and h_fs_stat has two distinct
         * failures: SYS_ERR_INVAL when the store is not open -- a SEALED volume,
         * which is every ATA machine from power-on until a login unlocks it --
         * and SYS_ERR_NOENT when the inode itself cannot be read. Flattening
         * them meant a caller walking the root of a sealed volume was told
         * "no such directory", which the shell's `ls` in turn read as
         * end-of-directory, and printed nothing at all with no error. A locked
         * store reported itself as an empty filesystem.
         *
         * That is the whole path behind a `ls` that returns nothing on a real
         * installed disk, and none of the three steps looked wrong on its own.
         * See FS_RC_ENDDIR in include/fs_proto.h. */
        int strc = sys_fs_stat(rq->dir_ino, &st);
#ifdef READDIR_END_IS_NOENT
        if (strc != 0) { rp->rc = SYS_ERR_NOENT; break; }
#else
        if (strc != 0) { rp->rc = strc; break; }
#endif
        if (!perm_ok(&st, cuid, cgid, P_R))          { rp->rc = SYS_ERR_PERM;  break; }  /* read the dir */
        if (!is_dir(&st))                            { rp->rc = SYS_ERR_INVAL; break; }  /* see is_dir */
        uint32_t ino, type; char name[FS_NAME_MAX];
        if (dir_get(rq->dir_ino, rq->offset, &ino, &type, name)) {
            rp->rc = 0; rp->ino = ino; rp->type = type;
            ustrncpy(rp->name, name, FS_NAME_MAX);
        } else {
            /* PAST THE END, which is not the same fact as the sys_fs_stat
             * failure above and no longer shares a code with it. Both answered
             * SYS_ERR_NOENT until 2026-09-06, so a caller could not tell a
             * directory it had read to the end from one it could not read at
             * all -- and all three callers in the tree guessed "end", which is
             * fail-open for a listing. See FS_RC_ENDDIR in include/fs_proto.h.
             *
             * READDIR_END_IS_NOENT=1 restores the overload; it is the control
             * arm for make smoke-readdir-end. */
#ifdef READDIR_END_IS_NOENT
            rp->rc = SYS_ERR_NOENT;
#else
            rp->rc = FS_RC_ENDDIR;
#endif
        }
        break;
    }
    case FS_OP_STAT: {
        if (sys_fs_stat(rq->ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
        /* Metadata is visible to root, the owner, or anyone who can read it. */
        if (!(cuid == st.uid || perm_ok(&st, cuid, cgid, P_R))) { rp->rc = SYS_ERR_PERM; break; }
        rp->rc = 0; rp->type = st.type; rp->size = (uint32_t)st.size;
        rp->mode = st.mode & 07777u; rp->uid = st.uid; rp->gid = st.gid;
        rp->links = st.links;
        break;
    }
    case FS_OP_READ: {
        if (sys_fs_stat(rq->ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
        if (!perm_ok(&st, cuid, cgid, P_R))          { rp->rc = SYS_ERR_PERM;  break; }
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
    case FS_OP_APPEND:
    case FS_OP_WRITE: {
        if (sys_fs_stat(rq->ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
        if (st.type == FS_TYPE_DIR)                  { rp->rc = SYS_ERR_INVAL; break; }  /* files only */
        if (!perm_ok(&st, cuid, cgid, P_W))          { rp->rc = SYS_ERR_PERM;  break; }
        /* O_APPEND: the offset is the current end of file, chosen here rather
         * than by the client. We already hold the size from the stat above and
         * nothing else runs between it and the write, so the append cannot land
         * on top of another client's. */
        uint32_t off = (rq->op == FS_OP_APPEND) ? (uint32_t)st.size : rq->offset;
        uint32_t len = rq->len;
        if (len > FS_IO_MAX) len = FS_IO_MAX;
        uint32_t blk = off / BLK, boff = off % BLK;
        if (boff + len > BLK) len = BLK - boff;   /* one block per request */
        static uint8_t tmp[BLK];
        /* Read-modify-write to preserve the rest of the block (hole => zeros). */
        if (sys_fblock_read(rq->ino, blk, tmp) != (int)BLK) umemset(tmp, 0, BLK);
        umemcpy(tmp + boff, rq->data, len);
        if (sys_fblock_write(rq->ino, blk, tmp, BLK) != (int)BLK) { rp->rc = SYS_ERR_IO; break; }
        /* Extend the logical file size if this write went past the old end
         * (the kernel only stores fixed-size blocks; size is ours to track). */
        uint32_t end = off + len;
        if (end > (uint32_t)st.size) sys_fs_set_size(rq->ino, end);
        rp->rc   = (int32_t)len;
        rp->size = end;          /* so the client can track its offset */
        break;
    }
    /* THE TWO METADATA RULES ARE DIFFERENT ON PURPOSE, and each has a control
     * arm of its own (FS_CHMOD_ANY_OWNER=1, FS_CHOWN_ANY_UID=1) because an arm
     * against one says nothing about the other. Changing a mode is something an
     * owner does to their own file; giving a file AWAY is not, so chown is
     * root-only -- an owner who could hand a file to another uid could leave an
     * object under a name that account is answerable for, and an owner who could
     * TAKE one could help themselves to anything readable. Both checks are made
     * against `cuid`, which is SYS_IPC_SENDER's kernel-attested uid and never a
     * field of the request. Until 2026-09-02 neither had a ring-3 caller at all:
     * the operations existed, the shell had no command for them, and nothing in
     * the tree had ever exercised either rule from a real login. */
    case FS_OP_CHMOD: {
        if (sys_fs_stat(rq->ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
#ifndef FS_CHMOD_ANY_OWNER
        if (!(cuid == 0 || cuid == st.uid))          { rp->rc = SYS_ERR_PERM;  break; }  /* owner or root */
#endif
        if (sys_fs_set_meta(rq->ino, rq->mode & 07777u, st.uid, st.gid) != 0) { rp->rc = SYS_ERR_IO; break; }
        rp->rc = 0;
        break;
    }
    case FS_OP_CHOWN: {
        if (sys_fs_stat(rq->ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
#ifndef FS_CHOWN_ANY_UID
        if (cuid != 0)                               { rp->rc = SYS_ERR_PERM;  break; }  /* only root may chown */
#endif
        if (sys_fs_set_meta(rq->ino, st.mode & 07777u, rq->arg_uid, rq->arg_gid) != 0) { rp->rc = SYS_ERR_IO; break; }
        rp->rc = 0;
        break;
    }
    case FS_OP_TRUNCATE: {
        if (sys_fs_stat(rq->ino, &st) != 0)          { rp->rc = SYS_ERR_NOENT; break; }
        if (st.type == FS_TYPE_DIR)                  { rp->rc = SYS_ERR_INVAL; break; }  /* files only */
        if (!perm_ok(&st, cuid, cgid, P_W))          { rp->rc = SYS_ERR_PERM;  break; }
        rp->rc = file_truncate(rq->ino, rq->offset, (uint32_t)st.size);
        break;
    }
    case FS_OP_RENAME: {
        /* Field mapping: dir_ino = old parent, name = old name,
         *                ino     = new parent, data = new name. */
        uint32_t old_parent = rq->dir_ino, new_parent = rq->ino;
        struct fs_stat sp, sq;
        if (sys_fs_stat(old_parent, &sp) != 0)       { rp->rc = SYS_ERR_NOENT; break; }
        if (sys_fs_stat(new_parent, &sq) != 0)       { rp->rc = SYS_ERR_NOENT; break; }
        if (!perm_ok(&sp, cuid, cgid, P_W) ||
            !perm_ok(&sq, cuid, cgid, P_W))          { rp->rc = SYS_ERR_PERM;  break; }  /* modify both dirs */
        if (!is_dir(&sp) || !is_dir(&sq))            { rp->rc = SYS_ERR_INVAL; break; }  /* see is_dir */
        if (fs_xdev(old_parent != new_parent))       { rp->rc = SYS_ERR_XDEV;  break; }  /* decision 11 */

        /* Copy and validate the new name out of data[] (NUL-bounded). */
        char newname[FS_DIRENT_NAME];
        ustrncpy(newname, (const char *)rq->data, FS_DIRENT_NAME);
        if (rq->name[0] == 0 || newname[0] == 0 ||
            uslen((const char *)rq->data) >= FS_DIRENT_NAME) { rp->rc = SYS_ERR_INVAL; break; }

        uint32_t src_ino, src_type;
        if (!dir_find(old_parent, rq->name, &src_ino, &src_type)) { rp->rc = SYS_ERR_NOENT; break; }

        /* No-op: same directory, same name. */
        if (old_parent == new_parent && ustreq(rq->name, newname)) { rp->rc = 0; break; }

        /* A directory may only be renamed within its own parent — a cross-parent
         * move could form a cycle, which the flat dirent store can't detect
         * without a parent walk. Files may move anywhere. */
        if (src_type == FS_TYPE_DIR && old_parent != new_parent) { rp->rc = SYS_ERR_INVAL; break; }

        /* If the target name already exists, POSIX rename replaces it. */
        uint32_t dst_ino, dst_type;
        if (dir_find(new_parent, newname, &dst_ino, &dst_type)) {
            if (dst_ino != src_ino) {
                if (dst_type == FS_TYPE_DIR) {   /* refuse to clobber a non-empty dir */
                    uint32_t cino, ctype; char cname[FS_NAME_MAX];
                    if (dir_get(dst_ino, 0, &cino, &ctype, cname)) { rp->rc = SYS_ERR_BUSY; break; }
                }
                if (dir_remove(new_parent, newname) == 0) { rp->rc = SYS_ERR_IO; break; }
                fs_ino_free(dst_ino);
            }
        }

        /* Link the source under the new name FIRST (a crash then leaves it
         * reachable, never orphaned), then unlink the old name. */
        int arc = dir_add(new_parent, newname, src_ino, src_type);
        if (arc != 0) { rp->rc = arc; break; }
        if (dir_remove(old_parent, rq->name) == 0) {
            dir_remove(new_parent, newname);     /* roll back: avoid two names for one inode */
            rp->rc = SYS_ERR_IO; break;
        }
        rp->rc = 0;
        break;
    }
    default:
        rp->rc = SYS_ERR_NOSYS;
        break;
    }
}

/* ---- capability-addressed requests (docs/design/filesystem.md §5, step 1) ----
 *
 * A request through a TOKENED capability. Its object is the token's inode, never
 * an inode the request names; what it may do is the invoking capability's rights,
 * which the kernel attests; and a name in it may not be ".", ".." or hold "/"
 * (§5.4: paths belong to the client, so a capability to a directory reaches that
 * directory and what is below it, and nothing else). LOOKUP, CREATE and MKDIR
 * hand back a capability to the child, which the kernel derives from the one
 * invoked (SYS_IPC_REPLY_CAP), so revoking a directory's capability revokes
 * everything opened through it.
 *
 * Sets *mint_rights and *mint_token when the reply should carry a capability. */
static int fs_name_ok(const char *n)
{
    if (n[0] == 0) return 0;
    if (n[0] == '.' && (n[1] == 0 || (n[1] == '.' && n[2] == 0))) return 0;
    for (unsigned i = 0; n[i]; i++) if (n[i] == '/') return 0;
    return 1;
}

/* FS_OP_WALK (fs_proto.h FS_WALK; design §5.4, decision 12): the names in
 * rq->data, walked down from directory `from` as a run of LOOKUPs, answering
 * with the last one's inode and type. The caller mints the one capability.
 *
 * EVERY NAME IS CHECKED BEFORE ANY IS LOOKED UP. The hazard is checking only
 * the first, as a single-name LOOKUP needs to: then "a" followed by ".." reaches
 * the directory search with a name the protocol forbids. v11 directories hold no
 * ".." entry, but the uid path, until step 6 removes it, will create one under
 * that name, and a format that stores one would turn the walk into a way up.
 * So a bad name anywhere refuses the whole walk, before any step is taken.
 *
 * EACH STEP IS AN ORDINARY LOOKUP, through handle(), so it gets everything a
 * LOOKUP gets by construction: a step from something that is not a directory is
 * refused (is_dir), and the system-tree rule (S116) runs. Nothing about a walk
 * is checked twice in two places that could drift.
 *
 * FS_WALK_NAMES_UNCHECKED=1 is the control arm for make smoke-fs-cap-walk-control:
 * only the first name is checked. Never ship. */
static void walk(const struct fs_request *rq, struct fs_response *rp, uint32_t from,
                 uint32_t cuid, uint32_t cgid)
{
    const char *d = (const char *)rq->data;
    uint32_t len = rq->len;

    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;
    /* At least one name, and the last one terminated inside the request, so no
     * name below can run past the end of data[]. */
    if (len == 0 || len > FS_WALK_BYTES || d[len - 1] != 0) { rp->rc = SYS_ERR_INVAL; return; }
    for (uint32_t at = 0; at < len; ) {
        uint32_t l = uslen(d + at);
        if (l >= FS_DIRENT_NAME || !fs_name_ok(d + at)) { rp->rc = SYS_ERR_INVAL; return; }
#ifdef FS_WALK_NAMES_UNCHECKED
        break;                              /* CONTROL ARM: the first name only */
#endif
        at += l + 1;
    }

    uint32_t cur = from;
    for (uint32_t at = 0; at < len; at += uslen(d + at) + 1) {
        struct fs_request step;
        umemset(&step, 0, sizeof(step));
        step.magic = FS_PROTO_MAGIC;
        step.op = FS_OP_LOOKUP;
        step.dir_ino = cur;
        ustrncpy(step.name, d + at, FS_NAME_MAX);
        handle(&step, rp, cuid, cgid);
        if (rp->rc != 0) return;
        cur = rp->ino;
    }
}

static void cap_request(const struct fs_request *rq, struct fs_response *rp,
                        const struct ipc_invoker *inv, uint32_t cuid, uint32_t cgid,
                        uint32_t *mint_rights, uint64_t *mint_token)
{
    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;
    *mint_rights = 0;
    *mint_token = 0;
    if (rq->magic != FS_PROTO_MAGIC) { rp->rc = SYS_ERR_INVAL; return; }

    uint32_t obj = fs_token_ino(inv->token);
    if (obj >= FS_GEN_INODES || (g_gen[obj] & FS_GEN_RETIRED) ||
        fs_token_gen(inv->token) != g_gen[obj]) {
        rp->rc = SYS_ERR_NOENT;             /* stale: the object it named is gone */
        return;
    }

    uint32_t need, is_dir_op = 0, names = 0;
    switch (rq->op) {
    case FS_OP_LOOKUP:   need = FS_R_LOOKUP; is_dir_op = 1; names = 1; break;
    case FS_OP_WALK:     need = FS_R_LOOKUP; is_dir_op = 1; break;   /* names: walk() */
    case FS_OP_CREATE:
    case FS_OP_MKDIR:    need = FS_R_CREATE; is_dir_op = 1; names = 1; break;
    case FS_OP_DELETE:   need = FS_R_DELETE; is_dir_op = 1; names = 1; break;
    case FS_OP_READDIR:  need = FS_R_READ;   is_dir_op = 1; break;
    case FS_OP_STAT:
    case FS_OP_READ:     need = FS_R_READ;   break;
    case FS_OP_WRITE:
    case FS_OP_TRUNCATE: need = FS_R_WRITE;  break;
    case FS_OP_APPEND:   need = (inv->rights & FS_R_APPEND) ? FS_R_APPEND : FS_R_WRITE; break;
    case FS_OP_RENAME:
        /* Within the capability's directory only: a rename there needs CREATE
         * for the new name and DELETE for the old (§5.5). Naming a second
         * directory would need a second capability, and phase 3 brings that
         * with the full rule; until then a request that names one is EXDEV. */
        if (fs_xdev(rq->ino != 0)) { rp->rc = SYS_ERR_XDEV; return; }
        need = FS_R_CREATE | FS_R_DELETE; is_dir_op = 1; names = 1;
        break;
    default:
        /* chmod/chown (step 4) and link are not on this path. A link names its
         * source by inode, which a capability never does. */
        rp->rc = SYS_ERR_NOSYS;
        return;
    }
#ifndef FS_CAP_RIGHTS_UNCHECKED
    if ((inv->rights & need) != need) { rp->rc = SYS_ERR_PERM; return; }
#else
    /* CONTROL ARM, never ship (smoke-fs-cap-control): the capability's rights are
     * not consulted, so a read-only one can write. */
    (void)need;
#endif
    if (names && !fs_name_ok(rq->name)) { rp->rc = SYS_ERR_INVAL; return; }
    if (rq->op == FS_OP_RENAME) {
        char nn[FS_DIRENT_NAME];
        ustrncpy(nn, (const char *)rq->data, FS_DIRENT_NAME);
        if (!fs_name_ok(nn)) { rp->rc = SYS_ERR_INVAL; return; }
    }

    struct fs_request r2 = *rq;
    if (is_dir_op) r2.dir_ino = obj; else r2.ino = obj;
    if (rq->op == FS_OP_RENAME) r2.ino = obj;      /* new parent: the same directory */

    /* A DELETE's generation bump happens in fs_ino_free, on the free itself. */
    g_by_cap = 1;
    if (rq->op == FS_OP_WALK) walk(rq, rp, obj, cuid, cgid);
    else handle(&r2, rp, cuid, cgid);
    g_by_cap = 0;

    if (rp->rc == 0 && (rq->op == FS_OP_LOOKUP || rq->op == FS_OP_WALK ||
                        rq->op == FS_OP_CREATE || rq->op == FS_OP_MKDIR)
        && rp->ino < FS_GEN_INODES && !(g_gen[rp->ino] & FS_GEN_RETIRED)) {
        /* A CHILD CARRIES AT MOST ITS DIRECTORY'S RIGHTS (§5.3): a directory
         * keeps every file right so files below it can still have them, a file
         * keeps only the rights that mean something on a file. The kernel
         * intersects with the invoking capability again on the way out. */
        uint32_t keep = (rp->type == FS_TYPE_DIR) ? FS_R_ALL : FS_R_FILE_MASK;
        /* And the kernel's own rights it already had: send (WRITE), pass on
         * (GRANT), make narrowed copies of it (MINT; a token is never minted from
         * a tokened capability, so this cannot make a new one, §5.1) and revoke
         * those copies (REVOKE). */
        *mint_rights = (inv->rights & keep) |
                       (inv->rights & (CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_MINT | CAP_RIGHT_REVOKE));
        *mint_token = fs_token(rp->ino, g_gen[rp->ino]);
    }
}

/* Find `name` in `parent_ino`; if it is a directory return it, else create it as a
 * root-owned 0755 directory. Idempotent — reuses the directory if present. Returns
 * the directory inode, or -1 (including when `name` exists as a non-directory). */
static int resolve_or_make_dir(uint32_t parent_ino, const char *name) {
    uint32_t ino, type;
    if (dir_find(parent_ino, name, &ino, &type)) return (type == FS_TYPE_DIR) ? (int)ino : -1;
    int nino = sys_fs_inode_alloc(FS_TYPE_DIR);
    if (nino < 0) return -1;
    sys_fs_set_meta((uint32_t)nino, 0755u, 0, 0);            /* root-owned */
    if (dir_add(parent_ino, name, (uint32_t)nino, FS_TYPE_DIR) != 0) { fs_ino_free((uint32_t)nino); return -1; }
    return nino;
}

/* Walk a '/'-separated path relative to the root, creating each component as a
 * directory. Returns the final directory's inode, or -1. e.g. "usr/share/man". */
static int ensure_dir_path(const char *path) {
    int cur = 0;   /* root inode */
    const char *p = path;
    while (*p == '/') p++;
    while (*p) {
        char comp[FS_NAME_MAX]; int c = 0;
        while (*p && *p != '/' && c < (int)FS_NAME_MAX - 1) comp[c++] = *p++;
        comp[c] = 0;
        while (*p == '/') p++;
        if (c == 0) continue;
        cur = resolve_or_make_dir((uint32_t)cur, comp);
        if (cur < 0) return -1;
    }
    return cur;
}

static int has_prefix(const char *s, const char *pre) {
    while (*pre) { if (*s != *pre) return 0; s++; pre++; }
    return 1;
}

/* Destination allowlist for boot modules (defence-in-depth, audit A4 companion).
 * A module's cmdline is its destination path and each module becomes a ROOT-OWNED
 * file — an executable 0755 under /bin. Constrain WHERE a module may land so a
 * stray or tampered module list cannot plant a root-owned file outside the two
 * intended trees. Accept only: a bare name (no '/', defaults under /bin), a path
 * under `bin/`, or a path under `usr/share/man/`. Reject absolute paths and any
 * empty, `.` or `..` component, so no entry can be named to climb out. Module
 * *content* is still trusted to the boot chain — verifying that is the open part
 * of A4 (see docs/ROADMAP.md Track 2.1). */
static int module_dest_ok(const char *path) {
    if (!path || path[0] == 0 || path[0] == '/') return 0;
    int ncomp = 0;
    const char *p = path;
    while (*p) {
        const char *start = p;
        while (*p && *p != '/') p++;
        int len = (int)(p - start);
        if (len == 0) return 0;                                   /* "//" or trailing '/' */
        if (len == 1 && start[0] == '.') return 0;                /* "." */
        if (len == 2 && start[0] == '.' && start[1] == '.') return 0; /* ".." */
        ncomp++;
        if (*p == '/') p++;
    }
    if (ncomp == 1) return 1;                                     /* bare name -> /bin */
    /* The system trees (S116) and nothing else: /sbin for programs only init or
     * an administrator runs, /usr/share/doc for the licence texts and source
     * offer that come with the GPL and LGPL programs. */
    return has_prefix(path, "bin/") || has_prefix(path, "sbin/") ||
           has_prefix(path, "usr/share/man/") || has_prefix(path, "usr/share/doc/");
}

/* Copy boot module `mod_index` (size bytes) to the '/'-relative destination `path`
 * (e.g. "bin/tail" or "usr/share/man/tail"): create any missing parent directories,
 * then write a root-owned file at the leaf. A bare name with no '/' defaults under
 * /bin (the common case — a runnable program). Executables under /bin are 0755;
 * everything else (man pages, config) is 0644. Idempotent: a leaf already present
 * at the right size is left alone. Returns 1 if installed, 0 if skipped (current),
 * -1 on failure (including the volume filling up, or a disallowed destination path).
 * Runs entirely inside the server, so the store primitives are called directly
 * rather than over IPC. */
/* Does file `ino` hold exactly the bytes of boot module `mod_index`? */
static int file_matches_module(uint32_t ino, uint32_t mod_index, uint32_t size) {
    struct fs_stat st;
    if (sys_fs_stat(ino, &st) != 0 || (uint32_t)st.size != size) return 0;
#ifdef SYSTEM_TREES_SIZE_ONLY
    /* CONTROL ARM -- never ship. The comparison before 2026-10-08: the same
     * size is taken as the same file. See make smoke-system-trees-rebuild-control. */
    return 1;
#endif
    static uint8_t fb[BLK], mb[BLK];
    uint32_t off = 0, blk = 0;
    while (off < size) {
        uint32_t chunk = size - off; if (chunk > BLK) chunk = BLK;
        if (sys_fblock_read(ino, blk, fb) != (int)BLK) return 0;
        if (sys_boot_module_read(mod_index, off, mb, chunk) != (int)chunk) return 0;
        for (uint32_t i = 0; i < chunk; i++) if (fb[i] != mb[i]) return 0;
        off += chunk; blk++;
    }
    return 1;
}

/* Remove entry `name` (inode `ino`, type `type`) from directory `parent`, and
 * everything under it if it is a directory. Bounded: a tree deeper than this is
 * not something provisioning ever made, and is left rather than chased. */
#define REMOVE_TREE_DEPTH 8
static void remove_tree(uint32_t parent, const char *name, uint32_t ino, uint32_t type, int depth) {
    if (type == FS_TYPE_DIR) {
        if (depth >= REMOVE_TREE_DEPTH) return;
        uint32_t cino, ctype, idx = 0; char cname[FS_NAME_MAX];
        /* An entry that cannot be removed is stepped past, never fetched again,
         * so a stubborn child cannot turn this into an endless loop. */
        while (dir_get(ino, idx, &cino, &ctype, cname)) {
            remove_tree(ino, cname, cino, ctype, depth + 1);
            if (dir_find(ino, cname, 0, 0)) idx++;
        }
        if (dir_get(ino, 0, &cino, &ctype, cname)) return;   /* not empty: leave it */
    }
    if (dir_remove(parent, name)) fs_ino_free(ino);
}

static int install_module_at(const char *path, uint32_t mod_index, uint32_t size) {
    if (!module_dest_ok(path)) {
        kputln("[fs_server] refusing boot module with a disallowed destination path");
        return -1;
    }
    const char *slash = 0;
    for (const char *q = path; *q; q++) if (*q == '/') slash = q;

    int parent_ino;
    const char *leaf;
    int is_exec;
    if (slash) {
        char parent[FS_NAME_MAX * 6]; int n = 0;
        for (const char *q = path; q < slash && n < (int)sizeof(parent) - 1; q++) parent[n++] = *q;
        parent[n] = 0;
        parent_ino = ensure_dir_path(parent);
        leaf = slash + 1;
        is_exec = (parent[0]=='b' && parent[1]=='i' && parent[2]=='n' &&
                   (parent[3]==0 || parent[3]=='/'));
    } else {
        parent_ino = ensure_dir_path("bin");                /* bare name -> /bin */
        leaf = path;
        is_exec = 1;
    }
    if (parent_ino < 0 || leaf[0] == 0) return -1;

    sys_mark((uint32_t)parent_ino);          /* every directory a module lands in */
    uint32_t eino, etype;
    if (dir_find((uint32_t)parent_ino, leaf, &eino, &etype)) {
        /* UP TO DATE MEANS THE SAME BYTES, not the same size (S116). Until
         * 2026-10-08 a file of the module's size was taken as current, so one
         * changed in place, byte for byte the same length, survived every boot.
         * Compared by reading, so an unchanged file costs reads and no writes;
         * its owner and mode are put back either way. */
        if (etype == FS_TYPE_FILE && file_matches_module(eino, mod_index, size)) {
            sys_fs_set_meta(eino, is_exec ? 0755u : 0644u, 0, 0);
            sys_mark(eino);
            return 0;
        }
        remove_tree((uint32_t)parent_ino, leaf, eino, etype, 0);   /* changed, or not a file: replace */
    }

    int ino = sys_fs_inode_alloc(FS_TYPE_FILE);
    if (ino < 0) return -1;
    sys_fs_set_meta((uint32_t)ino, is_exec ? 0755u : 0644u, 0, 0);   /* root-owned */
    static uint8_t buf[BLK];
    uint32_t off = 0, blk = 0;
    while (off < size) {
        uint32_t chunk = size - off; if (chunk > BLK) chunk = BLK;
        int got = sys_boot_module_read(mod_index, off, buf, chunk);
        if (got <= 0) { fs_ino_free((uint32_t)ino); return -1; }
        /* sys_fblock_write returns the byte count it stored (== got); it zero-pads
         * a short final block internally, so compare against got, not BLK. A write
         * failure here means the store volume filled up — free the partial inode
         * and let the caller skip this one. */
        if (sys_fblock_write((uint32_t)ino, blk, buf, (uint32_t)got) != got) {
            fs_ino_free((uint32_t)ino); return -1;
        }
        off += (uint32_t)got; blk++;
    }
    sys_fs_set_size((uint32_t)ino, size);
    if (dir_add((uint32_t)parent_ino, leaf, (uint32_t)ino, FS_TYPE_FILE) != 0) {
        fs_ino_free((uint32_t)ino); return -1;
    }
    sys_mark((uint32_t)ino);
    return 1;
}

/* Provision the filesystem at boot, once, after the store is readable (unlocked):
 *   1. Create the directory skeleton (/bin /etc /home /lib /usr /usr/share/man),
 *      so `ls` on a fresh root shows a real layout rather than an empty root — this
 *      runs even when no boot modules are shipped.
 *   2. Route each boot module to its declared destination path (bin/<name> for the
 *      coreutils binaries, usr/share/man/<name> for the man pages), creating parent
 *      dirs as needed. Idempotent, so a persistent disk is written only on the
 *      first boot that sees a new/changed module.
 * This is how program binaries and their man pages reach the filesystem WITHOUT
 * being baked into the kernel image. The 16 MiB store holds all of it at once. */
/* Give every account a home directory that the account OWNS.
 *
 * WHY THIS IS HERE AND NOT ANYWHERE ELSE. Three things have to be true at the
 * same moment, and this is the only place in the system where they are.
 *
 *   The account list. This is the one server holding CAP_USER for a reason of
 *   its own (init grants it as the SYS_REGISTER_FS_SERVER gate), so SYS_USERLIST
 *   costs no new authority -- nothing is granted here that was not already held.
 *
 *   The ability to stamp ownership. sys_fs_set_meta is gated on
 *   CAP_ENCRYPTED_STORAGE, which is this server and nothing else in ring 3. The
 *   installer deliberately holds no storage capability and could not do it; a
 *   task running as the account cannot either, because /home is root's.
 *
 *   The right MOMENT. On an installed machine the volume is sealed from
 *   power-on until a login unlocks it (S74), so anything attempted at boot runs
 *   against a locked store and silently writes nothing. Provisioning is already
 *   the code that waits for the unlock, and this rides with it.
 *
 * AN EXISTING DIRECTORY IS LEFT ENTIRELY ALONE -- not re-stamped. Re-asserting
 * 0700 and the owner on every boot would undo a mode the account chose for
 * itself, which is a filesystem server overruling its own permission model once
 * per power cycle. Absent means "this account has never had one"; present means
 * somebody -- the account, or an operator -- has had their say.
 *
 * A home is only ever /home/<leaf>. The path is validated rather than walked:
 * anything else in the record is left for whoever put it there, and a name with
 * a '/' in it is refused instead of being turned into a nested directory. */
static void provision_home_dirs(void) {
    int home_ino = ensure_dir_path("home");
    if (home_ino < 0) return;

    for (uint32_t i = 0; ; i++) {
        struct user_entry e;
        if (sys_userlist(i, &e) != 1) break;      /* 0 = past the last account */

        /* The home must be exactly "/home/<leaf>", with a non-empty leaf that is
         * a single path component. root's "/" falls out here, which is right:
         * root's home is the volume root and it already exists. */
        static const char pfx[] = "/home/";
        unsigned k = 0;
        while (pfx[k] && e.home[k] == pfx[k]) k++;
        if (pfx[k] != 0) continue;
        const char *leaf = e.home + k;
        if (leaf[0] == 0) continue;
        int bad = 0;
        for (unsigned j = 0; leaf[j]; j++) if (leaf[j] == '/') bad = 1;
        if (bad || uslen(leaf) >= FS_DIRENT_NAME) continue;

        uint32_t ino, type;
        if (dir_find((uint32_t)home_ino, leaf, &ino, &type)) continue;   /* had their say */

        int nino = sys_fs_inode_alloc(FS_TYPE_DIR);
        if (nino < 0) continue;
        /* Owner and mode BEFORE the link, for the reason FS_OP_CREATE gives: the
         * inode is not reachable by name yet, so the window in which it exists
         * owned by nobody is invisible to every other client. */
#ifdef HOME_DIR_ROOT_OWNED
        /* Control arm: created, but never given away. The directory is there and
         * the account cannot write a thing in it. */
        sys_fs_set_meta((uint32_t)nino, 0700u, 0, 0);
#else
        sys_fs_set_meta((uint32_t)nino, 0700u, e.uid, e.gid);
#endif
        if (dir_add((uint32_t)home_ino, leaf, (uint32_t)nino, FS_TYPE_DIR) != 0) {
            fs_ino_free((uint32_t)nino);
        }
    }
}

/* A system directory (S116), made if missing, and remade if something that is
 * not a directory sits where it belongs: a file named "bin" in the root would
 * otherwise stop /bin from existing at all. Root-owned and 0755 every boot. */
static int system_dir(const char *path) {
    int d = ensure_dir_path(path);
    if (d < 0) {
        const char *slash = 0;
        for (const char *q = path; *q; q++) if (*q == '/') slash = q;
        int parent = 0;
        const char *leaf = path;
        if (slash) {
            char pp[FS_NAME_MAX * 4]; int n = 0;
            for (const char *q = path; q < slash && n < (int)sizeof(pp) - 1; q++) pp[n++] = *q;
            pp[n] = 0;
            parent = ensure_dir_path(pp);
            leaf = slash + 1;
        }
        uint32_t ino, type;
        if (parent >= 0 && dir_find((uint32_t)parent, leaf, &ino, &type))
            remove_tree((uint32_t)parent, leaf, ino, type, 0);
        d = ensure_dir_path(path);
    }
    if (d >= 0) {
        sys_fs_set_meta((uint32_t)d, 0755u, 0, 0);
        sys_mark((uint32_t)d);
    }
    return d;
}

/* Remove from system directory `dir` everything that is not a system inode,
 * descending into the system directories inside it. Returns how many entries
 * were removed. */
static unsigned prune_tree(uint32_t dir, int depth) {
    unsigned removed = 0;
    uint32_t cino, ctype, idx = 0; char cname[FS_NAME_MAX];
    while (dir_get(dir, idx, &cino, &ctype, cname)) {
        if (is_sys(cino)) {
            if (ctype == FS_TYPE_DIR && depth < REMOVE_TREE_DEPTH) removed += prune_tree(cino, depth + 1);
            idx++;
            continue;
        }
#ifdef SYSTEM_TREES_NO_PRUNE
        /* CONTROL ARM -- never ship. Strays are left where they are, the
         * provisioning before 2026-10-08. See make smoke-system-trees-prune-control. */
        idx++;
        continue;
#endif
        remove_tree(dir, cname, cino, ctype, 0);
        if (dir_find(dir, cname, 0, 0)) idx++;   /* could not be removed: step past */
        else removed++;
    }
    return removed;
}

static void provision_boot_modules(void) {
    /* THE SYSTEM TREES FIRST (S116): made, marked, owned by root. Then the rest
     * of the layout in docs/design/installed-system.md section 2, which is the
     * operator's and is left as it is. /tmp is not made yet: a directory every
     * user can write needs the sticky rule (only an entry's owner removes it),
     * which this server does not enforce, and without it any user could delete
     * any other's files there. docs/LIMITATIONS.md says so. */
    static const char *const sys_dirs[] = {
        "bin", "sbin", "lib", "usr", "usr/share", "usr/share/man", "usr/share/doc", 0
    };
    static const char *const skel[] = { "etc", "home", "var", "var/log", 0 };
    g_sys_n = 0;
    for (int i = 0; sys_dirs[i]; i++) system_dir(sys_dirs[i]);
    for (int i = 0; skel[i]; i++) ensure_dir_path(skel[i]);

    /* After the skeleton, because it needs /home to exist; before the modules,
     * because a full volume should cost an account its home last, not first. */
    provision_home_dirs();

    int n = sys_boot_module_info(0, 0);
    int installed = 0, skipped = 0;
    for (int i = 0; i < n; i++) {
        struct boot_module_info info;
        if (sys_boot_module_info((uint32_t)i, &info) < 0) continue;
        if (info.name[0] == 0 || info.size == 0) continue;
        /* THE SHARED LIBC IS THE KERNEL'S, not a file. The kernel loads it from
         * this module before init exists (shlib_boot_load) and hands it out by
         * capability; nothing ever loads it from the store, so a copy here would
         * be a file nobody uses. Skipped by its one name, quietly and without
         * widening the allowlist below: lib/ stays a destination no module may
         * write. Until 2026-09-25 it fell into install_module_at, was refused as
         * a disallowed path, and was counted as a module that "did not fit",
         * which is a different failure reported as this one. */
        if (uslen(info.name) == 11 && has_prefix(info.name, "lib/libc.so")) continue;
        int rc = install_module_at(info.name, (uint32_t)i, info.size);
        if (rc == 1) installed++;
        else if (rc < 0) skipped++;
    }
    if (skipped  > 0) kputln("[fs_server] some boot modules did not fit the store volume");

    /* AND NOTHING ELSE: whatever in the system trees is not a module is
     * removed, so they hold exactly what the kernel verified. */
    unsigned strays = 0;
    for (int i = 0; sys_dirs[i]; i++) {
        int d = ensure_dir_path(sys_dirs[i]);
        if (d >= 0) strays += prune_tree((uint32_t)d, 0);
    }
    (void)installed;
    kput("[fs_server] system trees rebuilt from the verified modules: ");
    kput_int((int)g_sys_n);
    kput(" inodes, ");
    kput_int((int)strays);
    kputln(" strays removed");
    /* One marker whether or not modules were shipped: the skeleton is always
     * created, so a default (module-free) boot still reports a real filesystem. */
    kputln("[fs_server] filesystem provisioned");
}

/* The gate endpoint init shares with us (slot 3, object 0), and the badge we
 * fire on it once startup provisioning is done, so init can launch the shell.
 * init blocks in SYS_WAIT_NOTIFY on the same endpoint object until this arrives. */
#define FS_GATE_SLOT   CAPSLOT_NOTIFY   /* CAP_NOTIFICATION: the fs-ready rendezvous */
#define FS_READY_BADGE 0x5D0Eu

void _start(void) {
    kputln("[fs_server] userspace FS server starting (encrypted object store).");

    /* Register FIRST, before any provisioning work.
     *
     * Registration publishes the service so clients can acquire a capability to
     * it with SYS_CONNECT_FS_SERVER. Since IPC became capability-addressed
     * (finding C-1) that is the ONLY way a client reaches this server — the
     * ambient endpoint capability every task used to be born with is gone. So a
     * client that starts before registration completes cannot connect at all,
     * where previously it would simply have sent to the well-known endpoint and
     * waited. Registration is a couple of stores; provisioning copies megabytes
     * block-by-block through the encrypted store. Doing the cheap publish first
     * removes the window entirely rather than leaving clients to race it. */
    /* Retry until the capability arrives.
     *
     * A spawned task becomes runnable before its supervisor has finished
     * endowing it, and under SMP it genuinely runs first on another core — so
     * this registration can execute before init's SYS_CAP_GRANT of the listen
     * capability into CAPSLOT_FS_LISTEN has landed. Registration then fails for
     * want of a capability that is merely late, not absent.
     *
     * That window has always existed; it was hidden while registration happened
     * after the multi-megabyte provisioning copy, which gave init ample time.
     * Registering first (so clients can connect promptly — see above) exposes it,
     * so wait for the grant rather than racing it. Bounded, and yields between
     * attempts so the granting task actually gets the CPU on a single core. */
    {
        int reg = -1;
        for (int attempt = 0; attempt < 2000; attempt++) {
            reg = sys_register_fs_server(CAPSLOT_FS_LISTEN);
            if (reg == 0) break;
            sys_yield();
        }
        if (reg == 0) kputln("[fs_server] registered; serving.");
        else          kputln("[fs_server] warning: registration failed; serving anyway.");
    }

    /* Provision /bin from the boot modules with the CPU to ourselves, BEFORE the
     * shell exists. The shell reads the console with an unpreemptible ring-0 spin
     * (console_getc), which would otherwise starve this block-by-block copy on a
     * single core. This only runs when the store is already unlocked — the
     * ephemeral RAM disk, which comes up unlocked; a sealed ATA volume stays
     * locked until login, so there we fall back to the lazy in-loop provisioning
     * below (post-login, once, idempotent). Then notify init we are ready. */
    int provisioned = 0;
    {
        /* THE ANSWER TO THIS STAT IS THE WHOLE BRANCH, so it is reported rather
         * than merely taken. Until 2026-09-01 the store answered it on a SEALED
         * volume too (**S74**), so this ran its copy against a locked store, every
         * module's data write failed inside the AEAD, and `provisioned` was set
         * anyway -- which disabled the post-login fallback below for the rest of
         * the boot. A machine installed and powered off before the copy finished
         * then had an empty /bin on that disk forever. The syscall is fixed; the
         * marker stays because "which branch did this boot take" is not otherwise
         * observable, and the two arms of smoke-installer-provision are exactly
         * this line's two values. */
        struct fs_stat root_st;
        if (sys_fs_stat(0, &root_st) == 0) {
            kputln("FS_STORE: open at startup; provisioning now");
            provision_boot_modules();
            provisioned = 1;
        } else {
            kputln("FS_STORE: sealed at startup; provisioning deferred until unlock");
        }
    }
    /* Always signal, even if there was nothing to provision or the store is still
     * locked, so init never waits forever. The badge accumulates whether it fires
     * before or after init blocks. */
    sys_notify(FS_GATE_SLOT, FS_READY_BADGE);

    struct fs_request  rq;
    struct fs_response rp;
    for (;;) {
        /* Fallback for the sealed-ATA case: the volume was locked at startup, so
         * provision on the first loop after login unlocks it (a stat of the root
         * inode fails while locked). On the RAM disk this already ran above. */
        if (!provisioned) {
            struct fs_stat root_st;
            if (sys_fs_stat(0, &root_st) == 0) {
                kputln("FS_STORE: unlocked; provisioning now");
                provision_boot_modules();
                provisioned = 1;
            }
        }
        /* Sleep until a request arrives (roadmap 1.3), but only once the volume
         * has been provisioned.
         *
         * The `if (!provisioned)` fallback above is a POLL: on a sealed ATA
         * volume it re-stats the root inode every time round this loop, waiting
         * for a login to unlock it. Blocking unconditionally would park the
         * server before that ever succeeded and only re-check it one request
         * later -- so the two are kept apart deliberately, and the server sleeps
         * exactly when it has nothing left to poll for. That is the whole reason
         * this is not a one-line substitution.
         *
         * As in console_server: a negative return from the blocking receive is
         * permanent (it never returns IPC_AGAIN), so retrying it in a loop would
         * be the G-8 wedge rather than back-pressure. */
        int r;
        if (provisioned) {
            r = sys_ipc_recv_block(CAPSLOT_FS_LISTEN, (char *)&rq, sizeof(rq));
            if (r < 0) { kputln("[fs_server] listen capability lost; exiting"); sys_exit(); }
        } else {
            r = sys_ipc_recv(CAPSLOT_FS_LISTEN, (char *)&rq, sizeof(rq));
            if (r < 0) { spin_delay(); continue; }       /* no request yet */
        }

        /* Take the caller's identity from the kernel, not from the request: this
         * is tasks[sender].uid, fixed at that task's login (SYS_AUTH). A client
         * therefore cannot claim to be another user. Fail closed if the kernel
         * reports no valid sender. */
        uint32_t cgid = 0;
        uint32_t cuid = sys_ipc_sender(CAPSLOT_FS_LISTEN, &cgid);
        /* WHICH CAPABILITY THE REQUEST CAME THROUGH, as the kernel attests it. A
         * tokened one addresses its object by the token (cap_request); an
         * untokened one is the old uid path, until phase 1b step 6. */
        struct ipc_invoker inv;
        umemset(&inv, 0, sizeof(inv));
        if (sys_ipc_invoker(CAPSLOT_FS_LISTEN, &inv) != 0) inv.token = 0;
        uint32_t mint_rights = 0;
        uint64_t mint_token = 0;
        if (cuid == (uint32_t)-1) {
            umemset(&rp, 0, sizeof(rp));
            rp.magic = FS_PROTO_MAGIC;
            rp.rc = SYS_ERR_PERM;
        } else if (inv.token != 0) {
            cap_request(&rq, &rp, &inv, cuid, cgid, &mint_rights, &mint_token);
        } else {
            handle(&rq, &rp, cuid, cgid);
        }
        /* A reply that carries a capability to the child. Refused (the client
         * named no slot for it) delivers nothing and keeps the reply right, so
         * the plain reply below still answers. */
        if (mint_token != 0 &&
            sys_ipc_reply_cap(CAPSLOT_FS_LISTEN, &rp, sizeof(rp), mint_rights, mint_token) == 0)
            continue;
        /* Reply to THIS request's sender by kernel-recorded identity, not to a
         * shared reply endpoint — so concurrent clients never receive each other's
         * replies. A negative return is a transient "client still blocking" race
         * (SMP); retry until delivered. Must precede the next recv, which would
         * overwrite last_sender. */
        /* Retry only the transient race (-2: the client deposited its request but
         * has not yet published its block). A permanent failure here — the listen
         * capability revoked, say — must NOT be retried forever: that would wedge
         * the server silently and take every client down with it. See the IPC
         * retry contract in syscall.h (finding G-8). */
        {
            unsigned tries = 0;
            int rr;
            while ((rr = sys_ipc_reply_to(CAPSLOT_FS_LISTEN, (const char *)&rp, sizeof(rp))) < 0) {
                if (!ipc_transient(rr)) {
                    kputln("[fs_server] reply refused (capability lost?); dropping");
                    break;
                }
                if (++tries > 2000000u) {
                    kputln("[fs_server] reply retry exhausted; dropping");
                    break;
                }
                spin_delay();
            }
        }
    }
}
