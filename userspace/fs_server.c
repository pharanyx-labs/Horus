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
#include "fs_policy.h"

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
        if (!(g_by_cap || cuid == 0 || cuid == sst.uid)) { rp->rc = SYS_ERR_PERM;  break; }  /* owner or root; through a capability, the carried one decided */
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
        /* The object's own inode, for st_ino: through a capability the client
         * never named it (a walk's reply already tells the holder as much). */
        rp->ino = rq->ino;
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
/* ---- sessions (docs/design/filesystem.md §6.4, decision 13) ----------------
 *
 * Carries S128: a session reaches only what the policy grants its account, and
 * only init can open one (session_request).
 *
 * A login's session is ONE root capability whose token names a grant set G, and
 * this server applies the compiled policy (fs_policy.h) to what is reached
 * through it. g_sess[G] holds the compiled tree. A capability is TRACKED (token
 * bit 62) where the policy still has something to say below it: a directory on
 * the way to a grant, or a granted one with a deeper grant under it. Its node
 * records the inode it was minted for, so a request through it finds its node by
 * that inode and generation, and is allowed its capability's rights intersected
 * with the node's. Below a granted path with nothing deeper the capability is
 * untracked, minted with exactly the granted rights, and from there the kernel's
 * intersection bounds everything (S120).
 *
 * THE TRADE, as decision 13 states it: below a session's root, rights are
 * enforced here for tracked capabilities, not by the kernel, because the root
 * must carry the union of the session's rights for a wider grant below a
 * narrower one to be reachable at all. The kernel still bounds every capability
 * by that union. */
struct fs_session {
    int             live;
    struct fsp_tree tree;
    uint32_t        tmp_ino;    /* its private /tmp (§6.3), or 0: none */
    uint32_t        epoch;      /* the policy it was compiled from (g_policy_epoch) */
};

/* WHICH POLICY A SESSION'S BOUNDS CAME FROM (§7.1). The policy is read afresh
 * at every FS_OP_SESSION, so a session opened after an edit compiles the new
 * one while those already open keep the old. Their bounds on who else reaches
 * an object were computed from grants that may no longer be all of them, and a
 * bound that might be low is the one thing §7.1 forbids, so a session whose
 * epoch is not the current one reports every right as other, and refuses the
 * renames that depend on knowing every grant, until it is opened again. */
static uint32_t g_policy_epoch;
static int      g_policy_seen;
static int      g_policy_seen_src;
static uint32_t g_policy_seen_len;
static char     g_policy_seen_text[FSP_MAX_BYTES];

/* ---- a session's private /tmp (design §6.3; S129) ---------------------------
 *
 * A session whose policy says `@self /tmp` gets a directory of its own, made at
 * FS_OP_SESSION as /.session-tmp/<G> and removed, with everything in it, at
 * FS_OP_SESSION_END. In that session, and only there, the name "tmp" at its
 * root answers with that directory, so a program that writes to /tmp writes to
 * a directory nobody else holds a capability to. There is no shared /tmp, so
 * there is no sticky rule to get wrong and nothing to squat.
 *
 * THE STORE IS HIDDEN FROM EVERY SESSION, the administrator's included: a
 * request through a session's capability that names it in the root is answered
 * as absent, and a listing of the root leaves it out. Without that, "/ all"
 * would reach every other session's /tmp through it. Capabilities with no grant
 * set (init's, step 1's) still see it, and so does the uid path until step 6
 * removes it; docs/LIMITATIONS.md 1.24 says so. */
static struct fs_session g_sess[FS_SESSIONS_MAX + 1];   /* [0] is never used */

/* The rights of the kernel's own that a session's capabilities keep: send, pass
 * on (decision 10's spawner grants), make narrowed copies, revoke them. */
#define FS_KERNEL_RIGHTS (CAP_RIGHT_WRITE | CAP_RIGHT_GRANT | CAP_RIGHT_REVOKE | CAP_RIGHT_MINT)

/* Where a capability-addressed request stands in its session's policy. */
struct fs_pol {
    struct fs_session *s;   /* 0: a capability with no grant set (step 1's) */
    int      node;          /* the tracked node, or -1 */
    int      at;            /* the node at or above the object (decision 17), or -1 */
    uint32_t carry;         /* the most a capability minted from here may carry */
};

/* Does the session know every grant there is to know about where `p` stands?
 * Not if the others did not fit its tree, and not if the policy has changed
 * since it was compiled. */
static int fs_pol_complete(const struct fs_pol *p)
{
    return p->s && !p->s->tree.other_full && p->s->epoch == g_policy_epoch;
}

/* WHO ELSE MAY REACH THE OBJECT (§7.1): the union of the other principals'
 * grants at or above the node its token names. Every right whenever that
 * cannot be known for certain, because a bound may overstate and must never
 * understate: a capability with no grant set; a session that does not know every
 * grant (fs_pol_complete); and a file with more than one name, since another
 * name may lie under another grant (v11 keeps no back-references to say). */
static uint32_t fs_pol_other(const struct fs_pol *p, uint32_t links)
{
    if (!fs_pol_complete(p) || p->at < 0 || links > 1) return FS_R_ALL;
#ifdef FS_TOKEN_NODE_IGNORED
    /* CONTROL ARM, never ship (smoke-fs-cap-stat-control): the bound is taken at
     * the session's root, whatever the token says, so a file below another
     * principal's grant is reported as reached by nobody. */
    return p->s->tree.node[0].other;
#else
    return p->s->tree.node[p->at].other;
#endif
}

/* One step down, to entry `name` of type `type`. SYS_ERR_NOENT when the session
 * does not see that name: absent, never PERM, so the policy does not disclose
 * what it withholds. An untracked position has no policy left to apply. */
static int fs_pol_step(struct fs_pol *p, const char *name, uint32_t type)
{
    if (!p->s || p->node < 0) return 0;     /* untracked: `at` stays where it is */
    int child;
    uint32_t carry;
    int r = fsp_step(&p->s->tree, p->node, name, type == FS_TYPE_DIR, &child, &carry);
    if (r < 0) return SYS_ERR_NOENT;
    p->node = (r == 1) ? child : -1;
    p->at = child;
    p->carry = carry;
    return 0;
}

/* Is `name`, in directory `dir`, the hidden store of private /tmps, asked
 * through a session's capability? */
static int fs_pol_hidden(const struct fs_pol *p, uint32_t dir, const char *name)
{
#ifdef FS_SESSION_TMP_STORE_VISIBLE
    /* CONTROL ARM, never ship (smoke-fs-cap-session-tmp-store-control): the
     * store is an ordinary entry, so the administrator's "/ all" reaches every
     * other session's /tmp through it. */
    (void)p; (void)dir; (void)name;
    return 0;
#else
    return p->s && dir == 0 && ustreq(name, FS_SESSION_TMP_STORE_NAME);
#endif
}

/* Is `name`, at the tracked node `p` stands at, the session's private /tmp? */
static int fs_pol_private(const struct fs_pol *p, const char *name)
{
    return p->s && p->node >= 0 && fsp_is_private(&p->s->tree, p->node, name);
}

/* Record that a capability to `ino` is being minted at tracked node `node`. A
 * later binding of the same node (the directory was removed and made again)
 * replaces this one; capabilities to the old inode are stale by generation. */
static void fs_session_bind(struct fs_session *s, int node, uint32_t ino)
{
    s->tree.node[node].ino = ino;
    s->tree.node[node].gen = g_gen[ino];
    s->tree.node[node].bound = 1;
}

static void walk(const struct fs_request *rq, struct fs_response *rp, uint32_t from,
                 uint32_t cuid, uint32_t cgid, struct fs_pol *pol)
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
        if (fs_pol_hidden(pol, cur, step.name)) {
            umemset(rp, 0, sizeof(*rp));
            rp->magic = FS_PROTO_MAGIC;
            rp->rc = SYS_ERR_NOENT;
            return;
        }
        if (fs_pol_private(pol, step.name)) {
            /* The session's own /tmp, never the volume's entry of that name.
             * No directory (it could not be made) is absent, as a missing name
             * is. */
            umemset(rp, 0, sizeof(*rp));
            rp->magic = FS_PROTO_MAGIC;
            if (pol->s->tmp_ino == 0) { rp->rc = SYS_ERR_NOENT; return; }
            rp->ino = pol->s->tmp_ino;
            rp->type = FS_TYPE_DIR;
        } else {
            handle(&step, rp, cuid, cgid);
            if (rp->rc != 0) return;
        }
        /* The name exists; does this session see it? Answered after the lookup
         * because the answer depends on the entry's type (fs_policy.h fsp_step),
         * and answered as the lookup of a missing name would be. */
        if (fs_pol_step(pol, step.name, rp->type) != 0) {
            umemset(rp, 0, sizeof(*rp));
            rp->magic = FS_PROTO_MAGIC;
            rp->rc = SYS_ERR_NOENT;
            return;
        }
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

    /* A capability from a session: its grant set must still be open, and a
     * tracked one must name the node it was minted at. Either failing is NOENT,
     * fail closed: init revokes a session's capabilities before ending it, so
     * one that outlives its session is a defect, and it reaches nothing. */
    uint32_t g = fs_token_g(inv->token);
    struct fs_pol pol = { 0, -1, -1, FS_R_ALL };
    if (g != 0 || fs_token_tracked(inv->token)) {
        if (g == 0 || !g_sess[g].live) { rp->rc = SYS_ERR_NOENT; return; }
        pol.s = &g_sess[g];
        /* The node comes from the token, which the kernel attests: a client
         * cannot choose where it stands. One past the tree is a defect. A
         * tracked capability must be the one its node was last bound to. */
        uint32_t at = fs_token_node(inv->token);
        if (at >= pol.s->tree.n) { rp->rc = SYS_ERR_NOENT; return; }
        pol.at = (int)at;
        if (fs_token_tracked(inv->token)) {
            const struct fsp_node *nn = &pol.s->tree.node[at];
            if (!nn->bound || nn->ino != obj || nn->gen != fs_token_gen(inv->token)) {
                rp->rc = SYS_ERR_NOENT;
                return;
            }
            pol.node = (int)at;
            pol.carry = nn->below;
        }
    }
    /* What this request may use: the capability's rights, and at a tracked node
     * only those its node allows (fsp_op_rights). The kernel's own bits pass. */
    uint32_t have = inv->rights;
#ifndef FS_SESSION_RIGHTS_UNCHECKED
    if (pol.node >= 0) have &= fsp_op_rights(&pol.s->tree, pol.node) | ~(uint32_t)FS_R_ALL;
#endif

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
    case FS_OP_APPEND:   need = (have & FS_R_APPEND) ? FS_R_APPEND : FS_R_WRITE; break;
    case FS_OP_CHMOD:
    case FS_OP_CHOWN:    need = FS_R_READ;   break;   /* what stat needs: they answer as it does */
    case FS_OP_RENAME:
        /* Within the capability's directory only: a rename there needs CREATE
         * for the new name and DELETE for the old (§5.5). Naming a second
         * directory would need a second capability, and phase 3 brings that
         * with the full rule; until then a request that names one is EXDEV. */
        if (fs_xdev(rq->ino != 0)) { rp->rc = SYS_ERR_XDEV; return; }
        need = FS_R_CREATE | FS_R_DELETE; is_dir_op = 1; names = 1;
        break;
    case FS_OP_LINK:
        /* Step 4(c): a second name, in the capability's directory, for the file
         * the request CARRIES (SYS_IPC_CALL_CAP). A capability never names an
         * inode, so the source is the carried capability's object, attested
         * by the kernel as the directory's is; rq->ino is ignored. The new
         * name needs CREATE on the directory. */
        need = FS_R_CREATE; is_dir_op = 1; names = 1;
        break;
    default:
        rp->rc = SYS_ERR_NOSYS;
        return;
    }
#ifndef FS_CAP_RIGHTS_UNCHECKED
    if ((have & need) != need) { rp->rc = SYS_ERR_PERM; return; }
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

    /* In a session, the names the session does not see as the volume has them:
     * the hidden store of private /tmps is absent, and its own /tmp is not an
     * entry it can make, remove or rename. */
    if (pol.s && names) {
        char nn[FS_DIRENT_NAME];
        nn[0] = 0;
        if (rq->op == FS_OP_RENAME) ustrncpy(nn, (const char *)rq->data, FS_DIRENT_NAME);
        if (fs_pol_hidden(&pol, obj, rq->name) || (nn[0] && fs_pol_hidden(&pol, obj, nn))) {
            rp->rc = SYS_ERR_NOENT;
            return;
        }
        if (rq->op != FS_OP_LOOKUP &&
            (fs_pol_private(&pol, rq->name) || (nn[0] && fs_pol_private(&pol, nn)))) {
            rp->rc = (rq->op == FS_OP_CREATE || rq->op == FS_OP_MKDIR) ? SYS_ERR_EXIST : SYS_ERR_PERM;
            return;
        }
        /* A RENAME MAY NOT MOVE AN OBJECT ONTO A NAME THE POLICY NAMES, OR OFF
         * ONE (§5.5 condition 2, within one directory). Such a name decides
         * which grants reach what is under it: moving onto it would hand the
         * object to a grant that did not reach it when the capabilities to it
         * were minted, and their bound on who else reaches it (§7.1) would then
         * be low; moving off it would leave the grant's holders their
         * capabilities while new ones were bounded as if they had none. Both
         * are EXDEV, as a move across directories is, and a mover copies. A
         * session that does not know every grant (fs_pol_complete) cannot tell,
         * so it is refused every rename until it is opened again. */
        if (rq->op == FS_OP_RENAME &&
            (!fs_pol_complete(&pol) ||
             (pol.node >= 0 && (fsp_names(&pol.s->tree, pol.node, rq->name) ||
                                fsp_names(&pol.s->tree, pol.node, nn))))) {
            rp->rc = SYS_ERR_XDEV;
            return;
        }
    }

    /* LINK WITHIN ONE DIRECTORY (step 4(c), §5.5 as it applies there).
     *
     * THE SOURCE IS A CAPABILITY THE CALLER HOLDS, carried with the request:
     * its own object and generation are checked as the directory's were, and
     * it must belong to the same session (or both to none), so a session cannot
     * name a file through a capability from another.
     *
     * NO NEW AUTHORITY THROUGH THE NEW NAME. A capability reached later through
     * the new name gets what the directory gives a file: its rights here,
     * narrowed to a file's, and to what the policy carries below this node. The
     * caller must already hold at least that on the file, or a read-only file
     * plus CREATE on a writable directory would make a writable name.
     *
     * NOT A NAME THE POLICY NAMES. A grant naming the new name would reach the
     * file through it, which is the cross-grant move §5.5 refuses; and a session
     * that does not know every grant cannot tell, so it is refused, as rename
     * is. Both EXDEV: a mover copies.
     *
     * The step 5 rule stands in handle(): the directory must already hold a
     * name for the file, so this never moves a file into a directory. */
    uint32_t link_src = 0;
    if (rq->op == FS_OP_LINK) {
        if (!inv->carried) { rp->rc = SYS_ERR_INVAL; return; }
        link_src = fs_token_ino(inv->carry_token);
        if (link_src >= FS_GEN_INODES || (g_gen[link_src] & FS_GEN_RETIRED) ||
            fs_token_gen(inv->carry_token) != g_gen[link_src] ||
            fs_token_g(inv->carry_token) != g) {
            rp->rc = SYS_ERR_NOENT;
            return;
        }
        uint32_t would = have & FS_R_FILE_MASK & pol.carry;
#ifndef FS_CAP_LINK_WIDENS
        if ((inv->carry_rights & would) != would) { rp->rc = SYS_ERR_PERM; return; }
#else
        /* CONTROL ARM, never ship (smoke-fs-cap-link-control): the carried
         * capability's rights are not compared, so a read-only file gains a
         * writable name in a writable directory. */
        (void)would;
#endif
        if (pol.s && (!fs_pol_complete(&pol) ||
                      (pol.node >= 0 && fsp_names(&pol.s->tree, pol.node, rq->name)))) {
            rp->rc = SYS_ERR_XDEV;
            return;
        }
    }

    /* CHMOD AND CHOWN THROUGH A CAPABILITY STORE NOTHING (§7.2, decision 18).
     * The mode bits on the disk decide nothing on this path, so writing them
     * would change no one's access while reporting that it had. Instead each
     * is answered against the truth stat reports: success when it asks for what
     * is already true, PERM when it does not, so `chmod 600` on a file another
     * grant reaches fails loudly and says the file is shared. */
    if (rq->op == FS_OP_CHMOD || rq->op == FS_OP_CHOWN) {
        struct fs_stat st;
        if (sys_fs_stat(obj, &st) != 0) { rp->rc = SYS_ERR_NOENT; return; }
        int is_true = (rq->op == FS_OP_CHMOD)
            ? fsp_chmod_true(rq->mode & 07777u, have & FS_R_ALL, fs_pol_other(&pol, st.links),
                             st.type == FS_TYPE_DIR)
            : fsp_chown_true(rq->arg_uid, rq->arg_gid, cuid, cgid);
#ifdef FS_CAP_CHMOD_UNTRUE
        /* CONTROL ARM, never ship (smoke-fs-cap-chmod-control): every chmod
         * and chown through a capability reports success, the reassuring
         * answer §7 exists to refuse. */
        is_true = 1;
#endif
        rp->rc = is_true ? 0 : SYS_ERR_PERM;
        return;
    }

    struct fs_request r2 = *rq;
    if (is_dir_op) r2.dir_ino = obj; else r2.ino = obj;
    if (rq->op == FS_OP_LINK) r2.ino = link_src;   /* the carried file, never rq->ino */
    if (rq->op == FS_OP_RENAME) r2.ino = obj;      /* new parent: the same directory */
    /* A session's single-name LOOKUP is a one-name WALK, so the private /tmp and
     * the hidden store are answered in one place (walk), not two that could
     * drift. The name was checked above as a WALK checks each of its names. */
    struct fs_request wl;
    const struct fs_request *wrq = rq;
    if (pol.s && rq->op == FS_OP_LOOKUP) {
        const char *one[1] = { rq->name };
        wl = *rq;
        wl.op = FS_OP_WALK;
        if (fs_walk_pack(wl.data, &wl.len, one, 1) != 0) { rp->rc = SYS_ERR_INVAL; return; }
        wrq = &wl;
    }

    /* A DELETE's generation bump happens in fs_ino_free, on the free itself. */
    g_by_cap = 1;
    if (wrq->op == FS_OP_WALK) {
        walk(wrq, rp, obj, cuid, cgid, &pol);
    } else if (rq->op == FS_OP_READDIR && pol.s && (pol.node >= 0 || obj == 0)) {
        /* A SESSION'S DIRECTORY LISTS WHAT THE SESSION SEES and no more: the
         * entry at `offset` counts only visible names, so the listing is dense
         * and a withheld name leaves no gap to count. The hidden store is left
         * out of the root, and the session's own /tmp is listed once, after the
         * volume's entries, whether or not the volume has one of that name.
         * Ends as an unfiltered listing ends, with FS_RC_ENDDIR, or passes an
         * error through. */
        uint32_t seen = 0;
        for (uint32_t idx = 0; ; idx++) {
            r2.offset = idx;
            handle(&r2, rp, cuid, cgid);
            if (rp->rc != 0) break;
            int vis = !fs_pol_hidden(&pol, obj, rp->name) && !fs_pol_private(&pol, rp->name) &&
                      (pol.node < 0 ||
                       fsp_visible(&pol.s->tree, pol.node, rp->name, rp->type == FS_TYPE_DIR));
            if (vis) {
                if (seen == rq->offset) break;
                seen++;
            }
        }
        if (rp->rc == FS_RC_ENDDIR && rq->offset == seen && pol.s->tmp_ino != 0 &&
            fs_pol_private(&pol, "tmp")) {
            umemset(rp, 0, sizeof(*rp));
            rp->magic = FS_PROTO_MAGIC;
            rp->ino = pol.s->tmp_ino;
            rp->type = FS_TYPE_DIR;
            ustrncpy(rp->name, "tmp", FS_NAME_MAX);
        }
    } else {
        handle(&r2, rp, cuid, cgid);
        if (rq->op == FS_OP_STAT && rp->rc == 0) {
            /* THE TRUTHFUL VIEW (§7.1). Owner bits are this capability's
             * rights, as far as its node lets it use them; group bits are zero;
             * other bits are the bound on everyone else's. Nothing on the disk
             * is consulted for them: decision 1, the disk holds no authority.
             * uid and gid say "you": the caller's own, as the kernel attests
             * them for this request. They describe the caller and authorise
             * nothing; the capability already decided. */
            rp->mode = fsp_mode(have & FS_R_ALL, fs_pol_other(&pol, rp->links),
                                rp->type == FS_TYPE_DIR);
            rp->uid = cuid;
            rp->gid = cgid;
        }
        /* The child a lookup, create or mkdir names: is it in this session? */
        if (rp->rc == 0 && (rq->op == FS_OP_LOOKUP || rq->op == FS_OP_CREATE ||
                            rq->op == FS_OP_MKDIR) &&
            fs_pol_step(&pol, rq->name, rp->type) != 0) {
            umemset(rp, 0, sizeof(*rp));
            rp->magic = FS_PROTO_MAGIC;
            rp->rc = SYS_ERR_NOENT;
        }
    }
    g_by_cap = 0;

    if (rp->rc == 0 && (rq->op == FS_OP_LOOKUP || rq->op == FS_OP_WALK ||
                        rq->op == FS_OP_CREATE || rq->op == FS_OP_MKDIR)
        && rp->ino < FS_GEN_INODES && !(g_gen[rp->ino] & FS_GEN_RETIRED)) {
        /* A CHILD CARRIES AT MOST ITS DIRECTORY'S RIGHTS (§5.3): a directory
         * keeps every file right so files below it can still have them, a file
         * keeps only the rights that mean something on a file. The kernel
         * intersects with the invoking capability again on the way out. */
        uint32_t keep = (rp->type == FS_TYPE_DIR) ? FS_R_ALL : FS_R_FILE_MASK;
        /* In a session, at most what the policy gives the child: the union of
         * its subtree if it is tracked, exactly its granted rights if not
         * (pol.carry, set by the step). Outside one, carry is every right. */
        keep &= pol.carry;
        /* And the kernel's own rights it already had: send (WRITE), pass on
         * (GRANT), make narrowed copies of it (MINT; a token is never minted from
         * a tokened capability, so this cannot make a new one, §5.1) and revoke
         * those copies (REVOKE). */
        *mint_rights = (inv->rights & keep) | (inv->rights & FS_KERNEL_RIGHTS);
        /* The child keeps the session's grant set, tracked or not, so §5.5 and
         * §7 can later say which grant it descends from. */
        int tracked = pol.node >= 0;
        *mint_token = fs_token_in(rp->ino, g_gen[rp->ino], pol.s ? g : 0,
                                  pol.at >= 0 ? (uint32_t)pol.at : 0, tracked);
        if (tracked) fs_session_bind(pol.s, pol.node, rp->ino);
    }
}

/* ---- opening and ending sessions (§6.4) ------------------------------------ */

static struct fsp_policy g_policy;          /* scratch: parsed afresh at each open */
static char g_policy_text[FSP_MAX_BYTES];

/* Read /etc/fs.policy from the store into g_policy_text. 1 when present (*len
 * set; a file over the bound, or one that is not a regular file, reports a
 * length the parser refuses, so it is malformed rather than absent), 0 when
 * absent, -1 when the store could not be read: a policy that might exist is
 * never taken for one that does not. */
static int read_policy_file(uint32_t *len)
{
    struct fs_stat st;
    uint32_t etc, ino, type;
    *len = 0;
    if (sys_fs_stat(0, &st) != 0) return -1;
    if (!dir_find(0, "etc", &etc, &type) || type != FS_TYPE_DIR) return 0;
    if (!dir_find(etc, "fs.policy", &ino, &type)) return 0;
    if (sys_fs_stat(ino, &st) != 0) return -1;
    if (st.type != FS_TYPE_FILE || st.size > FSP_MAX_BYTES) { *len = FSP_MAX_BYTES + 1; return 1; }
    static uint8_t blk[BLK];
    for (uint32_t off = 0; off < (uint32_t)st.size; off += BLK) {
        if (sys_fblock_read(ino, off / BLK, blk) != (int)BLK) return -1;
        uint32_t n = (uint32_t)st.size - off;
        if (n > BLK) n = BLK;
        umemcpy(g_policy_text + off, blk, n);
    }
    *len = (uint32_t)st.size;
    return 1;
}

/* The session's working directory: its home, walked from the root through the
 * policy as a client's walk would be, so it carries exactly what a walk there
 * would have given. None if the home is missing, not a directory, or not in
 * this session. A home of "/" is the root itself. */
static void session_cwd(struct fs_session *s, uint32_t g, const char *home,
                        struct fs_session_grant *sg)
{
    char comp[FSP_MAX_DEPTH][FSP_NAME];
    int d = fsp_split(home, uslen(home), comp);
    if (d < 0) return;
    if (d == 0) { sg->cwd_token = sg->root_token; sg->cwd_rights = sg->root_rights; return; }
    struct fs_pol pol = { s, s->tree.node[0].nchild > 0 ? 0 : -1, 0, s->tree.node[0].below };
    uint32_t cur = 0, type = FS_TYPE_DIR;
    for (int k = 0; k < d; k++) {
        uint32_t ino;
        if (!dir_find(cur, comp[k], &ino, &type)) return;
        if (fs_pol_step(&pol, comp[k], type) != 0) return;
        cur = ino;
    }
    if (type != FS_TYPE_DIR || cur >= FS_GEN_INODES || (g_gen[cur] & FS_GEN_RETIRED)) return;
    int tracked = pol.node >= 0;
    if (tracked) fs_session_bind(s, pol.node, cur);
    sg->cwd_token = fs_token_in(cur, g_gen[cur], g, (uint32_t)pol.at, tracked);
    sg->cwd_rights = (pol.carry & FS_R_ALL) | FS_KERNEL_RIGHTS;
}

/* Remove everything below directory `top`, however deep, and leave `top`.
 *
 * NO DEPTH BOUND, unlike remove_tree, and that is the point: a session decides
 * what its /tmp holds, so a bound would let it nest a tree one level deeper than
 * the bound and keep it past its end. Memory stays bounded instead: each round
 * walks down from `top` along the first subdirectory to one that has none,
 * removing the files it passes in the bottom one, and removes that directory
 * from its parent. Rounds are bounded too, so a directory that cannot be
 * removed stops the sweep rather than spinning it. Returns 0 when `top` is
 * empty, -1 when something could not be removed. */
static int empty_tree(uint32_t top)
{
    for (uint32_t round = 0; round < FS_GEN_INODES; round++) {
        uint32_t parent = top, cur = top;
        char name[FS_NAME_MAX];
        int depth = 0;
        for (;;) {
            uint32_t idx = 0, cino, ctype;
            char cname[FS_NAME_MAX];
            int sub = 0;
            while (dir_get(cur, idx, &cino, &ctype, cname)) {
                if (ctype == FS_TYPE_DIR) { sub = 1; break; }
                if (dir_remove(cur, cname)) fs_ino_free(cino);
                else idx++;                     /* stubborn: step past, never refetch */
            }
            if (!sub) break;
            parent = cur;
            ustrncpy(name, cname, FS_NAME_MAX);
            cur = cino;
            depth++;
        }
        uint32_t ci, ct;
        char cn[FS_NAME_MAX];
        if (dir_get(cur, 0, &ci, &ct, cn)) return -1;   /* a file would not go */
        if (depth == 0) return 0;                       /* top itself is empty */
        if (!dir_remove(parent, name)) return -1;
        fs_ino_free(cur);
    }
    return -1;
}

/* The store of private /tmps, made if missing: root-owned 0700, so that the
 * uid path, until step 6 removes it, refuses it to everyone but root. */
static int session_tmp_store(uint32_t *out)
{
    uint32_t ino, type;
    if (dir_find(0, FS_SESSION_TMP_STORE_NAME, &ino, &type)) {
        if (type != FS_TYPE_DIR) return -1;
        *out = ino;
        return 0;
    }
    int n = sys_fs_inode_alloc(FS_TYPE_DIR);
    if (n < 0) return -1;
    sys_fs_set_meta((uint32_t)n, 0700u, 0, 0);
    if (dir_add(0, FS_SESSION_TMP_STORE_NAME, (uint32_t)n, FS_TYPE_DIR) != 0) {
        fs_ino_free((uint32_t)n);
        return -1;
    }
    *out = (uint32_t)n;
    return 0;
}

static void session_tmp_name(uint32_t g, char out[4])
{
    out[0] = (char)('0' + g / 10);
    out[1] = (char)('0' + g % 10);
    out[2] = 0;
}

/* Make session g's private /tmp, owned by its account and 0700 for the uid
 * path's sake. The first session of a boot first clears whatever a session of
 * an earlier boot left (a crash, a power cut): no session of this boot exists
 * yet, so everything there is a leftover. Returns the directory, or 0. */
static uint32_t session_tmp_make(uint32_t g, uint32_t uid, uint32_t gid)
{
    static int swept;
    uint32_t store;
    if (session_tmp_store(&store) != 0) return 0;
    if (!swept) {
        if (empty_tree(store) != 0)
            kputln("[fs_server] an earlier boot's session /tmp could not all be removed");
        swept = 1;
    }
    char nm[4];
    session_tmp_name(g, nm);
    uint32_t old, type;
    if (dir_find(store, nm, &old, &type)) {
        /* G is free, so this is one a failed sweep left: it must not be handed
         * to a new session with its contents. */
        if (type != FS_TYPE_DIR || empty_tree(old) != 0) return 0;
        if (!dir_remove(store, nm)) return 0;
        fs_ino_free(old);
    }
    int n = sys_fs_inode_alloc(FS_TYPE_DIR);
    if (n < 0) return 0;
    sys_fs_set_meta((uint32_t)n, 0700u, uid, gid);
    if (dir_add(store, nm, (uint32_t)n, FS_TYPE_DIR) != 0) {
        fs_ino_free((uint32_t)n);
        return 0;
    }
    return (uint32_t)n;
}

/* Remove session g's private /tmp and all it holds. */
static void session_tmp_remove(uint32_t g, uint32_t ino)
{
    uint32_t store, found, type;
    char nm[4];
#ifdef FS_SESSION_TMP_KEPT
    /* CONTROL ARM, never ship (smoke-fs-cap-session-tmp-kept-control): nothing
     * is removed, so a session's /tmp outlives its end. */
    (void)store; (void)found; (void)type; (void)nm; (void)g; (void)ino;
    return;
#endif
    session_tmp_name(g, nm);
    if (session_tmp_store(&store) != 0 || !dir_find(store, nm, &found, &type) || found != ino) return;
    if (empty_tree(ino) != 0 || !dir_remove(store, nm)) {
        kputln("[fs_server] a session's /tmp could not all be removed; the next boot's first session clears it");
        return;
    }
    fs_ino_free(ino);
}

/* FS_OP_SESSION: compile the account's grants into a free grant set and say
 * what init is to mint. The account comes from the kernel's list, by the uid
 * init read from the kernel's attestation of the login; the policy from the
 * store, by the store's kind as the kernel reports it (SYS_FS_STORE_KIND), never
 * from anything in the request. */
static void session_open(const struct fs_request *rq, struct fs_response *rp)
{
    struct user_entry e, x;
    int found = 0;
    /* The administrator's name too: lines naming it are the administrator's,
     * and never counted as someone else's reach (decision 16). */
    static char admin_name[sizeof(x.name)];
    admin_name[0] = 0;
    for (uint32_t i = 0; sys_userlist(i, &x) == 1; i++) {
        x.name[sizeof(x.name) - 1] = 0;
        if (x.uid == 0) ustrncpy(admin_name, x.name, sizeof(admin_name));
        if (x.uid == rq->arg_uid && !found) { e = x; found = 1; }
    }
    if (!found) { rp->rc = SYS_ERR_NOENT; return; }
    e.name[sizeof(e.name) - 1] = 0;
    e.home[sizeof(e.home) - 1] = 0;

    /* Only an answer of EPHEMERAL gives the default: anything else, a refusal
     * included, is treated as a persistent volume, which is the narrower rule. */
    int ephemeral = sys_fs_store_kind() == FS_STORE_EPHEMERAL;
    uint32_t len = 0;
    int have = 0;
    if (!ephemeral) {
        have = read_policy_file(&len);
        if (have < 0) { rp->rc = SYS_ERR_IO; return; }
    }
    unsigned bad = 0;
    int src = fsp_load(ephemeral, have, g_policy_text, len, &g_policy, &bad);
    if (src == FS_SESSION_SRC_MALFORMED) {
        kput("[fs_server] /etc/fs.policy does not parse (line ");
        kput_int((int)bad);
        kputln("); treated as absent: the administrator alone");
    }
    /* A different policy from the last one compiled starts a new epoch, and
     * every session already open is now behind it (g_policy_epoch). Compared as
     * text, so an edit that changes nothing still counts: that only overstates
     * until the next login. */
    {
        uint32_t tl = (src == FS_SESSION_SRC_FILE) ? len : 0;
        int same = g_policy_seen && g_policy_seen_src == src && g_policy_seen_len == tl;
        for (uint32_t i = 0; same && i < tl; i++)
            if (g_policy_seen_text[i] != g_policy_text[i]) same = 0;
        if (!same) {
            if (g_policy_seen) g_policy_epoch++;
            g_policy_seen = 1;
            g_policy_seen_src = src;
            g_policy_seen_len = tl;
            umemcpy(g_policy_seen_text, g_policy_text, tl);
        }
    }

    /* NEXT FIT, not lowest free. Reusing a grant set while a capability naming
     * it lives would hand that capability the new session's policy, and the
     * protocol rules it out (init revokes a session's capabilities before it
     * ends it). Taking the next free set after the last one handed out keeps a
     * just-ended set unused for as long as 62 others are free, so a mistake in
     * that order is far less likely to land on a live session. */
    static uint32_t last_g;
    uint32_t g = 0;
    for (uint32_t i = 0; i < FS_SESSIONS_MAX; i++) {
        uint32_t c = (last_g + i) % FS_SESSIONS_MAX + 1;
        if (!g_sess[c].live) { g = c; break; }
    }
    if (g == 0) { rp->rc = SYS_ERR_BUSY; return; }
    struct fs_session *s = &g_sess[g];
    struct fsp_who who = { e.name, e.home, e.uid == 0, admin_name[0] ? admin_name : 0 };
    if (fsp_compile(&g_policy, &who, &s->tree) != 0) {
        kputln("[fs_server] a session's grants cannot be compiled; session refused");
        rp->rc = SYS_ERR_NOMEM;
        return;
    }

    struct fs_session_grant sg;
    umemset(&sg, 0, sizeof(sg));
    sg.source = (uint32_t)src;
    struct fsp_node *root = &s->tree.node[0];
    if (root->below != 0) {
        int tracked = root->nchild > 0;
        if (tracked) fs_session_bind(s, 0, 0);
        sg.g = g;
        sg.root_token = fs_token_in(0, g_gen[0], g, 0, tracked);
        sg.root_rights = root->below | FS_KERNEL_RIGHTS;
        session_cwd(s, g, e.home, &sg);
        /* Its private /tmp, if the policy gives one. A /tmp that cannot be made
         * (a full volume) leaves the session without one, answered as absent,
         * rather than refusing the login that might be the one to free space. */
        s->tmp_ino = 0;
        for (unsigned i = 1; i < s->tree.n; i++) {
            if (!s->tree.node[i].private_tmp) continue;
#ifdef FS_SESSION_TMP_SHARED
            /* CONTROL ARM, never ship (smoke-fs-cap-session-tmp-shared-control):
             * every session is given the same directory, one shared /tmp. */
            static uint32_t shared;
            if (!shared) shared = session_tmp_make(FS_SESSIONS_MAX + 1, 0, 0);
            s->tmp_ino = shared;
#else
            s->tmp_ino = session_tmp_make(g, e.uid, e.gid);
#endif
            if (s->tmp_ino == 0) kputln("[fs_server] a session's /tmp could not be made; it has none");
            break;
        }
        s->epoch = g_policy_epoch;
        s->live = 1;
        last_g = g;
    }
    umemcpy(rp->data, &sg, sizeof(sg));
    rp->rc = 0;
}

/* FS_OP_SESSION and FS_OP_SESSION_END are answered ONLY through the untokened
 * capability that holds MINT (§6.4). init created the endpoint and alone holds
 * one; every client capability is tokened, or WRITE-only from
 * SYS_CONNECT_FS_SERVER. So opening a session is authorised by a capability,
 * never by who asks. FS_SESSION_ANY_CALLER=1 is the control arm
 * (make smoke-fs-cap-session-caller-control). */
static void session_request(const struct fs_request *rq, struct fs_response *rp,
                            const struct ipc_invoker *inv)
{
    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;
    if (rq->magic != FS_PROTO_MAGIC) { rp->rc = SYS_ERR_INVAL; return; }
#ifndef FS_SESSION_ANY_CALLER
    if (inv->token != 0 || !(inv->rights & CAP_RIGHT_MINT)) { rp->rc = SYS_ERR_PERM; return; }
#else
    (void)inv;
#endif
    if (rq->op == FS_OP_SESSION) { session_open(rq, rp); return; }
    uint32_t g = rq->offset;
    if (g == 0 || g > FS_SESSIONS_MAX || !g_sess[g].live) { rp->rc = SYS_ERR_NOENT; return; }
    /* Its /tmp goes with it. init has already revoked every capability the
     * session held, so nothing can be writing there. */
    if (g_sess[g].tmp_ino) session_tmp_remove(g, g_sess[g].tmp_ino);
    umemset(&g_sess[g], 0, sizeof(g_sess[g]));
    rp->rc = 0;
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
/* Does file `ino` hold exactly the `size` bytes of boot module `mod_index` that
 * start at `mod_off`? (`mod_off` is 0 for a module that is one file, and a
 * member's offset for a module that is an archive; see unpack_archive_module.) */
static int file_matches_module(uint32_t ino, uint32_t mod_index, uint32_t mod_off, uint32_t size) {
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
        if (sys_boot_module_read(mod_index, mod_off + off, mb, chunk) != (int)chunk) return 0;
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

static int install_module_at(const char *path, uint32_t mod_index, uint32_t mod_off, uint32_t size) {
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
        if (etype == FS_TYPE_FILE && file_matches_module(eino, mod_index, mod_off, size)) {
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
        int got = sys_boot_module_read(mod_index, mod_off + off, buf, chunk);
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

/* ---- archive modules (docs/design/configuration.md §4) ---------------------
 *
 * WHY A MODULE CAN BE AN ARCHIVE. MAX_BOOT_MODULES is 48 and an install image
 * already uses about 30, so forty-odd manual pages cannot each be a module. They
 * ship as ONE module, a ustar archive the build makes reproducibly, verified by
 * its hash like every other module (S96), and unpacked here into one system
 * directory. A module is an archive when its destination is `pack/<dir>`: the
 * members land in <dir>, which must itself be a destination module_dest_ok
 * accepts, and they are then ordinary system-tree files, compared, re-marked and
 * pruned like any module (S116).
 *
 * WHAT A MEMBER MAY BE, and the archive is refused WHOLE on the first that is
 * not: a regular file (typeflag '0' or NUL), with a ustar magic, no prefix
 * field, and a name that is one leaf of 1 to FS_NAME_MAX-1 characters drawn
 * from [A-Za-z0-9._-], not "." or "..". No directory, no link, no device, no
 * path. The archive is checked END TO END before anything is installed, so a
 * malformed one installs nothing rather than a prefix. The bytes are verified
 * by the boot chain already; these checks are so that a mistake in the build,
 * or a future archive with a laxer maker, cannot place a file outside its one
 * directory or make this server walk off the end of a module. */
#define TAR_BLOCK 512u

static uint32_t tar_octal(const uint8_t *f, int n, int *ok) {
    uint32_t v = 0; int i = 0, digits = 0;
    while (i < n && f[i] == ' ') i++;
    for (; i < n && f[i] >= '0' && f[i] <= '7'; i++) {
        if (v > (0xFFFFFFFFu >> 3)) { *ok = 0; return 0; }
        v = (v << 3) | (uint32_t)(f[i] - '0');
        digits++;
    }
    for (; i < n; i++) if (f[i] != 0 && f[i] != ' ') { *ok = 0; return 0; }
    if (!digits) *ok = 0;
    return v;
}

static int tar_block_zero(const uint8_t *h) {
    for (uint32_t i = 0; i < TAR_BLOCK; i++) if (h[i]) return 0;
    return 1;
}

/* Check one header; on success copy the member's leaf name into `leaf` and its
 * size into *size. */
static int tar_member_ok(const uint8_t *h, char *leaf, uint32_t *size) {
    if (!(h[257] == 'u' && h[258] == 's' && h[259] == 't' && h[260] == 'a' && h[261] == 'r'))
        return 0;
    if (h[156] != '0' && h[156] != 0) return 0;            /* regular files only */
    if (h[345] != 0) return 0;                              /* no prefix: one leaf */
    /* The header checksum: the 512 bytes summed with the checksum field read
     * as spaces. A build that wrote the archive wrongly is caught here. */
    int ok = 1;
    uint32_t want = tar_octal(h + 148, 8, &ok);
    uint32_t sum = 0;
    for (uint32_t i = 0; i < TAR_BLOCK; i++) sum += (i >= 148 && i < 156) ? ' ' : h[i];
    if (!ok || sum != want) return 0;
    int n = 0;
    while (n < 100 && h[n]) {
        char c = (char)h[n];
        int good = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!good || n >= FS_NAME_MAX - 1) return 0;
        leaf[n] = c; n++;
    }
    if (n == 0 || n == 100) return 0;
    leaf[n] = 0;
    if ((n == 1 && leaf[0] == '.') || (n == 2 && leaf[0] == '.' && leaf[1] == '.')) return 0;
    ok = 1;
    *size = tar_octal(h + 124, 12, &ok);
    return ok;
}

/* Walk archive module `mod_index` (`msize` bytes). With `install` 0, only check
 * it; with 1, install every member under `dir` as a system-tree file; with 2,
 * seed each member into `dir` only where no file of its name exists
 * (seed_archive_module). Returns the member count, or -1 if the archive is
 * malformed anywhere. */
static int seed_file_at(uint32_t dir_ino, const char *leaf, uint32_t mod_index,
                        uint32_t mod_off, uint32_t size);
static int walk_archive(uint32_t mod_index, uint32_t msize, const char *dir, int install) {
    static uint8_t h[TAR_BLOCK];
    uint32_t off = 0;
    int members = 0;
    for (;;) {
        if (off > msize || msize - off < TAR_BLOCK) return -1;   /* no end marker */
        if (sys_boot_module_read(mod_index, off, h, TAR_BLOCK) != (int)TAR_BLOCK) return -1;
        if (tar_block_zero(h)) return members;                 /* end of archive */
        char leaf[FS_NAME_MAX];
        uint32_t size;
        if (!tar_member_ok(h, leaf, &size)) return -1;
        uint32_t data = off + TAR_BLOCK;
        uint32_t padded = (size + TAR_BLOCK - 1) & ~(TAR_BLOCK - 1);
        if (size > msize || data > msize - size || padded < size ||
            data + padded > msize) return -1;
        if (install == 2) {
            int d = ensure_dir_path(dir);
            if (d < 0 || (size > 0 && seed_file_at((uint32_t)d, leaf, mod_index, data, size) < 0)) return -1;
        } else if (install) {
            char path[FS_NAME_MAX * 6];
            int n = 0;
            for (const char *q = dir; *q && n < (int)sizeof(path) - 2; q++) path[n++] = *q;
            path[n++] = '/';
            for (const char *q = leaf; *q && n < (int)sizeof(path) - 1; q++) path[n++] = *q;
            path[n] = 0;
            if (size > 0 && install_module_at(path, mod_index, data, size) < 0) return -1;
        }
        members++;
        off = data + padded;
    }
}

/* Write `size` bytes of module `mod_index` from `mod_off` as a NEW file `leaf` in
 * directory `dir_ino`, root-owned 0644, if and only if no entry of that name is
 * there. The /etc defaults (docs/design/configuration.md, rule 7): seeded, never
 * imposed, so an administrator's edit survives every boot. Not marked as a
 * system inode, because /etc is not a system tree. 1 written, 0 left alone, -1
 * on failure. */
static int seed_file_at(uint32_t dir_ino, const char *leaf, uint32_t mod_index,
                        uint32_t mod_off, uint32_t size) {
    if (dir_find(dir_ino, leaf, 0, 0)) return 0;
    int ino = sys_fs_inode_alloc(FS_TYPE_FILE);
    if (ino < 0) return -1;
    sys_fs_set_meta((uint32_t)ino, 0644u, 0, 0);
    static uint8_t buf[BLK];
    uint32_t off = 0, blk = 0;
    while (off < size) {
        uint32_t chunk = size - off; if (chunk > BLK) chunk = BLK;
        int got = sys_boot_module_read(mod_index, mod_off + off, buf, chunk);
        if (got <= 0 || sys_fblock_write((uint32_t)ino, blk, buf, (uint32_t)got) != got) {
            fs_ino_free((uint32_t)ino); return -1;
        }
        off += (uint32_t)got; blk++;
    }
    sys_fs_set_size((uint32_t)ino, size);
    if (dir_add(dir_ino, leaf, (uint32_t)ino, FS_TYPE_FILE) != 0) { fs_ino_free((uint32_t)ino); return -1; }
    return 1;
}

/* Seed /etc from archive module `mod_index`: the archive is checked whole, as
 * any archive is, and then each member is written only where no file of its
 * name exists. "etc" is the one directory a seed archive may name. */
static int seed_archive_module(uint32_t mod_index, uint32_t msize, const char *dir) {
    if (!(dir[0] == 'e' && dir[1] == 't' && dir[2] == 'c' && dir[3] == 0)) {
        kputln("[fs_server] refusing a seed archive for anywhere but /etc");
        return -1;
    }
    if (walk_archive(mod_index, msize, dir, 0) < 0) {
        kputln("[fs_server] refusing a malformed seed archive: nothing from it written");
        return -1;
    }
    return walk_archive(mod_index, msize, dir, 2);
}

/* Unpack archive module `mod_index` into `dir`. Returns members installed, or -1
 * (nothing installed) if the archive or its directory is refused. */
static int unpack_archive_module(uint32_t mod_index, uint32_t msize, const char *dir) {
    char probe[FS_NAME_MAX * 6];
    int n = 0;
    for (const char *q = dir; *q && n < (int)sizeof(probe) - 3; q++) probe[n++] = *q;
    probe[n++] = '/'; probe[n++] = 'x'; probe[n] = 0;
    if (!module_dest_ok(probe) || n < 3) {
        kputln("[fs_server] refusing an archive module with a disallowed directory");
        return -1;
    }
#ifndef ARCHIVE_NO_PRECHECK
    if (walk_archive(mod_index, msize, dir, 0) < 0) {
        kputln("[fs_server] refusing a malformed archive module: nothing from it installed");
        return -1;
    }
#else
    /* CONTROL ARM -- never ship. Install as the walk goes, checking each member
     * only when it is reached, so the members before a bad one land. See make
     * smoke-archive-refused-control. */
#endif
    return walk_archive(mod_index, msize, dir, 1);
}

static void provision_boot_modules(void);

/* If the volume has been unlocked, provision now. Returns 1 once provisioned. */
static int try_provision_after_unlock(void) {
    struct fs_stat root_st;
    if (sys_fs_stat(0, &root_st) != 0) return 0;
    kputln("FS_STORE: unlocked; provisioning now");
    provision_boot_modules();
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
     * operator's and is left as it is. /tmp is not made: there is no shared
     * /tmp, by design (§6.3). Each session gets a private one when it opens
     * (session_tmp_make, S129), which needs no sticky rule because nobody else
     * holds a capability to it. */
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
        if (has_prefix(info.name, "seed/")) {
            if (seed_archive_module((uint32_t)i, info.size, info.name + 5) < 0) skipped++;
            continue;
        }
        if (has_prefix(info.name, "pack/")) {
            int m = unpack_archive_module((uint32_t)i, info.size, info.name + 5);
            if (m < 0) skipped++;
            else {
                kput("[fs_server] archive module unpacked into /");
                kput(info.name + 5);
                kput(": ");
                kput_int(m);
                kputln(" files");
            }
            continue;
        }
        int rc = install_module_at(info.name, (uint32_t)i, 0, info.size);
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
#ifdef ARCHIVE_PROBE
    /* make smoke-archive-refused: the build shipped a second archive whose first
     * member is a good file and whose second is a symbolic link, which no archive
     * may carry. The whole archive must be refused, so the good member must not
     * be here. Said both ways, so a red run names what it saw. */
    {
        int d = ensure_dir_path("usr/share/doc");
        if (d >= 0 && dir_find((uint32_t)d, "archive-probe-good", 0, 0))
            kputln("ARCHIVE PROBE: FAIL a refused archive left a member installed");
        else
            kputln("ARCHIVE PROBE: nothing from the refused archive installed");
    }
#endif
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

    /* Which store this is decides every session's policy (§6.4), so say it once
     * where the log shows which rule this boot will apply. Asked again at each
     * session rather than cached: the kernel answers about the store it serves. */
    {
        int kind = sys_fs_store_kind();
        kputln(kind == FS_STORE_EPHEMERAL  ? "FS_STORE: ephemeral; sessions get the compiled-in policy" :
               kind == FS_STORE_PERSISTENT ? "FS_STORE: persistent; sessions get /etc/fs.policy, or the administrator alone" :
                                             "FS_STORE: kind unknown; treated as persistent");
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
        /* Provision once the volume is open: here, before blocking, for an unlock
         * that a request this server just answered brought about, and again
         * below, before answering the first request that finds the volume open,
         * for one the kernel brought about on a login. A stat of the root inode
         * fails while the volume is sealed (S74). On the RAM disk this already
         * ran above. */
        if (!provisioned && try_provision_after_unlock()) provisioned = 1;
        int r;
#if defined(FS_SEALED_POLL_SPIN) || defined(FS_SEALED_POLL_YIELD)
        /* CONTROL ARMS: the sealed-volume wait as a POLL. Until 2026-10-12 it spun
         * (spin_delay burns the whole time slice, and on one CPU the installer
         * dropped keystrokes: smoke-keyboard-install-spin-control); until
         * 2026-10-13 it yielded, which gave the CPU back but stayed runnable for
         * the whole of an install, and on a sealed installed machine until the
         * first login (smoke-installer-provision-poll-control). */
        if (!provisioned) {
            r = sys_ipc_recv(CAPSLOT_FS_LISTEN, (char *)&rq, sizeof(rq));
            if (r < 0) {
#ifdef FS_SEALED_POLL_SPIN
                spin_delay();
#else
                sys_yield();
#endif
                continue;
            }
        } else
#endif
        {
            /* SLEEP UNTIL A REQUEST ARRIVES, sealed or not (roadmap 1.3,
             * LIMITATIONS 3.6). The server used to poll while the volume was
             * sealed so that it would notice the unlock, but nothing needs it to
             * notice before a request does: provisioning exists to make the
             * system trees there for whoever asks, and the check below runs
             * before the first request after the unlock is answered. Blocking
             * keeps an idle machine idle for the whole of an install and at an
             * installed machine's login prompt. smoke-fs-sealed-sleep counts, in
             * the kernel, the empty polls this server makes while sealed: none.
             *
             * As in console_server: a negative return from the blocking receive
             * is permanent (it never returns IPC_AGAIN), so retrying it in a loop
             * would be the G-8 wedge rather than back-pressure. */
            r = sys_ipc_recv_block(CAPSLOT_FS_LISTEN, (char *)&rq, sizeof(rq));
            if (r < 0) { kputln("[fs_server] listen capability lost; exiting"); sys_exit(); }
        }
        if (!provisioned && try_provision_after_unlock()) provisioned = 1;

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
        } else if (rq.op == FS_OP_SESSION || rq.op == FS_OP_SESSION_END) {
            session_request(&rq, &rp, &inv);
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
