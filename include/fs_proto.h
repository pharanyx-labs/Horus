#ifndef HORUS_FS_PROTO_H
#define HORUS_FS_PROTO_H

/* IPC protocol between clients and the userspace filesystem server (Phase 2).
 *
 * Transport is the kernel's single-slot endpoint mailbox (IPC_MSG_MAX = 256),
 * so BOTH structs below must stay <= 256 bytes. A client issues one request and
 * blocks for the reply with SYS_IPC_CALL on FS_EP_REQ; the server does
 * recv(FS_EP_REQ), process, then SYS_IPC_REPLY_TO(FS_EP_REQ), which routes the
 * reply to that request's kernel-recorded sender. This makes CONCURRENT CLIENTS
 * safe: replies are delivered by identity, so two clients can never collide on a
 * shared reply endpoint. Requests still serialise through the single mailbox slot
 * (one processed at a time); a client whose request finds the slot full retries.
 *
 * The server persists everything through the kernel's encrypted object-store
 * syscalls (SYS_FS_INODE_ALLOC/FREE, SYS_FBLOCK_READ/WRITE, SYS_FS_STAT); it
 * never sees key material. Directories are ordinary inode data holding an array
 * of `fs_dirent` records; the root directory is inode 0.
 */

#include <stdint.h>
#include "errno.h"   /* SYS_ERR_* -- FS_RC_ENDDIR is one of them */

#define FS_PROTO_MAGIC   0x48465250u   /* "HFRP" */

/* The FS service's request endpoint OBJECT index.
 *
 * Since the capability-addressed IPC change (audit finding C-1) userspace does
 * NOT name this in a syscall: IPC arguments are cspace SLOTS, and the kernel
 * derives the object from the capability found there. The constant remains only
 * because the kernel mints the primordial capability against it (it is mirrored
 * in src/include/kernel.h) and the server names it when registering.
 *
 * FS_EP_REP is GONE. Clients used to park their blocking SYS_IPC_CALL on one
 * shared reply endpoint, so concurrent callers overwrote each other's waiter
 * (finding I-5). Every task now has a private kernel-allocated reply endpoint
 * (CAPSLOT_REPLY_EP), chosen by the kernel and nameable by no one else. */
#define FS_EP_REQ   4   /* client -> server requests (object index, not a slot) */

/* Legacy rights word for sys_connect_fs_server. Ignored by the kernel, which
 * now always mints the client capability WRITE-only — a client that could also
 * RECEIVE on the server's endpoint could dequeue its peers' requests and forge
 * the server's replies, which was the C-1 attack. Kept so existing callers
 * compile unchanged. */
#define CAP_R_W     0x3u

/* Operations. Access is enforced by the server against the caller's
 * kernel-attested uid/gid (SYS_IPC_SENDER) — never an identity the client sends. */
#define FS_OP_LOOKUP   1   /* dir_ino, name              -> ino, type   (needs x on dir) */
#define FS_OP_CREATE   2   /* dir_ino, name              -> ino          (needs w on dir) */
#define FS_OP_MKDIR    3   /* dir_ino, name              -> ino          (needs w on dir) */
#define FS_OP_DELETE   4   /* dir_ino, name              -> 0            (needs w on dir) */
#define FS_OP_READDIR  5   /* dir_ino, offset=index      -> name, ino, type (needs r on dir).
                            * Ends with FS_RC_ENDDIR, NOT with SYS_ERR_NOENT: see
                            * the note on FS_RC_ENDDIR below, which is a defect
                            * this protocol used to have rather than a nicety. */
#define FS_OP_READ     6   /* ino, offset, len           -> data[size], size (needs r on file) */
#define FS_OP_WRITE    7   /* ino, offset, data[len]     -> size         (needs w on file) */
#define FS_OP_STAT     8   /* ino                        -> size, type, mode, uid, gid */
#define FS_OP_CHMOD    9   /* ino, mode                  -> 0   (owner or root) */
#define FS_OP_CHOWN   10   /* ino, arg_uid, arg_gid      -> 0   (root only) */
#define FS_OP_RENAME  11   /* dir_ino=old parent, name=old name, ino=new parent,
                            * data=new name (NUL-terminated) -> 0
                            * (needs w on BOTH parent dirs). Replaces an existing
                            * target file; refuses a non-empty target dir; a
                            * directory may only be renamed within its own parent
                            * (no cross-parent dir move, so no cycle is possible). */
#define FS_OP_TRUNCATE 12  /* ino, offset=new length     -> 0   (needs w on file).
                            * Zeroes any already-allocated blocks in the truncated
                            * range so a later grow reads a clean hole, then sets
                            * the logical size. */
#define FS_OP_APPEND  13   /* ino, data[len]             -> size (needs w on file).
                            * As FS_OP_WRITE, except the server chooses the offset:
                            * it writes at the file's current end. `offset` in the
                            * request is ignored. This exists so O_APPEND cannot be
                            * implemented as a client-side stat-then-write, which
                            * would race another client extending the file in
                            * between; the server handles one request at a time, so
                            * reading the size and landing the data here is atomic
                            * against other clients. Both this and FS_OP_WRITE
                            * return the end offset of the write in `size`, so a
                            * client can track its file position without a
                            * follow-up stat. */
#define FS_OP_LINK    14   /* ino=source file, dir_ino=new parent, name=new name
                            * -> 0. Hard-link: add a second directory entry naming
                            * an existing regular file and bump its link count
                            * (needs w on the new parent dir, and owner-or-root on
                            * the source; directories are refused). unlink of
                            * either name then only frees the file once the last
                            * name is gone (FS_OP_DELETE drops one reference). */
#define FS_OP_WALK    15   /* data[len] = names, each NUL-terminated  -> ino, type,
                            * and ONE capability to the last (capability path only;
                            * needs LOOKUP). See FS_WALK below. */

/* READDIR's end-of-directory signal, and it is a SEPARATE VALUE from
 * SYS_ERR_NOENT on purpose.
 *
 * Until 2026-09-06 a server answered SYS_ERR_NOENT for BOTH "the offset is past
 * the last entry" and "that directory does not exist, or I could not stat it".
 * Two different facts, one code, and every caller in the tree resolved the
 * ambiguity the same way -- as end-of-directory, which is the fail-OPEN
 * direction for a listing. The consequence a user sees is `ls` printing nothing
 * and no error for a directory it could not read: an unreadable directory and an
 * empty one were indistinguishable, so a failure was reported as a fact about
 * the filesystem.
 *
 * The shell's `ls` reasoned explicitly from "sh_cwd_ino is a directory `cd`
 * already verified exists". That is untrue of its INITIAL value, 0, which no
 * `cd` ever verified -- so before the store is readable, or if the directory is
 * removed underneath, the listing is silently empty. `posix_readdir` was worse:
 * it returned "no more entries" for a permission failure and for a transport
 * failure too, so newlib's opendir/readdir reported an empty directory when it
 * had not spoken to the server at all.
 *
 * SYS_ERR_RANGE because that is what has actually happened: the OFFSET is past
 * the permitted range. It is not an error condition -- a caller walking a
 * directory to its end sees it every time -- which is why it must not share a
 * code with one.
 *
 * EVERY SERVER IMPLEMENTING THIS PROTOCOL MUST USE IT (fs_server and dev_server
 * both do), and every caller must treat anything else negative as a reason to
 * report rather than a reason to stop quietly. */
#define FS_RC_ENDDIR  SYS_ERR_RANGE


#define FS_NAME_MAX   32   /* directory entry name field (NUL-terminated) */
#define FS_IO_MAX    176   /* max data payload per request/response */

/* Directory entry as stored in a directory inode's data blocks (32 bytes; the
 * count per block is HORUS_BLOCK_SIZE/32, derived rather than written down --
 * fs_server computes DIRENTS_PER_BLK from it). ino == 0 marks a free slot. */
#define FS_DIRENT_NAME 24
struct fs_dirent {
    uint32_t ino;
    uint32_t type;                  /* FS_TYPE_FILE / FS_TYPE_DIR */
    char     name[FS_DIRENT_NAME];
};

struct fs_request {
    uint32_t magic;                 /* FS_PROTO_MAGIC */
    uint32_t op;
    uint32_t dir_ino;               /* parent dir (lookup/create/mkdir/delete/readdir) */
    uint32_t ino;                   /* target object (read/write/stat/chmod/chown) */
    uint32_t offset;                /* byte offset (read/write); entry index (readdir);
                                     * ignored for append (the server picks the end) */
    uint32_t len;                   /* payload length (read/write) */
    uint32_t mode;                  /* new permission bits (chmod) */
    uint32_t arg_uid;               /* new owner uid (chown) */
    uint32_t arg_gid;               /* new owner gid (chown) */
    char     name[FS_NAME_MAX];
    uint8_t  data[FS_IO_MAX];       /* write payload */
    /* NB: the request carries NO caller identity — the server takes the caller's
     * uid/gid from the kernel (SYS_IPC_SENDER), so a client cannot claim to be
     * another user. arg_uid/arg_gid are the *target* owner for chown, not the
     * caller. */
};                                  /* 36 + 32 + 176 = 244 <= 256 */

struct fs_response {
    uint32_t magic;                 /* FS_PROTO_MAGIC */
    int32_t  rc;                    /* 0 / bytes on success, negative SYS_ERR_* */
    uint32_t ino;                   /* result inode (lookup/create/mkdir/readdir) */
    uint32_t type;                  /* result/entry type */
    uint32_t size;                  /* file size (stat), bytes returned (read), or
                                     * end offset of the write (write/append) */
    uint32_t mode;                  /* permission bits (stat) */
    uint32_t uid;                   /* owner uid (stat) */
    uint32_t gid;                   /* owner gid (stat) */
    uint32_t links;                 /* hard-link count (stat) */
    char     name[FS_NAME_MAX];     /* readdir entry name */
    uint8_t  data[FS_IO_MAX];       /* read payload */
};                                  /* 36 + 32 + 176 = 244 <= 256 */

/* ---- Capability-addressed requests (docs/design/filesystem.md §5, phase 1b) --
 *
 * A request that arrives through a TOKENED capability to this endpoint names its
 * object by that token, not by the inode fields below: the kernel attests the
 * token and the capability's rights (SYS_IPC_INVOKER), so a client can neither
 * choose the object nor claim a right it was not given. The old ino-addressed
 * path, authorised by the caller's uid, stays beside this one until phase 1b
 * step 6 removes it.
 *
 * THE RIGHTS (§5.3) are bits of the endpoint capability's rights word, above the
 * kernel's own (bits 0-6). The kernel intersects them on every mint, so a right
 * only ever shrinks on the way down. CAP_RIGHT_WRITE (bit 1) is the kernel's
 * permission to send at all, and every file capability carries it. */
#define FS_R_LOOKUP   (1u << 10)   /* directory: derive a capability to a named child */
#define FS_R_CREATE   (1u << 11)   /* directory: add an entry (create, mkdir)        */
#define FS_R_DELETE   (1u << 12)   /* directory: remove an entry                      */
#define FS_R_READ     (1u << 13)   /* file: read, stat; directory: list, stat         */
#define FS_R_WRITE    (1u << 14)   /* file: overwrite, truncate                       */
#define FS_R_APPEND   (1u << 15)   /* file: write at the end only                     */
#define FS_R_SETATTR  (1u << 16)   /* file or directory: metadata (phase 1b step 4)    */
#define FS_R_EXEC     (1u << 17)   /* file: execute (advisory, §7.3)                   */
#define FS_R_ALL      (FS_R_LOOKUP | FS_R_CREATE | FS_R_DELETE | FS_R_READ | FS_R_WRITE | \
                       FS_R_APPEND | FS_R_SETATTR | FS_R_EXEC)
/* What makes sense on each kind of object: a child capability carries at most its
 * directory's rights, masked to these (§5.3, "only shrink"). */
#define FS_R_FILE_MASK (FS_R_READ | FS_R_WRITE | FS_R_APPEND | FS_R_SETATTR | FS_R_EXEC)
#define FS_R_DIR_MASK  (FS_R_READ | FS_R_LOOKUP | FS_R_CREATE | FS_R_DELETE | FS_R_SETATTR)

/* THE TOKEN (§5.2): bit 63 set (so a token is never 0, which means "untokened",
 * even for the root directory, inode 0), a 24-bit generation that fs_server keeps
 * per inode and raises when a name to it is removed (so a token never names a
 * different object than it was minted for: a stale one is refused NOENT), and the
 * inode. Bits 56-62 are reserved for the policy grant (§6, phase 1b step 3). */
#define FS_TOKEN_VALID      (1ULL << 63)
#define FS_TOKEN_GEN_MASK   0xFFFFFFu
static inline uint64_t fs_token(uint32_t ino, uint32_t gen) {
    return FS_TOKEN_VALID | ((uint64_t)(gen & FS_TOKEN_GEN_MASK) << 32) | ino;
}
static inline uint32_t fs_token_ino(uint64_t t) { return (uint32_t)t; }
static inline uint32_t fs_token_gen(uint64_t t) { return (uint32_t)(t >> 32) & FS_TOKEN_GEN_MASK; }

/* FS_WALK (docs/design/filesystem.md §5.4, decision 12): several names below the
 * directory capability invoked, answered with ONE capability to the last.
 *
 * Why it exists: a walk by FS_OP_LOOKUP leaves a capability per component, each
 * derived from the one before, and none can be let go alone, since revoking one
 * revokes everything below it. A task holds at most 128 capabilities, so a client
 * walking that way runs out. A walk's capability is derived straight from the
 * one invoked, so it is one slot, it is revoked with that one, and revoking it
 * (closing the file) takes nothing else with it.
 *
 * The request: `len` bytes of `data`, a run of names each ending in NUL, at
 * least one. Every name is checked before any is looked up (none empty, none
 * "." or "..", none holding "/", each shorter than FS_DIRENT_NAME), so a bad
 * name anywhere refuses the whole walk with INVAL. Each step is then an ordinary
 * LOOKUP, so a step from something that is not a directory is INVAL, and a
 * missing name NOENT, exactly as a LOOKUP answers. The server still never sees a
 * path, never interprets "..", and never follows a link: the client splits the
 * path and resolves those itself (§5.4). A path longer than one request walks
 * again from the capability the first walk gave. */
#define FS_WALK_BYTES  FS_IO_MAX

/* Pack `n` names into rq->data and rq->len for FS_OP_WALK. Returns 0, or
 * SYS_ERR_RANGE when they do not fit in one request (walk them in two). */
static inline int fs_walk_pack(uint8_t *data, uint32_t *len, const char *const *names, unsigned n)
{
    uint32_t at = 0;
    for (unsigned i = 0; i < n; i++) {
        const char *s = names[i];
        do {
            if (at >= FS_WALK_BYTES) return SYS_ERR_RANGE;
            data[at++] = (uint8_t)*s;
        } while (*s++);
    }
    *len = at;
    return 0;
}

#endif /* HORUS_FS_PROTO_H */
