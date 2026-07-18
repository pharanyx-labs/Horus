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

#define FS_PROTO_MAGIC   0x48465250u   /* "HFRP" */

/* Well-known endpoint indices for the FS service. Requests go to FS_EP_REQ;
 * replies are routed back to each caller by identity via SYS_IPC_REPLY_TO (see
 * above), so FS_EP_REP is only the endpoint a client parks its SYS_IPC_CALL block
 * on — not a shared mailbox other clients could read a reply from. */
#define FS_EP_REQ   4   /* client -> server requests */
#define FS_EP_REP   5   /* client's SYS_IPC_CALL reply-wait endpoint */

/* Rights a client requests when connecting (CAP_RIGHT_READ | CAP_RIGHT_WRITE),
 * enough to send requests and receive replies. */
#define CAP_R_W     0x3u

/* Operations. Access is enforced by the server against the caller's
 * kernel-attested uid/gid (SYS_IPC_SENDER) — never an identity the client sends. */
#define FS_OP_LOOKUP   1   /* dir_ino, name              -> ino, type   (needs x on dir) */
#define FS_OP_CREATE   2   /* dir_ino, name              -> ino          (needs w on dir) */
#define FS_OP_MKDIR    3   /* dir_ino, name              -> ino          (needs w on dir) */
#define FS_OP_DELETE   4   /* dir_ino, name              -> 0            (needs w on dir) */
#define FS_OP_READDIR  5   /* dir_ino, offset=index      -> name, ino, type (needs r on dir) */
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

#define FS_NAME_MAX   32   /* directory entry name field (NUL-terminated) */
#define FS_IO_MAX    176   /* max data payload per request/response */

/* Directory entry as stored in a directory inode's data blocks (32 bytes, so
 * 16 fit per 512-byte block). ino == 0 marks a free slot. */
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

#endif /* HORUS_FS_PROTO_H */
