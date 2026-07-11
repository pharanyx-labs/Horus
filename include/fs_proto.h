#ifndef HORUS_FS_PROTO_H
#define HORUS_FS_PROTO_H

/* IPC protocol between clients and the userspace filesystem server (Phase 2).
 *
 * Transport is the kernel's single-slot endpoint mailbox (IPC_MSG_MAX = 256),
 * so BOTH structs below must stay <= 256 bytes. The exchange is one request
 * then one reply on the same endpoint (client: send then recv; server: recv,
 * process, reply) — i.e. one in-flight request at a time (single-client;
 * concurrent clients are a documented follow-up).
 *
 * The server persists everything through the kernel's encrypted object-store
 * syscalls (SYS_FS_INODE_ALLOC/FREE, SYS_FBLOCK_READ/WRITE, SYS_FS_STAT); it
 * never sees key material. Directories are ordinary inode data holding an array
 * of `fs_dirent` records; the root directory is inode 0.
 */

#include <stdint.h>

#define FS_PROTO_MAGIC   0x48465250u   /* "HFRP" */

/* Well-known endpoint indices for the FS service. Requests and replies use
 * SEPARATE endpoints: the kernel mailbox has a single message slot, so sharing
 * one endpoint would let a client read back its own request as the "reply".
 * (One in-flight request at a time — concurrent clients are a follow-up.) */
#define FS_EP_REQ   4   /* client -> server requests */
#define FS_EP_REP   5   /* server -> client replies  */

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
    uint32_t offset;                /* byte offset (read/write); entry index (readdir) */
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
    uint32_t size;                  /* file size (stat) or bytes returned (read) */
    uint32_t mode;                  /* permission bits (stat) */
    uint32_t uid;                   /* owner uid (stat) */
    uint32_t gid;                   /* owner gid (stat) */
    char     name[FS_NAME_MAX];     /* readdir entry name */
    uint8_t  data[FS_IO_MAX];       /* read payload */
};                                  /* 32 + 32 + 176 = 240 <= 256 */

#endif /* HORUS_FS_PROTO_H */
