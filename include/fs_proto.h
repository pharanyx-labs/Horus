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

/* Operations. */
#define FS_OP_LOOKUP   1   /* dir_ino, name              -> ino, type            */
#define FS_OP_CREATE   2   /* dir_ino, name              -> ino (new file)       */
#define FS_OP_MKDIR    3   /* dir_ino, name              -> ino (new directory)  */
#define FS_OP_DELETE   4   /* dir_ino, name              -> 0                    */
#define FS_OP_READDIR  5   /* dir_ino, offset=index      -> name, ino, type      */
#define FS_OP_READ     6   /* ino, offset, len           -> data[size], size     */
#define FS_OP_WRITE    7   /* ino, offset, data[len]     -> size (bytes written) */
#define FS_OP_STAT     8   /* ino                        -> size, type           */

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
    uint32_t ino;                   /* target object (read/write/stat) */
    uint32_t offset;                /* byte offset (read/write); entry index (readdir) */
    uint32_t len;                   /* payload length (read/write) */
    char     name[FS_NAME_MAX];
    uint8_t  data[FS_IO_MAX];       /* write payload */
};                                  /* 24 + 32 + 176 = 232 <= 256 */

struct fs_response {
    uint32_t magic;                 /* FS_PROTO_MAGIC */
    int32_t  rc;                    /* 0 / bytes on success, negative SYS_ERR_* */
    uint32_t ino;                   /* result inode (lookup/create/mkdir/readdir) */
    uint32_t type;                  /* result/entry type */
    uint32_t size;                  /* file size (stat) or bytes returned (read) */
    char     name[FS_NAME_MAX];     /* readdir entry name */
    uint8_t  data[FS_IO_MAX];       /* read payload */
};                                  /* 20 + 32 + 176 = 228 <= 256 */

#endif /* HORUS_FS_PROTO_H */
