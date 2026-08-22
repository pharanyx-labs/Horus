/* dev_server -- a second filesystem server, mounted at /dev (roadmap 2.4).
 *
 * WHY THIS EXISTS, AND WHY IT IS THIS SMALL.
 *
 * A mount table with one mount cannot demonstrate anything: every path resolves
 * to the same server, so "longest prefix wins" and "the capability decides, not
 * the path" are both unfalsifiable. This is the second mount, and it is
 * deliberately the smallest thing that can be one.
 *
 * WHAT MAKES IT THE RIGHT SECOND MOUNT is what it does NOT hold. fs_server is
 * endowed with CAP_ENCRYPTED_STORAGE (the object store), CAP_BOOT_MODULE (the
 * /bin provisioning surface) and CAP_USER (its registration gate). This server
 * is endowed with ONE capability: the listen end of its own endpoint. It has no
 * object store, no boot modules, no user database, and there is no syscall it
 * can reach that touches any of them.
 *
 * That is roadmap 2.4's sentence made real -- "each server holds only the
 * object-store capabilities for its own subtree" -- and it is a property of the
 * capability graph rather than of this file's restraint. A monolithic VFS could
 * not express it: a single server owning /dev and / necessarily holds both sets.
 *
 * It speaks the existing fs_proto rather than a device dialect of its own, so
 * the VFS needs no per-server knowledge and hvfs_walk does not care which
 * server answers a LOOKUP.
 *
 * /dev/null  -- writes are accepted and discarded; reads return EOF.
 * /dev/zero  -- reads return zeros; writes are accepted and discarded.
 *
 * Both are read-only in the permission sense that they cannot be created,
 * deleted or renamed: this server implements no mutating directory operation at
 * all, so those refusals are structural rather than checked.
 */
#include "syscall.h"
#include "libhorus.h"
#include "fs_proto.h"

/* Inode numbers this server serves. 0 is its root directory, which is what
 * `/dev` itself resolves to and what hvfs_mount's probe stats. */
#define DEV_INO_ROOT  0u
#define DEV_INO_NULL  1u
#define DEV_INO_ZERO  2u

/* The slot init grants the listen capability into. Distinct from
 * CAPSLOT_FS_LISTEN so that a task holding one server's listen right does not
 * accidentally hold the other's. */
#define DEV_LISTEN_SLOT  CAPSLOT_FS_LISTEN

static void reply_err(struct fs_response *rp, int rc) {
    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;
    rp->rc    = rc;
}

static void handle(const struct fs_request *rq, struct fs_response *rp) {
    umemset(rp, 0, sizeof(*rp));
    rp->magic = FS_PROTO_MAGIC;

    if (rq->magic != FS_PROTO_MAGIC) { reply_err(rp, SYS_ERR_INVAL); return; }

    switch (rq->op) {
    case FS_OP_LOOKUP:
        if (rq->dir_ino != DEV_INO_ROOT) { reply_err(rp, SYS_ERR_NOENT); return; }
        if (ustreq(rq->name, "null")) { rp->ino = DEV_INO_NULL; rp->type = FS_TYPE_FILE; rp->rc = 0; return; }
        if (ustreq(rq->name, "zero")) { rp->ino = DEV_INO_ZERO; rp->type = FS_TYPE_FILE; rp->rc = 0; return; }
        reply_err(rp, SYS_ERR_NOENT);
        return;

    case FS_OP_STAT:
        /* The mount probe in hvfs_mount stats the root inode, so this is the
         * operation that decides whether a mount can be installed at all. It
         * discloses nothing a holder of the endpoint does not already have. */
        if (rq->ino == DEV_INO_ROOT) { rp->type = FS_TYPE_DIR;  rp->size = 0; rp->rc = 0; return; }
        if (rq->ino == DEV_INO_NULL ||
            rq->ino == DEV_INO_ZERO) { rp->type = FS_TYPE_FILE; rp->size = 0; rp->rc = 0; return; }
        reply_err(rp, SYS_ERR_NOENT);
        return;

    case FS_OP_READ: {
        uint32_t len = rq->len > FS_IO_MAX ? FS_IO_MAX : rq->len;
        if (rq->ino == DEV_INO_NULL) { rp->size = 0; rp->rc = 0; return; }  /* EOF */
        if (rq->ino == DEV_INO_ZERO) {
            umemset(rp->data, 0, len);
            rp->size = len;
            rp->rc   = 0;
            return;
        }
        reply_err(rp, SYS_ERR_NOENT);
        return;
    }

    case FS_OP_WRITE:
    case FS_OP_APPEND:
        if (rq->ino == DEV_INO_NULL || rq->ino == DEV_INO_ZERO) {
            rp->size = rq->len;      /* accepted and discarded */
            rp->rc   = 0;
            return;
        }
        reply_err(rp, SYS_ERR_NOENT);
        return;

    case FS_OP_READDIR:
        if (rq->dir_ino != DEV_INO_ROOT) { reply_err(rp, SYS_ERR_NOENT); return; }
        if (rq->offset == 0) { ustrncpy(rp->name, "null", FS_NAME_MAX); rp->ino = DEV_INO_NULL; rp->type = FS_TYPE_FILE; rp->rc = 0; return; }
        if (rq->offset == 1) { ustrncpy(rp->name, "zero", FS_NAME_MAX); rp->ino = DEV_INO_ZERO; rp->type = FS_TYPE_FILE; rp->rc = 0; return; }
        reply_err(rp, SYS_ERR_NOENT);
        return;

    default:
        /* Every mutating directory operation -- CREATE, MKDIR, DELETE, RENAME,
         * LINK, TRUNCATE, CHMOD, CHOWN -- lands here. Refused because this
         * server implements no namespace of its own to mutate, which makes the
         * refusal structural rather than a check somebody could forget to
         * write. Fail closed on an unknown op for the same reason. */
        reply_err(rp, SYS_ERR_NOSYS);
        return;
    }
}

void _start(void) {
    kputln("[dev_server] /dev server starting (no object store, no boot modules).");

    struct fs_request  rq;
    struct fs_response rp;

    for (;;) {
        /* Block rather than poll. A negative return is permanent -- the
         * blocking receive never returns IPC_AGAIN -- so retrying it would be
         * the [G-8] wedge rather than back-pressure, exactly as fs_server and
         * console_server document. */
        int r = sys_ipc_recv_block(DEV_LISTEN_SLOT, (char *)&rq, sizeof(rq));
        if (r < 0) { kputln("[dev_server] listen capability lost; exiting"); sys_exit(); }

        handle(&rq, &rp);

        /* Reply to THIS request's sender by kernel-recorded identity, so
         * concurrent clients never receive each other's replies. */
        int sent = sys_ipc_reply_to(DEV_LISTEN_SLOT, &rp, sizeof(rp));
        (void)sent;
    }
}
