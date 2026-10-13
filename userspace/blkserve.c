#include "syscall.h"
#include "blkproto.h"
#include "blkserve.h"

/*
 * blkserve -- the server half of the block-driver protocol.
 *
 * Step 2 of docs/design/ring3-storage.md: a ring-3 storage driver answers
 * clients on one endpoint, and the rules below are what every driver holds every
 * client to. They are here once, linked into sdhcid and nvmed, rather than
 * written into each driver, so a rule cannot be right in one driver and missing
 * from another.
 *
 * These rules are SECURITY.md S136: a client reaches only the extent and the
 * frame its token was bound to, and only the supervisor binds.
 *
 * AUTHORITY COMES FROM THE CAPABILITY, NEVER THE MESSAGE. After each receive the
 * kernel says which capability carried the request (SYS_IPC_INVOKER). Untokened
 * is the supervisor, who alone may BIND; tokened is a client, who reaches only
 * what its token was bound to. The message's own fields are inputs to check,
 * never statements of who is asking.
 *
 * EVERY REQUEST IS ANSWERED. A client is blocked in SYS_IPC_CALL until a reply
 * arrives, so a malformed or refused request gets a status rather than silence;
 * otherwise a hostile client's garbage would be a way to wedge an honest one
 * queued behind it.
 */

/* Where the bound frames are mapped in the driver: clear of every driver's own
 * register and queue windows (sdhcid and nvmed use 4 and 8 GiB). */
#define BLK_VA_FRAMES  0x0000000300000000ULL

struct binding {
    int      live;
    uint64_t token;
    uint64_t start;
    uint64_t length;
    unsigned frame_slot;
    unsigned char *buf;
};
static struct binding bindings[BLK_MAX_BINDINGS];

static struct binding *find(uint64_t token) {
    for (unsigned i = 0; i < BLK_MAX_BINDINGS; i++)
        if (bindings[i].live && bindings[i].token == token) return &bindings[i];
    return 0;
}

/* BIND (token, start, length, frame_slot), from the supervisor only. */
static int do_bind(const struct blk_backend *be, const struct blk_req *q, uint64_t inv_token) {
#ifndef BLK_BIND_UNCHECKED
    /* Only the untokened capability may bind. Every client holds a tokened one,
     * and a client that could bind could give its own token the whole disk. */
    if (inv_token != 0) return BLK_ERR_PERM;
#else
    /* Control arm -- never ship: any capability may bind. */
    (void)inv_token;
#endif
    if (q->token == 0 || q->reserved != 0 || q->count != 0 || q->sector != 0) return BLK_ERR_INVAL;
    if (q->length == 0 || q->start + q->length < q->start) return BLK_ERR_RANGE;
    if (q->start + q->length > be->sectors) return BLK_ERR_RANGE;
    if (q->frame_slot < BLK_SLOT_FRAME0 || q->frame_slot >= BLK_SLOT_FRAME0 + BLK_MAX_BINDINGS)
        return BLK_ERR_INVAL;
    if (find(q->token)) return BLK_ERR_INVAL;                 /* one binding per token */
    const unsigned idx = q->frame_slot - BLK_SLOT_FRAME0;
#ifndef BLK_FRAME_REUSE
    /* ONE FRAME PER CLIENT. A frame already bound is refused, so no two clients'
     * data ever pass through the same memory. The frame's slot is also its index,
     * so this is the same test as "is this binding slot taken". */
    if (bindings[idx].live) return BLK_ERR_INVAL;
#else
    /* Control arm -- never ship: a second token may share a bound frame. */
    if (bindings[idx].live) {
        for (unsigned i = 0; i < BLK_MAX_BINDINGS; i++) {
            if (bindings[i].live) continue;
            bindings[i] = bindings[idx];
            bindings[i].token = q->token; bindings[i].start = q->start; bindings[i].length = q->length;
            return BLK_OK;
        }
        return BLK_ERR_FULL;
    }
#endif
    /* The frame must be at least the page the protocol moves, and it is mapped
     * read-write: the driver reads a client's writes from it and puts its reads
     * there. A slot holding anything else fails the map and the bind. */
    if (sys_frame_pages(q->frame_slot) < 1) return BLK_ERR_INVAL;
    const uint64_t va = BLK_VA_FRAMES + (uint64_t)idx * 0x1000ULL;
    if (sys_map_frame(q->frame_slot, va, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) return BLK_ERR_INVAL;

    bindings[idx].live = 1;
    bindings[idx].token = q->token;
    bindings[idx].start = q->start;
    bindings[idx].length = q->length;
    bindings[idx].frame_slot = q->frame_slot;
    bindings[idx].buf = (unsigned char *)(unsigned long)va;
    return BLK_OK;
}

static int do_client(const struct blk_backend *be, const struct blk_req *q,
                     uint64_t inv_token, struct blk_rep *r) {
    /* The supervisor configures and is not a client: it holds no extent. */
    if (inv_token == 0) return BLK_ERR_PERM;
    struct binding *b = find(inv_token);
    if (!b) return BLK_ERR_PERM;                 /* a token nobody bound reaches nothing */

    const unsigned limit = be->max_count < BLK_MAX_COUNT ? be->max_count : BLK_MAX_COUNT;
    switch (q->op) {
    case BLK_OP_INFO:
        r->sectors = b->length;
        r->max_count = limit;
        return BLK_OK;
    case BLK_OP_FLUSH:
        return be->flush() == 0 ? BLK_OK : BLK_ERR_IO;
    case BLK_OP_READ:
    case BLK_OP_WRITE: {
        if (q->count == 0 || q->count > limit) return BLK_ERR_RANGE;
#ifndef BLK_NO_EXTENT_CHECK
        /* THE CLIENT'S RANGE. Both ends: the first sector inside the extent and
         * the whole run inside it, written so neither can overflow. */
        if (q->sector >= b->length || (uint64_t)q->count > b->length - q->sector)
            return BLK_ERR_RANGE;
#endif
#ifndef BLK_ABSOLUTE_SECTORS
        const uint64_t abs = b->start + q->sector;
#else
        /* Control arm -- never ship: the client's sector taken as the device's. */
        const uint64_t abs = q->sector;
#endif
        /* The device's own extent, whatever the binding said (S64). */
        if (abs >= be->sectors || (uint64_t)q->count > be->sectors - abs)
            return BLK_ERR_RANGE;
        const int rc = (q->op == BLK_OP_READ) ? be->read(abs, b->buf, q->count)
                                              : be->write(abs, b->buf, q->count);
        return rc == 0 ? BLK_OK : BLK_ERR_IO;
    }
    default:
        return BLK_ERR_INVAL;
    }
}

void blkserve_run(const struct blk_backend *be) {
    for (;;) {
        struct blk_req q;
        struct blk_rep r;
        for (unsigned i = 0; i < sizeof(q); i++) ((volatile unsigned char *)&q)[i] = 0;
        for (unsigned i = 0; i < sizeof(r); i++) ((volatile unsigned char *)&r)[i] = 0;

        const int n = sys_ipc_recv_block(BLK_SLOT_EP, &q, sizeof(q));
        if (n < 0) {
            /* No request was received, so there is no one to answer. A receive
             * that fails for good (the endpoint was revoked) must not become a
             * hot loop that starves the CPU. */
            sys_yield();
            continue;
        }
        struct ipc_invoker inv;
        if ((unsigned)n != sizeof(q) || sys_ipc_invoker(BLK_SLOT_EP, &inv) != 0)
            r.status = BLK_ERR_INVAL;
        else if (q.op == BLK_OP_BIND)
            r.status = do_bind(be, &q, inv.token);
        else
            r.status = do_client(be, &q, inv.token, &r);
        (void)sys_ipc_reply_to(BLK_SLOT_EP, &r, sizeof(r));
    }
}
