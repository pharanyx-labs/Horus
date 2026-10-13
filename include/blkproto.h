/* blkproto.h -- the block-driver protocol: how a client reads and writes a disk
 * through a ring-3 storage driver (docs/design/ring3-storage.md, section 5).
 *
 * A driver answers on one endpoint. Every request is a struct blk_req in one
 * message and every answer a struct blk_rep; the sectors themselves move in a
 * frame the client and the driver share, never in the message.
 *
 * WHO MAY ASK WHAT, BY THE CAPABILITY THE REQUEST CAME THROUGH. The driver asks
 * the kernel which capability carried each request (SYS_IPC_INVOKER), and acts
 * on that, never on anything the message says about its sender:
 *
 *   - An UNTOKENED capability is the supervisor's (init, or the self-test's
 *     blktest). Minting tokened capabilities needs the untokened one with MINT,
 *     so only the task that made the endpoint holds one. It alone may BIND.
 *   - A TOKENED capability is a client's. Its token names one binding the
 *     supervisor made: an extent of the disk and the frame that client's data
 *     moves through. A token nobody bound reaches nothing.
 *
 * A CLIENT IS GIVEN A RANGE, NOT A DISK. Sectors in a client's request are
 * relative to the start of its extent, and the whole transfer must lie inside
 * it, so a client cannot even name a sector it was not given. The driver also
 * bounds every transfer by the device's own reported extent (S64).
 *
 * Together these are SECURITY.md S136, enforced in userspace/blkserve.c.
 *
 * ONE FRAME PER CLIENT. Each binding names its own frame, so one client's data
 * never passes through memory another client can map.
 */
#ifndef HORUS_BLKPROTO_H
#define HORUS_BLKPROTO_H

#include <stdint.h>

#define BLK_SECTOR          512u

/* Requests. BIND is the supervisor's; the rest are a client's. */
#define BLK_OP_INFO         1u    /* -> the extent, in sectors, and the transfer limit   */
#define BLK_OP_READ         2u    /* (sector, count) -> the sectors, into the frame      */
#define BLK_OP_WRITE        3u    /* (sector, count) from the frame -> done              */
#define BLK_OP_FLUSH        4u    /* -> done once everything accepted is on stable media */
#define BLK_OP_BIND         16u   /* (token, start, length, frame slot), untokened only  */

/* Statuses: 0 is success, every refusal is negative, and none of them says why
 * beyond its class: a client learns that it may not, not what lies outside. */
#define BLK_OK              0
#define BLK_ERR_PERM        (-1)  /* this capability may not make this request       */
#define BLK_ERR_RANGE       (-2)  /* outside the extent, or past the transfer limit   */
#define BLK_ERR_IO          (-3)  /* the device failed the transfer                   */
#define BLK_ERR_INVAL       (-4)  /* a malformed request                              */
#define BLK_ERR_FULL        (-5)  /* no room for another binding                      */

struct blk_req {
    uint32_t op;
    uint32_t count;      /* sectors, READ and WRITE                                */
    uint64_t sector;     /* first sector, relative to the client's extent          */
    /* BIND only: */
    uint64_t token;      /* the token the client's capability carries (non-zero)   */
    uint64_t start;      /* the extent's first sector on the device                */
    uint64_t length;     /* its length in sectors                                  */
    uint32_t frame_slot; /* the driver's slot holding that client's frame          */
    uint32_t reserved;   /* must be 0                                              */
};

struct blk_rep {
    int32_t  status;
    uint32_t max_count;  /* INFO: the most sectors one READ or WRITE may move      */
    uint64_t sectors;    /* INFO: the extent's length                              */
};

/* The driver's side of the arrangement, by slot. The supervisor grants the
 * endpoint's receive capability into BLK_SLOT_EP and each client's frame into
 * one of the BLK_SLOT_FRAME0.. slots, then names that slot in the BIND. */
#define BLK_SLOT_EP         48
#define BLK_SLOT_FRAME0     49
#define BLK_MAX_BINDINGS    4

/* A frame is one page: eight sectors, the 4 KiB block the storage layer moves. */
#define BLK_FRAME_BYTES     4096u
#define BLK_MAX_COUNT       (BLK_FRAME_BYTES / BLK_SECTOR)

/* The spawn argument that puts a driver in serving mode rather than running its
 * own self-test (sys_spawn_arg). */
#define BLK_SERVE_ARG       0x424C4B53u   /* "BLKS" */

#endif /* HORUS_BLKPROTO_H */
