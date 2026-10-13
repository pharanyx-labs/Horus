/* blkserve.h -- the server half of the block-driver protocol (include/blkproto.h),
 * written once and linked into every ring-3 storage driver, so the rules a
 * client is held to are the same whichever disk is behind them. */
#ifndef HORUS_BLKSERVE_H
#define HORUS_BLKSERVE_H

#include <stdint.h>

/* What a driver supplies: its device's extent and three transfers on ABSOLUTE
 * sectors. blkserve has already bounded every request by the client's extent and
 * by `sectors` before it calls one; a backend checks again anyway, because the
 * bound it holds is the device's own and it trusts no caller (CLAUDE.md
 * section 1). Each returns 0 or a negative error. */
struct blk_backend {
    uint64_t sectors;       /* the device's extent, in 512-byte sectors */
    unsigned max_count;     /* the most sectors one transfer may move   */
    int (*read)(uint64_t lba, void *buf, unsigned count);
    int (*write)(uint64_t lba, const void *buf, unsigned count);
    int (*flush)(void);
};

/* Serve the protocol on BLK_SLOT_EP for ever. */
void blkserve_run(const struct blk_backend *be) __attribute__((noreturn));

#endif /* HORUS_BLKSERVE_H */
