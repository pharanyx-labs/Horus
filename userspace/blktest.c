#include "syscall.h"
#include "blkproto.h"

/*
 * blktest -- supervisor and clients of a ring-3 storage driver, for the
 * block-driver protocol's gate (make smoke-blkproto).
 *
 * It plays the part init will play in the installed system: it holds the
 * untyped memory, makes the driver's endpoint and the clients' frames, grants
 * the driver exactly what serving needs (the endpoint's RECEIVE right and one
 * frame per client), and binds each client's token to an extent. Then it acts as
 * those clients, through tokened capabilities only, and checks every rule
 * blkserve holds a client to:
 *
 *   - a client reaches its own extent, relative to its start, and nothing past
 *     either end of it (the partition rule);
 *   - a token nobody bound, and the supervisor's own untokened capability,
 *     reach nothing (authority is the capability, not the message);
 *   - only the untokened capability may bind, so a client cannot widen itself;
 *   - one frame serves one client: a second binding of a bound frame is refused.
 *
 * The write lands at a sector fixed by the binding, and tools/block_scratch.py
 * `blk` checks it on the host after QEMU exits: a driver that ignored the extent's
 * start would write the image's block 0 and pass every check made in the guest.
 *
 * ONLY A SCRATCH DISK IS WRITTEN. The supervisor reads block 0 through a binding
 * of its own and writes nothing unless it carries the harness's signature, so
 * this image booted on a real machine reads and stops.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }
static int same(const void *a, const void *b, unsigned n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    for (unsigned i = 0; i < n; i++) if (x[i] != y[i]) return 0;
    return 1;
}

#define FAIL(what) do { wr("BLKTEST: FAIL " what "\n"); for (;;) sys_yield(); } while (0)

/* Slots in blktest's own cspace. 29 is the CAP_TCB naming the driver, which the
 * self-test launcher installs: the right to push capabilities down into it. */
#define SLOT_DRV_TCB   29
#define SLOT_EP        30    /* the endpoint, every right: the supervisor's      */
#define SLOT_TMP       31
#define SLOT_F0        32    /* frames: block 0's reader, client 1, client 2     */
#define SLOT_F1        33
#define SLOT_F2        34
#define SLOT_C0        35    /* tokened capabilities                             */
#define SLOT_C1        36
#define SLOT_C2        37
#define SLOT_CX        38    /* minted, never bound                              */

#define TOK_C0   0x10ULL
#define TOK_C1   0x11ULL
#define TOK_C2   0x12ULL
#define TOK_CX   0x13ULL

#define VA_F0    0x0000000400000000ULL
#define VA_F1    0x0000000400001000ULL
#define VA_F2    0x0000000400002000ULL

/* The scratch layout; tools/block_scratch.py `blk` matches it. */
#define SCRATCH_MAGIC  "HORUS-BLKP-SCRATCH-V1"     /* 21 bytes + NUL */
#define WRITTEN_MAGIC  "HORUS-BLKP-WRITTEN-V1"
#define MAGIC_LEN      22u
#define NONCE_OFF      32u
#define NONCE_LEN      16u
#define C1_START       2048ULL     /* client 1's extent: sectors 2048..6143       */
#define C1_LEN         4096ULL
#define C2_START       8192ULL     /* client 2's: 8192..10239                     */
#define C2_LEN         2048ULL

static unsigned char rbuf[256];   /* IPC_MSG_MAX */

static int call(unsigned slot, struct blk_req *q, struct blk_rep *r) {
    q->reserved = 0;
    int n = sys_ipc_call((int)slot, 0, q, sizeof(*q), rbuf);
    if (n != (int)sizeof(*r)) return -100;
    for (unsigned i = 0; i < sizeof(*r); i++) ((unsigned char *)r)[i] = rbuf[i];
    return r->status;
}
static int bind(unsigned slot, uint64_t token, uint64_t start, uint64_t len, unsigned frame) {
    struct blk_req q = { .op = BLK_OP_BIND, .token = token, .start = start,
                         .length = len, .frame_slot = frame };
    struct blk_rep r;
    return call(slot, &q, &r);
}
static int io(unsigned slot, unsigned op, uint64_t sector, unsigned count) {
    struct blk_req q = { .op = op, .sector = sector, .count = count };
    struct blk_rep r;
    return call(slot, &q, &r);
}

/* A frame for a client: made from blktest's untyped, mapped here, and a
 * READ|WRITE copy granted to the driver at `drv_slot`. */
static void client_frame(int drv, unsigned slot, uint64_t va, unsigned drv_slot) {
    if (sys_retype_sized(CAPSLOT_UNTYPED, 1, (int)slot, 1) != 1) FAIL("frame-retype");
    if (sys_map_frame((int)slot, va, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) FAIL("frame-map");
    if (sys_cap_mint(SLOT_TMP, (int)slot, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) FAIL("frame-mint");
    if (sys_cap_grant(drv, SLOT_TMP, drv_slot) != 0) FAIL("frame-grant");
}

void _start(void) {
    const int drv = (int)sys_spawn_arg();
    wr("BLKTEST: begin\n");

    /* ---- the supervisor: endpoint, frames, grants ----------------------- */
    if (sys_retype(CAPSLOT_UNTYPED, KOBJ_ENDPOINT, 1, SLOT_EP) != 1) FAIL("endpoint-retype");
    /* The driver gets the RECEIVE right only: it answers on the endpoint and can
     * neither send on it nor mint from it. */
    if (sys_cap_mint(SLOT_TMP, SLOT_EP, CAP_RIGHT_READ) != 0) FAIL("endpoint-mint");
    if (sys_cap_grant(drv, SLOT_TMP, BLK_SLOT_EP) != 0) FAIL("endpoint-grant");
    client_frame(drv, SLOT_F0, VA_F0, BLK_SLOT_FRAME0);
    client_frame(drv, SLOT_F1, VA_F1, BLK_SLOT_FRAME0 + 1);
    client_frame(drv, SLOT_F2, VA_F2, BLK_SLOT_FRAME0 + 2);
    /* Each client's capability: send only, and carrying its token. */
    if (sys_cap_mint_token(SLOT_C0, SLOT_EP, CAP_RIGHT_WRITE, TOK_C0) != 0 ||
        sys_cap_mint_token(SLOT_C1, SLOT_EP, CAP_RIGHT_WRITE, TOK_C1) != 0 ||
        sys_cap_mint_token(SLOT_C2, SLOT_EP, CAP_RIGHT_WRITE, TOK_C2) != 0 ||
        sys_cap_mint_token(SLOT_CX, SLOT_EP, CAP_RIGHT_WRITE, TOK_CX) != 0) FAIL("token-mint");
    if (sys_task_resume(drv) != 0) FAIL("resume-driver");

    /* ---- binding: only the untokened capability may ---------------------- */
    if (bind(SLOT_EP, TOK_C0, 0, 1, BLK_SLOT_FRAME0) != BLK_OK) FAIL("bind-reader");
    /* A client trying to give a fresh token the whole disk. */
    if (bind(SLOT_C0, TOK_CX, 0, C2_START + C2_LEN, BLK_SLOT_FRAME0 + 3) != BLK_ERR_PERM)
        FAIL("client-could-bind");
    wr("BLKTEST: a client cannot bind\n");

    /* ---- is this a scratch disk? ---------------------------------------- */
    unsigned char *f0 = (unsigned char *)(unsigned long)VA_F0;
    unsigned char *f1 = (unsigned char *)(unsigned long)VA_F1;
    unsigned char *f2 = (unsigned char *)(unsigned long)VA_F2;
    if (io(SLOT_C0, BLK_OP_READ, 0, 1) != BLK_OK) FAIL("read-block0");
    if (!same(f0, SCRATCH_MAGIC, MAGIC_LEN)) {
        wr("BLKTEST: READ PASS (no scratch signature; nothing bound to write)\n");
        for (;;) sys_yield();
    }
    unsigned char nonce[NONCE_LEN];
    for (unsigned i = 0; i < NONCE_LEN; i++) nonce[i] = f0[NONCE_OFF + i];

    if (bind(SLOT_EP, TOK_C1, C1_START, C1_LEN, BLK_SLOT_FRAME0 + 1) != BLK_OK) FAIL("bind-client1");
    if (bind(SLOT_EP, TOK_C2, C2_START, C2_LEN, BLK_SLOT_FRAME0 + 2) != BLK_OK) FAIL("bind-client2");
    /* ONE FRAME PER CLIENT: client 1's frame offered again, for another token. */
    if (bind(SLOT_EP, TOK_CX, C2_START, C2_LEN, BLK_SLOT_FRAME0 + 1) == BLK_OK)
        FAIL("frame-bound-twice");
    wr("BLKTEST: a bound frame is not bound again\n");

    /* ---- client 1: its extent, as it sees it ---------------------------- */
    {
        struct blk_req q = { .op = BLK_OP_INFO };
        struct blk_rep r;
        if (call(SLOT_C1, &q, &r) != BLK_OK || r.sectors != C1_LEN || r.max_count == 0)
            FAIL("info");
    }
    /* Eight sectors at the start of its extent, each different, then flushed and
     * read back. On the device they are sectors 2048..2055. */
    for (unsigned k = 0; k < 8; k++) {
        unsigned char *s = f1 + k * 512u;
        for (unsigned i = 0; i < 512u; i++) s[i] = 0;
        for (unsigned i = 0; i < MAGIC_LEN; i++) s[i] = (unsigned char)WRITTEN_MAGIC[i];
        for (unsigned i = 0; i < NONCE_LEN; i++) s[NONCE_OFF + i] = nonce[i];
        for (unsigned i = NONCE_OFF + NONCE_LEN; i < 512u; i++)
            s[i] = (unsigned char)(nonce[i % NONCE_LEN] ^ (unsigned char)(i * 31u + 7u)
                                   ^ (unsigned char)(k * 13u));
    }
    static unsigned char wrote[4096];
    for (unsigned i = 0; i < 4096u; i++) wrote[i] = f1[i];
    if (io(SLOT_C1, BLK_OP_WRITE, 0, 8) != BLK_OK) FAIL("write");
    if (io(SLOT_C1, BLK_OP_FLUSH, 0, 0) != BLK_OK) FAIL("flush");
    for (unsigned i = 0; i < 4096u; i++) f1[i] = 0;
    if (io(SLOT_C1, BLK_OP_READ, 0, 8) != BLK_OK) FAIL("read-back");
    if (!same(f1, wrote, 4096u)) FAIL("read-back-differs");
    wr("BLKTEST: a client wrote, flushed and read back its own sectors\n");

    /* ---- the partition rule --------------------------------------------- */
    /* A run that starts inside the extent and ends past it, and one that
     * starts at its end. Both would be sectors of client 2's neighbourhood. */
    if (io(SLOT_C1, BLK_OP_READ, C1_LEN - 4, 8) != BLK_ERR_RANGE) FAIL("read-outside-extent-served");
    if (io(SLOT_C1, BLK_OP_READ, C1_LEN, 1) != BLK_ERR_RANGE) FAIL("read-past-extent-served");
    if (io(SLOT_C1, BLK_OP_WRITE, C1_LEN - 1, 2) != BLK_ERR_RANGE) FAIL("write-outside-extent-served");
    wr("BLKTEST: a client reaches nothing outside its extent\n");

    /* ---- authority is the capability ------------------------------------ */
    if (io(SLOT_CX, BLK_OP_READ, 0, 1) != BLK_ERR_PERM) FAIL("unbound-token-served");
    if (io(SLOT_EP, BLK_OP_READ, 0, 1) != BLK_ERR_PERM) FAIL("supervisor-served-as-client");
    wr("BLKTEST: an unbound token and the supervisor's capability reach nothing\n");

    /* ---- client 2 reads its own extent through its own frame ------------- */
    for (unsigned i = 0; i < 512u; i++) f2[i] = 0xA5;
    if (io(SLOT_C2, BLK_OP_READ, 0, 1) != BLK_OK) FAIL("client2-read");
    if (!same(f1, wrote, 4096u)) FAIL("client2-read-touched-client1-frame");

    wr("BLKTEST: PASS\n");
    for (;;) sys_yield();
}
