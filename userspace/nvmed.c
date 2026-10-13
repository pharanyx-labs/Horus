#include "syscall.h"

/*
 * nvmed -- an NVMe driver in ring 3, holding one device capability.
 *
 * Roadmap 2.7's second driver, and the first STORAGE driver outside ring 0. Its
 * entire authority is a CAP_IO_DEVICE naming the NVMe controller plus one
 * delegated untyped region it builds its queues and buffers from: no console
 * capability, no filesystem, no storage key, nothing ambient. Compromise it and
 * you hold a task that can drive one disk controller, within the reach its own
 * IOMMU mappings define (S45).
 *
 * WHY RING 3 AND NOT BESIDE sdhci.c. The maintainer's call on 2026-10-13, and
 * the direction CLAUDE.md section 1 sets: new code goes to ring 3 unless it
 * cannot. A storage controller is a bus master, so a ring-0 driver is a ring-0
 * program steering DMA; a ring-3 one is confined by a device address space that
 * starts empty and holds exactly the frames below. The volume is sealed and
 * Merkle-verified ABOVE the block layer, so once the kernel reads blocks through
 * this driver (milestone 2, not yet built) the driver sees ciphertext only: a
 * hostile one can refuse service, never read or forge.
 *
 * WHAT THIS MILESTONE DOES. Finds the register file, resets and enables the
 * controller, asks it to IDENTIFY itself and its first namespace, builds one I/O
 * queue pair, and reads block 0. If, and only if, block 0 carries the scratch
 * signature the test harness writes (tools/block_scratch.py), it then writes
 * block 1, flushes, and reads it back. A disk without the signature is never
 * written: the gate needs a write, and a real machine's disk must never get one
 * from a self-test. That is the fail-closed shape for data.
 *
 * WHY IT POLLS. NVMe interrupts are MSI-X on every controller worth having
 * (QEMU's has no MSI capability at all), and MSI-X is protected but not enabled
 * here (docs/LIMITATIONS.md, S48). A completion queue has a phase bit the
 * controller flips as it writes each entry, so polling it is exact rather than
 * hopeful; every wait is bounded by the clock, never by a count of yields.
 *
 * EVERYTHING THE CONTROLLER SAYS IS CHECKED. The device is outside the trusted
 * core like every other (CLAUDE.md section 1): a completion must name the
 * command and the queue it answers, a namespace's block size must be one the
 * buffers hold, and a register file that reads as floating bus is refused
 * rather than believed.
 */

/* ---- output ------------------------------------------------------------- */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }
static void wr_hex(unsigned long long v, int digits) {
    static const char h[] = "0123456789abcdef";
    char b[16];
    if (digits > 16) digits = 16;
    for (int i = digits - 1; i >= 0; i--) { b[i] = h[v & 0xF]; v >>= 4; }
    sys_write(1, b, (unsigned)digits);
}
static void wr_dec(unsigned long long v) {
    char b[20]; int n = 0;
    do { b[19 - n] = (char)('0' + v % 10); v /= 10; n++; } while (v && n < 20);
    sys_write(1, b + 20 - n, (unsigned)n);
}
/* A fixed-width ASCII field from IDENTIFY (model, serial), trailing spaces
 * dropped and anything unprintable shown as '?': the bytes come from the device,
 * and a device is not trusted to send a terminal only text. */
static void wr_field(const unsigned char *p, unsigned n) {
    while (n && (p[n - 1] == ' ' || p[n - 1] == 0)) n--;
    for (unsigned i = 0; i < n; i++) {
        char c = (p[i] >= 0x20 && p[i] < 0x7F) ? (char)p[i] : '?';
        sys_write(1, &c, 1);
    }
}

#define FAIL(what) do { wr("NVMETEST: FAIL " what "\n"); for (;;) sys_yield(); } while (0)

/* ---- small helpers ------------------------------------------------------ */

static void zero(void *p, unsigned n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    for (unsigned i = 0; i < n; i++) b[i] = 0;
}
static int same(const void *a, const void *b, unsigned n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    for (unsigned i = 0; i < n; i++) if (x[i] != y[i]) return 0;
    return 1;
}

/* Milliseconds since boot, from the monotonic clock (10 ms resolution). */
static unsigned long long now_ms(void) {
    struct horus_timespec t;
    if (sys_clock_gettime(0, &t) != 0) return 0;
    return t.sec * 1000ULL + t.nsec / 1000000u;
}

/* ---- NVMe registers, as byte offsets into BAR0 (NVMe 1.4, section 3.1) --- */

#define NVME_CAP     0x00    /* capabilities, 64-bit                         */
#define NVME_VS      0x08    /* version, major<<16 | minor<<8                */
#define NVME_INTMS   0x0C    /* interrupt mask set                           */
#define NVME_CC      0x14    /* controller configuration                     */
#define NVME_CSTS    0x1C    /* controller status                            */
#define NVME_AQA     0x24    /* admin queue sizes                            */
#define NVME_ASQ     0x28    /* admin submission queue base, 64-bit          */
#define NVME_ACQ     0x30    /* admin completion queue base, 64-bit          */
#define NVME_DOORBELL_BASE 0x1000

#define CC_EN        (1u << 0)
#define CC_CSS_NVM   (0u << 4)
#define CC_MPS_4K    (0u << 7)       /* 2^(12+0) bytes                        */
#define CC_AMS_RR    (0u << 11)
#define CC_IOSQES    (6u << 16)      /* 2^6 = 64-byte submission entries      */
#define CC_IOCQES    (4u << 20)      /* 2^4 = 16-byte completion entries      */

#define CSTS_RDY     (1u << 0)
#define CSTS_CFS     (1u << 1)       /* controller fatal status               */

/* Admin and NVM command opcodes. */
#define ADM_CREATE_IOSQ  0x01
#define ADM_CREATE_IOCQ  0x05
#define ADM_IDENTIFY     0x06
#define NVM_FLUSH        0x00
#define NVM_WRITE        0x01
#define NVM_READ         0x02

#define CNS_NAMESPACE    0x00
#define CNS_CONTROLLER   0x01
#define CNS_ACTIVE_NSIDS 0x02

/* A submission entry is 64 bytes, a completion 16 (CC_IOSQES/IOCQES above). */
struct nvme_sqe {
    unsigned int       cdw0;         /* opcode [7:0], command id [31:16]      */
    unsigned int       nsid;
    unsigned int       rsvd2, rsvd3;
    unsigned long long mptr;
    unsigned long long prp1;
    unsigned long long prp2;
    unsigned int       cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
};
struct nvme_cqe {
    unsigned int       dw0;
    unsigned int       rsvd;
    unsigned short     sqhd;
    unsigned short     sqid;
    unsigned short     cid;
    unsigned short     status;       /* phase in bit 0, status field above it */
};

/* ---- capability slots and address-space layout -------------------------- */

#define DEV_SLOT      CAPSLOT_IO_DEVICE
#define UNTYPED_SLOT  CAPSLOT_UNTYPED
#define SLOT_ASQ      40
#define SLOT_ACQ      41
#define SLOT_IOSQ     42
#define SLOT_IOCQ     43
#define SLOT_IDENT    44
#define SLOT_DATA     45
#define SLOT_CHECK    46

#define VA_BAR    0x0000000100000000ULL   /* 4 GiB: the register window      */
#define VA_ASQ    0x0000000200000000ULL
#define VA_ACQ    0x0000000200001000ULL
#define VA_IOSQ   0x0000000200002000ULL
#define VA_IOCQ   0x0000000200003000ULL
#define VA_IDENT  0x0000000200004000ULL
#define VA_DATA   0x0000000200005000ULL
#define VA_CHECK  0x0000000200006000ULL

/* Sixteen entries a queue: more than one command in flight is never needed
 * here. A controller may support as few as two, so CAP.MQES is checked. */
#define QDEPTH    16u
#define IO_QID    1u

/* The scratch disk's layout; tools/block_scratch.py writes and checks the same.
 * Block 0 carries SCRATCH_MAGIC then a 16-byte nonce the harness picked; the
 * driver writes block WRITE_LBA as WRITTEN_MAGIC, the nonce, and a pattern
 * derived from it. The host reads the image after QEMU exits, so the write is
 * witnessed OUTSIDE the guest -- a driver that wrote nowhere and read back its
 * own buffer could not satisfy it. */
#define SCRATCH_MAGIC  "HORUS-NVME-SCRATCH-V1"     /* 21 bytes + NUL           */
#define WRITTEN_MAGIC  "HORUS-NVME-WRITTEN-V1"
#define MAGIC_LEN      22u
#define NONCE_OFF      32u
#define NONCE_LEN      16u
#ifdef NVME_WRITE_WRONG_LBA
/* The arm for the host-side witness: write and read back a DIFFERENT block.
 * The guest's own read-back still matches, because it reads the block it wrote,
 * so only a check made outside the guest can tell. */
#define WRITE_LBA      2ULL
#else
#define WRITE_LBA      1ULL
#endif

/* ---- state -------------------------------------------------------------- */

static volatile unsigned char *bar;
static unsigned dstrd;               /* doorbell stride: 4 << CAP.DSTRD bytes  */
static unsigned long long timeout_ms;

struct queue {
    volatile struct nvme_sqe *sq;
    volatile struct nvme_cqe *cq;
    unsigned qid;
    unsigned sq_tail;
    unsigned cq_head;
    unsigned phase;
    unsigned short next_cid;
};
static struct queue adminq, ioq;

static inline unsigned mmio_r32(unsigned off) {
    return *(volatile unsigned int *)(bar + off);
}
static inline void mmio_w32(unsigned off, unsigned v) {
    *(volatile unsigned int *)(bar + off) = v;
}
/* 64-bit registers as two 32-bit halves, low first: the specification permits
 * it, and it keeps every access the width every controller decodes. */
static inline unsigned long long mmio_r64(unsigned off) {
    unsigned long long lo = mmio_r32(off), hi = mmio_r32(off + 4);
    return lo | (hi << 32);
}
static inline void mmio_w64(unsigned off, unsigned long long v) {
    mmio_w32(off, (unsigned)(v & 0xFFFFFFFFu));
    mmio_w32(off + 4, (unsigned)(v >> 32));
}
static unsigned sq_doorbell(unsigned qid) { return NVME_DOORBELL_BASE + (2u * qid) * dstrd; }
static unsigned cq_doorbell(unsigned qid) { return NVME_DOORBELL_BASE + (2u * qid + 1u) * dstrd; }

/* Retype `pages` of untyped into a frame at `slot`, map it into OUR address
 * space, and map it into the DEVICE's, returning the address the device must
 * be given. The second mapping is the IOMMU half (S45): without it the device
 * reaches nothing. `device_maps` is 0 only under the NVME_IOMMU_NO_MAP arm, and
 * only for the data buffer, so the admin path still works and the failure is
 * the read's own. */
static int frame_setup(unsigned slot, unsigned long long va, int device_maps,
                       void **out_ptr, unsigned long long *out_dma) {
    if (sys_retype_sized(UNTYPED_SLOT, 1, (int)slot, 1) != 1) return -1;
    if (sys_map_frame(slot, va, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) return -2;
    uint64_t dma = 0;
    int rc = device_maps
        ? sys_dma_addr(DEV_SLOT, slot, &dma)
        : sys_dma_addr_flags(DEV_SLOT, slot, &dma, DMA_ADDR_NO_MAP);
    if (rc != 0) return -3;
    *out_ptr = (void *)(unsigned long)va;
    *out_dma = dma;
    zero(*out_ptr, 4096u);
    return 0;
}

/* Wait until (CSTS & mask) == want, bounded by the controller's own CAP.TO.
 * Returns 0, -1 on timeout, -2 if the controller reports a fatal status. */
static int wait_csts(unsigned mask, unsigned want) {
    unsigned long long start = now_ms();
    for (;;) {
        unsigned csts = mmio_r32(NVME_CSTS);
        if (csts == 0xFFFFFFFFu) return -2;          /* the device went away */
        if ((csts & mask) == want) return 0;
        if (csts & CSTS_CFS) return -2;
        if (now_ms() - start > timeout_ms) return -1;
        sys_yield();
    }
}

/* Submit one command and wait for its completion.
 *
 * Returns the 15-bit status field (0 is success), or -1 if no completion came
 * within the bound, or -2 if one came that does not answer this command. A
 * completion naming another command id or another queue is the controller
 * saying something this driver did not ask; believing it would mean treating
 * a stranger's answer as ours, so it is refused rather than skipped past. */
static int submit_and_wait(struct queue *q, struct nvme_sqe *cmd, unsigned *out_dw0) {
    unsigned short cid = q->next_cid++;
    cmd->cdw0 = (cmd->cdw0 & 0xFFFFu) | ((unsigned)cid << 16);

    volatile struct nvme_sqe *slot = &q->sq[q->sq_tail];
    const unsigned *src = (const unsigned *)cmd;
    volatile unsigned *dst = (volatile unsigned *)slot;
    for (unsigned i = 0; i < sizeof(*cmd) / 4; i++) dst[i] = src[i];

    q->sq_tail = (q->sq_tail + 1u) % QDEPTH;
    /* The entry must be in memory before the doorbell tells the controller to
     * fetch it. Both are plain stores to write-back memory and an uncached BAR,
     * which x86 keeps in order; the compiler barrier stops the compiler
     * reordering them. */
    __asm__ volatile("" ::: "memory");
    mmio_w32(sq_doorbell(q->qid), q->sq_tail);

    unsigned long long start = now_ms();
    for (;;) {
        volatile struct nvme_cqe *e = &q->cq[q->cq_head];
        if ((e->status & 1u) == q->phase) {
            unsigned short ecid = e->cid, esqid = e->sqid, est = e->status;
            unsigned dw0 = e->dw0;
            q->cq_head = (q->cq_head + 1u) % QDEPTH;
            if (q->cq_head == 0) q->phase ^= 1u;
            mmio_w32(cq_doorbell(q->qid), q->cq_head);
            if (ecid != cid || esqid != q->qid) return -2;
            if (out_dw0) *out_dw0 = dw0;
            return (int)(est >> 1);
        }
        if (now_ms() - start > timeout_ms) return -1;
        sys_yield();
    }
}

static void cmd_clear(struct nvme_sqe *c) { zero(c, sizeof(*c)); }

/* An I/O command on one block. The buffer is one page and the block size is
 * checked to fit it, so PRP1 alone describes the transfer and PRP2 stays 0. */
static int block_io(unsigned opcode, unsigned nsid, unsigned long long lba,
                    unsigned long long dma) {
    struct nvme_sqe c; cmd_clear(&c);
    c.cdw0  = opcode;
    c.nsid  = nsid;
    c.prp1  = dma;
    c.cdw10 = (unsigned)(lba & 0xFFFFFFFFu);
    c.cdw11 = (unsigned)(lba >> 32);
    c.cdw12 = 0;                         /* number of blocks, 0-based: one */
    return submit_and_wait(&ioq, &c, 0);
}

/* The status of a failed command, in the log, so a red run says which. */
static void wr_status(const char *what, int rc) {
    wr("NVMED: "); wr(what);
    if (rc == -1) wr(" timed out\n");
    else if (rc == -2) wr(" answered by a stranger's completion\n");
    else { wr(" status 0x"); wr_hex((unsigned)rc, 4); wr("\n"); }
}

void _start(void) {
    struct dev_info dev;

    wr("NVMED: begin\n");

    /* ---- 1. what device is this, and where are its registers? ----------- */
    if (sys_device_info(DEV_SLOT, &dev) != 0) FAIL("device-info");
    if ((dev.classcode & 0xFFFFFFu) != 0x010802u) FAIL("not-an-nvme-controller");
    /* BAR0 is the register file (NVMe 1.4, section 2.1.10) and the kernel lists
     * memory BARs in BAR order, so it is the first. Not trusted for that: the
     * registers read through it are validated below before anything is driven. */
    if (dev.n_mmio == 0) FAIL("no-mmio-bar");
    unsigned long long bar_phys = dev.mmio[0].base, bar_len = dev.mmio[0].len;
    if ((bar_phys & 0xFFFULL) != 0 || bar_len < 0x2000) FAIL("bar0-too-small");

    /* ---- 2. decode and bus mastering ------------------------------------ */
    if (sys_device_enable(DEV_SLOT, DEV_ENABLE_MEM | DEV_ENABLE_BUSMASTER) != 0)
        FAIL("device-enable");

    /* The control page first; the doorbell pages once CAP says where they are. */
    if (sys_map_phys(DEV_SLOT, bar_phys, VA_BAR, 4096, MAP_PHYS_WRITE) != 0)
        FAIL("map-registers");
    bar = (volatile unsigned char *)(unsigned long)VA_BAR;

    /* ---- 3. validate before believing ----------------------------------- */
    unsigned long long cap = mmio_r64(NVME_CAP);
    unsigned vs = mmio_r32(NVME_VS);
    if (cap == 0xFFFFFFFFFFFFFFFFULL || vs == 0xFFFFFFFFu) FAIL("registers-float");
    unsigned mqes   = (unsigned)(cap & 0xFFFFu) + 1u;    /* 0-based in the register */
    unsigned to     = (unsigned)((cap >> 24) & 0xFFu);   /* 500 ms units */
    unsigned css    = (unsigned)((cap >> 37) & 0xFFu);
    unsigned mpsmin = (unsigned)((cap >> 48) & 0xFu);
    dstrd = 4u << ((cap >> 32) & 0xFu);
    if ((vs >> 16) < 1 || (vs >> 16) > 2) FAIL("unknown-version");
    if (!(css & 1u)) FAIL("no-nvm-command-set");
    if (mpsmin != 0) FAIL("4k-pages-unsupported");
    if (mqes < QDEPTH) FAIL("queues-shallower-than-16");
    /* CAP.TO is the worst case the controller promises for a ready transition;
     * a zero would make every wait fail at once, so it is floored, and capped so
     * a hostile value cannot park the driver for two minutes. */
    timeout_ms = (unsigned long long)(to ? to : 1) * 500ULL;
    if (timeout_ms > 30000ULL) timeout_ms = 30000ULL;

    wr("NVMED: controller version "); wr_dec(vs >> 16); wr("."); wr_dec((vs >> 8) & 0xFF);
    wr(", queues up to "); wr_dec(mqes); wr(" entries, doorbell stride ");
    wr_dec(dstrd); wr("\n");

    /* Doorbells for queues 0 and 1. Each page is mapped once, and only if the
     * device declares it; the kernel refuses the MSI-X table's page whatever we
     * ask (S48), so a stride that put a doorbell there fails here, loudly. */
    unsigned long long mapped[4] = { 0, 0, 0, 0 };
    unsigned n_mapped = 0;
    unsigned bells[4] = { sq_doorbell(0), cq_doorbell(0), sq_doorbell(IO_QID), cq_doorbell(IO_QID) };
    for (unsigned i = 0; i < 4; i++) {
        unsigned long long page = bells[i] & ~0xFFFULL;
        if (page + 0x1000 > bar_len) FAIL("doorbell-outside-bar");
        int seen = 0;
        for (unsigned j = 0; j < n_mapped; j++) if (mapped[j] == page) seen = 1;
        if (seen || page == 0) continue;
        if (sys_map_phys(DEV_SLOT, bar_phys + page, VA_BAR + page, 4096, MAP_PHYS_WRITE) != 0)
            FAIL("map-doorbells");
        mapped[n_mapped++] = page;
    }

    /* ---- 4. reset: disable, and wait for the controller to say so -------- */
    /* Firmware may have left it running (a UEFI NVMe driver does), with queues
     * pointing at memory this task does not own. Clearing EN is what makes the
     * controller forget them; until RDY drops, nothing below is safe to write. */
    mmio_w32(NVME_CC, mmio_r32(NVME_CC) & ~CC_EN);
    if (wait_csts(CSTS_RDY, 0) != 0) FAIL("disable-timeout");
    mmio_w32(NVME_INTMS, 0xFFFFFFFFu);       /* we poll; mask every vector */

    /* ---- 5. the admin queues, mapped for us AND for the device ----------- */
    void *p;
    unsigned long long asq_dma, acq_dma, iosq_dma, iocq_dma, ident_dma, data_dma, check_dma;
    if (frame_setup(SLOT_ASQ, VA_ASQ, 1, &p, &asq_dma) != 0) FAIL("asq-alloc");
    adminq.sq = (volatile struct nvme_sqe *)p;
    if (frame_setup(SLOT_ACQ, VA_ACQ, 1, &p, &acq_dma) != 0) FAIL("acq-alloc");
    adminq.cq = (volatile struct nvme_cqe *)p;
    adminq.qid = 0; adminq.phase = 1; adminq.next_cid = 1;

    mmio_w32(NVME_AQA, ((QDEPTH - 1u) << 16) | (QDEPTH - 1u));
    mmio_w64(NVME_ASQ, asq_dma);
    mmio_w64(NVME_ACQ, acq_dma);
    mmio_w32(NVME_CC, CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_IOSQES | CC_IOCQES);
    mmio_w32(NVME_CC, CC_CSS_NVM | CC_MPS_4K | CC_AMS_RR | CC_IOSQES | CC_IOCQES | CC_EN);
    {
        int rc = wait_csts(CSTS_RDY, CSTS_RDY);
        if (rc == -1) FAIL("enable-timeout");
        if (rc != 0) FAIL("controller-fatal");
    }
    wr("NVMED: controller enabled\n");

    /* ---- 6. IDENTIFY the controller -------------------------------------- */
    unsigned char *ident;
    if (frame_setup(SLOT_IDENT, VA_IDENT, 1, &p, &ident_dma) != 0) FAIL("identify-alloc");
    ident = (unsigned char *)p;
    {
        struct nvme_sqe c; cmd_clear(&c);
        c.cdw0 = ADM_IDENTIFY; c.prp1 = ident_dma; c.cdw10 = CNS_CONTROLLER;
        int rc = submit_and_wait(&adminq, &c, 0);
        if (rc != 0) { wr_status("identify controller", rc); FAIL("identify-controller"); }
    }
    unsigned nn = (unsigned)ident[516] | ((unsigned)ident[517] << 8)
                | ((unsigned)ident[518] << 16) | ((unsigned)ident[519] << 24);
    wr("NVMED: model \""); wr_field(ident + 24, 40);
    wr("\" serial \""); wr_field(ident + 4, 20);
    wr("\" firmware \""); wr_field(ident + 64, 8);
    wr("\", "); wr_dec(nn); wr(" namespace(s)\n");
    if (nn == 0) FAIL("no-namespaces");

    /* ---- 7. the first active namespace, and its block size ---------------- */
    unsigned nsid;
    {
        struct nvme_sqe c; cmd_clear(&c);
        zero(ident, 4096u);
        c.cdw0 = ADM_IDENTIFY; c.nsid = 0; c.prp1 = ident_dma; c.cdw10 = CNS_ACTIVE_NSIDS;
        int rc = submit_and_wait(&adminq, &c, 0);
        if (rc != 0) { wr_status("active namespace list", rc); FAIL("namespace-list"); }
        nsid = (unsigned)ident[0] | ((unsigned)ident[1] << 8)
             | ((unsigned)ident[2] << 16) | ((unsigned)ident[3] << 24);
        /* 0 ends the list, and 0xFFFFFFFF is the broadcast id, never a namespace. */
        if (nsid == 0 || nsid == 0xFFFFFFFFu || nsid > nn) FAIL("no-active-namespace");
    }
    unsigned long long nsze;
    unsigned lba_bytes;
    {
        struct nvme_sqe c; cmd_clear(&c);
        zero(ident, 4096u);
        c.cdw0 = ADM_IDENTIFY; c.nsid = nsid; c.prp1 = ident_dma; c.cdw10 = CNS_NAMESPACE;
        int rc = submit_and_wait(&adminq, &c, 0);
        if (rc != 0) { wr_status("identify namespace", rc); FAIL("identify-namespace"); }
        nsze = 0;
        for (int i = 7; i >= 0; i--) nsze = (nsze << 8) | ident[i];
        unsigned nlbaf = (unsigned)ident[25] + 1u;
        unsigned fmt   = ((unsigned)ident[26] & 0xFu) | (((unsigned)ident[26] >> 1) & 0x30u);
        if (fmt >= nlbaf || fmt >= 64u) FAIL("format-index-out-of-range");
        unsigned lbads = ident[128 + 4u * fmt + 2];
        unsigned ms    = (unsigned)ident[128 + 4u * fmt] | ((unsigned)ident[128 + 4u * fmt + 1] << 8);
        /* One block must fit the one-page buffers, and be at least the 512 bytes
         * every format defines. Metadata interleaved with data would land past
         * the block in the same buffer and is refused rather than handled. */
        if (lbads < 9 || lbads > 12) FAIL("unsupported-block-size");
        if (ms != 0) FAIL("metadata-format-unsupported");
        lba_bytes = 1u << lbads;
    }
    if (nsze < 3) FAIL("namespace-too-small");
    wr("NVMED: namespace "); wr_dec(nsid); wr(": "); wr_dec(nsze); wr(" blocks of ");
    wr_dec(lba_bytes); wr(" bytes\n");

    /* ---- 8. one I/O queue pair, completion queue first ------------------- */
    if (frame_setup(SLOT_IOCQ, VA_IOCQ, 1, &p, &iocq_dma) != 0) FAIL("iocq-alloc");
    ioq.cq = (volatile struct nvme_cqe *)p;
    if (frame_setup(SLOT_IOSQ, VA_IOSQ, 1, &p, &iosq_dma) != 0) FAIL("iosq-alloc");
    ioq.sq = (volatile struct nvme_sqe *)p;
    ioq.qid = IO_QID; ioq.phase = 1; ioq.next_cid = 1;
    {
        struct nvme_sqe c; cmd_clear(&c);
        c.cdw0  = ADM_CREATE_IOCQ; c.prp1 = iocq_dma;
        c.cdw10 = ((QDEPTH - 1u) << 16) | IO_QID;
        c.cdw11 = 1u;                     /* physically contiguous, interrupts off */
        int rc = submit_and_wait(&adminq, &c, 0);
        if (rc != 0) { wr_status("create I/O completion queue", rc); FAIL("create-iocq"); }
    }
    {
        struct nvme_sqe c; cmd_clear(&c);
        c.cdw0  = ADM_CREATE_IOSQ; c.prp1 = iosq_dma;
        c.cdw10 = ((QDEPTH - 1u) << 16) | IO_QID;
        c.cdw11 = (IO_QID << 16) | 1u;    /* its completions go to queue 1      */
        int rc = submit_and_wait(&adminq, &c, 0);
        if (rc != 0) { wr_status("create I/O submission queue", rc); FAIL("create-iosq"); }
    }

    /* ---- 9. read block 0 ------------------------------------------------- */
    /* THE IOMMU ARM'S POINT OF FAILURE. Under NVME_IOMMU_NO_MAP every capability
     * check still runs and the address is still right, but this one buffer is
     * never mapped into the device's address space, so the controller cannot
     * write the block into it. Everything above it worked, so the failure is the
     * mapping's and nothing else's. How a controller reports a DMA it could not
     * make varies: QEMU 11 completes the read with status 0 and leaves the buffer
     * untouched, and another model may return an error status or never complete.
     * All three mean the block was not delivered, and all three print a marker
     * beginning NVMETEST: FAIL read-block0, which is what the arm requires. */
    unsigned char *data, *check;
#ifdef NVME_IOMMU_NO_MAP
    if (frame_setup(SLOT_DATA, VA_DATA, 0, &p, &data_dma) != 0) FAIL("data-alloc");
#else
    if (frame_setup(SLOT_DATA, VA_DATA, 1, &p, &data_dma) != 0) FAIL("data-alloc");
#endif
    data = (unsigned char *)p;
    /* A SUCCESSFUL COMPLETION IS NOT A DELIVERED BLOCK. Measured 2026-10-13 under
     * NVME_IOMMU_NO_MAP: QEMU's controller faults on the unmapped buffer and still
     * completes the read with status 0, so the buffer keeps whatever it held and
     * the driver, trusting the status, read it as a disk. The buffer is therefore
     * poisoned before the read and checked after it. A block that happens to equal
     * the poison is possible, so a match is re-read under a second, different
     * poison: no block equals both, and a buffer that keeps each in turn is one
     * the controller never wrote. */
    {
        static const unsigned char poison[2] = { 0xA5, 0x5A };
        int delivered = 0;
        for (unsigned attempt = 0; attempt < 2 && !delivered; attempt++) {
            for (unsigned i = 0; i < lba_bytes; i++) data[i] = poison[attempt];
            int rc = block_io(NVM_READ, nsid, 0, data_dma);
            if (rc != 0) { wr_status("read of block 0", rc); FAIL("read-block0"); }
            for (unsigned i = 0; i < lba_bytes; i++)
                if (data[i] != poison[attempt]) { delivered = 1; break; }
        }
        if (!delivered) FAIL("read-block0-delivered-nothing");
    }
    wr("NVMED: block 0 read\n");

    if (!same(data, SCRATCH_MAGIC, MAGIC_LEN)) {
        /* A real disk. Read it, say so, and never write it. */
        wr("NVMETEST: READ PASS (no scratch signature; nothing written)\n");
        for (;;) sys_yield();
    }
    wr("NVMETEST: READ PASS\n");

    /* ---- 10. write block WRITE_LBA, flush, and read it back --------------- */
    unsigned char nonce[NONCE_LEN];
    for (unsigned i = 0; i < NONCE_LEN; i++) nonce[i] = data[NONCE_OFF + i];

    zero(data, 4096u);
    for (unsigned i = 0; i < MAGIC_LEN; i++) data[i] = (unsigned char)WRITTEN_MAGIC[i];
    for (unsigned i = 0; i < NONCE_LEN; i++) data[NONCE_OFF + i] = nonce[i];
    for (unsigned i = NONCE_OFF + NONCE_LEN; i < lba_bytes; i++)
        data[i] = (unsigned char)(nonce[i % NONCE_LEN] ^ (unsigned char)(i * 31u + 7u));

    {
        int rc = block_io(NVM_WRITE, nsid, WRITE_LBA, data_dma);
        if (rc != 0) { wr_status("write", rc); FAIL("write"); }
    }
    {
        /* Flush is mandatory for every controller, volatile cache or not, and is
         * what the host-side check relies on: a write still in the device's cache
         * when QEMU exits is not on the image. */
        struct nvme_sqe c; cmd_clear(&c);
        c.cdw0 = NVM_FLUSH; c.nsid = nsid;
        int rc = submit_and_wait(&ioq, &c, 0);
        if (rc != 0) { wr_status("flush", rc); FAIL("flush"); }
    }

    if (frame_setup(SLOT_CHECK, VA_CHECK, 1, &p, &check_dma) != 0) FAIL("check-alloc");
    check = (unsigned char *)p;
    {
        int rc = block_io(NVM_READ, nsid, WRITE_LBA, check_dma);
        if (rc != 0) { wr_status("read-back", rc); FAIL("read-back"); }
    }
    if (!same(check, data, lba_bytes)) FAIL("read-back-differs");

    wr("NVMETEST: PASS\n");
    for (;;) sys_yield();
}
