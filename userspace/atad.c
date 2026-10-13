#include "syscall.h"
#include "blkproto.h"
#include "blkserve.h"

/*
 * atad -- an IDE (parallel ATA) driver in ring 3, holding one device capability.
 *
 * WHY THIS EXISTS. src/kernel/ata.c drives the IDE controller from ring 0, and
 * every installer gate in this tree boots a disk on it. It is about 550 lines of
 * kernel C waiting on and believing a device CLAUDE.md section 1 says to treat as
 * hostile: a status byte, an IDENTIFY block, a drive that never clears BSY. The
 * maintainer chose (2026-10-13) to take every storage driver out of ring 0 by
 * moving the kernel's storage to ring 3 (docs/design/ring3-storage.md); sdhcid
 * and nvmed went first, and this is the third driver serving the block-driver
 * protocol. The ring-0 driver still serves the kernel's storage until the
 * cutover deletes it.
 *
 * ITS WHOLE AUTHORITY IS ONE CAP_IO_DEVICE NAMING THE CONTROLLER. No untyped
 * memory, no frame, no console, no filesystem, no key. It moves data by PIO
 * through the data port, so it gives the controller no memory: it sets I/O
 * decode and NOT bus mastering, and with bus mastering off the controller's DMA
 * engine (the bus-master registers its BAR 4 declares, which the port grant also
 * opens) cannot reach memory at all.
 *
 * THE PORTS ARE DECLARED ONLY IN THIS SELF-TEST'S BUILD (SECURITY.md S137). A
 * controller in compatibility mode has no BARs for its command block; its ports
 * are the fixed legacy ones, and the kernel declares 0x1F0-0x1F7 and 0x3F6 on the
 * IDE function only when ATAD_SELFTEST is set, which also turns ata.c's probe
 * off. A ship kernel, where ring 0 drives the controller, declares neither, so no
 * ring-3 task can be granted them while ring 0 is using them. Only the primary
 * channel is declared, because only the primary is driven: the secondary is
 * authority this driver has no use for. The master is the one disk served; the
 * slave comes with the cutover, when the installer's two-disk survey moves here.
 *
 * WHAT THE SELF-TEST DOES. Checks the device is an IDE controller with its
 * primary channel in compatibility mode and that the kernel declared exactly the
 * legacy ports for it, sets decode, takes the port grant, and IDENTIFYs the
 * master: the capacity is IDENTIFY words 60-61 (LBA28). It reads block 0. If,
 * and only if, block 0 carries the scratch signature the harness writes
 * (tools/block_scratch.py `ata`), the planted block must hold the same image's
 * nonce (the addressing check), and the driver then writes a run of eight
 * sectors in one command, flushes, and reads the run back. A disk without the
 * signature is never written.
 *
 * THE PLANTED BLOCK IS AT LBA 0x010205, so its address has a different non-zero
 * byte in each of the three LBA registers. Block 0 reads the same whatever order
 * the registers are written in; a driver that crossed any two of them reads a
 * different, empty block here and is refused. ATAD_LBA_REGS_SWAPPED is that arm.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, AND EVERYTHING THE DRIVE SAYS IS CHECKED.
 * The ring-0 driver bounded its waits by spin counts, whose length in time
 * depends on the CPU and on how often the host runs the emulator (ata.c, the
 * note above ATA_BSY_SPINS). Here each bound is milliseconds of the monotonic
 * clock. A bus nobody drives, an IDENTIFY that a non-ATA device aborts, a drive
 * without LBA, a capacity of zero, a sector the drive has not raised DRQ for,
 * and a transfer outside the drive's own reported extent are refused rather
 * than believed.
 */

/* ---- output ------------------------------------------------------------- */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }
static void wr_dec(unsigned long long v) {
    char b[20]; int n = 0;
    do { b[19 - n] = (char)('0' + v % 10); v /= 10; n++; } while (v && n < 20);
    sys_write(1, b + 20 - n, (unsigned)n);
}
static void wr_hex8(unsigned v) {
    static const char h[] = "0123456789abcdef";
    char b[4] = { '0', 'x', h[(v >> 4) & 0xFu], h[v & 0xFu] };
    sys_write(1, b, 4);
}

#define FAIL(what) do { wr("ATADTEST: FAIL " what "\n"); for (;;) sys_yield(); } while (0)

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

/* Native port I/O. These #GP unless the kernel loaded this task's grant into
 * the TSS bitmap (SYS_IOPORT_GRANT), and the grant is exactly the ports the
 * capability's device declares. */
static inline unsigned char inb(unsigned short port) {
    unsigned char v;
    __asm__ volatile ("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void outb(unsigned short port, unsigned char v) {
    __asm__ volatile ("outb %0, %1" : : "a"(v), "Nd"(port));
}
static inline unsigned short inw(unsigned short port) {
    unsigned short v;
    __asm__ volatile ("inw %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void outw(unsigned short port, unsigned short v) {
    __asm__ volatile ("outw %0, %1" : : "a"(v), "Nd"(port));
}

/* ---- the primary channel's registers (ATA-8 ACS, legacy addresses) ------ */

#define CMD_BASE      0x1F0u
#define CMD_LEN       8u
#define CTRL_PORT     0x3F6u

#define ATA_DATA      (CMD_BASE + 0)
#define ATA_SECCOUNT  (CMD_BASE + 2)
#define ATA_LBA_LOW   (CMD_BASE + 3)
#define ATA_LBA_MID   (CMD_BASE + 4)
#define ATA_LBA_HIGH  (CMD_BASE + 5)
#define ATA_DRIVE     (CMD_BASE + 6)
#define ATA_STATUS    (CMD_BASE + 7)
#define ATA_COMMAND   (CMD_BASE + 7)

#define CMD_READ      0x20u   /* READ SECTORS (LBA28, PIO)  */
#define CMD_WRITE     0x30u   /* WRITE SECTORS (LBA28, PIO) */
#define CMD_FLUSH     0xE7u   /* FLUSH CACHE (LBA28)        */
#define CMD_IDENTIFY  0xECu

#define ST_ERR        0x01u
#define ST_DRQ        0x08u
#define ST_DF         0x20u
#define ST_BSY        0x80u

/* Device control: nIEN (bit 1) masks the drive's interrupt. This driver polls,
 * so the line is kept quiet rather than left raising IRQ 14 at a kernel that has
 * nobody to give it to. */
#define CTRL_NIEN     0x02u

/* The drive register: the master in LBA mode, LBA bits 24-27 in the low nibble.
 * 0xA0 is the master for a command that carries no LBA (IDENTIFY). */
#define SEL_MASTER_LBA   0xE0u
#define SEL_MASTER_PLAIN 0xA0u

#define LBA28_MAX     0x0FFFFFFFULL

/* Every bound, in milliseconds. ATA-8 allows a drive 30 seconds to clear BSY on
 * a FLUSH CACHE, which may write its whole volatile cache out; the sector bound
 * is the same, for ata.c's reason (the note above ATA_BSY_SPINS): a loaded host
 * deschedules the emulator for whole seconds, and a wait that gives up early on
 * a busy drive manufactures a failure. A bus nobody drives is caught on its
 * first read, not by the bound. */
#define BSY_MS        30000ULL
#define FLUSH_MS      30000ULL

/* ---- capability slot ----------------------------------------------------- */

#define DEV_SLOT   CAPSLOT_IO_DEVICE

/* ---- the scratch disk's layout; tools/block_scratch.py `ata` matches ----- */

#define SCRATCH_MAGIC  "HORUS-ATAD-SCRATCH-V1"     /* 21 bytes + NUL           */
#define READ_MAGIC     "HORUS-ATAD-PLANTED-V1"     /* 21 bytes + NUL           */
#define WRITTEN_MAGIC  "HORUS-ATAD-WRITTEN-V1"
#define SCRATCH_LEN    22u
#define READ_LEN       22u
#define NONCE_OFF      32u
#define NONCE_LEN      16u
#define READ_LBA       0x010205ULL                 /* low 05, mid 02, high 01  */
#define RUN            8u                          /* one 4 KiB block, in sectors */
#ifdef ATAD_WRITE_WRONG_LBA
/* The arm for the host-side witness: write and read back a DIFFERENT run. The
 * guest's own read-back still matches, because it reads what it wrote, so only
 * the check of the image after QEMU exits can tell. */
#define WRITE_LBA      24ULL
#else
#define WRITE_LBA      8ULL
#endif

/* ---- the drive ------------------------------------------------------------ */

static unsigned long long g_sectors;   /* IDENTIFY words 60-61; 0 until known */

/* Is nobody driving the bus? All-ones is a floating bus and all-zero a cleared
 * controller with no device; neither is a status a working drive produces
 * (0xFF asserts ERR, DRQ and BSY at once). The same test as ata.c's
 * ata_bus_absent, and it is what ends a wait on an empty bus at once. */
static int bus_absent(unsigned st) { return st == 0xFFu || st == 0x00u; }

/* Wait for BSY to clear, bounded by the clock. 0 = clear, -1 = the bound was
 * reached or nobody is on the bus. The clock is read once every 64 status reads:
 * each read is a port access the emulator handles, and a system call per read
 * would make the wait mostly system calls. */
static int wait_not_busy(unsigned long long bound_ms, int absent_ends) {
    const unsigned long long t0 = now_ms();
    for (unsigned n = 0;; n++) {
        const unsigned st = inb(ATA_STATUS);
        if (!(st & ST_BSY)) return 0;
        if (absent_ends && bus_absent(st)) return -1;
        if ((n & 63u) == 63u && now_ms() - t0 > bound_ms) return -1;
    }
}

/* The 400 ns a drive is allowed after a register write before its status means
 * anything: four reads of the alternate status register, ~100 ns each. */
static void settle(void) {
    for (int i = 0; i < 4; i++) (void)inb(CTRL_PORT);
}

/* May a sector move against this status? BSY clear, neither ERR nor DF, and DRQ
 * set: DRQ is the drive saying it has (or wants) the data, and it is the bit that
 * makes reading the data port mean anything. ata.c's ata_transfer_ready, which
 * smoke-ata-ready checks against all 256 values. */
static int transfer_ready(unsigned st) {
    if (st & ST_BSY) return 0;
    if (st & (ST_ERR | ST_DF)) return 0;
    if (!(st & ST_DRQ)) return 0;
    return 1;
}

/* IDENTIFY the master. 0, or a negative step number naming what failed. */
static int identify(unsigned short id[256]) {
    outb(CTRL_PORT, CTRL_NIEN);
    settle();
    outb(ATA_DRIVE, SEL_MASTER_PLAIN);
    settle();
    unsigned st = inb(ATA_STATUS);
    if (bus_absent(st)) return -1;                       /* nobody on the bus      */

    outb(ATA_SECCOUNT, 0); outb(ATA_LBA_LOW, 0); outb(ATA_LBA_MID, 0); outb(ATA_LBA_HIGH, 0);
    outb(ATA_COMMAND, CMD_IDENTIFY);
    st = inb(ATA_STATUS);
    if (st == 0) return -1;                              /* command ignored: absent */
    if (wait_not_busy(BSY_MS, 1) != 0) return -2;

    /* A packet device (ATAPI, or a SATA signature) aborts IDENTIFY and leaves its
     * signature in LBA mid/high; a parallel-ATA disk leaves them zero. */
    if (inb(ATA_LBA_MID) != 0 || inb(ATA_LBA_HIGH) != 0) return -3;

    st = inb(ATA_STATUS);
    if (!transfer_ready(st)) return -4;
    for (int i = 0; i < 256; i++) id[i] = inw(ATA_DATA);
    return 0;
}

/* Move `count` sectors starting at `lba` in ONE command, as ata.c's ata_xfer
 * does: per-sector DRQ checks, because a drive that faults part-way through must
 * be caught at the sector it faulted on. 0, or a negative step number.
 *
 * THE BOUND IS THE DRIVE'S OWN EXTENT, checked here whatever the caller decided
 * (blkserve has already held a client to its extent; this holds every caller to
 * the disk), and LBA28's: a sector past 2^28 cannot be named by this command. */
static int rw_sectors(unsigned long long lba, unsigned char *buf, unsigned count, int is_write) {
    if (count == 0 || count > 255u) return -1;
    if (g_sectors == 0 || lba >= g_sectors || count > g_sectors - lba) return -1;
    if (lba + count - 1u > LBA28_MAX) return -1;

    outb(ATA_DRIVE, (unsigned char)(SEL_MASTER_LBA | ((lba >> 24) & 0x0Fu)));
    settle();
    if (wait_not_busy(BSY_MS, 1) != 0) return -2;

    outb(ATA_SECCOUNT, (unsigned char)count);
    outb(ATA_LBA_LOW, (unsigned char)(lba & 0xFFu));
#ifdef ATAD_LBA_REGS_SWAPPED
    /* The arm for the addressing check: LBA bits 8-15 and 16-23 written to each
     * other's register. Block 0 and the write at sector 8 are unchanged by it;
     * the planted block is not. */
    outb(ATA_LBA_MID,  (unsigned char)((lba >> 16) & 0xFFu));
    outb(ATA_LBA_HIGH, (unsigned char)((lba >> 8) & 0xFFu));
#else
    outb(ATA_LBA_MID,  (unsigned char)((lba >> 8) & 0xFFu));
    outb(ATA_LBA_HIGH, (unsigned char)((lba >> 16) & 0xFFu));
#endif
    outb(ATA_COMMAND, (unsigned char)(is_write ? CMD_WRITE : CMD_READ));

    for (unsigned s = 0; s < count; s++) {
        unsigned char *sect = buf + (unsigned long)s * 512u;
        if (wait_not_busy(BSY_MS, 1) != 0) return -3;
        settle();
        if (!transfer_ready(inb(ATA_STATUS))) return -4;
        if (is_write) {
            for (int i = 0; i < 256; i++)
                outw(ATA_DATA, (unsigned short)(sect[i * 2] | (sect[i * 2 + 1] << 8)));
        } else {
            for (int i = 0; i < 256; i++) {
                const unsigned short w = inw(ATA_DATA);
                sect[i * 2] = (unsigned char)(w & 0xFFu);
                sect[i * 2 + 1] = (unsigned char)(w >> 8);
            }
        }
    }

    /* A write is not done until the drive says so, and DF counts as well as ERR:
     * a device fault is the drive saying the write did not land. */
    if (is_write) {
        if (wait_not_busy(BSY_MS, 1) != 0) return -5;
        settle();
        if (inb(ATA_STATUS) & (ST_ERR | ST_DF)) return -6;
    }
    return 0;
}

/* FLUSH CACHE: 0 only once the drive reports its cache on stable media. A drive
 * that leaves status 0 after the command did not take it, and that is a failure,
 * never a vacuous success: without a flush every write may sit in the drive's
 * volatile cache (ata.c, ata_flush). */
static int flush(void) {
    outb(ATA_DRIVE, SEL_MASTER_LBA);
    settle();
    if (wait_not_busy(FLUSH_MS, 1) != 0) return -1;
    outb(ATA_COMMAND, CMD_FLUSH);
    if (bus_absent(inb(ATA_STATUS))) return -1;
    if (wait_not_busy(FLUSH_MS, 0) != 0) return -1;
    settle();
    if (inb(ATA_STATUS) & (ST_ERR | ST_DF)) return -1;
    return 0;
}

/* The block-driver protocol's backend (userspace/blkserve.c). blkserve has
 * already held the request to the client's extent; rw_sectors holds it to the
 * drive's own, whatever blkserve decided. */
static int be_read(uint64_t lba, void *buf, unsigned count)        { return rw_sectors(lba, buf, count, 0); }
static int be_write(uint64_t lba, const void *buf, unsigned count) { return rw_sectors(lba, (void *)buf, count, 1); }
static int be_flush(void)                                          { return flush(); }

/* Does the device declare exactly [base, base+len) among its port ranges? */
static int declares(const struct dev_info *d, unsigned base, unsigned len) {
    for (unsigned i = 0; i < d->n_port && i < IODEV_MAX_PORT; i++)
        if (d->port[i].base == base && d->port[i].len == len) return 1;
    return 0;
}

void _start(void) {
    struct dev_info dev;

    wr("ATAD: begin\n");

    /* ---- 1. what device is this? -------------------------------------- */
    if (sys_device_info(DEV_SLOT, &dev) != 0) FAIL("device-info");
    /* Class 01, subclass 01: an IDE controller. Programming-interface bit 0 set
     * would put the primary channel in native mode, with its ports in BARs 0-1
     * rather than at the legacy addresses this driver names. */
    if ((dev.classcode >> 8) != 0x0101u) FAIL("not-an-ide-controller");
    if (dev.classcode & 0x01u) FAIL("primary-channel-not-in-compatibility-mode");
    if (!declares(&dev, CMD_BASE, CMD_LEN) || !declares(&dev, CTRL_PORT, 1u))
        FAIL("legacy-ports-not-declared");

    /* ---- 2. I/O decode, and NOT bus mastering --------------------------- */
    /* The decode bits are set to exactly this, so a bus-master bit firmware left
     * on is cleared: a PIO driver never lets its controller start a DMA. */
    if (sys_device_enable(DEV_SLOT, DEV_ENABLE_IO) != 0) FAIL("device-enable");
    if (sys_ioport_grant(DEV_SLOT) != 0) FAIL("port-grant");

    /* ---- 3. the master, and its extent ------------------------------------ */
    static unsigned short id[256];
    {
        const int rc = identify(id);
        if (rc == -1) FAIL("no-drive");
        if (rc == -3) FAIL("not-an-ata-disk");
        if (rc != 0) { wr("ATAD: IDENTIFY failed at step "); wr_dec((unsigned)-rc); wr("\n"); FAIL("identify"); }
    }
    /* Word 49 bit 9: LBA supported. Every command below addresses by LBA. */
    if (!(id[49] & (1u << 9))) FAIL("no-lba");
#ifdef ATAD_CAPACITY_CHS
    /* The arm for the capacity check: words 57-58, the CURRENT CHS capacity,
     * which is cylinders x heads x sectors and falls short of the LBA count on
     * any disk not a whole number of cylinders. A plausible number, and a wrong
     * one, caught only by comparing it with the image. */
    g_sectors = (unsigned long long)id[57] | ((unsigned long long)id[58] << 16);
#else
    /* Words 60-61: the LBA28 user-addressable sector count. A drive over 128 GiB
     * reports it saturated at 2^28-1, which is exactly the largest LBA this
     * driver can name, so taking it is right (ata.c, ata_probe_drive). */
    g_sectors = (unsigned long long)id[60] | ((unsigned long long)id[61] << 16);
#endif
    if (g_sectors == 0) FAIL("zero-capacity");
    wr("ATAD: primary master, capacity "); wr_dec(g_sectors); wr(" sectors, PIO, LBA28\n");
    if (g_sectors <= READ_LBA || g_sectors < WRITE_LBA + RUN) FAIL("disk-too-small");

    /* ---- 4. block 0 --------------------------------------------------------- */
    static unsigned char blk0[512];
    {
        const int rc = rw_sectors(0, blk0, 1, 0);
        if (rc != 0) {
            wr("ATAD: read of block 0 failed at step "); wr_dec((unsigned)-rc);
            wr(", status "); wr_hex8(inb(ATA_STATUS)); wr("\n");
            FAIL("read-block0");
        }
    }

    /* ---- serving: the block-driver protocol, when spawned to serve ---------- */
    /* From here the driver answers clients instead of testing itself, and what
     * it may write is whatever its supervisor bound: the scratch-signature rule
     * below is the self-test's, and blktest keeps the same rule as supervisor. */
    if (sys_spawn_arg() == BLK_SERVE_ARG) {
        static struct blk_backend be;
        be.sectors = g_sectors;
        be.max_count = BLK_MAX_COUNT;
        be.read = be_read;
        be.write = be_write;
        be.flush = be_flush;
        wr("ATAD: serving the block protocol\n");
        blkserve_run(&be);
    }

    /* ---- 5. a real disk is read and never written ------------------------- */
    if (!same(blk0, SCRATCH_MAGIC, SCRATCH_LEN)) {
        wr("ATADTEST: READ PASS (no scratch signature; nothing written)\n");
        for (;;) sys_yield();
    }

    /* ---- 6. the planted block holds THIS image's nonce: the addressing check */
    unsigned char nonce[NONCE_LEN];
    for (unsigned i = 0; i < NONCE_LEN; i++) nonce[i] = blk0[NONCE_OFF + i];
    {
        static unsigned char planted[512];
        if (rw_sectors(READ_LBA, planted, 1, 0) != 0) FAIL("planted-block-read");
        if (!same(planted, READ_MAGIC, READ_LEN) || !same(planted + NONCE_OFF, nonce, NONCE_LEN))
            FAIL("planted-block-not-this-image");
    }
    wr("ATADTEST: READ PASS\n");

    /* ---- 7. a run of eight sectors in one command, flushed, read back ------ */
    static unsigned char run[RUN * 512u], check[RUN * 512u];
    zero(run, sizeof(run));
    for (unsigned k = 0; k < RUN; k++) {
        unsigned char *s = run + k * 512u;
        for (unsigned i = 0; i < SCRATCH_LEN; i++) s[i] = (unsigned char)WRITTEN_MAGIC[i];
        for (unsigned i = 0; i < NONCE_LEN; i++) s[NONCE_OFF + i] = nonce[i];
        for (unsigned i = NONCE_OFF + NONCE_LEN; i < 512u; i++)
            s[i] = (unsigned char)(nonce[i % NONCE_LEN] ^ (unsigned char)(i * 31u + 7u)
                                   ^ (unsigned char)(k * 13u));
    }
    {
        const int rc = rw_sectors(WRITE_LBA, run, RUN, 1);
        if (rc != 0) { wr("ATAD: write failed at step "); wr_dec((unsigned)-rc); wr("\n"); FAIL("write"); }
    }
    if (flush() != 0) FAIL("flush");
    {
        const int rc = rw_sectors(WRITE_LBA, check, RUN, 0);
        if (rc != 0) { wr("ATAD: read-back failed at step "); wr_dec((unsigned)-rc); wr("\n"); FAIL("read-back"); }
    }
    if (!same(check, run, sizeof(run))) FAIL("read-back-differs");

    wr("ATAD: wrote, flushed and read back sectors "); wr_dec(WRITE_LBA); wr("-");
    wr_dec(WRITE_LBA + RUN - 1u); wr("\n");
    wr("ATADTEST: PASS\n");
    for (;;) sys_yield();
}
