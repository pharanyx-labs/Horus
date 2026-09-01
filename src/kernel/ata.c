#include "kernel.h"

#define ATA_DATA       0x1F0
#define ATA_ERROR      0x1F1
#define ATA_SECCOUNT   0x1F2
#define ATA_LBA_LOW    0x1F3
#define ATA_LBA_MID    0x1F4
#define ATA_LBA_HIGH   0x1F5
#define ATA_DRIVE      0x1F6
#define ATA_STATUS     0x1F7
#define ATA_COMMAND    0x1F7
#define ATA_CTRL       0x3F6

#define ATA_CMD_READ   0x20
#define ATA_CMD_WRITE  0x30
#define ATA_CMD_FLUSH  0xE7   /* FLUSH CACHE (LBA28). LBA48 uses 0xEA; this driver
                               * is LBA28 throughout — see the 0xE0 | lba>>24 drive
                               * select in ata_read_sector — so 0xE7 is the correct
                               * opcode and 0xEA would be rejected as unsupported. */

static inline uint16_t inw(uint16_t port) {
    uint16_t val;
    __asm__ volatile ("inw %1, %0" : "=a"(val) : "d"(port));
    return val;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "d"(port));
}

/* Serialises access to the ATA PIO port sequence across CPUs. This is a
 * DEDICATED lock, deliberately NOT storage_lock: the crypto layer
 * (storage_encrypt_block) holds storage_lock while flushing per-block metadata,
 * which walks down through the metadata cache -> do_block_write -> ata_write_sector.
 * If the sector ops took storage_lock too, that path would re-acquire a
 * non-recursive spinlock and self-deadlock — the exact hang that made the ATA
 * backend never complete a write end-to-end. The RAM vdisk's block ops take no
 * lock, so the bug was invisible there. Lock order is always storage_lock ->
 * ata_lock (never the reverse), so no deadlock. */
static spinlock_t ata_lock = { 0 };

/* Wait for BSY to clear (SECURITY.md S69). 0 = clear, -1 = the bound was reached.
 *
 * THE RETURN VALUE IS NEW, AND SO IS EVERY CALLER CHECKING IT. This returned
 * void, and its comment said "on timeout the caller's status check sees
 * BSY/0xFF/ERR and treats the device as absent or the operation as failed."
 * That is true of the probe, which tests for 0xFF and 0x00 explicitly, and it
 * was FALSE of the sector paths: BSY is 0x80 and ata_read_sector tested only
 * 0x01 (ERR). A wait that timed out therefore left BSY set, ERR clear, and the
 * driver went on to read 256 words out of a drive that had not said it had any
 * — returning garbage, and returning it as SUCCESS.
 *
 * Bounded rather than infinite for the original reason: an absent or floating
 * bus reads 0xFF, which has BSY set forever, and the shipped kernel probes for a
 * disk on every boot. An unbounded wait turns "no disk" into "hang at mount". */
static int ata_wait_busy(void) {
    for (uint32_t i = 0; i < 2000000u; i++) {
        if (!(inb(ATA_STATUS) & 0x80)) return 0;
    }
    return -1;
}

/* ATA status bits this driver reasons about. */
#define ATA_ST_ERR  0x01
#define ATA_ST_DRQ  0x08
#define ATA_ST_DF   0x20
#define ATA_ST_BSY  0x80

/* May a sector be transferred against this status?
 *
 * Factored out as a PURE FUNCTION of the byte, and tested as one
 * (make smoke-ata-ready), because the interesting cases are the ones a working
 * QEMU never produces: BSY still set, DRQ never asserted, DF raised. An
 * integration test can only exercise the statuses the emulator chooses to
 * generate, so the policy is checked here against all 256 instead. The scheduler
 * factors sched_domain_switch_would_flush out for the same reason.
 *
 * DRQ IS THE POINT. ERR says the drive refused; DRQ says the drive has data.
 * Only the second is evidence that reading the data port means anything, and it
 * was the bit nobody checked. */
static int ata_transfer_ready(uint8_t status)
{
#ifdef ATA_READY_ERR_ONLY
    /* The pre-2026-09-01 rule: ERR alone. Accepts BSY-still-set and
     * DRQ-never-asserted, which is a transfer against a drive that has not said
     * it has anything to transfer. */
    return (status & ATA_ST_ERR) ? 0 : 1;
#else
    if (status & ATA_ST_BSY) return 0;              /* still working */
    if (status & (ATA_ST_ERR | ATA_ST_DF)) return 0; /* refused, or faulted */
    if (!(status & ATA_ST_DRQ)) return 0;           /* nothing to transfer */
    return 1;
#endif
}

#ifdef ATA_READY_SELFTEST
/* The predicate, reachable from the witness. Selftest builds only: nothing in a
 * shipping kernel has any business asking the driver to classify a status byte
 * it did not read from the drive. */
int ata_test_transfer_ready(uint8_t status) { return ata_transfer_ready(status); }
#endif

/* Say so, once per boot, rather than failing silently. A refused transfer that
 * nothing reports presents as a block that is mysteriously corrupt, somewhere
 * else, later. */
static int g_ata_refusal_reported;
static uint64_t g_ata_refusals;
uint64_t ata_transfer_refusals(void) { return g_ata_refusals; }

static int ata_refuse(const char *what, uint32_t lba, uint8_t status)
{
    g_ata_refusals++;
    if (!g_ata_refusal_reported) {
        g_ata_refusal_reported = 1;
        kmsg_begin();
        print("ata: refusing a ");
        print(what);
        print(" the drive is not ready for (lba ");
        print_decimal(lba);
        print(", status ");
        print_hex(status);              /* print_hex adds the 0x */
        print(") - failing closed\n");
    }
    return -1;
}

static void ata_400ns_delay(void) {
    for (int i = 0; i < 4; i++) inb(ATA_CTRL);
}

/* FLUSH CACHE is the one command whose completion time is not bounded by a
 * sector transfer: ATA-8 permits up to 30 seconds, because the drive may be
 * writing out its entire volatile cache. ata_wait_busy()'s 2e6-iteration cap is
 * sized for a PIO sector (microseconds) and would time out mid-flush, and a
 * timed-out flush that the caller reads as success is precisely the silent
 * durability hole this exists to close. So the flush path gets its own, much
 * larger bound.
 *
 * It stays bounded rather than infinite for the same reason ata_wait_busy() is:
 * a floating bus reads 0xFF, which has BSY set forever, and the shipped kernel
 * probes for a disk on every boot. An unbounded wait here would turn "no disk"
 * into "hang at mount". On timeout we report failure and the journal fails
 * closed, which is the safe direction — a spurious "flush failed" costs a
 * refused transaction, a spurious "flush succeeded" costs the guarantee.
 *
 * Sizing: a port read of 0x1F7 costs on the order of a microsecond on real
 * hardware, so ata_wait_busy()'s 2e6 is roughly a 2-second budget — right for a
 * PIO sector, wrong for a flush. 30e6 puts this at roughly the 30 seconds ATA-8
 * allows, and no higher: the cap is a backstop against a wedged bus, and making
 * it arbitrarily large just converts a clean failure into a boot that looks
 * hung. Under TCG each iteration is cheaper, so the wall-clock ceiling in CI is
 * well under that. In practice QEMU and real drives clear BSY long before. */
static int ata_wait_busy_flush(void) {
    for (uint32_t i = 0; i < 30000000u; i++) {
        if (!(inb(ATA_STATUS) & 0x80)) return 0;
    }
    return -1;
}

/* Issue FLUSH CACHE and wait for the drive to report the cache is on stable
 * media. Returns 0 only when the drive completed the flush without error;
 * -1 on ERR/DF, on timeout, or on an absent/floating bus.
 *
 * Callers MUST treat -1 as "this data is not durable" and fail the enclosing
 * transaction. Without this command every WRITE the driver issues may sit in the
 * drive's volatile write cache indefinitely: on real hardware a power failure
 * then loses the journal commit record, and the crash-atomicity property the
 * filesystem advertises does not hold. It went unnoticed for as long as it did
 * because QEMU with cache=writethrough persists every write on its own, so the
 * emulator supplied a guarantee the kernel never asked for. */
int ata_flush(void) {
    spin_lock(&ata_lock);

    if (ata_wait_busy_flush() != 0) { spin_unlock(&ata_lock); return -1; }
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0);          /* primary master, LBA mode */
    ata_400ns_delay();
    outb(ATA_COMMAND, ATA_CMD_FLUSH);

    /* A device that does not implement FLUSH CACHE leaves status 0 here; treat
     * that as a failure rather than as a vacuous success. */
    uint8_t status = inb(ATA_STATUS);
    if (status == 0 || status == 0xFF) { spin_unlock(&ata_lock); return -1; }

    if (ata_wait_busy_flush() != 0) { spin_unlock(&ata_lock); return -1; }
    ata_400ns_delay();

    status = inb(ATA_STATUS);
    if (status & 0x21) {            /* ERR (bit 0) or DF/device fault (bit 5) */
        spin_unlock(&ata_lock);
        return -1;
    }

    spin_unlock(&ata_lock);
    return 0;
}

/* Filled by ata_init from IDENTIFY words 60-61; 0 until then. */
static uint32_t g_ata_sectors = 0;

static int ata_read_sector(uint32_t lba, uint8_t *buf) {
    spin_lock(&ata_lock);

    if (ata_wait_busy() != 0) {
        spin_unlock(&ata_lock);
        return ata_refuse("read", lba, inb(ATA_STATUS));
    }
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
    outb(ATA_COMMAND, ATA_CMD_READ);

    if (ata_wait_busy() != 0) {
        spin_unlock(&ata_lock);
        return ata_refuse("read", lba, inb(ATA_STATUS));
    }
    ata_400ns_delay();

    /* The drive must say it HAS the data before the data port is read. Without
     * this the loop below runs against whatever the bus happens to return and
     * hands it back as a sector. */
    uint8_t status = inb(ATA_STATUS);
    if (!ata_transfer_ready(status)) {
        spin_unlock(&ata_lock);
        return ata_refuse("read", lba, status);
    }

    for (int i = 0; i < 256; i++) {
        uint16_t data = inw(ATA_DATA);
        buf[i*2 + 0] = data & 0xFF;
        buf[i*2 + 1] = data >> 8;
    }
    spin_unlock(&ata_lock);
    return 0;
}

static int ata_write_sector(uint32_t lba, const uint8_t *buf) {
    spin_lock(&ata_lock);

    if (ata_wait_busy() != 0) {
        spin_unlock(&ata_lock);
        return ata_refuse("write", lba, inb(ATA_STATUS));
    }
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
    outb(ATA_COMMAND, ATA_CMD_WRITE);

    if (ata_wait_busy() != 0) {
        spin_unlock(&ata_lock);
        return ata_refuse("write", lba, inb(ATA_STATUS));
    }
    ata_400ns_delay();

    /* The drive must be ASKING for the data before it is pushed. Writing 256
     * words at a drive that has not raised DRQ is a write that did not happen,
     * and the status check afterwards will not necessarily say so. */
    uint8_t status = inb(ATA_STATUS);
    if (!ata_transfer_ready(status)) {
        spin_unlock(&ata_lock);
        return ata_refuse("write", lba, status);
    }

    for (int i = 0; i < 256; i++) {
        uint16_t data = (buf[i*2 + 1] << 8) | buf[i*2 + 0];
        outw(ATA_DATA, data);
    }

    if (ata_wait_busy() != 0) {
        spin_unlock(&ata_lock);
        return ata_refuse("write", lba, inb(ATA_STATUS));
    }
    ata_400ns_delay();

    /* DF as well as ERR: a device fault is the drive saying the write did not
     * land, and it was not tested for. */
    status = inb(ATA_STATUS);
    if (status & (ATA_ST_ERR | ATA_ST_DF)) {
        spin_unlock(&ata_lock);
        return ata_refuse("write", lba, status);
    }

    spin_unlock(&ata_lock);
    return 0;
}

/* Probe the primary master with IDENTIFY and report whether a usable ATA disk is
 * attached. Returns 1 for a real ATA disk, 0 for an absent/floating bus or a
 * non-ATA (e.g. ATAPI) device. storage_init() uses this to choose the persistent
 * ATA store when a disk is present and fall back to the ephemeral RAM vdisk when
 * it is not — so a diskless/CI boot must land on 0 here without hanging. */
int ata_init(void) {
    outb(ATA_CTRL, 0x00);
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xA0);          /* select primary master */
    ata_400ns_delay();

    /* Floating bus (no device drives the data lines) reads back all-ones; a
     * cleared controller with no device reads all-zero. Either means absent. */
    uint8_t status = inb(ATA_STATUS);
    if (status == 0xFF || status == 0x00) {
        kmsg("ata: primary master not present");
        return 0;
    }

    outb(ATA_SECCOUNT, 0);
    outb(ATA_LBA_LOW, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HIGH, 0);
    outb(ATA_COMMAND, 0xEC);        /* IDENTIFY */

    status = inb(ATA_STATUS);
    if (status == 0) {              /* command ignored: no device */
        kmsg("ata: primary master not present");
        return 0;
    }
    ata_wait_busy();                /* bounded */

    /* A non-ATA device (ATAPI/SATA) writes a signature into the LBA-mid/high
     * registers and aborts IDENTIFY; a genuine parallel-ATA disk keeps them 0. */
    if (inb(ATA_LBA_MID) != 0 || inb(ATA_LBA_HIGH) != 0) {
        kmsg("ata: primary master is not an ATA disk");
        return 0;
    }

    status = inb(ATA_STATUS);
    if (status & 0x01) {            /* ERR/ABRT */
        kmsg("ata: primary master not present or error");
        return 0;
    }
    if (!(status & 0x08)) {         /* DRQ never asserted: no IDENTIFY data */
        kmsg("ata: primary master not ready");
        return 0;
    }

    /* KEEP WORDS 60-61: the LBA28 user-addressable sector count. The block was
     * drained and discarded until 2026-08-31, which meant the kernel had no idea
     * how large the disk in front of it was -- so the filesystem was laid out
     * against a COMPILE-TIME constant instead, and every volume was
     * BLOCKS_PER_DISK blocks whatever the medium held. That is the wrong way
     * round in both directions: a smaller disk gets a filesystem that runs off
     * the end of it, and a larger one is truncated to the constant with no way
     * to say so.
     *
     * Words 60-61 are a 32-bit little-endian count and are LBA28: they saturate
     * at 0x0FFFFFFF. A drive larger than 128 GiB reports the saturated value and
     * its true size lives in words 100-103 (LBA48), which this driver cannot
     * address anyway -- see the LBA28 _Static_assert in storage.c. Taking the
     * saturated value is therefore correct here: it is exactly the largest LBA
     * this driver can reach. */
    uint16_t id[256];
    for (int i = 0; i < 256; i++) id[i] = inw(ATA_DATA);
    g_ata_sectors = (uint32_t)id[60] | ((uint32_t)id[61] << 16);

    kmsg("ata: primary master ready (PIO)");
    return 1;
}

/* User-addressable 512-byte sectors reported by IDENTIFY, or 0 if the probe
 * never ran or the drive reported nothing. 0 means "unknown", and every caller
 * must treat it as a refusal rather than as a size. */
uint32_t ata_total_sectors(void) { return g_ata_sectors; }

int ata_read(uint32_t lba, void *buf, uint32_t sectors) {
    uint8_t *b = (uint8_t*)buf;
    for (uint32_t s = 0; s < sectors; s++) {
        if (ata_read_sector(lba + s, b + s * 512) != 0) return -1;
    }
    return 0;
}

int ata_write(uint32_t lba, const void *buf, uint32_t sectors) {
    const uint8_t *b = (const uint8_t*)buf;
    for (uint32_t s = 0; s < sectors; s++) {
        if (ata_write_sector(lba + s, b + s * 512) != 0) return -1;
    }
    return 0;
}
