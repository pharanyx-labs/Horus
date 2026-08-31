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

static void ata_wait_busy(void) {
    /* Bounded so an absent/floating bus (status stuck at 0xFF with BSY set) can
     * never hang the boot-time probe — the shipped kernel now probes for a disk
     * on every boot. On timeout the caller's status check sees BSY/0xFF/ERR and
     * treats the device as absent or the operation as failed. QEMU and real
     * drives clear BSY almost immediately, so the cap is never reached in
     * practice. */
    for (uint32_t i = 0; i < 2000000u && (inb(ATA_STATUS) & 0x80); i++) { }
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

static int ata_read_sector(uint32_t lba, uint8_t *buf) {
    spin_lock(&ata_lock);

    ata_wait_busy();
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
    outb(ATA_COMMAND, ATA_CMD_READ);

    ata_wait_busy();
    ata_400ns_delay();

    uint8_t status = inb(ATA_STATUS);
    if (status & 0x01) { spin_unlock(&ata_lock); return -1; }

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

    ata_wait_busy();
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xE0 | ((lba >> 24) & 0x0F));
    outb(ATA_SECCOUNT, 1);
    outb(ATA_LBA_LOW,  lba & 0xFF);
    outb(ATA_LBA_MID,  (lba >> 8) & 0xFF);
    outb(ATA_LBA_HIGH, (lba >> 16) & 0xFF);
    outb(ATA_COMMAND, ATA_CMD_WRITE);

    ata_wait_busy();
    ata_400ns_delay();

    for (int i = 0; i < 256; i++) {
        uint16_t data = (buf[i*2 + 1] << 8) | buf[i*2 + 0];
        outw(ATA_DATA, data);
    }

    ata_wait_busy();
    ata_400ns_delay();

    uint8_t status = inb(ATA_STATUS);
    if (status & 0x01) { spin_unlock(&ata_lock); return -1; }

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

    for (int i = 0; i < 256; i++) {
        (void)inw(ATA_DATA);        /* drain the 256-word IDENTIFY block */
    }

    kmsg("ata: primary master ready (PIO)");
    return 1;
}

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
