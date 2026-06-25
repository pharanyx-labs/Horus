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

static inline uint16_t inw(uint16_t port) {
    uint16_t val;
    __asm__ volatile ("inw %1, %0" : "=a"(val) : "d"(port));
    return val;
}

static inline void outw(uint16_t port, uint16_t val) {
    __asm__ volatile ("outw %0, %1" : : "a"(val), "d"(port));
}

static void ata_wait_busy(void) {
    while (inb(ATA_STATUS) & 0x80) { }
}

static void ata_400ns_delay(void) {
    for (int i = 0; i < 4; i++) inb(ATA_CTRL);
}

static int ata_read_sector(uint32_t lba, uint8_t *buf) {
    
    extern spinlock_t storage_lock;
    spin_lock(&storage_lock);

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
    if (status & 0x01) { spin_unlock(&storage_lock); return -1; }

    for (int i = 0; i < 256; i++) {
        uint16_t data = inw(ATA_DATA);
        buf[i*2 + 0] = data & 0xFF;
        buf[i*2 + 1] = data >> 8;
    }
    spin_unlock(&storage_lock);
    return 0;
}

static int ata_write_sector(uint32_t lba, const uint8_t *buf) {
    
    extern spinlock_t storage_lock;
    spin_lock(&storage_lock);

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
    if (status & 0x01) { spin_unlock(&storage_lock); return -1; }

    spin_unlock(&storage_lock);
    return 0;
}

void ata_init(void) {
    outb(ATA_CTRL, 0x00);
    ata_400ns_delay();

    outb(ATA_DRIVE, 0xA0);
    ata_wait_busy();

    outb(ATA_SECCOUNT, 0);
    outb(ATA_LBA_LOW, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HIGH, 0);
    outb(ATA_COMMAND, 0xEC);

    ata_wait_busy();

    uint8_t status = inb(ATA_STATUS);
    if (status & 0x01) {
        println("ATA: primary master not present or error");
        return;
    }

    for (int i = 0; i < 256; i++) {
        (void)inw(ATA_DATA);
    }

    println("ATA: primary master ready (PIO)");
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
