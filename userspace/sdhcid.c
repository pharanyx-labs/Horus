#include "syscall.h"
#include "blkproto.h"
#include "blkserve.h"

/*
 * sdhcid -- an SD/eMMC driver in ring 3, holding one device capability.
 *
 * WHY THIS EXISTS. src/kernel/sdhci.c drives the SD/eMMC host controller from
 * ring 0, and it is the driver the one real installed machine (an IdeaPad whose
 * only disk is soldered eMMC) boots from: about 1,400 lines of kernel C reading
 * card responses, capacity fields and status bits from a device CLAUDE.md
 * section 1 says to treat as hostile. A bug there, or a card that never answers,
 * is a fault in the kernel. The maintainer chose (2026-10-13) to take the
 * storage drivers out of ring 0, this one first, by moving the kernel's storage
 * to ring 3 rather than having the kernel wait on a ring-3 driver: the kernel
 * never switches tasks mid-syscall (scheduler.c, `yield`), so it cannot wait on
 * one. docs/design/ring3-storage.md is the route. This is its first step: the
 * driver, proved on its own, with nothing else changed. The ring-0 driver still
 * serves the kernel's storage until the cutover deletes it.
 *
 * ITS WHOLE AUTHORITY IS ONE CAP_IO_DEVICE NAMING THE CONTROLLER. No untyped
 * memory, no frame, no console, no filesystem, no key. Less than nvmed holds,
 * because this driver moves data by PIO through the controller's buffer data
 * port, so the controller is never handed memory: it is given memory decode and
 * NOT bus mastering, and with bus mastering off a PCI device cannot start a DMA
 * at all. Compromise this task and you hold the register file of one SD host
 * controller. The volume is sealed and authenticated above the block layer, so
 * once the storage reads through this driver it sees ciphertext only: a hostile
 * driver can refuse service, never read or forge.
 *
 * WHAT THE SELF-TEST DOES. Finds the register file, resets the controller,
 * brings the card up (SD or eMMC), learns its capacity, switches to a 4-bit bus
 * at a data clock and proves the switch with a read, and reads block 0 and block
 * 100. If, and only if, block 0 carries the scratch signature the harness writes
 * (tools/block_scratch.py), block 100 must hold the same image's nonce (the
 * addressing check), and the driver then writes a run of eight sectors in one
 * command, flushes, and reads the run back. A card without the signature is
 * never written, so the self-test image booted on a real machine reads and
 * stops.
 *
 * EVERY WAIT IS BOUNDED BY THE CLOCK, AND EVERYTHING THE CARD SAYS IS CHECKED.
 * The ring-0 driver bounded its waits by spin counts, whose length in time
 * depends on the CPU. Here each bound is milliseconds of the monotonic clock. A
 * register file that reads as floating bus, a response that is not the one the
 * specification defines, a capacity of zero, and a transfer outside the card's
 * own reported extent are refused rather than believed.
 */

/* ---- output ------------------------------------------------------------- */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }
static void wr_dec(unsigned long long v) {
    char b[20]; int n = 0;
    do { b[19 - n] = (char)('0' + v % 10); v /= 10; n++; } while (v && n < 20);
    sys_write(1, b + 20 - n, (unsigned)n);
}

#define FAIL(what) do { wr("SDHCIDTEST: FAIL " what "\n"); for (;;) sys_yield(); } while (0)

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

/* ---- SD Host Controller registers (Simplified Specification 3.00, 2.1) --- */

#define SDHCI_BLOCK_SIZE      0x04   /* 16-bit                                  */
#define SDHCI_BLOCK_COUNT     0x06   /* 16-bit                                  */
#define SDHCI_ARGUMENT        0x08
#define SDHCI_TRANSFER_MODE   0x0C   /* 16-bit; the command register is at 0x0E */
#define SDHCI_COMMAND         0x0E
#define SDHCI_RESPONSE        0x10   /* 0x10,0x14,0x18,0x1C                     */
#define SDHCI_BUFFER_DATA     0x20
#define SDHCI_PRESENT_STATE   0x24
#define SDHCI_HOST_CONTROL    0x28
#define SDHCI_POWER_CONTROL   0x29
#define SDHCI_CLOCK_CONTROL   0x2C   /* 16-bit                                  */
#define SDHCI_TIMEOUT_CONTROL 0x2E
#define SDHCI_SOFTWARE_RESET  0x2F
#define SDHCI_INT_STATUS      0x30   /* normal (16) then error (16) at 0x32     */
#define SDHCI_ERR_STATUS      0x32
#define SDHCI_INT_ENABLE      0x34   /* status ENABLE -- latching, not signalling */
#define SDHCI_ERR_ENABLE      0x36
#define SDHCI_SIGNAL_ENABLE   0x38
#define SDHCI_CAPABILITIES    0x40
#define SDHCI_HOST_VERSION    0xFE

#define PSTATE_CMD_INHIBIT    (1u << 0)
#define PSTATE_DAT_INHIBIT    (1u << 1)
#define PSTATE_CARD_INSERTED  (1u << 16)
#define PSTATE_CARD_STABLE    (1u << 17)
#define PSTATE_DAT0_LEVEL     (1u << 20)

#define RESET_ALL             0x01u
#define RESET_CMD             0x02u
#define RESET_DAT             0x04u

#define CLK_INTERNAL_EN       (1u << 0)
#define CLK_INTERNAL_STABLE   (1u << 1)
#define CLK_SD_EN             (1u << 2)

#define PWR_ON                (1u << 0)
#define PWR_3V3               (0x7u << 1)
#define PWR_3V0               (0x6u << 1)
#define PWR_1V8               (0x5u << 1)

#define INT_CMD_COMPLETE      (1u << 0)
#define INT_XFER_COMPLETE     (1u << 1)
#define INT_BUF_WRITE_READY   (1u << 4)
#define INT_BUF_READ_READY    (1u << 5)

#define RESP_NONE             0x0u
#define RESP_136              0x1u
#define RESP_48               0x2u
#define RESP_48_BUSY          0x3u
#define CMD_CRC_CHECK         (1u << 3)
#define CMD_INDEX_CHECK       (1u << 4)
#define CMD_DATA_PRESENT      (1u << 5)

/* Transfer Mode: direction is bit 4 and 1 means card-to-host, so ZERO IS A
 * WRITE, and a transfer whose direction was never set writes. That is why the
 * mode is written by the data paths before their command and never cleared by
 * one (sd_command_data). */
#define XFER_READ             (1u << 4)
#define XFER_WRITE            0u
#define XFER_BLK_COUNT_EN     (1u << 1)
#define XFER_AUTO_CMD12       (1u << 2)
#define XFER_MULTI            (1u << 5)

#define CMD_GO_IDLE            0u
#define CMD_SEND_OP_COND_MMC   1u    /* eMMC only                               */
#define CMD_ALL_SEND_CID       2u
#define CMD_SEND_RELATIVE_ADDR 3u
#define CMD_MMC_SWITCH         6u    /* eMMC: write one EXT_CSD byte            */
#define ACMD_SET_BUS_WIDTH     6u    /* SD: 0 = 1-bit, 2 = 4-bit                */
#define CMD_SELECT_CARD        7u
#define CMD_SEND_IF_COND       8u    /* SD                                      */
#define CMD_MMC_SEND_EXT_CSD   8u    /* eMMC: a 512-byte data read at index 8   */
#define CMD_SEND_CSD           9u
#define CMD_READ_SINGLE       17u
#define CMD_READ_MULTI        18u
#define CMD_WRITE_SINGLE      24u
#define CMD_WRITE_MULTI       25u
#define ACMD_SEND_OP_COND     41u    /* SD                                      */
#define CMD_APP_CMD           55u
#define EXT_CSD_BUS_WIDTH    183u
#define HOST_CTRL_4BIT       (1u << 1)
#define SDHCI_DATA_KHZ_MMC  26000u   /* eMMC default-speed ceiling              */
#define SDHCI_DATA_KHZ_SD   25000u   /* SD default-speed ceiling                */

#define VER_SPEC_MAX          4u     /* 0 = 1.00 ... 4 = 4.10; above is not SDHCI */

/* Every bound, in milliseconds. A register answers in microseconds; a card
 * programming data it accepted may hold DAT0 low for hundreds of milliseconds,
 * and the op-cond negotiation polls a card that is still powering up, which the
 * SD specification allows a second for. Each is a ceiling on a wait for
 * hardware that may never answer, so "no card" is an error and never a hang. */
#define CMD_MS     1000ULL
#define DATA_MS    2000ULL
#define BUSY_MS    5000ULL
#define OPCOND_MS  3000ULL

/* ---- capability slot and address-space layout --------------------------- */

#define DEV_SLOT   CAPSLOT_IO_DEVICE
#define VA_REGS    0x0000000100000000ULL   /* 4 GiB: one page per memory region */

/* ---- the scratch card's layout; tools/block_scratch.py `sd` matches ------ */

#define SCRATCH_MAGIC  "HORUS-SDHC-SCRATCH-V1"     /* 21 bytes + NUL           */
#define READ_MAGIC     "HORUS-SDHC-BLOCK100-V1"    /* 22 bytes + NUL           */
#define WRITTEN_MAGIC  "HORUS-SDHC-WRITTEN-V1"
#define SCRATCH_LEN    22u
#define READ_LEN       23u
#define NONCE_OFF      32u
#define NONCE_LEN      16u
#define READ_LBA       100ULL
#define RUN            8u                          /* one 4 KiB block, in sectors */
#ifdef SDHCID_WRITE_WRONG_LBA
/* The arm for the host-side witness: write and read back a DIFFERENT run. The
 * guest's own read-back still matches, because it reads what it wrote, so only
 * the check of the image after QEMU exits can tell. */
#define WRITE_LBA      24ULL
#else
#define WRITE_LBA      8ULL
#endif

/* ---- state -------------------------------------------------------------- */

static volatile unsigned char *regs;
static unsigned long long g_sectors;    /* the card's own extent, in 512-byte sectors */
static int g_is_hc;                     /* block-addressed (1) or byte-addressed (0)  */

static inline unsigned r32(unsigned off) { return *(volatile unsigned int *)(regs + off); }
static inline unsigned r16(unsigned off) { return *(volatile unsigned short *)(regs + off); }
static inline unsigned r8(unsigned off)  { return *(volatile unsigned char *)(regs + off); }
static inline void w32(unsigned off, unsigned v) { *(volatile unsigned int *)(regs + off) = v; }
static inline void w16(unsigned off, unsigned v) { *(volatile unsigned short *)(regs + off) = (unsigned short)v; }
static inline void w8(unsigned off, unsigned v)  { *(volatile unsigned char *)(regs + off) = (unsigned char)v; }

/* Wait until (r16/r32 at `off` & mask) is non-zero or zero, as asked, within
 * `ms`. The clock is read every 64 polls and the CPU offered to other tasks with
 * it: a register that answers at once costs no system call, and one that does
 * not cannot hold the CPU. Returns 0, or -1 when the bound passed. */
static int wait_bits(unsigned off, int width, unsigned mask, int want_set,
                     unsigned long long ms) {
    unsigned long long start = now_ms();
    for (unsigned i = 0; ; i++) {
        unsigned v = (width == 8) ? r8(off) : (width == 16) ? r16(off) : r32(off);
        if (want_set ? (v & mask) != 0 : (v & mask) == 0) return 0;
        if ((i & 63u) == 63u) {
            if (now_ms() - start > ms) return -1;
            sys_yield();
        }
    }
}

/* Put the command line, and the data line when asked, back into a state where
 * the next command can be issued (SDHCI 3.00 section 3.10.1). A failed command
 * leaves the line inhibited, and every later command then fails for a reason
 * that is not its own; QEMU's card models clear the inhibit by themselves, so
 * only real silicon showed this (2026-09-22, src/kernel/sdhci.c). The latched
 * status is cleared too, or the next command reads it as its own failure. */
static void line_recover(int also_dat) {
    const unsigned bits = RESET_CMD | (also_dat ? RESET_DAT : 0u);
    w8(SDHCI_SOFTWARE_RESET, bits);
    (void)wait_bits(SDHCI_SOFTWARE_RESET, 8, bits, 0, CMD_MS);
    w16(SDHCI_INT_STATUS, 0xFFFFu);
    w16(SDHCI_ERR_STATUS, 0xFFFFu);
}

/* The SD clock at no more than `khz`. SDCLK is base / (2 * N), and N's encoding
 * depends on the specification version: a 3.00 host takes a 10-bit N of any
 * value (bits 15:8 low, 7:6 high), a 2.00 host an 8-bit power of two. The
 * IdeaPad's 3.00 host has a 200 MHz base, where the 2.00 rule cannot get below
 * 781 kHz and identification needs 400 kHz or less. Returns the clock set, in
 * kHz, or 0 if the internal clock would not settle or the base is unknown. */
static unsigned set_clock(unsigned khz) {
    const unsigned caps = r32(SDHCI_CAPABILITIES);
    const unsigned base_khz = ((caps >> 8) & 0xFFu) * 1000u;
    const unsigned spec = r16(SDHCI_HOST_VERSION) & 0xFFu;
    if (base_khz == 0 || khz == 0) return 0;
    unsigned div = 1, bits;
    if (spec >= 2u) {
        div = (base_khz + 2u * khz - 1u) / (2u * khz);     /* ceil(base / 2khz) */
        if (div > 0x3FFu) div = 0x3FFu;
        bits = ((div & 0xFFu) << 8) | (((div >> 8) & 0x3u) << 6);
    } else {
        while (base_khz / (2u * div) > khz && div < 0x80u) div <<= 1;
        bits = (div & 0xFFu) << 8;
    }
    w16(SDHCI_CLOCK_CONTROL, 0);                            /* stop before changing */
    w16(SDHCI_CLOCK_CONTROL, bits | CLK_INTERNAL_EN);
    if (wait_bits(SDHCI_CLOCK_CONTROL, 16, CLK_INTERNAL_STABLE, 1, CMD_MS) != 0) return 0;
    w16(SDHCI_CLOCK_CONTROL, r16(SDHCI_CLOCK_CONTROL) | CLK_SD_EN);
    return base_khz / (2u * div);
}

/* Reset the controller, then power, then clock: the specification's order, and
 * not interchangeable. Clocking a card before it is powered leaves it idle for
 * good, which looks like "no card" rather than like a sequencing mistake.
 * Returns the identification clock in kHz, or 0 on failure. */
static unsigned host_reset(void) {
    w8(SDHCI_SOFTWARE_RESET, RESET_ALL);
    if (wait_bits(SDHCI_SOFTWARE_RESET, 8, RESET_ALL, 0, CMD_MS) != 0) return 0;

    /* The highest voltage the controller says it supports: capabilities bits
     * 24..26 are 3.3 V, 3.0 V and 1.8 V. */
    const unsigned caps = r32(SDHCI_CAPABILITIES);
    unsigned pwr;
    if      (caps & (1u << 24)) pwr = PWR_3V3;
    else if (caps & (1u << 25)) pwr = PWR_3V0;
    else if (caps & (1u << 26)) pwr = PWR_1V8;
    else return 0;
    w8(SDHCI_POWER_CONTROL, pwr | PWR_ON);

    const unsigned khz = set_clock(400u);
    if (khz == 0) return 0;
    w8(SDHCI_TIMEOUT_CONTROL, 0x0E);                 /* the maximum data timeout */

    /* Status ENABLED so it latches, never SIGNALLED: this driver polls, and a
     * signalled interrupt would arrive with nothing registered to take it. */
    w16(SDHCI_INT_ENABLE, 0xFFFFu);
    w16(SDHCI_ERR_ENABLE, 0xFFFFu);
    w16(SDHCI_SIGNAL_ENABLE, 0);
    return khz;
}

/* Issue one command and wait for it to complete. Returns 0, or -1 on an error,
 * an inhibited line or no completion, after putting the lines back.
 * `touch_xfer_mode` is 0 only for a data command, whose direction the caller
 * has already written: clearing it here would make every read a write. */
static int sd_command_common(unsigned index, unsigned arg, unsigned resp,
                             unsigned flags, int touch_xfer_mode) {
    const int uses_dat = ((flags & CMD_DATA_PRESENT) != 0) || (resp == RESP_48_BUSY);

    /* Both lines free: a command that changes card state must not go out while
     * an earlier transfer is still using the data line. Whatever holds the bus
     * past the bound is not this command's doing, so both lines are reset. */
    if (wait_bits(SDHCI_PRESENT_STATE, 32, PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT, 0, CMD_MS) != 0) {
        line_recover(1);
        return -1;
    }

    w16(SDHCI_INT_STATUS, 0xFFFFu);                  /* write-1-to-clear */
    w16(SDHCI_ERR_STATUS, 0xFFFFu);
    w32(SDHCI_ARGUMENT, arg);
    if (touch_xfer_mode) w16(SDHCI_TRANSFER_MODE, 0);
    w16(SDHCI_COMMAND, (index << 8) | resp | flags);

    unsigned long long start = now_ms();
    for (unsigned i = 0; ; i++) {
        unsigned st = r16(SDHCI_INT_STATUS), err = r16(SDHCI_ERR_STATUS);
        if (err) { line_recover(uses_dat); return -1; }   /* timeout, CRC, index */
        if (st & INT_CMD_COMPLETE) return 0;
        if ((i & 63u) == 63u) {
            if (now_ms() - start > CMD_MS) { line_recover(uses_dat); return -1; }
            sys_yield();
        }
    }
}
static int sd_command(unsigned index, unsigned arg, unsigned resp, unsigned flags) {
    return sd_command_common(index, arg, resp, flags, 1);
}
static int sd_command_data(unsigned index, unsigned arg, unsigned resp, unsigned flags) {
    return sd_command_common(index, arg, resp, flags, 0);
}

/* Wait for one of the data-phase status bits, or fail on any error bit. The
 * bit is cleared once seen (write-1-to-clear), because the controller raises
 * buffer-ready once per block, and a loop that does not clear it sees the first
 * block's assertion every time and races the card. */
static int wait_data(unsigned bit) {
    unsigned long long start = now_ms();
    for (unsigned i = 0; ; i++) {
        unsigned st = r16(SDHCI_INT_STATUS), err = r16(SDHCI_ERR_STATUS);
        if (err) return -1;
        if (st & bit) { w16(SDHCI_INT_STATUS, bit); return 0; }
        if ((i & 63u) == 63u) {
            if (now_ms() - start > DATA_MS) return -1;
            sys_yield();
        }
    }
}

/* The address a data command carries for sector `lba`. A high-capacity card
 * takes a block number and a standard-capacity card a byte offset. Wrong, every
 * transfer lands 512 times away, except block 0, which is address 0 in both
 * units: the reason the self-test checks block 100. A standard-capacity card is
 * at most 2 GiB, so its byte offset fits the 32-bit argument; a block number
 * that does not fit is refused by the caller's bound on the card's extent. */
static unsigned sd_arg(unsigned long long lba) {
#ifdef SDHCID_ADDR_INVERTED
    /* Control arm: the units swapped, which block 0 cannot show. */
    return g_is_hc ? (unsigned)(lba * 512u) : (unsigned)lba;
#else
    return g_is_hc ? (unsigned)lba : (unsigned)(lba * 512u);
#endif
}

/* Move `count` contiguous sectors in ONE command, by PIO. CMD18/CMD25 with
 * Auto CMD12 for a run, CMD17/CMD24 for one sector. Refused unless the WHOLE run
 * lies inside the card's own reported extent: a transfer that stopped at the
 * edge would report success for sectors that were never moved (S64). */
static int rw_sectors(unsigned long long lba, void *buf, unsigned count, int is_write) {
    if (count == 0 || count > 0xFFFFu) return -1;
    if (lba >= g_sectors || (unsigned long long)count > g_sectors - lba) return -1;
    if (!g_is_hc && lba + count > 0xFFFFFFFFULL / 512u) return -1;

    unsigned *p = (unsigned *)buf;
    const unsigned ready = is_write ? INT_BUF_WRITE_READY : INT_BUF_READ_READY;

    w16(SDHCI_BLOCK_SIZE, 512);
    w16(SDHCI_BLOCK_COUNT, count);
    unsigned mode = is_write ? XFER_WRITE : XFER_READ;
    if (count > 1) mode |= XFER_MULTI | XFER_BLK_COUNT_EN | XFER_AUTO_CMD12;
    /* The direction BEFORE the command: the controller latches it then. */
    w16(SDHCI_TRANSFER_MODE, mode);

    const unsigned index = count > 1 ? (is_write ? CMD_WRITE_MULTI : CMD_READ_MULTI)
                                     : (is_write ? CMD_WRITE_SINGLE : CMD_READ_SINGLE);
    if (sd_command_data(index, sd_arg(lba), RESP_48,
                        CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT) != 0)
        return -2;

    for (unsigned b = 0; b < count; b++) {
        if (wait_data(ready) != 0) { line_recover(1); return -3; }
        if (is_write) for (unsigned i = 0; i < 128u; i++) w32(SDHCI_BUFFER_DATA, p[i]);
        else          for (unsigned i = 0; i < 128u; i++) p[i] = r32(SDHCI_BUFFER_DATA);
        p += 128u;
    }
    if (wait_data(INT_XFER_COMPLETE) != 0) { line_recover(1); return -4; }
    return 0;
}

/* One 512-byte data read of a non-sector command: an eMMC's extended CSD. */
static int read_ext_csd(unsigned char *buf) {
    w16(SDHCI_BLOCK_SIZE, 512);
    w16(SDHCI_BLOCK_COUNT, 1);
    w16(SDHCI_TRANSFER_MODE, XFER_READ);
    if (sd_command_data(CMD_MMC_SEND_EXT_CSD, 0, RESP_48,
                        CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT) != 0)
        return -1;
    unsigned *p = (unsigned *)buf;
    if (wait_data(INT_BUF_READ_READY) != 0) { line_recover(1); return -2; }
    for (unsigned i = 0; i < 128u; i++) p[i] = r32(SDHCI_BUFFER_DATA);
    if (wait_data(INT_XFER_COMPLETE) != 0) { line_recover(1); return -3; }
    return 0;
}

/* The card holds DAT0 low while it is busy: after an R1b response, and while it
 * programs data it accepted. */
static int wait_dat0(void) {
    return wait_bits(SDHCI_PRESENT_STATE, 32, PSTATE_DAT0_LEVEL, 1, BUSY_MS);
}

/* Everything accepted is on the card: the controller has no transfer running
 * AND the card has released DAT0. The inhibit bit alone is the controller's,
 * not the card's; on the IdeaPad (2026-09-24) it read clear while DAT0 was still
 * low. The SD protocol has no separate cache-flush command, so this is what "on
 * stable media" means for this device. */
static int sd_flush(void) {
    if (wait_bits(SDHCI_PRESENT_STATE, 32, PSTATE_DAT_INHIBIT, 0, DATA_MS) != 0) return -1;
    return wait_dat0();
}

/* A 4-bit bus and a data clock: eMMC by CMD6 SWITCH of EXT_CSD BUS_WIDTH, SD by
 * ACMD6, then the host's width, then 26 or 25 MHz (default speed, no timing
 * switch). Returns the data clock in kHz, or 0 if nothing was changed. */
static unsigned go_fast(int is_mmc, unsigned rca) {
    if (is_mmc) {
        const unsigned arg = (3u << 24) | (EXT_CSD_BUS_WIDTH << 16) | (1u << 8);
        if (sd_command(CMD_MMC_SWITCH, arg, RESP_48_BUSY, CMD_CRC_CHECK | CMD_INDEX_CHECK) != 0) return 0;
        if (wait_dat0() != 0) return 0;
    } else {
        if (sd_command(CMD_APP_CMD, rca << 16, RESP_48, CMD_CRC_CHECK) != 0) return 0;
        if (sd_command(ACMD_SET_BUS_WIDTH, 2u, RESP_48, CMD_CRC_CHECK) != 0) return 0;
    }
    w8(SDHCI_HOST_CONTROL, r8(SDHCI_HOST_CONTROL) | HOST_CTRL_4BIT);
    return set_clock(is_mmc ? SDHCI_DATA_KHZ_MMC : SDHCI_DATA_KHZ_SD);
}

/* Back to one line at the identification clock, card and host both. */
static void go_slow(int is_mmc, unsigned rca) {
    if (is_mmc) {
        (void)sd_command(CMD_MMC_SWITCH, (3u << 24) | (EXT_CSD_BUS_WIDTH << 16),
                         RESP_48_BUSY, CMD_CRC_CHECK | CMD_INDEX_CHECK);
        (void)wait_dat0();
    } else if (sd_command(CMD_APP_CMD, rca << 16, RESP_48, CMD_CRC_CHECK) == 0) {
        (void)sd_command(ACMD_SET_BUS_WIDTH, 0u, RESP_48, CMD_CRC_CHECK);
    }
    w8(SDHCI_HOST_CONTROL, r8(SDHCI_HOST_CONTROL) & ~HOST_CTRL_4BIT);
    (void)set_clock(400u);
}

/* Bring the card up and learn its extent. SD: CMD8 then ACMD41. eMMC: CMD1.
 * The two share CMD2, CMD3, CMD9 and CMD7. Returns 0, or the failing step as a
 * negative number (named in the log by the caller). */
static int card_identify(int *is_mmc_out, unsigned *rca_out) {
    if (sd_command(CMD_GO_IDLE, 0, RESP_NONE, 0) != 0) return -1;

    /* Index 8 is SEND_IF_COND on SD and SEND_EXT_CSD (a data read) on eMMC. An
     * eMMC device answers it and then drives DAT with nobody draining it, so the
     * answer is believed only if it is SD's own echo of the check pattern, and
     * both lines are put back whatever happened. That dangling data phase is
     * what made the IdeaPad report "the card did not come up" (2026-09-22). */
    int sd_v2 = 0;
    if (sd_command(CMD_SEND_IF_COND, 0x1AAu, RESP_48, CMD_CRC_CHECK) == 0)
        sd_v2 = ((r32(SDHCI_RESPONSE) & 0xFFFu) == 0x1AAu);
    line_recover(1);

    int is_mmc = 0;
    unsigned ocr = 0;
    {
        unsigned long long start = now_ms();
        int up = 0;
        for (;;) {
            if (sd_command(CMD_APP_CMD, 0, RESP_48, CMD_CRC_CHECK) != 0) { is_mmc = 1; break; }
            /* HCS when the card claimed 2.0: without it a high-capacity card
             * refuses and reports an extent it does not have. */
            const unsigned arg = 0x00FF8000u | (sd_v2 ? (1u << 30) : 0u);
            if (sd_command(ACMD_SEND_OP_COND, arg, RESP_48, 0) != 0) { is_mmc = 1; break; }
            ocr = r32(SDHCI_RESPONSE);
            if (ocr & (1u << 31)) { up = 1; break; }     /* finished powering up */
            if (now_ms() - start > OPCOND_MS) break;
            sys_yield();
        }
        if (!is_mmc && !up) return -9;
    }

    if (is_mmc) {
        if (sd_command(CMD_GO_IDLE, 0, RESP_NONE, 0) != 0) return -8;
        /* 2.7-3.6 V always, and 1.70-1.95 V (OCR bit 7) when the host supplies
         * it: a device whose range the argument misses goes inactive until it
         * is power-cycled, and the IdeaPad's host supplies only 1.8 V. Bit 30
         * asks for sector addressing. */
        const unsigned mmc_ocr = 0x40FF8000u |
            ((r32(SDHCI_CAPABILITIES) & (1u << 26)) ? (1u << 7) : 0u);
        unsigned long long start = now_ms();
        for (;;) {
            if (sd_command(CMD_SEND_OP_COND_MMC, mmc_ocr, RESP_48, 0) != 0) return -2;
            ocr = r32(SDHCI_RESPONSE);
            if (ocr & (1u << 31)) break;
            if (now_ms() - start > OPCOND_MS) return -2;
            sys_yield();
        }
    }

    if (sd_command(CMD_ALL_SEND_CID, 0, RESP_136, CMD_CRC_CHECK) != 0) return -3;
    /* CMD3: an SD card REPORTS its address, an eMMC device is TOLD one; a
     * non-zero argument is ignored by SD and required by eMMC. */
    if (sd_command(CMD_SEND_RELATIVE_ADDR, 1u << 16, RESP_48, CMD_CRC_CHECK) != 0) return -4;
    const unsigned rca = is_mmc ? 1u : (r32(SDHCI_RESPONSE) >> 16);
    if (rca == 0) return -4;                     /* 0 is the broadcast address */
    if (sd_command(CMD_SEND_CSD, rca << 16, RESP_136, CMD_CRC_CHECK) != 0) return -5;

    /* THE CSD ARRIVES SHIFTED BY EIGHT BITS: a 136-bit response is stored with
     * the CRC byte dropped, so CSD bit R sits at response bit R-8, spread over
     *   c1 = resp[63:32], c2 = resp[95:64], c3 = resp[127:96].
     * Reading the specification's own bit numbers reads correctly and is wrong:
     * it is how the ring-0 driver once reported a 128 MiB card as 30752 MiB. */
    const unsigned c1 = r32(SDHCI_RESPONSE + 4);
    const unsigned c2 = r32(SDHCI_RESPONSE + 8);
    const unsigned c3 = r32(SDHCI_RESPONSE + 12);
    const unsigned csd_ver = (c3 >> 22) & 0x3u;      /* CSD[127:126] */
    unsigned long long sectors;
#ifdef SDHCID_CSD_SPEC_BITS
    /* Control arm: the fields at their specification positions, unshifted. */
    if (csd_ver == 1) {
        const unsigned c_size = ((c1 >> 16) | (c2 << 16)) & 0x3FFFFFu;
        sectors = ((unsigned long long)c_size + 1u) * 1024u;
    } else {
        const unsigned c_size      = ((c2 & 0x3FFu) << 2) | (c1 >> 30);
        const unsigned c_size_mult = (c1 >> 15) & 0x7u;
        const unsigned read_bl_len = (c2 >> 16) & 0xFu;
        sectors = (((unsigned long long)c_size + 1u) * (1ULL << (c_size_mult + 2u))
                   * (1ULL << read_bl_len)) / 512u;
    }
#else
    if (csd_ver == 1) {
        /* CSD v2: C_SIZE is CSD[69:48] -> c1 bits 29:8, in 512 KiB units. */
        const unsigned c_size = (c1 >> 8) & 0x3FFFFFu;
        sectors = ((unsigned long long)c_size + 1u) * 1024u;
    } else {
        /* CSD v1: (C_SIZE+1) * 2^(C_SIZE_MULT+2) * 2^READ_BL_LEN bytes.
         *   READ_BL_LEN CSD[83:80] -> c2 bits 11:8
         *   C_SIZE      CSD[73:62] -> c2 bits 1:0 (high) + c1 bits 31:22 (low)
         *   C_SIZE_MULT CSD[49:47] -> c1 bits 9:7 */
        const unsigned read_bl_len = (c2 >> 8) & 0xFu;
        const unsigned c_size      = ((c2 & 0x3u) << 10) | ((c1 >> 22) & 0x3FFu);
        const unsigned c_size_mult = (c1 >> 7) & 0x7u;
        /* READ_BL_LEN is 9 to 11 for every card the specification allows; a
         * larger one is a card lying about its geometry, refused rather than
         * shifted into an extent it does not have. */
        if (read_bl_len < 9u || read_bl_len > 11u) return -5;
        sectors = (((unsigned long long)c_size + 1u) * (1ULL << (c_size_mult + 2u))
                   * (1ULL << read_bl_len)) / 512u;
    }
#endif

    if (sd_command(CMD_SELECT_CARD, rca << 16, RESP_48_BUSY, CMD_CRC_CHECK) != 0) return -6;

    /* An eMMC over 2 GiB states a placeholder in its CSD and its real size in
     * EXT_CSD SEC_COUNT, bytes 212..215, little-endian (JESD84). A failed or zero
     * read is an error, never a reason to fall back on a number known to be
     * wrong. */
    if (is_mmc && (ocr & (1u << 30))) {
        static unsigned char ext_csd[512];
        if (read_ext_csd(ext_csd) != 0) return -7;
        const unsigned sec = (unsigned)ext_csd[212] | ((unsigned)ext_csd[213] << 8) |
                             ((unsigned)ext_csd[214] << 16) | ((unsigned)ext_csd[215] << 24);
        if (sec == 0) return -7;
        sectors = sec;
    }
    if (sectors == 0) return -5;

    g_sectors = sectors;
    /* OCR bit 30 (CCS) is the ADDRESSING MODE, not a capacity label. */
    g_is_hc = (ocr & (1u << 30)) ? 1 : 0;
    *is_mmc_out = is_mmc;
    *rca_out = rca;
    return 0;
}

/* The block-driver protocol's backend (userspace/blkserve.c). blkserve has
 * already held the request to the client's extent; rw_sectors holds it to the
 * card's own, whatever blkserve decided. */
static int be_read(uint64_t lba, void *buf, unsigned count)        { return rw_sectors(lba, buf, count, 0); }
static int be_write(uint64_t lba, const void *buf, unsigned count) { return rw_sectors(lba, (void *)buf, count, 1); }
static int be_flush(void)                                          { return sd_flush(); }

/* Indexed by -rc of card_identify; keep in step with its returns. */
static const char *const identify_step[] = {
    "",
    "CMD0 go-idle",
    "CMD1 eMMC op-cond",
    "CMD2 all-send-CID",
    "CMD3 relative address",
    "CMD9 send-CSD",
    "CMD7 select-card",
    "CMD8 extended CSD read",
    "CMD0 go-idle, eMMC retry",
    "ACMD41 SD op-cond never finished",
};

void _start(void) {
    struct dev_info dev;

    wr("SDHCID: begin\n");

    /* ---- 1. what device is this? -------------------------------------- */
    if (sys_device_info(DEV_SLOT, &dev) != 0) FAIL("device-info");
    /* Class 08, subclass 05: SD host controller. The programming interface
     * (00 no DMA, 01 DMA, 02 vendor) is not tested: this driver uses none of
     * the DMA either way. */
    if ((dev.classcode >> 8) != 0x0805u) FAIL("not-an-sd-host-controller");
    if (dev.n_mmio == 0) FAIL("no-mmio-region");

    /* ---- 2. memory decode, and NOT bus mastering ------------------------- */
    /* The decode bits are set to exactly this, so a bus-master bit firmware left
     * on is cleared: a PIO driver never lets its controller start a DMA. */
    if (sys_device_enable(DEV_SLOT, DEV_ENABLE_MEM) != 0) FAIL("device-enable");

    /* ---- 3. which region is the register file? -------------------------- */
    /* The SDHCI Slot Information register (PCI configuration offset 0x40) names
     * slot 0's BAR, and ring 3 cannot read configuration space. So each memory
     * region the device declares is mapped and asked, and the first, in BAR
     * order, whose registers answer as a host controller is used: a version
     * this specification defines and a capabilities word that is neither 0 nor
     * all ones. The IdeaPad's controller has two regions, and its second reads
     * all zeros (2026-09-22): that is the failure this test refuses, where the
     * ring-0 driver's first guess (the highest region) took it. */
    int chosen = -1;
    unsigned n_answered = 0;
    for (unsigned i = 0; i < dev.n_mmio && i < 8u; i++) {
        unsigned long long base = dev.mmio[i].base, len = dev.mmio[i].len;
        if ((base & 0xFFFULL) != 0 || len < 0x100) continue;
        unsigned long long va = VA_REGS + (unsigned long long)i * 0x1000ULL;
        if (sys_map_phys(DEV_SLOT, base, va, len < 4096 ? len : 4096, MAP_PHYS_WRITE) != 0)
            continue;
        volatile unsigned char *r = (volatile unsigned char *)(unsigned long)va;
        const unsigned ver  = *(volatile unsigned short *)(r + SDHCI_HOST_VERSION);
        const unsigned caps = *(volatile unsigned int *)(r + SDHCI_CAPABILITIES);
        if ((ver & 0xFFu) > VER_SPEC_MAX || caps == 0 || caps == 0xFFFFFFFFu) continue;
        n_answered++;
        if (chosen < 0) { chosen = (int)i; regs = r; }
    }
    if (chosen < 0) FAIL("no-region-answers-as-a-host-controller");

    const unsigned ver = r16(SDHCI_HOST_VERSION) & 0xFFu;
    const unsigned caps = r32(SDHCI_CAPABILITIES);
    wr("SDHCID: host controller v"); wr_dec(ver + 1u); wr(".0, base clock ");
    wr_dec((caps >> 8) & 0xFFu); wr(" MHz, region "); wr_dec((unsigned)chosen);
    wr(" of "); wr_dec(dev.n_mmio); wr(", "); wr_dec(n_answered); wr(" answered\n");

    /* ---- 4. is there a card? -------------------------------------------- */
    /* An embedded slot (capabilities 31:30 = 01) holds a soldered device whose
     * detect line the specification does not require: the IdeaPad's eMMC. Any
     * other slot must report a card inserted AND the line settled. */
    const unsigned ps = r32(SDHCI_PRESENT_STATE);
    if (((caps >> 30) & 0x3u) == 0x1u) {
        wr("SDHCID: embedded slot, its soldered device is present by construction\n");
    } else if ((ps & PSTATE_CARD_INSERTED) && (ps & PSTATE_CARD_STABLE)) {
        wr("SDHCID: a card is present and the detect line is stable\n");
    } else {
        FAIL("no-card");
    }

    /* ---- 5. reset, identify, and the card's extent ---------------------- */
    const unsigned id_khz = host_reset();
    if (id_khz == 0) FAIL("controller-reset");
    wr("SDHCID: identification clock "); wr_dec(id_khz); wr(" kHz\n");

    int is_mmc = 0;
    unsigned rca = 0;
    {
        const int rc = card_identify(&is_mmc, &rca);
        if (rc != 0) {
            const int nsteps = (int)(sizeof(identify_step) / sizeof(identify_step[0]));
            wr("SDHCID: the card did not come up (");
            if (-rc > 0 && -rc < nsteps) wr(identify_step[-rc]);
            wr(")\n");
            FAIL("card-identify");
        }
    }
    wr("SDHCID: "); wr(is_mmc ? "eMMC" : "SD card"); wr(", capacity ");
    wr_dec(g_sectors); wr(" sectors, ");
    wr(g_is_hc ? "block-addressed\n" : "byte-addressed\n");
    if (g_sectors < WRITE_LBA + RUN || g_sectors <= READ_LBA) FAIL("card-too-small");

    /* ---- 6. block 0 at the identification settings, then go fast --------- */
    static unsigned char blk0[512], fast0[512];
    {
        const int rc = rw_sectors(0, blk0, 1, 0);
        if (rc != 0) { wr("SDHCID: read of block 0 failed at step "); wr_dec((unsigned)-rc); wr("\n"); FAIL("read-block0"); }
    }
    /* The switch is proved by reading block 0 again at the new settings and
     * comparing: a bus that comes back with different bytes is worse than a
     * slow one, so a mismatch falls back rather than carrying on. */
    unsigned data_khz = go_fast(is_mmc, rca);
    if (data_khz && (rw_sectors(0, fast0, 1, 0) != 0 || !same(fast0, blk0, 512))) {
        wr("SDHCID: the card did not read back at the data clock; back to identification settings\n");
        go_slow(is_mmc, rca);
        data_khz = 0;
    }
    if (data_khz) { wr("SDHCID: 4-bit bus at "); wr_dec(data_khz); wr(" kHz\n"); }
    else          wr("SDHCID: one data line at the identification clock\n");

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
        wr("SDHCID: serving the block protocol\n");
        blkserve_run(&be);
    }

    /* ---- 7. a real card is read and never written ----------------------- */
    if (!same(blk0, SCRATCH_MAGIC, SCRATCH_LEN)) {
        static unsigned char b100[512];
        if (rw_sectors(READ_LBA, b100, 1, 0) != 0) FAIL("read-block100");
        wr("SDHCIDTEST: READ PASS (no scratch signature; nothing written)\n");
        for (;;) sys_yield();
    }

    /* ---- 8. block 100 holds THIS image's nonce: the addressing check ----- */
    unsigned char nonce[NONCE_LEN];
    for (unsigned i = 0; i < NONCE_LEN; i++) nonce[i] = blk0[NONCE_OFF + i];
    {
        static unsigned char b100[512];
        if (rw_sectors(READ_LBA, b100, 1, 0) != 0) FAIL("block100-read");
        if (!same(b100, READ_MAGIC, READ_LEN) || !same(b100 + NONCE_OFF, nonce, NONCE_LEN))
            FAIL("block100-not-this-image");
    }
    wr("SDHCIDTEST: READ PASS\n");

    /* ---- 9. a run of eight sectors in one command, flushed, read back ---- */
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
        if (rc != 0) { wr("SDHCID: write failed at step "); wr_dec((unsigned)-rc); wr("\n"); FAIL("write"); }
    }
    if (sd_flush() != 0) FAIL("flush");
    {
        const int rc = rw_sectors(WRITE_LBA, check, RUN, 0);
        if (rc != 0) { wr("SDHCID: read-back failed at step "); wr_dec((unsigned)-rc); wr("\n"); FAIL("read-back"); }
    }
    if (!same(check, run, sizeof(run))) FAIL("read-back-differs");

    wr("SDHCID: wrote, flushed and read back sectors "); wr_dec(WRITE_LBA); wr("-");
    wr_dec(WRITE_LBA + RUN - 1u); wr("\n");
    wr("SDHCIDTEST: PASS\n");
    for (;;) sys_yield();
}
