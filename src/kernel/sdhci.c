/* sdhci.c -- find the SD/eMMC host controller, and say what is in it.
 *
 * WHY THIS EXISTS, AND WHY IT IS THE ONE THAT MATTERS FOR A LAPTOP.
 *
 * This tree has two storage drivers: `ata.c` (legacy IDE PIO) and, since
 * 2026-09-07, enough of `ahci.c` to make a SATA disk identify itself. Neither
 * reaches the machine this is for. A budget laptop's internal storage is
 * frequently soldered eMMC behind an SD host controller -- a third controller
 * type, sharing nothing with either of the others -- so `boot.iso` boots on that
 * hardware, the installer surveys the machine, and finds NO DISK.
 *
 * This is the first half of answering that, and deliberately only the first
 * half: it FINDS the controller and REPORTS what the hardware says. It resets
 * nothing, issues no command, sets no clock, and takes no interrupt. Bringing
 * the card up (CMD0/CMD1/CMD2/CMD3, the CSD, the capacity) is the next change,
 * and reading blocks the one after that.
 *
 * SPLIT THERE FOR THE REASON THE AHCI WORK WAS: the risky half is talking to the
 * hardware, and it can be wrong on its own without half a driver in the tree to
 * explain the symptom. It also answers the question a laptop owner actually has
 * -- "does Horus see my storage at all?" -- before any of the rest exists.
 *
 * WHAT IT READS. The SD Host Controller specification puts the register file in
 * a memory BAR. Three registers say whether this is a controller worth talking
 * to and whether anything is in it:
 *
 *   0xFE  Host Controller Version -- the specification revision, in its low byte
 *   0x40  Capabilities            -- base clock, max block length, voltages
 *   0x24  Present State           -- card inserted, and whether the line is stable
 *
 * VALIDATED BEFORE BELIEVED, the same way ahci.c validates its ABAR. A BAR that
 * is wrong, or a controller that is powered down, reads as all-ones; a
 * capabilities register of 0xFFFFFFFF and a version of 0xFF are what that looks
 * like, and reporting either as a disk survey would be worse than saying
 * nothing. A controller that fails those tests is reported as unrecognised.
 */
#include "kernel.h"

/* Register offsets from the SD Host Controller Simplified Specification 3.00,
 * section 2.1. */
#define SDHCI_BLOCK_SIZE      0x04   /* 16-bit                                  */
#define SDHCI_BLOCK_COUNT     0x06   /* 16-bit                                  */
#define SDHCI_ARGUMENT        0x08
#define SDHCI_TRANSFER_MODE   0x0C   /* 16-bit; the command register is at 0x0E */
#define SDHCI_COMMAND         0x0E
#define SDHCI_RESPONSE        0x10   /* 0x10,0x14,0x18,0x1C                     */
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

/* Present State */
#define PSTATE_CMD_INHIBIT    (1u << 0)   /* the command line is busy   */
#define PSTATE_DAT_INHIBIT    (1u << 1)   /* the data line is busy      */

/* Software Reset */
#define RESET_ALL             0x01u
#define RESET_CMD             0x02u
#define RESET_DAT             0x04u

/* Clock Control */
#define CLK_INTERNAL_EN       (1u << 0)
#define CLK_INTERNAL_STABLE   (1u << 1)
#define CLK_SD_EN             (1u << 2)

/* Power Control */
#define PWR_ON                (1u << 0)
#define PWR_3V3               (0x7u << 1)
#define PWR_3V0               (0x6u << 1)
#define PWR_1V8               (0x5u << 1)

/* Normal / error interrupt status */
#define INT_CMD_COMPLETE      (1u << 0)
#define INT_XFER_COMPLETE     (1u << 1)
#define INT_BUF_READ_READY    (1u << 5)
#define ERR_CMD_TIMEOUT       (1u << 0)

/* Command register: index<<8 | type<<6 | data<<5 | idxchk<<4 | crcchk<<3 | resp */
#define RESP_NONE             0x0u
#define RESP_136              0x1u
#define RESP_48               0x2u
#define RESP_48_BUSY          0x3u
#define CMD_CRC_CHECK         (1u << 3)
#define CMD_INDEX_CHECK       (1u << 4)
#define CMD_DATA_PRESENT      (1u << 5)

/* Transfer Mode: direction is bit 4, and 1 means card-to-host. */
#define XFER_READ             (1u << 4)
#define SDHCI_BUFFER_DATA     0x20

/* The commands this file issues. CMD1 is the eMMC one and CMD8/ACMD41 the SD
 * ones -- see card_identify() for why both exist and only one is testable. */
#define CMD_GO_IDLE           0u    /* CMD0                      */
#define CMD_SEND_OP_COND_MMC  1u    /* CMD1, eMMC only           */
#define CMD_ALL_SEND_CID      2u    /* CMD2                      */
#define CMD_SEND_RELATIVE_ADDR 3u   /* CMD3                      */
#define CMD_SELECT_CARD       7u    /* CMD7                      */
#define CMD_SEND_IF_COND      8u    /* CMD8, SD only             */
#define CMD_SEND_CSD          9u    /* CMD9                      */
#define CMD_READ_SINGLE      17u    /* CMD17                     */
#define CMD_APP_CMD          55u    /* CMD55, prefixes an ACMD   */
#define ACMD_SEND_OP_COND    41u    /* ACMD41, SD only           */

/* How long to wait for the controller, in polls. Bounded for ata.c's reason: an
 * unbounded wait on hardware that is not going to answer turns "no card" into
 * "hang at boot", which is the failure that cannot be diagnosed from outside. */
#define SDHCI_SPINS           1000000u
/* The op-cond negotiation is a poll loop by design -- the card reports "still
 * busy" until it has powered up -- so it gets its own, larger bound. */
#define SDHCI_OPCOND_TRIES    10000u

/* Present State. CARD_INSERTED is the one that answers "is there storage here";
 * CARD_STABLE says the debounce has settled, so a 1 in INSERTED with a 0 in
 * STABLE is a card still being detected rather than a card that is there. */
#define PSTATE_CARD_INSERTED  (1u << 16)
#define PSTATE_CARD_STABLE    (1u << 17)

/* Capabilities, low word: the fields worth reporting. */
#define CAP_BASE_CLK_SHIFT    8      /* MHz, 8 bits (0 = "ask another way")     */
#define CAP_BASE_CLK_MASK     0xFFu
#define CAP_MAX_BLK_SHIFT     16     /* 0=512, 1=1024, 2=2048 bytes             */
#define CAP_MAX_BLK_MASK      0x3u

/* Host Controller Version, low byte: 0 = 1.00, 1 = 2.00, 2 = 3.00, 3 = 4.00.
 * Anything above 4 is not a revision this specification defines, and is the
 * signature of a BAR that is not a host controller. */
#define VER_SPEC_MASK         0xFFu
#define VER_SPEC_MAX          4u

static uint64_t g_sdhci_bar;      /* 0 when no controller was recognised */
static uint32_t g_sdhci_cards;    /* slots reporting a card present      */
static uint64_t g_sdhci_sectors;  /* capacity of the card that came up   */
static int      g_sdhci_is_hc;    /* block-addressed (HC) vs byte-addressed */

uint64_t sdhci_bar(void)        { return g_sdhci_bar; }
uint32_t sdhci_card_count(void) { return g_sdhci_cards; }
uint64_t sdhci_sectors(void)    { return g_sdhci_sectors; }

static inline uint32_t sdhci_read32(uint64_t bar, uint32_t off) {
    return *(volatile uint32_t *)(uintptr_t)(bar + off);
}
static inline uint16_t sdhci_read16(uint64_t bar, uint32_t off) {
    return *(volatile uint16_t *)(uintptr_t)(bar + off);
}

static inline void sdhci_write32(uint64_t bar, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(uintptr_t)(bar + off) = v;
}
static inline void sdhci_write16(uint64_t bar, uint32_t off, uint16_t v) {
    *(volatile uint16_t *)(uintptr_t)(bar + off) = v;
}
static inline void sdhci_write8(uint64_t bar, uint32_t off, uint8_t v) {
    *(volatile uint8_t *)(uintptr_t)(bar + off) = v;
}
static inline uint8_t sdhci_read8(uint64_t bar, uint32_t off) {
    return *(volatile uint8_t *)(uintptr_t)(bar + off);
}

/* Reset the controller and bring its clock and power up.
 *
 * The order is the specification's and is not interchangeable: reset first
 * (which clears the clock enables), then power, then clock. Enabling the SD
 * clock before the card is powered clocks a dead card, and the card then never
 * leaves idle -- a failure that looks like "no card" rather than like a
 * sequencing mistake. */
static int host_reset(uint64_t bar) {
    sdhci_write8(bar, SDHCI_SOFTWARE_RESET, RESET_ALL);
    for (uint32_t i = 0; i < SDHCI_SPINS; i++)
        if ((sdhci_read8(bar, SDHCI_SOFTWARE_RESET) & RESET_ALL) == 0) goto reset_done;
    return -1;
reset_done:

    /* Voltage from what the controller says it supports, highest first. The
     * capabilities register bits 24..26 are 3.3V, 3.0V, 1.8V. */
    const uint32_t caps = sdhci_read32(bar, SDHCI_CAPABILITIES);
    uint8_t pwr = 0;
    if      (caps & (1u << 24)) pwr = PWR_3V3;
    else if (caps & (1u << 25)) pwr = PWR_3V0;
    else if (caps & (1u << 26)) pwr = PWR_1V8;
    else return -2;                       /* a controller that supports no voltage */
    sdhci_write8(bar, SDHCI_POWER_CONTROL, (uint8_t)(pwr | PWR_ON));

    /* Identification runs at 400 kHz or less, which is a requirement of the card
     * rather than a preference: a card that has not yet been told its bus speed
     * must be clocked slowly enough to answer. The divisor is base/(2*div), and
     * an 8-bit divisor covers every base clock this will meet. */
    const uint32_t base_mhz = (caps >> CAP_BASE_CLK_SHIFT) & CAP_BASE_CLK_MASK;
    uint32_t div = 1;
    if (base_mhz > 0) { while ((base_mhz * 1000u) / (2u * div) > 400u && div < 0x80u) div <<= 1; }

    sdhci_write16(bar, SDHCI_CLOCK_CONTROL, 0);          /* stop before changing */
    sdhci_write16(bar, SDHCI_CLOCK_CONTROL,
                  (uint16_t)(((div & 0xFFu) << 8) | CLK_INTERNAL_EN));
    for (uint32_t i = 0; i < SDHCI_SPINS; i++) {
        if (sdhci_read16(bar, SDHCI_CLOCK_CONTROL) & CLK_INTERNAL_STABLE) goto clk_ok;
    }
    return -3;
clk_ok:
    sdhci_write16(bar, SDHCI_CLOCK_CONTROL,
                  (uint16_t)(sdhci_read16(bar, SDHCI_CLOCK_CONTROL) | CLK_SD_EN));
    sdhci_write8(bar, SDHCI_TIMEOUT_CONTROL, 0x0E);      /* the maximum */

    /* Status bits must be ENABLED to latch, which is separate from being
     * SIGNALLED as an interrupt. This driver polls, so it enables the status and
     * leaves the signal disabled -- enabling the signal would deliver an
     * interrupt nothing is registered to take. */
    sdhci_write16(bar, SDHCI_INT_ENABLE, 0xFFFFu);
    sdhci_write16(bar, SDHCI_ERR_ENABLE, 0xFFFFu);
    sdhci_write16(bar, SDHCI_SIGNAL_ENABLE, 0);
    return 0;
}

/* Issue one command and wait for it to complete. `resp` is one of RESP_*.
 * Returns 0, or -1 on timeout/error, with the response left in the controller's
 * response registers for the caller to read. */
static int sd_command_common(uint64_t bar, uint32_t index, uint32_t arg, uint32_t resp,
                             uint32_t extra_flags, int touch_xfer_mode) {
    /* Both inhibit bits: the command line for every command, and the data line
     * too, because a command that changes card state must not be issued while a
     * previous data transfer is still using it. */
    for (uint32_t i = 0; ; i++) {
        uint32_t ps = sdhci_read32(bar, SDHCI_PRESENT_STATE);
        if ((ps & (PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT)) == 0) break;
        if (i >= SDHCI_SPINS) return -1;
    }

    sdhci_write16(bar, SDHCI_INT_STATUS, 0xFFFFu);   /* write-1-to-clear */
    sdhci_write16(bar, SDHCI_ERR_STATUS, 0xFFFFu);
    sdhci_write32(bar, SDHCI_ARGUMENT, arg);
    /* Only a command WITHOUT a data phase clears the transfer mode. A data
     * command has already had its direction written, and zeroing it here would
     * turn every read into a write of whatever the FIFO held -- which is the
     * kind of mistake that destroys a disk rather than failing a test. */
    if (touch_xfer_mode) sdhci_write16(bar, SDHCI_TRANSFER_MODE, 0);

    uint16_t cmd = (uint16_t)((index << 8) | resp | extra_flags);
    sdhci_write16(bar, SDHCI_COMMAND, cmd);

    for (uint32_t i = 0; ; i++) {
        uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
        uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
        if (err) return -1;                          /* timeout, CRC, index... */
        if (st & INT_CMD_COMPLETE) return 0;
        if (i >= SDHCI_SPINS) return -1;
    }
}

/* A command with no data phase: the transfer mode is cleared. */
static int sd_command(uint64_t bar, uint32_t index, uint32_t arg, uint32_t resp,
                      uint32_t extra_flags) {
    return sd_command_common(bar, index, arg, resp, extra_flags, 1);
}

/* A command whose caller has already programmed the transfer mode. */
static int sd_command_data(uint64_t bar, uint32_t index, uint32_t arg, uint32_t resp,
                           uint32_t extra_flags) {
    return sd_command_common(bar, index, arg, resp, extra_flags, 0);
}

/* Identify the card and learn its capacity.
 *
 * TWO OP-COND PATHS, AND ONLY ONE OF THEM IS TESTABLE HERE. An SD card is told
 * to power up with CMD8 followed by ACMD41 (CMD55 then CMD41); an eMMC device
 * uses CMD1, and an SD card must NOT answer CMD1 at all. QEMU 10.0 has no eMMC
 * device -- only `sd-card`, which speaks SD -- so `make smoke-sdhci-card`
 * exercises the SD branch and the eMMC branch has never run anywhere.
 *
 * That is recorded rather than hidden, and it is why the two branches share
 * everything they can: the reset, the clock, the command mechanism, the response
 * decoding, CMD2/CMD3/CMD9/CMD7 and the CSD arithmetic are common, so the
 * untested delta is one command and its argument rather than a second driver.
 * The first machine to run the CMD1 path will be real hardware.
 */
static int card_identify(uint64_t bar, uint64_t *sectors_out, int *is_mmc_out,
                         int *is_hc_out) {
    if (sd_command(bar, CMD_GO_IDLE, 0, RESP_NONE, 0) != 0) return -1;

    int is_mmc = 0;
    uint32_t ocr = 0;

    /* SD first: CMD8 asks whether the card understands the 2.0 interface
     * condition. A card that does not answer is either pre-2.0 SD or eMMC, and
     * the CMD1 path below tells those apart. 0x1AA is "2.7-3.6V, check pattern
     * 0xAA", and the card echoes it. */
    int sd_v2 = (sd_command(bar, CMD_SEND_IF_COND, 0x1AAu, RESP_48, CMD_CRC_CHECK) == 0);

    for (uint32_t i = 0; i < SDHCI_OPCOND_TRIES; i++) {
        if (sd_command(bar, CMD_APP_CMD, 0, RESP_48, CMD_CRC_CHECK) != 0) { is_mmc = 1; break; }
        /* HCS when the card claimed 2.0: without it a high-capacity card is
         * refused and reports a byte-addressed capacity it does not have. */
        uint32_t arg = 0x00FF8000u | (sd_v2 ? (1u << 30) : 0u);
        if (sd_command(bar, ACMD_SEND_OP_COND, arg, RESP_48, 0) != 0) { is_mmc = 1; break; }
        ocr = sdhci_read32(bar, SDHCI_RESPONSE);
        if (ocr & (1u << 31)) break;          /* card has finished powering up */
    }

    if (is_mmc) {
        /* eMMC. Sector addressing is requested with bit 30, as for SD.
         *
         * UNTESTED ANYWHERE -- see the note above this function. There is no
         * control arm for this branch, deliberately: QEMU has no eMMC device, so
         * an arm that disabled it could never be observed to fail, and a control
         * arm that cannot fail cannot gate. */
        if (sd_command(bar, CMD_GO_IDLE, 0, RESP_NONE, 0) != 0) return -1;
        int ok = 0;
        for (uint32_t i = 0; i < SDHCI_OPCOND_TRIES; i++) {
            if (sd_command(bar, CMD_SEND_OP_COND_MMC, 0x40FF8000u, RESP_48, 0) != 0) return -2;
            ocr = sdhci_read32(bar, SDHCI_RESPONSE);
            if (ocr & (1u << 31)) { ok = 1; break; }
        }
        if (!ok) return -2;
    }

    /* From here the two are the same card to the host. */
    if (sd_command(bar, CMD_ALL_SEND_CID, 0, RESP_136, CMD_CRC_CHECK) != 0) return -3;

    /* CMD3: an SD card REPORTS its address; an eMMC device is TOLD one. Sending
     * a non-zero argument is harmless to SD (which ignores it and answers with
     * its own) and is required by eMMC, so one call serves both. */
    if (sd_command(bar, CMD_SEND_RELATIVE_ADDR, (1u << 16), RESP_48, CMD_CRC_CHECK) != 0) return -4;
    uint32_t rca = is_mmc ? 1u : (sdhci_read32(bar, SDHCI_RESPONSE) >> 16);

    if (sd_command(bar, CMD_SEND_CSD, rca << 16, RESP_136, CMD_CRC_CHECK) != 0) return -5;

    /* THE CSD ARRIVES SHIFTED BY EIGHT BITS, and getting that wrong is why the
     * first version of this reported a 128 MiB card as 30752 MiB.
     *
     * A 136-bit response is stored with the CRC byte DROPPED, so response bit R
     * carries CSD bit R+8. Every field below is therefore addressed at its
     * specification position minus 8, spread over four 32-bit registers:
     *   c1 = resp[63:32], c2 = resp[95:64], c3 = resp[127:96].
     * Writing the spec's own bit numbers here reads correctly and is wrong. */
    uint32_t c1 = sdhci_read32(bar, SDHCI_RESPONSE + 4);
    uint32_t c2 = sdhci_read32(bar, SDHCI_RESPONSE + 8);
    uint32_t c3 = sdhci_read32(bar, SDHCI_RESPONSE + 12);

    /* CSD_STRUCTURE: CSD[127:126] -> resp[119:118] -> c3 bits 23:22 */
    uint32_t csd_ver = (c3 >> 22) & 0x3u;

    uint64_t sectors;
#ifdef SDHCI_CSD_SPEC_BITS
    /* Control arm: the fields read at their SPECIFICATION bit positions, without
     * the eight-bit shift the dropped CRC byte introduces. This is not an
     * invented mistake -- it is the one this driver made, and it reported a
     * 128 MiB card as 30752 MiB: a plausible number, and a wrong one. The gate
     * catches it only by comparing against the size of the image it created. */
    if (csd_ver == 1) {
        uint32_t c_size = ((c1 >> 16) | (c2 << 16)) & 0x3FFFFFu;
        sectors = ((uint64_t)c_size + 1u) * 1024u;
    } else {
        uint32_t c_size      = ((c2 & 0x3FFu) << 2) | (c1 >> 30);
        uint32_t c_size_mult = (c1 >> 15) & 0x7u;
        uint32_t read_bl_len = (c2 >> 16) & 0xFu;
        sectors = (((uint64_t)c_size + 1u) * ((uint64_t)1u << (c_size_mult + 2u))
                   * ((uint64_t)1u << read_bl_len)) / 512u;
    }
#else
    if (csd_ver == 1) {
        /* CSD v2 (SDHC/SDXC and eMMC over 2 GiB): C_SIZE is CSD[69:48] ->
         * resp[61:40] -> c1 bits 29:8. Capacity is (C_SIZE+1) * 512 KiB, which
         * is (C_SIZE+1) * 1024 sectors of 512 bytes. */
        uint32_t c_size = (c1 >> 8) & 0x3FFFFFu;
        sectors = ((uint64_t)c_size + 1u) * 1024u;
    } else {
        /* CSD v1: capacity is (C_SIZE+1) * 2^(C_SIZE_MULT+2) * 2^READ_BL_LEN.
         *   READ_BL_LEN  CSD[83:80] -> resp[75:72] -> c2 bits 11:8
         *   C_SIZE       CSD[73:62] -> resp[65:54] -> c2 bits 1:0 (high two)
         *                                             + c1 bits 31:22 (low ten)
         *   C_SIZE_MULT  CSD[49:47] -> resp[41:39] -> c1 bits 9:7 */
        uint32_t read_bl_len = (c2 >> 8) & 0xFu;
        uint32_t c_size      = ((c2 & 0x3u) << 10) | ((c1 >> 22) & 0x3FFu);
        uint32_t c_size_mult = (c1 >> 7) & 0x7u;
        uint64_t bytes = ((uint64_t)c_size + 1u)
                         * ((uint64_t)1u << (c_size_mult + 2u))
                         * ((uint64_t)1u << read_bl_len);
        sectors = bytes / 512u;
    }
#endif

    if (sd_command(bar, CMD_SELECT_CARD, rca << 16, RESP_48_BUSY, CMD_CRC_CHECK) != 0) return -6;

    *sectors_out = sectors;
    *is_mmc_out  = is_mmc;
    /* OCR bit 30 (CCS) is the ADDRESSING MODE, and it is not cosmetic: a
     * high-capacity card takes a BLOCK number where a standard-capacity card
     * takes a BYTE offset. Get it wrong and every read lands 512x away from
     * where it was meant to -- except block 0, which is address 0 either way and
     * therefore cannot reveal the mistake. */
    *is_hc_out   = (ocr & (1u << 30)) ? 1 : 0;
    return 0;
}

/* Read one 512-byte block into `buf`, by PIO through the buffer data port.
 *
 * PIO AND NOT DMA, DELIBERATELY. A DMA read needs a descriptor table, a physical
 * buffer the controller may reach, and an IOMMU mapping when VT-d is on -- three
 * more things to get wrong, for a speed nobody installing an operating system
 * will notice. The buffer data port is a FIFO the host drains itself, and it is
 * the simplest thing that can be correct.
 *
 * THE ARGUMENT IS AN ADDRESS IN TWO DIFFERENT UNITS. A high-capacity card takes
 * a block number; a standard-capacity card takes a byte offset. Passing the
 * wrong one reads a location 512 times away from the intended -- and block 0
 * cannot show it, because 0 is 0 in both units. */
static int sd_read_block(uint64_t bar, uint64_t lba, void *buf, int is_hc) {
    uint32_t *out = (uint32_t *)buf;

    sdhci_write16(bar, SDHCI_BLOCK_SIZE, 512);
    sdhci_write16(bar, SDHCI_BLOCK_COUNT, 1);

    /* Set the direction BEFORE issuing the command: the controller latches the
     * transfer mode when the command register is written. */
    sdhci_write16(bar, SDHCI_TRANSFER_MODE, XFER_READ);

#ifdef SDHCI_ADDR_MODE_INVERTED
    /* Control arm: the addressing mode inverted. A high-capacity card is given a
     * byte offset and a standard-capacity card a block number, so every read
     * lands 512x from where it should -- EXCEPT block 0, which is address 0 in
     * both units and reads correctly either way. That is precisely why the gate
     * reads a non-zero block. */
    const uint32_t arg = is_hc ? (uint32_t)(lba * 512u) : (uint32_t)lba;
#else
    const uint32_t arg = is_hc ? (uint32_t)lba : (uint32_t)(lba * 512u);
#endif
    if (sd_command_data(bar, CMD_READ_SINGLE, arg,
                        RESP_48, CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT) != 0)
        return -1;

    for (uint32_t i = 0; ; i++) {
        uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
        uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
        if (err) return -2;
        if (st & INT_BUF_READ_READY) break;
        if (i >= SDHCI_SPINS) return -3;
    }

    for (uint32_t i = 0; i < 512u / 4u; i++)
        out[i] = sdhci_read32(bar, SDHCI_BUFFER_DATA);

    for (uint32_t i = 0; ; i++) {
        uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
        uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
        if (err) return -4;
        if (st & INT_XFER_COMPLETE) return 0;
        if (i >= SDHCI_SPINS) return -5;
    }
}

/* The controller, if the machine has one.
 *
 * Class 0x08 subclass 0x05 is "SD Host controller". THE PROG-IF IS NOT TESTED,
 * and that is the difference from ahci.c: there, prog-if 0x01 is what separates
 * an AHCI controller from the same silicon in IDE-compatibility mode, so it must
 * be checked. Here 0x00 and 0x01 both mean SDHCI -- they distinguish "no DMA"
 * from "supports DMA", which is a capability of a controller this probe would
 * drive either way, not a different programming interface. */
static const struct io_device *find_sdhci_controller(uint64_t *index_out) {
    uint32_t n = iodev_total();
    for (uint32_t i = 0; i < n; i++) {
        const struct io_device *d = iodev_get(i);
        if (!d || !d->present) continue;
        if ((d->classcode >> 8) != 0x0805u) continue;   /* class:subclass */
        if (index_out) *index_out = i;
        return d;
    }
    return NULL;
}

/* Called from kernel_main after iodev_init, which populates the table this
 * reads. Reports and returns; nothing else depends on it yet. */
void sdhci_probe(void) {
#ifdef SDHCI_PROBE_ABSENT
    /* The control arm: the probe is compiled out, so a machine WITH an SD host
     * controller says nothing about it -- the state this tree was in before
     * 2026-09-07, and the reason the installer finds no disk on a laptop whose
     * storage is eMMC. See make smoke-sdhci-detect. */
    return;
#else
    uint64_t devindex = 0;
    const struct io_device *d = find_sdhci_controller(&devindex);
    if (!d) {
        print("sdhci: no SD/eMMC host controller\n");
        return;
    }

    /* The register file is in a memory BAR. As in ahci.c, struct io_device does
     * not record which BAR index a region came from, so the highest-based MMIO
     * region is the candidate and the hardware then has to agree. */
    uint64_t bar = 0, bar_len = 0;
    for (uint32_t i = 0; i < d->n_mmio; i++) {
        if (d->mmio[i].base > bar) { bar = d->mmio[i].base; bar_len = d->mmio[i].len; }
    }
    if (bar == 0 || bar_len < 0x100) {
        print("sdhci: controller has no register BAR large enough; ignoring it\n");
        return;
    }

    ensure_ahci_abar_mapped(NULL, bar);   /* two pages: the file is 0x100 bytes */

    const uint16_t ver  = sdhci_read16(bar, SDHCI_HOST_VERSION);
    const uint32_t caps = sdhci_read32(bar, SDHCI_CAPABILITIES);
    const uint32_t ps   = sdhci_read32(bar, SDHCI_PRESENT_STATE);
    const uint32_t spec = (uint32_t)(ver & VER_SPEC_MASK);

    /* VALIDATE BEFORE BELIEVING. An unmapped or powered-down BAR reads as all
     * ones, which would otherwise be reported as a controller with a card in it. */
    if (spec > VER_SPEC_MAX || caps == 0xFFFFFFFFu || caps == 0) {
        print("sdhci: controller at ");
        print_hex(bar);
        print(" did not answer as a host controller (VER=0x");
        print_hex(ver);
        print(" CAP=0x");
        print_hex(caps);
        print("); ignoring it\n");
        return;
    }

    g_sdhci_bar = bar;

    print("sdhci: host controller v");
    print_decimal(spec + 1u);          /* 0 encodes 1.00 */
    print(".0, base clock ");
    print_decimal((caps >> CAP_BASE_CLK_SHIFT) & CAP_BASE_CLK_MASK);
    print(" MHz, max block ");
    switch ((caps >> CAP_MAX_BLK_SHIFT) & CAP_MAX_BLK_MASK) {
        case 0:  print("512");  break;
        case 1:  print("1024"); break;
        case 2:  print("2048"); break;
        default: print("reserved"); break;
    }
    print(" bytes\n");

    /* CARD_STABLE as well as CARD_INSERTED: a card still being debounced reports
     * inserted before the line has settled, and calling that "a card" would be
     * reporting a race as a fact. */
    if ((ps & PSTATE_CARD_INSERTED) && (ps & PSTATE_CARD_STABLE)) {
        g_sdhci_cards = 1;
        print("  [ OK ] sdhci: a card is present and the detect line is stable\n");
    } else if (ps & PSTATE_CARD_INSERTED) {
        print("  sdhci: a card is being detected (not yet stable)\n");
    } else {
        print("  sdhci: the slot is empty\n");
    }

    /* Bring the card up and ask it how big it is. Only attempted when the slot
     * reports a card that is present AND settled: running the identification
     * sequence against a slot mid-debounce would fail for a reason that is not a
     * fault, and report it as one. */
    if (g_sdhci_cards) {
        if (host_reset(bar) != 0) {
            print("  sdhci: the controller would not reset\n");
        } else {
            uint64_t sectors = 0;
            int is_mmc = 0, is_hc = 0;
            int rc = card_identify(bar, &sectors, &is_mmc, &is_hc);
            if (rc == 0) {
                g_sdhci_sectors = sectors;
                g_sdhci_is_hc   = is_hc;
                print("         ");
                print(is_mmc ? "eMMC" : "SD card");
                print(", ");
                print_decimal(sectors / 2048u);      /* 512-byte sectors -> MiB */
                print(" MiB, ");
                print(is_hc ? "block-addressed\n" : "byte-addressed\n");

                /* Read two blocks and report the first eight bytes of each.
                 *
                 * TWO, AND NEITHER OF THEM ONLY BLOCK 0. Block 0 is address 0
                 * whether the card is block- or byte-addressed, so a read of it
                 * alone cannot distinguish the two and would pass with the
                 * addressing mode inverted. The second block is far enough out
                 * that the wrong unit lands somewhere else entirely. */
                static uint8_t blk[512];
                struct { uint64_t lba; const char *label; } probes[2] = {
                    { 0,   "block0" },
                    { 100, "block100" },
                };
                for (int p = 0; p < 2; p++) {
                    int brc = sd_read_block(bar, probes[p].lba, blk, is_hc);
                    print("         sdhci-read ");
                    print(probes[p].label);
                    if (brc != 0) {
                        print(": failed (");
                        print_decimal((uint64_t)(-brc));
                        print(")\n");
                        continue;
                    }
                    print(": ");
                    for (int i = 0; i < 8; i++) {
                        char c = (char)blk[i];
                        print_char((c >= 32 && c < 127) ? c : '.');
                    }
                    print("\n");
                }
            } else {
                print("  sdhci: the card did not come up (");
                print_decimal((uint64_t)(-rc));
                print(")\n");
            }
        }
    }

    print("sdhci: ");
    print_decimal(g_sdhci_cards);
    print(" card(s) present; no block driver yet, so none is mountable\n");
#endif /* SDHCI_PROBE_ABSENT */
}
