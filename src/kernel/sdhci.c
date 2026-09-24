/* sdhci.c -- find the SD/eMMC host controller, and say what is in it.
 *
 * WHY THIS EXISTS, AND WHY IT IS THE ONE THAT MATTERS FOR A LAPTOP.
 *
 * This tree has two storage drivers: `ata.c` (legacy IDE PIO) and, since
 * 2026-09-07, enough of `ahci.c` to make a SATA disk identify itself. Neither
 * reaches the machine this is for. A budget laptop's internal storage is
 * frequently soldered eMMC behind an SD host controller -- a third controller
 * type, sharing nothing with either of the others -- so `horus.iso` boots on that
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

/* Transfer Mode: direction is bit 4, and 1 means card-to-host. Zero is
 * host-to-card, i.e. a WRITE -- so a transfer whose direction was never set
 * writes. See sd_command_data() on why that is a separate function. */
#define XFER_READ             (1u << 4)
#define XFER_WRITE            0u
/* Transfer Mode, for a MULTI-block transfer (SDHCI 3.00 section 2.2.5).
 * Block Count Enable makes the controller honour SDHCI_BLOCK_COUNT, Multi
 * selects the multi-block form, and Auto CMD12 has the controller send the
 * STOP_TRANSMISSION the card needs at the end of an open-ended transfer. Doing
 * CMD12 in the controller rather than by hand is not laziness: the stop has to
 * land immediately after the last block, and a stop issued late leaves the card
 * still streaming into a FIFO nobody is draining. */
#define XFER_BLK_COUNT_EN     (1u << 1)
#define XFER_AUTO_CMD12       (1u << 2)
#define XFER_MULTI            (1u << 5)
#define INT_BUF_WRITE_READY   (1u << 4)
#define SDHCI_BUFFER_DATA     0x20

/* The commands this file issues. CMD1 is the eMMC one and CMD8/ACMD41 the SD
 * ones -- see card_identify() for why both exist and only one is testable. */
#define CMD_GO_IDLE           0u    /* CMD0                      */
#define CMD_SEND_OP_COND_MMC  1u    /* CMD1, eMMC only           */
#define CMD_ALL_SEND_CID      2u    /* CMD2                      */
#define CMD_SEND_RELATIVE_ADDR 3u   /* CMD3                      */
#define CMD_SELECT_CARD       7u    /* CMD7                      */
#define CMD_SEND_IF_COND      8u    /* CMD8, SD only             */
#define CMD_MMC_SEND_EXT_CSD  8u    /* CMD8 on eMMC: a 512-byte data read, a
                                     * different command at the same index */
#define CMD_SEND_CSD          9u    /* CMD9                      */
#define CMD_READ_SINGLE      17u    /* CMD17                     */
#define CMD_WRITE_SINGLE     24u    /* CMD24                     */
#define CMD_READ_MULTI       18u    /* CMD18, many blocks in one command */
#define CMD_WRITE_MULTI      25u    /* CMD25, many blocks in one command */
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

/* Forward declarations: the block operations below are defined near the
 * accessors, above the PIO implementations they call. */
static int sd_read_block(uint64_t bar, uint64_t lba, void *buf, int is_hc);
static int sd_rw_blocks(uint64_t bar, uint64_t lba, void *buf, uint32_t count,
                        int is_hc, int is_write, int repeat_one);
static int sd_pio_read512(uint64_t bar, uint32_t index, uint32_t arg, void *buf);
static int sd_write_block(uint64_t bar, uint64_t lba, const void *buf, int is_hc);
static int sd_flush(uint64_t bar);

static uint64_t g_sdhci_bar;      /* 0 when no controller was recognised */
/* The identification clock host_reset chose, in kHz, reported by sdhci_probe so
 * a gate can hold it to the 400 kHz ceiling (smoke-sdhci-emmc). */
static uint32_t g_sdhci_id_khz;
static uint32_t g_sdhci_cards;    /* slots reporting a card present      */
static uint64_t g_sdhci_sectors;  /* capacity of the card that came up   */
static int      g_sdhci_is_hc;    /* block-addressed (HC) vs byte-addressed */

uint64_t sdhci_bar(void)        { return g_sdhci_bar; }
uint32_t sdhci_card_count(void) { return g_sdhci_cards; }
uint64_t sdhci_sectors(void)    { return g_sdhci_sectors; }

/* ONE COMMAND ON THE CONTROLLER AT A TIME, ACROSS CPUs.
 *
 * An SD host controller runs one command and one data transfer, and its
 * registers (argument, transfer mode, block count, the buffer port) are a single
 * set. Until 2026-09-24 nothing here serialised them, and on a machine with two
 * cores two tasks reached the card at once: the IdeaPad 1 14IGL05's trace shows
 * a CMD25 and a CMD18 failing in the same microsecond, their SDTRACE lines
 * interleaved character by character, and every install failing at whichever
 * read landed inside another CPU's write. Every QEMU gate that touches SD boots
 * one CPU ("smp: uniprocessor"), which is why none of them could see it, and why
 * three earlier diagnoses (a busy card, a stranded transfer) each explained part
 * of the symptom and none of the cause.
 *
 * The same shape as ata_lock in src/kernel/ata.c and for the same reason a
 * DEDICATED lock rather than storage_lock: the crypto layer holds storage_lock
 * on paths that reach the block device, and a non-recursive spinlock taken
 * twice is a hang. Held for one operation, including its abort and retry, so a
 * recovery is never interleaved with another CPU's command either. Declared in
 * .github/lock-order.yml (S88). */
static spinlock_t sdhci_lock = { 0 };
#ifdef SDHCI_NO_LOCK
/* CONTROL ARM -- never ship. The driver as it was before 2026-09-24: nothing
 * serialises the controller, so two CPUs' block operations run on it at once.
 * See make smoke-installer-sd-smp-control. */
#define spin_lock(l)   ((void)(l))
#define spin_unlock(l) ((void)(l))
#endif

/* The block operations, for storage.c's block_device.
 *
 * They refuse when no card came up rather than reaching into a zero BAR, and
 * they BOUND THE BLOCK against the capacity the card itself reported -- a block
 * device may not accept a block it has no medium for (S64), and the card's own
 * CSD is the only statement of its extent this kernel has. */
int sdhci_bd_read(uint64_t lba, void *buf) {
    if (!g_sdhci_bar || !g_sdhci_sectors) return -1;
    if (lba >= g_sdhci_sectors) return -1;
    spin_lock(&sdhci_lock);
    int rc = sd_read_block(g_sdhci_bar, lba, buf, g_sdhci_is_hc);
    spin_unlock(&sdhci_lock);
    return rc;
}

int sdhci_bd_write(uint64_t lba, const void *buf) {
    if (!g_sdhci_bar || !g_sdhci_sectors) return -1;
    if (lba >= g_sdhci_sectors) return -1;
    spin_lock(&sdhci_lock);
    int rc = sd_write_block(g_sdhci_bar, lba, buf, g_sdhci_is_hc);
    spin_unlock(&sdhci_lock);
    return rc;
}

/* A RUN OF CONTIGUOUS SECTORS IN ONE COMMAND. Bounded against the card's own
 * reported capacity exactly as the single-sector pair above is, and at BOTH
 * ends: a run is refused if its LAST sector is past the medium, because a
 * partial transfer that stops at the edge would report success for blocks that
 * were never written (S64). */
#ifdef SDHCI_HW_TRACE
/* DIAGNOSTIC (the 2026-09-24 laptop lag): how many block transfers an operation
 * costs and how long they take. Every 8 reads it prints how many timer ticks
 * (10 ms each) those 64 took, and the running totals, so an `ls` on the machine
 * shows up in the kernel log as a count and a rate. */
static uint32_t sdtrace_io_reads, sdtrace_io_writes, sdtrace_io_t0;
static void sdtrace_io(int is_write) {
    if (is_write) { sdtrace_io_writes++; return; }
    if (sdtrace_io_reads++ % 8u == 0u) { sdtrace_io_t0 = get_system_ticks(); return; }
    if (sdtrace_io_reads % 8u == 0u) {
        print("SDTRACE   io: 8 reads in ");
        print_decimal(get_system_ticks() - sdtrace_io_t0);
        print(" ticks; "); print_decimal(sdtrace_io_reads); print(" reads, ");
        print_decimal(sdtrace_io_writes); print(" writes so far\n");
    }
}
#else
#define sdtrace_io(w) ((void)0)
#endif

int sdhci_bd_rw_run(uint64_t lba, void *buf, uint32_t count, int is_write) {
    if (!g_sdhci_bar || !g_sdhci_sectors) return -1;
    if (count == 0) return 0;
    if (lba >= g_sdhci_sectors) return -1;
    if ((uint64_t)count > g_sdhci_sectors - lba) return -1;
    spin_lock(&sdhci_lock);
    int rc = sd_rw_blocks(g_sdhci_bar, lba, buf, count, g_sdhci_is_hc, is_write, 0);
    sdtrace_io(is_write);
    spin_unlock(&sdhci_lock);
    return rc;
}

/* Write ONE 512-byte sector to `count` consecutive positions, in as few commands
 * as the block-count register allows. Bounded against the medium at both ends
 * exactly as the run above is. */
int sdhci_bd_fill_run(uint64_t lba, const void *sector, uint64_t count) {
    if (!g_sdhci_bar || !g_sdhci_sectors) return -1;
    if (count == 0) return 0;
    if (lba >= g_sdhci_sectors) return -1;
    if (count > g_sdhci_sectors - lba) return -1;
    while (count) {
        uint32_t n = count > 0xFFFFu ? 0xFFFFu : (uint32_t)count;
        /* Per command, not per run: the controller needs exclusivity for one
         * transfer, and a format's run is minutes long on a slow card, which is
         * too long to hold every other CPU's storage off. */
        spin_lock(&sdhci_lock);
        int rc = sd_rw_blocks(g_sdhci_bar, lba, (void *)(uintptr_t)sector, n,
                              g_sdhci_is_hc, 1, 1);
        spin_unlock(&sdhci_lock);
        if (rc != 0) return -1;
        lba += n; count -= n;
    }
    return 0;
}

int sdhci_bd_flush(void) {
    if (!g_sdhci_bar) return -1;
    spin_lock(&sdhci_lock);
    int rc = sd_flush(g_sdhci_bar);
    spin_unlock(&sdhci_lock);
    return rc;
}

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

#ifdef SDHCI_HW_TRACE
/* Hex, fixed width, for the SDTRACE lines. It lives up here rather than beside
 * the rest of the trace code near sdhci_probe() because sd_cmd_failed() below
 * reports through it, and that is called from the command path. */
static void sdtrace_hx(uint32_t v, int digits) {
    static const char hex[] = "0123456789abcdef";
    for (int sh = (digits - 1) * 4; sh >= 0; sh -= 4)
        print_char(hex[(v >> sh) & 0xF]);
}

/* Name the command that failed and what the controller said about it.
 *
 * The shipped probe reports one line per STAGE ("the card did not come up"),
 * which is the right amount of noise for a machine that is working. It is not
 * enough to diagnose one that is not: "which command, and what did the error
 * register say" is the whole question, and on a laptop with no serial cable the
 * screen is the only place to ask it. Under the instrument every failed command
 * answers; without it this compiles away entirely. */
static void sd_cmd_failed(uint64_t bar, uint32_t index, const char *why) {
    print("SDTRACE   CMD");
    print_decimal(index);
    print(" ");
    print(why);
    print(" err=");  sdtrace_hx(sdhci_read16(bar, SDHCI_ERR_STATUS), 4);
    print(" int=");  sdtrace_hx(sdhci_read16(bar, SDHCI_INT_STATUS), 4);
    print(" ps=");   sdtrace_hx(sdhci_read32(bar, SDHCI_PRESENT_STATE), 8);
    print("\n");
}

/* Name the DATA-PHASE step of a multi-block transfer that failed.
 *
 * sd_cmd_failed covers the command; it says nothing once the command has been
 * accepted, and every failure after that point in sd_rw_blocks returned a bare
 * code. That is the gap a laptop fell into on 2026-09-24: the installer's first
 * read after the format (the key-slot region, for SYS_PASSWD) failed with the
 * installer's rc=-32, and a trace build would have printed nothing at all.
 * `stage` is which wait gave up (the per-block buffer-ready wait, or the final
 * transfer-complete), `b` how many blocks of the run had already moved. */
static void sd_rw_failed(uint64_t bar, const char *stage, int is_write,
                         uint64_t lba, uint32_t count, uint32_t b) {
    print("SDTRACE   ");
    print(is_write ? "WRITE" : "READ");
    print(" ");
    print(stage);
    print(" lba=");  sdtrace_hx((uint32_t)lba, 8);
    print(" n=");    print_decimal(count);
    print(" at=");   print_decimal(b);
    print(" err=");  sdtrace_hx(sdhci_read16(bar, SDHCI_ERR_STATUS), 4);
    print(" int=");  sdtrace_hx(sdhci_read16(bar, SDHCI_INT_STATUS), 4);
    print(" ps=");   sdtrace_hx(sdhci_read32(bar, SDHCI_PRESENT_STATE), 8);
    print("\n");
}
#else
#define sd_cmd_failed(bar, index, why) ((void)0)
#define sd_rw_failed(bar, stage, is_write, lba, count, b) ((void)0)
#endif

/* Put the command line, and optionally the data line, back into a state where
 * the next command can be issued.
 *
 * A FAILED COMMAND LEAVES THE LINE INHIBITED, AND THE NEXT COMMAND THEN FAILS
 * FOR A REASON THAT IS NOT ITS OWN. SD Host Controller specification 3.00
 * section 3.10.1: when a command error is raised the host driver sets Software
 * Reset For CMD Line and waits for the bit to clear; until it does, Command
 * Inhibit (CMD) in the present state register stays set and every later command
 * times out against it. A command that had a data phase, or a busy response
 * that holds DAT low, needs Software Reset For DAT Line as well.
 *
 * NOTHING IN THIS DRIVER DID THAT UNTIL 2026-09-22, and no emulated gate could
 * have noticed: QEMU's `sd-card` and `emmc` models drop the inhibit by
 * themselves, so a missing recovery is invisible under every gate this tree
 * runs. Real silicon does not. RESET_CMD and RESET_DAT were defined from the
 * first version of this file and never used, which is the shape of a step that
 * was understood and then not written.
 *
 * Bounded like every other wait here, for ata.c's reason: a controller that
 * will not clear its own reset bit must not turn a dead card into a hang. */
static void sd_line_recover(uint64_t bar, int also_dat) {
    const uint8_t bits = (uint8_t)(RESET_CMD | (also_dat ? RESET_DAT : 0u));
    sdhci_write8(bar, SDHCI_SOFTWARE_RESET, bits);
    for (uint32_t i = 0; i < SDHCI_SPINS; i++)
        if ((sdhci_read8(bar, SDHCI_SOFTWARE_RESET) & bits) == 0) break;
    /* Clear what caused this too. A latched error left behind would be read by
     * the next command's own error check and reported as its failure. */
    sdhci_write16(bar, SDHCI_INT_STATUS, 0xFFFFu);
    sdhci_write16(bar, SDHCI_ERR_STATUS, 0xFFFFu);
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
     * must be clocked slowly enough to answer. SDCLK is base / (2 * N).
     *
     * THE DIVIDER DEPENDS ON THE SPEC VERSION, and assuming 2.00 was wrong for
     * the first real controller this met. A 2.00 host takes an 8-bit N that must
     * be a power of two, at most 0x80, so its slowest clock is base / 256. A
     * 3.00 host takes a 10-bit N (bits 15:8 low, 7:6 high) of any value. The
     * IdeaPad's controller is 3.00 with a 200 MHz base clock: the 2.00 rule
     * bottoms out at 781 kHz, nearly twice the ceiling, where N = 250 gives
     * exactly 400 kHz. SDHCI_DIV_V2_ONLY=1 restores the 2.00-only rule. */
    const uint32_t base_khz = ((caps >> CAP_BASE_CLK_SHIFT) & CAP_BASE_CLK_MASK) * 1000u;
    const uint32_t spec = (uint32_t)(sdhci_read16(bar, SDHCI_HOST_VERSION) & VER_SPEC_MASK);
    uint32_t div = 1;
    uint16_t clk_bits;
#ifndef SDHCI_DIV_V2_ONLY
    if (spec >= 2u) {                              /* 3.00 or later */
        if (base_khz > 0) div = (base_khz + 799u) / 800u;   /* ceil(base / 800 kHz) */
        if (div > 0x3FFu) div = 0x3FFu;
        clk_bits = (uint16_t)(((div & 0xFFu) << 8) | (((div >> 8) & 0x3u) << 6));
    } else
#endif
    {
        if (base_khz > 0) { while (base_khz / (2u * div) > 400u && div < 0x80u) div <<= 1; }
        clk_bits = (uint16_t)((div & 0xFFu) << 8);
    }
    g_sdhci_id_khz = base_khz ? base_khz / (2u * div) : 0;
    (void)spec;

    sdhci_write16(bar, SDHCI_CLOCK_CONTROL, 0);          /* stop before changing */
    sdhci_write16(bar, SDHCI_CLOCK_CONTROL, (uint16_t)(clk_bits | CLK_INTERNAL_EN));
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
    /* Whether a failure here has to reset the DATA line as well as the command
     * line: a command with a data phase, or one whose response signals busy by
     * holding DAT low. Both leave the data line inhibited when they go wrong. */
    const int uses_dat = ((extra_flags & CMD_DATA_PRESENT) != 0) || (resp == RESP_48_BUSY);

    /* Both inhibit bits: the command line for every command, and the data line
     * too, because a command that changes card state must not be issued while a
     * previous data transfer is still using it. */
    for (uint32_t i = 0; ; i++) {
        uint32_t ps = sdhci_read32(bar, SDHCI_PRESENT_STATE);
        if ((ps & (PSTATE_CMD_INHIBIT | PSTATE_DAT_INHIBIT)) == 0) {
#ifdef SDHCI_HW_TRACE
            /* A NEAR MISS IS EVIDENCE TOO. How long the card held the line
             * before this command could go, whenever that is more than an
             * eighth of the bound: a busy card after a long write run is the
             * state no emulator produces, and this says how close it came. */
            if (i > SDHCI_SPINS / 8) {
                print("SDTRACE   CMD"); print_decimal(index);
                print(" waited "); print_decimal(i); print(" spins for the line\n");
            }
#endif
            break;
        }
        if (i >= SDHCI_SPINS) {
            /* Still inhibited from something earlier. Reset BOTH lines, not the
             * one this command would have used: whatever is holding the bus is
             * not this command's doing, so this is the last chance to clear it
             * before every remaining command inherits the same failure. */
            sd_cmd_failed(bar, index, "line still inhibited");
            sd_line_recover(bar, 1);
            return -1;
        }
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
        if (err) {                                   /* timeout, CRC, index... */
            sd_cmd_failed(bar, index, "error");
            sd_line_recover(bar, uses_dat);
            return -1;
        }
        if (st & INT_CMD_COMPLETE) return 0;
        if (i >= SDHCI_SPINS) {
            /* No error and no completion either: the controller never answered.
             * The line is reset all the same, because a command that was
             * accepted and never completed leaves the inhibit set exactly as a
             * failed one does. */
            sd_cmd_failed(bar, index, "no completion");
            sd_line_recover(bar, uses_dat);
            return -1;
        }
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
 * TWO OP-COND PATHS. An SD card is told to power up with CMD8 followed by
 * ACMD41 (CMD55 then CMD41); an eMMC device uses CMD1, and an SD card must NOT
 * answer CMD1 at all. `make smoke-sdhci-detect` exercises the SD branch on
 * QEMU's `sd-card`. The eMMC branch first ran on 2026-09-22, under QEMU 11's
 * `emmc` device (QEMU 10.0, which CI and this note were written against, has
 * none); `make smoke-sdhci-emmc` drives it where the host QEMU has the device.
 * The branches share the reset, the clock, the command mechanism, the response
 * decoding and CMD2/CMD3/CMD9/CMD7; eMMC adds CMD1 and, over 2 GiB, the
 * extended CSD read for its capacity.
 */
static int card_identify(uint64_t bar, uint64_t *sectors_out, int *is_mmc_out,
                         int *is_hc_out) {
    if (sd_command(bar, CMD_GO_IDLE, 0, RESP_NONE, 0) != 0) return -1;

    int is_mmc = 0;
    uint32_t ocr = 0;

    /* SD first: CMD8 asks whether the card understands the 2.0 interface
     * condition. A card that does not answer is either pre-2.0 SD or eMMC, and
     * the CMD1 path below tells those apart. 0x1AA is "2.7-3.6V, check pattern
     * 0xAA", and the card echoes it.
     *
     * THE ANSWER IS BELIEVED ONLY IF IT IS SD'S, and "the command completed" is
     * not that answer. Index 8 is SEND_IF_COND on SD and SEND_EXT_CSD on eMMC,
     * two different commands at one number, and the eMMC one is a 512-byte data
     * read. Asking for it here, with no data phase programmed, gets a response
     * from an eMMC device that then starts sending on DAT with nobody draining
     * it: the data line stays inhibited and every later command fails against
     * it, which is why an IdeaPad 1 14IGL05 reported "the card did not come up"
     * with the device present and answering.
     *
     * The specification's own test is the echo, so that is the test used: an SD
     * 2.0 card returns the check pattern and voltage range it was given in R7.
     * Anything else, including a completed command that echoes something other
     * than 0x1AA, is not an SD 2.0 card.
     *
     * Then both lines are put back regardless of the outcome. This is the one
     * command in the sequence that can leave a data phase dangling behind a
     * response that looked like a success, so it is the one place recovering
     * after a FAILURE is not enough. */
    int sd_v2 = 0;
    if (sd_command(bar, CMD_SEND_IF_COND, 0x1AAu, RESP_48, CMD_CRC_CHECK) == 0)
        sd_v2 = ((sdhci_read32(bar, SDHCI_RESPONSE) & 0xFFFu) == 0x1AAu);
    sd_line_recover(bar, 1);

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
        /* eMMC. Sector addressing is requested with bit 30, as for SD. Run
         * under QEMU 11's `emmc` device; see the note above this function. */
        if (sd_command(bar, CMD_GO_IDLE, 0, RESP_NONE, 0) != 0) return -8;
        /* The voltage window offered: 2.7-3.6 V always, and 1.70-1.95 V (OCR bit
         * 7) when the host can supply it. A device whose range the argument
         * misses goes INACTIVE and answers nothing until power-cycled, and the
         * IdeaPad's controller reports 1.8 V as its only supported voltage. */
        const uint32_t mmc_ocr = 0x40FF8000u |
            ((sdhci_read32(bar, SDHCI_CAPABILITIES) & (1u << 26)) ? (1u << 7) : 0u);
        int ok = 0;
        for (uint32_t i = 0; i < SDHCI_OPCOND_TRIES; i++) {
            if (sd_command(bar, CMD_SEND_OP_COND_MMC, mmc_ocr, RESP_48, 0) != 0) return -2;
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

    /* AN eMMC OVER 2 GiB DOES NOT STATE ITS SIZE IN THE CSD. A sector-mode device
     * (OCR bit 30) sets C_SIZE to 0xFFF, a placeholder that decodes to about
     * 1 GiB, and puts the real count in EXT_CSD SEC_COUNT, bytes 212..215,
     * little-endian, in 512-byte sectors (JEDEC JESD84). The first run of this
     * branch, under QEMU 11 on 2026-09-22, reported a 64 GiB device as
     * 1024 MiB. A failed or zero read is an error, not a reason to fall back on a
     * number known to be wrong. SDHCI_EMMC_CSD_ONLY=1 restores the placeholder
     * for the control arm. */
#ifndef SDHCI_EMMC_CSD_ONLY
    if (is_mmc && (ocr & (1u << 30))) {
        static uint8_t ext_csd[512];
        if (sd_pio_read512(bar, CMD_MMC_SEND_EXT_CSD, 0, ext_csd) != 0) return -7;
        uint32_t sec = (uint32_t)ext_csd[212] | ((uint32_t)ext_csd[213] << 8) |
                       ((uint32_t)ext_csd[214] << 16) | ((uint32_t)ext_csd[215] << 24);
        if (sec == 0) return -7;
        sectors = sec;
    }
#endif

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
    return sd_pio_read512(bar, CMD_READ_SINGLE, arg, buf);
}

/* One 512-byte data read by PIO: CMD17 for a block, or CMD8 on eMMC for the
 * extended CSD, which is a data transfer of exactly the same shape. */
static int sd_pio_read512(uint64_t bar, uint32_t index, uint32_t arg, void *buf) {
    uint32_t *out = (uint32_t *)buf;

    sdhci_write16(bar, SDHCI_BLOCK_SIZE, 512);
    sdhci_write16(bar, SDHCI_BLOCK_COUNT, 1);

    /* Set the direction BEFORE issuing the command: the controller latches the
     * transfer mode when the command register is written. */
    sdhci_write16(bar, SDHCI_TRANSFER_MODE, XFER_READ);

    if (sd_command_data(bar, index, arg,
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

/* Move `count` contiguous 512-byte blocks in ONE command.
 *
 * WHY THIS EXISTS, WITH THE ARITHMETIC. A filesystem block is 4096 bytes and a
 * card block is 512, so every block used to be eight CMD24s, each with its own
 * command round trip and its own wait for the card to leave programming state.
 * Formatting a volume clears a crypto metadata region of one 32-byte entry per
 * block: on a 16 GiB volume that is 32,768 blocks, so 262,144 single-block
 * writes before any of the operator's data exists. On a laptop's eMMC that was
 * measured as a format still running after ten minutes and reported as a hang
 * (2026-09-23). It was not hung.
 *
 * CMD18 and CMD25 carry many blocks under one command, so the same bytes and
 * the same cryptography cost a fraction of the round trips. NOTHING ABOUT WHAT
 * IS WRITTEN CHANGES: this is the transport, not the format.
 *
 * THE BUFFER-READY BIT MUST BE CLEARED BETWEEN BLOCKS. It is write-1-to-clear
 * and the controller raises it once per block; a loop that waits on it without
 * clearing sees the FIRST block's assertion every time and races ahead of the
 * card, writing block two into a FIFO that has not drained. sd_command_common
 * clears the status once, at the command, which is enough for a single block
 * and is exactly what is not enough here.
 *
 * COUNT IS BOUNDED BY THE 16-BIT BLOCK COUNT REGISTER, and callers pass small
 * runs, so the bound is checked rather than assumed. */
static int sd_rw_blocks(uint64_t bar, uint64_t lba, void *buf, uint32_t count,
                        int is_hc, int is_write, int repeat_one) {
    if (count == 0) return 0;
    if (count > 0xFFFFu) return -1;

    uint32_t *p = (uint32_t *)buf;
    const uint16_t ready = is_write ? INT_BUF_WRITE_READY : INT_BUF_READ_READY;

    sdhci_write16(bar, SDHCI_BLOCK_SIZE, 512);
    sdhci_write16(bar, SDHCI_BLOCK_COUNT, (uint16_t)count);

    uint16_t mode = (is_write ? XFER_WRITE : XFER_READ);
    if (count > 1) mode |= XFER_MULTI | XFER_BLK_COUNT_EN | XFER_AUTO_CMD12;
    sdhci_write16(bar, SDHCI_TRANSFER_MODE, mode);

    const uint32_t index = count > 1 ? (is_write ? CMD_WRITE_MULTI : CMD_READ_MULTI)
                                     : (is_write ? CMD_WRITE_SINGLE : CMD_READ_SINGLE);
    const uint32_t arg = is_hc ? (uint32_t)lba : (uint32_t)(lba * 512u);
    if (sd_command_data(bar, index, arg, RESP_48,
                        CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT) != 0)
        return -1;

    for (uint32_t b = 0; b < count; b++) {
        for (uint32_t i = 0; ; i++) {
            uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
            uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
            if (err) { sd_rw_failed(bar, "block error", is_write, lba, count, b); return -2; }
            if (st & ready) break;
            if (i >= SDHCI_SPINS) {
                sd_rw_failed(bar, "block not ready", is_write, lba, count, b);
                return -3;
            }
        }
        /* Cleared BEFORE the data moves, so the next block's assertion is this
         * loop's own and not the one just consumed. */
        sdhci_write16(bar, SDHCI_INT_STATUS, ready);

        if (is_write)
            for (uint32_t i = 0; i < 512u / 4u; i++)
                sdhci_write32(bar, SDHCI_BUFFER_DATA, p[i]);
        else
            for (uint32_t i = 0; i < 512u / 4u; i++)
                p[i] = sdhci_read32(bar, SDHCI_BUFFER_DATA);
        /* REPEAT MODE DOES NOT ADVANCE, and that is the whole trick. Clearing
         * the metadata region writes the SAME all-zero sector to every block in
         * it, so the controller can be fed from one 512-byte buffer for the
         * length of the run. A 128 MiB region is then a handful of commands
         * instead of a quarter of a million, and it costs no memory at all: the
         * alternative was a multi-block buffer in .bss, on a budget that is
         * already exactly full. */
        if (!repeat_one) p += 512u / 4u;
    }

    for (uint32_t i = 0; ; i++) {
        uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
        uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
        if (err) { sd_rw_failed(bar, "completion error", is_write, lba, count, count); return -4; }
        if (st & INT_XFER_COMPLETE) return 0;
        if (i >= SDHCI_SPINS) {
            sd_rw_failed(bar, "no completion", is_write, lba, count, count);
            return -5;
        }
    }
}

/* Write one 512-byte block from `buf`, by PIO. The mirror of sd_read_block, and
 * the same addressing rule applies: high-capacity cards take a block number,
 * standard-capacity a byte offset.
 *
 * NOTHING IN A SHIPPED BOOT CALLS THIS. The probe below exercises it only under
 * SDHCI_WRITE_SELFTEST, and that is a safety property rather than a testing
 * convenience: a boot-time write round-trip would corrupt whatever is on the
 * card of the machine it booted, which on a laptop is the operator's own
 * storage. A read is safe to do unasked; a write is not. */
static int sd_write_block(uint64_t bar, uint64_t lba, const void *buf, int is_hc) {
    const uint32_t *in = (const uint32_t *)buf;

    sdhci_write16(bar, SDHCI_BLOCK_SIZE, 512);
    sdhci_write16(bar, SDHCI_BLOCK_COUNT, 1);
    sdhci_write16(bar, SDHCI_TRANSFER_MODE, XFER_WRITE);

    const uint32_t arg = is_hc ? (uint32_t)lba : (uint32_t)(lba * 512u);
    if (sd_command_data(bar, CMD_WRITE_SINGLE, arg,
                        RESP_48, CMD_CRC_CHECK | CMD_INDEX_CHECK | CMD_DATA_PRESENT) != 0)
        return -1;

    for (uint32_t i = 0; ; i++) {
        uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
        uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
        if (err) return -2;
        if (st & INT_BUF_WRITE_READY) break;
        if (i >= SDHCI_SPINS) return -3;
    }

    for (uint32_t i = 0; i < 512u / 4u; i++)
        sdhci_write32(bar, SDHCI_BUFFER_DATA, in[i]);

    /* Transfer Complete is the card acknowledging the DATA. It is not a
     * durability barrier: the card may still be programming internally, which is
     * what the busy state after this covers, and what sd_flush waits out. */
    for (uint32_t i = 0; ; i++) {
        uint16_t st  = sdhci_read16(bar, SDHCI_INT_STATUS);
        uint16_t err = sdhci_read16(bar, SDHCI_ERR_STATUS);
        if (err) return -4;
        if (st & INT_XFER_COMPLETE) return 0;
        if (i >= SDHCI_SPINS) return -5;
    }
}

/* Wait until the card has finished programming everything already accepted.
 *
 * A card signals internal programming by holding DAT0 low, which the controller
 * reports as the data line being inhibited. Waiting for that to clear is what
 * "the write is on stable media" means for this device -- there is no separate
 * cache-flush command in the SD protocol the way ATA has one.
 *
 * It returns a STATUS rather than void: raw_block_flush treats a backend that
 * cannot flush as a failure rather than a no-op, deliberately, so that a new
 * block device cannot silently inherit "durability not implemented" while the
 * journal keeps advertising crash atomicity. */
static int sd_flush(uint64_t bar) {
#ifdef SDHCI_WRITE_NO_FLUSH
    /* CONTROL ARM -- never ship. The wait is gone, so a write reports success
     * while the card is still programming: a power cut in that window loses data
     * the journal was told was durable.
     *
     * IT WAS DEFINED AND UNREAD UNTIL 2026-09-10. The Makefile added
     * -DSDHCI_WRITE_NO_FLUSH and nothing tested it, so the arm built an
     * identical kernel -- and the measurement recorded against it ("QEMU's
     * sd-card completes a write synchronously, so both checks pass with the
     * flush removed") was taken on a build where the flush was still there. */
    (void)bar;
    return 0;
#else
    for (uint32_t i = 0; ; i++) {
        if ((sdhci_read32(bar, SDHCI_PRESENT_STATE) & PSTATE_DAT_INHIBIT) == 0) return 0;
        if (i >= SDHCI_SPINS) {
            sd_rw_failed(bar, "flush: card still busy", 1, 0, 0, 0);
            return -1;
        }
    }
#endif
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

#ifdef SDHCI_HW_TRACE
/* See the SDHCI_HW_TRACE note in pci.c. One step: config state, then VER, CAP
 * and PRESENT_STATE read from EVERY memory region the function declares, so a
 * wrong-BAR choice shows up as the other region answering. sdtrace_hx() is
 * defined above the command path, which reports through it too. */
static void sdhci_trace_step(const struct io_device *d, const char *when) {
    iodev_trace_config(d, when);
    for (uint32_t i = 0; i < d->n_mmio; i++) {
        uint64_t b = d->mmio[i].base;
        if (b == 0 || d->mmio[i].len < 0x100) continue;
        /* Through the ordinary four-page storage-register list, so the
         * instrument adds no code to ring 0's core (paging.c). Each region
         * costs two pages there; the one controller measured (two adjacent
         * 4 KiB BARs) needs three. A controller with more BARs could fill the
         * list, and a refused page is a fault on the read below: this is a
         * diagnostic build, and that limit is stated in docs/BUILDING.md. */
        ensure_storage_regs_mapped(NULL, b);
        /* Eight digits where the high half is zero, which it is below 4 GiB:
         * the sixteen-digit form ran off an 80-column screen on the laptop. */
        print("SDTRACE   @");
        if (b >> 32) sdtrace_hx((uint32_t)(b >> 32), 8);
        sdtrace_hx((uint32_t)b, 8);
        print(" len="); sdtrace_hx((uint32_t)d->mmio[i].len, 5);
        print(" ver="); sdtrace_hx(sdhci_read16(b, SDHCI_HOST_VERSION), 4);
        print(" cap="); sdtrace_hx(sdhci_read32(b, SDHCI_CAPABILITIES), 8);
        print(" ps=");  sdtrace_hx(sdhci_read32(b, SDHCI_PRESENT_STATE), 8);
        print("\n");
    }
}
#endif

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

#ifdef SDHCI_HW_TRACE
    /* Read as found, then after each candidate fix in turn, so whichever step
     * makes the registers answer is the cause. The normal probe then runs on
     * the state the last step left. */
    sdhci_trace_step(d, "as found");
    iodev_trace_force_d0(d);
    sdhci_trace_step(d, "after D0");
    iodev_set_decode(d, IODEV_DECODE_MEM);
    sdhci_trace_step(d, "after MEM decode");
#endif

    /* THE REGISTER FILE IS IN THE BAR THE CONTROLLER NAMES. The SDHCI Slot
     * Information register (PCI config 0x40) gives slot 0's BAR number, and the
     * region recorded from that BAR is the one used.
     *
     * Until 2026-09-22 this took the highest-based memory region, because
     * struct io_device did not record which BAR a region came from. QEMU's
     * controller has one BAR, so every gate agreed with that guess. An IdeaPad
     * 1 14IGL05 (Intel 8086:31cc) has two: BAR0 at 0xa1135000 answered
     * VER=0x1002 CAP=0x546ec881, BAR2 at 0xa1136000 read all zeros, and the
     * probe chose BAR2 and reported "did not answer as a host controller" (read
     * off the machine with SDHCI_HW_TRACE=1). A device that names no valid BAR,
     * or names one that is not a memory region, is refused rather than guessed
     * at. SDHCI_BAR_HIGHEST=1 restores the guess for the control arm. */
    uint64_t bar = 0, bar_len = 0;
#ifdef SDHCI_BAR_HIGHEST
    for (uint32_t i = 0; i < d->n_mmio; i++) {
        if (d->mmio[i].base > bar) { bar = d->mmio[i].base; bar_len = d->mmio[i].len; }
    }
#else
    const int first_bar = iodev_sdhci_first_bar(d);
    for (uint32_t i = 0; first_bar >= 0 && i < d->n_mmio && i < IODEV_MAX_MMIO; i++) {
        if (d->mmio_bar[i] == (uint8_t)(first_bar + 1)) {   /* stored BAR + 1 */
            bar = d->mmio[i].base; bar_len = d->mmio[i].len;
            break;
        }
    }
#endif
    if (bar == 0 || bar_len < 0x100) {
        print("sdhci: controller has no register BAR large enough; ignoring it\n");
        return;
    }

    ensure_storage_regs_mapped(NULL, bar);

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
    /* AN EMBEDDED SLOT HOLDS A SOLDERED DEVICE, AND ITS DETECT LINE NEED NOT
     * SAY SO. Capabilities bits 31:30 = 01 is "embedded slot for one device"
     * (SDHCI 3.00 section 2.2.26): an eMMC chip on the board, which cannot be
     * removed and which the specification does not require to drive card
     * detect. The IdeaPad's controller reports exactly this. Waiting for the
     * detect line there would report a laptop's only disk as an empty slot.
     * SDHCI_EMBEDDED_NEEDS_CD=1 restores the wait for the control arm. */
#ifndef SDHCI_EMBEDDED_NEEDS_CD
    if (((caps >> 30) & 0x3u) == 0x1u) {
        g_sdhci_cards = 1;
        print("  [ OK ] sdhci: embedded slot, its soldered device is present by construction\n");
    } else
#endif
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
            print("         sdhci: identification clock ");
            print_decimal(g_sdhci_id_khz);
            print(" kHz\n");
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
#ifdef SDHCI_WRITE_SELFTEST
                /* WRITE ROUND TRIP -- BUILD-GATED, AND THAT IS A SAFETY
                 * PROPERTY, NOT A TESTING CONVENIENCE. A shipped boot must
                 * never write to the card it found: on a laptop that is the
                 * operator's own storage, and a probe that scribbled on it to
                 * prove it could would be indefensible. Only the gate builds
                 * this in.
                 *
                 * Block 200, not block 0: the addressing mode makes block 0
                 * address 0 in either unit, so a round trip there would pass
                 * with the mode inverted -- the same reason the read probes use
                 * a non-zero block. */
                {
                    static uint8_t wbuf[512], rbuf[512];
                    for (int i = 0; i < 512; i++) wbuf[i] = (uint8_t)('W' + (i & 7));
                    int wrc = sd_write_block(bar, 200, wbuf, is_hc);
                    int frc = (wrc == 0) ? sd_flush(bar) : -1;
                    int rrc = (frc == 0) ? sd_read_block(bar, 200, rbuf, is_hc) : -1;
                    int same = 1;
                    if (rrc == 0) {
                        for (int i = 0; i < 512; i++)
                            if (rbuf[i] != wbuf[i]) { same = 0; break; }
                    }
                    print("         sdhci-write block200: ");
                    if (wrc != 0)      print("write failed\n");
                    else if (frc != 0) print("flush failed\n");
                    else if (rrc != 0) print("readback failed\n");
                    else if (!same)    print("readback differs\n");
                    else               print("SDHCI-WRITE-OK\n");
                }
#endif
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
                /* NAME THE STEP, NOT JUST THE NUMBER. On 2026-09-22 this
                 * printed "(1)" on the laptop, and 1 was two different places:
                 * the opening CMD0 and the one that reopens the eMMC branch.
                 * Which of them it was is the whole difference between "the
                 * card never answered at all" and "the card answered and then
                 * something wedged the bus", and the number could not say.
                 * Indexed by -rc; keep it in step with the returns above. */
                static const char *const step[] = {
                    "",                             /*  0, unused */
                    "CMD0 go-idle",                 /* -1 */
                    "CMD1 eMMC op-cond",            /* -2 */
                    "CMD2 all-send-CID",            /* -3 */
                    "CMD3 relative address",        /* -4 */
                    "CMD9 send-CSD",                /* -5 */
                    "CMD7 select-card",             /* -6 */
                    "CMD8 extended CSD read",       /* -7 */
                    "CMD0 go-idle, eMMC retry",     /* -8 */
                };
                const int nsteps = (int)(sizeof(step) / sizeof(step[0]));
                print("  sdhci: the card did not come up (");
                print_decimal((uint64_t)(-rc));
                if (-rc > 0 && -rc < nsteps) { print(", "); print(step[-rc]); }
                print(")\n");
            }
        }
    }

    print("sdhci: ");
    print_decimal(g_sdhci_cards);
    print(" card(s) present\n");
#endif /* SDHCI_PROBE_ABSENT */
}
