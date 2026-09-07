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
 * section 2.1. Only the three this probe reads are named. */
#define SDHCI_PRESENT_STATE   0x24
#define SDHCI_CAPABILITIES    0x40
#define SDHCI_HOST_VERSION    0xFE

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

uint64_t sdhci_bar(void)        { return g_sdhci_bar; }
uint32_t sdhci_card_count(void) { return g_sdhci_cards; }

static inline uint32_t sdhci_read32(uint64_t bar, uint32_t off) {
    return *(volatile uint32_t *)(uintptr_t)(bar + off);
}
static inline uint16_t sdhci_read16(uint64_t bar, uint32_t off) {
    return *(volatile uint16_t *)(uintptr_t)(bar + off);
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

    print("sdhci: ");
    print_decimal(g_sdhci_cards);
    print(" card(s) present; no block driver yet, so none is mountable\n");
#endif /* SDHCI_PROBE_ABSENT */
}
