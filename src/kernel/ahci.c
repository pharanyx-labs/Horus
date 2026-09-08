/* ahci.c -- find the SATA controller, and say what is attached to it.
 *
 * WHY THIS EXISTS, AND WHY IT IS ONLY A PROBE.
 *
 * The only storage driver in this tree is `ata.c`: legacy IDE PIO on ports
 * 0x1F0/0x170. That is what QEMU gives by default and it is not what a laptop
 * has. A machine built this decade exposes its SSD through AHCI (SATA) or NVMe,
 * so `boot.iso` boots on real hardware -- since 2026-09-07 it boots from a USB
 * stick under UEFI too -- and then the installer surveys the machine and finds
 * NO DISK, because nothing here can see one. That is the item that actually
 * gates installing onto a laptop, and `docs/LIMITATIONS.md` §4 says so.
 *
 * It FINDS the controller, brings each attached port up, and asks the drive to
 * IDENTIFY itself -- so the report names the model and the capacity rather than
 * merely "something is there". It does NOT read or write blocks yet: there is no
 * block_device registration for a SATA disk, so storage.c cannot mount one. The
 * SD/eMMC driver next door does have one as of 2026-09-08, so the shape to copy
 * is `g_sd_bd` in storage.c -- the block layer, the survey's enumeration and the
 * installer's target selection are controller-independent and already in place.
 *
 * WHY IDENTIFY AND NOT READ. IDENTIFY exercises the whole mechanism a read would
 * -- command list, FIS receive area, command table, PRDT, and the completion
 * handshake -- against a command that CANNOT DAMAGE THE DISK. If the DMA
 * addresses, the alignment rules or the polling are wrong, they are wrong here,
 * on a command whose worst failure is a timeout. Getting that wrong first with a
 * WRITE is how a driver destroys the disk it was meant to install onto.
 *
 * WHAT IT READS. The HBA's register file lives in a memory BAR (ABAR, always
 * BAR5 in the AHCI specification). The generic host control block is the first
 * 0x100 bytes: CAP, GHC, IS, PI, VS. Each implemented port then has a 0x80-byte
 * block at 0x100 + port*0x80, of which two registers say whether anything is
 * there -- SSTS (device detection and interface power state) and SIG (what kind
 * of device answered). Thirty-two ports at 0x80 is 0x1000, so the whole file is
 * 0x1100 bytes and two pages of mapping cover it.
 *
 * WHY THE BAR IS TAKEN AS "THE HIGHEST-BASED MMIO REGION" RATHER THAN BY INDEX.
 * `struct io_device` records each sized BAR's base and length but not which BAR
 * index it came from, so this cannot simply ask for BAR5. Taking the highest
 * base is a heuristic, so it is not TRUSTED: the candidate is validated against
 * the hardware before anything is reported (VS must name a version this
 * specification defines, and PI must implement at least one port). A controller
 * that fails those checks is reported as unrecognised rather than guessed at --
 * the whole point of this file is to say what is actually there.
 */
#include "kernel.h"

/* Generic host control, and the two per-port registers that answer "is there a
 * disk?". Offsets from the AHCI 1.3.1 specification, section 3. */
#define AHCI_CAP        0x00    /* host capabilities                           */
#define AHCI_PI         0x0C    /* ports implemented (a bitmap)                */
#define AHCI_VS         0x10    /* version, as major<<16 | minor               */
#define AHCI_PORT_BASE  0x100
#define AHCI_PORT_STRIDE 0x80
#define AHCI_PxSIG      0x24    /* signature: what answered                    */
#define AHCI_PxSSTS     0x28    /* SATA status: DET in [3:0], IPM in [11:8]    */

#define AHCI_MAX_PORTS  32

/* Per-port registers, offsets from the port block. */
#define AHCI_PxCLB      0x00    /* command list base (low 32)                  */
#define AHCI_PxCLBU     0x04
#define AHCI_PxFB       0x08    /* FIS receive base (low 32)                   */
#define AHCI_PxFBU      0x0C
#define AHCI_PxIS       0x10    /* interrupt status                            */
#define AHCI_PxCMD      0x18    /* command and status                          */
#define AHCI_PxTFD      0x20    /* task file data: the drive's status byte      */
#define AHCI_PxSERR     0x30    /* SATA error                                  */
#define AHCI_PxCI       0x38    /* commands issued                             */

#define PxCMD_ST        0x0001u /* start: process the command list             */
#define PxCMD_FRE       0x0010u /* FIS receive enable                          */
#define PxCMD_FR        0x4000u /* FIS receive running                         */
#define PxCMD_CR        0x8000u /* command list running                        */

#define PxIS_TFES       (1u << 30)  /* task file error                         */
#define ATA_ST_BSY      0x80u
#define ATA_ST_DRQ      0x08u
#define ATA_ST_ERR      0x01u

#define ATA_CMD_IDENTIFY 0xECu
#define FIS_TYPE_H2D     0x27u

/* How long to wait for the HBA, in polls.
 *
 * BOUNDED, NEVER INFINITE, and for ata.c's reason: an unbounded wait on a
 * controller that is not going to answer turns "no disk" into "hang at boot",
 * which is the failure that cannot be diagnosed from the other side. On timeout
 * the port is reported as not answering and the probe moves on. */
#define AHCI_SPINS       2000000u

/* The command list, the FIS receive area, one command table and one data buffer
 * all fit in ONE 4 KiB page, and their alignment requirements fall out of the
 * layout rather than needing separate allocations:
 *
 *   0x0000  command list      1 KiB, must be 1 KiB aligned (page base is)
 *   0x0400  FIS receive       256 B, must be 256 B aligned
 *   0x0500  command table     128 B header + PRDT, must be 128 B aligned
 *   0x0800  data buffer       512 B, the IDENTIFY response
 *
 * One page per port, allocated once and kept: this is the only DMA memory the
 * probe needs, and freeing it would mean stopping the port again. */
#define AHCI_CL_OFF     0x000
#define AHCI_FIS_OFF    0x400
#define AHCI_CT_OFF     0x500
#define AHCI_DATA_OFF   0x800

struct ahci_cmd_header {
    uint16_t flags;         /* [4:0] CFIS length in dwords, bit 6 = write */
    uint16_t prdtl;
    volatile uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t rsvd[4];
} __attribute__((packed));

struct ahci_prdt_entry {
    uint32_t dba;
    uint32_t dbau;
    uint32_t rsvd;
    uint32_t dbc;           /* byte count - 1, bit 31 = interrupt on completion */
} __attribute__((packed));

struct ahci_cmd_table {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t rsvd[48];
    struct ahci_prdt_entry prdt[1];
} __attribute__((packed));

/* PxSIG values. A SATA disk answers 0x00000101; ATAPI, an enclosure processor
 * and a port multiplier answer differently, and telling them apart matters
 * because only the first is something an installer could ever write to. */
#define SIG_SATA        0x00000101u
#define SIG_ATAPI       0xEB140101u
#define SIG_SEMB        0xC33C0101u
#define SIG_PM          0x96690101u

static uint64_t g_ahci_abar;        /* 0 when no controller was recognised */
static uint32_t g_ahci_ports;       /* implemented-port bitmap             */
static uint32_t g_ahci_devices;     /* ports with a SATA disk present      */

uint64_t ahci_abar(void)        { return g_ahci_abar; }
uint32_t ahci_device_count(void){ return g_ahci_devices; }

static inline uint32_t abar_read(uint64_t abar, uint32_t off) {
    return *(volatile uint32_t *)(uintptr_t)(abar + off);
}

/* The controller, if the machine has one. Mass storage (class 0x01), SATA
 * (subclass 0x06), AHCI programming interface (0x01) -- the prog-if matters,
 * because the SAME controller in IDE-compatibility mode presents as 0x01/0x01
 * and is driven by ata.c instead. */
static const struct io_device *find_ahci_controller(uint64_t *index_out) {
    uint32_t n = iodev_total();
    for (uint32_t i = 0; i < n; i++) {
        const struct io_device *d = iodev_get(i);
        if (!d || !d->present) continue;
        if ((d->classcode >> 8) != 0x0106u) continue;   /* class:subclass */
        if ((d->classcode & 0xFFu) != 0x01u) continue;  /* prog-if: AHCI  */
        if (index_out) *index_out = i;
        return d;
    }
    return NULL;
}

/* Stop a port's engines so its base addresses can be rewritten.
 *
 * BOTH must be observed to have STOPPED, not merely asked to stop: the HBA
 * finishes what it is doing first, and rewriting PxCLB while the command engine
 * is still running points live hardware at memory that is about to be reused. */
static int ahci_port_stop(uint64_t pbase) {
    volatile uint32_t *cmd = (volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxCMD);
    *cmd &= ~PxCMD_ST;
    *cmd &= ~PxCMD_FRE;
    for (uint32_t i = 0; i < AHCI_SPINS; i++)
        if ((*cmd & (PxCMD_CR | PxCMD_FR)) == 0) return 0;
    return -1;
}

/* Point the port at its DMA structures and start it again. */
static int ahci_port_start(uint64_t pbase, uint32_t page_phys) {
    volatile uint32_t *cmd = (volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxCMD);

    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxCLB)  = page_phys + AHCI_CL_OFF;
    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxCLBU) = 0;
    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxFB)   = page_phys + AHCI_FIS_OFF;
    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxFBU)  = 0;

    /* SERR is write-1-to-clear: a link that negotiated during boot leaves bits
     * set, and a stale error there makes the first command look like a failure. */
    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxSERR) = 0xFFFFFFFFu;
    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxIS)   = 0xFFFFFFFFu;

    *cmd |= PxCMD_FRE;
    *cmd |= PxCMD_ST;
    return 0;
}

/* Wait for the drive to be neither busy nor asking to transfer. */
static int ahci_wait_ready(uint64_t pbase) {
    for (uint32_t i = 0; i < AHCI_SPINS; i++) {
        uint32_t tfd = *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxTFD);
        if ((tfd & (ATA_ST_BSY | ATA_ST_DRQ)) == 0) return 0;
    }
    return -1;
}

/* IDENTIFY DEVICE on one port. Fills `model` (41 bytes: 40 chars and a NUL) and
 * `sectors`, and returns 0 only if the drive actually answered. */
static int ahci_identify(uint64_t pbase, uint32_t page_phys,
                         char *model, uint64_t *sectors) {
    uint8_t *page = (uint8_t *)PHYS_KVA((uint64_t)page_phys);
    struct ahci_cmd_header *hdr = (struct ahci_cmd_header *)(page + AHCI_CL_OFF);
    struct ahci_cmd_table  *ct  = (struct ahci_cmd_table  *)(page + AHCI_CT_OFF);
    uint16_t *data = (uint16_t *)(page + AHCI_DATA_OFF);

    for (uint32_t i = 0; i < PAGE_SIZE; i++) page[i] = 0;

    hdr->flags = (uint16_t)(5u);          /* CFIS is 5 dwords; not a write */
    hdr->prdtl = 1;
    hdr->prdbc = 0;
    hdr->ctba  = page_phys + AHCI_CT_OFF;
    hdr->ctbau = 0;

    ct->prdt[0].dba  = page_phys + AHCI_DATA_OFF;
    ct->prdt[0].dbau = 0;
    ct->prdt[0].dbc  = 511;               /* 512 bytes, expressed as count - 1 */

    ct->cfis[0] = FIS_TYPE_H2D;
    ct->cfis[1] = 0x80;                   /* C: this FIS carries a command */
    ct->cfis[2] = ATA_CMD_IDENTIFY;

    if (ahci_wait_ready(pbase) != 0) return -1;

    *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxCI) = 1u;

    for (uint32_t i = 0; ; i++) {
        uint32_t ci = *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxCI);
        if ((ci & 1u) == 0) break;
        /* A task-file error aborts the wait: the command is not going to
         * complete, and spinning out the full bound would turn a refused command
         * into a several-second stall per port. */
        if (*(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxIS) & PxIS_TFES) return -1;
        if (i >= AHCI_SPINS) return -1;
    }

    uint32_t tfd = *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxTFD);
    if (tfd & ATA_ST_ERR) return -1;
    if (hdr->prdbc == 0) return -1;       /* completed, transferred nothing */

    /* Words 27..46 are the model, in BIG-endian pairs -- the one field in this
     * structure that is not little-endian, so the bytes swap within each word. */
    for (int w = 0; w < 20; w++) {
        uint16_t v = data[27 + w];
        model[w * 2]     = (char)(v >> 8);
        model[w * 2 + 1] = (char)(v & 0xFF);
    }
    model[40] = 0;
    for (int i = 39; i >= 0 && (model[i] == ' ' || model[i] == 0); i--) model[i] = 0;

    /* Words 100..103 are the 48-bit capacity; words 60..61 the 28-bit one, which
     * is all a pre-48-bit drive fills in. Preferring the first and falling back
     * is what stops a large disk being reported as its low 32 bits. */
#ifdef AHCI_CAPACITY_CONSTANT
    /* The control arm: a capacity that is plausible and is not the drive's. A
     * driver that read the right words from the wrong offset, or that filled in
     * a default it never checked, looks exactly like this -- and the number it
     * prints is a perfectly reasonable one, which is why the gate compares it to
     * the size of the disk it attached rather than to a range. */
    (void)data;
    *sectors = 128u * 1024u * 1024u / 512u;   /* always 128 MiB */
#else
    uint64_t s48 = (uint64_t)data[100] | ((uint64_t)data[101] << 16) |
                   ((uint64_t)data[102] << 32) | ((uint64_t)data[103] << 48);
    uint64_t s28 = (uint64_t)data[60] | ((uint64_t)data[61] << 16);
    *sectors = s48 ? s48 : s28;
#endif
    return 0;
}

static void report_port(uint32_t port, uint32_t ssts, uint32_t sig) {
    const uint32_t det = ssts & 0xFu;
    /* DET==3 is "device present and communication established". Anything else --
     * no device, or a link that never came up -- is not something to report as a
     * disk, and saying so is the difference between "no disk" and "a disk we
     * failed to talk to". */
    if (det != 3) return;

    print("  [ OK ] ahci: port ");
    print_decimal(port);
    switch (sig) {
        case SIG_SATA:  print(": SATA disk\n");                break;
        case SIG_ATAPI: print(": ATAPI device\n");             break;
        case SIG_SEMB:  print(": enclosure processor\n");      break;
        case SIG_PM:    print(": port multiplier\n");          break;
        default:
            print(": unrecognised signature 0x");
            print_hex(sig);
            print("\n");
            break;
    }
}

/* Called from kernel_main after iodev_init, which is what populates the device
 * table this reads. Reports and returns; nothing else in the kernel depends on
 * it yet. */
void ahci_probe(void) {
#ifdef AHCI_PROBE_ABSENT
    /* The control arm: the probe is compiled out, so a machine WITH an AHCI
     * controller reports nothing about it. See make smoke-ahci-detect. */
    return;
#else
    uint64_t devindex = 0;
    const struct io_device *d = find_ahci_controller(&devindex);
    if (!d) {
        print("ahci: no SATA controller (storage is legacy ATA only)\n");
        return;
    }

    /* The highest-based memory BAR is the candidate -- see the header comment on
     * why this is a heuristic and what validates it. */
    uint64_t abar = 0, abar_len = 0;
    for (uint32_t i = 0; i < d->n_mmio; i++) {
        if (d->mmio[i].base > abar) { abar = d->mmio[i].base; abar_len = d->mmio[i].len; }
    }
    if (abar == 0 || abar_len < 0x1100) {
        print("ahci: controller has no register BAR large enough; ignoring it\n");
        return;
    }

    ensure_storage_regs_mapped(NULL, abar);

    const uint32_t vs = abar_read(abar, AHCI_VS);
    const uint32_t pi = abar_read(abar, AHCI_PI);
    const uint32_t cap = abar_read(abar, AHCI_CAP);

    /* VALIDATE BEFORE BELIEVING. A wrong BAR reads as open bus (all ones) or as
     * some other device's registers, and either would otherwise be reported as a
     * disk survey. AHCI defines 0.95, 1.0, 1.1, 1.2, 1.3 and 1.3.1, so a major
     * version of 1 (or the 0.95 encoding) is the whole legal set; and a
     * controller implementing no ports is not one worth reporting. */
    const uint32_t major = vs >> 16;
    if ((major != 1 && vs != 0x00000905u) || pi == 0) {
        print("ahci: controller at ");
        print_hex(abar);
        print(" did not answer as an HBA (VS=0x");
        print_hex(vs);
        print(" PI=0x");
        print_hex(pi);
        print("); ignoring it\n");
        return;
    }

    g_ahci_abar  = abar;
    g_ahci_ports = pi;

    print("ahci: HBA v");
    print_decimal(major);
    print(".");
    print_decimal((vs >> 8) & 0xFFu);
    print(", ");
    print_decimal((cap & 0x1Fu) + 1u);       /* CAP.NP is zero-based */
    print(" ports, ");
    print_decimal((cap >> 8) & 0x1Fu ? ((cap >> 8) & 0x1Fu) + 1u : 1u);
    print(" command slots\n");

    for (uint32_t p = 0; p < AHCI_MAX_PORTS; p++) {
        if ((pi & (1u << p)) == 0) continue;
        const uint64_t pbase = abar + AHCI_PORT_BASE + (uint64_t)p * AHCI_PORT_STRIDE;
        const uint32_t ssts = *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxSSTS);
        const uint32_t sig  = *(volatile uint32_t *)(uintptr_t)(pbase + AHCI_PxSIG);
        if ((ssts & 0xFu) == 3 && sig == SIG_SATA) g_ahci_devices++;
        report_port(p, ssts, sig);

        /* Ask the drive who it is. Only a SATA disk is asked: an ATAPI device
         * answers a different command (IDENTIFY PACKET DEVICE), and the boot
         * CD-ROM is one of those, so issuing this at it would time out for a
         * reason that is not a fault. */
        if ((ssts & 0xFu) != 3 || sig != SIG_SATA) continue;

        uint32_t page = alloc_user_physical_page();
        if (page == 0) { print("         (no memory to identify it)\n"); continue; }

        /* When VT-d is active the controller reaches nothing it has not been
         * given, which includes these structures -- so the mapping is installed
         * before the port is pointed at them, not after. On a machine with no
         * DMAR this is a no-op and the DMA is unrestricted anyway. */
        if (iommu_active()) (void)iommu_map(devindex, d->bdf, (uint64_t)page, 1, 1);

        char model[41];
        uint64_t sectors = 0;
        if (ahci_port_stop(pbase) != 0) { print("         (port would not stop)\n"); continue; }
        ahci_port_start(pbase, page);

        if (ahci_identify(pbase, page, model, &sectors) == 0) {
            print("         ");
            print(model);
            print(", ");
            print_decimal(sectors / 2048u);   /* 512-byte sectors -> MiB */
            print(" MiB\n");
        } else {
            print("         (the drive did not answer IDENTIFY)\n");
        }
    }

    print("ahci: ");
    print_decimal(g_ahci_devices);
    print(" SATA disk(s) identified; no block driver yet, so none is mountable\n");
#endif /* AHCI_PROBE_ABSENT */
}
