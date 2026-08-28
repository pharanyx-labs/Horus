/* pci.c -- the I/O-device table: what a CAP_IO_DEVICE names.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * CAP_IO_DEVICE was a capability *type* with no object. There was exactly one,
 * primordial, in root_cnode[10], its `object` field permanently 0 and never read
 * by anything; the three syscalls it gated resolved their authority from a
 * constant instead:
 *
 *   - SYS_MAP_PHYS consulted device_frame_allowed(), a hardcoded two-range VGA
 *     allowlist compiled into syscall_hw.c;
 *   - SYS_IOPORT_GRANT set one per-task boolean, and the TSS bitmap it activated
 *     had been prefilled at boot with one fixed console port set;
 *   - SYS_IRQ_REGISTER accepted IRQ 0 or 1 from anyone holding the type.
 *
 * So "hardware authority" was a single indivisible grant meaning *the console*,
 * and a second driver could not be given the hardware it needs without also being
 * given the hardware it does not. That is the [C-1] shape one layer down: an
 * unmediated constant standing in for the object a capability is supposed to
 * name. The fix is the same fix — resolve the object, and check the request
 * against what that object actually declares.
 *
 * WHAT A DEVICE IS HERE
 * ---------------------
 * `iodev_table[]` is the kernel's list of delegatable hardware. Index 0 is
 * permanently absent (see IODEV_NONE in kernel.h: zero must not name a device).
 * Entry 1 is the legacy platform device — the PIT, the PS/2 controller, the two
 * UARTs, and the VGA register file with its framebuffer, none of which are
 * enumerable — and entries 2.. are PCI functions found on bus 0. Each entry declares exactly three
 * kinds of resource, because those are exactly the three things the syscalls hand
 * out: physical frames (SYS_MAP_PHYS), I/O port ranges (SYS_IOPORT_GRANT), and
 * interrupt lines (SYS_IRQ_REGISTER).
 *
 * The table is built once, at boot, before any ring-3 task exists, and is
 * READ-ONLY afterwards. Nothing here is reachable from a syscall: ring 3 never
 * names a bus address, only a capability, and the capability names an index into
 * this table. Config space itself is never exposed — a driver that could write
 * config space could reprogram its own BARs and point them at somebody else's
 * device, which would make every check below decorative.
 *
 * WHY BUS 0 ONLY, AND WHY THAT IS NOT A HOLE
 * ------------------------------------------
 * The scan walks bus 0 and does not follow PCI-to-PCI bridges. On the machines
 * this kernel targets (QEMU i440fx and q35) every device is on bus 0, so this
 * finds all of them. It matters which direction the limitation errs in: a device
 * behind a bridge is simply ABSENT from the table, so no capability can be minted
 * naming it and no authority can be granted over it. Missing a device costs a
 * feature; inventing one would cost the property. Extending the walk is a
 * bounded, additive change when a bridge first appears.
 */
#include "syscall_internal.h"

/* 32-bit port I/O, needed only for PCI configuration space. Deliberately local:
 * exporting inl/outl would invite their use elsewhere, and the kernel's own
 * device access is byte-wide everywhere else (terminal.c, ata.c). */
static inline void outl(uint16_t port, uint32_t val) {
    __asm__ volatile ("outl %0, %1" :: "a"(val), "Nd"(port));
}
static inline uint32_t inl(uint16_t port) {
    uint32_t v;
    __asm__ volatile ("inl %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

#define PCI_CFG_ADDR   0xCF8
#define PCI_CFG_DATA   0xCFC

/* Configuration-space offsets used below. */
#define PCI_VENDOR_ID     0x00
#define PCI_COMMAND       0x04
#define PCI_REVISION      0x08   /* rev:8 | prog-if:8 | subclass:8 | class:8 */
#define PCI_HEADER_TYPE   0x0E
#define PCI_BAR0          0x10
#define PCI_INTERRUPT_LINE 0x3C

#define PCI_CMD_IO        0x0001
#define PCI_CMD_MEM       0x0002
#define PCI_CMD_MASTER    0x0004

#define PCI_HDR_MULTIFN   0x80
#define PCI_HDR_TYPE_MASK 0x7F
#define PCI_HDR_GENERAL   0x00   /* type 0: the only header with 6 BARs */

static uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off) {
    uint32_t addr = 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) |
                    ((uint32_t)fn << 8) | (uint32_t)(off & 0xFC);
    outl(PCI_CFG_ADDR, addr);
    return inl(PCI_CFG_DATA);
}

static void pci_cfg_write32(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off, uint32_t val) {
    uint32_t addr = 0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) |
                    ((uint32_t)fn << 8) | (uint32_t)(off & 0xFC);
    outl(PCI_CFG_ADDR, addr);
    outl(PCI_CFG_DATA, val);
}

static uint16_t pci_cfg_read16(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off) {
    uint32_t v = pci_cfg_read32(bus, dev, fn, off);
    return (uint16_t)((v >> ((off & 2) * 8)) & 0xFFFF);
}

static uint8_t pci_cfg_read8(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t off) {
    uint32_t v = pci_cfg_read32(bus, dev, fn, off);
    return (uint8_t)((v >> ((off & 3) * 8)) & 0xFF);
}

/* The table. Static storage, sized at compile time: this is boot-time kernel
 * bookkeeping, not a ring-3-allocatable object, so it does not belong in the
 * untyped arena and cannot be exhausted by anything a task does. */
static struct io_device iodev_table[IODEV_MAX];
static uint32_t iodev_count;
static int iodev_ready;

/* ---- the platform (non-enumerable) device -------------------------------- */

/* Entry 1 (index 0 is reserved). These are the resources SYS_MAP_PHYS /
 * SYS_IOPORT_GRANT / SYS_IRQ_REGISTER used to hand out to any holder of the type,
 * restated here as what ONE device declares — so the set is unchanged for console_server and is
 * now refused to everybody else.
 *
 * The frames are the VGA text framebuffer [0xB8000,0xBA000) (an 80x50 text buffer
 * is 8000 bytes, so two 4 KiB frames) and the graphics/font plane
 * [0xA0000,0xB0000), written during mode init when load_8x8_font blits into the
 * font plane.
 *
 * The ports are the PS/2 keyboard, the two UART register files, and the VGA
 * CRTC/sequencer/graphics/attribute block — deliberately not the PIC, not ATA,
 * not CMOS, and not PCI configuration space (0xCF8/0xCFC), which is the one range
 * whose omission is load-bearing: a driver that could write config space could
 * reprogram any device's BARs and defeat every mmio check in this file.
 *
 * The IRQs are 0 (PIT) and 1 (PS/2 keyboard). IRQ 0 is here because the platform
 * timer is a platform device; irqtest routes it to prove the bridge works. */
static void iodev_add_platform(void) {
    struct io_device *d = &iodev_table[IODEV_PLATFORM];
    d->present   = 1;
    d->name      = "platform";
    d->bdf       = IODEV_BDF_NONE;
    d->vendor    = 0;
    d->device    = 0;
    d->classcode = 0;

    d->mmio[0].base = 0xA0000ULL; d->mmio[0].len = 0x10000ULL;  /* VGA graphics/font plane */
    d->mmio[1].base = 0xB8000ULL; d->mmio[1].len = 0x2000ULL;   /* VGA text framebuffer    */
    d->n_mmio = 2;

    d->port[0].base = 0x60;  d->port[0].len = 1;      /* PS/2 data           */
    d->port[1].base = 0x64;  d->port[1].len = 1;      /* PS/2 status/command */
    d->port[2].base = 0x2F8; d->port[2].len = 8;      /* COM2                */
    d->port[3].base = 0x3F8; d->port[3].len = 8;      /* COM1                */
    d->port[4].base = 0x3B0; d->port[4].len = 0x30;   /* VGA register file   */
    d->n_port = 5;

    d->irq_mask = (1u << 0) | (1u << 1);

    iodev_count = IODEV_PLATFORM + 1;
}

/* ---- PCI enumeration ----------------------------------------------------- */

/* Size one BAR the standard way: write all-ones, read back the mask, restore.
 *
 * The write is only safe while the device is not decoding, because between the
 * ones-write and the restore the BAR names a different address — a device
 * decoding there would answer at the wrong place. So the caller drops the
 * command register's I/O and memory decode bits first and restores them after,
 * and NOTHING between those two points may print: the VGA device is one of the
 * devices being sized, and a println() landing inside its decode-off window would
 * write into a framebuffer that is momentarily not there.
 *
 * Returns 0 for an unimplemented BAR, and sets *is_io / *is_64. */
static uint64_t pci_bar_size(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t idx,
                             uint64_t *out_base, int *is_io, int *is_64) {
    uint8_t off = (uint8_t)(PCI_BAR0 + idx * 4);
    uint32_t orig = pci_cfg_read32(bus, dev, fn, off);
    if (orig == 0) { *out_base = 0; *is_io = 0; *is_64 = 0; return 0; }

    *is_io = (orig & 1u) ? 1 : 0;
    *is_64 = (!*is_io && ((orig >> 1) & 3u) == 2u) ? 1 : 0;

    uint32_t orig_hi = 0;
    if (*is_64) orig_hi = pci_cfg_read32(bus, dev, fn, (uint8_t)(off + 4));

    pci_cfg_write32(bus, dev, fn, off, 0xFFFFFFFFu);
    uint32_t mask = pci_cfg_read32(bus, dev, fn, off);
    pci_cfg_write32(bus, dev, fn, off, orig);

    uint32_t mask_hi = 0;
    if (*is_64) {
        pci_cfg_write32(bus, dev, fn, (uint8_t)(off + 4), 0xFFFFFFFFu);
        mask_hi = pci_cfg_read32(bus, dev, fn, (uint8_t)(off + 4));
        pci_cfg_write32(bus, dev, fn, (uint8_t)(off + 4), orig_hi);
    }

    uint64_t base, size;
    if (*is_io) {
        base = (uint64_t)(orig & 0xFFFFFFFCu);
        size = (uint64_t)(~(mask & 0xFFFFFFFCu) + 1u) & 0xFFFFu;
    } else {
        base = (uint64_t)(orig & 0xFFFFFFF0u) | ((uint64_t)orig_hi << 32);
        uint64_t m = (uint64_t)(mask & 0xFFFFFFF0u) | ((uint64_t)mask_hi << 32);
        size = (m == 0) ? 0 : (~m + 1ULL);
    }
    /* A BAR whose base firmware never assigned decodes nothing; recording it
     * would put address 0 — and with it every page of low memory the size
     * happens to cover — into a device's resource list. */
    if (base == 0) { *out_base = 0; return 0; }
    *out_base = base;
    return size;
}

/* Record one PCI function. Bounded by IODEV_MAX: a machine with more functions
 * than the table holds loses the tail, which is the same direction of failure as
 * the bus-0 limit — absent, therefore un-delegatable. */
static void pci_add_function(uint8_t bus, uint8_t dev, uint8_t fn,
                             uint16_t vendor, uint16_t device) {
    if (iodev_count >= IODEV_MAX) return;
    struct io_device *d = &iodev_table[iodev_count];

    uint32_t rev = pci_cfg_read32(bus, dev, fn, PCI_REVISION);
    d->classcode = rev >> 8;                       /* class:subclass:prog-if */
    d->present   = 1;
    d->name      = "pci";
    d->bdf       = (uint16_t)(((uint32_t)bus << 8) | ((uint32_t)dev << 3) | fn);
    d->vendor    = vendor;
    d->device    = device;
    d->n_mmio    = 0;
    d->n_port    = 0;
    d->irq_mask  = 0;

    /* Only a type-0 header has six BARs; a bridge's header aliases BAR2 onward
     * onto bus-number and window registers, and sizing those would corrupt the
     * bridge. Bridges therefore contribute no resources at all. */
    uint8_t hdr = (uint8_t)(pci_cfg_read8(bus, dev, fn, PCI_HEADER_TYPE) & PCI_HDR_TYPE_MASK);
    if (hdr == PCI_HDR_GENERAL) {
        uint16_t cmd = pci_cfg_read16(bus, dev, fn, PCI_COMMAND);
        pci_cfg_write32(bus, dev, fn, PCI_COMMAND,
                        (uint32_t)(cmd & (uint16_t)~(PCI_CMD_IO | PCI_CMD_MEM)));

        for (uint8_t i = 0; i < 6; i++) {
            uint64_t base = 0; int is_io = 0, is_64 = 0;
            uint64_t size = pci_bar_size(bus, dev, fn, i, &base, &is_io, &is_64);
            if (size != 0) {
                if (is_io) {
                    if (d->n_port < IODEV_MAX_PORT && base < 0x10000ULL &&
                        base + size <= 0x10000ULL) {
                        d->port[d->n_port].base = (uint16_t)base;
                        d->port[d->n_port].len  = (uint16_t)size;
                        d->n_port++;
                    }
                } else {
                    if (d->n_mmio < IODEV_MAX_MMIO) {
                        d->mmio[d->n_mmio].base = base;
                        d->mmio[d->n_mmio].len  = size;
                        d->n_mmio++;
                    }
                }
            }
            if (is_64) i++;   /* the upper half is not a BAR of its own */
        }

        pci_cfg_write32(bus, dev, fn, PCI_COMMAND, cmd);

        /* The interrupt line firmware programmed. 0xFF means "unrouted", and 15
         * is the top of the legacy PIC's range; anything else declares nothing,
         * so the device may route no interrupt at all. */
        uint8_t line = pci_cfg_read8(bus, dev, fn, PCI_INTERRUPT_LINE);
        if (line < 16) d->irq_mask = (1u << line);
    }

    iodev_count++;
}

/* ---- boot-time construction ---------------------------------------------- */

/* Build the table: the platform device, then every function on bus 0.
 *
 * Called from kernel_main BEFORE cap_init, because cap_init mints the primordial
 * device capabilities and each one has to name an index that already exists. */
void iodev_init(void) {
    for (uint32_t i = 0; i < IODEV_MAX; i++) iodev_table[i].present = 0;
    iodev_count = 0;
    iodev_add_platform();   /* claims index IODEV_PLATFORM; index 0 stays absent */

    for (uint8_t dev = 0; dev < 32; dev++) {
        uint32_t id = pci_cfg_read32(0, dev, 0, PCI_VENDOR_ID);
        uint16_t vendor = (uint16_t)(id & 0xFFFF);
        if (vendor == 0xFFFF) continue;             /* no function 0 => no device */
        uint16_t device = (uint16_t)(id >> 16);

        uint8_t hdr = pci_cfg_read8(0, dev, 0, PCI_HEADER_TYPE);
        pci_add_function(0, dev, 0, vendor, device);

        if (hdr & PCI_HDR_MULTIFN) {
            for (uint8_t fn = 1; fn < 8; fn++) {
                uint32_t fid = pci_cfg_read32(0, dev, fn, PCI_VENDOR_ID);
                uint16_t fv = (uint16_t)(fid & 0xFFFF);
                if (fv == 0xFFFF) continue;
                pci_add_function(0, dev, fn, fv, (uint16_t)(fid >> 16));
            }
        }
    }
    iodev_ready = 1;

    /* One line, because the table is the authority behind every device
     * capability and a reader debugging a refused SYS_MAP_PHYS wants to know
     * whether the device was found at all. Deliberately a count and not a
     * listing: this is the kernel log, and enumerating hardware into it would be
     * a bus walk anyone with CAP_KERNEL_LOG could read. */
    kmsg_begin();
    print("iodev: ");
    print_decimal((uint64_t)(iodev_count - IODEV_PLATFORM));
    print(" delegatable devices (platform + PCI bus 0)\n");
}

/* ---- queries ------------------------------------------------------------- */

const struct io_device *iodev_get(uint64_t index) {
    if (!iodev_ready) return 0;
    if (index == IODEV_NONE || index >= IODEV_MAX) return 0;
    if (!iodev_table[index].present) return 0;
    return &iodev_table[index];
}

uint32_t iodev_total(void) { return iodev_count; }

/* The first function whose PCI class byte is `class_hi` (0x02 = network
 * controller), or IODEV_NONE. Used once, at cap_init, to name the NIC the
 * primordial network-device capability refers to. */
uint64_t iodev_first_of_class(uint8_t class_hi) {
    for (uint32_t i = IODEV_PLATFORM; i < IODEV_MAX; i++) {
        if (!iodev_table[i].present) continue;
        if (iodev_table[i].bdf == IODEV_BDF_NONE) continue;
        if ((iodev_table[i].classcode >> 16) == class_hi) return i;
    }
    return IODEV_NONE;
}

/* Does `d` declare the whole of [paddr, paddr+len)?
 *
 * Whole, not overlapping: a request that runs off the end of a declared range is
 * refused rather than clipped. Clipping would let a caller ask for one legal byte
 * and a page of somebody else's device, and be told yes. Overflow on the sum is
 * checked because paddr comes from ring 3. */
int iodev_allows_mmio(const struct io_device *d, uint64_t paddr, uint64_t len) {
    if (!d || len == 0) return 0;
    if (paddr + len < paddr) return 0;
    for (uint32_t i = 0; i < d->n_mmio; i++) {
        uint64_t b = d->mmio[i].base, e = b + d->mmio[i].len;
        if (e < b) continue;
        if (paddr >= b && paddr + len <= e) return 1;
    }
    return 0;
}

int iodev_allows_port(const struct io_device *d, uint16_t port) {
    if (!d) return 0;
    for (uint32_t i = 0; i < d->n_port; i++) {
        uint32_t b = d->port[i].base, e = b + d->port[i].len;
        if (port >= b && port < e) return 1;
    }
    return 0;
}

/* Set the three PCI command-register decode bits of `d` to exactly `flags`
 * (IODEV_DECODE_IO / _MEM / _BUSMASTER), preserving every other bit.
 *
 * This is the ONLY write to configuration space reachable from ring 3, and the
 * narrowness is the whole design. A driver needs it — a device that is not
 * decoding answers nothing, and a device that is not a bus master cannot DMA, so
 * without this a ring-3 driver can map a BAR and find silence. What it must not
 * become is a config-space write primitive: the BARs live in the same 256 bytes,
 * and a driver that could move its own BAR could point it at another device's
 * registers and make iodev_allows_mmio's answer a lie. So the offset is fixed
 * here, the value is masked to three bits, and the device is the one the caller's
 * capability named — never one it passed by address.
 *
 * BUS MASTERING IS THE ONE THAT MATTERS, and it is worth being plain about what
 * granting it means on this machine: there is no IOMMU, so a device that is a bus
 * master reaches ALL of physical memory, whatever its driver holds. This call
 * bounds who may turn that on and for which device; it cannot bound where the
 * device then goes. See docs/LIMITATIONS.md §2.12.
 *
 * Refuses a platform device: the legacy console hardware has no configuration
 * space, and silently succeeding would report a decode that was never set. */
int iodev_set_decode(const struct io_device *d, uint32_t flags) {
    if (!d || d->bdf == IODEV_BDF_NONE) return -1;
    if (flags & ~(uint32_t)(IODEV_DECODE_IO | IODEV_DECODE_MEM | IODEV_DECODE_BUSMASTER))
        return -1;

    uint8_t bus = (uint8_t)(d->bdf >> 8);
    uint8_t dev = (uint8_t)((d->bdf >> 3) & 0x1F);
    uint8_t fn  = (uint8_t)(d->bdf & 0x07);

    uint32_t want = 0;
    if (flags & IODEV_DECODE_IO)        want |= PCI_CMD_IO;
    if (flags & IODEV_DECODE_MEM)       want |= PCI_CMD_MEM;
    if (flags & IODEV_DECODE_BUSMASTER) want |= PCI_CMD_MASTER;

    uint32_t cmd = pci_cfg_read32(bus, dev, fn, PCI_COMMAND);
    uint32_t hi  = cmd & 0xFFFF0000u;              /* status half: preserved */
    uint32_t low = (uint32_t)((uint16_t)cmd);
    low &= (uint32_t)~(PCI_CMD_IO | PCI_CMD_MEM | PCI_CMD_MASTER);
    low |= want;
    pci_cfg_write32(bus, dev, fn, PCI_COMMAND, hi | low);
    return 0;
}

int iodev_allows_irq(const struct io_device *d, int irq) {
    if (!d || irq < 0 || irq > 31) return 0;
    return (d->irq_mask & (1u << irq)) ? 1 : 0;
}
