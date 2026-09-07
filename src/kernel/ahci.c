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
 * This file is the first half of answering it, and deliberately only the first
 * half: it FINDS the controller and REPORTS what the hardware says is attached.
 * It issues no commands, allocates nothing, and takes no interrupt. A driver
 * that reads and writes blocks is a separate change on top of this one, and
 * keeping them apart means the risky part -- talking to a real HBA -- can be
 * wrong on its own without a half-written driver in the tree to explain it.
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
static const struct io_device *find_ahci_controller(void) {
    uint32_t n = iodev_total();
    for (uint32_t i = 0; i < n; i++) {
        const struct io_device *d = iodev_get(i);
        if (!d || !d->present) continue;
        if ((d->classcode >> 8) != 0x0106u) continue;   /* class:subclass */
        if ((d->classcode & 0xFFu) != 0x01u) continue;  /* prog-if: AHCI  */
        return d;
    }
    return NULL;
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
    const struct io_device *d = find_ahci_controller();
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

    ensure_ahci_abar_mapped(NULL, abar);

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
    }

    print("ahci: ");
    print_decimal(g_ahci_devices);
    print(" SATA disk(s) attached; no driver yet, so none is usable\n");
#endif /* AHCI_PROBE_ABSENT */
}
