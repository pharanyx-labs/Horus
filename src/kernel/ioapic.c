/* ioapic.c -- routing interrupts through the I/O APIC instead of the 8259.
 *
 * WHY MOVE OFF THE PIC
 * --------------------
 * The 8259 pair works, and until now it was enough: S46 delivers a PCI interrupt
 * to a ring-3 driver through it, masked until acknowledged. What it cannot do is
 * be REMAPPED. VT-d's interrupt-remapping half applies to interrupts that arrive
 * as messages -- from an I/O APIC or as MSI -- and not to the 8259's direct
 * delivery, so a machine on the PIC has a DMA-confined device (S45) whose
 * interrupts are still unmediated. This file is the prerequisite for closing
 * that, and it is worth being precise that on its own it closes nothing: a
 * device today can only assert the INTx line firmware assigned it, so the gap is
 * narrow. It becomes wide the moment MSI exists, because an MSI is a memory
 * write and a device that can DMA anywhere can write any vector.
 *
 * WHAT THIS CHANGES, AND WHAT IT DELIBERATELY DOES NOT
 * ----------------------------------------------------
 * Routing only. Every property S46 states is preserved exactly: a line is
 * unmasked when a capability is accepted for it, masked again when it fires,
 * unmasked by SYS_IRQ_ACK, and masked when its driver dies. Those operations now
 * write a redirection-table entry instead of a PIC mask register, and idt.c calls
 * the same four functions either way.
 *
 * The PIC is not left enabled alongside. Both controllers driving the same
 * vectors would deliver every interrupt twice, and a spurious 8259 interrupt
 * would arrive on a vector the I/O APIC also owns -- so the PIC is fully masked
 * and left that way. It is still INITIALISED, because its vector remap (to 32+)
 * is what keeps a spurious interrupt off the exception vectors.
 *
 * GSIs ARE NOT ISA IRQ NUMBERS, which is the part that bites. Firmware may route
 * ISA IRQ n to any global system interrupt, and on QEMU's q35 the PIT sits on
 * GSI 2 rather than GSI 0. The MADT's Interrupt Source Overrides say where each
 * one went; acpi_find_ioapic reads them and gsi_for_irq() applies them. A kernel
 * that assumes identity programs the wrong pin for the timer and never ticks.
 */
#include "kernel.h"

#define IOAPIC_REGSEL   0x00
#define IOAPIC_REGWIN   0x10

#define IOAPIC_ID       0x00
#define IOAPIC_VER      0x01
#define IOAPIC_REDTBL   0x10   /* two 32-bit registers per pin */

/* Redirection-table entry bits (low word). */
#define RED_MASKED      (1u << 16)
#define RED_LEVEL       (1u << 15)   /* trigger mode: 1 = level, 0 = edge */
#define RED_ACTIVE_LOW  (1u << 13)   /* polarity:     1 = low,   0 = high */

/* MADT Interrupt Source Override flag encodings. */
#define ISO_POLARITY_MASK   0x3
#define ISO_POLARITY_LOW    0x3
#define ISO_TRIGGER_MASK    0xC
#define ISO_TRIGGER_LEVEL   0xC

static volatile uint8_t *ioapic_regs;
static struct acpi_ioapic_info ioapic_info;
static uint32_t ioapic_pins;
static int ioapic_ready;

static uint32_t ioapic_read(uint32_t reg) {
    *(volatile uint32_t *)(ioapic_regs + IOAPIC_REGSEL) = reg;
    return *(volatile uint32_t *)(ioapic_regs + IOAPIC_REGWIN);
}

static void ioapic_write(uint32_t reg, uint32_t val) {
    *(volatile uint32_t *)(ioapic_regs + IOAPIC_REGSEL) = reg;
    *(volatile uint32_t *)(ioapic_regs + IOAPIC_REGWIN) = val;
}

int ioapic_active(void) { return ioapic_ready; }

/* Which global system interrupt carries legacy ISA IRQ `irq`. Identity unless the
 * firmware said otherwise -- see the header comment on why assuming identity
 * costs you the timer. */
static uint32_t gsi_for_irq(int irq) {
    if (irq < 0 || irq > 15) return (uint32_t)irq;
    return ioapic_info.iso_gsi[irq];
}

/* The pin on THIS unit that a GSI lands on. One I/O APIC is assumed, which is
 * true of every machine this kernel targets; a GSI below this unit's base or
 * past its pin count belongs to a unit that does not exist here, and is refused
 * rather than wrapped onto a pin that does. */
static int pin_for_gsi(uint32_t gsi) {
    if (gsi < ioapic_info.gsi_base) return -1;
    uint32_t pin = gsi - ioapic_info.gsi_base;
    if (pin >= ioapic_pins) return -1;
    return (int)pin;
}

/* Program one pin's redirection entry, or mask it.
 *
 * The high word carries the destination APIC id; the low word the vector, the
 * delivery mode (0 = fixed), polarity, trigger mode and the mask bit.
 *
 * THE MASK IS WRITTEN FIRST AND THE HIGH WORD BEFORE THE LOW. An entry is two
 * separate 32-bit writes, and the unit may deliver on the strength of a
 * half-written entry: setting the destination while the vector still holds a
 * previous pin's value is a real interrupt to the wrong handler. Masking first
 * makes the window unreachable, exactly as the VT-d context entry writes its high
 * word before its present bit. */
static void ioapic_program(int pin, uint8_t vector, int level, int active_low,
                           int masked) {
    uint32_t reg = IOAPIC_REDTBL + (uint32_t)pin * 2;

    ioapic_write(reg, RED_MASKED);                      /* mask before touching */
    ioapic_write(reg + 1, 0u << 24);                    /* destination: APIC 0 */

    uint32_t low = vector;
    if (level)      low |= RED_LEVEL;
    if (active_low) low |= RED_ACTIVE_LOW;
    if (masked)     low |= RED_MASKED;
    ioapic_write(reg, low);
}

/* Route legacy IRQ `irq` to vector 32+irq, masked or not.
 *
 * TRIGGER MODE COMES FROM THE FIRMWARE where it said, and from the ISA/PCI
 * convention where it did not: ISA IRQs are edge-triggered active-high, PCI INTx
 * lines are level-triggered active-low. Getting this wrong is not cosmetic -- an
 * edge-programmed level line delivers once and then never again, because the
 * line stays asserted and there is no second edge, which looks exactly like a
 * driver that stopped working. */
int ioapic_set_irq(int irq, int masked) {
    if (!ioapic_ready) return -1;
    if (irq < 0 || irq > 15) return -1;

    int pin = pin_for_gsi(gsi_for_irq(irq));
    if (pin < 0) return -1;

    uint16_t flags = ioapic_info.iso_flags[irq];
    int level, active_low;

    if ((flags & ISO_TRIGGER_MASK) != 0) {
        /* Firmware stated it: believe firmware. */
        level = ((flags & ISO_TRIGGER_MASK) == ISO_TRIGGER_LEVEL);
    } else {
        /* Firmware said nothing, so fall back on what the line IS. The classic
         * ISA sources are edge-triggered active-high; everything else on a modern
         * machine reaching a low GSI is a PCI INTx line, which is level-triggered
         * active-low. Properly this comes from the ACPI _PRT, which needs an AML
         * interpreter this kernel does not have and should not grow for it.
         *
         * The direction of a wrong guess is worth knowing. An edge-programmed
         * LEVEL line fires exactly once and then never again -- the line stays
         * asserted, so there is no second edge -- which looks precisely like a
         * driver that stopped working rather than like a misprogrammed pin. That
         * is the failure this heuristic exists to avoid, and it is why anything
         * not obviously ISA is assumed level. */
        switch (irq) {
        case 0: case 1: case 2: case 8: case 13:
            level = 0; break;                 /* PIT, PS/2, cascade, RTC, FPU */
        default:
            level = 1; break;                 /* assume PCI INTx */
        }
    }

    if ((flags & ISO_POLARITY_MASK) != 0)
        active_low = ((flags & ISO_POLARITY_MASK) == ISO_POLARITY_LOW);
    else
        active_low = level;                   /* level => PCI => active low */

    ioapic_program(pin, (uint8_t)(32 + irq), level, active_low, masked);
    return 0;
}

/* Bring the unit up with EVERY pin masked.
 *
 * Masked-by-default is the same decision the IOMMU's empty address space is: the
 * machine starts unable to deliver anything nobody has asked for, and a
 * DELEGATABLE line becomes live only when a capability is accepted for it. The
 * alternative -- unmask the legacy set at boot and rely on registration to decide
 * who is notified -- would make delivery ambient again, which is what
 * LIMITATIONS 2.13 was about.
 *
 * The two exceptions are the kernel's own: see the note at the unmask below.
 *
 * Returns 0 on success. A machine with no MADT I/O APIC entry leaves
 * ioapic_ready at 0 and every caller falls back to the 8259, which is the honest
 * degradation rather than a kernel that will not boot. */
int ioapic_init(void) {
    ioapic_ready = 0;

    if (acpi_find_ioapic(&ioapic_info) != 0) {
        kmsg_begin();
        print("ioapic: none in the MADT; interrupts stay on the 8259\n");
        return -1;
    }

    /* The register window is device MMIO above the physical pool, so it needs an
     * identity mapping of its own in every address space -- SYS_IRQ_ACK unmasks a
     * pin while running on the caller's cr3. Same treatment as the LAPIC, the TPM
     * and the VT-d register file. */
    ensure_ioapic_mapped(NULL, ioapic_info.base);
    ioapic_regs = (volatile uint8_t *)(uintptr_t)ioapic_info.base;

    ioapic_pins = ((ioapic_read(IOAPIC_VER) >> 16) & 0xFF) + 1;
    if (ioapic_pins == 0 || ioapic_pins > 240) {
        kmsg_begin();
        print("ioapic: implausible pin count; staying on the 8259\n");
        return -1;
    }

    for (uint32_t p = 0; p < ioapic_pins; p++)
        ioapic_write(IOAPIC_REDTBL + p * 2, RED_MASKED);

    ioapic_ready = 1;

    /* THE KERNEL'S OWN TWO LINES ARE NOT DELEGATABLE, and masking them was wrong.
     *
     * "Every pin starts masked" is the right rule for a line a driver may be
     * granted -- nothing should be deliverable that nobody asked for. It is the
     * wrong rule for the lines the KERNEL is the driver of. IRQ 0 is the
     * preemption tick: mask it and the scheduler never runs, which a cooperative
     * workload hides completely because every task yields anyway. IRQ 1 is the
     * in-kernel console reader, the fallback that exists for when no ring-3
     * console server owns the hardware.
     *
     * Found by `make smoke-preempt`, which timed out while `make smoke` passed --
     * exactly the gate that exists to catch a scheduler that has stopped
     * scheduling. Neither is delegatable authority: irq_notify_register can route
     * a NOTIFICATION for IRQ 0 to a driver that wants a periodic wake, but the
     * line itself belongs to the kernel and is not the driver's to take down. */
    ioapic_set_irq(0, 0);
    ioapic_set_irq(1, 0);

    kmsg_begin();
    print("ioapic: ");
    print_decimal((uint64_t)ioapic_pins);
    print(" pins; timer+keyboard live, every delegatable line masked until a capability is accepted\n");
    return 0;
}
