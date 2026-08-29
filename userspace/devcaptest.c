#include "syscall.h"

/*
 * DEVCAP_SELFTEST driver — the witness that a device capability names a DEVICE.
 *
 * The kernel (devcap_selftest) spawns this program holding TWO device
 * capabilities: the legacy platform device (VGA, the UARTs, the PS/2 controller,
 * the PIT) in CAPSLOT_IO_DEVICE, and the machine's PCI network controller in
 * CAPSLOT_IO_DEVICE_ALT. It also holds a CAP_NOTIFICATION and a CAP_CONSOLE,
 * neither of which is a device capability.
 *
 * WHAT IS BEING WITNESSED
 * -----------------------
 * Until 2026-08-28, CAP_IO_DEVICE was a type with no object: SYS_MAP_PHYS
 * consulted a compiled-in VGA allowlist, SYS_IOPORT_GRANT activated one
 * compiled-in console port set, and SYS_IRQ_REGISTER took any of a hardcoded pair
 * of IRQs. Holding ANY device capability was therefore holding the console. That
 * is finding [C-1]'s shape — an object named by a constant rather than by the
 * capability — and this probe is the negative conformance test whose absence let
 * it stand, in the same shape captest's IPC tests take.
 *
 * The suite is deliberately SYMMETRIC. Each capability is shown to reach its own
 * device's resource and to be refused the other's, in both directions:
 *
 *              platform cap        NIC cap
 *   VGA frame  maps (P3)           REFUSED (N1)
 *   NIC BAR    REFUSED (N2)        maps (P4)
 *   IRQ 1      (platform's own)    REFUSED (N3)
 *   COM1 port  reads (P5)          REFUSED (N6)
 *
 * N7 is separate: SYS_DEVICE_ENABLE's input validation, which is load-bearing
 * because it writes the only configuration-space register ring 3 can reach.
 *
 * One direction alone would not do it. "The NIC cap is refused the VGA" is
 * satisfied by a kernel that refuses everything, and P3/P4 are what rule that
 * out — they are the base arm of each pair, in the same call, on the same boot.
 *
 * A FAIL marker names which half broke, because the three control arms each break
 * exactly one: IO_DEVICE_OBJECT_UNCHECKED -> N1, IO_DEVICE_PORTS_GLOBAL -> N6,
 * IO_DEVICE_IRQ_UNCHECKED -> N3.
 */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }

#define PLATFORM_SLOT  CAPSLOT_IO_DEVICE       /* the legacy console hardware */
#define NIC_SLOT       CAPSLOT_IO_DEVICE_ALT   /* the PCI network controller  */
#define NOTIF_SLOT     CAPSLOT_NOTIFY          /* not a device capability     */
#define CONSOLE_SLOT   CAPSLOT_CONSOLE         /* not a device capability     */
#define EMPTY_SLOT     40                      /* nothing was ever put here   */

#define VGA_PADDR      0xB8000ULL
#define VGA_VADDR      0xB8000ULL              /* identity, as mapphystest does */
#define BAR_VADDR      0x0000000100000000ULL   /* 4 GiB: clear of image/heap/stack */

#define IRQ_KEYBOARD   1                       /* the PLATFORM device's line */
#define COM1_LSR       0x3FD                   /* a platform port: line status */
#define BADGE          0x0000D0E0u

/* Stage, so the fault handler can tell an expected #GP from an unexpected one.
 * The port half of the suite can only be observed by faulting: a denied in/out
 * traps, there is no return value to test, and a fault handler here cannot
 * resume the faulting instruction — so exactly ONE port fault is observable per
 * boot, and which one it is has to be chosen deliberately.
 *
 * The first arrangement tried read the NIC's OWN port after granting it, then a
 * console port. It detected the global-bitmap defect, but by the wrong half: with
 * one console bitmap loaded for every grant, the NIC's own port is the one that
 * is denied, so the probe died at `nic-own-port-faulted` and never reached the
 * read that would have shown the console's ports being handed over. A detector
 * that halts truncates its own evidence.
 *
 * So the pair is now console-port-before and console-port-after: read COM1 under
 * a PLATFORM grant (must succeed — a grant does confer its own device's ports),
 * then regrant to the NIC and read COM1 again (must fault — the grant followed
 * the capability). The positive that the NIC capability reaches its own device is
 * carried by P4, which maps its BAR, so nothing is lost by not reading its port. */
static volatile int stage = 0;

static inline unsigned char inb(unsigned short port) {
    unsigned char v;
    __asm__ volatile ("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

static void handler(void) {
    if (stage == 6)      wr("DEVCAPTEST: PASS\n");
    else if (stage == 5) wr("DEVCAPTEST: FAIL platform-own-port-faulted\n");
    else                 wr("DEVCAPTEST: FAIL unexpected-fault\n");
    for (;;) { sys_yield(); }
}

void _start(void) {
    struct dev_info plat, nic;

    if (sys_signal((uintptr_t)&handler) != 0) {
        wr("DEVCAPTEST: FAIL register\n"); sys_exit();
    }
    wr("DEVCAPTEST: begin\n");

    /* ---- P1/P2: each capability reports its OWN device ---------------------
     * SYS_DEVICE_INFO is how a driver learns the BARs firmware assigned it. It
     * is also what makes the rest of this test possible without hardcoding an
     * address that differs per machine — which is the same reason a real driver
     * needs it. */
    if (sys_device_info(PLATFORM_SLOT, &plat) != 0) {
        wr("DEVCAPTEST: FAIL platform-info\n"); sys_exit();
    }
    if (sys_device_info(NIC_SLOT, &nic) != 0) {
        wr("DEVCAPTEST: FAIL nic-info\n"); sys_exit();
    }
    if (plat.bdf != 0xFFFF) { wr("DEVCAPTEST: FAIL platform-is-pci\n"); sys_exit(); }
    if (nic.bdf == 0xFFFF || nic.vendor == 0) {
        wr("DEVCAPTEST: FAIL nic-not-pci\n"); sys_exit();
    }
    /* The two must be different devices, or nothing below distinguishes them. */
    if (nic.n_mmio == 0) { wr("DEVCAPTEST: FAIL nic-no-mmio\n"); sys_exit(); }
    if (nic.n_port == 0) { wr("DEVCAPTEST: FAIL nic-no-ports\n"); sys_exit(); }
    if (nic.irq_mask == 0) { wr("DEVCAPTEST: FAIL nic-no-irq\n"); sys_exit(); }

    /* A page-aligned page of the NIC's own MMIO, for P4/N2. */
    unsigned long long bar = 0;
    for (unsigned i = 0; i < nic.n_mmio && bar == 0; i++) {
        if ((nic.mmio[i].base & 0xFFFULL) != 0 || nic.mmio[i].len < 4096) continue;
        /* Skip the page holding the device's MSI-X vector table: it is refused to
         * every driver, capability or not (S48), so mapping it is not the
         * cross-device question this probe is asking. A real driver routes around
         * the same page for the same reason -- this is what that looks like. */
        for (unsigned long long p = nic.mmio[i].base;
             p + 4096 <= nic.mmio[i].base + nic.mmio[i].len; p += 4096) {
            if (nic.msix_table != 0 && p == nic.msix_table) continue;
            bar = p; break;
        }
    }
    if (bar == 0) { wr("DEVCAPTEST: FAIL nic-no-aligned-bar\n"); sys_exit(); }

    /* And while we are here: that page IS refused, to a capability that reaches
     * every other page of the same BAR. Checked on the NIC capability, which is
     * the strongest place to check it -- this task holds exactly the authority
     * that would otherwise permit the mapping. */
    if (nic.msix_table != 0 &&
        sys_map_phys(NIC_SLOT, nic.msix_table, BAR_VADDR + 0x10000, 4096,
                     MAP_PHYS_WRITE) == 0) {
        wr("DEVCAPTEST: FAIL nic-cap-mapped-msix-table\n"); sys_exit();
    }

    /* ---- N1: the NIC capability must NOT reach the console's framebuffer ---
     * THE defect. Under IO_DEVICE_OBJECT_UNCHECKED this succeeds, because the
     * object is not consulted and 0xB8000 is on the compiled-in allowlist. */
    if (sys_map_phys(NIC_SLOT, VGA_PADDR, VGA_VADDR, 4096, MAP_PHYS_WRITE) == 0) {
        wr("DEVCAPTEST: FAIL nic-cap-mapped-vga\n"); sys_exit();
    }

    /* ---- N2: and the platform capability must not reach the NIC's BAR ------
     * The same property from the other side. Without it the suite would pass on
     * a kernel that simply kept the old allowlist: everything off it refused,
     * everything on it allowed, whatever capability you hold. */
    if (sys_map_phys(PLATFORM_SLOT, bar, BAR_VADDR, 4096, MAP_PHYS_WRITE) == 0) {
        wr("DEVCAPTEST: FAIL platform-cap-mapped-nic-bar\n"); sys_exit();
    }

    /* ---- N4/N5: a capability of the wrong type, and an empty slot ---------- */
    if (sys_map_phys(CONSOLE_SLOT, VGA_PADDR, VGA_VADDR, 4096, MAP_PHYS_WRITE) == 0) {
        wr("DEVCAPTEST: FAIL nondevice-cap-mapped\n"); sys_exit();
    }
    if (sys_map_phys(EMPTY_SLOT, VGA_PADDR, VGA_VADDR, 4096, MAP_PHYS_WRITE) == 0) {
        wr("DEVCAPTEST: FAIL empty-slot-mapped\n"); sys_exit();
    }
    if (sys_device_info(CONSOLE_SLOT, &plat) == 0) {
        wr("DEVCAPTEST: FAIL nondevice-cap-info\n"); sys_exit();
    }

    /* ---- P3/P4: each capability DOES reach its own device ------------------
     * The base arm. A kernel that refuses every request satisfies every negative
     * above; these two are what it cannot also satisfy. */
    if (sys_map_phys(PLATFORM_SLOT, VGA_PADDR, VGA_VADDR, 4096, MAP_PHYS_WRITE) != 0) {
        wr("DEVCAPTEST: FAIL platform-cap-refused-vga\n"); sys_exit();
    }
    if (sys_map_phys(NIC_SLOT, bar, BAR_VADDR, 4096, MAP_PHYS_READ) != 0) {
        wr("DEVCAPTEST: FAIL nic-cap-refused-own-bar\n"); sys_exit();
    }

    /* ---- N7: SYS_DEVICE_ENABLE refuses what it cannot mean ----------------
     *
     * It writes the one configuration-space register ring 3 can reach, so its
     * input validation is load-bearing rather than tidy: the BARs live in the
     * same 256 bytes, and a driver that could reach them could move its own BAR
     * onto another device's registers and make every check above a lie. Unknown
     * bits are REFUSED, not masked away — masking would let a caller ask for
     * something and be told yes while getting something else. */
    if (sys_device_enable(NIC_SLOT, 0xFFu) == 0) {
        wr("DEVCAPTEST: FAIL device-enable-took-unknown-bits\n"); sys_exit();
    }
    /* The platform device has no configuration space at all. Succeeding here
     * would report a decode that was never set, and a driver would then wait on
     * hardware that is not listening and blame its own ring buffers. */
    if (sys_device_enable(PLATFORM_SLOT, DEV_ENABLE_IO) == 0) {
        wr("DEVCAPTEST: FAIL platform-device-enabled\n"); sys_exit();
    }
    if (sys_device_enable(CONSOLE_SLOT, DEV_ENABLE_IO) == 0) {
        wr("DEVCAPTEST: FAIL nondevice-cap-enabled\n"); sys_exit();
    }

    /* ---- N3: the NIC capability must not route the keyboard's interrupt ----
     * An interrupt line is a device's, not a type's. Under
     * IO_DEVICE_IRQ_UNCHECKED this succeeds and the NIC driver is subscribed to
     * the console's keyboard. */
    if (sys_irq_register(NIC_SLOT, IRQ_KEYBOARD, NOTIF_SLOT, BADGE) == 0) {
        wr("DEVCAPTEST: FAIL nic-cap-took-platform-irq\n"); sys_exit();
    }

    /* ---- N6: nor may it be granted the console's ports ---------------------
     * The same port, twice, under two different grants — which is what makes the
     * second read's fault mean "the grant followed the capability" rather than
     * "port I/O does not work here".
     *
     * Grant the PLATFORM device: COM1 must read (stage 5; a fault here says the
     * grant mechanism itself is broken, and is a failure, not a pass). Then
     * regrant to the NIC: the same COM1 must now #GP, because a grant is to ONE
     * device and the NIC declares no such port (stage 6 — the fault IS the pass).
     *
     * Under IO_DEVICE_PORTS_GLOBAL the regrant loads the console's bitmap anyway,
     * the second read succeeds, and control falls through to the FAIL below. */
    if (sys_ioport_grant(PLATFORM_SLOT) != 0) {
        wr("DEVCAPTEST: FAIL platform-grant-refused\n"); sys_exit();
    }
    stage = 5;
    (void)inb(COM1_LSR);

    if (sys_ioport_grant(NIC_SLOT) != 0) {
        wr("DEVCAPTEST: FAIL nic-grant-refused\n"); sys_exit();
    }
    stage = 6;
    (void)inb(COM1_LSR);

    wr("DEVCAPTEST: FAIL nic-cap-got-console-ports\n");
    for (;;) sys_yield();
}
