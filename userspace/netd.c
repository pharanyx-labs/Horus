#include "syscall.h"

/*
 * netd -- an Intel e1000 network driver in ring 3, holding one device capability.
 *
 * Roadmap 2.6's driver, and since VT-d landed it is also **S45's witness**: the
 * proof that a device reaches exactly the memory its driver mapped for it, and
 * nothing else.
 *
 * Its entire authority is a CAP_IO_DEVICE naming the NIC plus one delegated
 * untyped region it builds its descriptor rings from. No console capability, no
 * filesystem, no boot modules, nothing ambient. Compromise it and you have
 * compromised a task that can drive one network card, within the reach its own
 * mappings define.
 *
 * WHY e1000 AND NOT virtio-net, WHICH THIS DRIVER USED TO BE.
 *
 * The first version drove legacy virtio-net over its I/O BAR: fewer registers,
 * no MMIO, and no PCI capability-list walk through configuration space (which
 * ring 3 deliberately cannot read). It worked, and it was **unable to witness the
 * property this driver now exists for**.
 *
 * Paravirtual virtio devices access guest memory DIRECTLY. They sit on the near
 * side of the IOMMU unless the device negotiates VIRTIO_F_ACCESS_PLATFORM
 * (feature bit 33), and a *legacy* virtio device has no such bit -- its feature
 * register is 32 bits wide. QEMU says so outright when asked:
 *
 *     -device virtio-net-pci,iommu_platform=on:
 *     VIRTIO_F_IOMMU_PLATFORM was supported by neither legacy nor transitional device
 *
 * So under VT-d the old driver kept working with an EMPTY device address space,
 * and would have "passed" a gate that proved nothing -- a property stated,
 * enforced by real code, and bound to nothing. Measured 2026-08-28: translation
 * enabled (GSTS=0xC0000000), root table installed, zero faults recorded, and the
 * ARP exchange completing anyway.
 *
 * e1000 is a real PCI device model. Its DMA goes through the device's own
 * address space like any other bus master's, so the IOMMU applies to it and the
 * mapping calls below are load-bearing rather than decorative. It costs nothing
 * in realism either: this is the interface a physical 82540EM presents.
 *
 * WHAT THE DRIVER MUST NOW DO THAT IT DID NOT BEFORE. Every page the device
 * touches has to be mapped into its address space with SYS_DMA_ADDR -- both
 * descriptor rings and both buffer pools. Miss one and the device faults on it
 * and the ring simply never advances. That is the intended behaviour, and
 * NET_IOMMU_NO_MAP is the arm that demonstrates it.
 *
 * WHY IT POLLS. A PCI interrupt line cannot be delivered to ring 3 on this
 * machine: pic_init programs the 8259 master 0xFC, so IRQ 0/1 are the only
 * unmasked lines and the cascade is masked with them (docs/LIMITATIONS.md 2.13).
 * The driver polls its receive ring, bounded, and says so rather than waiting on
 * a notification that cannot arrive.
 */

/* ---- output ------------------------------------------------------------- */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }
static void wr_hex2(unsigned v) {
    static const char h[] = "0123456789abcdef";
    char b[2]; b[0] = h[(v >> 4) & 0xF]; b[1] = h[v & 0xF];
    sys_write(1, b, 2);
}

/* ---- e1000 registers, as byte offsets into BAR0 -------------------------- */

#define E1000_CTRL     0x0000
#define E1000_STATUS   0x0008
#define E1000_ICR      0x00C0   /* interrupt cause, read-to-clear */
#define E1000_IMC      0x00D8   /* interrupt mask clear */
#define E1000_IMS      0x00D0   /* interrupt mask set */

#define ICR_TXDW       (1u << 0)   /* transmit descriptor written back */
#define E1000_RCTL     0x0100
#define E1000_TCTL     0x0400
#define E1000_TIPG     0x0410
#define E1000_RDBAL    0x2800
#define E1000_RDBAH    0x2804
#define E1000_RDLEN    0x2808
#define E1000_RDH      0x2810
#define E1000_RDT      0x2818
#define E1000_TDBAL    0x3800
#define E1000_TDBAH    0x3804
#define E1000_TDLEN    0x3808
#define E1000_TDH      0x3810
#define E1000_TDT      0x3818
#define E1000_RAL0     0x5400   /* receive address low  (the MAC) */
#define E1000_RAH0     0x5404   /* receive address high + valid bit */

#define CTRL_RST       (1u << 26)
#define CTRL_ASDE      (1u << 5)
#define CTRL_SLU       (1u << 6)   /* set link up */

#define RCTL_EN        (1u << 1)
#define RCTL_BAM       (1u << 15)  /* accept broadcast */
#define RCTL_SZ_2048   (0u << 16)
#define RCTL_SECRC     (1u << 26)  /* strip the Ethernet CRC */
#define RCTL_UPE       (1u << 3)   /* EXPERIMENT: unicast promiscuous */

#define TCTL_EN        (1u << 1)
#define TCTL_PSP       (1u << 3)   /* pad short packets */

#define RAH_AV         (1u << 31)  /* receive address valid */

#define TXD_CMD_EOP    (1u << 0)
#define TXD_CMD_IFCS   (1u << 1)   /* insert FCS */
#define TXD_CMD_RS     (1u << 3)   /* report status, so DD comes back */
#define TXD_STA_DD     (1u << 0)
#define RXD_STA_DD     (1u << 0)

/* e1000 descriptors are 16 bytes; the ring base must be 16-byte aligned and the
 * length a multiple of 128, both of which a whole page satisfies. */
struct tx_desc {
    unsigned long long addr;
    unsigned short     length;
    unsigned char      cso;
    unsigned char      cmd;
    unsigned char      status;
    unsigned char      css;
    unsigned short     special;
};
struct rx_desc {
    unsigned long long addr;
    unsigned short     length;
    unsigned short     checksum;
    unsigned char      status;
    unsigned char      errors;
    unsigned short     special;
};

/* ---- capability slots this task is endowed with ------------------------- */

#define NIC_SLOT      CAPSLOT_IO_DEVICE
#define UNTYPED_SLOT  CAPSLOT_UNTYPED
#define SLOT_RXRING   40
#define SLOT_TXRING   41
#define SLOT_RXBUF    42
#define SLOT_TXBUF    43
#define NOTIF_SLOT    CAPSLOT_NOTIFY   /* CAP_NOTIFICATION: the IRQ rendezvous */
#define IRQ_BADGE     0x0000E1E1u

#define VA_BAR     0x0000000100000000ULL   /* 4 GiB: the MMIO window */
#define VA_RXRING  0x0000000200000000ULL
#define VA_TXRING  0x0000000200010000ULL
#define VA_RXBUF   0x0000000200020000ULL
#define VA_TXBUF   0x0000000200030000ULL

#define RING_PAGES  1
#define RING_BYTES  4096
#define NDESC       (RING_BYTES / 16)

#define RXBUF_COUNT 8
#define BUF_SIZE    2048
#define RXBUF_PAGES 4               /* 8 * 2048 = 16 KiB exactly */
#define TXBUF_PAGES 1

/* ---- the ARP exchange this driver is proved by -------------------------- */

#define ETH_P_ARP   0x0806
#define ARP_REQUEST 1
#define ARP_REPLY   2

/* QEMU's user-mode network is 10.0.2.0/24 with the gateway at 10.0.2.2 and the
 * guest conventionally at 10.0.2.15. Slirp answers ARP for the gateway
 * immediately and without any host configuration, which is what makes this a
 * deterministic gate rather than one that depends on a network being there. */
static const unsigned char OUR_IP[4] = { 10, 0, 2, 15 };
static const unsigned char GW_IP[4]  = { 10, 0, 2, 2 };

static unsigned char mac[6];

static void put16be(unsigned char *p, unsigned v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }

/* ---- small helpers ------------------------------------------------------ */

static void zero(void *p, unsigned n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    for (unsigned i = 0; i < n; i++) b[i] = 0;
}
static void copy(void *d, const void *s, unsigned n) {
    unsigned char *a = (unsigned char *)d; const unsigned char *b = (const unsigned char *)s;
    for (unsigned i = 0; i < n; i++) a[i] = b[i];
}
static int same(const void *a, const void *b, unsigned n) {
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    for (unsigned i = 0; i < n; i++) if (x[i] != y[i]) return 0;
    return 1;
}

/* MMIO accessors. `volatile` throughout: these are device registers, and the
 * compiler must not cache, reorder or elide a single access to them. */
static volatile unsigned char *bar;
static inline void mmio_w(unsigned off, unsigned int v) {
    *(volatile unsigned int *)(bar + off) = v;
}
static inline unsigned int mmio_r(unsigned off) {
    return *(volatile unsigned int *)(bar + off);
}

/* A settling delay by yielding. The e1000 reset needs one and this program has
 * no microsecond source; yields are coarse and generous, which is the right way
 * to err for a reset. */
static void settle(int rounds) { for (int i = 0; i < rounds; i++) sys_yield(); }

/* Retype one frame of `pages`, map it into OUR address space, and map it into
 * the DEVICE's address space, returning the address the device must be given.
 *
 * The second mapping is what is new since VT-d, and it is what makes the device's
 * reach exactly this set of frames. Under NET_IOMMU_NO_MAP the device mapping is
 * skipped and the device is handed an address it cannot reach -- which is how the
 * gate demonstrates that its address space really does start empty. */
static int frame_setup(unsigned slot, unsigned pages, unsigned long long va,
                       unsigned char **out_ptr, uint64_t *out_dma) {
    /* Three distinct failures, reported distinctly. A single "alloc failed"
     * marker cannot tell a kernel-memory shortage from a mapping refusal from an
     * IOMMU that would not take the mapping, and those want different fixes. */
    if (sys_retype_sized(UNTYPED_SLOT, 1, (int)slot, pages) != 1) return -1;
    if (sys_map_frame(slot, va, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) return -2;
    uint64_t dma = 0;
#ifdef NET_IOMMU_NO_MAP
    /* The address, withheld of its mapping: a number the device cannot reach. */
    if (sys_dma_addr_flags(NIC_SLOT, slot, &dma, DMA_ADDR_NO_MAP) != 0) return -3;
#else
    if (sys_dma_addr(NIC_SLOT, slot, &dma) != 0) return -3;
#endif
    *out_ptr = (unsigned char *)(unsigned long)va;
    *out_dma = dma;
    zero(*out_ptr, pages * 4096u);
    return 0;
}

void _start(void) {
    struct dev_info nic;
    struct tx_desc *txr;
    struct rx_desc *rxr;
    unsigned char *rxbuf, *txbuf, *rxring, *txring;
    uint64_t rxring_dma, txring_dma, rxbuf_dma, txbuf_dma;

    wr("NETD: begin\n");

    /* ---- 1. what device is this, and where are its registers? ----------- */
    if (sys_device_info(NIC_SLOT, &nic) != 0) {
        wr("NETTEST: FAIL device-info\n"); sys_exit();
    }
    if (nic.n_mmio == 0) { wr("NETTEST: FAIL no-mmio-bar\n"); sys_exit(); }

    unsigned long long bar_phys = 0;
    for (unsigned i = 0; i < nic.n_mmio; i++) {
        if ((nic.mmio[i].base & 0xFFFULL) == 0 && nic.mmio[i].len >= 0x6000) {
            bar_phys = nic.mmio[i].base; break;
        }
    }
    if (bar_phys == 0) { wr("NETTEST: FAIL no-aligned-bar\n"); sys_exit(); }

    /* ---- 2. decode + bus mastering -------------------------------------- */
    /* MEM rather than IO: an e1000's register file is memory-mapped. Bus
     * mastering is what lets it touch memory at all -- and under VT-d, what it
     * may then touch is exactly the mappings made below. */
    /* NET_NO_DECODE withholds every decode bit: the device then stops answering
     * its own BAR and the register file reads back as floating bus. It is the arm
     * for SYS_DEVICE_ENABLE writing the one configuration-space register ring 3
     * can reach. Both call sites below carry it -- the rewrite from virtio to
     * e1000 dropped the ifdef once, the arm silently stopped being wired, and the
     * gate went green for the wrong reason. */
#ifdef NET_NO_DECODE
    if (sys_device_enable(NIC_SLOT, 0) != 0) {
#else
    if (sys_device_enable(NIC_SLOT, DEV_ENABLE_MEM | DEV_ENABLE_BUSMASTER) != 0) {
#endif
        wr("NETTEST: FAIL device-enable\n"); sys_exit();
    }

    /* One page at a time, because SYS_MAP_PHYS maps one named frame per call --
     * a device mapping is never a range the caller can stretch. Five pages cover
     * everything this driver touches: the control/interrupt block at 0x0000, the
     * receive and transmit register blocks at 0x2800/0x3800, and the receive
     * address registers at 0x5400. */
    static const unsigned long long bar_pages[] = { 0x0000, 0x1000, 0x2000, 0x3000, 0x5000 };
    for (unsigned i = 0; i < sizeof(bar_pages)/sizeof(bar_pages[0]); i++) {
        if (sys_map_phys(NIC_SLOT, bar_phys + bar_pages[i],
                         VA_BAR + bar_pages[i], 4096, MAP_PHYS_WRITE) != 0) {
            wr("NETTEST: FAIL map-bar\n"); sys_exit();
        }
    }
    bar = (volatile unsigned char *)(unsigned long)VA_BAR;

    /* ---- 3. reset, then bring the link up ------------------------------- */
    mmio_w(E1000_IMC, 0xFFFFFFFFu);          /* mask every interrupt: we poll */
    mmio_w(E1000_CTRL, mmio_r(E1000_CTRL) | CTRL_RST);
    settle(50);
    mmio_w(E1000_IMC, 0xFFFFFFFFu);          /* the reset re-enables them */
    mmio_w(E1000_CTRL, mmio_r(E1000_CTRL) | CTRL_SLU | CTRL_ASDE);
    settle(20);

    /* Re-assert decode and bus mastering AFTER the device reset.
     *
     * QEMU's e1000 checks the PCI bus-master bit on the RECEIVE path only
     * (e1000x_rx_ready), never on transmit -- so a driver that loses the bit
     * transmits perfectly and silently receives nothing, which is exactly the
     * shape this cost a morning to find. Traced: "e1000x_rx_can_recv_disabled
     * link_up: 1, rx_enabled 0, pci_master 0".
     *
     * Re-asserting is cheap, idempotent, and the honest response to "a device
     * reset may clear state the driver set before it". */
#ifdef NET_NO_DECODE
    if (sys_device_enable(NIC_SLOT, 0) != 0) {
#else
    if (sys_device_enable(NIC_SLOT, DEV_ENABLE_MEM | DEV_ENABLE_BUSMASTER) != 0) {
#endif
        wr("NETTEST: FAIL device-enable-post-reset\n"); sys_exit();
    }

    /* ---- 4. the MAC ------------------------------------------------------
     * QEMU pre-loads RAL0/RAH0 from the device's configured address, so there is
     * no EEPROM read to do. AV must be set for the receiver to accept unicast to
     * this address; assert rather than assume, because a zero MAC here would make
     * every later failure look like a network problem. */
    unsigned int ral = mmio_r(E1000_RAL0), rah = mmio_r(E1000_RAH0);
    if (!(rah & RAH_AV)) { wr("NETTEST: FAIL mac-not-valid\n"); sys_exit(); }
    mac[0] = (unsigned char)(ral      ); mac[1] = (unsigned char)(ral >>  8);
    mac[2] = (unsigned char)(ral >> 16); mac[3] = (unsigned char)(ral >> 24);
    mac[4] = (unsigned char)(rah      ); mac[5] = (unsigned char)(rah >>  8);

    /* ---- 5. rings and buffers, mapped for us AND for the device ---------- */
    int rc = frame_setup(SLOT_TXRING, RING_PAGES, VA_TXRING, &txring, &txring_dma);
    if (rc != 0) {
        if (rc == -1)      wr("NETTEST: FAIL txring-retype\n");
        else if (rc == -2) wr("NETTEST: FAIL txring-map\n");
        else               wr("NETTEST: FAIL txring-dma\n");
        sys_exit();
    }
    if (frame_setup(SLOT_RXRING, RING_PAGES, VA_RXRING, &rxring, &rxring_dma) != 0) {
        wr("NETTEST: FAIL rxring-alloc\n"); sys_exit();
    }
    if (frame_setup(SLOT_RXBUF, RXBUF_PAGES, VA_RXBUF, &rxbuf, &rxbuf_dma) != 0) {
        wr("NETTEST: FAIL rxbuf-alloc\n"); sys_exit();
    }
    if (frame_setup(SLOT_TXBUF, TXBUF_PAGES, VA_TXBUF, &txbuf, &txbuf_dma) != 0) {
        wr("NETTEST: FAIL txbuf-alloc\n"); sys_exit();
    }
    txr = (struct tx_desc *)txring;
    rxr = (struct rx_desc *)rxring;

    /* ---- 6. receive ring: buffers first, then hand it to the device ------ */
    for (unsigned i = 0; i < RXBUF_COUNT; i++) {
        rxr[i].addr   = rxbuf_dma + (unsigned long long)i * BUF_SIZE;
        rxr[i].status = 0;
    }
    mmio_w(E1000_RDBAL, (unsigned int)(rxring_dma & 0xFFFFFFFFu));
    mmio_w(E1000_RDBAH, (unsigned int)(rxring_dma >> 32));
    mmio_w(E1000_RDLEN, RING_BYTES);
    mmio_w(E1000_RDH, 0);
    mmio_w(E1000_RDT, RXBUF_COUNT);      /* everything up to here is the device's */
    mmio_w(E1000_RCTL, RCTL_EN | RCTL_BAM | RCTL_UPE | RCTL_SZ_2048 | RCTL_SECRC);

    /* ---- 7. transmit ring ------------------------------------------------ */
    mmio_w(E1000_TDBAL, (unsigned int)(txring_dma & 0xFFFFFFFFu));
    mmio_w(E1000_TDBAH, (unsigned int)(txring_dma >> 32));
    mmio_w(E1000_TDLEN, RING_BYTES);
    mmio_w(E1000_TDH, 0);
    mmio_w(E1000_TDT, 0);
    mmio_w(E1000_TIPG, 0x0060200A);       /* the 82540EM's documented IPG */
    mmio_w(E1000_TCTL, TCTL_EN | TCTL_PSP | (0x0F << 4) | (0x40 << 12));

    /* ---- 8. an ARP request for the gateway ------------------------------ */
    zero(txbuf, BUF_SIZE);
    unsigned char *eth = txbuf;
    for (int i = 0; i < 6; i++) eth[i] = 0xFF;            /* broadcast */
    copy(eth + 6, mac, 6);
    put16be(eth + 12, ETH_P_ARP);
    unsigned char *arp = eth + 14;
    put16be(arp + 0, 1);            /* hardware type: Ethernet */
    put16be(arp + 2, 0x0800);       /* protocol type: IPv4     */
    arp[4] = 6; arp[5] = 4;
    put16be(arp + 6, ARP_REQUEST);
    copy(arp + 8, mac, 6);
    copy(arp + 14, OUR_IP, 4);
    zero(arp + 18, 6);
    copy(arp + 24, GW_IP, 4);

    /* 60 bytes is the Ethernet minimum without FCS. TCTL_PSP would pad for us,
     * but padding here keeps this correct against hardware that does not. */
    txr[0].addr   = txbuf_dma;
    txr[0].length = 60;
    txr[0].cmd    = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
    txr[0].status = 0;
    mmio_w(E1000_TDT, 1);                 /* the write that starts the transmit */

    /* ---- THIS IS THE WITNESS -------------------------------------------
     *
     * DD is written back into the descriptor BY THE DEVICE, so waiting for it
     * proves a complete DMA round trip through the IOMMU, in both directions:
     *
     *   - the device READ the descriptor ring, at rxring/txring_dma, to find the
     *     descriptor at all;
     *   - it READ the packet buffer, at txbuf_dma, to fetch 60 bytes to send;
     *   - it WROTE the status byte back into the ring.
     *
     * Every one of those addresses was mapped into this device's address space
     * by SYS_DMA_ADDR and by nothing else. The device's address space starts
     * EMPTY, so without those mappings none of the three accesses can land --
     * which is exactly what NET_IOMMU_NO_MAP demonstrates: same driver, same
     * device, mappings withheld, and DD never arrives.
     *
     * That is the whole of S45. It does not depend on there being a network at
     * the other end of the wire, on the emulator's receive path, or on anything
     * this program cannot observe directly -- which is why the PASS is printed
     * here, and not after the ARP reply below. */
    int sent = 0;
    for (long i = 0; i < 200000L && !sent; i++) {
        if (txr[0].status & TXD_STA_DD) { sent = 1; break; }
        sys_yield();
    }
    if (!sent) { wr("NETTEST: FAIL dma-never-completed\n"); for (;;) sys_yield(); }

    wr("NETTEST: PASS\n");

    /* ---- 9. route this device's interrupt to us, and service it ---------
     *
     * The line comes from SYS_DEVICE_INFO -- firmware decides it, so a driver
     * that hardcoded one would be subscribing to whatever happened to be there.
     * SYS_IRQ_REGISTER refuses a line the named device does not declare (S43),
     * and unmasking it at the PIC is that capability taking effect in hardware:
     * until 2026-08-28 no PCI line was unmasked at all and this could not have
     * been delivered whatever a driver held.
     *
     * Deliberately AFTER the DMA witness above, so the two properties fail
     * separately: an interrupt that never arrives leaves `NETTEST: PASS` standing
     * and only `IRQ PASS` missing. The transmit has already completed, so TXDW is
     * pending in ICR and enabling IMS raises the line at once. */
    int irq = -1;
    for (int i = 0; i < 16; i++) if (nic.irq_mask & (1u << i)) { irq = i; break; }
    if (irq < 0) { wr("NETTEST: FAIL no-irq-line\n"); sys_exit(); }

    if (sys_irq_register(NIC_SLOT, (uint32_t)irq, NOTIF_SLOT, IRQ_BADGE) != 0) {
        wr("NETTEST: FAIL irq-register\n"); sys_exit();
    }
    mmio_w(E1000_IMS, ICR_TXDW);      /* interrupt on transmit completion */


    /* ---- the interrupt, and the acknowledgement it requires ---------------
     *
     * The transmit above raises TXDW. The kernel masks the line, notifies us, and
     * leaves it masked -- so servicing the device and calling SYS_IRQ_ACK is not
     * politeness, it is the only way this device ever interrupts again. A driver
     * that skipped the ack would simply go deaf, which is the fail-closed shape:
     * a broken driver costs its own hardware and not the machine.
     *
     * Bounded, like every wait here: it decides how long a failure takes to say
     * so. sys_wait_notify returns immediately when this is the only runnable task
     * (the kernel has nothing to switch to), so this is a poll of the badge. */
    uint32_t badge = 0;
    for (long i = 0; i < 300000L && badge == 0; i++) {
        if (sys_wait_notify(NOTIF_SLOT, &badge) != 0) break;
    }
    if (badge == IRQ_BADGE) {
        unsigned int cause = mmio_r(E1000_ICR);   /* read-to-clear: service it */
        if (sys_irq_ack(NIC_SLOT, (uint32_t)irq) != 0) {
            wr("NETTEST: FAIL irq-ack\n"); for (;;) sys_yield();
        }
        wr("NETD: irq serviced and acknowledged");
        if (cause & ICR_TXDW) wr(" (txdw)");
        wr("\n");
        wr("NETTEST: IRQ PASS\n");
    } else {
        wr("NETTEST: FAIL no-irq\n"); for (;;) sys_yield();
    }

    /* ---- 9. and, best effort, the reply ---------------------------------
     *
     * NOT part of the gate. The receive path does not work against QEMU's e1000
     * yet and the reason is not known; see the RECEIVE note in the header. It is
     * left in because it is where the work resumes, and because the receive ring
     * being mapped is part of what the NET_IOMMU_NO_MAP arm withholds.
     *
     * Bounded, and the bound is a FAILURE budget: it decides how long this takes
     * to give up, and must stay inside the harness timeout. */
    int got = 0;
    unsigned tail = RXBUF_COUNT;
    /* Re-arm the tail before polling. Writing RDT is what tells the device fresh
     * descriptors are available, and it is also what makes an emulator release a
     * packet it queued while the ring looked empty. Harmless when nothing is
     * queued, and the difference between a working receive path and a silent one
     * when something is. */
    mmio_w(E1000_RDT, tail);
    for (long spin = 0; spin < 300000L && !got; spin++) {
        for (unsigned i = 0; i < RXBUF_COUNT && !got; i++) {
            if (!(rxr[i].status & RXD_STA_DD)) continue;

            unsigned char *f = rxbuf + (unsigned long)i * BUF_SIZE;
            unsigned len = rxr[i].length;
            if (len >= 42 && f[12] == 0x08 && f[13] == 0x06) {
                unsigned char *a = f + 14;
                if (a[6] == 0 && a[7] == ARP_REPLY && same(a + 14, GW_IP, 4)) {
                    wr("NETD: arp reply from 10.0.2.2 at ");
                    for (int k = 0; k < 6; k++) { if (k) wr(":"); wr_hex2(a[8 + k]); }
                    wr("\n");
                    got = 1;
                    break;
                }
            }
            /* Recycle the descriptor either way, so unrelated traffic cannot
             * fill the ring before the reply arrives. */
            rxr[i].status = 0;
            tail = (tail + 1) % NDESC;
            mmio_w(E1000_RDT, tail);
        }
        if (!got) sys_yield();
    }

    (void)mmio_r(E1000_ICR);     /* read-to-clear, so nothing is left asserted */

    if (!got) {
        /* Reception does not work against this device model yet, and that is a
         * DRIVER gap rather than a failure of the property above -- see the
         * RECEIVE note in the header comment and docs/LIMITATIONS.md 2.14. The
         * PASS has already been printed, because it is the DMA round trip that
         * witnesses S45 and that has completed by this point. */
        wr("NETD: no arp reply (receive path incomplete; LIMITATIONS 2.14)\n");
    }
    for (;;) sys_yield();
}