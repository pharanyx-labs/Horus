#include "syscall.h"

/*
 * netd -- a virtio-net driver in ring 3, holding one device capability.
 *
 * Roadmap 2.6's first half. This is the demonstration the architecture is for: a
 * network device driven entirely from an unprivileged address space, whose whole
 * authority is one `CAP_IO_DEVICE` naming one PCI function. It holds no console
 * capability, no filesystem capability, no untyped region beyond the one delegated
 * to it, and no ambient anything. Compromise it and you have compromised a task
 * that can drive a NIC.
 *
 * WHAT IT IS NOT, said first because a driver that looked confined and is not
 * would be worse than none. There is no IOMMU on this machine. The moment
 * DEV_ENABLE_BUSMASTER is set, this device can read and write ALL of physical
 * memory, and the descriptors telling it where to go are written by this program.
 * So the sentence "a network-stack compromise is contained to one address space"
 * is NOT yet true, and the capability is not what would make it true — an IOMMU
 * is. What the capability does establish is who may turn that on, and for which
 * device, which is the enforceable part and the part an IOMMU would complete.
 * SECURITY.md S44, docs/LIMITATIONS.md §2.12.
 *
 * WHY LEGACY VIRTIO. QEMU's default machine is i440fx, so `virtio-net-pci` is a
 * transitional device on a conventional PCI bus and its BAR0 is an I/O region
 * carrying the whole legacy register interface. That keeps this driver to port
 * I/O plus DMA and avoids the modern capability-list walk through configuration
 * space, which ring 3 deliberately cannot read (see src/kernel/pci.c). The one
 * thing legacy costs is that queue addresses are 32-bit page frame numbers, which
 * is why the frames this asks for have to live under 2^44 — they do: the untyped
 * arena is a few MiB inside the physical pool.
 *
 * WHY IT POLLS RATHER THAN WAITS ON ITS INTERRUPT. The IRQ->notification bridge
 * exists and is capability-gated (S43), and this device declares its line — but
 * the 8259 master is programmed `0xFC` at boot, so IRQ 0 and IRQ 1 are the only
 * lines unmasked and the cascade to the slave PIC is masked too. A PCI line
 * therefore cannot be DELIVERED today, whatever a driver holds. Unmasking one is
 * a change to the interrupt controller's global state rather than to any
 * capability, so it belongs in its own commit; docs/LIMITATIONS.md §2.13 records
 * it. Until then this driver polls the used ring, bounded, and says so rather
 * than pretending the wait is real.
 */

/* ---- output ------------------------------------------------------------- */

static unsigned slen(const char *s) { unsigned n = 0; while (s[n]) n++; return n; }
static void wr(const char *s) { sys_write(1, s, slen(s)); }
static void wr_hex2(unsigned v) {
    static const char h[] = "0123456789abcdef";
    char b[3]; b[0] = h[(v >> 4) & 0xF]; b[1] = h[v & 0xF]; b[2] = 0;
    sys_write(1, b, 2);
}

/* ---- port I/O (usable only after sys_ioport_grant) ---------------------- */

static inline void outb(unsigned short p, unsigned char v) {
    __asm__ volatile ("outb %0, %1" :: "a"(v), "Nd"(p));
}
static inline void outw(unsigned short p, unsigned short v) {
    __asm__ volatile ("outw %0, %1" :: "a"(v), "Nd"(p));
}
static inline void outl(unsigned short p, unsigned int v) {
    __asm__ volatile ("outl %0, %1" :: "a"(v), "Nd"(p));
}
static inline unsigned char inb(unsigned short p) {
    unsigned char v; __asm__ volatile ("inb %1, %0" : "=a"(v) : "Nd"(p)); return v;
}
static inline unsigned short inw(unsigned short p) {
    unsigned short v; __asm__ volatile ("inw %1, %0" : "=a"(v) : "Nd"(p)); return v;
}
static inline unsigned int inl(unsigned short p) {
    unsigned int v; __asm__ volatile ("inl %1, %0" : "=a"(v) : "Nd"(p)); return v;
}

/* ---- legacy virtio-net register file, as offsets from BAR0 -------------- */

#define VIRTIO_DEVICE_FEATURES  0x00   /* 32, RO */
#define VIRTIO_GUEST_FEATURES   0x04   /* 32, RW */
#define VIRTIO_QUEUE_PFN        0x08   /* 32, RW -- physical address >> 12 */
#define VIRTIO_QUEUE_SIZE       0x0C   /* 16, RO */
#define VIRTIO_QUEUE_SELECT     0x0E   /* 16, RW */
#define VIRTIO_QUEUE_NOTIFY     0x10   /* 16, RW */
#define VIRTIO_STATUS           0x12   /*  8, RW */
#define VIRTIO_ISR              0x13   /*  8, RO, clear-on-read */
#define VIRTIO_NET_CFG_MAC      0x14   /* device config, MSI-X disabled */

#define VIRTIO_STATUS_ACK       0x01
#define VIRTIO_STATUS_DRIVER    0x02
#define VIRTIO_STATUS_DRIVER_OK 0x04
#define VIRTIO_STATUS_FAILED    0x80

#define VIRTIO_NET_F_MAC        (1u << 5)

#define VRING_DESC_F_NEXT       1
#define VRING_DESC_F_WRITE      2

#define RX_QUEUE  0
#define TX_QUEUE  1

/* The one alignment legacy virtio fixes: the used ring starts on a 4 KiB
 * boundary measured from the queue's own base. */
#define VRING_ALIGN 4096

struct vring_desc {
    unsigned long long addr;
    unsigned int       len;
    unsigned short     flags;
    unsigned short     next;
};
struct vring_used_elem { unsigned int id; unsigned int len; };

/* ---- capability slots this task is endowed with ------------------------- */

#define NIC_SLOT      CAPSLOT_IO_DEVICE
#define UNTYPED_SLOT  CAPSLOT_UNTYPED
#define SLOT_RXRING   40
#define SLOT_TXRING   41
#define SLOT_RXBUF    42
#define SLOT_TXBUF    43

/* Virtual addresses to map the frames at. Well clear of the image (ASLR'd at
 * 16 GiB), the heap (16 MiB) and the stack. */
#define VA_RXRING  0x0000000200000000ULL
#define VA_TXRING  0x0000000200010000ULL
#define VA_RXBUF   0x0000000200020000ULL
#define VA_TXBUF   0x0000000200030000ULL

/* Queue size 256 is what QEMU reports and legacy virtio gives a driver no way to
 * change it -- the register is read-only. Three pages covers it:
 *   desc  16*256                        = 4096
 *   avail 6 + 2*256                     =  518  -> padded to the 4 KiB boundary
 *   used  6 + 8*256                     = 2054
 * The driver refuses any other size rather than computing a layout it has not
 * been checked against. */
#define QSZ        256
#define RING_PAGES 3

#define RXBUF_COUNT 8
#define BUF_SIZE    2048            /* virtio-net header + a 1518-byte frame */
#define RXBUF_PAGES 4               /* 8 * 2048 = 16 KiB exactly */
#define TXBUF_PAGES 1

/* virtio-net's per-buffer header. 10 bytes without MRG_RXBUF, which is why the
 * feature is deliberately not negotiated: accepting it changes this struct and
 * the receive path with it, for a throughput win a conformance driver has no use
 * for. */
#define NET_HDR_LEN 10

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

/* One queue's worth of state: where its ring is in our address space, and where
 * the DEVICE sees it. The two are unrelated numbers and conflating them is the
 * mistake NET_DMA_ADDR_VIRTUAL reproduces. */
struct queue {
    unsigned char     *base;      /* our mapping */
    uint64_t           dma;       /* the device's view */
    struct vring_desc *desc;
    unsigned short    *avail_flags, *avail_idx, *avail_ring;
    unsigned short    *used_flags, *used_idx;
    struct vring_used_elem *used_ring;
    unsigned short     last_used;
};

static void queue_layout(struct queue *q, unsigned char *base, uint64_t dma) {
    q->base = base;
    q->dma  = dma;
    q->desc = (struct vring_desc *)base;
    unsigned char *avail = base + 16u * QSZ;
    q->avail_flags = (unsigned short *)avail;
    q->avail_idx   = (unsigned short *)(avail + 2);
    q->avail_ring  = (unsigned short *)(avail + 4);
    unsigned long off = (unsigned long)(16u * QSZ) + 6u + 2u * QSZ;
    off = (off + (VRING_ALIGN - 1)) & ~(unsigned long)(VRING_ALIGN - 1);
    unsigned char *used = base + off;
    q->used_flags = (unsigned short *)used;
    q->used_idx   = (unsigned short *)(used + 2);
    q->used_ring  = (struct vring_used_elem *)(used + 4);
    q->last_used  = 0;
}

/* Retype one frame of `pages` from the delegated untyped region, map it, and ask
 * the kernel for the address the DEVICE will use to reach it.
 *
 * sys_dma_addr is the whole reason this driver needs a device capability for
 * something other than its registers: a descriptor holds a bus address, and ring
 * 3 has no other way to learn one. Under NET_DMA_ADDR_VIRTUAL the virtual address
 * is used instead -- which is a number, and looks like one, and is not where the
 * device will go. */
static int frame_setup(unsigned slot, unsigned pages, unsigned long long va,
                       unsigned char **out_ptr, uint64_t *out_dma) {
    if (sys_retype_sized(UNTYPED_SLOT, 1, (int)slot, pages) != 1) return -1;
    if (sys_map_frame(slot, va, CAP_RIGHT_READ | CAP_RIGHT_WRITE) != 0) return -2;
    uint64_t dma = 0;
    if (sys_dma_addr(NIC_SLOT, slot, &dma) != 0) return -3;
#ifdef NET_DMA_ADDR_VIRTUAL
    dma = va;
#endif
    *out_ptr = (unsigned char *)(unsigned long)va;
    *out_dma = dma;
    zero(*out_ptr, pages * 4096u);
    return 0;
}

void _start(void) {
    struct dev_info nic;
    struct queue rxq, txq;
    unsigned char *rxbuf, *txbuf;
    uint64_t rxbuf_dma, txbuf_dma, rxring_dma, txring_dma;
    unsigned char *rxring, *txring;

    wr("NETD: begin\n");

    /* ---- 1. what device is this, and where does it live? ---------------- */
    if (sys_device_info(NIC_SLOT, &nic) != 0) {
        wr("NETTEST: FAIL device-info\n"); sys_exit();
    }
    if (nic.n_port == 0) { wr("NETTEST: FAIL no-io-bar\n"); sys_exit(); }
    unsigned short io = (unsigned short)nic.port[0].base;

    /* ---- 2. decode + bus mastering, then the ports themselves ----------- */
    /* Bus mastering is the authority that matters and the one with no capability
     * bound on where it goes.
     *
     * MEASURED 2026-08-28, and it is why NET_NO_BUSMASTER is not a gate: with the
     * bus-master bit left CLEAR this driver still completes the whole exchange
     * under QEMU. The emulator does not enforce PCI bus-master enable for
     * virtio-net, so on this machine the bit is not what permits the DMA. It is
     * set anyway because a real NIC will not move a byte without it, and because
     * a driver that works by accident on an emulator is how a device that never
     * works on hardware ships. What IS observable here is the decode itself --
     * NET_NO_DECODE clears all three bits and the register file goes dead, which
     * is the arm that proves this syscall does something. */
#ifdef NET_NO_DECODE
    if (sys_device_enable(NIC_SLOT, 0) != 0) {
#elif defined(NET_NO_BUSMASTER)
    if (sys_device_enable(NIC_SLOT, DEV_ENABLE_IO) != 0) {
#else
    if (sys_device_enable(NIC_SLOT, DEV_ENABLE_IO | DEV_ENABLE_BUSMASTER) != 0) {
#endif
        wr("NETTEST: FAIL device-enable\n"); sys_exit();
    }
    if (sys_ioport_grant(NIC_SLOT) != 0) {
        wr("NETTEST: FAIL ioport-grant\n"); sys_exit();
    }

    /* ---- 3. reset and take ownership ------------------------------------ */
    outb(io + VIRTIO_STATUS, 0);
    (void)inb(io + VIRTIO_STATUS);
    outb(io + VIRTIO_STATUS, VIRTIO_STATUS_ACK);
    outb(io + VIRTIO_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    /* ---- 4. features: take the MAC, refuse everything else --------------
     * Every offload the device offers changes the shape of a buffer or the
     * meaning of the header. A driver that accepts a feature it does not
     * implement is a driver that misparses its own receive path, so the mask is
     * an allowlist of one. */
    unsigned int devf = inl(io + VIRTIO_DEVICE_FEATURES);
    if (!(devf & VIRTIO_NET_F_MAC)) { wr("NETTEST: FAIL no-mac-feature\n"); sys_exit(); }
    outl(io + VIRTIO_GUEST_FEATURES, VIRTIO_NET_F_MAC);

    for (int i = 0; i < 6; i++) mac[i] = inb((unsigned short)(io + VIRTIO_NET_CFG_MAC + i));

    /* ---- 5. rings and buffers ------------------------------------------- */
    if (frame_setup(SLOT_RXRING, RING_PAGES, VA_RXRING, &rxring, &rxring_dma) != 0) {
        wr("NETTEST: FAIL rxring-alloc\n"); sys_exit();
    }
    if (frame_setup(SLOT_TXRING, RING_PAGES, VA_TXRING, &txring, &txring_dma) != 0) {
        wr("NETTEST: FAIL txring-alloc\n"); sys_exit();
    }
    if (frame_setup(SLOT_RXBUF, RXBUF_PAGES, VA_RXBUF, &rxbuf, &rxbuf_dma) != 0) {
        wr("NETTEST: FAIL rxbuf-alloc\n"); sys_exit();
    }
    if (frame_setup(SLOT_TXBUF, TXBUF_PAGES, VA_TXBUF, &txbuf, &txbuf_dma) != 0) {
        wr("NETTEST: FAIL txbuf-alloc\n"); sys_exit();
    }
    queue_layout(&rxq, rxring, rxring_dma);
    queue_layout(&txq, txring, txring_dma);

    /* ---- 6. publish the queues ------------------------------------------
     * The PFN register is the device's view shifted right by 12, which is the
     * one place a virtual address would be accepted without complaint and then
     * quietly mean somebody else's memory. */
    outw(io + VIRTIO_QUEUE_SELECT, RX_QUEUE);
    if (inw(io + VIRTIO_QUEUE_SIZE) != QSZ) { wr("NETTEST: FAIL rx-queue-size\n"); sys_exit(); }
    outl(io + VIRTIO_QUEUE_PFN, (unsigned int)(rxq.dma >> 12));

    outw(io + VIRTIO_QUEUE_SELECT, TX_QUEUE);
    if (inw(io + VIRTIO_QUEUE_SIZE) != QSZ) { wr("NETTEST: FAIL tx-queue-size\n"); sys_exit(); }
    outl(io + VIRTIO_QUEUE_PFN, (unsigned int)(txq.dma >> 12));

    outb(io + VIRTIO_STATUS,
         VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK);

    /* ---- 7. offer the device somewhere to put received frames ------------ */
    for (unsigned i = 0; i < RXBUF_COUNT; i++) {
        rxq.desc[i].addr  = rxbuf_dma + (unsigned long long)i * BUF_SIZE;
        rxq.desc[i].len   = BUF_SIZE;
        rxq.desc[i].flags = VRING_DESC_F_WRITE;   /* the DEVICE writes these */
        rxq.desc[i].next  = 0;
        rxq.avail_ring[i % QSZ] = (unsigned short)i;
    }
    *rxq.avail_idx = RXBUF_COUNT;
    outw(io + VIRTIO_QUEUE_NOTIFY, RX_QUEUE);

    /* ---- 8. an ARP request for the gateway ------------------------------- */
    zero(txbuf, BUF_SIZE);
    unsigned char *eth = txbuf + NET_HDR_LEN;
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

    /* 60 bytes on the wire is the Ethernet minimum without FCS; an ARP frame is
     * 42, and padding here rather than relying on the emulator to do it keeps
     * this correct against a real NIC too. */
    unsigned tx_len = NET_HDR_LEN + 60;
    txq.desc[0].addr  = txbuf_dma;
    txq.desc[0].len   = tx_len;
    txq.desc[0].flags = 0;                                /* the device READS this */
    txq.desc[0].next  = 0;
    txq.avail_ring[0] = 0;
    *txq.avail_idx = 1;
    outw(io + VIRTIO_QUEUE_NOTIFY, TX_QUEUE);

    /* ---- 9. wait for the reply ------------------------------------------
     * Polling, bounded, and see the header comment for why: a PCI interrupt line
     * cannot be delivered on this machine yet, so a wait on the notification
     * would be a wait that can only time out. The bound is what turns "no reply"
     * into a named failure instead of a hang the harness reports as a timeout. */
    /* The bound is a few hundred thousand yields, not tens of millions. Slirp
     * answers ARP in microseconds, so the base arm leaves this loop almost at
     * once and the number only decides how long a FAILING build takes to say so.
     * The first version spun 40 million times: correct, and it outlived the
     * harness's 40-second budget, so the DMA control arm reported a TIMEOUT
     * rather than its own marker -- a gate failing for a reason that looks
     * identical to a hang. */
    int got = 0;
    for (long spin = 0; spin < 300000L && !got; spin++) {
        if (*rxq.used_idx == rxq.last_used) { sys_yield(); continue; }

        while (rxq.last_used != *rxq.used_idx) {
            struct vring_used_elem *e = &rxq.used_ring[rxq.last_used % QSZ];
            unsigned char *b = rxbuf + (unsigned long)e->id * BUF_SIZE;
            unsigned char *f = b + NET_HDR_LEN;
            rxq.last_used++;

            if (e->len < NET_HDR_LEN + 42) continue;
            if (!(f[12] == 0x08 && f[13] == 0x06)) continue;   /* not ARP */
            unsigned char *a = f + 14;
            if (!(a[6] == 0 && a[7] == ARP_REPLY)) continue;
            if (!same(a + 14, GW_IP, 4)) continue;             /* not the gateway */

            wr("NETD: arp reply from 10.0.2.2 at ");
            for (int i = 0; i < 6; i++) { if (i) wr(":"); wr_hex2(a[8 + i]); }
            wr("\n");
            got = 1;
            break;
        }
    }

    /* Reading ISR acknowledges the device's interrupt. Nothing is listening to
     * the line, but leaving it asserted would be a landmine for whoever unmasks
     * it (§2.13) -- the driver that ignores its own ISR is how an interrupt
     * storm arrives one commit later. */
    (void)inb(io + VIRTIO_ISR);

    if (!got) { wr("NETTEST: FAIL no-arp-reply\n"); for (;;) sys_yield(); }

    wr("NETTEST: PASS\n");
    for (;;) sys_yield();
}
