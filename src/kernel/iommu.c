/* iommu.c -- Intel VT-d DMA remapping: what a device is allowed to reach.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Since S43 a CAP_IO_DEVICE names one device, and since S44 turning that device
 * into a bus master is an act a capability gates. Neither says anything about
 * WHERE the device then goes, and until this file there was nothing that could:
 * a bus-mastering device reaches all of physical memory, and the descriptors
 * directing it are written by its own ring-3 driver. `netd` holds one capability
 * and can, today, point a NIC at the kernel's page tables.
 *
 * That was the largest single gap in the model and it is not closable in
 * software -- it needs the hardware that translates a device's addresses. VT-d
 * is that hardware. With it, a device has an ADDRESS SPACE of its own, exactly as
 * a task does, and reaches only what has been mapped into it.
 *
 * THE PROPERTY, AND THE DEFAULT THAT MAKES IT ONE
 * ----------------------------------------------
 * Every device starts with an EMPTY address space. Not an identity map of the
 * pool, not "everything below 4 GiB" -- empty. A device whose driver has mapped
 * nothing reaches nothing, and every address it emits faults. That is the
 * fail-closed default, and it is what makes the capability meaningful rather
 * than advisory: a driver's DMA reach is exactly the frames it holds a CAP_FRAME
 * for and has asked to map, and no more.
 *
 * An identity map would have been far easier and is the shape most kernels
 * start with. It would also make this file decorative -- the device would reach
 * all of memory again, through a translation that always says yes.
 *
 * WHAT IS TRANSLATED, AND WHAT IS NOT
 * -----------------------------------
 * DMA remapping only. Interrupt remapping (the other half of VT-d) is NOT
 * enabled here: the machine cannot deliver a PCI interrupt to ring 3 at all yet
 * (docs/LIMITATIONS.md 2.13), so there is no interrupt to remap and enabling it
 * would be authority added for nobody. When that lands it belongs here, next to
 * this comment.
 *
 * STRUCTURE
 * ---------
 * VT-d's tables are a three-level lookup keyed by the device's bus:dev.fn:
 *
 *   root table    [bus]        -> context table for that bus
 *   context table [dev:fn]     -> a second-level page-table root + domain id
 *   second-level page tables   -> the device's own address space
 *
 * The second-level tables look like ordinary x86-64 page tables and are walked
 * the same way, but the bits mean different things: bit 0 is READ and bit 1 is
 * WRITE (there is no present bit -- readable-or-writable IS present), and the
 * privilege/NX bits do not exist. Reusing paging.c's helpers would therefore be
 * a type confusion that happens to compile, so the walk is written out here.
 *
 * EVERY DEVICE GETS ITS OWN DOMAIN. Sharing one domain between two devices would
 * mean a mapping made for one is reachable by the other -- the S43 defect, one
 * layer further down, and invisible because both devices would work.
 */
#include "kernel.h"

/* ---- DMAR (ACPI) --------------------------------------------------------- */

struct dmar_header {
    char     sig[4];          /* "DMAR" */
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oemid[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
    uint8_t  host_addr_width;  /* MGAW-1: the widest address the platform uses */
    uint8_t  flags;
    uint8_t  reserved[10];
} __attribute__((packed));

struct dmar_remap_header {
    uint16_t type;
    uint16_t length;
} __attribute__((packed));

#define DMAR_TYPE_DRHD  0

struct dmar_drhd {
    struct dmar_remap_header hdr;
    uint8_t  flags;            /* bit 0: INCLUDE_PCI_ALL */
    uint8_t  reserved;
    uint16_t segment;
    uint64_t register_base;    /* physical base of this unit's register file */
} __attribute__((packed));

#define DRHD_FLAG_INCLUDE_ALL 0x1

/* ---- register file ------------------------------------------------------- */

#define DMAR_VER      0x00
#define DMAR_CAP      0x08
#define DMAR_ECAP     0x10
#define DMAR_GCMD     0x18
#define DMAR_GSTS     0x1C
#define DMAR_RTADDR   0x20
#define DMAR_CCMD     0x28
#define DMAR_FSTS     0x34
#define DMAR_FECTL    0x38
#define DMAR_IQH      0x80
#define DMAR_IQT      0x88
#define DMAR_IQA      0x90

#define GCMD_TE       (1u << 31)   /* translation enable */
#define GCMD_SRTP     (1u << 30)   /* set root table pointer */
#define GCMD_WBF      (1u << 27)   /* write buffer flush */
#define GSTS_TES      (1u << 31)
#define GSTS_RTPS     (1u << 30)
#define GSTS_WBFS     (1u << 27)

#define CCMD_ICC      (1ull << 63)
#define CCMD_CIRG_GLOBAL (1ull << 61)

/* Invalidate-address / IOTLB registers live at an offset the capability register
 * reports rather than at a fixed address. */
#define CAP_SAGAW_SHIFT   8
#define CAP_SAGAW_MASK    0x1Full
#define CAP_MGAW_SHIFT    16
#define CAP_MGAW_MASK     0x3Full
#define CAP_ND_MASK       0x7ull
#define ECAP_IRO_SHIFT    8
#define ECAP_IRO_MASK     0x3FFull
#define IOTLB_IVT         (1ull << 63)
#define IOTLB_IIRG_GLOBAL (1ull << 60)

/* SAGAW bit 2 is the 3-level (39-bit) address width, bit 3 the 4-level (48-bit).
 * Three levels is enough for every physical address this kernel can produce and
 * costs one fewer table per domain, so it is preferred; 4 is the fallback for a
 * unit that does not offer 3. */
#define SAGAW_39BIT   (1u << 1)
#define SAGAW_48BIT   (1u << 2)

/* ---- second-level page tables -------------------------------------------- */

#define SL_READ   (1ull << 0)
#define SL_WRITE  (1ull << 1)
#define SL_ADDR_MASK 0x000FFFFFFFFFF000ull

/* One device's address space. */
struct iommu_domain {
    uint32_t in_use;
    uint16_t bdf;
    uint16_t domain_id;
    uint64_t sl_root_phys;   /* second-level page-table root */
};

static struct iommu_domain domains[IODEV_MAX];

static volatile uint8_t *iommu_regs;      /* the unit's register file, mapped */
static uint64_t iommu_cap, iommu_ecap;
static uint64_t root_table_phys;
static int      iommu_levels;             /* 3 or 4 */
static int      iommu_ready;
static uint16_t next_domain_id = 1;       /* 0 is reserved */

static inline uint32_t reg32(uint32_t off) {
    return *(volatile uint32_t *)(iommu_regs + off);
}
static inline void reg32_write(uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(iommu_regs + off) = v;
}
static inline uint64_t reg64(uint32_t off) {
    return *(volatile uint64_t *)(iommu_regs + off);
}
static inline void reg64_write(uint32_t off, uint64_t v) {
    *(volatile uint64_t *)(iommu_regs + off) = v;
}

/* ---- page allocation ----------------------------------------------------- */

/* IOMMU structures are kernel objects with a device on the other end of them, so
 * they come from the kernel's own page allocator rather than the untyped arena:
 * an arena page is something ring 3 can hold a capability to, and a root table
 * ring 3 could name is a root table ring 3 could retype. */
static uint64_t iommu_page(void) {
    uint64_t p = alloc_user_physical_page();
    if (!p) return 0;
    uint8_t *v = (uint8_t *)PHYS_KVA(p);
    for (uint32_t i = 0; i < PAGE_SIZE; i++) v[i] = 0;
    return p;
}

/* ---- the second-level walk ----------------------------------------------- */

/* Index of `iova` at `level`, where level 1 is the leaf (4 KiB) table. */
static inline uint32_t sl_index(uint64_t iova, int level) {
    return (uint32_t)((iova >> (12 + 9 * (level - 1))) & 0x1FF);
}

/* Walk `domain`'s tables to the leaf entry for `iova`, allocating tables on the
 * way when `create`. Returns a pointer to the 64-bit entry, or NULL. */
static uint64_t *sl_entry(struct iommu_domain *d, uint64_t iova, int create) {
    uint64_t table_phys = d->sl_root_phys;
    for (int level = iommu_levels; level > 1; level--) {
        uint64_t *t = (uint64_t *)PHYS_KVA(table_phys);
        uint64_t *e = &t[sl_index(iova, level)];
        if (!(*e & (SL_READ | SL_WRITE))) {
            if (!create) return NULL;
            uint64_t next = iommu_page();
            if (!next) return NULL;
            /* A non-leaf entry carries R|W: the permission check is at the leaf,
             * and an intermediate entry that denied either would deny the whole
             * subtree regardless of what the leaf says. */
            *e = (next & SL_ADDR_MASK) | SL_READ | SL_WRITE;
        }
        table_phys = *e & SL_ADDR_MASK;
    }
    uint64_t *t = (uint64_t *)PHYS_KVA(table_phys);
    return &t[sl_index(iova, 1)];
}

/* ---- invalidation -------------------------------------------------------- */

/* After changing a mapping the unit may still hold the old one. Both caches are
 * flushed globally rather than by address: this kernel maps rarely and at
 * startup, so the cost is irrelevant, and a global flush cannot be got subtly
 * wrong the way a selective one can -- a missed selective invalidation is a
 * device reading through a mapping the kernel believes it removed, which is
 * precisely the failure this file exists to prevent. */
static void iommu_flush(void) {
    /* Context cache, then IOTLB: the order matters, since a context-cache entry
     * can pull in IOTLB entries for the domain it names. */
    reg64_write(DMAR_CCMD, CCMD_ICC | CCMD_CIRG_GLOBAL);
    while (reg64(DMAR_CCMD) & CCMD_ICC) { }

    uint32_t iro = (uint32_t)((iommu_ecap >> ECAP_IRO_SHIFT) & ECAP_IRO_MASK) * 16;
    uint32_t iotlb_reg = iro + 8;    /* IOTLB_REG sits one qword past IVA_REG */
    reg64_write(iotlb_reg, IOTLB_IVT | IOTLB_IIRG_GLOBAL);
    while (reg64(iotlb_reg) & IOTLB_IVT) { }
}

/* ---- domains ------------------------------------------------------------- */

/* The context entry for one device, installed on first use. Two 64-bit words:
 * the low one carries present + translation type + the second-level root, the
 * high one the address width and the domain id. */
static int context_install(uint16_t bdf, struct iommu_domain *d) {
    uint8_t bus = (uint8_t)(bdf >> 8);
    uint8_t devfn = (uint8_t)(bdf & 0xFF);

    uint64_t *root = (uint64_t *)PHYS_KVA(root_table_phys);
    uint64_t *rent = &root[(uint64_t)bus * 2];      /* 16 bytes per bus */

    uint64_t ctx_phys;
    if (*rent & 1ull) {
        ctx_phys = *rent & SL_ADDR_MASK;
    } else {
        ctx_phys = iommu_page();
        if (!ctx_phys) return -1;
        *rent = (ctx_phys & SL_ADDR_MASK) | 1ull;   /* present */
    }

    uint64_t *ctx = (uint64_t *)PHYS_KVA(ctx_phys);
    uint64_t *cent = &ctx[(uint64_t)devfn * 2];

    /* AW field: 1 => 3-level (39-bit), 2 => 4-level (48-bit). */
    uint64_t aw = (iommu_levels == 3) ? 1ull : 2ull;
    cent[1] = (aw & 0x7ull) | ((uint64_t)d->domain_id << 8);
    /* Translation type 0 = use the second-level table for everything. Present
     * last, and after the high word: the unit may read this entry the instant
     * the present bit appears, and it must never see a present entry whose
     * domain id and width have not been written. */
    cent[0] = (d->sl_root_phys & SL_ADDR_MASK) | 1ull;
    return 0;
}

/* The domain for one device, created empty on first use. */
static struct iommu_domain *domain_for(uint64_t devindex, uint16_t bdf) {
    if (devindex >= IODEV_MAX) return NULL;
    struct iommu_domain *d = &domains[devindex];
    if (d->in_use) return d;

    /* How many domain ids this unit supports: ND=0 gives 16, and each step adds
     * two bits, so ND=6 gives 65536.
     *
     * Computed in 32 bits and compared in 32 bits ON PURPOSE. The obvious
     * `(uint16_t)(1u << (4 + 2*nd))` truncates to ZERO for ND=6 -- which is what
     * QEMU reports -- so the guard read "1 >= 0", refused every domain, and every
     * SYS_DMA_ADDR returned SYS_ERR_FAULT. It cost a boot to find and it is the
     * same 32-bit truncation shape as issue #176. A limit must be computed in a
     * type that can hold it. */
    uint32_t nd = (uint32_t)(iommu_cap & CAP_ND_MASK);
    uint32_t domain_limit = 1u << (4 + 2 * nd);
    if ((uint32_t)next_domain_id >= domain_limit)
        return NULL;                 /* out of domain ids this unit supports */

    uint64_t root = iommu_page();
    if (!root) return NULL;

    d->sl_root_phys = root;
    d->bdf          = bdf;
    d->domain_id    = next_domain_id++;
    d->in_use       = 1;

    if (context_install(bdf, d) != 0) { d->in_use = 0; return NULL; }
    iommu_flush();
    return d;
}

/* ---- public ------------------------------------------------------------- */

int iommu_active(void) { return iommu_ready; }

/* Map `pages` pages of physical memory at `phys` into `dev`'s address space, at
 * an IOVA equal to the physical address.
 *
 * IOVA == PA is a CHOICE and not an identity map, and the difference is the
 * whole property. An identity map installs the whole address space up front and
 * the device reaches everything; this installs one mapping per frame a driver
 * actually asks for, so the device reaches exactly those frames and faults on
 * every other address -- including addresses inside frames it was never given.
 * Using the physical address as the IOVA merely spares the driver a second
 * number to track, and it is what lets SYS_DMA_ADDR keep the same signature it
 * had before the IOMMU existed.
 *
 * `writable` is the driver's declared direction. A receive buffer needs WRITE; a
 * transmit buffer needs only READ, and giving it WRITE anyway would let a
 * compromised device scribble on a page the driver only ever reads from. */
int iommu_map(uint64_t devindex, uint16_t bdf, uint64_t phys, uint32_t pages,
              int writable) {
    if (!iommu_ready) return -1;
    if (pages == 0 || pages > MAX_FRAME_PAGES) return -1;
    if (phys & (PAGE_SIZE - 1)) return -1;

    struct iommu_domain *d = domain_for(devindex, bdf);
    if (!d) return -1;

    uint64_t flags = SL_READ | (writable ? SL_WRITE : 0);
    for (uint32_t i = 0; i < pages; i++) {
        uint64_t pa = phys + (uint64_t)i * PAGE_SIZE;
        uint64_t *e = sl_entry(d, pa, 1);
        if (!e) return -1;
        /* Re-mapping the same page is allowed and idempotent; a driver that maps
         * a buffer twice has done nothing wrong. Widening READ to READ|WRITE is
         * allowed for the same reason. */
        *e = (pa & SL_ADDR_MASK) | flags;
    }
    iommu_flush();
    return 0;
}

/* Remove `pages` pages from `dev`'s address space. Called when a frame
 * capability is revoked or a driver dies: a mapping that outlived its capability
 * is a device still writing into memory the kernel has reclaimed, which no
 * software check can catch after the fact. */
int iommu_unmap(uint64_t devindex, uint64_t phys, uint32_t pages) {
    if (!iommu_ready) return -1;
    if (devindex >= IODEV_MAX) return -1;
    struct iommu_domain *d = &domains[devindex];
    if (!d->in_use) return 0;              /* nothing was ever mapped */

    for (uint32_t i = 0; i < pages; i++) {
        uint64_t *e = sl_entry(d, phys + (uint64_t)i * PAGE_SIZE, 0);
        if (e) *e = 0;
    }
    iommu_flush();
    return 0;
}

/* Does `dev`'s address space currently translate `phys`?
 *
 * A kernel-internal query, with no syscall behind it: the answer is a statement
 * about another protection domain's page tables, and ring 3 has no business
 * asking. It exists so a selftest can witness that destroying a frame removes
 * the device's translation, rather than the test having to infer it from a
 * packet that did or did not arrive. */
int iommu_translates(uint64_t devindex, uint64_t phys) {
    if (!iommu_ready) return -1;
    if (devindex >= IODEV_MAX) return -1;
    struct iommu_domain *d = &domains[devindex];
    if (!d->in_use) return 0;
    uint64_t *e = sl_entry(d, phys, 0);
    if (!e) return 0;
    return (*e & (SL_READ | SL_WRITE)) ? 1 : 0;
}

/* Remove `pages` pages from EVERY device's address space.
 *
 * Called when a frame object is destroyed. The IOVA is the physical address by
 * construction (see iommu_map), so one physical run identifies the same mapping
 * in every domain, and the loop is bounded by IODEV_MAX.
 *
 * WHY DESTRUCTION TEARS THE MAPPING DOWN RATHER THAN REFUSING TO COLLECT.
 * destroy_dyn_frame's neighbouring policy for CPU mappings is the opposite: a
 * frame with a live PTE is left alone, and the name leaks until the last holder
 * unmaps or dies. That is right for a PTE because the holder is a live task
 * still reading the bytes, and collecting underneath it would scrub memory
 * somebody is using.
 *
 * A device mapping is not that. The authority behind it was a CAP_FRAME the
 * kernel is in the middle of destroying, and the "holder" is a piece of hardware
 * that cannot be asked to stop. Refusing to collect would leave a bus-mastering
 * device with write access to the run forever, on the strength of a capability
 * that no longer exists; tearing the mapping down leaves the device faulting on
 * an address it is no longer entitled to, which is the direction that fails
 * closed. The two policies differ because the two holders differ, not because
 * one of them was copied. */
void iommu_unmap_all(uint64_t phys, uint32_t pages) {
    if (!iommu_ready) return;
    for (uint64_t dev = 0; dev < IODEV_MAX; dev++) {
        if (!domains[dev].in_use) continue;
        (void)iommu_unmap(dev, phys, pages);
    }
}

/* Drop every mapping a device holds. */
void iommu_reset_device(uint64_t devindex) {
    if (!iommu_ready || devindex >= IODEV_MAX) return;
    struct iommu_domain *d = &domains[devindex];
    if (!d->in_use) return;
    /* Zero the root table's top level: the pages below it stay allocated, which
     * leaks a few pages per device teardown and is deliberate for now -- walking
     * and freeing them needs a bound on depth and a story for a device that is
     * mid-transaction, and getting that wrong frees a page a device is writing
     * to. Recorded in docs/LIMITATIONS.md. */
    uint64_t *t = (uint64_t *)PHYS_KVA(d->sl_root_phys);
    for (uint32_t i = 0; i < 512; i++) t[i] = 0;
    iommu_flush();
}

/* ---- bring-up ------------------------------------------------------------ */

/* Find the first DRHD in the DMAR table and return its register base, or 0. */
static uint64_t dmar_find_unit(void) {
    const struct acpi_sdt_header *h = acpi_find_table("DMAR");
    if (!h) return 0;
    uint32_t len = acpi_table_length(h);
    if (len < sizeof(struct dmar_header)) return 0;

    const uint8_t *base = (const uint8_t *)h;
    uint32_t off = sizeof(struct dmar_header);
    while (off + sizeof(struct dmar_remap_header) <= len) {
        const struct dmar_remap_header *rh =
            (const struct dmar_remap_header *)(base + off);
        uint16_t rlen = rh->length;
        /* A zero or overlong length would loop forever or walk off the table.
         * Firmware is semi-trusted; fail closed rather than trust the walk. */
        if (rlen < sizeof(*rh) || off + rlen > len) return 0;
        if (rh->type == DMAR_TYPE_DRHD && rlen >= sizeof(struct dmar_drhd)) {
            const struct dmar_drhd *drhd = (const struct dmar_drhd *)rh;
            return drhd->register_base;
        }
        off += rlen;
    }
    return 0;
}

/* Bring the unit up with an empty root table, so every device reaches nothing
 * until something maps a frame for it.
 *
 * Called from kernel_main after paging and before any ring-3 task exists. A
 * machine with no DMAR simply leaves iommu_ready at 0, and every caller then
 * behaves as it did before this file existed -- which is the honest degradation:
 * the property is unavailable, and SYS_DMA_ADDR says so rather than pretending. */
void iommu_init(void) {
    iommu_ready = 0;

    uint64_t regs_phys = dmar_find_unit();
    if (!regs_phys) {
        kmsg_begin();
        print("iommu: no DMAR; device DMA is unrestricted\n");
        return;
    }

    /* The register file is device MMIO, above the physical pool, so it needs a
     * mapping of its own rather than the PHYS_KVA window -- and it must be
     * identity-mapped into EVERY address space, because SYS_DMA_ADDR writes these
     * registers while running on the calling task's cr3. Same treatment as the
     * LAPIC and the TPM TIS page. */
    ensure_iommu_regs_mapped(NULL, regs_phys);
    iommu_regs = (volatile uint8_t *)(uintptr_t)regs_phys;

    iommu_cap  = reg64(DMAR_CAP);
    iommu_ecap = reg64(DMAR_ECAP);

    uint32_t sagaw = (uint32_t)((iommu_cap >> CAP_SAGAW_SHIFT) & CAP_SAGAW_MASK);
    if (sagaw & SAGAW_39BIT)      iommu_levels = 3;
    else if (sagaw & SAGAW_48BIT) iommu_levels = 4;
    else {
        kmsg_begin();
        print("iommu: no supported address width; DMA left unrestricted\n");
        return;
    }

    root_table_phys = iommu_page();
    if (!root_table_phys) return;

    /* Publish the (empty) root table, then enable translation. In this order:
     * a unit told to translate before it has a root table is a unit translating
     * through whatever the register happened to hold. */
    reg64_write(DMAR_RTADDR, root_table_phys);
    reg32_write(DMAR_GCMD, GCMD_SRTP);
    while (!(reg32(DMAR_GSTS) & GSTS_RTPS)) { }

    iommu_flush();

    reg32_write(DMAR_GCMD, GCMD_TE);
    while (!(reg32(DMAR_GSTS) & GSTS_TES)) { }

    iommu_ready = 1;

    kmsg_begin();
    print("iommu: VT-d active, ");
    print_decimal((uint64_t)iommu_levels);
    print("-level, every device starts unable to reach memory\n");
}
