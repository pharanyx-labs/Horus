/* acpi.c -- minimal ACPI table walk to enumerate the CPUs from the MADT.
 *
 * SMP bringup only needs one fact from firmware: how many CPUs actually exist.
 * Rather than broadcast an INIT-SIPI and then *guess* by waiting for a fixed
 * MAX_CPUS to check in (which stalls the boot for cores that will never appear),
 * the BSP reads the count straight from the ACPI MADT and waits for exactly that
 * many. This file locates the RSDP, walks the RSDT/XSDT to the MADT ("APIC"),
 * and counts the enabled Processor-Local-APIC entries.
 *
 * Firmware tables are semi-trusted input: every signature and checksum is
 * verified, every entry length is bounds-checked against the table it came from,
 * and every physical pointer is confined to the PHYS_KVA window before it is
 * dereferenced. Anything that does not validate makes the whole probe fail
 * closed (return -1) — the caller then falls back to the conservative broadcast
 * path rather than trusting a partial parse. See docs/proposals — SMP.
 */
#include "kernel.h"

/* All ACPI pointers are physical. They are read through the higher-half physmap
 * (PHYS_KVA), which only covers [0, PHYS_POOL_CEIL). A table above that ceiling
 * is unreachable without touching page tables, so treat it as "can't parse"
 * rather than fault. acpi_phys() returns NULL for any out-of-window address and
 * every caller checks. */
static const void *acpi_phys(uint64_t p, uint64_t span) {
    if (p == 0) return NULL;
    if (span == 0) return NULL;
    if (p + span < p) return NULL;                 /* wrap */
    if (p + span > (uint64_t)PHYS_POOL_CEIL) return NULL;
    return (const void *)PHYS_KVA(p);
}

/* 8-bit ACPI checksum: a valid structure's bytes sum to 0 (mod 256). */
static int acpi_checksum_ok(const uint8_t *p, uint64_t len) {
    uint8_t sum = 0;
    for (uint64_t i = 0; i < len; i++) sum = (uint8_t)(sum + p[i]);
    return sum == 0;
}

struct acpi_rsdp {
    char     sig[8];        /* "RSD PTR " */
    uint8_t  checksum;      /* over the first 20 bytes (ACPI 1.0) */
    char     oemid[6];
    uint8_t  revision;      /* 0 => ACPI 1.0 (RSDT); >=2 => ACPI 2.0+ (XSDT) */
    uint32_t rsdt_addr;
    uint32_t length;        /* ACPI 2.0+ only */
    uint64_t xsdt_addr;     /* ACPI 2.0+ only */
    uint8_t  ext_checksum;  /* over the whole `length` bytes */
    uint8_t  reserved[3];
} __attribute__((packed));

struct acpi_sdt_header {
    char     sig[4];
    uint32_t length;        /* total table length incl. this header */
    uint8_t  revision;
    uint8_t  checksum;      /* over `length` bytes */
    char     oemid[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

/* MADT ("APIC"): SDT header, then local-APIC address + flags, then a variable
 * run of (type,length)-prefixed entries. Type 0 is a Processor Local APIC. */
struct acpi_madt {
    struct acpi_sdt_header hdr;
    uint32_t lapic_addr;
    uint32_t flags;
    /* entries follow */
} __attribute__((packed));

#define MADT_TYPE_LOCAL_APIC   0
#define MADT_LAPIC_ENABLED     0x1   /* entry flags bit 0: processor usable */

/* Scan [start,end) physical for the 16-byte-aligned "RSD PTR " anchor with a
 * valid ACPI-1.0 checksum. Both windows scanned live below 1 MiB (in physmap). */
static const struct acpi_rsdp *scan_rsdp(uint64_t start, uint64_t end) {
    for (uint64_t p = start; p + sizeof(struct acpi_rsdp) <= end; p += 16) {
        const struct acpi_rsdp *r = acpi_phys(p, sizeof(*r));
        if (!r) continue;
        if (r->sig[0]=='R'&&r->sig[1]=='S'&&r->sig[2]=='D'&&r->sig[3]==' '&&
            r->sig[4]=='P'&&r->sig[5]=='T'&&r->sig[6]=='R'&&r->sig[7]==' ' &&
            acpi_checksum_ok((const uint8_t *)r, 20)) {
            return r;
        }
    }
    return NULL;
}

static const struct acpi_rsdp *find_rsdp(void) {
    /* 1) The 1 KiB Extended BIOS Data Area, whose segment is at phys 0x40E. */
    const uint16_t *ebda_seg = acpi_phys(0x40E, sizeof(uint16_t));
    if (ebda_seg) {
        uint64_t ebda = (uint64_t)(*ebda_seg) << 4;
        if (ebda >= 0x400 && ebda < 0xA0000) {
            const struct acpi_rsdp *r = scan_rsdp(ebda, ebda + 0x400);
            if (r) return r;
        }
    }
    /* 2) The BIOS read-only area 0xE0000..0xFFFFF. */
    return scan_rsdp(0xE0000, 0x100000);
}

/* Count enabled Processor-Local-APIC entries in the MADT, recording each APIC id
 * into apic_ids[] (up to max_ids). Returns the enabled-CPU count, or -1 on any
 * validation failure. */
static int madt_count(const struct acpi_madt *m, uint8_t *apic_ids, int max_ids) {
    uint32_t total = m->hdr.length;
    if (total < sizeof(struct acpi_madt) || total > 0x10000) return -1;
    if (!acpi_phys((uint64_t)(uintptr_t)m - PHYS_KVA_BASE, total)) return -1;
    if (!acpi_checksum_ok((const uint8_t *)m, total)) return -1;

    const uint8_t *base = (const uint8_t *)m;
    uint32_t off = sizeof(struct acpi_madt);
    int count = 0;
    while (off + 2 <= total) {
        uint8_t type = base[off];
        uint8_t len  = base[off + 1];
        if (len < 2 || off + len > total) return -1;   /* malformed: fail closed */
        if (type == MADT_TYPE_LOCAL_APIC && len >= 8) {
            uint8_t apic_id = base[off + 3];
            uint32_t eflags = (uint32_t)base[off + 4] | ((uint32_t)base[off + 5] << 8) |
                              ((uint32_t)base[off + 6] << 16) | ((uint32_t)base[off + 7] << 24);
            if (eflags & MADT_LAPIC_ENABLED) {
                if (apic_ids && count < max_ids) apic_ids[count] = apic_id;
                count++;
            }
        }
        off += len;
    }
    return count > 0 ? count : -1;
}

/* Walk one system-description table (RSDT: 32-bit entries, or XSDT: 64-bit) for
 * a table with signature `sig`, and return it fully validated, or NULL.
 *
 * This used to be MADT-specific with the signature compared inline. It is generic
 * because DMAR (roadmap 2.6's IOMMU) needs the same walk, and duplicating it
 * would duplicate the VALIDATION -- which is the part that matters here, since
 * every byte is semi-trusted firmware input. One walker, one set of checks: the
 * signature is the only thing that varies.
 *
 * The returned table has had its length bounds-checked, its whole extent
 * confirmed inside the PHYS_KVA window, and its checksum verified, so a caller
 * may read `h->length` bytes from it and no more. */
static const struct acpi_sdt_header *walk_sdt_for(uint64_t sdt_phys, int is_xsdt,
                                                  const char *sig) {
    const struct acpi_sdt_header *h = acpi_phys(sdt_phys, sizeof(*h));
    if (!h) return NULL;
    uint32_t total = h->length;
    if (total < sizeof(*h) || total > 0x10000) return NULL;
    if (!acpi_phys(sdt_phys, total)) return NULL;
    if (!acpi_checksum_ok((const uint8_t *)h, total)) return NULL;

    uint32_t esize  = is_xsdt ? 8 : 4;
    uint32_t nents  = (total - sizeof(*h)) / esize;
    const uint8_t *ent = (const uint8_t *)h + sizeof(*h);
    for (uint32_t i = 0; i < nents; i++) {
        uint64_t tp = is_xsdt
            ? *(const uint64_t *)(ent + (uint64_t)i * 8)
            : *(const uint32_t *)(ent + (uint64_t)i * 4);
        const struct acpi_sdt_header *th = acpi_phys(tp, sizeof(*th));
        if (!th) continue;
        if (th->sig[0] != sig[0] || th->sig[1] != sig[1] ||
            th->sig[2] != sig[2] || th->sig[3] != sig[3]) continue;
        /* Validate the TARGET table as thoroughly as the directory: its own
         * length, its own extent, its own checksum. A caller that trusted the
         * directory's word for a table's existence would be reading a length
         * field nothing had checked. */
        uint32_t tlen = th->length;
        if (tlen < sizeof(*th) || tlen > 0x10000) continue;
        if (!acpi_phys(tp, tlen)) continue;
        if (!acpi_checksum_ok((const uint8_t *)th, tlen)) continue;
        return th;
    }
    return NULL;
}

/* Find one ACPI table by signature, trying the 64-bit XSDT first and falling
 * back to the 32-bit RSDT, exactly as acpi_detect_cpus does. Returns a validated
 * table or NULL. */
const struct acpi_sdt_header *acpi_find_table(const char *sig) {
    const struct acpi_rsdp *r = find_rsdp();
    if (!r) return NULL;
    if (r->revision >= 2 && r->length >= sizeof(struct acpi_rsdp) &&
        acpi_checksum_ok((const uint8_t *)r, r->length) && r->xsdt_addr) {
        const struct acpi_sdt_header *h = walk_sdt_for(r->xsdt_addr, 1, sig);
        if (h) return h;
    }
    if (r->rsdt_addr) {
        const struct acpi_sdt_header *h = walk_sdt_for(r->rsdt_addr, 0, sig);
        if (h) return h;
    }
    return NULL;
}

/* Public: how many CPUs does firmware report? Fills apic_ids[] (best effort, up
 * to max_ids). Returns the enabled-CPU count (>=1) or -1 if ACPI is unreadable —
 * in which case the caller uses its conservative fallback. */
int acpi_detect_cpus(uint8_t *apic_ids, int max_ids) {
    const struct acpi_sdt_header *h = acpi_find_table("APIC");
    if (!h) return -1;
    return madt_count((const struct acpi_madt *)h, apic_ids, max_ids);
}

/* The validated length of a table from acpi_find_table. An accessor rather than
 * an exported struct: iommu.c needs the extent to bound its own walk, and giving
 * it the layout would let it read fields this file has not checked. */
uint32_t acpi_table_length(const struct acpi_sdt_header *h) {
    return h ? h->length : 0;
}
