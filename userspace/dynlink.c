/* dynlink.c -- the ring-3 linker (S108): a program's references to the shared libc,
 * resolved by name before main, then sealed (docs/design/shared-libc.md §8).
 *
 * WHAT THE KERNEL HAS ALREADY DONE. It loaded this image, applied its
 * R_X86_64_RELATIVE relocations and resolved every reference to a symbol the
 * image defines. It LEFT ALONE, because this image asked for the library
 * (DT_NEEDED "libc.so"), each R_X86_64_64, GLOB_DAT and JUMP_SLOT against an
 * undefined symbol: those are references to library names, and the kernel has
 * neither the names nor any business growing a symbol resolver. It gave this
 * task the library's text capabilities and a private copy of its data.
 *
 * WHAT THIS DOES, in order, before anything calls into the library:
 *
 *   1. Map the library: SYS_SHLIB_INFO, then each text page READ|EXEC (S49).
 *   2. Check the ABI: the library's table carries a hash of its names, kinds and
 *      order; this program was compiled with the hash of the table it linked
 *      against. A mismatch is a refusal: a name that moved or changed kind
 *      would otherwise be a call into the wrong function.
 *   3. Resolve each deferred reference by NAME against the table, and write the
 *      address into its slot. A name the library does not export is a refusal,
 *      never a zero (a weak reference excepted, which is allowed to be absent).
 *   4. Seal the slots: SYS_MEM_SEAL over [__horus_relro_start, __horus_relro_end)
 *      (userspace/pie_shared.ld), so nothing can redirect a call afterwards (S107).
 *
 * IT CANNOT CALL THE LIBRARY, which is what it is linking. Everything here is
 * syscalls and hand-rolled loops, and every symbol it touches is hidden, so the
 * compiler reaches it PC-relative rather than through a GOT slot this file has
 * not filled in yet.
 */
#include "syscall.h"
#include "dynlink.h"
#include "libc_exports.h"          /* SHLIB_ABI_HASH: the table this was built against */

#define HIDDEN __attribute__((visibility("hidden")))
extern char __horus_image_start[] HIDDEN;   /* link address 0: its runtime address is the base */
extern char __horus_relro_start[] HIDDEN;
extern char __horus_relro_end[] HIDDEN;
extern const uint64_t _DYNAMIC[] HIDDEN;

/* The hash this program expects. A build may override it only to make a program
 * that expects a DIFFERENT library, which is how the refusal is tested
 * (make smoke-shlib-link, dynstale). */
#ifndef DYNLINK_EXPECT_HASH
#define DYNLINK_EXPECT_HASH SHLIB_ABI_HASH
#endif

#define DT_NULL      0
#define DT_PLTRELSZ  2
#define DT_STRTAB    5
#define DT_SYMTAB    6
#define DT_RELA      7
#define DT_RELASZ    8
#define DT_RELAENT   9
#define DT_JMPREL   23

#define R_X86_64_64        1
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7

/* The most entries the table may have. It is generated from a few dozen names; a
 * table that does not end within this many slots is not one this was built for. */
#define TABLE_MAX 4096

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

/* Where the library lives and what it exports, filled by map_library. */
static const uint64_t *g_table;
static const char     *g_names;
static uint64_t        g_count;

static int map_library(void) {
    struct shlib_info si;
    if (sys_shlib_info(CAPSLOT_LIBC_FIRST, &si) != 0) return DYNLINK_NO_CAP;
    if (si.pages == 0 || si.entry == 0) return DYNLINK_NO_CAP;
    int data_mapped = (si.flags & SHLIB_INFO_DATA_MAPPED) != 0;
    for (unsigned i = 0; i < si.pages; i++) {
        int is_data = (si.data_first != SHLIB_INFO_NO_DATA) &&
                      (i >= si.data_first) && (i < si.data_first + si.data_pages);
        if (is_data) {
            /* The kernel maps a program's private copy at spawn and exec
             * (S106); a program it did not map any for cannot be linked. */
            if (!data_mapped) return DYNLINK_NO_DATA;
            continue;
        }
        if (sys_map_frame(CAPSLOT_LIBC_FIRST + i,
                          si.base + (unsigned long long)i * 4096,
                          CAP_RIGHT_READ | CAP_RIGHT_EXEC) != 0)
            return DYNLINK_TEXT;
    }
    g_table = (const uint64_t *)(uintptr_t)si.entry;
    uint64_t n = 0;
    while (n < TABLE_MAX && g_table[n] != 0) n++;
    if (n == TABLE_MAX) return DYNLINK_ABI;
    g_count = n;
    g_names = (const char *)(uintptr_t)g_table[n + 1];
#ifndef DYNLINK_ABI_UNCHECKED
    if (g_names == 0 || g_table[n + 2] != (uint64_t)DYNLINK_EXPECT_HASH) return DYNLINK_ABI;
#else
    /* CONTROL ARM -- never ship. The hash is not compared, so a program runs
     * against a library it was not built for, and a name that moved resolves to
     * whatever is there now. See make smoke-shlib-link-abi-control. */
    if (g_names == 0) return DYNLINK_ABI;
#endif
    return 0;
}

/* The address the library exports under `name`, or 0. Linear over a few dozen
 * names, once per reference, before main: not worth a hash. */
static uint64_t lookup(const char *name) {
    const char *p = g_names;
    for (uint64_t i = 0; i < g_count; i++) {
        if (streq(p, name)) return g_table[i];
        while (*p) p++;
        p++;
    }
    return 0;
}

static int apply(uint64_t base, const uint8_t *rela, uint64_t size,
                 const uint8_t *symtab, const char *strtab, const char **unknown) {
    for (uint64_t o = 0; o + 24 <= size; o += 24) {
        uint64_t r_offset = *(const uint64_t *)(rela + o);
        uint64_t r_info   = *(const uint64_t *)(rela + o + 8);
        int64_t  r_addend = *(const int64_t *)(rela + o + 16);
        uint32_t type = (uint32_t)(r_info & 0xFFFFFFFFu);
        uint64_t sym  = r_info >> 32;
        if (type != R_X86_64_64 && type != R_X86_64_GLOB_DAT && type != R_X86_64_JUMP_SLOT)
            continue;                  /* the kernel's, and already applied */
        if (sym == 0) continue;
        const uint8_t *s = symtab + sym * 24;
        uint16_t shndx = *(const uint16_t *)(s + 6);
        if (shndx != 0) continue;      /* defined here: the kernel resolved it */
        const char *name = strtab + *(const uint32_t *)(s + 0);
        uint64_t addr = lookup(name);
        if (addr == 0) {
            int weak = (*(s + 4) >> 4) == 2;
#ifndef DYNLINK_UNKNOWN_ZERO
            if (!weak) { *unknown = name; return DYNLINK_UNKNOWN; }
#else
            /* CONTROL ARM -- never ship. An unknown name resolves to zero and
             * the program carries on, to fault wherever it first uses it, far
             * from the reason. See make smoke-shlib-link-unknown-control. */
            (void)weak;
#endif
        }
        uint64_t value = (type == R_X86_64_64) ? addr + (uint64_t)r_addend : addr;
        *(volatile uint64_t *)(uintptr_t)(base + r_offset) = value;
    }
    return 0;
}

int horus_dynlink(const char **unknown) {
    int rc = map_library();
    if (rc != 0) return rc;

    uint64_t base = (uint64_t)(uintptr_t)__horus_image_start;
    uint64_t rela = 0, relasz = 0, relaent = 24, jmprel = 0, pltrelsz = 0, symtab = 0, strtab = 0;
    for (const uint64_t *d = _DYNAMIC; d[0] != DT_NULL; d += 2) {
        switch (d[0]) {
        case DT_RELA:     rela = d[1];     break;
        case DT_RELASZ:   relasz = d[1];   break;
        case DT_RELAENT:  relaent = d[1];  break;
        case DT_JMPREL:   jmprel = d[1];   break;
        case DT_PLTRELSZ: pltrelsz = d[1]; break;
        case DT_SYMTAB:   symtab = d[1];   break;
        case DT_STRTAB:   strtab = d[1];   break;
        default: break;
        }
    }
    if (relaent != 24) return DYNLINK_RELOC;
    if ((relasz || pltrelsz) && (!symtab || !strtab)) return DYNLINK_RELOC;
    const uint8_t *st = (const uint8_t *)(uintptr_t)(base + symtab);
    const char *str = (const char *)(uintptr_t)(base + strtab);
    if (relasz && (rc = apply(base, (const uint8_t *)(uintptr_t)(base + rela), relasz, st, str, unknown)) != 0)
        return rc;
    if (pltrelsz && (rc = apply(base, (const uint8_t *)(uintptr_t)(base + jmprel), pltrelsz, st, str, unknown)) != 0)
        return rc;

#ifndef DYNLINK_NO_SEAL
    uintptr_t a = (uintptr_t)__horus_relro_start, b = (uintptr_t)__horus_relro_end;
    if (b > a && sys_mem_seal((const void *)a, (uint64_t)(b - a)) != 0) return DYNLINK_SEAL;
#else
    /* CONTROL ARM -- never ship. The table is filled and left writable, so a
     * later write can redirect any call into the library.
     * See make smoke-shlib-link-seal-control. */
#endif
    return 0;
}
