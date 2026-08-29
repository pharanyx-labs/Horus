/* shlib.c -- one copy of a library, executed by many tasks, writable by none.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every newlib-linked program in this tree statically links its own libc.
 * Measured 2026-08-29: `coreutils_echo` is 404,572 bytes, for `echo`. Eleven of
 * them ship, and each carries its own private copy of the same code.
 *
 * The size argument is the obvious one and it is real. The SECURITY argument is
 * the reason this file is written the way it is: once a library is shared, its
 * text is memory that many tasks execute, and the question of who may WRITE it
 * stops being rhetorical. A shared library mapped writable is a code-injection
 * primitive between every task that maps it -- one task patches a function, and
 * another task calls it and runs the patch. That is strictly worse than the
 * static copies it replaces, which at least isolated the damage.
 *
 * So the library's text is loaded ONCE into frames, and every task maps it
 * through a CAP_FRAME carrying READ and EXEC and NOT WRITE (S49). The rights
 * floor that S27 already enforces for ordinary shared memory is what enforces
 * it: a capability that never held WRITE cannot produce a descendant that does,
 * so there is no delegation path by which a task could obtain a writable mapping
 * of code another task is running.
 *
 * WHY THE TEXT IS AT A FIXED ADDRESS
 * ----------------------------------
 * Shared text must be identical in every address space, and text that needed
 * per-task relocation would not be -- each task would need its own copy, which
 * is the thing being removed. So the library is relocated ONCE at load, to one
 * base, and mapped at that same virtual address everywhere.
 *
 * That costs the library the address-space randomisation ordinary images get
 * (src/kernel/aslr.c), and it is a real cost rather than an oversight: a fixed
 * mapping is a known address for a ROP chain. It is recorded in
 * docs/LIMITATIONS.md rather than glossed, and it is the direct price of
 * sharing. Per-task randomisation of shared text needs either per-task
 * relocation (no sharing) or PC-relative code with a per-task GOT (which is
 * where full dynamic linking goes next).
 *
 * WHAT THIS IS NOT, YET
 * ---------------------
 * It is not a dynamic linker. It loads one object, resolves nothing by name, and
 * newlib is still statically linked into the programs that use it. What it is is
 * the mechanism underneath that -- shared text, capability-mediated, provably
 * unwritable -- and the migration of newlib onto it is a build-system job that
 * gets its own commit. docs/ROADMAP.md 2.5.
 */
#include "kernel.h"

/* The fixed base. Chosen above the image ASLR window and below the heap so it
 * collides with neither: image at 16 GiB (USER_IMAGE_ASLR_BASE), heap at 16 MiB,
 * stack below 8 MiB. A collision here would be a library mapped over a task's
 * own text, which fails as a fault at an address nobody expects. */
#define SHLIB_BASE   0x0000000300000000ULL

static int shlib_relocate_impl(const uint8_t *elf, uint64_t len, uint64_t phoff,
                               uint16_t phentsz, uint16_t phnum);

static uint32_t shlib_text_frames[SHLIB_MAX_PAGES];
static uint32_t shlib_text_count;
static uint64_t shlib_entry_table;      /* vaddr of the library's export table */
static int      shlib_ready;

/* Which pages came from a PF_W PT_LOAD. Those are the library's DATA, and the
 * frames carved for them here are a TEMPLATE -- the library's initial image --
 * rather than something any task maps. Each task gets its own copy (S50). */
static uint8_t  shlib_page_w[SHLIB_MAX_PAGES];

int shlib_active(void) { return shlib_ready; }
uint32_t shlib_pages(void) { return shlib_text_count; }
uint64_t shlib_base(void) { return SHLIB_BASE; }

/* Non-zero if page `i` is the library's writable data rather than its text.
 * The caller uses this to decide WHICH primordial a page is endowed from, so a
 * wrong answer here is a rights decision made on the wrong basis -- it fails
 * closed (an out-of-range page reports "not writable", so it would be endowed
 * read+exec and a write to it would fault) rather than open. */
int shlib_page_writable(uint32_t i) {
    if (i >= shlib_text_count) return 0;
    return shlib_page_w[i] != 0;
}

/* The frame index of text page `i`, for minting a capability over it. */
uint32_t shlib_frame_index(uint32_t i) {
    if (i >= shlib_text_count) return 0;
    return shlib_text_frames[i];
}

/* Load the embedded shared object into frames.
 *
 * Deliberately NOT a general ELF path: this reads the program headers, copies
 * every PT_LOAD into freshly carved frames at SHLIB_BASE, applies the object's
 * R_X86_64_RELATIVE relocations against that base, and stops. A shared object
 * with anything else in its relocation table -- an undefined symbol, a
 * JUMP_SLOT, a TLS entry -- is REFUSED rather than partially applied, because a
 * library that is half-relocated is a library whose calls go somewhere nobody
 * chose.
 *
 * Called once at boot, before any ring-3 task exists, so there is no task whose
 * address space could observe a partially built library. */
int shlib_init(const uint8_t *elf, uint64_t len) {
    shlib_ready = 0;
    shlib_text_count = 0;

    if (!elf || len < 64) return -1;
    if (!(elf[0] == 0x7F && elf[1] == 'E' && elf[2] == 'L' && elf[3] == 'F')) return -1;
    if (elf[4] != 2) return -1;                      /* ELFCLASS64 */
    uint16_t etype = (uint16_t)(elf[16] | ((uint16_t)elf[17] << 8));
    if (etype != 3) return -1;                       /* ET_DYN */

    uint64_t phoff   = *(const uint64_t *)(elf + 32);
    uint16_t phentsz = *(const uint16_t *)(elf + 54);
    uint16_t phnum   = *(const uint16_t *)(elf + 56);
    if (phentsz < 56 || phoff + (uint64_t)phnum * phentsz > len) return -1;

    /* Pass 1: the highest vaddr any PT_LOAD reaches, so the frame count is known
     * before anything is carved. Carving then copying would leave frames
     * allocated on a failure, and the untyped allocator never gives them back. */
    uint64_t hi = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsz;
        uint32_t p_type = *(const uint32_t *)(ph + 0);
        if (p_type != 1) continue;                   /* PT_LOAD */
        uint64_t vaddr = *(const uint64_t *)(ph + 16);
        uint64_t memsz = *(const uint64_t *)(ph + 40);
        if (vaddr + memsz < vaddr) return -1;
        if (vaddr + memsz > hi) hi = vaddr + memsz;
    }
    if (hi == 0) return -1;

    uint32_t pages = (uint32_t)((hi + PAGE_SIZE - 1) / PAGE_SIZE);
    if (pages == 0 || pages > SHLIB_MAX_PAGES) return -1;

    /* Mark every page a PF_W segment touches, BEFORE anything is carved.
     *
     * memsz and not filesz: .bss has no bytes in the file and is still writable
     * data, and a page of it endowed read+exec would fault on the library's
     * first store. Rounding is deliberately OUTWARD -- a page shared between a
     * read-only and a writable segment is counted writable -- because the
     * imprecision has to fall on the side of "this task gets its own copy". The
     * opposite rounding would share a page some task then writes, which is
     * exactly the disclosure S50 exists to refuse. shlib.ld page-aligns the
     * boundary so the ambiguous case does not arise; this loop does not depend
     * on that holding, because a linker script is not an enforcement mechanism. */
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsz;
        if (*(const uint32_t *)(ph + 0) != 1) continue;            /* PT_LOAD */
        uint32_t p_flags = *(const uint32_t *)(ph + 4);
        if (!(p_flags & 2)) continue;                              /* PF_W */
        uint64_t vaddr = *(const uint64_t *)(ph + 16);
        uint64_t memsz = *(const uint64_t *)(ph + 40);
        if (memsz == 0) continue;
        uint64_t first = vaddr / PAGE_SIZE;
        uint64_t last  = (vaddr + memsz - 1) / PAGE_SIZE;
        if (last >= pages) return -1;
        for (uint64_t pg = first; pg <= last; pg++) shlib_page_w[pg] = 1;
    }

    /* Carve from UNTYPED_KERNEL, not the user-facing region. These frames back
     * code every task executes; they must not come out of a budget ring 3 can
     * exhaust, and no capability naming that region is ever minted. */
    for (uint32_t p = 0; p < pages; p++) {
        uint32_t idx = 0;
        void *mem = kobj_alloc(UNTYPED_KERNEL, KOBJ_FRAME, 1, &idx);
        if (!mem || idx == 0) return -1;
        shlib_text_frames[p] = idx;
        shlib_text_count = p + 1;
        uint8_t *b = (uint8_t *)mem;
        for (uint32_t k = 0; k < PAGE_SIZE; k++) b[k] = 0;
    }

    /* Pass 2: copy each PT_LOAD into the frames. The library's link-time vaddrs
     * start at 0 (ET_DYN), so a vaddr IS an offset from the base. */
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsz;
        uint32_t p_type = *(const uint32_t *)(ph + 0);
        if (p_type != 1) continue;
        uint64_t off   = *(const uint64_t *)(ph + 8);
        uint64_t vaddr = *(const uint64_t *)(ph + 16);
        uint64_t filesz= *(const uint64_t *)(ph + 32);
        if (off + filesz > len) return -1;

        for (uint64_t b = 0; b < filesz; b++) {
            uint64_t v = vaddr + b;
            uint32_t pg = (uint32_t)(v / PAGE_SIZE);
            if (pg >= shlib_text_count) return -1;
            uint64_t phys = frame_phys_by_index(shlib_text_frames[pg]);
            if (!phys) return -1;
            ((uint8_t *)PHYS_KVA(phys))[v % PAGE_SIZE] = elf[off + b];
        }
    }

    /* Pass 3: relocations, applied ONCE against SHLIB_BASE. */
    if (shlib_relocate_impl(elf, len, phoff, phentsz, phnum) != 0) return -1;

    /* The export table's address comes from e_entry. A shared object has no
     * "entry point" in the runnable sense, so the field is free, and the linker
     * sets it from -e. Using it means the loader does not have to guess a layout
     * or trust a section name to survive the toolchain. */
    uint64_t entry = *(const uint64_t *)(elf + 24);
    if (entry == 0 || entry >= (uint64_t)shlib_text_count * PAGE_SIZE) return -1;
    shlib_entry_table = SHLIB_BASE + entry;

    shlib_ready = 1;
    uint32_t wpages = 0;
    for (uint32_t p = 0; p < shlib_text_count; p++) if (shlib_page_w[p]) wpages++;

    kmsg_begin();
    print("shlib: ");
    print_decimal((uint64_t)shlib_text_count);
    print(" pages loaded (");
    print_decimal((uint64_t)wpages);
    print(" per-task data); no task can write another's code or read its data\n");

    return 0;
}

/* Apply the object's R_X86_64_RELATIVE relocations against SHLIB_BASE.
 *
 * RELATIVE only, and anything else fails the load. A shared object built
 * -fPIC -nostdlib with no undefined symbols has nothing else, and accepting a
 * type this does not implement would mean writing a value nobody computed into
 * code every task runs. */
static int shlib_relocate_impl(const uint8_t *elf, uint64_t len, uint64_t phoff,
                               uint16_t phentsz, uint16_t phnum) {
    uint64_t dyn_off = 0, dyn_sz = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = elf + phoff + (uint64_t)i * phentsz;
        if (*(const uint32_t *)(ph + 0) != 2) continue;      /* PT_DYNAMIC */
        dyn_off = *(const uint64_t *)(ph + 8);
        dyn_sz  = *(const uint64_t *)(ph + 32);
        break;
    }
    if (dyn_sz == 0) return 0;                                /* nothing to do */
    if (dyn_off + dyn_sz > len) return -1;

    uint64_t rela = 0, relasz = 0, relaent = 24;
    for (uint64_t o = 0; o + 16 <= dyn_sz; o += 16) {
        uint64_t tag = *(const uint64_t *)(elf + dyn_off + o);
        uint64_t val = *(const uint64_t *)(elf + dyn_off + o + 8);
        if (tag == 0) break;                                  /* DT_NULL */
        else if (tag == 7)  rela    = val;                    /* DT_RELA    */
        else if (tag == 8)  relasz  = val;                    /* DT_RELASZ  */
        else if (tag == 9)  relaent = val;                    /* DT_RELAENT */
        else if (tag == 17 || tag == 18 || tag == 19) return -1;  /* DT_REL*: i386 form */
    }
    if (relasz == 0) return 0;
    if (relaent < 24) return -1;

    for (uint64_t o = 0; o + relaent <= relasz; o += relaent) {
        uint64_t at = rela + o;
        /* The RELA table's own address is a link-time vaddr, i.e. an offset. */
        if (at + 24 > len) return -1;
        uint64_t r_off  = *(const uint64_t *)(elf + at);
        uint64_t r_info = *(const uint64_t *)(elf + at + 8);
        int64_t  r_add  = *(const int64_t  *)(elf + at + 16);
        uint32_t rtype  = (uint32_t)(r_info & 0xFFFFFFFFu);

        if (rtype == 0) continue;                             /* R_X86_64_NONE */
        if (rtype != 8) return -1;                            /* only RELATIVE */

        uint32_t pg = (uint32_t)(r_off / PAGE_SIZE);
        if (pg >= shlib_text_count) return -1;
        if ((r_off % PAGE_SIZE) + 8 > PAGE_SIZE) return -1;   /* must not straddle */
        uint64_t phys = frame_phys_by_index(shlib_text_frames[pg]);
        if (!phys) return -1;
        *(uint64_t *)((uint8_t *)PHYS_KVA(phys) + (r_off % PAGE_SIZE)) =
            SHLIB_BASE + (uint64_t)r_add;
    }
    return 0;
}

/* Carve a PRIVATE copy of writable page `page` for one task, and return its
 * frame index (0 on failure).
 *
 * THIS IS S50. The frames shlib_init carved are a template: they hold the
 * library's initial image and no task ever maps them. A task that maps the
 * library's data maps a frame of its own, copied from that template, so it sees
 * the library's initialisers and never another task's writes.
 *
 * WHY PRIVATE DATA IS NOT A CONVENIENCE. Of the 59 newlib symbols the shipped
 * coreutils reference, three are writable: _impure_ptr -- which is errno, the
 * stdio buffers, the atexit list and the rand state -- plus optarg and optind.
 * Shared, one task reads another's stdio buffers and errno, and a write through
 * a shared malloc arena corrupts an allocator another task is mid-call in. That
 * is strictly worse than the per-program static copies it replaces, which is
 * the same argument S49 makes about text arriving one segment further on.
 *
 * The copy is made from the RELOCATED template, once, and never re-relocated:
 * shlib_init applied R_X86_64_RELATIVE against SHLIB_BASE before any task
 * existed, and the library is mapped at that same base everywhere, so a pointer
 * in .data is already correct in every copy.
 *
 * Carved from UNTYPED_KERNEL for the reason the text frames are: this is a
 * per-task allocation driven by task creation, and a budget ring 3 could
 * exhaust would make library instantiation a denial of service. */
uint32_t shlib_instantiate_data(uint32_t page) {
    if (!shlib_ready || page >= shlib_text_count) return 0;
    if (!shlib_page_w[page]) return 0;          /* text is shared, not copied */

#ifdef SHLIB_DATA_SHARED
    /* Control arm: hand back the TEMPLATE frame itself, so every task maps the
     * same physical page and the library's data is shared. One task's write to
     * shlib_counter is then visible to every other -- the disclosure this
     * property refuses. See make smoke-shlib-data-shared-control. */
    return shlib_text_frames[page];
#else
    uint32_t idx = 0;
    void *mem = kobj_alloc(UNTYPED_KERNEL, KOBJ_FRAME, 1, &idx);
    if (!mem || idx == 0) return 0;

    uint8_t *dst = (uint8_t *)mem;
#ifdef SHLIB_DATA_UNINITIALISED
    /* Control arm: a private frame, but zero-filled instead of copied from the
     * library's image. Separable from SHLIB_DATA_SHARED on purpose -- this one
     * is LOSS where that one is DISCLOSURE, and each arm's other half still
     * passes, which is what shows the two checks are independent. The FPU pair
     * (FPU_NO_SAVE / FPU_NO_RESTORE) is the same shape and the reason this is
     * two flags rather than one. */
    for (uint32_t k = 0; k < PAGE_SIZE; k++) dst[k] = 0;
#else
    uint64_t src_phys = frame_phys_by_index(shlib_text_frames[page]);
    if (!src_phys) return 0;
    const uint8_t *src = (const uint8_t *)PHYS_KVA(src_phys);
    for (uint32_t k = 0; k < PAGE_SIZE; k++) dst[k] = src[k];
#endif
    return idx;
#endif
}

/* The library's export table lives at its base: a fixed array of function
 * pointers a caller indexes. Deliberately not symbol resolution by name -- that
 * is the dynamic linker this file is the substrate for, and pretending to have
 * one would be the harder claim without the harder implementation. */
uint64_t shlib_entry(void) { return shlib_entry_table ? shlib_entry_table : SHLIB_BASE; }
