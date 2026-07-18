#include "kernel.h"

extern uint8_t stack_top[];
extern tcb_t tasks[MAX_TASKS];

#define PAGE_PRESENT   (1 << 0)
#define PAGE_WRITE     (1 << 1)
#define PAGE_USER      (1 << 2)
#define PAGE_WT        (1 << 3)
#define PAGE_CD        (1 << 4)
#define PAGE_ACCESSED  (1 << 5)
#define PAGE_DIRTY     (1 << 6)
#define PAGE_4MB       (1 << 7)
/* Page Size bit. Set in a PDPTE it means a 1 GiB page; in a PDE, a 2 MiB page.
 * Either way the entry's frame base is NOT a pointer to a lower-level table, so
 * a page walker must stop rather than dereference it. */
#define PAGE_PS        (1ULL << 7)
#define PAGE_GLOBAL    (1 << 8)
#define PAGE_COW       (1 << 9)
/* No-execute (bit 63). EFER.NXE is enabled in multiboot.S, so the CPU honours
 * it on 64-bit page-table entries. Used to map user stacks non-executable
 * (W^X): data pages must never be executable, defeating classic shellcode on
 * the stack. The image/heap region stays executable because the flat-binary
 * loader cannot tell code from data within it. */
#define PAGE_NX        (1ULL << 63)
/* Physical frame bits of a PTE (52-bit phys, 4 KiB aligned). Masks off BOTH the
 * low 12 flag bits AND the high bits (notably NX, bit 63) — `& ~0xFFF` leaves NX
 * set, so a noexec page's frame address would carry bit 63 and land nowhere. */
#define PTE_ADDR_MASK  0x000FFFFFFFFFF000ULL

/* The W^X "is this user page non-executable?" policy lives in Rust
 * (rust_user_page_is_noexec); the kernel ORs PAGE_NX into the PTE when it
 * returns true. See rust/src/lib.rs. */

/* KERNEL_VMA / virt_to_phys / phys_to_virt / PHYS_KVA live in kernel.h — the
 * self-test and SMP bringup paths need them too. */


static uint32_t free_page_stack[USER_PHYS_PAGES];
static int free_page_count = 0;
static uint16_t page_refcounts[USER_PHYS_PAGES];

/* Runtime pool size in frames — how many of the USER_PHYS_PAGES-capacity arrays
 * are actually backed by RAM and handed out. Chosen from the E820 memory map at
 * boot (phys_set_pool_pages, before paging_init); defaults to the pre-E820
 * 64 MiB so a boot that cannot parse a map still runs exactly as before. */
static uint32_t g_phys_pool_pages = USER_PHYS_DEFAULT_PAGES;

uint32_t get_free_user_pages(void) { return (uint32_t)free_page_count; }

void phys_set_pool_pages(uint32_t pages) {
    if (pages < PHYS_POOL_MIN_PAGES) pages = PHYS_POOL_MIN_PAGES;
    if (pages > USER_PHYS_PAGES)     pages = USER_PHYS_PAGES;
    g_phys_pool_pages = pages;
}

/* Shared zero page. One immortal, pre-zeroed frame that every demand-zero READ
 * fault maps read-only + PAGE_COW; the first WRITE turns into a copy-on-write
 * fault that hands the task its own private page. So an allocation that is read
 * but never written costs one shared frame across every task, instead of a fresh
 * zeroed page each. Immortal by construction — task teardown never frees user
 * pages (task_teardown), and free_user_physical_page refuses this frame anyway. */
static uint64_t g_zero_page_phys = 0;

/* Copy-on-write faults resolved (shared-zero private-copy + any future generic
 * COW). Exposed for the COW self-test, which asserts it advanced. */
static uint64_t g_cow_faults = 0;
uint64_t get_cow_fault_count(void) { return g_cow_faults; }

static void init_user_page_allocator(void) {

    free_page_count = 0;
    /* Zero the whole refcount array: the Rust trust boundary is registered over
     * all USER_PHYS_PAGES slots, so every slot must be initialised even though
     * only the first g_phys_pool_pages are ever handed out. */
    for (int i = 0; i < USER_PHYS_PAGES; i++) {
        page_refcounts[i] = 0;
    }
    /* Push only the frames the pool actually covers (E820-sized). Frame i maps to
     * USER_PHYS_BASE + i*PAGE_SIZE; the cap keeps the top below PHYS_POOL_CEIL. */
    for (int i = (int)g_phys_pool_pages - 1; i >= 0; i--) {
        free_page_stack[free_page_count++] = USER_PHYS_BASE + ((uint32_t)i * PAGE_SIZE);
    }
    /* Register the one true refcount table with the Rust trust boundary so any
     * later inc/dec passing a wrong pointer/size is refused rather than trusted. */
    if (!rust_page_refcounts_register(page_refcounts, (uint32_t)USER_PHYS_PAGES)) {
        for (;;) { __asm__ volatile("cli; hlt"); }  /* misconfiguration: refuse to run */
    }
}

uint32_t alloc_user_physical_page(void) {
    
    if (free_page_count == 0) {
        return 0;
    }
    uint32_t phys = free_page_stack[--free_page_count];
    int idx = (phys - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx] = 1;
    }
    return phys;
}

void free_user_physical_page(uint32_t phys_addr) {
    /* The shared zero page is immortal: many PTEs across many tasks alias it, so
     * it must never return to the free list. */
    if ((uint64_t)phys_addr == g_zero_page_phys) return;
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx] = 0;
    }
    if (free_page_count < USER_PHYS_PAGES) {
        free_page_stack[free_page_count++] = phys_addr;
    }
}

void page_ref_inc(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES) {
        page_refcounts[idx]++;
    }
}

int page_ref_dec(uint32_t phys_addr) {
    int idx = (phys_addr - USER_PHYS_BASE) / PAGE_SIZE;
    if (idx >= 0 && idx < USER_PHYS_PAGES && page_refcounts[idx] > 0) {
        page_refcounts[idx]--;
        return page_refcounts[idx];
    }
    return 0;
}

void ensure_lapic_mapped(uint64_t *root);
static void kstack_guards_init(void);   /* defined below per_task_kstacks */
static void kern_fixed_stack_guards_init(void);   /* BSP boot + IST stack guards */

/* ---- The kernel's own view ------------------------------------------------
 *
 * multiboot.S builds ONE page directory (`pd`) covering physical [0, 1 GiB) as
 * 2 MiB pages with P|W and no NX, then hangs it off three separate entries:
 *
 *     pml4[0] -> pdpt[0]  -> pd      the low identity map
 *     high_pdpt[2]        -> pd      the PHYS_KVA window
 *     high_pdpt[510]      -> pd      the kernel's own image mapping
 *
 * (multiboot.S says so itself: "One `pd` is aliased by all three of the entries
 * below; a write here is visible through every view.")
 *
 * The consequence is that the kernel's .text is writable, its .rodata is
 * writable *and* executable, and its .data/.bss are executable — via three
 * aliases, any one of which suffices. EFER.NXE has been on the whole time; no
 * kernel PTE has ever set the NX bit. linker64.ld already page-aligns every
 * section and exports their bounds, so the information needed to do better is
 * present and simply unused.
 *
 * Tightening `pd` in place is not an option: it is the same memory behind all
 * three views, so NX-ing it would unmap the kernel out from under itself
 * mid-instruction. Each consumer needs its own directory first.
 *
 * This function does that for high_pdpt[510] and then maps the image one
 * section at a time, honouring what linker64.ld already laid out:
 *
 *     .text            r-x    read-only, executable
 *     .rodata          r--    read-only, never executable
 *     .data .bss       rw-    writable, never executable
 *     everything else  ---    absent
 *
 * The tables start out entirely absent and each section opts back in, so the
 * gaps — the low megabyte, the dead .boot stage, and the slack between .bss and
 * USER_PHYS_BASE — are unmapped by construction rather than by remembering to
 * punch them out. A stray kernel pointer into any of them faults instead of
 * quietly hitting whatever happened to be there.
 */

/* [0, 16 MiB): the kernel image (~1..15.4 MiB) plus slack to USER_PHYS_BASE.
 * Only PDE 0 strictly needs splitting for the section boundaries, but
 * per_task_kstacks spans PDEs 0..2 and guard pages will need those at 4 KiB
 * too; splitting the whole 16 MiB costs 5 extra pages and removes "which PDE is
 * this address in" from every later question. */
#define KERN_SPLIT_PDES  8

/* Map physical [start, end) with `flags` in a directory built by build_pd().
 * Rounds outward to whole pages: linker64.ld page-aligns every section
 * boundary, so this only matters if a future section stops being aligned, and
 * covering too much is the safe direction — the alternative is silently leaving
 * the tail page absent. */
static void pd_map_range(uint64_t *pdir, uint64_t start, uint64_t end,
                         uint64_t flags) {
    for (uint64_t p = start & ~0xFFFULL; p < end; p += PAGE_SIZE) {
        uint64_t pde = p >> 21;
        if (pde >= KERN_SPLIT_PDES) return;   /* past the 4 KiB-mapped window */
        uint64_t *pt = (uint64_t *)PHYS_KVA(pdir[pde] & PTE_ADDR_MASK);
        pt[(p >> 12) & 511] = p | flags;
    }
}

/* Build a page directory over physical [0, 1 GiB): PDEs 0..KERN_SPLIT_PDES-1 as
 * 4 KiB page tables so the kernel image's section boundaries are expressible,
 * the rest as 2 MiB pages. `low_flags` is applied to every 4 KiB page (0 =
 * absent) and `huge_flags` to the 2 MiB tail; callers then override the ranges
 * they care about with pd_map_range(). Returns 0 on allocation failure.
 *
 * No PAGE_GLOBAL anywhere, though ensure_lapic_mapped sets it on its own split
 * PDEs: a global entry survives the CR3 reload these directories are installed
 * with, so the permissions would only be half in effect. */
/* Make one 4 KiB page of the kernel's own mapping absent, so touching it faults.
 * Only meaningful below KERN_SPLIT_PDES, where that mapping is 4 KiB pages
 * rather than 2 MiB — above it there is no PTE to clear and this refuses rather
 * than silently doing nothing at the wrong granularity. Returns 0 if the page
 * is now absent. */
static int kern_page_set_absent(uint64_t vaddr) {
    extern uint64_t high_pdpt[512];
    uint64_t phys = virt_to_phys(vaddr);
    if ((phys >> 21) >= KERN_SPLIT_PDES) return -1;
    if ((phys & 0xFFFULL) != 0) return -1;          /* not page-aligned */

    uint64_t *kern_pd = (uint64_t *)PHYS_KVA(high_pdpt[510] & PTE_ADDR_MASK);
    uint64_t pde = kern_pd[phys >> 21];
    if (!(pde & PAGE_PRESENT) || (pde & PAGE_PS)) return -1;

    uint64_t *pt = (uint64_t *)PHYS_KVA(pde & PTE_ADDR_MASK);
    pt[(phys >> 12) & 511] = 0;
    __asm__ volatile ("invlpg (%0)" :: "r"(vaddr) : "memory");
    return 0;
}

/* Public wrapper: unmap one page of the kernel's own mapping, returning 0 when
 * it is now absent. Exists so the SMP AP IST-stack guards (whose stacks live in
 * gdt.c, out of this file's reach) arm through the exact same kernel-window
 * unmap the per-task and fixed stack guards use, rather than a second copy of
 * the walk. Like those, it must run before smp_bringup() so the cleared entry is
 * inherited into every AP's CR3 with no shootdown. */
int kern_arm_guard_page(uint64_t vaddr) {
    return kern_page_set_absent(vaddr);
}

static uint64_t build_pd(uint64_t low_flags, uint64_t huge_flags) {
    uint64_t pd_phys = alloc_user_physical_page();
    if (pd_phys == 0) return 0;
    uint64_t *pdir = (uint64_t *)PHYS_KVA(pd_phys);

    for (int i = 0; i < KERN_SPLIT_PDES; i++) {
        uint64_t pt_phys = alloc_user_physical_page();
        if (pt_phys == 0) return 0;
        uint64_t *pt = (uint64_t *)PHYS_KVA(pt_phys);
        for (int j = 0; j < 512; j++) {
            uint64_t frame = ((uint64_t)i << 21) | ((uint64_t)j << 12);
            pt[j] = low_flags ? (frame | low_flags) : 0;
        }
        pdir[i] = pt_phys | PAGE_PRESENT | PAGE_WRITE;
    }
    for (int i = KERN_SPLIT_PDES; i < 512; i++) {
        pdir[i] = ((uint64_t)i << 21) | huge_flags;
    }
    return pd_phys;
}

static void kernel_remap_init(void) {
    extern uint64_t pml4[512];
    extern uint64_t high_pdpt[512];
    extern uint64_t pd[512];
    /* linker64.ld exports these; every one is 4 KiB-aligned, which is what makes
     * per-section permissions expressible at page granularity at all. */
    extern uint8_t __text_start[],   __text_end[];
    extern uint8_t __rodata_start[], __rodata_end[];
    extern uint8_t __data_start[],   __bss_end[];

    (void)pd;   /* the shared boot directory; both views below replace it */

    const uint64_t text_start = virt_to_phys(__text_start);
    const uint64_t text_end   = virt_to_phys(__text_end);
    const uint64_t ro_start   = virt_to_phys(__rodata_start);
    const uint64_t ro_end     = virt_to_phys(__rodata_end);
    const uint64_t data_start = virt_to_phys(__data_start);
    const uint64_t bss_end    = virt_to_phys(__bss_end);

    /* ---- View 1: the kernel's own mapping, high_pdpt[510] -----------------
     * Starts absent; the image opts back in section by section, so the low
     * megabyte, the dead .boot stage (linked VA == PA, reached through the low
     * identity map, and finished once long_mode_low has run) and the slack
     * between .bss and USER_PHYS_BASE are unmapped by construction rather than
     * by remembering to punch them out.
     *
     * The 2 MiB tail is [16 MiB, 1 GiB) — the physical page pool at its kernel
     * alias. It inherited `pd`'s P|W and no NX, which made it a supervisor RWX
     * alias of every page userspace owns: ring 3 writes its own page, and the
     * same frame is executable at KERNEL_VMA+phys, where SMEP does not apply
     * because the mapping is supervisor rather than user. It is data to the
     * kernel; NX it. */
    uint64_t kern_pd_phys = build_pd(0 /* absent */,
                                     PAGE_PRESENT | PAGE_WRITE | PAGE_PS | PAGE_NX);
    if (kern_pd_phys == 0) return;   /* keep the alias: a partial view is worse */
    uint64_t *kern_pd = (uint64_t *)PHYS_KVA(kern_pd_phys);

    pd_map_range(kern_pd, text_start, text_end, PAGE_PRESENT);                          /* r-x */
    pd_map_range(kern_pd, ro_start,   ro_end,   PAGE_PRESENT | PAGE_NX);                /* r-- */
    pd_map_range(kern_pd, data_start, bss_end,  PAGE_PRESENT | PAGE_WRITE | PAGE_NX);   /* rw- */

    /* ---- View 2: the PHYS_KVA window, high_pdpt[2] ------------------------
     * This is where the policy above leaks away if it is left alone. The window
     * aliases the same `pd`, mapping physical [0, 1 GiB) writable AND
     * executable — and that gigabyte contains the kernel's own .text. Marking
     * .text read-only at its kernel address while an RW+X alias of the same
     * frames stays open is not a weaker policy, it is no policy.
     *
     * Two separate holes, and NX alone only closes one of them:
     *
     *   - execute through the window. Nothing needs it: every user derefences
     *     this window as data — page tables, the zero page, VGA text and the
     *     font plane, freshly allocated frames, and the AP trampoline blob,
     *     which is copied here and then executed through the identity map at
     *     0x8000, not through this alias. So the whole window is NX.
     *
     *   - write .text through the window, execute it at its kernel address.
     *     NX does not touch this one: the frame is writable here and executable
     *     there, so W^X is defeated across the pair even though neither view is
     *     W+X by itself. Nothing writes .text or .rodata through the window
     *     either, so those frames are read-only here too, which closes it.
     *
     * Everything else keeps W, because the window is how the kernel legitimately
     * writes: VGA and the trampoline below 1 MiB, the boot page tables in .bss
     * (ensure_lapic_mapped walks pml4[0]'s pdpt through PHYS_KVA), and the
     * allocator pool above 16 MiB. */
    uint64_t phys_pd_phys = build_pd(PAGE_PRESENT | PAGE_WRITE | PAGE_NX,
                                     PAGE_PRESENT | PAGE_WRITE | PAGE_PS | PAGE_NX);
    if (phys_pd_phys == 0) return;   /* nothing installed yet; the alias stands */
    uint64_t *phys_pd = (uint64_t *)PHYS_KVA(phys_pd_phys);

    pd_map_range(phys_pd, text_start, ro_end, PAGE_PRESENT | PAGE_NX);   /* r-- */

    /* ---- View 3: the low identity map, pdpt[0] ----------------------------
     * The last alias, and the one whose necessity is overstated in three
     * comments. It maps physical [0, 1 GiB) RWX at its own address, which is a
     * third writable+executable view of the kernel image and of every page in
     * the allocator pool.
     *
     * Almost none of it is needed. Every symbol linked low is boot-stage —
     * _start, long_mode_low, boot_gdt, boot_stack_top ("low scratch stack; the
     * real one is high") — and all of it is finished before paging_init runs.
     * The AP trampoline is the single exception: it far-jumps to `long_mode` at
     * ~0x8000 *after* enabling paging on this CR3, and then reads the cells at
     * 0x8FD8/0x8FE8. Blob and cells share one page (the blob is 286 bytes at
     * 0x8000; the cells sit at offset 0xFD8), so one page covers it.
     *
     * That page is R+X, not RWX. The BSP writes the blob through the PHYS_KVA
     * window (smp.c copies to PHYS_KVA(AP_TRAMP_PHYS)) and the AP executes it
     * here, so the write alias and the execute alias are different mappings and
     * neither is W+X on its own.
     *
     * It stays mapped for the life of the kernel rather than being dropped
     * after bringup: the BSP's wait for the APs is bounded (smp.c gives up
     * after a fixed spin count and continues), so a straggler can still be
     * inside the trampoline when bringup "finishes". Unmapping on that basis
     * would be a race whose loser executes unmapped memory. One R+X page,
     * writable through no alias but PHYS_KVA, is the cheaper trade.
     *
     * pml4[0] itself must survive regardless — 0xFEE00000 decodes to
     * pml4[0]/pdpt[3], so the LAPIC hangs off the same PML4 entry through a
     * *different* PDPT slot. Only pdpt[0] is replaced. */
    uint64_t ident_pd_phys = build_pd(0 /* absent */, 0 /* absent */);
    if (ident_pd_phys == 0) return;
    uint64_t *ident_pd = (uint64_t *)PHYS_KVA(ident_pd_phys);
    pd_map_range(ident_pd, AP_TRAMP_PHYS, AP_TRAMP_PHYS + PAGE_SIZE, PAGE_PRESENT); /* r-x */

    /* The swap. Everything above was written through the PHYS_KVA window, so
     * the live tables have not been touched until these single aligned 8-byte
     * stores — which the page walker either sees or does not. There is no
     * half-written state to be caught executing in.
     *
     * high_pdpt[2] last: every write above reached its table *through* it, so
     * it has to stay as it is until there is nothing left to write. It only
     * gains NX, never loses present or write, so the writes already issued
     * remain valid afterwards.
     *
     * pdpt is reached through pml4[0] rather than by naming the symbol: that
     * follows the tables the CPU is actually walking instead of assuming the
     * boot layout, and it keeps pml4 the only page-table global C needs. */
    uint64_t *pdpt = (uint64_t *)PHYS_KVA(pml4[0] & PTE_ADDR_MASK);
    pdpt[0]        = ident_pd_phys | PAGE_PRESENT | PAGE_WRITE;
    high_pdpt[510] = kern_pd_phys  | PAGE_PRESENT | PAGE_WRITE;
    high_pdpt[2]   = phys_pd_phys  | PAGE_PRESENT | PAGE_WRITE;

    /* Reload CR3 rather than invlpg: this replaced a PDPTE covering a gigabyte,
     * and none of the entries under it are global. */
    uint64_t cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(cr3));
    __asm__ volatile ("mov %0, %%cr3" :: "r"(cr3) : "memory");

    /* CR0.WP, without which everything above is decoration.
     *
     * With WP clear — and it has been clear since boot, CR0 reads 0x80000013 —
     * a supervisor write IGNORES the PTE's read/write bit completely. The
     * read-only mappings just installed would be honoured for ring 3 and
     * silently disregarded for ring 0, which is the only ring that can reach
     * them. Verified the hard way: with the r-x PTEs live but WP clear, a write
     * to __text_start still landed.
     *
     * NX needs no such switch — EFER.NXE alone enforces it — so the executable
     * half of W^X worked and the read-only half did not. Set it last, once the
     * tables it applies to are actually in place. */
    uint64_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= (1UL << 16);
    __asm__ volatile ("mov %0, %%cr0" :: "r"(cr0) : "memory");
}

void paging_init(void) {
    init_user_page_allocator();
    /* Reserve and zero the shared zero page up front, so the very first
     * demand-zero read fault can alias it. */
    g_zero_page_phys = alloc_user_physical_page();
    if (g_zero_page_phys) {
        uint8_t *z = (uint8_t *)PHYS_KVA(g_zero_page_phys);
        for (int i = 0; i < PAGE_SIZE; i++) z[i] = 0;
    }
    set_tss_kernel_stack(KERNEL_TSS_STACK);
    /* SMEP/SMAP are enabled by cpu_enable_protections(), not here. An SMAP
     * enable block used to sit at this point, but paging_init() runs before
     * cpu_detect_features() (see kernel_main), so it tested a platform struct
     * that was still zeroed .bss and never once fired. It read as protection
     * that was not there. */
    extern uint64_t pml4[512];
    if ((pml4[510] & 0x1) == 0) {
        /* Self-map. The entry needs pml4's PHYSICAL address; `(uint64_t)pml4` is
         * its virtual one and is only the same number because the kernel is
         * linked identity-mapped.
         *
         * NX, because a recursive map is 512 GiB of page tables addressable as
         * ordinary memory, and page-table entries are full of attacker-influenced
         * physical addresses — a classic surface for spraying bytes that happen to
         * decode as instructions. Nothing executes through the self-map; it exists
         * to read and write table entries. NX on an upper-level entry vetoes
         * execute for everything beneath it, so this one bit covers the whole
         * region. */
        pml4[510] = virt_to_phys(pml4) | 0x3 | PAGE_NX;
    }
    ensure_lapic_mapped(NULL);
    /* Last: give the kernel's own mapping a page directory of its own. Must stay
     * ahead of smp_bringup() — the APs load the BSP's live CR3 (smp.c publishes
     * it to AP_CR3_CELL), so they inherit whatever view exists at that moment
     * and need no fixup of their own. */
    kernel_remap_init();
    /* Needs the 4 KiB kernel mapping kernel_remap_init just installed, and must
     * stay ahead of smp_bringup() for the same reason it does: the APs inherit
     * this CR3, so a guard unmapped now needs no cross-CPU shootdown. */
    kstack_guards_init();
    kern_fixed_stack_guards_init();
#ifdef SMP
    /* Same boot-time, pre-smp_bringup() arming for the per-CPU AP IST fault
     * stacks (defined in gdt.c). The APs inherit this CR3, so their guards are
     * absent from the first fault they take on an IST stack. */
    extern void ap_ist_guards_init(void);
    ap_ist_guards_init();
#endif
    return;
}

/* Per-task kernel stacks (4 MiB of .bss, at KERNEL_VMA + ~1.5 MiB).
 *
 * This array used to sit at [1.46, 5.43) MiB — inside the user window — and its
 * top edge was the floor of the kernel's always-critical globals, exposed as
 * kernel_lowmem_critical_floor() so the heap allocator and image ASLR could
 * refuse to place user pages over kernel state. With the kernel at KERNEL_VMA
 * no kernel address is a user address, so that function and its guards are gone. */
static uint8_t per_task_kstacks[MAX_TASKS][KERNEL_STACK_SIZE * 2] __attribute__((aligned(4096)));

/* Count of stack guards actually unmapped; read by the gated self-test, which
 * would otherwise pass just as happily if this loop never ran. */
uint32_t kstack_guards_armed = 0;

#ifdef WX_SELFTEST
/* per_task_kstacks is file-local and should stay that way; the self-test needs
 * the guard address without the array coming with it. Gated, so the ship build
 * does not carry an accessor into the kernel's stacks at all. */
uint64_t kstack_guard_vaddr(int id) {
    if (id < 0 || id >= MAX_TASKS) return 0;
    return (uint64_t)(uintptr_t)per_task_kstacks[id];
}
#endif

/* Unmap the guard page below every task's kernel stack.
 *
 * create_user_pagedir has always carved a page off the bottom of each stack
 * area and called it a guard, but only ever used it to offset stack_base — the
 * page stayed mapped and its present bit was never touched. So a kernel stack
 * overflow ran straight through the "guard" into the next task's stack and
 * corrupted it silently, which is the failure the guard exists to make loud.
 * The name was there; the protection was not.
 *
 * Doing it here rather than per-task is what keeps it simple: the stacks are a
 * static array that never moves, so their guards are a property of the image,
 * not of any task. One pass at boot, before the APs exist, means no TLB
 * shootdown and nothing to redo when a task slot is reused.
 *
 * Slot 0 is included: task 0 (the boot/idle/reaper) now runs on
 * per_task_kstacks[0] too — create_user_pagedir binds its stack above this same
 * guard — so its kernel stack is guarded like every other task's. It used to
 * keep a separate, unguarded task0_kernel_stack, which is why slot 0 was skipped
 * and its guard left mapped. The array is in the 4 KiB-mapped kernel window
 * (KERN_SPLIT_PDES), so every slot's guard, including 0, is unmappable. */
static void kstack_guards_init(void) {
    for (int i = 0; i < MAX_TASKS; i++) {
        if (kern_page_set_absent((uint64_t)(uintptr_t)per_task_kstacks[i]) == 0)
            kstack_guards_armed++;
    }
}

/* The BSP boot stack and the three boot IST fault stacks are fixed, single
 * purpose stacks defined in multiboot.S, outside the per_task_kstacks array.
 * Each is laid out above a page-aligned guard page there; this unmaps those
 * guards so an overflow of the boot/idle stack or of a fault handler's IST stack
 * faults instead of silently corrupting adjacent .bss/.data or the TSS. They all
 * live in the kernel image below KERN_SPLIT_PDES, so the guards are 4 KiB pages
 * that kern_page_set_absent can clear — the same requirement per_task_kstacks
 * meets. IST1 (#DF/#GP/#PF) is used on every demand page fault and every ring-3
 * fault-signal delivery, so its guard is exercised constantly, not just in
 * theory. */
uint32_t fixed_stack_guards_armed = 0;

/* Ordered exactly as the self-test enumerates them (see WX_SELFTEST accessor). */
static uint64_t fixed_stack_guard_addr(int i) {
    extern uint8_t bsp_stack_guard[];
    extern uint8_t ist1_stack_guard[];
    extern uint8_t ist2_stack_guard[];
    extern uint8_t ist3_stack_guard[];
    switch (i) {
        case 0: return (uint64_t)(uintptr_t)bsp_stack_guard;
        case 1: return (uint64_t)(uintptr_t)ist1_stack_guard;
        case 2: return (uint64_t)(uintptr_t)ist2_stack_guard;
        case 3: return (uint64_t)(uintptr_t)ist3_stack_guard;
        default: return 0;
    }
}
#define FIXED_STACK_GUARD_COUNT 4

static void kern_fixed_stack_guards_init(void) {
    for (int i = 0; i < FIXED_STACK_GUARD_COUNT; i++) {
        if (kern_page_set_absent(fixed_stack_guard_addr(i)) == 0)
            fixed_stack_guards_armed++;
    }
}

#ifdef WX_SELFTEST
/* Gated: expose the fixed-stack guard count and addresses so smoke-wx can assert
 * each guard is absent and the stack just above it is still present. */
uint32_t kern_fixed_stack_guard_count(void) { return FIXED_STACK_GUARD_COUNT; }
uint64_t kern_fixed_stack_guard_vaddr(int i) { return fixed_stack_guard_addr(i); }
#endif

/* ---- Address-space reclaim ------------------------------------------------
 *
 * Every spawn allocated a page-directory tree plus the task's premapped image
 * and stack pages — 71 frames, 284 KiB, measured — and nothing ever gave them
 * back. task_teardown only marks the slot dead, and free_user_physical_page was
 * defined and never called from anywhere in the tree. With a 16384-frame pool
 * that is ~230 spawns to exhaustion, and init relaunches the shell every time it
 * exits or faults, so logging out repeatedly is enough to reach it. No attacker
 * required; it is a normal-usage bug.
 *
 * Reclaimed at slot reuse rather than at teardown, and that is not an
 * implementation detail. task_teardown runs BEFORE task_exit_switch, so the
 * dying task's CR3 can still be the one the CPU is walking — freeing there is a
 * use-after-free of the page tables in active use, and it would be a rare,
 * timing-dependent one. By the time create_user_pagedir builds a new task in
 * this slot, do_spawn and exec_into_armed_image have already switched to the
 * kernel address space, so nothing is standing on the old tree.
 *
 * The cost is that a dead task's memory is held until its slot is reused, which
 * bounds the pool at MAX_TASKS x the per-task footprint (~18 MiB of 64) instead
 * of letting it run to zero. Bounded is the property worth having.
 */

/* Drop one reference to a leaf frame, returning it only when the last goes.
 *
 * Leaves are refcounted because they are aliased: the shared zero page backs
 * every demand-zero read in every task, and a COW pair shares the original
 * frame until someone writes. Freeing on sight would pull a live page out from
 * under another task. rust_page_ref_dec fails closed — negative for an
 * out-of-range frame or one already at zero — and only an exact 0 means the
 * reference this address space held was the last one. */
static void user_leaf_release(uint64_t phys) {
    int32_t refs = rust_page_ref_dec((uint32_t)phys, page_refcounts,
                                     (uint32_t)USER_PHYS_PAGES);
    if (refs == 0) free_user_physical_page((uint32_t)phys);
}

/* Free one level of a user page-table tree, then the table itself.
 * `level`: 4 = PML4, 3 = PDPT, 2 = PD, 1 = PT.
 *
 * Recursive rather than a hand-unrolled four-deep walk, so it frees whatever
 * shape it is handed — including the deeper trees a wider user address space
 * will build. Tables are never aliased (each is allocated for exactly one
 * address space), so they are freed outright; only leaves go through the
 * refcount. */
static void free_user_table(uint64_t table_phys, int level) {
    uint64_t *t = (uint64_t *)PHYS_KVA(table_phys);
    for (int i = 0; i < 512; i++) {
        uint64_t e = t[i];
        if (!(e & PAGE_PRESENT)) continue;
        uint64_t child = e & PTE_ADDR_MASK;
        if (level == 1 || (e & PAGE_PS)) {
            user_leaf_release(child);        /* 4 KiB, 2 MiB or 1 GiB leaf */
        } else {
            free_user_table(child, level - 1);
        }
    }
    free_user_physical_page((uint32_t)table_phys);
}

/* Release the address space a previous task left behind in this slot. Walks the
 * USER half only: pml4[256..511] is the kernel's own mapping, shared by every
 * task and by the kernel itself, and pml4[510] is the self-map pointing back at
 * this very table — freeing either would take the kernel down rather than the
 * task. */
static void free_user_aspace(uint64_t pml4_phys);

#ifdef ASPACE_SELFTEST
/* Gated: the self-test releases a space it built, to prove the pool comes back.
 * Not exported in the ship build — nothing outside this file should be able to
 * tear down an address space out of band. */
void free_user_aspace_for_test(uint64_t pml4_phys) { free_user_aspace(pml4_phys); }

/* Gated: map a page at an arbitrary VA, so the self-test can show the walker
 * reaches addresses the old fixed three-table shape could not express, and
 * refuses the ones it must. */
static int user_map_fresh_page(uint64_t *pml4_tab, uint64_t vaddr, uint64_t flags);
int user_map_fresh_page_for_test(uint64_t pml4_phys, uint64_t vaddr, uint64_t flags) {
    return user_map_fresh_page((uint64_t *)PHYS_KVA(pml4_phys), vaddr, flags);
}
#endif

static void free_user_aspace(uint64_t pml4_phys) {
    if (pml4_phys == 0) return;
    uint64_t *p4 = (uint64_t *)PHYS_KVA(pml4_phys);
    for (int i = 0; i < 256; i++) {
        uint64_t e = p4[i];
        if (!(e & PAGE_PRESENT)) continue;
        free_user_table(e & PTE_ADDR_MASK, 3);
        p4[i] = 0;
    }
    free_user_physical_page((uint32_t)pml4_phys);
}

/* ---- Building a user address space ----------------------------------------
 *
 * The premap used to be hand-rolled around one fixed shape: pml4[0] -> pdpt[0]
 * -> pd -> two page tables, everything reachable only inside [0, 1 GiB). That
 * shape *was* the ASLR ceiling. ASLR_MAX_LOAD_RANDOM_PAGES is literally
 * `512 - USER_ASPACE_PREMAP_PAGES` — the number of 4 KiB slots left in one 2 MiB
 * PD entry once the premap is subtracted — so the entropy figure was a
 * restatement of the page-table layout, not a security decision. Nothing above
 * 1 GiB could be mapped at all.
 *
 * These walk to a page and allocate whatever levels are missing, so a mapping
 * costs the same code at 4 MiB as at 0x7fff_0000_0000. */

static bool is_canonical_address(uint64_t addr);   /* defined below */

/* Follow `tab[idx]` down a level, allocating the next table if absent.
 * Intermediate entries carry PAGE_USER because the CPU ANDs U across every
 * level: a user page under a supervisor table is unreachable from ring 3, and
 * the leaf's own bits are what actually restrict it. */
static uint64_t *user_table_next(uint64_t *tab, uint64_t idx) {
    uint64_t e = tab[idx];
    if (e & PAGE_PRESENT) {
        /* A huge page here means someone already mapped this range at a coarser
         * granularity. Splitting it under a caller that asked for 4 KiB would
         * silently change what every other address in the range maps to, so
         * refuse rather than guess. */
        if (e & PAGE_PS) return 0;
        return (uint64_t *)PHYS_KVA(e & PTE_ADDR_MASK);
    }
    uint64_t phys = alloc_user_physical_page();
    if (phys == 0) return 0;
    uint64_t *t = (uint64_t *)PHYS_KVA(phys);
    for (int i = 0; i < 512; i++) t[i] = 0;
    tab[idx] = phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
    return t;
}

/* Resolve `vaddr` to its 4 KiB PTE slot, building the path down to it.
 * Returns 0 for an address this must never map, or if a table could not be
 * allocated. */
static uint64_t *user_pte_slot(uint64_t *pml4_tab, uint64_t vaddr) {
    /* Non-canonical addresses are not merely invalid to the CPU — the shift
     * below would index a table from bits the hardware ignores, so a rejected
     * address and an accepted one could land on the same slot. */
    if (!is_canonical_address(vaddr)) return 0;

    uint64_t i4 = (vaddr >> 39) & 511;
    /* The hard line: pml4[256..511] is the kernel's own half, shared into every
     * task, and pml4[510] is the self-map. A user mapping installed there would
     * be a user-writable alias of kernel page tables — the whole point of the
     * higher-half split. Nothing this function is asked to map belongs there,
     * so treat any such request as a bug and refuse it rather than trusting the
     * caller's bounds. */
    if (i4 >= 256) return 0;

    uint64_t *pdpt = user_table_next(pml4_tab, i4);
    if (!pdpt) return 0;
    uint64_t *pd = user_table_next(pdpt, (vaddr >> 30) & 511);
    if (!pd) return 0;
    uint64_t *pt = user_table_next(pd, (vaddr >> 21) & 511);
    if (!pt) return 0;
    return &pt[(vaddr >> 12) & 511];
}

/* Map one 4 KiB user page. Returns 0 on success. */
static int user_map_page(uint64_t *pml4_tab, uint64_t vaddr, uint64_t phys,
                         uint64_t flags) {
    uint64_t *slot = user_pte_slot(pml4_tab, vaddr);
    if (!slot) return -1;
    *slot = phys | flags;
    return 0;
}

/* Allocate a zeroed frame and map it at `vaddr`. Returns 0 on success; on
 * failure nothing is left half-mapped and the frame is returned to the pool. */
static int user_map_fresh_page(uint64_t *pml4_tab, uint64_t vaddr, uint64_t flags) {
    uint64_t phys = alloc_user_physical_page();
    if (phys == 0) return -1;
    uint8_t *pg = (uint8_t *)PHYS_KVA(phys);
    for (int b = 0; b < PAGE_SIZE; b++) pg[b] = 0;
    if (user_map_page(pml4_tab, vaddr, phys, flags) != 0) {
        free_user_physical_page((uint32_t)phys);
        return -1;
    }
    return 0;
}

void create_user_pagedir(uint32_t task_id) {
    if (task_id >= MAX_TASKS) return;
    if (task_id == 0) {
        /* Task 0 runs on the kernel's own address space (cr3 = 0 means "keep the
         * kernel pml4"), but it still needs a kernel stack for the reaper/idle
         * path. Bind it to per_task_kstacks[0], above the guard page
         * kstack_guards_init unmaps, so an overflow of task 0 faults on the guard
         * instead of running into whatever .bss follows — the same protection
         * every other task's stack already had. */
        tasks[task_id].cr3 = 0;
        uint8_t *stack_area = per_task_kstacks[0];
        uint64_t stack_base = (uint64_t)stack_area + PAGE_SIZE;   /* skip the guard */
        tasks[task_id].kernel_stack_top = stack_base + KERNEL_STACK_SIZE - 16;
        return;
    }

    spin_lock(&page_lock);

    /* Reclaim the previous occupant of this slot before building the new one.
     * Safe here and nowhere earlier: the caller is on the kernel CR3, so the
     * tree about to be freed is not the one any CPU is walking. */
    if (tasks[task_id].cr3) {
        free_user_aspace(tasks[task_id].cr3);
        tasks[task_id].cr3 = 0;
    }
    
    uint64_t pml4_phys = alloc_user_physical_page();
    if (pml4_phys == 0) { println("pagedir: no pml4 phys"); spin_unlock(&page_lock); return; }
    uint64_t *pml4_tab = (uint64_t *)PHYS_KVA(pml4_phys);
    /* User half [0..255] stays zero; the task's own mappings are built below. */
    for (int i = 0; i < 512; i++) pml4_tab[i] = 0;

    extern uint64_t pml4[512];

    /* Kernel half: share the kernel's mappings so the kernel remains addressable
     * on this CR3 (syscalls, ISRs, the pager), but strip PAGE_USER so ring 3
     * cannot reach any of it. This is what carries PHYS_KVA into every task.
     * The [510] self-map is set after this loop — it would overwrite it. */
    for (int i = 256; i < 512; i++) {
        pml4_tab[i] = pml4[i] & ~((uint64_t)PAGE_USER);
    }

    /* NOTHING is mapped in the user half but the task's own pages.
     *
     * This used to identity-fill PD[0..7] — physical [0, 16 MiB) as supervisor
     * 2 MiB huge pages — because the kernel was linked low and had to reach
     * tasks[]/the page tables/its own .bss while running on this CR3. The kernel
     * now lives at KERNEL_VMA and is reached through the pml4[256..511] copy
     * above, so replicating low memory into a user address space has no purpose.
     * A user page directory can no longer contain a mapping for any address the
     * kernel uses, so a user mapping cannot shadow kernel state *by
     * construction* rather than by a bound on where ASLR may place things.
     *
     * The premap below no longer builds the page-table path by hand either. It
     * used to allocate exactly one PDPT, one PD and one PT and index them
     * directly, which is why the image had to fit inside a single 2 MiB PD entry
     * and why nothing above 1 GiB was addressable at all. user_map_fresh_page
     * walks to whatever address it is given and allocates the levels it needs,
     * so the base is now bounded by policy (ASLR_MAX_LOAD_RANDOM_PAGES) rather
     * than by the shape of the tables. */

    uint64_t vbase = tasks[task_id].image_base ? (uint64_t)tasks[task_id].image_base
                                               : (uint64_t)USER_AREA_BASE;

    /* The image window. Premap the staged image's whole loaded span
     * (image_premap_pages, set by the spawn/exec path from staged_image_span_pages;
     * 0 for task 0 / flat demos falls back to the fixed default), clamped to
     * USER_IMAGE_MAX_PAGES. The loader writes each PT_LOAD segment with
     * copy_to_user, which needs the target pages present, so this must cover the
     * image or a load larger than the premap fails on its first unmapped page.
     * Left not-present outside the premap, so a fault there reaches the pager
     * (which gates on the task's own region bounds) instead of finding the
     * identity-supervisor page this used to fill in. */
    uint64_t premap_pages = tasks[task_id].image_premap_pages
                                ? tasks[task_id].image_premap_pages
                                : (uint64_t)USER_ASPACE_PREMAP_PAGES;
    if (premap_pages > USER_IMAGE_MAX_PAGES) premap_pages = USER_IMAGE_MAX_PAGES;
    int build_failed = 0;
    for (uint64_t p = 0; p < premap_pages; p++) {
        uint64_t va   = vbase + p * PAGE_SIZE;
        uint32_t prot = rust_get_user_page_protection(task_id, va);
        uint64_t flags = prot ? (prot & 0x7) : (PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
        if (user_map_fresh_page(pml4_tab, va, flags) != 0) { build_failed = 1; break; }
    }

    /* The low user stack: 32 pages below 0x7ff000, USER + NX (W^X: a stack is
     * data). No longer needs a "different PD entry from the image" guard — the
     * walker shares a level correctly when two regions land in one, and
     * allocates a fresh one when they do not. */
    if (!build_failed) {
        uint64_t low_stack_top  = 0x007ff000ULL;
        uint64_t low_stack_base = low_stack_top - (32ULL * PAGE_SIZE);
        for (uint64_t s = 0; s < 32; s++) {
            uint64_t va = low_stack_base + s * PAGE_SIZE;
            if (user_map_fresh_page(pml4_tab, va,
                                    PAGE_PRESENT | PAGE_WRITE | PAGE_USER | PAGE_NX) != 0) {
                build_failed = 1;
                break;
            }
        }
    }

    /* A half-built address space must never run: the task would fault on the
     * first unmapped page of its own image. Give the pages back and leave cr3 at
     * 0 so the slot is plainly unusable rather than subtly wrong. Freeing here is
     * only possible because the reclaim exists — this path used to leak
     * everything it had allocated before failing. */
    if (build_failed) {
        println("pagedir: out of physical pages");
        free_user_aspace(pml4_phys);
        tasks[task_id].cr3 = 0;
        spin_unlock(&page_lock);
        return;
    }

    /* pml4[0] is not installed here any more: the walker installs whichever
     * PML4 entries the mapped addresses actually need, which for a low image is
     * still [0] and for a high one is not.
     *
     * The self-map. Index 510 is in the kernel half, so the walker refuses it by
     * design and it is written directly — it points at pml4_phys itself, which is
     * a kernel structure, not one of the task's pages. NX because nothing
     * executes through a page-table alias (see paging_init's kernel self-map).
     * It must come after the pml4[256..511] copy above, which would overwrite
     * it with the kernel's own. */
    pml4_tab[510] = pml4_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_NX;

    ensure_lapic_mapped(pml4_tab);

    tasks[task_id].cr3 = pml4_phys;

    
    /* The stack must be large enough for the deepest in-kernel call chain —
     * notably the Argon2id password hash run from SYS_AUTH, which stacks several
     * 1 KiB blocks and overflowed the old 8 KiB stack (login hung). */
    uint8_t *stack_area = per_task_kstacks[task_id];
    /* The first page of the area is the guard, unmapped once at boot by
     * kstack_guards_init. The stack starts above it and grows down onto it, so
     * an overflow faults on the guard instead of reaching the previous task's
     * stack. Nothing to do per task: the guard is a property of the static
     * array, and a reused slot inherits the same absent page. */
    uint64_t guard_vaddr = (uint64_t)stack_area;
    uint64_t stack_base = guard_vaddr + PAGE_SIZE;
    tasks[task_id].kernel_stack_top = stack_base + KERNEL_STACK_SIZE - 16;
    spin_unlock(&page_lock);
}

void switch_cr3(addr_t cr3) {
    
    if (cr3 == 0) {
        
        for(;;) { asm volatile("cli; hlt"); }
    }
    
    if ((cr3 & 0xFFFULL) != 0) {
        for(;;) { asm volatile("cli; hlt"); }
    }
    asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
    /* The CR3 reload above already flushed this CPU's non-global TLB entries, so
     * a purely local address-space switch needs no cross-CPU shootdown. (A real
     * shootdown -- for tearing down or reducing permissions on a mapping another
     * CPU may have cached -- goes through smp_maybe_shootdown at that site, with
     * interrupts enabled and no scheduler lock held, so its ack wait is safe.) */
}

int handle_demand_page_fault(uint64_t fault_addr, uint32_t err_code) {
    
    uint64_t cr3_phys = tasks[get_current_task()].cr3;
    if (cr3_phys == 0) {
        /* page_lock is NOT held yet (we lock below), so must not unlock here:
         * a stray spin_unlock releases a lock we never took and decrements the
         * IRQ-nesting depth, corrupting interrupt state if ever reached under a
         * held lock. */
        int tid = get_current_task();
        tasks[tid].state = 0;
        return -1;
    }

    spin_lock(&page_lock);

    /* Page tables live in the user page pool (>= USER_PHYS_BASE = 16 MiB) and we
     * are running on the faulting task's CR3, whose low identity map only covers
     * [0, 16 MiB). Reach every table through the higher-half alias. */
    uint64_t *pml4v = (uint64_t *)PHYS_KVA(cr3_phys);

    uint64_t v = fault_addr;
    uint64_t pml4_i = (v >> 39) & 0x1FF;
    uint64_t pdpt_i = (v >> 30) & 0x1FF;
    uint64_t pd_i   = (v >> 21) & 0x1FF;
    uint64_t pt_i   = (v >> 12) & 0x1FF;

    uint64_t pml4e = pml4v[pml4_i];
    if ((pml4e & PAGE_PRESENT) == 0) { spin_unlock(&page_lock); return -1; }
    uint64_t *pdptv = (uint64_t *)PHYS_KVA(pml4e & ~0xFFFULL);

    uint64_t pdpte = pdptv[pdpt_i];
    /* A 1 GiB huge PDPTE has no page directory below it: its 30-bit-aligned frame
     * base is NOT a table pointer. Walking into it would read (and then write)
     * arbitrary memory as if it were a page table. Refuse. */
    if ((pdpte & PAGE_PRESENT) && (pdpte & PAGE_PS)) { spin_unlock(&page_lock); return -1; }
    if ((pdpte & PAGE_PRESENT) == 0) {

        uint64_t new_pd_phys = alloc_user_physical_page();
        if (new_pd_phys == 0) { spin_unlock(&page_lock); return -3; }
        uint64_t *new_pd = (uint64_t *)PHYS_KVA(new_pd_phys);
        for (int i = 0; i < 512; i++) new_pd[i] = 0;
        pdptv[pdpt_i] = new_pd_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        pdpte = pdptv[pdpt_i];
        asm volatile("invlpg (%0)" :: "r"(v) : "memory");
    }
    uint64_t *pdv = (uint64_t *)PHYS_KVA(pdpte & ~0xFFFULL);

    uint64_t pde = pdv[pd_i];
    /* Same for a 2 MiB huge PDE. create_user_pagedir premaps PD[0..7] as
     * supervisor huge pages, so without this the walker treats a 2 MiB frame base
     * as a page table, reads kernel .bss as a PTE, and can write a user PTE over
     * it — while the fault never resolves, so it re-faults and drains the page
     * pool. Nothing legitimate demand-faults inside a huge mapping. */
    if ((pde & PAGE_PRESENT) && (pde & PAGE_PS)) { spin_unlock(&page_lock); return -1; }
    if ((pde & PAGE_PRESENT) == 0) {

        uint64_t new_pt_phys = alloc_user_physical_page();
        if (new_pt_phys == 0) { spin_unlock(&page_lock); return -3; }
        uint64_t *new_pt = (uint64_t *)PHYS_KVA(new_pt_phys);
        for (int i = 0; i < 512; i++) new_pt[i] = 0;
        pdv[pd_i] = new_pt_phys | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
        pde = pdv[pd_i];
        asm volatile("invlpg (%0)" :: "r"(v) : "memory");
    }
    uint64_t *ptv = (uint64_t *)PHYS_KVA(pde & ~0xFFFULL);

    uint64_t pte = ptv[pt_i];

    int is_write = (err_code & 2) != 0;

    if (is_write && (pte & PAGE_COW) != 0) {
        /* Mask with PTE_ADDR_MASK, not ~0xFFF: a noexec page has NX (bit 63) set,
         * which ~0xFFF leaves in place — the frame address would then carry bit 63
         * and every dereference/compare below would go wrong. */
        uint64_t old_phys = pte & PTE_ADDR_MASK;

        /* Shared zero page: a write to a demand-zero page that was only read so
         * far. Hand out a private page — the "copy" of an all-zero frame is just
         * zeros, so there is nothing to copy and the immortal zero frame's
         * refcount is never touched (it is aliased by many PTEs and must not move).
         * Preserve W^X from the faulting address. */
        if (old_phys == g_zero_page_phys) {
            uint64_t np = alloc_user_physical_page();
            if (np == 0) { spin_unlock(&page_lock); return -3; }
            uint8_t *d = (uint8_t *)PHYS_KVA(np);
            for (int i = 0; i < PAGE_SIZE; i++) d[i] = 0;
            uint64_t nf = PAGE_PRESENT | PAGE_WRITE | PAGE_USER;   /* COW cleared */
            if (rust_user_page_is_noexec(fault_addr)) nf |= PAGE_NX;
            ptv[pt_i] = np | nf;
            g_cow_faults++;
            asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
            spin_unlock(&page_lock);
            return 0;
        }

        int refs = rust_page_ref_dec((uint32_t)old_phys,
                                     page_refcounts,
                                     (uint32_t)USER_PHYS_PAGES);

        int is_write_f = 1;
        if (!rust_cow_copy_required(true, is_write_f != 0, (uint16_t)((refs > 0 ? refs : 0) + 1))) {
            if (refs >= 0) {
                (void)rust_page_ref_inc((uint32_t)old_phys,
                                        page_refcounts,
                                        (uint32_t)USER_PHYS_PAGES);
            }
            spin_unlock(&page_lock);
            return 0;
        }

        uint64_t new_phys = alloc_user_physical_page();
        if (new_phys == 0) {
            if (refs >= 0) {
                (void)rust_page_ref_inc((uint32_t)old_phys,
                                        page_refcounts,
                                        (uint32_t)USER_PHYS_PAGES);
            }
            spin_unlock(&page_lock);
            return -3;
        }

        /* Both frames are in the user pool (>= 16 MiB), unreachable through the
         * low identity map on this task's CR3 — copy via the higher-half alias. */
        uint8_t *src = (uint8_t *)PHYS_KVA(old_phys);
        uint8_t *dst = (uint8_t *)PHYS_KVA(new_phys);
        for (int i = 0; i < PAGE_SIZE; i++) dst[i] = src[i];

        (void)rust_page_ref_inc((uint32_t)new_phys,
                                page_refcounts,
                                (uint32_t)USER_PHYS_PAGES);

        uint64_t new_flags = (pte & 0xFFFULL) | PAGE_PRESENT | PAGE_WRITE;
        new_flags &= ~((uint64_t)PAGE_COW);
        /* Preserve W^X across copy-on-write: the low-12-bit mask above drops
         * the NX bit (63), so re-derive it from the faulting address. */
        if (rust_user_page_is_noexec(fault_addr)) new_flags |= PAGE_NX;
        ptv[pt_i] = new_phys | new_flags;
        g_cow_faults++;

        asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
        spin_unlock(&page_lock);
        return 0;
    }

    if ((pte & PAGE_PRESENT) != 0) {

        spin_unlock(&page_lock);
        return -2;
    }

    /* Region gate: only demand-map an address that is a legitimate part of this
     * task's user space (image, heap, or the low stack window). A fault anywhere
     * else — a wild pointer, the kernel-.bss shadow in [4, 16) MiB, the gaps
     * between regions — is a real access violation. Return -1 without mapping so
     * the fault handler turns it into a SIGSEGV, rather than silently backing an
     * arbitrary address with a fresh page. */
    int tid_g = get_current_task();
    if (tid_g <= 0 || tid_g >= MAX_TASKS ||
        !rust_validate_page_fault(fault_addr, err_code,
                                  tasks[tid_g].image_base, tasks[tid_g].image_end,
                                  (uint32_t)tasks[tid_g].heap_start,
                                  (uint32_t)tasks[tid_g].heap_end)) {
        spin_unlock(&page_lock);
        return -1;
    }

    /* A READ fault on a fresh page: alias the shared zero page read-only + COW.
     * The page reads as zeros with no allocation; a later write takes the COW
     * fault above and gets a private page. A WRITE fault skips this and allocates
     * a private page directly, so the common write-first case does not pay a
     * second fault. */
    if (!is_write && g_zero_page_phys) {
        uint64_t zflags = PAGE_PRESENT | PAGE_USER | PAGE_COW;   /* read-only: no PAGE_WRITE */
        if (rust_user_page_is_noexec(fault_addr)) zflags |= PAGE_NX;
        ptv[pt_i] = g_zero_page_phys | zflags;
        asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
        spin_unlock(&page_lock);
        return 0;
    }

    uint64_t phys = alloc_user_physical_page();
    if (phys == 0) {
        spin_unlock(&page_lock);
        return -3;
    }

    /* Zero through the higher-half alias: `phys` is in the user pool at/above
     * 16 MiB, which this task's CR3 does not identity-map. */
    uint8_t *page = (uint8_t *)PHYS_KVA(phys);
    for (int i = 0; i < PAGE_SIZE; i++) page[i] = 0;

    uint32_t prot = rust_get_user_page_protection(get_current_task(), fault_addr);
    uint64_t flags = prot ? (prot & 0x7ULL) : (PAGE_PRESENT | PAGE_WRITE | PAGE_USER);
    /* Demand-paged stack pages are non-executable (W^X). */
    if (rust_user_page_is_noexec(fault_addr)) flags |= PAGE_NX;
    ptv[pt_i] = phys | flags | PAGE_PRESENT;

    asm volatile("invlpg (%0)" :: "r"(fault_addr) : "memory");
    spin_unlock(&page_lock);
    return 0;
}

void drop_to_ring3(addr_t entry, addr_t stack) {
    __asm__ volatile ("movw $0x3f8,%%dx; movb $'E',%%al; outb %%al,%%dx; movb $'N',%%al; outb %%al,%%dx; movb $'T',%%al; outb %%al,%%dx" ::: "rax","rdx","memory");
    asm volatile (
        "cli\n"
        "mov $0x33, %%ax\n"
        "mov %%ax, %%ds\n"
        "mov %%ax, %%es\n"
        "mov %%ax, %%fs\n"
        "mov %%ax, %%gs\n"
        "push $0x33\n"
        "push %[user_rsp]\n"
        "push $0x202\n"
        "push $0x2b\n"
        "push %[user_rip]\n"
        "iretq\n"
        :
        : [user_rsp] "r" (stack),
          [user_rip] "r" (entry)
        : "memory", "rax"
    );
}

static bool is_canonical_address(uint64_t addr) {
    uint64_t high_bits = addr >> 48;
    return (high_bits == 0) || (high_bits == 0xFFFF);
}

#define PT_PHYS_MASK 0x000FFFFFFFFFF000ULL


static uint64_t pt_walk(uint64_t cr3, uint64_t v) {
    uint64_t *t = (uint64_t *)PHYS_KVA(cr3 & PT_PHYS_MASK);
    uint64_t e = t[(v >> 39) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    t = (uint64_t *)PHYS_KVA(e & PT_PHYS_MASK);
    e = t[(v >> 30) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    if (e & PAGE_4MB) return e;                 
    t = (uint64_t *)PHYS_KVA(e & PT_PHYS_MASK);
    e = t[(v >> 21) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    if (e & PAGE_4MB) return e;                 
    t = (uint64_t *)PHYS_KVA(e & PT_PHYS_MASK);
    e = t[(v >> 12) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return 0;
    return e;
}

/* Return the leaf page-table entry mapping `vaddr` in the address space rooted
 * at `cr3` (raw PTE including flag bits), or 0 if not present. Read-only walk
 * by physical address; used by the ELF-loader self-test to inspect the W^X
 * bits try_elf_load produced. */
uint64_t user_lookup_pte(uint64_t cr3, uint64_t vaddr) {
    if (cr3 == 0) return 0;
    return pt_walk(cr3, vaddr);
}

/* Apply final W^X protection to an already-mapped 4 KiB user page in the
 * CURRENT task's address space: clear PAGE_WRITE unless `writable`, and set the
 * NX bit (63) unless `executable`. The ELF loader maps segments writable, copies
 * the bytes in, then calls this per page to honour the segment's p_flags so code
 * ends up read+execute and data ends up read+write+no-execute.
 *
 * Walks the page tables through PHYS_KVA with a present-bit check at every
 * level, exactly as create_user_pagedir does. (This comment used to say the walk
 * relied on low memory being identity-mapped; the body has used PHYS_KVA for
 * some time, and the low map is now a single page for the AP trampoline.) No TLB
 * shootdown is needed: the target task is not yet scheduled, so its CR3 is
 * loaded fresh when it first runs. Returns 0 on success, -1 if the page is
 * absent or not a 4 KiB leaf. */
int user_protect_page(uint64_t vaddr, int writable, int executable) {
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return -1;
    uint64_t cr3 = tasks[cur].cr3;
    if (cr3 == 0) return -1;

    uint64_t *t = (uint64_t *)PHYS_KVA(cr3 & PT_PHYS_MASK);
    uint64_t e = t[(vaddr >> 39) & 0x1FF];
    if (!(e & PAGE_PRESENT)) return -1;
    t = (uint64_t *)PHYS_KVA(e & PT_PHYS_MASK);
    e = t[(vaddr >> 30) & 0x1FF];
    if (!(e & PAGE_PRESENT) || (e & PAGE_4MB)) return -1;
    t = (uint64_t *)PHYS_KVA(e & PT_PHYS_MASK);
    e = t[(vaddr >> 21) & 0x1FF];
    if (!(e & PAGE_PRESENT) || (e & PAGE_4MB)) return -1;
    t = (uint64_t *)PHYS_KVA(e & PT_PHYS_MASK);
    int i = (int)((vaddr >> 12) & 0x1FF);
    uint64_t pte = t[i];
    if (!(pte & PAGE_PRESENT)) return -1;

    if (writable)   pte |= PAGE_WRITE;
    else            pte &= ~(uint64_t)PAGE_WRITE;
    if (executable) pte &= ~PAGE_NX;
    else            pte |= PAGE_NX;

    t[i] = pte;
    return 0;
}


static int user_copy(uint64_t uaddr, uint8_t *kbuf, size_t n, int to_user, int need_write) {
    if (n == 0) return 0;
    int cur = get_current_task();
    if (cur <= 0 || cur >= MAX_TASKS) return -1;
    uint64_t ucr3 = tasks[cur].cr3;
    if (ucr3 == 0) return -1;
    if (!is_canonical_address(uaddr) || (uaddr + n) < uaddr) return -1;

    extern uint64_t pml4[512];
    uint64_t kcr3_phys = virt_to_phys(pml4);   /* CR3 takes a physical address */

    uint64_t fl;
    __asm__ volatile ("pushfq; pop %0; cli" : "=r"(fl) :: "memory");
    uint64_t prev_cr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(prev_cr3));
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3_phys) : "memory");

    int rc = 0;
    size_t done = 0;
    uint64_t need = PAGE_PRESENT | PAGE_USER | (need_write ? (uint64_t)PAGE_WRITE : 0);
    const uint64_t cow_present = PAGE_PRESENT | PAGE_USER | PAGE_COW;
    while (done < n) {
        uint64_t v = uaddr + done;
        uint64_t e = pt_walk(ucr3, v);
        /* A kernel write into a present COW page must break COW first, exactly as
         * a ring-3 write would. Without this, a copy_to_user into a page the task
         * has only read — now aliasing the shared zero page, read-only — would
         * spuriously fail the PAGE_WRITE check below; and writing through the
         * physical alias regardless would corrupt the shared zero frame for every
         * task. Drive the pager's COW path (write fault) and re-walk. */
        if (need_write && (e & cow_present) == cow_present && !(e & PAGE_WRITE)) {
            handle_demand_page_fault(v, (uint32_t)PAGE_WRITE);
            e = pt_walk(ucr3, v);
        }
        if ((e & need) != need) { rc = -1; break; }

        uint64_t phys, chunk;
        if (e & PAGE_4MB) {
            phys  = (e & 0x000FFFFFFFE00000ULL) + (v & 0x1FFFFF);
            chunk = 0x200000 - (v & 0x1FFFFF);
        } else {
            phys  = (e & PT_PHYS_MASK) + (v & 0xFFF);
            chunk = 0x1000 - (v & 0xFFF);
        }
        if (chunk > n - done) chunk = n - done;

        /* Reach the user's frame through the higher-half alias, not its low
         * identity VA: this runs on the KERNEL CR3 (switched above), whose low
         * map covers [0, 1 GiB) today — but the alias is the mapping that is
         * guaranteed to exist in every address space and to survive the kernel
         * moving out of low memory. */
        uint8_t *p = (uint8_t *)PHYS_KVA(phys);
        if (to_user) {
            for (uint64_t i = 0; i < chunk; i++) p[i] = kbuf[done + i];
        } else {
            for (uint64_t i = 0; i < chunk; i++) kbuf[done + i] = p[i];
        }
        done += chunk;
    }

    __asm__ volatile ("mov %0, %%cr3" :: "r"(prev_cr3) : "memory");
    if (fl & 0x200) __asm__ volatile ("sti" ::: "memory");
    return rc;
}

int copy_from_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;
    return user_copy((uint64_t)(uintptr_t)src, (uint8_t *)dst, n, 0, 0);
}

int copy_to_user(void *dst, const void *src, size_t n) {
    if (n == 0) return 0;
    if (n > USER_MEM_MAX_COPY) n = USER_MEM_MAX_COPY;
    return user_copy((uint64_t)(uintptr_t)dst, (uint8_t *)(void *)src, n, 1, 1);
}

void ensure_lapic_mapped(uint64_t *root_pml4) {
    extern uint64_t pml4[512];
    if (root_pml4 == NULL) root_pml4 = pml4;
    const uint64_t vaddr = 0xFEE00000ULL;
    const uint64_t paddr = 0xFEE00000ULL;
    const int pml4i = (int)((vaddr >> 39) & 511);
    const int pdpti = (int)((vaddr >> 30) & 511);
    const int pdi   = (int)((vaddr >> 21) & 511);
    const int pti   = (int)((vaddr >> 12) & 511);
    const uint64_t PS_BIT = (1ULL << 7); 

    uint64_t ent = root_pml4[pml4i];
    uint64_t *pdpt = (uint64_t *)PHYS_KVA(ent & ~0xFFFULL);
    if ((ent & PAGE_PRESENT) == 0 || !pdpt) {
        uint64_t np = alloc_user_physical_page();
        if (np == 0) return;
        pdpt = (uint64_t *)PHYS_KVA(np);
        for (int k = 0; k < 512; k++) pdpt[k] = 0;
        root_pml4[pml4i] = np | PAGE_PRESENT | PAGE_WRITE;
    }

    
    ent = pdpt[pdpti];
    if (ent & PS_BIT) {
        uint64_t huge_base = ent & ~0xFFFULL & ~((1ULL<<30)-1); 
        uint64_t npd_phys = alloc_user_physical_page();
        if (npd_phys == 0) return;
        uint64_t *npd = (uint64_t *)PHYS_KVA(npd_phys);
        for (int j = 0; j < 512; j++) {
            
            uint64_t base2m = huge_base + ((uint64_t)j << 21);
            npd[j] = base2m | PAGE_PRESENT | PAGE_WRITE | PS_BIT | PAGE_GLOBAL;
        }
        pdpt[pdpti] = npd_phys | PAGE_PRESENT | PAGE_WRITE; 
        ent = pdpt[pdpti];
    }

    uint64_t *pd = (uint64_t *)PHYS_KVA(ent & ~0xFFFULL);
    if ((ent & PAGE_PRESENT) == 0 || !pd) {
        uint64_t np = alloc_user_physical_page();
        if (np == 0) return;
        pd = (uint64_t *)PHYS_KVA(np);
        for (int k = 0; k < 512; k++) pd[k] = 0;
        pdpt[pdpti] = np | PAGE_PRESENT | PAGE_WRITE;
    }

    
    ent = pd[pdi];
    if (ent & PS_BIT) {
        uint64_t huge_base = ent & ~0xFFFULL & ~((1ULL<<21)-1);
        uint64_t npt_phys = alloc_user_physical_page();
        if (npt_phys == 0) return;
        uint64_t *npt = (uint64_t *)PHYS_KVA(npt_phys);
        for (int j = 0; j < 512; j++) {
            uint64_t base4k = huge_base + ((uint64_t)j << 12);
            /* NX for the same reason as the leaf below: this splits a 2 MiB page
             * of the MMIO hole into 4 KiB, and none of it is code. */
            uint64_t flags = PAGE_PRESENT | PAGE_WRITE | PAGE_GLOBAL | PAGE_NX;
            if (base4k == paddr) flags |= PAGE_CD;
            npt[j] = base4k | flags;
        }
        pd[pdi] = npt_phys | PAGE_PRESENT | PAGE_WRITE; 
        ent = pd[pdi];
    }

    uint64_t *pt = (uint64_t *)PHYS_KVA(ent & ~0xFFFULL);
    if ((ent & PAGE_PRESENT) == 0 || !pt) {
        uint64_t np = alloc_user_physical_page();
        if (np == 0) return;
        pt = (uint64_t *)PHYS_KVA(np);
        for (int k = 0; k < 512; k++) pt[k] = 0;
        pd[pdi] = np | PAGE_PRESENT | PAGE_WRITE;
    }

    
    /* NX: this is the LAPIC's MMIO registers. The kernel reads and writes them;
     * nothing executes them, and a writable+executable mapping is a W^X hole
     * wherever it is — the register file is as good a place to land shellcode as
     * any other. (Found by the WX_SELFTEST sweep, which flagged it as the one
     * writable-and-executable leaf left in the address space once the kernel
     * image itself was clean. It sits outside the image, so none of the
     * per-section checks would ever have looked at it.) */
    pt[pti] = paddr | PAGE_PRESENT | PAGE_WRITE | PAGE_CD | PAGE_NX;

    asm volatile("invlpg (%0)" :: "r"(vaddr) : "memory");
}
