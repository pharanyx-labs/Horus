/* selftest.c -- gated in-kernel self-tests (ELF loader / preemption / SMP /
 * process lifecycle / signals / filesystem / newlib). Every block is compiled
 * only under its -D*_SELFTEST switch, so the default build yields an (almost)
 * empty object. Split out of syscall.c. */
#include "syscall_internal.h"
#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST)
#include "fs_proto.h"   /* FS_EP_REQ/FS_EP_REP for the FS self-test harnesses */
#endif

#ifdef ASPACE_SELFTEST
/* Gated: prove a rebuilt address space returns the pages the old one held.
 *
 * Every spawn allocates ~71 frames for a task's page tables and its premapped
 * image and stack. Nothing used to give them back — task_teardown only marks the
 * slot dead, and free_user_physical_page had no callers at all — so the pool
 * fell by 284 KiB per spawn until it ran out, ~230 spawns later, and init
 * relaunches the shell on every exit or fault.
 *
 * Building the same slot repeatedly is the test, because slot reuse is exactly
 * when the reclaim runs. The first build has nothing to free and is expected to
 * consume; every one after it must be free-neutral. Asserting on the pool count
 * rather than on the code path means a reclaim that frees only *some* of the
 * tree still fails — which a "did we call free" check would not catch. */
void aspace_selftest(void) {
    const int slot = MAX_TASKS - 1;   /* never spawned into during a normal boot */

    print("ASPACE_SELFTEST: begin\n");

    tasks[slot].image_base = USER_AREA_BASE;
    tasks[slot].image_end  = USER_AREA_BASE;
    tasks[slot].image_premap_pages = 0;   /* default 32-page premap, constant across the rebuilds below */
    tasks[slot].cr3        = 0;

    uint32_t before_first = get_free_user_pages();
    create_user_pagedir((uint32_t)slot);
    uint32_t after_first = get_free_user_pages();

    if (tasks[slot].cr3 == 0 || after_first >= before_first) {
        print("ASPACE_SELFTEST: FAIL first build consumed nothing\n");
        return;
    }
    uint32_t per_aspace = before_first - after_first;

    /* Rebuild the same slot: each pass frees the previous tree and builds a new
     * one, so the count must land back where it started every time. */
    for (int i = 0; i < 8; i++) {
        create_user_pagedir((uint32_t)slot);
        uint32_t now = get_free_user_pages();
        if (now != after_first) {
            print("ASPACE_SELFTEST: FAIL rebuild ");
            print_decimal((uint64_t)i);
            print(" leaked ");
            print_decimal((uint64_t)(after_first - now));
            print(" pages\n");
            return;
        }
    }

    /* And releasing it outright must return everything the first build took. */
    free_user_aspace_for_test(tasks[slot].cr3);
    tasks[slot].cr3 = 0;
    uint32_t after_free = get_free_user_pages();
    if (after_free != before_first) {
        print("ASPACE_SELFTEST: FAIL free returned ");
        print_decimal((uint64_t)(after_free - after_first));
        print(" of ");
        print_decimal((uint64_t)per_aspace);
        print(" pages\n");
        return;
    }

    /* --- The walker reaches what the old fixed shape could not, and refuses
     * what it must.
     *
     * The premap used to allocate exactly one PDPT, one PD and one PT and index
     * them directly, so every user mapping lived under pml4[0]/pdpt[0] — inside
     * [0, 1 GiB). That shape *was* the ASLR ceiling: ASLR_MAX_LOAD_RANDOM_PAGES
     * is literally `512 - USER_ASPACE_PREMAP_PAGES`, the slots left in one 2 MiB
     * PD entry. Mapping above 1 GiB is the whole point of the restructure, so it
     * is worth proving rather than assuming — a refactor that kept the ceiling
     * would pass every test above this one.
     *
     * The rejections matter as much as the mappings. A user page installed in
     * the kernel half would be a ring-3-writable alias of kernel page tables,
     * and a non-canonical address would index a table from bits the CPU ignores
     * — so two different addresses could land on one slot. */
    tasks[slot].image_base = USER_AREA_BASE;
    tasks[slot].image_premap_pages = 0;   /* default 32-page premap; this test checks reach, not size */
    tasks[slot].cr3        = 0;
    create_user_pagedir((uint32_t)slot);
    if (tasks[slot].cr3 == 0) {
        print("ASPACE_SELFTEST: FAIL rebuild for reach test\n");
        return;
    }
    uint64_t cr3 = tasks[slot].cr3;
    const uint64_t uflags = 0x7ULL | (1ULL << 63);   /* P|W|U|NX */

    struct { const char *name; uint64_t va; int want_ok; } reach[] = {
        /* Inside pml4[0] but past pdpt[0]: 2 GiB needed a second PDPT entry, and
         * the old code only ever allocated pdpt[0]. */
        { "2GiB",        0x0000000080000000ULL,             1 },
        /* pml4[255] — exactly where ASLR_HIGH_STACK_BASE claimed to premap a
         * high stack and never did: the old block indexed a PD hanging off
         * pml4[0], so its pages landed near 0x3ffe0000 and nothing read them. */
        { "high-stack",  ASLR_HIGH_STACK_BASE,              1 },
        /* Kernel half: must be refused. */
        { "kernel-half", 0xFFFF800000000000ULL,             0 },
        /* Non-canonical, and chosen so it reaches the canonical check rather
         * than the guard above: bit 48 set with bit 47 clear puts every level
         * index at 0, so pml4 idx is 0 and the kernel-half guard waves it
         * through. Unchecked, the walker would map it at VA 0 — the caller asks
         * for 2^48 and silently gets page zero, and now two addresses alias one
         * slot. (2^47 does not test this: its pml4 idx is exactly 256, so the
         * kernel-half guard catches it first and the canonical check could be
         * deleted with the test still green. It was, until this was fixed.) */
        { "noncanon",    0x0001000000000000ULL,             0 },
    };
    for (unsigned i = 0; i < sizeof(reach) / sizeof(reach[0]); i++) {
        int rc = user_map_fresh_page_for_test(cr3, reach[i].va, uflags);
        if ((rc == 0) != (reach[i].want_ok != 0)) {
            print("ASPACE_SELFTEST: FAIL ");
            print(reach[i].name);
            print(reach[i].want_ok ? " should map but did not\n"
                                   : " mapped but must be refused\n");
            return;
        }
        /* A map that reported success must actually resolve — the page-table
         * path is what is under test, so take the CPU's own view of it. */
        if (reach[i].want_ok && !(user_lookup_pte(cr3, reach[i].va) & 1)) {
            print("ASPACE_SELFTEST: FAIL ");
            print(reach[i].name);
            print(" mapped but does not resolve\n");
            return;
        }
    }
    free_user_aspace_for_test(cr3);
    tasks[slot].cr3 = 0;

    print("ASPACE_SELFTEST: PASS aspace = ");
    print_decimal((uint64_t)per_aspace);
    print(" pages, 8 rebuilds leaked 0, free returned all, maps at 2GiB + pml4[255], refuses kernel-half + noncanon\n");
}
#endif /* ASPACE_SELFTEST */

#ifdef WX_SELFTEST
/* Gated: prove the kernel's own image is mapped W^X — and, more importantly,
 * that *no* mapping in the kernel half is both writable and executable.
 *
 * The per-section checks are the obvious half. The sweep is the half that
 * matters: every hole found while building this policy was an ALIAS — a second
 * mapping of the same frames with different bits. The kernel image was mapped
 * three times over (identity, PHYS_KVA, higher-half) from one shared page
 * directory; the physical window was RW+X across the whole image; the 2 MiB tail
 * was a supervisor RWX alias of every page userspace owns. Each was found by
 * hand, by guessing where to look. Checking .text's own PTE would have caught
 * none of them — .text's own PTE was fine.
 *
 * So the invariant is stated over the address space rather than over the
 * sections: walk every present leaf and assert none is simultaneously writable
 * and executable, whatever it maps and however many times it is mapped. That is
 * the property the policy is actually for.
 *
 * The walk covers ALL of pml4, not just the kernel half [256..511]. The low
 * identity map hangs off pml4[0] — the user half — even though every page in it
 * is a supervisor mapping the kernel installed for itself. A sweep of the kernel
 * half alone reads as thorough and misses it: restoring the old [0, 1 GiB) RWX
 * identity map leaves such a sweep reporting PASS on 8790 clean leaves while a
 * gigabyte of writable, executable kernel image sits one entry to the left.
 * Nothing has run at this point but the kernel, so everything in this CR3 —
 * both halves — is the kernel's own.
 *
 * Both permissions accumulate across levels, so a leaf's own bits are not the
 * answer:
 *   - NX is an OR: set at any level, execute is vetoed beneath it.
 *   - W is an AND (given CR0.WP): clear at any level, writes are refused below.
 * Reading the leaf alone would be wrong in both directions. */

#define WX_PRESENT (1ULL << 0)
#define WX_WRITE   (1ULL << 1)
#define WX_PS      (1ULL << 7)
#define WX_NX      (1ULL << 63)
#define WX_ADDR    0x000FFFFFFFFFF000ULL

static uint64_t wx_leaves_seen;
static uint64_t wx_violations;

/* Recurse one level. `w` = writable so far (AND), `nx` = non-executable so far
 * (OR). `level` counts down: 4 = PML4, 3 = PDPT, 2 = PD, 1 = PT. */
static void wx_walk(uint64_t table_phys, int level, int w, int nx) {
    /* An NX subtree cannot contain a W+X leaf, whatever is under it. Pruning
     * here is not just speed: the self-map points pml4[510] back at pml4, so an
     * unpruned walk would recurse into the page tables forever. It is NX, which
     * is exactly why that is safe. */
    if (nx) return;

    uint64_t *t = (uint64_t *)PHYS_KVA(table_phys);
    for (int i = 0; i < 512; i++) {
        uint64_t e = t[i];
        if (!(e & WX_PRESENT)) continue;

        int cw  = w  && (e & WX_WRITE);
        int cnx = nx || (e & WX_NX) != 0;

        if (level == 1 || (e & WX_PS)) {        /* a leaf: 4 KiB, 2 MiB or 1 GiB */
            wx_leaves_seen++;
            if (cw && !cnx) wx_violations++;    /* writable AND executable */
            continue;
        }
        wx_walk(e & WX_ADDR, level - 1, cw, cnx);
    }
}

void wx_selftest(void) {
    extern uint64_t pml4[512];
    extern uint8_t __text_start[], __text_end[];
    extern uint8_t __rodata_start[];
    extern uint8_t __data_start[], __bss_start[];

    int ok = 1;
    const char *why = "";

    /* --- The bits are only a policy if the CPU is applying them, and the two
     * halves are enforced by different switches. NX needs only EFER.NXE. But a
     * read-only bit is ignored for supervisor writes unless CR0.WP is set, and
     * ring 0 is the only ring that can reach these pages — so with WP clear the
     * entire r-x/r-- half of the table below is decoration, while looking
     * perfect. It was clear for the project's whole history: every PTE checked
     * out and a write to __text_start still landed. Check the switches before
     * trusting the bits. */
    uint64_t cr0;
    __asm__ volatile ("mov %%cr0, %0" : "=r"(cr0));
    if (!((cr0 >> 16) & 1)) {
        print("WX_SELFTEST: FAIL CR0.WP clear — ring 0 ignores every read-only bit below\n");
        return;
    }
    uint32_t efer_lo, efer_hi;
    __asm__ volatile ("rdmsr" : "=a"(efer_lo), "=d"(efer_hi) : "c"(0xC0000080));
    if (!((efer_lo >> 11) & 1)) {
        print("WX_SELFTEST: FAIL EFER.NXE clear — the NX bits below are inert\n");
        return;
    }

    /* --- Per-section spot checks. user_lookup_pte returns the leaf entry; for these
     * addresses every upper level is writable and executable, so the leaf's own
     * bits are the effective ones. The sweep below is what does not assume that. */
    uint64_t kcr3 = virt_to_phys(pml4);
    struct { const char *name; uint64_t va; int want_w; int want_nx; } secs[] = {
        { "text",   (uint64_t)(uintptr_t)__text_start,   0, 0 },   /* r-x */
        { "rodata", (uint64_t)(uintptr_t)__rodata_start, 0, 1 },   /* r-- */
        { "data",   (uint64_t)(uintptr_t)__data_start,   1, 1 },   /* rw- */
        { "bss",    (uint64_t)(uintptr_t)__bss_start,    1, 1 },   /* rw- */
    };
    for (unsigned i = 0; i < sizeof(secs) / sizeof(secs[0]); i++) {
        uint64_t e = user_lookup_pte(kcr3, secs[i].va);
        if (!(e & WX_PRESENT))                        { ok = 0; why = secs[i].name; break; }
        if (!!(e & WX_WRITE) != secs[i].want_w)       { ok = 0; why = secs[i].name; break; }
        if (!!(e & WX_NX)    != secs[i].want_nx)      { ok = 0; why = secs[i].name; break; }
    }
    if (!ok) {
        print("WX_SELFTEST: FAIL section bits wrong: "); print(why); print("\n");
        return;
    }

    /* --- .text must be read-only through its PHYS_KVA alias too. This is the
     * cross-alias hole: writable via one mapping and executable via another
     * defeats W^X across the pair, while neither mapping is W+X by itself. The
     * sweep cannot see it — it checks each leaf alone — so it is checked here. */
    uint64_t tphys = virt_to_phys(__text_start);
    uint64_t ae = user_lookup_pte(kcr3, (uint64_t)PHYS_KVA(tphys));
    if (!(ae & WX_PRESENT) || (ae & WX_WRITE)) {
        print("WX_SELFTEST: FAIL .text writable through its PHYS_KVA alias\n");
        return;
    }

    /* --- Kernel stack guards. These were computed and then never unmapped, so
     * the check that matters is that the page is ABSENT — a mapped guard is the
     * bug, and it looks identical from any angle except this one. The armed
     * count is checked too: an empty loop would satisfy the absence test
     * vacuously if the stacks were never mapped in the first place. */
    extern uint32_t kstack_guards_armed;
    extern uint64_t kstack_guard_vaddr(int id);
    if (kstack_guards_armed != (uint32_t)MAX_TASKS) {
        print("WX_SELFTEST: FAIL armed ");
        print_decimal(kstack_guards_armed);
        print(" stack guards, expected ");
        print_decimal((uint64_t)MAX_TASKS);
        print("\n");
        return;
    }
    /* From 0: task 0 (boot/idle/reaper) now runs on a guarded per_task_kstacks[0]
     * too, so its guard must be absent and its stack present like the rest. */
    for (int i = 0; i < MAX_TASKS; i++) {
        uint64_t guard = kstack_guard_vaddr(i);
        if (user_lookup_pte(kcr3, guard) & WX_PRESENT) {
            print("WX_SELFTEST: FAIL stack guard still mapped for task ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
        /* The stack itself must still be there — unmapping one page too many
         * would take the stack with it, and every task would fault on entry. */
        if (!(user_lookup_pte(kcr3, guard + PAGE_SIZE) & WX_PRESENT)) {
            print("WX_SELFTEST: FAIL stack base unmapped for task ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
    }

    /* --- Fixed (non-per-task) kernel stack guards: the BSP boot stack and the
     * three boot IST fault stacks. Same contract — guard absent, stack above it
     * present — for stacks that live in multiboot.S rather than per_task_kstacks. */
    extern uint32_t fixed_stack_guards_armed;
    extern uint32_t kern_fixed_stack_guard_count(void);
    extern uint64_t kern_fixed_stack_guard_vaddr(int i);
    uint32_t fixed_n = kern_fixed_stack_guard_count();
    if (fixed_stack_guards_armed != fixed_n) {
        print("WX_SELFTEST: FAIL armed ");
        print_decimal(fixed_stack_guards_armed);
        print(" fixed stack guards, expected ");
        print_decimal((uint64_t)fixed_n);
        print("\n");
        return;
    }
    for (uint32_t i = 0; i < fixed_n; i++) {
        uint64_t guard = kern_fixed_stack_guard_vaddr((int)i);
        if (user_lookup_pte(kcr3, guard) & WX_PRESENT) {
            print("WX_SELFTEST: FAIL fixed stack guard still mapped, index ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
        if (!(user_lookup_pte(kcr3, guard + PAGE_SIZE) & WX_PRESENT)) {
            print("WX_SELFTEST: FAIL fixed stack base unmapped, index ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
    }

#ifdef SMP
    /* --- Per-CPU AP IST fault stacks (SMP builds only). Same contract as the
     * fixed IST stacks above — guard absent, stack page above it present — for
     * the per-core IST stacks in gdt.c. Only reachable when built WX_SELFTEST=1
     * SMP=1 (make smoke-wx-smp); the default WX build has no ap_ist. */
    extern uint32_t ap_ist_guards_armed;
    extern uint32_t ap_ist_guard_count(void);
    extern uint64_t ap_ist_guard_vaddr(int i);
    uint32_t ap_n = ap_ist_guard_count();
    if (ap_ist_guards_armed != ap_n) {
        print("WX_SELFTEST: FAIL armed ");
        print_decimal(ap_ist_guards_armed);
        print(" AP IST guards, expected ");
        print_decimal((uint64_t)ap_n);
        print("\n");
        return;
    }
    for (uint32_t i = 0; i < ap_n; i++) {
        uint64_t guard = ap_ist_guard_vaddr((int)i);
        if (user_lookup_pte(kcr3, guard) & WX_PRESENT) {
            print("WX_SELFTEST: FAIL AP IST guard still mapped, index ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
        if (!(user_lookup_pte(kcr3, guard + PAGE_SIZE) & WX_PRESENT)) {
            print("WX_SELFTEST: FAIL AP IST stack unmapped, index ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
    }
#endif /* SMP */

    /* --- The global invariant, over every entry in this CR3. */
    wx_leaves_seen = 0;
    wx_violations  = 0;
    uint64_t *p4 = (uint64_t *)PHYS_KVA(kcr3);
    for (int i = 0; i < 512; i++) {
        uint64_t e = p4[i];
        if (!(e & WX_PRESENT)) continue;
        wx_walk(e & WX_ADDR, 3, (e & WX_WRITE) != 0, (e & WX_NX) != 0);
    }

    /* A sweep that walked nothing would pass every assertion above it. */
    if (wx_leaves_seen < 1000) {
        print("WX_SELFTEST: FAIL swept only ");
        print_decimal(wx_leaves_seen);
        print(" leaves — walk is not reaching the kernel mappings\n");
        return;
    }
    if (wx_violations) {
        print("WX_SELFTEST: FAIL ");
        print_decimal(wx_violations);
        print(" of ");
        print_decimal(wx_leaves_seen);
        print(" leaves are writable AND executable\n");
        return;
    }

    print("WX_SELFTEST: PASS sections r-x/r--/rw- + no W^X violation in ");
    print_decimal(wx_leaves_seen);
    print(" leaves\n");
}
#endif /* WX_SELFTEST */

#ifdef CPU_SELFTEST
/* Gated: prove the CR4 protections are actually engaged, against a known
 * environment.
 *
 * tools/smoke_test.sh boots QEMU with -cpu qemu64,+smep,+smap,+umip, so all
 * three ARE advertised here. That is what makes "the kernel reports them
 * absent" a failure rather than an honest answer about the hardware, and it is
 * why this test knows something a code read cannot: a detection bug looks like
 * a CPU without the feature.
 *
 * Written after exactly that bug. cpu_detect_features read CPUID leaf 7 with
 * whatever ECX the previous CPUID had left behind (the tail of the vendor
 * string), which is far past leaf 7's max_subleaf of 0, so EBX read back as
 * zero. Both features looked absent on every boot, cpu_enable_protections had
 * nothing to turn on, and the kernel ran with SMEP and SMAP off while
 * documenting them as enabled. Asking the kernel what it detected would have
 * agreed with the kernel; this pins it to the harness's -cpu line instead. */
void cpu_protections_selftest(void) {
    uint64_t cr4;
    __asm__ volatile ("mov %%cr4, %0" : "=r"(cr4));

    int ok = 1;
    const char *why = "";
    if      (!platform.has_smep)      { ok = 0; why = "smep-advertised-but-not-detected"; }
    else if (!((cr4 >> 20) & 1))      { ok = 0; why = "smep-detected-but-not-in-cr4"; }
    else if (!platform.has_smap)      { ok = 0; why = "smap-advertised-but-not-detected"; }
    else if (!((cr4 >> 21) & 1))      { ok = 0; why = "smap-detected-but-not-in-cr4"; }
    else if (!platform.has_umip)      { ok = 0; why = "umip-advertised-but-not-detected"; }
    else if (!((cr4 >> 11) & 1))      { ok = 0; why = "umip-detected-but-not-in-cr4"; }

    if (ok) {
        print("CPU_SELFTEST: PASS smep+smap+umip detected and enabled in CR4\n");
    } else {
        print("CPU_SELFTEST: FAIL "); print(why); print("\n");
    }
}
#endif /* CPU_SELFTEST */

#if defined(ELF_SELFTEST) || defined(ELF64_SELFTEST)
/* In-kernel self-test of the ELF loader's W^X enforcement (gated; never in the
 * ship build). Loads a real multi-segment ELF (userspace/elftest.elf, embedded
 * in multiboot.S) through the production do_spawn -> try_elf_load path, then
 * inspects the resulting page-table entries to prove try_elf_load honoured each
 * PT_LOAD's p_flags: .text R+X (executable), .data R+W+NX, .rodata R(O)+NX.
 * Because EFER.NXE is asserted enabled at boot, correct NX/WRITE bits mean the
 * CPU will enforce W^X. Prints ELF_SELFTEST: PASS / FAIL <reason> to serial;
 * the headless smoke test (make smoke-elf) asserts on PASS.
 *
 * The PTE defines and read helpers below are shared with the ELF64 variant
 * (ELF64_SELFTEST), hence the wider guard. */
#define SELFTEST_PTE_PRESENT  (1ULL << 0)
#define SELFTEST_PTE_WRITE    (1ULL << 1)
#define SELFTEST_PTE_USER     (1ULL << 2)
#define SELFTEST_PTE_NX       (1ULL << 63)
#define SELFTEST_PTE_PHYS     0x000FFFFFFFFFF000ULL

static int selftest_read_byte(uint64_t cr3, uint64_t vaddr, uint8_t *out) {
    uint64_t pte = user_lookup_pte(cr3, vaddr);
    if (!(pte & SELFTEST_PTE_PRESENT)) return -1;
    uint64_t phys = (pte & SELFTEST_PTE_PHYS) | (vaddr & 0xFFF);
    *out = *(volatile uint8_t *)PHYS_KVA(phys);
    return 0;
}

__attribute__((unused))
static int selftest_read_u32(uint64_t cr3, uint64_t vaddr, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b;
        if (selftest_read_byte(cr3, vaddr + i, &b) != 0) return -1;
        v |= (uint32_t)b << (i * 8);
    }
    *out = v;
    return 0;
}

__attribute__((unused))
static int selftest_read_u64(uint64_t cr3, uint64_t vaddr, uint64_t *out) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b;
        if (selftest_read_byte(cr3, vaddr + i, &b) != 0) return -1;
        v |= (uint64_t)b << (i * 8);
    }
    *out = v;
    return 0;
}
#endif /* ELF_SELFTEST || ELF64_SELFTEST */

#ifdef ELF_SELFTEST

static void elf64_wr(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

/* Stage a minimal ELF64 with one PT_LOAD, so a single 8-byte field can be
 * driven out of 32-bit range per case. p_filesz/p_memsz of 0 mean the loader
 * copies nothing and maps nothing even when it accepts the header. */
static void elf64_build_min(uint64_t e_phoff, uint64_t p_offset,
                            uint64_t p_vaddr, uint64_t p_filesz,
                            uint64_t p_memsz) {
    for (uint32_t i = 0; i < 256; i++) loader_staging[i] = 0;
    uint8_t *st = loader_staging;
    st[0] = 0x7f; st[1] = 'E'; st[2] = 'L'; st[3] = 'F';
    st[4] = 2;                            /* ELFCLASS64  */
    st[5] = 1;                            /* ELFDATA2LSB */
    st[16] = 2;                           /* e_type = ET_EXEC */
    st[18] = 62;                          /* e_machine = EM_X86_64 */
    elf64_wr(st + 24, USER_AREA_BASE);    /* e_entry */
    elf64_wr(st + 32, e_phoff);
    st[56] = 1;                           /* e_phnum */

    uint8_t *p = st + 64;                 /* where the baseline e_phoff points */
    p[0] = 1;                             /* p_type = PT_LOAD */
    p[4] = 5;                             /* p_flags = PF_R|PF_X */
    elf64_wr(p + 8,  p_offset);
    elf64_wr(p + 16, p_vaddr);
    elf64_wr(p + 32, p_filesz);
    elf64_wr(p + 40, p_memsz);
    elf64_wr(p + 48, 4096);               /* p_align */
}

/* Every ELF64 address/size field is 8 bytes wide while the loader's plumbing is
 * 32-bit. Reading only the low half would not just lose range, it would defeat
 * the bounds checks — they would validate a number that is not the one in the
 * file — so each read must fail closed (-17) instead.
 *
 * The control case matters as much as the rejections: the same header with
 * every field in range must NOT return -17. Without it these cases would still
 * pass if the loader rejected the fixture for some unrelated malformation, and
 * the test would prove nothing. */
static int elf64_narrow_checks_ok(const char **why) {
    const uint64_t HIGH = 0x100000000ULL;   /* one bit above the 32-bit window */
    uint64_t entry = 0, img_end = 0;

    elf64_build_min(64, 0, USER_AREA_BASE, 0, 0);
    if (try_elf_load(USER_AREA_BASE, &entry, &img_end) == -17) {
        *why = "narrow-control-rejected"; return 0;
    }

    struct { uint64_t phoff, off, va, filesz, memsz; const char *name; } cases[] = {
        { 64 | HIGH, 0,    USER_AREA_BASE,        0,    0,    "narrow-e_phoff"  },
        { 64,        0,    USER_AREA_BASE | HIGH, 0,    0,    "narrow-p_vaddr"  },
        { 64,        HIGH, USER_AREA_BASE,        0,    0,    "narrow-p_offset" },
        { 64,        0,    USER_AREA_BASE,        HIGH, 0,    "narrow-p_filesz" },
        { 64,        0,    USER_AREA_BASE,        0,    HIGH, "narrow-p_memsz"  },
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        elf64_build_min(cases[i].phoff, cases[i].off, cases[i].va,
                        cases[i].filesz, cases[i].memsz);
        if (try_elf_load(USER_AREA_BASE, &entry, &img_end) != -17) {
            *why = cases[i].name; return 0;
        }
    }
    return 1;
}

void elf_loader_selftest(void) {
    extern uint8_t embedded_elftest_start[];
    extern uint8_t embedded_elftest_end[];
    uint32_t sz = (uint32_t)(embedded_elftest_end - embedded_elftest_start);

    print("ELF_SELFTEST: begin\n");

    /* Run before the real image is staged: these cases scribble on
     * loader_staging, which the staging below then refills. */
    const char *nwhy = "";
    if (!elf64_narrow_checks_ok(&nwhy)) {
        print("ELF_SELFTEST: FAIL "); print(nwhy); print("\n");
        return;
    }

    if (sz == 0 || sz > MAX_PROGRAM_SIZE) { print("ELF_SELFTEST: FAIL embed-size\n"); return; }

    /* Stage the raw ELF and arm it; try_elf_load recomputes the real entry. */
    for (uint32_t i = 0; i < sz; i++) loader_staging[i] = embedded_elftest_start[i];
    armed_hdr.entry = 0;
    armed_hdr.size  = sz;
    armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
    armed_hdr.name[3] = 't'; armed_hdr.name[4] = 0;
    program_armed = 1;

    int saved = get_current_task();
    int pid = do_spawn();                 /* runs the real try_elf_load + W^X pass */
    if (pid <= 0) { print("ELF_SELFTEST: FAIL spawn\n"); set_current_task(saved); return; }

    uint64_t cr3  = tasks[pid].cr3;
    uint64_t base = tasks[pid].image_base;   /* ASLR-randomized load base */

    /* Parse the three PT_LOAD program headers from the staged (base-0) ELF to
     * locate each segment by its permission flags, so the checks hold at the
     * randomized base (identify by PF_X -> text, PF_W -> data, R-only -> rodata). */
    const uint8_t *est = loader_staging;
    uint32_t e_phoff = elf_rd32(est + 28);
    uint16_t e_phnum = (uint16_t)est[44] | ((uint16_t)est[45] << 8);
    uint32_t text_va = 0xFFFFFFFFu, ro_va = 0xFFFFFFFFu, data_va = 0xFFFFFFFFu;
    for (uint16_t i = 0; i < e_phnum && i < 16; i++) {
        const uint8_t *p = est + e_phoff + (uint32_t)i * 32;
        if (elf_rd32(p) != 1) continue;            /* PT_LOAD */
        uint32_t va = elf_rd32(p + 8);
        uint32_t fl = elf_rd32(p + 24);
        if      (fl & 1u) text_va = va;            /* PF_X */
        else if (fl & 2u) data_va = va;            /* PF_W */
        else              ro_va   = va;            /* R only */
    }

    int ok = 1;
    const char *why = "";
    if (text_va == 0xFFFFFFFFu || ro_va == 0xFFFFFFFFu || data_va == 0xFFFFFFFFu) {
        ok = 0; why = "phdr-missing";
    }

    uint64_t pte_text = 0, pte_data = 0, pte_ro = 0;
    if (ok) {
        pte_text = user_lookup_pte(cr3, (uint64_t)base + text_va);
        pte_data = user_lookup_pte(cr3, (uint64_t)base + data_va);
        pte_ro   = user_lookup_pte(cr3, (uint64_t)base + ro_va);

        if      (!((pte_text & SELFTEST_PTE_PRESENT) && (pte_text & SELFTEST_PTE_USER))) { ok = 0; why = "text-absent"; }
        else if (!((pte_data & SELFTEST_PTE_PRESENT) && (pte_data & SELFTEST_PTE_USER))) { ok = 0; why = "data-absent"; }
        else if (!((pte_ro   & SELFTEST_PTE_PRESENT) && (pte_ro   & SELFTEST_PTE_USER))) { ok = 0; why = "rodata-absent"; }
        /* W^X execute bits: code executable (NX clear), data/rodata non-exec. */
        else if (pte_text & SELFTEST_PTE_NX)    { ok = 0; why = "text-noexec"; }
        else if (!(pte_data & SELFTEST_PTE_NX)) { ok = 0; why = "data-executable"; }
        else if (!(pte_ro   & SELFTEST_PTE_NX)) { ok = 0; why = "rodata-executable"; }
        /* write bits: data writable, rodata read-only. */
        else if (!(pte_data & SELFTEST_PTE_WRITE)) { ok = 0; why = "data-readonly"; }
        else if (pte_ro & SELFTEST_PTE_WRITE)      { ok = 0; why = "rodata-writable"; }
    }

    /* Content spot-check: markers copied to the right (randomized) vaddrs. The
     * data segment holds selfptr (4 bytes) then the 0xD2 marker. */
    if (ok) {
        uint8_t b;
        if (selftest_read_byte(cr3, (uint64_t)base + ro_va, &b) != 0 || b != 0x5A)      { ok = 0; why = "rodata-marker"; }
        else if (selftest_read_byte(cr3, (uint64_t)base + data_va + 4, &b) != 0 || b != 0xD2) { ok = 0; why = "data-marker"; }
    }

    /* Relocation check: selfptr (first word of .data) was linked as &rodata_marker
     * (link vaddr == ro_va) and must have been fixed up to base + ro_va by the
     * loader's R_386_RELATIVE handling. If relocation were skipped it would still
     * hold the small link-time value (< base) and this fails. */
    if (ok) {
        uint32_t selfptr = 0;
        uint8_t b;
        if (selftest_read_u32(cr3, (uint64_t)base + data_va, &selfptr) != 0) { ok = 0; why = "selfptr-read"; }
        else if (selfptr != base + ro_va)                                   { ok = 0; why = "selfptr-not-relocated"; }
        else if (selftest_read_byte(cr3, selfptr, &b) != 0 || b != 0x5A)     { ok = 0; why = "selfptr-target"; }
    }

    if (ok) {
        print("ELF_SELFTEST: PASS\n");
    } else {
        print("ELF_SELFTEST: FAIL "); print(why); print("\n");
    }

    /* Free the throwaway task slot so the scheduler never runs it. */
    tasks[pid].state = 0;
    set_current_task(saved);
}
#endif /* ELF_SELFTEST */

#ifdef ELF64_SELFTEST
/* In-kernel self-test of the loader's x86-64 RELA relocation path (gated).
 *
 * The 64-bit sibling of elf_loader_selftest: loads userspace/elftest64.elf --
 * the same elftest.c, linked as a 64-bit static-PIE -- through the real
 * do_spawn -> try_elf_load path and proves elf_apply_relocations_x86_64 applied
 * its R_X86_64_RELATIVE relocation, plus that W^X still holds for an ELF64
 * image.
 *
 * This runs BEFORE the ring-3 ABI is 64-bit (Stage 3c), and that is fine: the
 * loaded image is never executed. Relocation happens at load time, and the test
 * verifies it by reading the task's memory through its page tables, then frees
 * the slot so the scheduler never touches it. Loading and running are separable,
 * which is what lets the relocator land and be gated one stage early instead of
 * arriving as untested code underneath the ABI flip.
 *
 * The image's single relocation is selfptr (first quadword of .data) = &rodata
 * marker, link vaddr 0x1000, addend 0x1000. Applied, it must read base + ro_va;
 * skipped, it would still hold the small link-time value. */
void elf64_loader_selftest(void) {
    extern uint8_t embedded_elftest64_start[];
    extern uint8_t embedded_elftest64_end[];
    uint32_t sz = (uint32_t)(embedded_elftest64_end - embedded_elftest64_start);

    print("ELF64_SELFTEST: begin\n");
    if (sz == 0 || sz > MAX_PROGRAM_SIZE) { print("ELF64_SELFTEST: FAIL embed-size\n"); return; }

    for (uint32_t i = 0; i < sz; i++) loader_staging[i] = embedded_elftest64_start[i];
    armed_hdr.entry = 0;
    armed_hdr.size  = sz;
    armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
    armed_hdr.name[3] = '6'; armed_hdr.name[4] = '4'; armed_hdr.name[5] = 0;
    program_armed = 1;

    int saved = get_current_task();
    int pid = do_spawn();                 /* the real try_elf_load + RELA + W^X */
    if (pid <= 0) { print("ELF64_SELFTEST: FAIL spawn\n"); set_current_task(saved); return; }

    uint64_t cr3  = tasks[pid].cr3;
    uint64_t base = tasks[pid].image_base;

    /* Locate the three PT_LOAD segments by p_flags in the staged (base-0)
     * Elf64 image, so the checks hold at the randomized base. Elf64_Phdr is 56
     * bytes: p_type(0,4) p_flags(4,4) p_offset(8,8) p_vaddr(16,8). */
    const uint8_t *est = loader_staging;
    uint64_t e_phoff = elf_rd64(est + 32);
    uint16_t e_phnum = (uint16_t)est[56] | ((uint16_t)est[57] << 8);
    uint64_t text_va = ~0ULL, ro_va = ~0ULL, data_va = ~0ULL;
    for (uint16_t i = 0; i < e_phnum && i < 16; i++) {
        const uint8_t *p = est + e_phoff + (uint64_t)i * 56;
        if (elf_rd32(p) != 1) continue;            /* PT_LOAD */
        uint32_t fl = elf_rd32(p + 4);             /* p_flags */
        uint64_t va = elf_rd64(p + 16);            /* p_vaddr */
        if      (fl & 1u) text_va = va;            /* PF_X */
        else if (fl & 2u) data_va = va;            /* PF_W */
        else              ro_va   = va;            /* R only */
    }

    int ok = 1;
    const char *why = "";
    if (text_va == ~0ULL || ro_va == ~0ULL || data_va == ~0ULL) { ok = 0; why = "phdr-missing"; }

    if (ok) {
        uint64_t pte_text = user_lookup_pte(cr3, base + text_va);
        uint64_t pte_data = user_lookup_pte(cr3, base + data_va);
        uint64_t pte_ro   = user_lookup_pte(cr3, base + ro_va);

        if      (!((pte_text & SELFTEST_PTE_PRESENT) && (pte_text & SELFTEST_PTE_USER))) { ok = 0; why = "text-absent"; }
        else if (!((pte_data & SELFTEST_PTE_PRESENT) && (pte_data & SELFTEST_PTE_USER))) { ok = 0; why = "data-absent"; }
        else if (!((pte_ro   & SELFTEST_PTE_PRESENT) && (pte_ro   & SELFTEST_PTE_USER))) { ok = 0; why = "rodata-absent"; }
        else if (pte_text & SELFTEST_PTE_NX)       { ok = 0; why = "text-noexec"; }
        else if (!(pte_data & SELFTEST_PTE_NX))    { ok = 0; why = "data-executable"; }
        else if (!(pte_ro   & SELFTEST_PTE_NX))    { ok = 0; why = "rodata-executable"; }
        else if (!(pte_data & SELFTEST_PTE_WRITE)) { ok = 0; why = "data-readonly"; }
        else if (pte_ro & SELFTEST_PTE_WRITE)      { ok = 0; why = "rodata-writable"; }
    }

    /* Markers. selfptr is 8 bytes here (4 on i386), so the data marker sits at
     * data_va + 8. */
    if (ok) {
        uint8_t b;
        if (selftest_read_byte(cr3, base + ro_va, &b) != 0 || b != 0x5A)          { ok = 0; why = "rodata-marker"; }
        else if (selftest_read_byte(cr3, base + data_va + 8, &b) != 0 || b != 0xD2) { ok = 0; why = "data-marker"; }
    }

    /* The relocation itself: the whole point of this test. */
    if (ok) {
        uint64_t selfptr = 0;
        uint8_t b;
        if (selftest_read_u64(cr3, base + data_va, &selfptr) != 0)  { ok = 0; why = "selfptr-read"; }
        else if (selfptr != base + ro_va)                           { ok = 0; why = "selfptr-not-relocated"; }
        else if (selftest_read_byte(cr3, selfptr, &b) != 0 || b != 0x5A) { ok = 0; why = "selfptr-target"; }
    }

    if (ok) {
        print("ELF64_SELFTEST: PASS\n");
    } else {
        print("ELF64_SELFTEST: FAIL "); print(why); print("\n");
    }

    tasks[pid].state = 0;
    set_current_task(saved);
}
#endif /* ELF64_SELFTEST */

#ifdef ASLR_SELFTEST
/* Image-base ASLR self-test (gated; never in the ship build).
 *
 * Spawns several PIE images and inspects the load base the loader chose for each.
 * Two properties, and the first one exists because it has actually been broken:
 * image-base ASLR was once silently disabled entirely — pinned to USER_AREA_BASE
 * on every spawn — while the docs advertised ~9 bits, because the bound was
 * compared against the wrong linker symbol and the guard failed safe. Nothing
 * caught it, because nothing looked.
 *
 *   1. The base actually varies. A handful of spawns must not all land on the
 *      same address.
 *   2. The base stays inside the premap-containment bound. create_user_pagedir
 *      builds the image premap from a SINGLE page table, so [base_pti,
 *      base_pti + USER_ASPACE_PREMAP_PAGES) must fit in one 512-entry table.
 *      Exceeding it would write past that table — this is the invariant that
 *      bounds ASLR, and the reason the entropy figure is what it is.
 *
 * Deliberately NOT asserted: a statistical entropy estimate. With a handful of
 * samples over 480 slots, any threshold tight enough to catch a regression is
 * loose enough to flake. The entropy claim is structural — log2 of the bound
 * checked in (2) — not something a few draws can evidence. */
#define ASLR_PROBE_SPAWNS 8

void aslr_selftest(void) {
    /* The 64-bit fixture: only ELFCLASS64 images take the high ASLR window this
     * test asserts on. */
    extern uint8_t embedded_elftest64_start[];
    extern uint8_t embedded_elftest64_end[];
    uint8_t *embedded_elftest_start = embedded_elftest64_start;
    uint8_t *embedded_elftest_end   = embedded_elftest64_end;
    uint32_t sz = (uint32_t)(embedded_elftest_end - embedded_elftest_start);

    print("ASLR_SELFTEST: begin\n");
    if (sz == 0 || sz > MAX_PROGRAM_SIZE) { print("ASLR_SELFTEST: FAIL embed-size\n"); return; }

    uint64_t bases[ASLR_PROBE_SPAWNS];
    int got = 0;
    int saved = get_current_task();

    for (int i = 0; i < ASLR_PROBE_SPAWNS; i++) {
        for (uint32_t j = 0; j < sz; j++) loader_staging[j] = embedded_elftest_start[j];
        armed_hdr.entry = 0;
        armed_hdr.size  = sz;
        armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
        armed_hdr.name[3] = 't'; armed_hdr.name[4] = 0;
        program_armed = 1;

        int pid = do_spawn();
        if (pid <= 0) { print("ASLR_SELFTEST: FAIL spawn\n"); set_current_task(saved); return; }
        bases[got++] = tasks[pid].image_base;
        tasks[pid].state = 0;          /* throwaway slot; never scheduled */
        set_current_task(saved);
    }

    /* (2) Every base inside the high ASLR window. A regression to the old low
     * window (anchored at USER_AREA_BASE, 4 MiB) fails this outright. The
     * "premap must not cross its page table" check that used to sit here is
     * gone: the multi-level walk allocates whatever levels a base needs, so a
     * window-crossing premap is now correct, not a bug. */
    uint64_t lo = USER_IMAGE_ASLR_BASE;
    uint64_t hi = USER_IMAGE_ASLR_BASE +
                  (uint64_t)ASLR_MAX_LOAD_RANDOM_PAGES * PAGE_SIZE;
    for (int i = 0; i < got; i++) {
        if (bases[i] < lo || bases[i] >= hi) {
            print("ASLR_SELFTEST: FAIL base out of window "); print_hex(bases[i]); print("\n");
            set_current_task(saved); return;
        }
    }

    /* (1) The base varies. */
    int distinct = 0;
    for (int i = 0; i < got; i++) {
        int seen = 0;
        for (int j = 0; j < i; j++) if (bases[j] == bases[i]) { seen = 1; break; }
        if (!seen) distinct++;
    }

    uint64_t minb = bases[0], maxb = bases[0];
    for (int i = 1; i < got; i++) {
        if (bases[i] < minb) minb = bases[i];
        if (bases[i] > maxb) maxb = bases[i];
    }
    print("ASLR_SELFTEST: "); print_decimal(distinct); print("/");
    print_decimal(got); print(" distinct, min="); print_hex(minb);
    print(" max="); print_hex(maxb); print("\n");

    if (distinct < got) {
        /* 30 bits over a 4 TiB window: a collision among 8 draws is ~2^-25, so
         * anything short of all-distinct means the entropy is not what the
         * window claims. The old test tolerated 5/8 because 8.91 bits made
         * collisions plausible; they are not any more. */
        print("ASLR_SELFTEST: FAIL bases collide (entropy below the window)\n");
        set_current_task(saved); return;
    }

    /* The spread across 8 draws must dwarf the entire OLD window. Eight uniform
     * samples in a 4 TiB span cover a few TiB; a regression that quietly shrank
     * the window back toward the old ~2 MiB would leave them bunched. Requiring
     * > 1 GiB of spread fails such a regression loudly, while the chance of 8
     * genuine 30-bit draws all landing within 1 GiB is ~2^-84 — it will not
     * flake. */
    if (maxb - minb < 0x40000000ULL) {
        print("ASLR_SELFTEST: FAIL spread too small (window collapsed)\n");
        set_current_task(saved); return;
    }

    print("ASLR_SELFTEST: PASS\n");
    set_current_task(saved);
}
#endif /* ASLR_SELFTEST */

#ifdef PREEMPT_SELFTEST
/* ---- Preemptive-scheduling self-test (PREEMPT_SELFTEST builds only) --------
 * Spawn two independent copies of the embedded preempttest payload. Each one
 * busy-spins in ring 3 and periodically calls SYS_PREEMPT_TRACE *without ever
 * yielding*. The only way control can pass from one to the other is the timer
 * preempting it, so repeated alternation between the two task ids in the trace
 * proves preemption is live. h_preempt_trace prints the PASS marker once it has
 * seen enough back-and-forth. Without preemption only the first task would ever
 * run and the marker would never appear (smoke then fails on timeout). */

static volatile int pt_first_id     = -1;
static volatile int pt_second_id    = -1;
static volatile int pt_last_id      = -1;
static volatile int pt_transitions  = 0;
static volatile int pt_done         = 0;

void h_preempt_trace(struct interrupt_frame64 *r) {
    int id = get_current_task();
    if (pt_first_id < 0) pt_first_id = id;
    else if (pt_second_id < 0 && id != pt_first_id) pt_second_id = id;

    if (pt_last_id >= 0 && id != pt_last_id) pt_transitions++;
    pt_last_id = id;

    if (!pt_done && pt_transitions >= 6 && pt_first_id >= 0 && pt_second_id >= 0) {
        pt_done = 1;
        print("PREEMPT_SELFTEST: PASS transitions=");
        print_decimal(pt_transitions);
        print(" tasks=");
        print_decimal(pt_first_id);
        print(",");
        print_decimal(pt_second_id);
        print("\n");
    }
    r->rax = 0;
}

/* Arm the embedded flat payload and spawn one instance; returns its pid. */
static int preempt_spawn_one(uint32_t entry, uint32_t size, const uint8_t *payload) {
    for (uint32_t i = 0; i < size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = entry;
    armed_hdr.size  = size;
    armed_hdr.name[0] = 'p'; armed_hdr.name[1] = 't'; armed_hdr.name[2] = 0;
    program_armed = 1;
    return do_spawn();
}

void preempt_selftest(void) {
    extern uint8_t embedded_preempttest_bin_start[];
    extern uint8_t embedded_preempttest_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_preempttest_bin_end - embedded_preempttest_bin_start);

    print("PREEMPT_SELFTEST: begin\n");
    if (full_sz < 44) { print("PREEMPT_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }

    const uint8_t *bin = embedded_preempttest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("PREEMPT_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("PREEMPT_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    const uint8_t *payload = bin + 44;

    int a = preempt_spawn_one(h_entry, h_size, payload);
    int b = preempt_spawn_one(h_entry, h_size, payload);
    if (a <= 0 || b <= 0) { print("PREEMPT_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch task A into ring 3 via its fabricated trap frame; the timer then
     * time-slices A and B. Does not return. */
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* PREEMPT_SELFTEST */

#ifdef SMP_SELFTEST
/* ---- SMP self-test (SMP_SELFTEST builds only) -----------------------------
 * The application processors are already online (smp_bringup). Spawn a pool of
 * forever-looping worker tasks, open the cross-CPU scheduling gate, and confirm
 * the APs actually pull and run those workers: they must be observed running on
 * at least two distinct CPUs while the APs' LAPIC timer keeps ticking. The
 * workers reuse the preemption-test payload, so each also does an int-0x80
 * syscall from ring 3 on an AP -- exercising per-CPU TSS RSP0 delivery. Prints
 * "SMP_SELFTEST: PASS ..." for `make smoke-smp`. The BSP stays in ring 0 here
 * (its cpu-0 ring-0 context is never pulled into a task), so it monitors freely
 * while the APs do the work. */
static int smp_spawn_worker(uint32_t entry, uint32_t size, const uint8_t *payload) {
    for (uint32_t i = 0; i < size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = entry;
    armed_hdr.size  = size;
    armed_hdr.name[0] = 'w'; armed_hdr.name[1] = 'k'; armed_hdr.name[2] = 0;
    program_armed = 1;
    return do_spawn();
}

void smp_selftest(void) {
    extern uint8_t embedded_preempttest_bin_start[];
    extern uint8_t embedded_preempttest_bin_end[];
    extern volatile int smp_sched_enabled;
    extern volatile unsigned smp_cpus_ran_tasks;
    extern volatile unsigned long ap_timer_ticks;

    int online = smp_get_online_count();
    print("SMP_SELFTEST: begin online="); print_decimal(online); print("\n");
    if (online < 2) { print("SMP_SELFTEST: FAIL no-aps\n"); for (;;) asm volatile("hlt"); }

    uint32_t full_sz = (uint32_t)(embedded_preempttest_bin_end - embedded_preempttest_bin_start);
    if (full_sz < 44) { print("SMP_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }
    const uint8_t *bin = embedded_preempttest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("SMP_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("SMP_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;
    const uint8_t *payload = bin + 44;

    /* Spawn one worker per online CPU so an AP always has work to pull. Preserve
     * the kernel address space across do_spawn (which installs the new task's
     * CR3) so the BSP keeps monitoring on the kernel page tables. */
    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));
    int spawned = 0;
    for (int i = 0; i < online; i++) {
        if (smp_spawn_worker(h_entry, h_size, payload) > 0) spawned++;
    }
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    if (spawned < 2) { print("SMP_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    print("SMP_SELFTEST: spawned="); print_decimal(spawned); print(" workers\n");

    /* Arm preemption and open the gate: the APs now pull workers on each tick. */
    sched_enable_preemption();
    smp_sched_enabled = 1;

    unsigned long t0 = ap_timer_ticks;
    for (int spins = 0; spins < 4000; spins++) {
        for (volatile int d = 0; d < 200000; d++) __asm__ volatile ("pause");
        unsigned mask = smp_cpus_ran_tasks;
        int distinct = 0;
        for (int c = 0; c < 32; c++) if (mask & (1u << c)) distinct++;
        if (distinct >= 2 && ap_timer_ticks > t0 + 10) {
            /* Multi-core scheduling proven. Now exercise the TLB-shootdown
             * round-trip: broadcast to the (busy, interrupts-enabled) APs and
             * confirm every one flushed and acknowledged. */
            extern volatile int smp_shootdown_pending;
            extern void smp_maybe_shootdown(uint64_t);
            smp_maybe_shootdown(0x1000);
            int shootdown_ok = (smp_shootdown_pending == 0);
            if (!shootdown_ok) {
                print("SMP_SELFTEST: FAIL shootdown pending=");
                print_decimal(smp_shootdown_pending); print("\n");
                for (;;) asm volatile("hlt");
            }
            print("SMP_SELFTEST: PASS online="); print_decimal(online);
            print(" cpus_ran=0x"); print_hex(mask);
            print(" distinct="); print_decimal(distinct);
            print(" ap_ticks="); print_decimal((uint32_t)ap_timer_ticks);
            print(" shootdown=ok");
            print("\n");
            for (;;) asm volatile("hlt");
        }
    }
    print("SMP_SELFTEST: FAIL timeout cpus_ran=0x"); print_hex(smp_cpus_ran_tasks);
    print(" ap_ticks="); print_decimal((uint32_t)ap_timer_ticks); print("\n");
    for (;;) asm volatile("hlt");
}
#endif /* SMP_SELFTEST */

#ifdef PROC_SELFTEST
/* Spawn a registered (spawn_table) program from the kernel, keeping the kernel
 * address space across do_spawn (which installs the new task's CR3 and makes it
 * current). Returns the new pid. */
static int proc_spawn_named(const char *name) {
    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));
    set_current_task(0);                 /* so do_spawn's spawner-cap grant is skipped */
    int pid = (arm_named_binary(name) == 0) ? do_spawn() : -1;
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    return pid;
}

/* Spawn a HORU-headered embedded image with an explicit task name. */
static int proc_spawn_embed(const uint8_t *start, const uint8_t *end, const char *nm) {
    uint32_t full = (uint32_t)(end - start);
    if (full < 44) return -1;
    uint32_t magic   = *(const uint32_t *)start;
    uint32_t h_entry = *(const uint32_t *)(start + 4);
    uint32_t h_size  = *(const uint32_t *)(start + 8);
    if (magic != 0x55524F48 || h_size == 0 || h_size > MAX_PROGRAM_SIZE) return -1;
    if (full < 44 + h_size) h_size = full - 44;

    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));
    set_current_task(0);
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = start[44 + i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    int k = 0;
    for (; nm[k] && k < 31; k++) armed_hdr.name[k] = nm[k];
    armed_hdr.name[k] = 0;
    program_armed = 1;
    int pid = do_spawn();
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    return pid;
}

/* ---- Process-control self-test (PROC_SELFTEST builds only) -----------------
 * The kernel spawns three tasks: a "hello" child that finishes with sys_exit, a
 * "looper" child (the preemption-test payload) that loops forever, and the
 * proctest driver. The driver is granted CAP_AUDIT (to read task state) and a
 * CAP_TCB capability to the looper (to terminate it), then dropped to ring 3. It
 * confirms the hello child exits and that it can SYS_KILL the looper via that
 * capability, printing PROC_SELFTEST: PASS. (The driver does not spawn anything
 * itself — ring-3 spawn is deferred to the init/exec stage.) Entry into
 * ring 3 does not return. */
void proc_selftest(void) {
    extern uint8_t embedded_proctest_bin_start[];
    extern uint8_t embedded_proctest_bin_end[];
    extern uint8_t embedded_preempttest_bin_start[];
    extern uint8_t embedded_preempttest_bin_end[];

    print("PROC_SELFTEST: begin\n");

    int hello_id = proc_spawn_named("hello");
    int loop_id  = proc_spawn_embed(embedded_preempttest_bin_start, embedded_preempttest_bin_end, "looper");
    int a        = proc_spawn_embed(embedded_proctest_bin_start,   embedded_proctest_bin_end,   "proc");
    if (hello_id <= 0 || loop_id <= 0 || a <= 0) { print("PROC_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Grant the driver a real CAP_AUDIT (root slot 7) so SYS_GET_TASK_INFO can
     * read the children's state — but NOT admin, so the kill must go through a
     * genuine CAP_TCB capability — plus a CAP_TCB to the looper child (root slot
     * 0 is the primordial TCB cap), scoped to loop_id. Both get fresh serials so
     * cap_lookup accepts them. */
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    cap_install_from_root(a, 7, 7, 0);            /* CAP_AUDIT: read task info   */
    cap_install_from_root(a, 16, 0, (uint32_t)loop_id);  /* CAP_TCB -> captest   */
    tasks[a].uid = 0;

    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* PROC_SELFTEST */

#ifdef SIGNAL_SELFTEST
/* ---- Signal-handling self-test (SIGNAL_SELFTEST builds only) ---------------
 * Spawn the sigtest payload: it registers a ring-3 fault handler and then does
 * a null-pointer write. Without signal handling that fault kills the task;
 * with it, the kernel redirects the task into its handler, which prints
 * "SIGNAL_SELFTEST: PASS". Entry into ring 3 does not return. */
void signal_selftest(void) {
    extern uint8_t embedded_sigtest_bin_start[];
    extern uint8_t embedded_sigtest_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_sigtest_bin_end - embedded_sigtest_bin_start);

    print("SIGNAL_SELFTEST: launch\n");
    if (full_sz < 44) { print("SIGNAL_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }

    const uint8_t *bin = embedded_sigtest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("SIGNAL_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("SIGNAL_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;

    const uint8_t *payload = bin + 44;
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    armed_hdr.name[0] = 's'; armed_hdr.name[1] = 'i'; armed_hdr.name[2] = 'g'; armed_hdr.name[3] = 0;
    program_armed = 1;

    int a = do_spawn();
    if (a <= 0) { print("SIGNAL_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch into ring 3 via the fabricated full trap frame. */
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* SIGNAL_SELFTEST */

#ifdef TSD_SELFTEST
/* ---- RDTSC / CR4.TSD self-test (TSD_SELFTEST builds only) ------------------
 * Spawn the tsdtest payload: it registers a ring-3 fault handler and then
 * executes RDTSC. With CR4.TSD engaged (cpu_enable_protections) the ring-3
 * RDTSC #GPs, and the kernel redirects the task into its handler, which prints
 * "TSD_SELFTEST: PASS"; a timestamp instead means TSD is not in effect and the
 * payload prints FAIL. Entry into ring 3 does not return. */
void tsd_selftest(void) {
    extern uint8_t embedded_tsdtest_bin_start[];
    extern uint8_t embedded_tsdtest_bin_end[];
    uint32_t full_sz = (uint32_t)(embedded_tsdtest_bin_end - embedded_tsdtest_bin_start);

    print("TSD_SELFTEST: launch\n");
    if (full_sz < 44) { print("TSD_SELFTEST: FAIL embed-size\n"); for (;;) asm volatile("hlt"); }

    const uint8_t *bin = embedded_tsdtest_bin_start;
    uint32_t magic   = *(const uint32_t *)bin;
    uint32_t h_entry = *(const uint32_t *)(bin + 4);
    uint32_t h_size  = *(const uint32_t *)(bin + 8);
    if (magic != 0x55524F48)                     { print("TSD_SELFTEST: FAIL magic\n"); for (;;) asm volatile("hlt"); }
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) { print("TSD_SELFTEST: FAIL size\n");  for (;;) asm volatile("hlt"); }
    if (full_sz < 44 + h_size) h_size = full_sz - 44;

    const uint8_t *payload = bin + 44;
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    armed_hdr.name[0] = 't'; armed_hdr.name[1] = 's'; armed_hdr.name[2] = 'd'; armed_hdr.name[3] = 0;
    program_armed = 1;

    int a = do_spawn();
    if (a <= 0) { print("TSD_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch into ring 3 via the fabricated full trap frame. */
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* TSD_SELFTEST */

#ifdef E820_SELFTEST
/* ---- E820 physical-pool self-test (E820_SELFTEST builds only) --------------
 * Runs after paging_init has built the free list from the E820-sized pool. The
 * harness boots with -m 512M, so a parsed memory map must have grown the pool
 * well past the pre-E820 64 MiB default (USER_PHYS_DEFAULT_PAGES frames). Freshly
 * initialised, the free count is the whole pool minus the handful of frames
 * paging_init spent on page tables and the zero page — still far above the
 * default. Pure kernel assertion; no ring-3 payload. */
void e820_selftest(void) {
    uint32_t free_pages = get_free_user_pages();
    print("E820_SELFTEST: free pool frames = ");
    print_decimal((uint64_t)free_pages);
    print("\n");
    if (free_pages > USER_PHYS_DEFAULT_PAGES)
        print("E820_SELFTEST: PASS pool sized from the multiboot2 memory map\n");
    else
        print("E820_SELFTEST: FAIL pool not grown past the default\n");
}
#endif /* E820_SELFTEST */

#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST) || defined(NOTIFY_SELFTEST) || defined(COW_SELFTEST) || defined(CAPTEST_SELFTEST)
/* ---- Selftest spawn helper (FS/NEWLIB/NOTIFY/COW/CAPTEST only) ----
 * Stage an embedded, headered PIE binary and spawn it; returns the new pid. */

static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm) {
    uint32_t full = (uint32_t)(end - start);
    if (full < 44) return -1;
    uint32_t magic   = *(const uint32_t *)start;
    uint32_t h_entry = *(const uint32_t *)(start + 4);
    uint32_t h_size  = *(const uint32_t *)(start + 8);
    if (magic != 0x55524F48) return -1;
    if (h_size == 0 || h_size > MAX_PROGRAM_SIZE) return -1;
    if (full < 44 + h_size) h_size = full - 44;

    const uint8_t *payload = start + 44;
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;           /* recomputed by try_elf_load for the PIE ELF */
    armed_hdr.size  = h_size;
    int k = 0;
    while (k < 31 && nm[k]) { armed_hdr.name[k] = nm[k]; k++; }
    armed_hdr.name[k] = 0;
    program_armed = 1;
    return do_spawn();
}
#endif /* FS_SELFTEST || NEWLIB_SELFTEST || NOTIFY_SELFTEST || COW_SELFTEST || COREUTILS_SELFTEST || CAPTEST_SELFTEST */

#ifdef FS_SELFTEST
void fs_selftest(void) {
    extern uint8_t embedded_fsserver_bin_start[], embedded_fsserver_bin_end[];
    extern uint8_t embedded_fsclient_bin_start[], embedded_fsclient_bin_end[];

    print("FS_SELFTEST: begin\n");

    int srv = fs_spawn_embedded(embedded_fsserver_bin_start, embedded_fsserver_bin_end, "fsserver");
    if (srv <= 0) { print("FS_SELFTEST: FAIL spawn-server\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    /* Provision the server: an endpoint cap for the IPC gate (slot 3) and for
     * registration (slot 4, bound to FS_EP_REQ), a CAP_USER admin cap (slot 6)
     * for SYS_REGISTER_FS_SERVER, and an all-rights cap (slot 7) to satisfy the
     * object-store gate. */
    cap_install_from_root(srv, 3, 2, 0);          /* root_cnode[2] = CAP_ENDPOINT   */
    cap_install_from_root(srv, 4, 2, FS_EP_REQ);
    cap_install_from_root(srv, 6, 6, 0);          /* root_cnode[6] = CAP_USER (ALL) */
    cap_install_from_root(srv, 7, 8, 0);          /* root_cnode[8] = ALL rights     */

#ifdef CONC_SELFTEST
    /* Multi-client concurrency test: spawn a coordinator (spawn arg 0) plus three
     * worker clients (args 1..3), each uid 0 with a delegated endpoint cap, all
     * hammering the single server at once. Each worker verifies it receives ITS
     * OWN replies (SYS_IPC_REPLY_TO routes by the request's kernel-recorded
     * sender); the coordinator waits for every worker's done-marker and prints
     * CONC_SELFTEST: PASS. */
    for (int i = 0; i <= 3; i++) {
        int c = fs_spawn_embedded(embedded_fsclient_bin_start, embedded_fsclient_bin_end, "fsclient");
        if (c <= 0) { print("CONC_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
        tasks[c].uid       = 0;
        tasks[c].spawn_arg = (uint32_t)i;       /* 0 = coordinator, 1..3 = workers */
        cap_install_from_root(c, 3, 2, 0);      /* endpoint cap for the IPC gate */
    }
#else
    int cli = fs_spawn_embedded(embedded_fsclient_bin_start, embedded_fsclient_bin_end, "fsclient");
    if (cli <= 0) { print("FS_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
    tasks[cli].uid = 0;
    /* Delegate an endpoint cap into the client's slot 3 so its IPC calls pass
     * the capability gate. (This is the spawner delegating authority — the
     * capability model in practice. sys_connect_fs_server can't target slot 3,
     * which slots 0-3 reserve; reconciling that with the slot-3 IPC gate is a
     * follow-up.) */
    cap_install_from_root(cli, 3, 2, 0);
#endif

    /* Launch the server; when it blocks in IPC the full-context path runs the
     * client(s). Does not return. */
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* FS_SELFTEST */

#ifdef WAL_CRASHTEST
/* Journal crash-recovery test — two boots against one persistent disk.
 *
 * Boot 1 (fresh disk): create an inode, then write its first block with the
 * commit "crash" armed — journal_commit makes the transaction durable (writes the
 * commit header) and then halts BEFORE applying it to the home locations. So on
 * disk the update is committed-in-journal but not-yet-applied.
 *
 * Boot 2 (same disk): storage_unlock's journal_recover replays that committed
 * transaction (idempotent redo); we read the block back and confirm the write
 * survived the crash. Proves redo recovery end-to-end. `make smoke-fs-wal` asserts
 * "WAL_CRASHTEST: PASS" on boot 2. */
void wal_crashtest(void) {
    extern int g_wal_crash_armed;
    extern int storage_fresh_format;
    static const char MARK[16] = "WAL-REDO-OK-2468";

    print("WAL_CRASHTEST: begin\n");
    if (storage_unlock("waltestpw", 9) != 0) {
        print("WAL_CRASHTEST: FAIL unlock\n"); for (;;) asm volatile ("hlt");
    }
    mounted_fs_t *mfs = storage_get_mounted_fs();

    if (storage_fresh_format) {
        int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
        if (ino < 1) { print("WAL_CRASHTEST: FAIL alloc\n"); for (;;) asm volatile ("hlt"); }
        on_disk_inode_t nd;
        for (size_t i = 0; i < sizeof(nd); i++) ((uint8_t *)&nd)[i] = 0;
        nd.type = 1; nd.mode = 0100600; nd.links = 1;
        storage_write_inode(mfs->bd, &mfs->sb, (uint64_t)ino, &nd);

        uint8_t buf[512];
        for (int i = 0; i < 512; i++) buf[i] = 0;
        for (int i = 0; i < 16; i++)  buf[i] = (uint8_t)MARK[i];

        print("WAL_CRASHTEST: boot1 armed; committing then crashing\n");
        g_wal_crash_armed = 1;
        storage_write_file_block(mfs, (uint64_t)ino, 0, buf);   /* commits, then halts */
        print("WAL_CRASHTEST: FAIL no-crash\n");                /* unreachable */
    } else {
        uint8_t buf[512];
        if (storage_read_file_block(mfs, 1, 0, buf) != 0) {
            print("WAL_CRASHTEST: FAIL read\n");
        } else {
            int ok = 1;
            for (int i = 0; i < 16; i++) if (buf[i] != (uint8_t)MARK[i]) ok = 0;
            print(ok ? "WAL_CRASHTEST: PASS\n" : "WAL_CRASHTEST: FAIL content\n");
        }
    }
    for (;;) asm volatile ("hlt");
}
#endif /* WAL_CRASHTEST */

/* ---- Large-file / double-indirect self-test (BIGFILE_SELFTEST builds only) --
 * Single boot against the ephemeral RAM store (storage_init already formatted +
 * mounted + unlocked it). Allocate one inode and write blocks spanning every
 * mapping region — direct (0, 11), single-indirect boundaries (12, 75), and the
 * point of this test, double-indirect (76 = first, then deep: 200, 1000, 3000) —
 * then read them back. Each block is stamped with its logical block number and a
 * number-derived body pattern, so a block that lands at the wrong physical
 * location reads as wrong content. Also confirms an unwritten hole reads as
 * absent (not another block's data) and that freeing the whole tree succeeds.
 * Prints BIGFILE_SELFTEST: PASS; `make smoke-fs-large` asserts on it. */
#ifdef BIGFILE_SELFTEST
void bigfile_selftest(void) {
    print("BIGFILE_SELFTEST: begin\n");

    mounted_fs_t *mfs = storage_get_mounted_fs();
    if (!mfs || !mfs->mounted || !mfs->unlocked) {
        print("BIGFILE_SELFTEST: FAIL not-ready\n"); for (;;) asm volatile ("hlt");
    }

    int64_t ino = storage_alloc_inode(mfs->bd, &mfs->sb);
    if (ino < 1) { print("BIGFILE_SELFTEST: FAIL alloc-inode\n"); for (;;) asm volatile ("hlt"); }
    {
        on_disk_inode_t nd;
        for (size_t i = 0; i < sizeof(nd); i++) ((uint8_t *)&nd)[i] = 0;
        nd.type = 1; nd.mode = 0100644; nd.links = 1;
        storage_write_inode(mfs->bd, &mfs->sb, (uint64_t)ino, &nd);
    }

    static const uint64_t blocks[] = { 0, 11, 12, 75, 76, 200, 1000, 3000 };
    const unsigned N = sizeof(blocks) / sizeof(blocks[0]);

    for (unsigned i = 0; i < N; i++) {
        uint64_t b = blocks[i];
        uint8_t buf[BLOCK_SIZE];
        for (int j = 0; j < BLOCK_SIZE; j++) buf[j] = (uint8_t)(b * 7u + (unsigned)j);
        for (int j = 0; j < 8; j++)          buf[j] = (uint8_t)(b >> (j * 8));   /* stamp */
        if (storage_write_file_block(mfs, (uint64_t)ino, b, buf) != 0) {
            print("BIGFILE_SELFTEST: FAIL write blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
    }

    /* Contiguous span deep in the double-indirect region (crosses several
     * single-indirect blocks). This makes the free below release ~130 data
     * blocks plus their pointer blocks in one journal transaction; every block
     * freed clears the same single block-bitmap sector, so the writes coalesce
     * and the transaction stays well under the 16-sector journal limit rather
     * than overflowing (a large-file free must never abort). */
    for (uint64_t b = 400; b < 530; b++) {
        uint8_t buf[BLOCK_SIZE];
        for (int j = 0; j < 8; j++) buf[j] = (uint8_t)(b >> (j * 8));   /* stamp */
        if (storage_write_file_block(mfs, (uint64_t)ino, b, buf) != 0) {
            print("BIGFILE_SELFTEST: FAIL span-write blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
    }

    for (unsigned i = 0; i < N; i++) {
        uint64_t b = blocks[i];
        uint8_t rb[BLOCK_SIZE];
        if (storage_read_file_block(mfs, (uint64_t)ino, b, rb) != 0) {
            print("BIGFILE_SELFTEST: FAIL read blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
        uint64_t stamp = 0;
        for (int j = 0; j < 8; j++) stamp |= ((uint64_t)rb[j]) << (j * 8);
        if (stamp != b) {
            print("BIGFILE_SELFTEST: FAIL stamp blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
        if (rb[100] != (uint8_t)(b * 7u + 100u)) {
            print("BIGFILE_SELFTEST: FAIL body blk=0x"); print_hex(b); print("\n");
            for (;;) asm volatile ("hlt");
        }
    }

    /* Spot-check the contiguous span read-back (stamp at a mid-span block). */
    {
        uint8_t rb[BLOCK_SIZE];
        if (storage_read_file_block(mfs, (uint64_t)ino, 465, rb) != 0) {
            print("BIGFILE_SELFTEST: FAIL span-read\n"); for (;;) asm volatile ("hlt");
        }
        uint64_t stamp = 0;
        for (int j = 0; j < 8; j++) stamp |= ((uint64_t)rb[j]) << (j * 8);
        if (stamp != 465) { print("BIGFILE_SELFTEST: FAIL span-stamp\n"); for (;;) asm volatile ("hlt"); }
    }

    /* A never-written hole in the double-indirect range must read as absent. */
    {
        uint8_t rb[BLOCK_SIZE];
        if (storage_read_file_block(mfs, (uint64_t)ino, 1500, rb) == 0) {
            print("BIGFILE_SELFTEST: FAIL hole-readable\n"); for (;;) asm volatile ("hlt");
        }
    }

    if (storage_free_inode_blocks(mfs, (uint64_t)ino) != 0) {
        print("BIGFILE_SELFTEST: FAIL free\n"); for (;;) asm volatile ("hlt");
    }

    print("BIGFILE_SELFTEST: PASS\n");
    for (;;) asm volatile ("hlt");
}
#endif /* BIGFILE_SELFTEST */

/* ---- Newlib smoke test (NEWLIB_SELFTEST builds only) ---------------------- */
#ifdef NEWLIB_SELFTEST
void newlib_selftest(void) {
    extern uint8_t embedded_hello_newlib_bin_start[], embedded_hello_newlib_bin_end[];
    extern uint8_t embedded_fsserver_bin_start[], embedded_fsserver_bin_end[];

    print("NEWLIB_SELFTEST: begin\n");

    /* Bring up the userspace fs_server so the client can exercise the real
     * newlib file paths (open/write/close/unlink). Provisioned exactly as in
     * fs_selftest: an endpoint cap for the IPC gate (slot 3) and registration
     * (slot 4, bound to FS_EP_REQ), a CAP_USER admin cap (slot 6), and an
     * all-rights cap (slot 7) for the object-store gate. */
    int srv = fs_spawn_embedded(embedded_fsserver_bin_start, embedded_fsserver_bin_end, "fsserver");
    if (srv <= 0) { print("NEWLIB_SELFTEST: FAIL spawn-server\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    cap_install_from_root(srv, 3, 2, 0);
    cap_install_from_root(srv, 4, 2, FS_EP_REQ);
    cap_install_from_root(srv, 6, 6, 0);
    cap_install_from_root(srv, 7, 8, 0);

    int pid = fs_spawn_embedded(embedded_hello_newlib_bin_start,
                                embedded_hello_newlib_bin_end,
                                "hello_newlib");
    print("NEWLIB_SELFTEST: pid="); print_hex(pid); print("\n");
    if (pid <= 0) {
        print("NEWLIB_SELFTEST: FAIL spawn\n");
        for (;;) asm volatile("hlt");
    }
    tasks[pid].uid = 0;
    /* Delegate an endpoint cap into the client's slot 3 so its fs_server IPC
     * passes the capability gate (the RAM store is auto-unlocked at boot and the
     * client is kernel-attested uid 0, so no login is needed). */
    cap_install_from_root(pid, 3, 2, 0);

    /* Enter the server; when it blocks in IPC recv the full-context path runs
     * the client, whose FS requests wake the server. Does not return. */
    print("NEWLIB_SELFTEST: launching\n");
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* NEWLIB_SELFTEST */

#ifdef NOTIFY_SELFTEST
/* Async-notification self-test. Spawn two copies of notifytest — a waiter (spawn
 * arg 0) and a sender (arg 1) — each with a slot-3 endpoint cap so it passes the
 * SYS_NOTIFY (WRITE) / SYS_WAIT_NOTIFY (READ) gate. The sender fires one known
 * badge; the waiter blocks in SYS_WAIT_NOTIFY and must get that badge back,
 * proving the badge round-trips to userspace (prints NOTIFY_SELFTEST: PASS). */
void notify_selftest(void) {
    extern uint8_t embedded_notifytest_bin_start[], embedded_notifytest_bin_end[];
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);

    print("NOTIFY_SELFTEST: launching\n");

    int waiter = fs_spawn_embedded(embedded_notifytest_bin_start,
                                   embedded_notifytest_bin_end, "notifywaiter");
    if (waiter <= 0) { print("NOTIFY_SELFTEST: FAIL spawn-waiter\n"); for (;;) asm volatile("hlt"); }
    tasks[waiter].uid       = 0;
    tasks[waiter].spawn_arg = 0;                    /* role 0 = waiter */
    cap_install_from_root(waiter, 3, 2, 0);         /* slot 3 = CAP_ENDPOINT (READ|WRITE) */

    int sender = fs_spawn_embedded(embedded_notifytest_bin_start,
                                   embedded_notifytest_bin_end, "notifysender");
    if (sender <= 0) { print("NOTIFY_SELFTEST: FAIL spawn-sender\n"); for (;;) asm volatile("hlt"); }
    tasks[sender].uid       = 0;
    tasks[sender].spawn_arg = 1;                    /* role 1 = sender */
    cap_install_from_root(sender, 3, 2, 0);

    /* Enter the waiter; it blocks in SYS_WAIT_NOTIFY and the full-context path
     * runs the sender, whose SYS_NOTIFY wakes it with the badge. Does not return. */
    sched_enable_preemption();
    sched_enter_user(waiter);
}
#endif /* NOTIFY_SELFTEST */

#ifdef COW_SELFTEST
/* Copy-on-write self-test. Spawn cowtest, which reads two fresh heap pages (each
 * aliasing the shared zero page read-only + COW), writes one, and asserts the
 * sibling is unaffected — i.e. the write broke COW into a private page rather
 * than mutating a shared frame. cowtest prints COW_SELFTEST: PASS/FAIL from ring 3
 * and sched_enter_user does not return, so the assertions are all userspace-side;
 * see the note in userspace/cowtest.c for what that does and does not prove. */
void cow_selftest(void) {
    extern uint8_t embedded_cowtest_bin_start[], embedded_cowtest_bin_end[];
    print("COW_SELFTEST: begin\n");

    int pid = fs_spawn_embedded(embedded_cowtest_bin_start,
                                embedded_cowtest_bin_end, "cowtest");
    if (pid <= 0) { print("COW_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[pid].uid = 0;

    sched_enable_preemption();
    sched_enter_user(pid);   /* cowtest prints the PASS/FAIL marker; does not return */
}
#endif /* COW_SELFTEST */



#ifdef CAPTEST_SELFTEST
/* ---- Capability/syscall conformance self-test (CAPTEST_SELFTEST only) -------
 *
 * Spawns userspace/captest, which drives the syscall surface and the capability
 * model from ring 3 and asserts on the results -- mostly on the REFUSALS, since
 * that is what a capability system has to get right (see userspace/captest.c).
 *
 * It is spawned with the default cspace an ordinary task gets (CAP_TCB for
 * itself, a frame, two endpoints) and deliberately NOT given CAP_BLOCK_DEV or
 * admin, so the negative probes are probing a real absence of authority rather
 * than a capability we quietly removed for the test.
 */
void captest_selftest(void) {
    extern uint8_t embedded_captest_bin_start[], embedded_captest_bin_end[];

    print("CAPTEST_SELFTEST: begin\n");

    int pid = fs_spawn_embedded(embedded_captest_bin_start,
                                embedded_captest_bin_end, "captest");
    if (pid <= 0) {
        print("CAPTEST: FAIL spawn\n");
        for (;;) asm volatile("hlt");
    }

    print("CAPTEST_SELFTEST: launching\n");
    sched_enable_preemption();
    sched_enter_user(pid);   /* captest prints the PASS/FAIL marker; does not return */
}
#endif /* CAPTEST_SELFTEST */
