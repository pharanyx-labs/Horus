/* selftest.c -- gated in-kernel self-tests (ELF loader / preemption / SMP /
 * process lifecycle / signals / filesystem / newlib). Every block is compiled
 * only under its -D*_SELFTEST switch, so the default build yields an (almost)
 * empty object. Split out of syscall.c. */
#include "syscall_internal.h"

/* Resume every task this harness spawned.
 *
 * do_spawn leaves children SUSPENDED so a supervisor can endow them before they
 * run (see the comment there). The in-kernel self-test harnesses do all of their
 * endowment synchronously, before enabling preemption, so a single sweep here is
 * the harness equivalent of the SYS_TASK_RESUME a ring-3 supervisor issues.
 * Only tasks with a fabricated context are touched. */
__attribute__((unused)) static void selftest_resume_all(void) {
    for (int t = 1; t < MAX_TASKS; t++)
        if (tasks[t].state && tasks[t].saved_ksp) tasks[t].runnable_ctx = 1;
}
#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST)
#include "fs_proto.h"   /* FS_EP_REQ for the FS self-test harnesses */
#endif

#ifdef SPAWN_OWNER_SELFTEST
/* Gated: prove the staged image can only be consumed by the task that armed it
 * ([G-11], roadmap 1.7).
 *
 * The staging is one process-wide buffer, and until 2026-08-18 nothing recorded
 * the connection between the task that armed an image and the task that spawned
 * it. SYS_SUDO makes that a privilege boundary rather than an oddity: it
 * re-authenticates the caller and then spawns whatever is armed AS UID 0, in a
 * separate syscall from the arm, so a correct password could elevate another
 * task's program.
 *
 * The test forges exactly the state a second task's arm leaves behind -- a
 * legitimately staged image whose recorded owner is somebody else -- and
 * requires do_spawn to refuse it. It then re-arms honestly and requires the
 * spawn to SUCCEED, because a check that refuses everything is not a check;
 * both directions or neither.
 *
 * Deterministic and single-threaded on purpose. The concurrent half of roadmap
 * 1.7 -- two CPUs interleaving through the arm -> consume window -- has no gate,
 * because it has no reachable workload: 214 window entries over 16 boots at
 * -smp 4, never two at once (TESTS.md, finding G-10). This one is about the
 * rule rather than the race, and a rule wants a test that cannot pass by luck.
 *
 * Control arm: SPAWN_OWNER_UNCHECKED=1 removes the refusal, and this prints
 * FAIL foreign-image-spawned. `make smoke-spawn-owner-control` requires it. */
void spawn_owner_selftest(void) {
    int saved = get_current_task();
    print("SPAWN_OWNER_SELFTEST: begin\n");

    set_current_task(0);
    spawn_stage_acquire();

    if (arm_named_binary("hello") != 0) {
        spawn_stage_release();
        print("SPAWN_OWNER_SELFTEST: FAIL arm\n");
        set_current_task(saved);
        return;
    }

    /* Somebody else armed it. MAX_TASKS-1 is never spawned into during a normal
     * boot, so this names a task that is not the consumer without disturbing a
     * live one. */
    staged_owner_task = MAX_TASKS - 1;
    int refused = do_spawn();
    if (refused > 0) {
        spawn_stage_release();
        print("SPAWN_OWNER_SELFTEST: FAIL foreign-image-spawned pid ");
        print_decimal(refused);
        print("\n");
        tasks[refused].state = 0;
        set_current_task(saved);
        return;
    }

    /* Now arm it honestly: same image, same caller, owner recorded by
     * loader_arm_commit rather than forged. This must go through. */
    if (arm_named_binary("hello") != 0) {
        spawn_stage_release();
        print("SPAWN_OWNER_SELFTEST: FAIL rearm\n");
        set_current_task(saved);
        return;
    }
    int pid = do_spawn();
    spawn_stage_release();
    if (pid <= 0) {
        print("SPAWN_OWNER_SELFTEST: FAIL own-image-refused rc ");
        print_decimal(pid);
        print("\n");
        set_current_task(saved);
        return;
    }

    tasks[pid].state = 0;            /* throwaway slot; never scheduled */
    set_current_task(saved);
    print("SPAWN_OWNER_SELFTEST: PASS refused a foreign staged image, spawned its own\n");
}
#endif /* SPAWN_OWNER_SELFTEST */

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

    /* WARM-UP, and it is not ceremony: since the per-task kernel stacks left
     * `.bss`, create_user_pagedir binds this slot's stack on FIRST use -- eight
     * stack pages plus the page table covering them. Those are deliberately
     * permanent (a stack is kept for the life of the boot, like the slot's
     * cspace), so free_user_aspace_for_test does not and must not return them,
     * and counting them as part of an ADDRESS SPACE made this test report a
     * 9-page leak that was not one.
     *
     * Building and freeing once before the accounting starts leaves the stack
     * bound, so every count below is address-space pages and nothing else. The
     * idempotence this relies on is itself asserted, by the rebuild loop: a
     * second bind would show up there as a leak. */
    create_user_pagedir((uint32_t)slot);
    if (tasks[slot].cr3) {
        free_user_aspace_for_test(tasks[slot].cr3);
        tasks[slot].cr3 = 0;
    }
    extern uint32_t kstack_slots_mapped;
    uint32_t kstacks_before = kstack_slots_mapped;

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
    /* No slot may have been bound a second time. The page counts above would
     * catch a stack allocated twice as a leak, but only by its SIZE -- this says
     * what actually must not happen, and says it even if a future stack costs a
     * different number of pages. */
    if (kstack_slots_mapped != kstacks_before) {
        print("ASPACE_SELFTEST: FAIL rebuilding an address space bound ");
        print_decimal((uint64_t)(kstack_slots_mapped - kstacks_before));
        print(" more kernel stacks\n");
        return;
    }
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

/* Carries S8: no kernel page is simultaneously writable and executable. Sweeps
 * every leaf PTE rather than sampling, and S9's guard pages with it. */
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
    extern uint32_t kstack_slots_mapped;
    extern uint64_t kstack_guard_vaddr(int id);

    /* THE SHAPE OF THIS CHECK CHANGED WHEN THE STACKS LEFT `.bss`, and the new
     * shape is stronger rather than weaker.
     *
     * It used to require all MAX_TASKS stacks to be present, which was true only
     * because they were a static array mapped in its entirety whether a task
     * existed or not. Slots are bound on first use now, so "every slot is
     * mapped" is no longer a property of a correct kernel -- asserting it would
     * make this test fail on a healthy boot.
     *
     * What replaces it says MORE than the old test did, because it splits the
     * two cases the array could not distinguish:
     *
     *   bound slot   -> guard ABSENT and stack PRESENT   (as before)
     *   unbound slot -> guard ABSENT and stack ABSENT    (new: an unbound slot
     *                   must not have been mapped by anything, which the static
     *                   array could not express because every slot was mapped)
     *
     * and the counted total is cross-checked against kstack_slots_mapped, so an
     * empty loop cannot satisfy it vacuously -- the reason the old armed-count
     * check existed. */
    uint32_t seen_bound = 0;
    for (int i = 0; i < MAX_TASKS; i++) {
        uint64_t guard = kstack_guard_vaddr(i);
        if (user_lookup_pte(kcr3, guard) & WX_PRESENT) {
            print("WX_SELFTEST: FAIL stack guard mapped for task ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
        int stack_present = (user_lookup_pte(kcr3, guard + PAGE_SIZE) & WX_PRESENT) ? 1 : 0;
        if (stack_present) {
            seen_bound++;
            /* The whole stack, not just its first page: a bind that mapped one
             * page and stopped would satisfy a single-page check and then fault
             * the moment the stack grew past it. */
            for (uint64_t pg = 1; pg < (uint64_t)KERNEL_STACK_SIZE / PAGE_SIZE; pg++) {
                if (!(user_lookup_pte(kcr3, guard + PAGE_SIZE + pg * PAGE_SIZE) & WX_PRESENT)) {
                    print("WX_SELFTEST: FAIL stack hole in task ");
                    print_decimal((uint64_t)i);
                    print("\n");
                    return;
                }
            }
        }
    }
    if (seen_bound == 0 || seen_bound != kstack_slots_mapped) {
        print("WX_SELFTEST: FAIL ");
        print_decimal(seen_bound);
        print(" stacks present, kstack_slots_mapped says ");
        print_decimal(kstack_slots_mapped);
        print("\n");
        return;
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

    /* --- Per-CPU ring-0 idle/park stacks (smp.c). These had NO guard until
     * 2026-08-17, which made S9's "below every kernel stack" false: enter_cpu_idle()
     * has always parked CPUs here, and since the [G-8] park fix the fault/exit
     * fallbacks do too, so this is ring-0 execution on a stack whose neighbour is
     * another CPU's. The guard is the slot's FIRST page, which leaves the stack top
     * where ap_trampoline.S computes it. Slot 0 is the BSP's and is armed too. */
    extern uint32_t ap_idle_guards_armed;
    extern uint32_t ap_idle_guard_count(void);
    extern uint64_t ap_idle_guard_vaddr(int i);
    uint32_t idle_n = ap_idle_guard_count();
    if (ap_idle_guards_armed != idle_n) {
        print("WX_SELFTEST: FAIL armed ");
        print_decimal(ap_idle_guards_armed);
        print(" AP idle-stack guards, expected ");
        print_decimal((uint64_t)idle_n);
        print("\n");
        return;
    }
    for (uint32_t i = 0; i < idle_n; i++) {
        uint64_t guard = ap_idle_guard_vaddr((int)i);
        if (user_lookup_pte(kcr3, guard) & WX_PRESENT) {
            print("WX_SELFTEST: FAIL AP idle-stack guard still mapped, index ");
            print_decimal((uint64_t)i);
            print("\n");
            return;
        }
        if (!(user_lookup_pte(kcr3, guard + PAGE_SIZE) & WX_PRESENT)) {
            print("WX_SELFTEST: FAIL AP idle stack unmapped, index ");
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

#ifdef PERCPU_SELFTEST
/* Gated: prove the per-CPU identity fast path is sound on every core, and that
 * the staged SYSCALL path stays unreachable.
 *
 * this_cpu() answers "which CPU am I" from the TSS selector in TR (`str`,
 * cpu = (TR - 0x38) / 0x10) instead of the uncached LAPIC MMIO read it used to
 * do -- finding [I-6], the dominant avoidable cost in the syscall path, paid
 * several times per syscall because get_current_task() sits on ~110 call sites.
 *
 * That derivation is a claim about a GDT layout owned by two OTHER files
 * (setup_tss64 in src/boot/multiboot.S pins the BSP at 0x38; ap_tss_selector in
 * src/kernel/gdt.c pins APs at 0x48/0x58/0x68). Nothing in the type system ties
 * them together. If either moves, this_cpu() starts returning another CPU's
 * index and every get_current_task() on that core silently names the wrong
 * task -- one core reading and writing another's current-task slot.
 *
 * WHAT MAKES THIS EVIDENCE RATHER THAN AGREEMENT WITH ITSELF: it does not ask
 * this_cpu() to confirm this_cpu(). percpu_id_verify_self() runs ON each core,
 * at the moment that core's TSS is loaded, and compares the STR derivation
 * against the LAPIC -- an independent oracle, the one the code used before.
 * Disagreement panics there; this test asserts the witness bitmask shows the
 * comparison actually HAPPENED on every online CPU, so a core that skipped the
 * check (or never came up) fails rather than passing by absence.
 *
 * The harness boots this with -smp 4, so `online` is expected > 1: a build where
 * the APs never start would otherwise pass this test having proven the mapping
 * on the BSP alone, which is the one case where 0x38 - 0x38 == 0 is right by
 * accident.
 *
 * It also asserts EFER.SCE is clear. STAR/LSTAR/SFMASK are programmed
 * (init_syscall_instruction_path) while SCE is not set, which is what keeps
 * syscall_entry -- staged, and still carrying a CPU-0-only kernel stack -- out
 * of reach. Setting SCE is a plausible one-line "optimisation"; this turns that
 * into a red CI run instead of two cores sharing a kernel stack. */
void percpu_selftest(void) {
    extern volatile unsigned percpu_id_verified;

    int ok = 1;
    const char *why = "";

    int online = smp_get_online_count();
    unsigned mask = percpu_id_verified;
    unsigned want = 0;
    for (int c = 0; c < online && c < MAX_CPUS; c++) want |= 1u << (unsigned)c;

    /* Every CPU that came online must have run the comparison on itself. */
    if (online < 2) {
        ok = 0; why = "single-cpu-run-mapping-unproven";
    } else if ((mask & want) != want) {
        ok = 0; why = "cpu-missing-from-id-witness";
    }

    /* The BSP's own answer, checked here against the constant it must be. */
    if (ok && this_cpu() != this_cpu_lapic()) {
        ok = 0; why = "bsp-str-lapic-disagree";
    }

    /* EFER.SCE must be clear: the staged SYSCALL path is not SMP-safe. */
    if (ok) {
        uint32_t efer_lo, efer_hi;
        __asm__ volatile ("rdmsr" : "=a"(efer_lo), "=d"(efer_hi) : "c"(0xC0000080));
        (void)efer_hi;
        if (efer_lo & 1u) { ok = 0; why = "efer-sce-set-syscall-path-not-smp-safe"; }
    }

    if (ok) {
        print("PERCPU_SELFTEST: PASS online="); print_decimal(online);
        print(" id-witness="); print_hex(mask);
        print(" str==lapic on every cpu, EFER.SCE clear\n");
    } else {
        print("PERCPU_SELFTEST: FAIL "); print(why);
        print(" online="); print_decimal(online);
        print(" id-witness="); print_hex(mask);
        print("\n");
    }
}
#endif /* PERCPU_SELFTEST */

#ifdef STACKGUARD_SELFTEST
/* Assert the stack-protector canary was actually re-seeded at boot.
 *
 * The kernel is built with -fstack-protector-strong, and every protected
 * function checks __stack_chk_guard on exit — but that only proves the guard is
 * *consistent*, never that it is *unpredictable*. If stack_protector_init() were
 * skipped, or the CSPRNG returned zeros (so the zero-guard fallback kept the
 * compile-time value), the guard would stay the published, reproducible-build
 * constant: stack protection present, every check passing, and yet trivially
 * bypassable — the SMEP/SMAP "silently off" pattern applied to the canary.
 *
 * Runs from kernel_main right after stack_protector_init(), so it observes the
 * live, post-reseed guard. Pass = the guard is neither the compile-time default
 * nor 0. */
void stackguard_selftest(void) {
    extern uintptr_t __stack_chk_guard;
    uintptr_t g = __stack_chk_guard;
    if (g == STACK_GUARD_COMPILE_DEFAULT) {
        print("STACKGUARD_SELFTEST: FAIL guard still the published compile-time constant (re-seed did not run)\n");
    } else if (g == 0) {
        print("STACKGUARD_SELFTEST: FAIL guard is zero (protection inert)\n");
    } else {
        print("STACKGUARD_SELFTEST: PASS canary re-seeded from CSPRNG\n");
    }
}
#endif /* STACKGUARD_SELFTEST */

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

    /* Stage the raw ELF and arm it; try_elf_load recomputes the real entry.
     * Bracketed like every other arm -> consume window (roadmap 1.7): this runs
     * on the BSP with the APs already running tasks that can spawn. */
    spawn_stage_acquire();
    for (uint32_t i = 0; i < sz; i++) loader_staging[i] = embedded_elftest_start[i];
    armed_hdr.entry = 0;
    armed_hdr.size  = sz;
    armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
    armed_hdr.name[3] = 't'; armed_hdr.name[4] = 0;
    loader_arm_commit();

    int saved = get_current_task();
    int pid = do_spawn();                 /* runs the real try_elf_load + W^X pass */
    spawn_stage_release();
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

    spawn_stage_acquire();
    for (uint32_t i = 0; i < sz; i++) loader_staging[i] = embedded_elftest64_start[i];
    armed_hdr.entry = 0;
    armed_hdr.size  = sz;
    armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
    armed_hdr.name[3] = '6'; armed_hdr.name[4] = '4'; armed_hdr.name[5] = 0;
    loader_arm_commit();

    int saved = get_current_task();
    int pid = do_spawn();                 /* the real try_elf_load + RELA + W^X */
    spawn_stage_release();
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
        spawn_stage_acquire();
        for (uint32_t j = 0; j < sz; j++) loader_staging[j] = embedded_elftest_start[j];
        armed_hdr.entry = 0;
        armed_hdr.size  = sz;
        armed_hdr.name[0] = 'e'; armed_hdr.name[1] = 'l'; armed_hdr.name[2] = 'f';
        armed_hdr.name[3] = 't'; armed_hdr.name[4] = 0;
        loader_arm_commit();

        int pid = do_spawn();
        spawn_stage_release();
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
    spawn_stage_acquire();
    for (uint32_t i = 0; i < size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = entry;
    armed_hdr.size  = size;
    armed_hdr.name[0] = 'p'; armed_hdr.name[1] = 't'; armed_hdr.name[2] = 0;
    loader_arm_commit();
    int pid = do_spawn();
    spawn_stage_release();
    return pid;
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
    selftest_resume_all();
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
    spawn_stage_acquire();
    for (uint32_t i = 0; i < size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = entry;
    armed_hdr.size  = size;
    armed_hdr.name[0] = 'w'; armed_hdr.name[1] = 'k'; armed_hdr.name[2] = 0;
    loader_arm_commit();
    int pid = do_spawn();
    spawn_stage_release();
    return pid;
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
    selftest_resume_all();
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
    spawn_stage_acquire();
    int pid = (arm_named_binary(name) == 0) ? do_spawn() : -1;
    spawn_stage_release();
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
    spawn_stage_acquire();
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = start[44 + i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    int k = 0;
    for (; nm[k] && k < 31; k++) armed_hdr.name[k] = nm[k];
    armed_hdr.name[k] = 0;
    loader_arm_commit();
    int pid = do_spawn();
    spawn_stage_release();
    __asm__ volatile ("mov %0, %%cr3" :: "r"(kcr3) : "memory");
    return pid;
}

/* ---- Process-control self-test (PROC_SELFTEST builds only) -----------------
 * The kernel spawns three tasks: a "hello" child that finishes with sys_exit, a
 * "looper" child (the preemption-test payload) that loops forever, and the
 * proctest driver. The driver is granted CAP_DEBUG (to read task state) and a
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

    /* Grant the driver a real CAP_DEBUG (root slot 18) so SYS_GET_TASK_INFO can
     * read the children's state — but NOT admin, so the kill must go through a
     * genuine CAP_TCB capability — plus a CAP_TCB to the looper child (root slot
     * 0 is the primordial TCB cap), scoped to loop_id. Both get fresh serials so
     * cap_lookup accepts them. */
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    /* BOTH, and for two different reasons -- which is the distinction roadmap
     * 3.6 exists to make.
     *
     * CAP_DEBUG (root 18) is what SYS_GET_TASK_INFO requires since 2026-08-24:
     * observing another task's state is observation, not audit authority.
     *
     * CAP_AUDIT (root 7) stays because the DELEGATION test needs a real
     * capability to hand a child and watch it work -- the grantee polls
     * SYS_READ_AUDIT to prove the grant landed. Swapping that for CAP_DEBUG
     * would have been least privilege applied to the wrong thing: the test is
     * about grant, and it needs a capability with an observable effect. Doing it
     * anyway broke `PROC_SELFTEST: FAIL grant-rc` on the first build, which is
     * the gate noticing before CI had to. */
    cap_install_from_root(a, CAPSLOT_DEBUG, 18, 0);  /* CAP_DEBUG: read task info  */
    cap_install_from_root(a, 7, 7, 0);               /* CAP_AUDIT: the grant test  */
    cap_install_from_root(a, 16, 0, (uint32_t)loop_id);  /* CAP_TCB -> captest   */
    tasks[a].uid = 0;

    selftest_resume_all();
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
    spawn_stage_acquire();
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    armed_hdr.name[0] = 's'; armed_hdr.name[1] = 'i'; armed_hdr.name[2] = 'g'; armed_hdr.name[3] = 0;
    loader_arm_commit();

    int a = do_spawn();
    spawn_stage_release();               /* before sched_enter_user, which never returns */
    if (a <= 0) { print("SIGNAL_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch into ring 3 via the fabricated full trap frame. */
    selftest_resume_all();
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
    spawn_stage_acquire();
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;
    armed_hdr.size  = h_size;
    armed_hdr.name[0] = 't'; armed_hdr.name[1] = 's'; armed_hdr.name[2] = 'd'; armed_hdr.name[3] = 0;
    loader_arm_commit();

    int a = do_spawn();
    spawn_stage_release();               /* before sched_enter_user, which never returns */
    if (a <= 0) { print("TSD_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    /* Launch into ring 3 via the fabricated full trap frame. */
    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* TSD_SELFTEST */

#ifdef KLOG_FORGE_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- kernel-log forgery self-test (KLOG_FORGE_SELFTEST builds only) ---------
 * The witness for finding [H-2]: a ring-3 task cannot forge lines into the
 * kernel message ring, and cannot evict what is already in it, by writing to
 * fd 1.
 *
 * The probe (userspace/klogtest.c) is endowed with CAP_KERNEL_LOG so it can READ
 * the ring back and check its own work. That capability carries CAP_RIGHT_READ
 * and nothing else -- root_cnode[15] mints it that way, and delegation may only
 * narrow -- so endowing the probe does NOT hand it the write authority the gate
 * asks for. That is the point: the probe holds the capability for this object
 * and is still refused the direction it was not given, which is a strictly
 * stronger claim than a bare task being refused everything.
 *
 * The marker below must go into the ring before ring-3 entry and must be
 * distinctive enough that the probe cannot match it by accident. Keep it in step
 * with KERNEL_MARKER in userspace/klogtest.c. */
void klog_forge_selftest(void) {
    extern uint8_t embedded_klogtest_bin_start[], embedded_klogtest_bin_end[];

    print("KLOG_FORGE_SELFTEST: launch\n");

    int a = fs_spawn_embedded(embedded_klogtest_bin_start,
                              embedded_klogtest_bin_end, "klogtest");
    if (a <= 0) { print("KLOGTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* uid 0 above, and it buys the probe NOTHING here -- the gate in h_write()
     * asks the capability graph, not the uid ([I-1], [H-1]). It is set only so
     * this harness matches the others; if setting it ever started to matter, the
     * ambient-authority regression would be the finding. */

    /* Slot 16 (CAPSLOT_KERNEL_LOG) from root slot 15 = CAP_KERNEL_LOG, READ. */
    if (cap_install_from_root(a, CAPSLOT_KERNEL_LOG, 15, 0) != 0) {
        print("KLOGTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
    }

    /* Seeded last, immediately before ring-3 entry, so no further kernel output
     * pushes it out of the ring before the probe has looked for it. */
    print("KLOGTEST-KMARK-7F3A\n");

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* KLOG_FORGE_SELFTEST */

#ifdef MAPPHYS_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- SYS_MAP_PHYS device-frame mapping self-test (MAPPHYS_SELFTEST builds only)
 * The first driver-privilege-separation job (Phase 6): prove a ring-3 task
 * endowed with CAP_IO_DEVICE can map the ALLOWLISTED VGA framebuffer into its own
 * address space, that the mapping is the REAL physical frame, and that an
 * off-list frame is refused. We seed a sentinel into a VGA cell here; the probe
 * (userspace/mapphystest.c) reads it back through its own mapping, writes+reads a
 * magic, checks the allowlist refusal, and prints MAPPHYS_SELFTEST: PASS. Entry
 * into ring 3 does not return. See docs/design/console-server.md. */
void mapphys_selftest(void) {
    extern uint8_t embedded_mapphystest_bin_start[], embedded_mapphystest_bin_end[];

    print("MAPPHYS_SELFTEST: launch\n");

    /* mapphystest is a PIE image, so it goes through the ELF loader
     * (fs_spawn_embedded), not the flat-payload staging the RDTSC/signal tests
     * use. */
    int a = fs_spawn_embedded(embedded_mapphystest_bin_start,
                              embedded_mapphystest_bin_end, "mapphys");
    if (a <= 0) { print("MAPPHYS_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* Endow the probe with a capability naming the PLATFORM device in slot 10 --
     * SYS_MAP_PHYS gate. Nothing else is ever given a copy. */
    if (cap_install_from_root(a, 10, 10, IODEV_PLATFORM) != 0) {
        print("MAPPHYS_SELFTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
    }

    /* Seed the sentinel into the last VGA text cell via the kernel's own
     * higher-half alias of 0xB8000. The probe reads this exact value back through
     * its user mapping; a fresh page would read zero. This runs after all boot
     * output, immediately before ring-3 entry, so nothing overwrites the cell
     * first. Must match CELL/SENTINEL in userspace/mapphystest.c. */
    volatile uint16_t *vga = (volatile uint16_t *)PHYS_KVA(0xB8000);
    vga[1000] = 0x0741;

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* MAPPHYS_SELFTEST */

#ifdef SHLIBC_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- The REAL shared libc, called from ring 3 (SHLIBC_SELFTEST builds only) --
 *
 * Roadmap 2.5's remaining claim. Everything under SHLIB_SELFTEST demonstrates
 * the mechanism's PROPERTIES -- text shared and unwritable (S49), data private
 * per task (S50), base drawn per boot (S51) -- on `shlibdemo.so`, a three-page
 * object written for the purpose. This one loads the real thing: ~135 KiB of
 * newlib, its port glue and libhorus, and requires a ring-3 task to actually
 * call into it.
 *
 * WHY A DEMO OBJECT COULD NOT ESTABLISH THIS. newlib is not a bag of pure
 * functions. It has writable state (`_impure_ptr` -- errno, the stdio buffers,
 * the atexit list, the rand state), it calls back into the port's syscall glue,
 * and it allocates. Each of those crosses the shared/private boundary S50 draws,
 * and none was exercised by an object whose whole data segment was one `int`.
 *
 * ONE TASK, not two, and the asymmetry with shlib_selftest is deliberate. That
 * test's question is cross-task -- can one holder write what another executes --
 * and needs a peer to answer. This one's question is whether the library WORKS,
 * which one task settles. Adding a second here would be a second copy of a test
 * that already exists rather than a stronger claim.
 *
 * The task is endowed exactly as shlibtest is, from the same two primordials:
 * text from root[20] (READ|EXEC, never WRITE) and its own private copy of the
 * data page from root[21] (READ|WRITE, never EXEC). No new authority -- what is
 * new is the object on the far side of it. */
void shlibc_selftest(void) {
    extern uint8_t embedded_libc_so_start[], embedded_libc_so_end[];
    extern uint8_t embedded_libctest_bin_start[], embedded_libctest_bin_end[];
    extern uint8_t embedded_hello_shared_bin_start[], embedded_hello_shared_bin_end[];

    print("SHLIBC_SELFTEST: launch\n");

    if (shlib_init(embedded_libc_so_start,
                   (uint64_t)(embedded_libc_so_end - embedded_libc_so_start)) != 0) {
        print("LIBCTEST: FAIL libc-load\n"); for (;;) asm volatile("hlt");
    }

    int a = fs_spawn_embedded(embedded_libctest_bin_start,
                              embedded_libctest_bin_end, "libctest");
    if (a <= 0) { print("LIBCTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* hello_shared is the other half of the claim, and a different one.
     *
     * libctest indexes the export table by hand: it proves the library WORKS.
     * hello_shared is written in ordinary C -- it calls printf and strlen by
     * name -- and links no libc at all, only the generated stub archive. It
     * proves a PROGRAM can be built against the library, which is what roadmap
     * 2.5 was actually for. Measured: the same source linked statically is
     * 106,392 bytes and linked this way is 13,088.
     *
     * Both are endowed identically and from the same primordials, so the second
     * task adds no authority -- only a second consumer of it. */
    int hs = fs_spawn_embedded(embedded_hello_shared_bin_start,
                               embedded_hello_shared_bin_end, "hello_shared");
    if (hs <= 0) { print("HELLOSHARED: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[hs].uid = 0;

    /* Same endowment rule as shlib_selftest, read off shlib_page_writable rather
     * than assuming a layout: which primordial a page comes from is a security
     * decision and belongs in one visible place. */
    for (uint32_t p = 0; p < shlib_pages(); p++) {
        uint32_t fidx = shlib_frame_index(p);
        if (fidx == 0) { print("LIBCTEST: FAIL frame-index\n"); for (;;) asm volatile("hlt"); }

        if (!shlib_page_writable(p)) {
            if (cap_install_from_root(a,  LIBC_SLOT_FIRST + p, 20, fidx) != 0 ||
                cap_install_from_root(hs, LIBC_SLOT_FIRST + p, 20, fidx) != 0) {
                print("LIBCTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
            }
            continue;
        }
        /* A private copy EACH: two tasks, two frames, from the one template
         * (S50). Instantiating once and installing it twice would be the
         * SHLIB_DATA_SHARED defect written by hand. */
        uint32_t d  = shlib_instantiate_data(p);
        uint32_t dh = shlib_instantiate_data(p);
        if (d == 0 || dh == 0) { print("LIBCTEST: FAIL instantiate-data\n"); for (;;) asm volatile("hlt"); }
        if (cap_install_from_root(a,  LIBC_SLOT_FIRST + p, 21, d)  != 0 ||
            cap_install_from_root(hs, LIBC_SLOT_FIRST + p, 21, dh) != 0) {
            print("LIBCTEST: FAIL endow-data\n"); for (;;) asm volatile("hlt");
        }
    }

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* SHLIBC_SELFTEST */

#ifdef SHLIB_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Shared library text self-test (SHLIB_SELFTEST builds only) -------------
 *
 * Roadmap 2.5's mechanism, and S49's witness. The library is loaded ONCE into
 * frames here at boot; two tasks are then endowed with READ|EXEC capabilities
 * over the SAME frames, map them independently, and execute them.
 *
 * TWO TASKS, NOT ONE, AND THAT IS THE POINT. A single task proving it cannot
 * write its own library page proves less than it looks. The failure worth
 * excluding is cross-task: one holder of a shared mapping patching code a
 * DIFFERENT holder runs, which is a code-injection primitive that static
 * per-program copies did not have. So the peer is the half that would notice,
 * and it reports the pair's verdict. */
void shlib_selftest(void) {
    extern uint8_t embedded_shlibdemo_so_start[], embedded_shlibdemo_so_end[];
    extern uint8_t embedded_shlibtest_bin_start[], embedded_shlibtest_bin_end[];
    extern uint8_t embedded_shlibpeer_bin_start[], embedded_shlibpeer_bin_end[];

    print("SHLIB_SELFTEST: launch\n");

    if (shlib_init(embedded_shlibdemo_so_start,
                   (uint64_t)(embedded_shlibdemo_so_end - embedded_shlibdemo_so_start)) != 0) {
        print("SHLIBTEST: FAIL shlib-load\n"); for (;;) asm volatile("hlt");
    }

    int peer = fs_spawn_embedded(embedded_shlibpeer_bin_start,
                                 embedded_shlibpeer_bin_end, "shlibpeer");
    if (peer <= 0) { print("SHLIBTEST: FAIL spawn-peer\n"); for (;;) asm volatile("hlt"); }
    tasks[peer].uid = 0;

    int a = fs_spawn_embedded(embedded_shlibtest_bin_start,
                              embedded_shlibtest_bin_end, "shlibtest");
    if (a <= 0) { print("SHLIBTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;
    tasks[a].spawn_arg = (uint32_t)peer;

    /* The supervisor right over the peer, so shlibtest may release it when its
     * own checks are done. Root slot 0 is the CAP_TCB template; the object is
     * rewritten to the peer's task id, which is what turns a template into a
     * capability naming one task. task_kill_authorized scans the cspace for it,
     * so the slot number is a convention and the capability is the authority. */
    if (cap_install_from_root(a, SHLIB_SLOT_PEER_TCB, 0, (uint32_t)peer) != 0) {
        print("SHLIBTEST: FAIL endow-peer-tcb\n"); for (;;) asm volatile("hlt");
    }

    /* Endow both tasks, and the two segments are endowed DIFFERENTLY -- which is
     * the whole of S50 expressed in one loop.
     *
     * TEXT: the same frames for both, from root[20], READ|EXEC and never WRITE.
     * One physical copy of the library's code, executed by two tasks, writable
     * by neither (S49).
     *
     * DATA: a frame of its OWN for each task, carved and initialised from the
     * library's image by shlib_instantiate_data, endowed from root[21] with
     * READ|WRITE and never EXEC. Two tasks, two copies, no shared writable
     * state. Note where the isolation lives: NOT in the rights, which are
     * identical for both tasks, but in the OBJECT each capability names being a
     * different frame. Rights say what may be done; the object says to what.
     *
     * Reading shlib_page_writable at each page rather than assuming a layout
     * keeps that decision in one visible place -- the linker script puts data on
     * its own page, but a linker script is not an enforcement mechanism. */
    for (uint32_t p = 0; p < shlib_pages(); p++) {
        uint32_t fidx = shlib_frame_index(p);
        if (fidx == 0) { print("SHLIBTEST: FAIL frame-index\n"); for (;;) asm volatile("hlt"); }

        if (!shlib_page_writable(p)) {
            if (cap_install_from_root(a,    SHLIB_SLOT_FIRST + p, 20, fidx) != 0 ||
                cap_install_from_root(peer, SHLIB_SLOT_FIRST + p, 20, fidx) != 0) {
                print("SHLIBTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
            }
            continue;
        }

        uint32_t da = shlib_instantiate_data(p);
        uint32_t dp = shlib_instantiate_data(p);
        if (da == 0 || dp == 0) {
            print("SHLIBTEST: FAIL instantiate-data\n"); for (;;) asm volatile("hlt");
        }
        if (cap_install_from_root(a,    SHLIB_SLOT_FIRST + p, 21, da) != 0 ||
            cap_install_from_root(peer, SHLIB_SLOT_FIRST + p, 21, dp) != 0) {
            print("SHLIBTEST: FAIL endow-data\n"); for (;;) asm volatile("hlt");
        }
    }

    selftest_resume_all();
    /* ...then hold the peer back again. resume_all wakes every spawned task, and
     * the peer must not read the library before the first task has finished with
     * it -- under the control arm the first task PATCHES it, and a peer that read
     * early would report a pass that meant nothing. frametest holds its peer the
     * same way and for the same reason. */
    tasks[peer].runnable_ctx = 0;

    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* SHLIB_SELFTEST */

#ifdef NET_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Ring-3 network driver self-test (NET_SELFTEST builds only) --------------
 *
 * Roadmap 2.6's first half: stand up `netd`, an Intel e1000 driver whose ENTIRE
 * authority is one CAP_IO_DEVICE naming the NIC plus a delegated untyped region,
 * and require it to complete a real exchange on the wire — an ARP request for
 * QEMU's user-mode gateway, and the reply coming back through its own receive
 * ring (NETTEST: PASS).
 *
 * Two capabilities and nothing else. No console capability (its output is the
 * ambient fd-1 write every probe uses), no filesystem, no boot modules, no user
 * database. If it needed anything more, the claim that a network stack can be
 * driven from an unprivileged address space would be weaker than it looks.
 *
 * FAILS rather than skips with no NIC, for devcap_selftest's reason: without the
 * device the whole experiment is vacuous, and a gate that quietly becomes a no-op
 * reports PASS. `make smoke-net` boots QEMU with SMOKE_NET=user, which is what
 * puts both a NIC and something at the other end of it. */
void net_selftest(void) {
    extern uint8_t embedded_netd_bin_start[], embedded_netd_bin_end[];

    print("NET_SELFTEST: launch\n");

    uint64_t nic = iodev_first_of_class(IODEV_CLASS_NETWORK);
    if (nic == IODEV_NONE) {
        print("NETTEST: FAIL no-nic-present\n"); for (;;) asm volatile("hlt");
    }

    int a = fs_spawn_embedded(embedded_netd_bin_start, embedded_netd_bin_end, "netd");
    if (a <= 0) { print("NET_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* The NIC, and the kernel memory it needs to build rings in. The untyped
     * region is the one authority beyond the device: a driver has to be able to
     * allocate DMA-able memory, and doing that through CAP_UNTYPED means the
     * memory it consumes is bounded and attributable rather than ambient. */
    if (cap_install_from_root(a, CAPSLOT_IO_DEVICE, 10, (uint32_t)nic) != 0) {
        print("NET_SELFTEST: FAIL endow-nic\n"); for (;;) asm volatile("hlt");
    }
    if (cap_install_from_root(a, CAPSLOT_UNTYPED, 17, UNTYPED_ROOT) != 0) {
        print("NET_SELFTEST: FAIL endow-untyped\n"); for (;;) asm volatile("hlt");
    }
    /* The rendezvous its interrupt is routed to. A notification is a separate
     * capability from the device precisely so that "may drive this hardware" and
     * "may be woken here" are separate grants -- SYS_IRQ_REGISTER needs both, and
     * refuses to aim a real interrupt at a notification the caller does not hold
     * (finding C-2). */
    cap_install_from_root(a, CAPSLOT_NOTIFY, 14, NOTIF_FS_READY);

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* NET_SELFTEST */

#ifdef DEVCAP_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Device-capability isolation self-test (DEVCAP_SELFTEST builds only) -----
 *
 * The witness that a CAP_IO_DEVICE names a DEVICE. The probe
 * (userspace/devcaptest.c) is endowed with TWO device capabilities — the legacy
 * platform device in slot 10 and the machine's PCI network controller in slot 20
 * — and shows that each reaches its own device's frames, ports and interrupt and
 * is refused the other's, in both directions. DEVCAPTEST: PASS.
 *
 * WHY THE HARNESS FAILS RATHER THAN SKIPS WHEN THERE IS NO NIC. A second device
 * is the entire experiment: with only the platform device present, every negative
 * in the probe is vacuous and the suite would pass on the very kernel it exists
 * to reject. A gate that quietly becomes a no-op on a machine without a NIC is
 * worse than one that is absent, because it reports PASS. `make smoke-devcap`
 * boots QEMU with SMOKE_NET=1 for exactly this reason. */
void devcap_selftest(void) {
    extern uint8_t embedded_devcaptest_bin_start[], embedded_devcaptest_bin_end[];

    print("DEVCAP_SELFTEST: launch\n");

    uint64_t nic = iodev_first_of_class(IODEV_CLASS_NETWORK);
    if (nic == IODEV_NONE) {
        /* Not "skip". See above. */
        print("DEVCAPTEST: FAIL no-nic-present\n"); for (;;) asm volatile("hlt");
    }

    int a = fs_spawn_embedded(embedded_devcaptest_bin_start,
                              embedded_devcaptest_bin_end, "devcap");
    if (a <= 0) { print("DEVCAP_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* Slot 10: the platform device. Slot 20: the NIC. Both are copied from the
     * root cnode, so both are primordial CAP_IO_DEVICE capabilities with the same
     * type and the same rights — they differ in exactly one field, the object,
     * which is the point. If the object did not matter these two would be
     * interchangeable, and that is what the suite falsifies. */
    if (cap_install_from_root(a, CAPSLOT_IO_DEVICE, 10, IODEV_PLATFORM) != 0) {
        print("DEVCAP_SELFTEST: FAIL endow-platform\n"); for (;;) asm volatile("hlt");
    }
    if (cap_install_from_root(a, CAPSLOT_IO_DEVICE_ALT, 10, (uint32_t)nic) != 0) {
        print("DEVCAP_SELFTEST: FAIL endow-nic\n"); for (;;) asm volatile("hlt");
    }
    /* A notification (the SYS_IRQ_REGISTER destination) and a CAP_CONSOLE, which
     * is there to be the WRONG type: the probe checks a non-device capability in
     * the device-slot argument is refused, not merely that an empty slot is. */
    cap_install_from_root(a, CAPSLOT_NOTIFY,  14, NOTIF_FS_READY);
    cap_install_from_root(a, CAPSLOT_CONSOLE,  8, 0);

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* DEVCAP_SELFTEST */

#ifdef IOPORT_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- TSS I/O-permission bitmap self-test (IOPORT_SELFTEST builds only) -------
 * Second driver-privilege-separation job (Phase 6): prove a ring-3 task endowed
 * with CAP_IO_DEVICE can be granted native port I/O (SYS_IOPORT_GRANT) on the
 * console ports and that the grant is precise -- an allowlisted port succeeds, a
 * non-allowlisted port still #GPs. The probe (userspace/ioporttest.c) self-asserts
 * and prints IOPORT_SELFTEST: PASS. Entry into ring 3 does not return. See
 * docs/design/console-server.md. */
void ioport_selftest(void) {
    extern uint8_t embedded_ioporttest_bin_start[], embedded_ioporttest_bin_end[];

    print("IOPORT_SELFTEST: launch\n");

    int a = fs_spawn_embedded(embedded_ioporttest_bin_start,
                              embedded_ioporttest_bin_end, "ioport");
    if (a <= 0) { print("IOPORT_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* Endow the probe with a capability naming the PLATFORM device in slot 10 --
     * SYS_IOPORT_GRANT gate. Nothing else is ever given a copy. */
    if (cap_install_from_root(a, 10, 10, IODEV_PLATFORM) != 0) {
        print("IOPORT_SELFTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
    }

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* IOPORT_SELFTEST */

#ifdef IRQ_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- IRQ -> notification bridge self-test (IRQ_SELFTEST builds only) ---------
 * Third driver-privilege-separation job (Phase 6): prove a ring-3 task endowed
 * with CAP_IO_DEVICE can route a hardware IRQ to an async notification. The probe
 * (userspace/irqtest.c) registers the timer IRQ, blocks in SYS_WAIT_NOTIFY, and a
 * real timer interrupt wakes it with the registered badge (IRQ_SELFTEST: PASS).
 * The timer self-triggers, so no key injection is needed. Entry into ring 3 does
 * not return. See docs/design/console-server.md. */
void irq_selftest(void) {
    extern uint8_t embedded_irqtest_bin_start[], embedded_irqtest_bin_end[];

    print("IRQ_SELFTEST: launch\n");

    int a = fs_spawn_embedded(embedded_irqtest_bin_start,
                              embedded_irqtest_bin_end, "irqtest");
    if (a <= 0) { print("IRQ_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[a].uid = 0;

    /* Notifications are capability-addressed (finding C-2): SYS_IRQ_REGISTER and
     * SYS_WAIT_NOTIFY both take a cspace slot holding a CAP_NOTIFICATION, so the
     * test needs one. slot 10 = CAP_IO_DEVICE gates SYS_IRQ_REGISTER; nothing
     * else gets the device cap. */
    cap_install_from_root(a, CAPSLOT_NOTIFY, 14, NOTIF_FS_READY);
    if (cap_install_from_root(a, 10, 10, IODEV_PLATFORM) != 0) {
        print("IRQ_SELFTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
    }

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(a);
}
#endif /* IRQ_SELFTEST */

#ifdef CONSOLE_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Ring-3 console server self-test (CONSOLE_SELFTEST builds only) ----------
 * The J5 cutover's first, gated milestone: stand up the userspace console_server
 * (which owns the console hardware via SYS_MAP_PHYS + SYS_IOPORT_GRANT) and a
 * client that drives it over IPC, exactly as FS_SELFTEST first proved the
 * filesystem server before it became the default. The client asks the server to
 * write a line; the server emits it to serial with its own hands, so
 * "CONSOLE_SELFTEST: PASS" appearing on serial proves the whole ring-3 console
 * output path (client -> IPC -> server -> hardware). Entry into ring 3 does not
 * return. See docs/design/console-server.md. */
void console_selftest(void) {
    extern uint8_t embedded_console_server_bin_start[], embedded_console_server_bin_end[];
    extern uint8_t embedded_consoletest_bin_start[], embedded_consoletest_bin_end[];

    print("CONSOLE_SELFTEST: begin\n");

    int srv = fs_spawn_embedded(embedded_console_server_bin_start,
                                embedded_console_server_bin_end, "console_server");
    if (srv <= 0) { print("CONSOLE_SELFTEST: FAIL spawn-server\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    /* The console LISTEN capability (READ = the receive right) lets the server
     * recv requests and answer them with SYS_IPC_REPLY_TO; slot 10 =
     * CAP_IO_DEVICE gates SYS_MAP_PHYS / SYS_IOPORT_GRANT. Nothing else gets the
     * device cap — only the console server owns the hardware. */
    cap_install_from_root(srv, CAPSLOT_CONSOLE_EP, 11, CON_EP_REQ);
    if (cap_install_from_root(srv, 10, 10, IODEV_PLATFORM) != 0) {
        print("CONSOLE_SELFTEST: FAIL endow\n"); for (;;) asm volatile("hlt");
    }

    int cli = fs_spawn_embedded(embedded_consoletest_bin_start,
                                embedded_consoletest_bin_end, "consoletest");
    if (cli <= 0) { print("CONSOLE_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
    tasks[cli].uid = 0;
    cap_install_from_root(cli, CAPSLOT_CONSOLE_EP, 12, CON_EP_REQ);  /* client: WRITE only */

    /* Launch the server; when it blocks in IPC the full-context path runs the
     * client. Does not return. */
    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* CONSOLE_SELFTEST */

#ifdef LIBHORUS_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- libhorus conformance self-test (LIBHORUS_SELFTEST builds only) ---------
 *
 * Spawns one ring-3 task and lets it assert against the shared userspace runtime
 * every freestanding program now links. It is endowed with NOTHING beyond what a
 * spawn gives it, and that is deliberate: the test that matters most calls
 * ipc_call_retry on an empty capability slot and requires it to come back with a
 * refusal instead of spinning. Installing any endpoint capability here would
 * remove the very condition under test.
 *
 * Entry into ring 3 does not return. */
void libhorus_selftest(void) {
    extern uint8_t embedded_libhorustest_bin_start[], embedded_libhorustest_bin_end[];

    print("LIBHORUS_SELFTEST: spawning\n");

    int t = fs_spawn_embedded(embedded_libhorustest_bin_start,
                              embedded_libhorustest_bin_end, "libhorustest");
    if (t <= 0) { print("LIBHORUS_SELFTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(t);
}
#endif /* LIBHORUS_SELFTEST */

#ifdef VFS_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- VFS mount-table self-test (VFS_SELFTEST builds only) -------------------
 *
 * Roadmap 2.4. Stands up a SECOND filesystem server and a client that mounts
 * both into one namespace, because a mount table with one mount cannot
 * demonstrate anything: every path resolves to the same server, so "longest
 * prefix wins" and "the capability decides, not the path" are both
 * unfalsifiable.
 *
 * ENDPOINTS. dev_server serves on CON_EP_REQ, reusing root slots 11 (READ|WRITE,
 * the listen right) and 12 (WRITE only, the client). Nothing console-related
 * runs in this build, so it is simply a spare endpoint with a ready-made
 * asymmetric capability pair -- the same trade recvblock_selftest makes and for
 * the same reason: changing the primordial capability table to test something
 * that is not about the primordial capability table is a poor trade.
 *
 * The production path is different and deliberately not exercised here: init
 * will retype an endpoint out of its own CAP_UNTYPED and mint the client copy
 * with SYS_CAP_MINT. That needs init to hold a CAP_UNTYPED, which it does not
 * today, and widening the delegation root's authority belongs in its own commit
 * rather than riding along inside a test harness.
 *
 * WHAT vfstest IS AND IS NOT GIVEN. It gets the WRITE-only client capability for
 * dev_server (slot 21) and the ordinary fs client capability, and NOTHING in
 * slot 30 -- which is what makes "a mount needs a capability, not a prefix"
 * checkable from ring 3. Entry into ring 3 does not return. */
void vfs_selftest(void) {
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    extern uint8_t embedded_dev_server_bin_start[], embedded_dev_server_bin_end[];
    extern uint8_t embedded_vfstest_bin_start[], embedded_vfstest_bin_end[];

    extern uint8_t embedded_fsserver_bin_start[], embedded_fsserver_bin_end[];

    print("VFS_SELFTEST: begin\n");

    /* The ROOT mount's server. Endowed exactly as fs_selftest endows it -- the
     * listen endpoint, the CAP_USER that gates registration, the object store,
     * and the boot-module surface. It is here to be the OTHER server: the whole
     * point of the mount table is that two paths reach two different tasks, and
     * with one server that is unfalsifiable. */
    int fss = fs_spawn_embedded(embedded_fsserver_bin_start,
                                embedded_fsserver_bin_end, "fs_server");
    if (fss <= 0) { print("VFSTEST: FAIL spawn-fs-server\n"); for (;;) asm volatile("hlt"); }
    tasks[fss].uid = 0;
    cap_install_from_root(fss, CAPSLOT_FS_LISTEN,   13, FS_EP_REQ);
    cap_install_from_root(fss, 6, 6, 0);                      /* CAP_USER, registration */
    cap_install_from_root(fss, CAPSLOT_AUDIT,        9, 0);   /* CAP_ENCRYPTED_STORAGE  */
    cap_install_from_root(fss, CAPSLOT_BOOT_MODULE, 16, 0);   /* CAP_BOOT_MODULE        */

    int dev = fs_spawn_embedded(embedded_dev_server_bin_start,
                                embedded_dev_server_bin_end, "dev_server");
    if (dev <= 0) { print("VFSTEST: FAIL spawn-dev-server\n"); for (;;) asm volatile("hlt"); }
    /* The listen right, and to nobody else: only dev_server can dequeue requests
     * on this endpoint and answer them with SYS_IPC_REPLY_TO. */
    cap_install_from_root(dev, CAPSLOT_FS_LISTEN, 11, CON_EP_REQ);

    int cli = fs_spawn_embedded(embedded_vfstest_bin_start,
                                embedded_vfstest_bin_end, "vfstest");
    if (cli <= 0) { print("VFSTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
    cap_install_from_root(cli, 21, 12, CON_EP_REQ);   /* /dev client: WRITE only */
    /* Slot 30 is left EMPTY on purpose -- it is the uncapable slot vfstest
     * mounts against to prove a prefix alone installs nothing. */

    /* fs_server first: it must REGISTER before vfstest's sys_connect_fs_server
     * can succeed, and it blocks on an empty endpoint once it has. The switch
     * that follows runs dev_server, then the client. vfstest retries the connect
     * with a bound, so this ordering is belt-and-braces rather than relied on. */
    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(fss);
}
#endif /* VFS_SELFTEST */

#ifdef PASSWD_PROBE
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* Spawn one ring-3 task endowed with NOTHING and let it try to read the user
 * database. uid 0 is set only to show it is irrelevant -- the path under test
 * consults no uid. */
void passwd_probe_selftest(void) {
    extern uint8_t embedded_passwdprobe_bin_start[], embedded_passwdprobe_bin_end[];
    extern int do_passwd(uint32_t target_uid, const char *new_password);
    print("PASSWD_PROBE: begin\n");

    /* Establish the ORDINARY precondition, in kernel context so the probe's own
     * timing is not dominated by Argon2: somebody has changed a password in
     * this boot. That is the only thing that puts the user database into the
     * ramfs -- users_init only ever LOADS from it, and nothing persists the
     * ramfs to disk, so before the first change the file does not exist.
     *
     * This is not privilege the probe is being lent. do_passwd permits a user
     * to change their OWN password with no admin right at all, so any account
     * on the system can reach this state unaided; doing it here just keeps the
     * expensive hash off the path under test. */
    if (do_passwd(0, "rootpass2") != 0) {
        print("PASSWDPROBE: FAIL could not establish the precondition\n");
        for (;;) asm volatile("hlt");
    }
    print("PASSWD_PROBE: a password was changed; the database is now in the ramfs\n");
    int t = fs_spawn_embedded(embedded_passwdprobe_bin_start,
                              embedded_passwdprobe_bin_end, "passwdprobe");
    if (t <= 0) { print("PASSWDPROBE: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    /* uid 1000, the ordinary "user" account -- NOT root. The point is that no
     * privilege of any kind is needed, so giving the probe uid 0 would weaken
     * the demonstration rather than strengthen it. It is endowed with no
     * capability at all beyond what create_task hands every task. */
    tasks[t].uid = 1000;
    tasks[t].gid = 100;
    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(t);
}
#endif /* PASSWD_PROBE */

#ifdef FRAME_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Frame-capability self-test (FRAME_SELFTEST builds only) ----------------
 *
 * Roadmap 2.1 / finding F-2.1. Stands up two ring-3 tasks around one page of
 * physical memory: frametest holds a CAP_UNTYPED and does the creating, mapping
 * and delegating; framepeer holds nothing except the READ-only capability
 * frametest mints and grants it, and proves both halves of what shared memory
 * has to mean -- it sees the bytes, and it cannot write them.
 *
 * WHAT IS ENDOWED, AND WHAT IS DELIBERATELY NOT.
 *
 * frametest gets exactly one capability beyond what a spawn gives it: the
 * CAP_UNTYPED over the user-facing region, from root slot 17. That is what pays
 * for the frame, and endowing it is the whole point -- a frame must be
 * attributable to untyped authority somebody holds, not conjured by a syscall.
 *
 * framepeer gets NOTHING. Every capability it ends up with came from frametest
 * across SYS_CAP_GRANT, which is the only way it can have got them. If the test
 * endowed the peer directly, the delegation under test would be scaffolding
 * rather than the mechanism, and the READ-only check would prove nothing about
 * minting.
 *
 * frametest also gets a CAP_TCB naming the peer, because SYS_CAP_GRANT and
 * SYS_TASK_RESUME both authorise on "a CAP_TCB to the target, or CAP_USER
 * admin" -- a task may only push capabilities DOWN into a child it supervises.
 * The first draft of this harness set tasks[pid].uid = 0 instead, on the pattern
 * the older self-tests use, and both operations were refused: since [H-1] uid 0
 * is not admin anywhere, `admin` means holding a CAP_USER. That refusal is the
 * S18 property working, so the endowment is the supervisor capability the design
 * actually intends rather than a way around it. Deliberately NOT a CAP_USER:
 * that would hand the test user-management authority to obtain a resume.
 *
 * SUSPENSION. The peer is spawned and then explicitly held back, so frametest
 * finishes its own refusal checks and grants before the peer runs at all. The
 * peer additionally waits for its capability with a BOUNDED retry, so this
 * ordering is belt-and-braces rather than a thing correctness rests on -- an
 * unbounded wait would turn a failed grant into a hang, which is the failure
 * mode finding G-8 signature C is about.
 *
 * The peer prints the pair's marker. Entry into ring 3 does not return. */
#define FRAMETEST_SLOT_PEER_TCB 29   /* must match userspace/frametest.c */
void frame_selftest(void) {
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    extern uint8_t embedded_frametest_bin_start[], embedded_frametest_bin_end[];
    extern uint8_t embedded_framepeer_bin_start[], embedded_framepeer_bin_end[];

    print("FRAME_SELFTEST: begin\n");

    int peer = fs_spawn_embedded(embedded_framepeer_bin_start,
                                 embedded_framepeer_bin_end, "framepeer");
    if (peer <= 0) { print("FRAMETEST: FAIL spawn-peer\n"); for (;;) asm volatile("hlt"); }

    int pid = fs_spawn_embedded(embedded_frametest_bin_start,
                                embedded_frametest_bin_end, "frametest");
    if (pid <= 0) { print("FRAMETEST: FAIL spawn-parent\n"); for (;;) asm volatile("hlt"); }

    tasks[pid].spawn_arg = (uint64_t)peer;  /* how frametest names its delegate */
    if (cap_install_from_root(pid, CAPSLOT_UNTYPED, 17, UNTYPED_ROOT) != 0) {
        print("FRAMETEST: FAIL endow-untyped\n"); for (;;) asm volatile("hlt");
    }
    /* Root slot 0 is the CAP_TCB template (CAP_RIGHT_ALL); the object is
     * rewritten to the peer's task id, which is what makes it a capability for
     * THAT child rather than for task 0. */
    if (cap_install_from_root(pid, FRAMETEST_SLOT_PEER_TCB, 0, (uint32_t)peer) != 0) {
        print("FRAMETEST: FAIL endow-peer-tcb\n"); for (;;) asm volatile("hlt");
    }

    selftest_resume_all();
    /* ...then hold the peer back again. resume_all is a blunt instrument that
     * wakes every spawned task; the peer must not observe its slot before the
     * grant lands, or the check that the grant WORKED would be racing the check
     * that an ungranted slot is refused. frametest resumes it explicitly. */
    tasks[peer].runnable_ctx = 0;

    sched_enable_preemption();
    sched_enter_user(pid);
}
#endif /* FRAME_SELFTEST */

#ifdef RECVBLOCK_SELFTEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Blocking IPC receive self-test (RECVBLOCK_SELFTEST builds only) --------
 *
 * Roadmap 1.3's last item. Stands up two ring-3 tasks around one endpoint: a
 * server that waits with SYS_IPC_RECV_BLOCK and a client that deliberately
 * dawdles before each request. The server asserts it made exactly one receive
 * syscall per message — the witness that it SLEPT rather than polled — and that
 * the wake left it holding the one-shot reply right. It prints the marker itself
 * from ring 3, so RECVBLOCK_SELFTEST: PASS on serial is end-to-end proof.
 *
 * The endpoint is the console request endpoint, reusing root slots 11 (READ|
 * WRITE, the receive right) and 12 (WRITE only, the client). Nothing console-
 * related runs in this build — console_server is not spawned — so the object is
 * simply a spare endpoint with a ready-made asymmetric capability pair. Adding
 * root slots for a self-test would mean editing cap_init, and changing the
 * primordial capability table to test something that is not about the primordial
 * capability table is a poor trade.
 *
 * Note the client holds WRITE only: it can send but can never receive on this
 * endpoint, so the exchange also depends on the C-1 asymmetry holding. Entry
 * into ring 3 does not return. */
void recvblock_selftest(void) {
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    extern uint8_t embedded_recvblocksrv_bin_start[], embedded_recvblocksrv_bin_end[];
    extern uint8_t embedded_recvblockcli_bin_start[], embedded_recvblockcli_bin_end[];

    print("RECVBLOCK_SELFTEST: begin\n");

    int srv = fs_spawn_embedded(embedded_recvblocksrv_bin_start,
                                embedded_recvblocksrv_bin_end, "recvblocksrv");
    if (srv <= 0) { print("RECVBLOCK_SELFTEST: FAIL spawn-server\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    cap_install_from_root(srv, CAPSLOT_CONSOLE_EP, 11, CON_EP_REQ);   /* READ|WRITE */

    int cli = fs_spawn_embedded(embedded_recvblockcli_bin_start,
                                embedded_recvblockcli_bin_end, "recvblockcli");
    if (cli <= 0) { print("RECVBLOCK_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
    tasks[cli].uid = 0;
    cap_install_from_root(cli, CAPSLOT_CONSOLE_EP, 12, CON_EP_REQ);   /* WRITE only */

    /* Launch the server first: it blocks on an empty endpoint, and the full-
     * context switch that follows is what runs the client. That ordering is the
     * point — if the block did not deschedule, the client would never start. */
    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* RECVBLOCK_SELFTEST */

#ifdef CONSOLE_ISOLATION_TEST
static int fs_spawn_embedded(const uint8_t *start, const uint8_t *end, const char *nm);
/* ---- Console blast-radius self-test (CONSOLE_ISOLATION_TEST builds only) ------
 * The Phase 6 close-out: prove the security win of moving the console into ring 3.
 * console_server (built with the same flag) takes ownership of the hardware, then
 * deliberately faults. Because it now runs in ring 3, the fault is delivered to
 * its own handler and the kernel keeps running -- it cannot reach kernel memory or
 * the capability system, which is exactly the blast-radius reduction the program
 * set out to achieve. The handler prints CONSOLE_ISOLATION: PASS through the
 * (still-alive) kernel console. Entry into ring 3 does not return. See
 * docs/design/console-server.md. */
void console_isolation_selftest(void) {
    extern uint8_t embedded_console_server_bin_start[], embedded_console_server_bin_end[];

    print("CONSOLE_ISOLATION: begin\n");

    int srv = fs_spawn_embedded(embedded_console_server_bin_start,
                                embedded_console_server_bin_end, "console_server");
    if (srv <= 0) { print("CONSOLE_ISOLATION: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[srv].uid = 0;
    cap_install_from_root(srv, CAPSLOT_CONSOLE_EP, 11, CON_EP_REQ);  /* console listen */
    if (cap_install_from_root(srv, 10, 10, IODEV_PLATFORM) != 0) {
        print("CONSOLE_ISOLATION: FAIL endow\n"); for (;;) asm volatile("hlt");
    }

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(srv);
}
#endif /* CONSOLE_ISOLATION_TEST */

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

#if defined(FS_SELFTEST) || defined(NEWLIB_SELFTEST) || defined(NOTIFY_SELFTEST) || defined(COW_SELFTEST) || defined(CAPTEST_SELFTEST) || defined(MAPPHYS_SELFTEST) || defined(IOPORT_SELFTEST) || defined(IRQ_SELFTEST) || defined(CONSOLE_SELFTEST) || defined(CONSOLE_ISOLATION_TEST) || defined(RECVBLOCK_SELFTEST) || defined(KLOG_FORGE_SELFTEST) \
    || defined(LIBHORUS_SELFTEST) || defined(FRAME_SELFTEST) || defined(PASSWD_PROBE) || defined(VFS_SELFTEST) || defined(FORK_SELFTEST) || defined(FPU_SELFTEST) || defined(FORKEXEC_SELFTEST) || defined(DEVCAP_SELFTEST) || defined(NET_SELFTEST) || defined(SHLIB_SELFTEST) || defined(SHLIBC_SELFTEST)
/* ---- Selftest spawn helper (FS/NEWLIB/NOTIFY/COW/CAPTEST/MAPPHYS/IOPORT/IRQ/CONSOLE/RECVBLOCK/KLOG_FORGE/FORK only) ----
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
    spawn_stage_acquire();
    for (uint32_t i = 0; i < h_size; i++) loader_staging[i] = payload[i];
    armed_hdr.entry = h_entry;           /* recomputed by try_elf_load for the PIE ELF */
    armed_hdr.size  = h_size;
    int k = 0;
    while (k < 31 && nm[k]) { armed_hdr.name[k] = nm[k]; k++; }
    armed_hdr.name[k] = 0;
    loader_arm_commit();
    int pid = do_spawn();
    spawn_stage_release();
    return pid;
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
    cap_install_from_root(srv, CAPSLOT_FS_LISTEN, 13, FS_EP_REQ);  /* fs listen (READ|WRITE) */
    cap_install_from_root(srv, 6, 6, 0);          /* root_cnode[6] = CAP_USER (ALL) */
    /* The object-store capability, BY TYPE (finding I-1). This used to install
     * root_cnode[8] — a CAP_CONSOLE — into slot 7, and it worked only because the
     * dispatch table passed the CAP_BLOCK_DEV type constant in the RIGHTS field
     * with ctype = SC_ANYTYPE, so the gate never checked the type at all. Now the
     * store syscalls require CAP_ENCRYPTED_STORAGE (root_cnode[9]) by type, which
     * is what fs_server is actually meant to hold. */
    cap_install_from_root(srv, CAPSLOT_AUDIT,       9,  0);   /* CAP_ENCRYPTED_STORAGE */
    cap_install_from_root(srv, CAPSLOT_BOOT_MODULE, 16, 0);   /* CAP_BOOT_MODULE       */

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
        /* Only the coordinator polls the OTHER clients' task state to know when
         * they have finished. Cross-task introspection now requires a real
         * CAP_AUDIT (finding I-1) — it used to work merely because the caller was
         * uid 0, which is exactly the ambient authority that was removed. The
         * workers are deliberately NOT given it: least privilege, and it keeps
         * this harness an honest exercise of the capability model. */
        /* The coordinator polls its workers' task state, which is CAP_DEBUG's
         * job since 2026-08-24 -- it never read the audit log. */
        if (i == 0) cap_install_from_root(c, CAPSLOT_DEBUG, 18, 0);  /* CAP_DEBUG */
    }
#else
    int cli = fs_spawn_embedded(embedded_fsclient_bin_start, embedded_fsclient_bin_end, "fsclient");
    if (cli <= 0) { print("FS_SELFTEST: FAIL spawn-client\n"); for (;;) asm volatile("hlt"); }
    tasks[cli].uid = 0;
    /* No endpoint endowment needed: the client acquires a WRITE-only capability
     * to the fs service itself via SYS_CONNECT_FS_SERVER (into CAPSLOT_FS_EP).
     * That is now the only way a client reaches a server — the ambient slot-3
     * endpoint capability this used to rely on no longer exists (finding C-1). */
#endif

    /* Launch the server; when it blocks in IPC the full-context path runs the
     * client(s). Does not return. */
    selftest_resume_all();
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
    cap_install_from_root(srv, CAPSLOT_FS_LISTEN, 13, FS_EP_REQ);  /* fs listen (READ|WRITE) */
    cap_install_from_root(srv, 6, 6, 0);
    cap_install_from_root(srv, CAPSLOT_AUDIT,       9,  0);   /* CAP_ENCRYPTED_STORAGE (by type) */
    cap_install_from_root(srv, CAPSLOT_BOOT_MODULE, 16, 0);   /* CAP_BOOT_MODULE                 */

    int pid = fs_spawn_embedded(embedded_hello_newlib_bin_start,
                                embedded_hello_newlib_bin_end,
                                "hello_newlib");
    print("NEWLIB_SELFTEST: pid="); print_hex(pid); print("\n");
    if (pid <= 0) {
        print("NEWLIB_SELFTEST: FAIL spawn\n");
        for (;;) asm volatile("hlt");
    }
    tasks[pid].uid = 0;
    /* The client acquires its fs capability itself via SYS_CONNECT_FS_SERVER
     * (the RAM store is auto-unlocked at boot and the client is kernel-attested
     * uid 0, so no login is needed). */

    /* Enter the server; when it blocks in IPC recv the full-context path runs
     * the client, whose FS requests wake the server. Does not return. */
    print("NEWLIB_SELFTEST: launching\n");
    selftest_resume_all();
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
    cap_install_from_root(waiter, CAPSLOT_NOTIFY, 14, NOTIF_FS_READY);  /* CAP_NOTIFICATION */

    int sender = fs_spawn_embedded(embedded_notifytest_bin_start,
                                   embedded_notifytest_bin_end, "notifysender");
    if (sender <= 0) { print("NOTIFY_SELFTEST: FAIL spawn-sender\n"); for (;;) asm volatile("hlt"); }
    tasks[sender].uid       = 0;
    tasks[sender].spawn_arg = 1;                    /* role 1 = sender */
    cap_install_from_root(sender, CAPSLOT_NOTIFY, 14, NOTIF_FS_READY);  /* CAP_NOTIFICATION */

    /* Enter the waiter; it blocks in SYS_WAIT_NOTIFY and the full-context path
     * runs the sender, whose SYS_NOTIFY wakes it with the badge. Does not return. */
    selftest_resume_all();
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

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(pid);   /* cowtest prints the PASS/FAIL marker; does not return */
}
#endif /* COW_SELFTEST */

#ifdef FPU_SELFTEST
/* ---- XMM register-file isolation (SECURITY.md S16, FPU_SELFTEST only) ------
 *
 * Two ring-3 tasks, both runnable, sharing one CPU. `fputest` loads a sentinel
 * into all sixteen xmm registers and requires it intact after 64 switches away
 * and back; `fpupeer` never writes an xmm register and requires that none of
 * them ever holds `fputest`'s sentinel.
 *
 * THE PEER IS HELD BACK AND RELEASED BY `fputest` ITSELF, once the sentinel is
 * in the registers and before the first yield. Nothing else orders the two, and
 * without that ordering the arm is a race: the peer samples a bounded number of
 * times and then reports success, so released together it can spend its whole
 * window while `fputest` is still filling its sentinel buffer -- reporting no
 * leak having never looked at a moment when there was one. Measured, before the
 * fix: the leak arm reproduced on 2 boots in 3, and the miss was exactly that.
 *
 * `selftest_resume_all` is a blunt instrument that wakes every spawned task, so
 * the peer is re-suspended after it, the same way `frame_selftest` does.
 *
 * The ONLY capability either task is endowed with is `fputest`'s CAP_TCB naming
 * the peer, which is what makes SYS_TASK_RESUME legal. S16 is about what a task
 * can read from the HARDWARE rather than about authority, so anything further
 * would obscure what is being shown. */
#define FPUTEST_SLOT_PEER_TCB 29   /* must match nothing in userspace: resume takes a tid */
void fpu_selftest(void) {
    extern uint8_t embedded_fputest_bin_start[], embedded_fputest_bin_end[];
    extern uint8_t embedded_fpupeer_bin_start[], embedded_fpupeer_bin_end[];
    print("FPU_SELFTEST: begin\n");

    int peer = fs_spawn_embedded(embedded_fpupeer_bin_start,
                                 embedded_fpupeer_bin_end, "fpupeer");
    if (peer <= 0) { print("FPUTEST: FAIL spawn-peer\n"); for (;;) asm volatile("hlt"); }
    tasks[peer].uid = 0;

    int pid = fs_spawn_embedded(embedded_fputest_bin_start,
                                embedded_fputest_bin_end, "fputest");
    if (pid <= 0) { print("FPUTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[pid].uid = 0;

    tasks[pid].spawn_arg = (uint32_t)peer;   /* how fputest names the task it releases */
    /* Root slot 0 is the CAP_TCB template (CAP_RIGHT_ALL); the object is
     * rewritten to the peer's task id, which is what makes it a capability for
     * THAT task rather than for task 0. Same construction frame_selftest uses. */
    {
        extern int cap_install_from_root(int p, uint32_t slot, uint32_t root_slot, uint32_t object);
        if (cap_install_from_root(pid, FPUTEST_SLOT_PEER_TCB, 0, (uint32_t)peer) != 0) {
            print("FPUTEST: FAIL endow-peer-tcb\n"); for (;;) asm volatile("hlt");
        }
    }

    selftest_resume_all();
    /* ...then hold the peer back again: it must not sample its registers before
     * fputest has loaded the sentinel, or a miss is indistinguishable from a
     * pass. fputest releases it explicitly. */
    tasks[peer].runnable_ctx = 0;

    sched_enable_preemption();
    sched_enter_user(pid);   /* both print their own marker; does not return */
}
#endif /* FPU_SELFTEST */

#ifdef FORK_SELFTEST
/* ---- fork self-test (roadmap 2.3, FORK_SELFTEST only) ----------------------
 *
 * Spawn userspace/forktest, which forks itself and asserts from ring 3 that the
 * child's memory is a COPY of the parent's rather than a share (S36), and that a
 * task holding a mapped CAP_FRAME is refused (S37). Every assertion is
 * userspace-side; see userspace/forktest.c for why the two isolation directions
 * are tested differently.
 *
 * It is endowed with exactly ONE capability beyond a spawn's: a CAP_UNTYPED, so
 * it can retype the frame the S37 check needs. That is authority to create an
 * object, not authority to fork -- fork answers to the slot-3 capability every
 * task is born with, the same one SYS_SPAWN answers to. Handing it the untyped
 * is what makes the refusal a measurement rather than a task that simply had no
 * frame to map. */
void fork_selftest(void) {
    extern uint8_t embedded_forktest_bin_start[], embedded_forktest_bin_end[];
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    print("FORK_SELFTEST: begin\n");

    int pid = fs_spawn_embedded(embedded_forktest_bin_start,
                                embedded_forktest_bin_end, "forktest");
    if (pid <= 0) { print("FORKTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    tasks[pid].uid = 0;

    cap_install_from_root(pid, CAPSLOT_UNTYPED, 17, UNTYPED_ROOT);
    /* CAP_DEBUG (root slot 18, READ-only) so the S41 checks can read the
     * derivation graph with SYS_CAP_ENUMERATE -- serial and badge in the child's
     * cspace, which is the structural statement of "the copy is derived".
     *
     * An observability capability rather than a second authority: it discloses
     * type/rights/serial/badge and deliberately not `object`, so it cannot be
     * used to reach anything. Reading the graph is how the invariant is checked
     * WITHOUT a rendezvous between parent and child -- and a forked child shares
     * nothing it could rendezvous through, which is the property under test. */
    cap_install_from_root(pid, CAPSLOT_DEBUG, 18, 0);

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(pid);   /* forktest prints the PASS/FAIL marker; does not return */
}
#endif /* FORK_SELFTEST */

#ifdef FORKEXEC_SELFTEST
/* ---- fork+exec self-test (roadmap 2.3, FORKEXEC_SELFTEST only) -------------
 *
 * Spawn userspace/forkexectest, which forks itself, lets the child replace its
 * image with userspace/forkexecee through SYS_EXEC_NAMED, and then asserts from
 * ring 3 that the exec replaced the IMAGE and not the AUTHORITY (S42) -- and
 * that the parent's memory survived the reclaim of the cloned address space the
 * exec performed (S39, one layer on from what fork_selftest can reach).
 *
 * Endowed exactly as fork_selftest endows forktest, and for the same two
 * reasons: a CAP_UNTYPED so there is a real delegated capability whose lineage
 * the exec can be measured against -- authority to create an object, not
 * authority to fork or exec, both of which answer to the slot-3 capability every
 * task is born with -- and a READ-only CAP_DEBUG so the driver can read serial
 * and badge out of the derivation graph with SYS_CAP_ENUMERATE.
 *
 * CAP_DEBUG is load-bearing twice here. It is how the invariant is checked
 * structurally, and it is also the only channel the three tasks have to
 * rendezvous through: a forked child shares no memory with its parent, and after
 * the exec it does not share a program either. See userspace/forkexectest.c. */
void forkexec_selftest(void) {
    extern uint8_t embedded_forkexectest_bin_start[], embedded_forkexectest_bin_end[];
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    print("FORKEXEC_SELFTEST: begin\n");

    int pid = fs_spawn_embedded(embedded_forkexectest_bin_start,
                                embedded_forkexectest_bin_end, "forkexectest");
    if (pid <= 0) { print("FORKEXECTEST: FAIL spawn\n"); for (;;) asm volatile("hlt"); }
    /* uid 0 for SYS_CAP_GRANT and SYS_KILL against the child, which the driver
     * uses to release it into the exec and to reap it afterwards. The authority
     * being exercised by the test is the CAP_UNTYPED below; this is the
     * supervisor relationship the driver needs to drive its own children, and it
     * is the same endowment forktest gets. */
    tasks[pid].uid = 0;

    cap_install_from_root(pid, CAPSLOT_UNTYPED, 17, UNTYPED_ROOT);
    cap_install_from_root(pid, CAPSLOT_DEBUG, 18, 0);

    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(pid);   /* forkexectest prints the PASS/FAIL marker; does not return */
}
#endif /* FORKEXEC_SELFTEST */



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

    /* Endow exactly the capabilities the C-1 conformance checks probe. The task
     * already holds its private reply endpoint (slot 4) from create_task.
     *
     *  slot 5  — a WRITE-ONLY endpoint capability, i.e. a CLIENT capability, the
     *            shape SYS_CONNECT_FS_SERVER mints. captest asserts it permits
     *            send and REFUSES recv / reply_to / sender: those refusals are
     *            the interception and reply-forgery halves of C-1.
     *  slot 11 — a CAP_NOTIFICATION, so the type-separation checks can prove an
     *            endpoint capability does not authorise notify/wait_notify and
     *            vice versa.
     *  slot 21 — a second, distinct READ|WRITE endpoint capability, so "holding
     *            a capability is not authority over it" (the revoke-rights
     *            checks) is tested against a real endpoint rather than the
     *            task's own reply endpoint.
     *  slot 18 — a CAP_UNTYPED over the user-facing region (roadmap 0.3), so the
     *            retype checks can exercise BOTH directions: that a held untyped
     *            actually creates usable objects, and that it refuses every
     *            malformed request. Without it the retype checks would only ever
     *            prove "a task with no authority is refused", which a kernel that
     *            refused everything would also pass. */
    extern int cap_install_from_root(int pid, uint32_t slot, uint32_t root_slot, uint32_t object);
    cap_install_from_root(pid, 5,  12, CON_EP_REQ);       /* client: WRITE only     */
    cap_install_from_root(pid, 11, 14, NOTIF_FS_READY);   /* CAP_NOTIFICATION       */
    cap_install_from_root(pid, 21, 11, CON_EP_REQ);       /* listen: READ|WRITE     */
    cap_install_from_root(pid, CAPSLOT_UNTYPED, 17, UNTYPED_ROOT);  /* CAP_UNTYPED  */

    print("CAPTEST_SELFTEST: launching\n");
    selftest_resume_all();
    sched_enable_preemption();
    sched_enter_user(pid);   /* captest prints the PASS/FAIL marker; does not return */
}
#endif /* CAPTEST_SELFTEST */

#ifdef TASKCEIL_SELFTEST
/* ---- The task ceiling is real, not merely compiled -------------------------
 *
 * MAX_TASKS moved from 64 to 256, and "it builds and boots" is not evidence for
 * that: a boot uses about six tasks, all of them below 64, so every defect this
 * change could plausibly introduce lives in the range no boot visits. Three
 * things had to scale, and each fails SILENTLY rather than loudly if it did not.
 *
 *  1. THE KERNEL STACKS. They left `.bss` for a region indexed by task id. A
 *     slot-index that truncated -- or a region that wrapped -- would give task
 *     t and task t-64 the SAME stack, and two tasks sharing one kernel stack is
 *     S20, the exact corruption the [G-8] work exists to prevent. Nothing about
 *     it is visible until both run at once.
 *
 *  2. THE INFLIGHT WITNESS. `g_kstack_inflight` was one `uint64_t` with bit t
 *     per task. At MAX_TASKS > 64, `1ULL << t` is undefined for t >= 64 and x86
 *     masks the shift to 6 bits, so task 64 aliases task 0. The detector then
 *     answers about the wrong task: no report for a real collision above 63, and
 *     a false report below it. THIS is the check that matters most, because a
 *     detector that has gone blind looks exactly like a system with no defects.
 *
 *  3. THE CSPACES. The kernel reserve is derived from MAX_TASKS now rather than
 *     carved out of a fixed total. A reserve that under-provided would halt in
 *     create_task -- loudly, but only for the task that ran out.
 *
 * Each check below is stated against the ALIAS PAIR (t, t-64), because that is
 * the pair every one of these defects makes identical.
 */
void taskceiling_selftest(void)
{
    extern uint64_t kstack_guard_vaddr(int id);
    extern int      kstack_inflight_task(int t);
    extern void     kstack_inflight_selftest_set(int t);
    extern void     kstack_inflight_selftest_clear(int t);
    extern uint32_t kstack_slots_mapped;
    extern void     create_user_pagedir(uint32_t task_id);
    /* Declared here rather than relying on WX_SELFTEST's file-scope defines and
     * ASPACE_SELFTEST's prototypes: this test is built on its own, and a helper
     * it borrowed from another flag's block would make the two flags a hidden
     * dependency that only shows up as an implicit-declaration error. */
    const uint64_t PRESENT = 1ULL;
    uint64_t kcr3;
    __asm__ volatile ("mov %%cr3, %0" : "=r"(kcr3));

    print("TASKCEIL_SELFTEST: begin\n");

    if (MAX_TASKS <= 64) {
        /* Not a pass. This test's entire content is about ids above 63; if the
         * ceiling is back at 64 there is nothing here to check and saying PASS
         * would be a green light for a property nothing examined. */
        print("TASKCEIL_SELFTEST: FAIL MAX_TASKS is not above 64, nothing to test\n");
        return;
    }

    /* Pick the pair as high as the table allows, so the test exercises the top
     * of the range rather than the first id past the old bound. */
    const int hi = MAX_TASKS - 1;
    const int lo = hi - 64;

    /* ---- 1. distinct, mapped kernel stacks ------------------------------- */
    uint64_t g_hi = kstack_guard_vaddr(hi);
    uint64_t g_lo = kstack_guard_vaddr(lo);
    if (g_hi == 0 || g_lo == 0 || g_hi == g_lo) {
        print("TASKCEIL_SELFTEST: FAIL alias pair shares a kernel stack slot\n");
        return;
    }

    uint32_t before = kstack_slots_mapped;
    create_user_pagedir((uint32_t)lo);
    create_user_pagedir((uint32_t)hi);
    if (kstack_slots_mapped != before + 2) {
        print("TASKCEIL_SELFTEST: FAIL binding two stacks mapped ");
        print_decimal((uint64_t)(kstack_slots_mapped - before));
        print(" slots\n");
        return;
    }
    if (tasks[hi].kernel_stack_top == 0 || tasks[lo].kernel_stack_top == 0 ||
        tasks[hi].kernel_stack_top == tasks[lo].kernel_stack_top) {
        print("TASKCEIL_SELFTEST: FAIL alias pair got the same kernel_stack_top\n");
        return;
    }
    /* Both stacks live, and both guards absent -- the guard being absent is what
     * makes an overflow fault rather than land in the neighbouring slot. */
    if (!(user_lookup_pte(kcr3, g_hi + PAGE_SIZE) & PRESENT) ||
        !(user_lookup_pte(kcr3, g_lo + PAGE_SIZE) & PRESENT)) {
        print("TASKCEIL_SELFTEST: FAIL a high-id kernel stack is not mapped\n");
        return;
    }
    if ((user_lookup_pte(kcr3, g_hi) & PRESENT) ||
        (user_lookup_pte(kcr3, g_lo) & PRESENT)) {
        print("TASKCEIL_SELFTEST: FAIL a high-id stack guard is mapped\n");
        return;
    }

    /* ---- 2. the inflight witness addresses the right task ---------------- */
    /* Both clear to start with: this runs before any task above 63 has ever been
     * switched to, so a set bit here would itself be the aliasing defect. */
    if (kstack_inflight_task(hi) || kstack_inflight_task(lo)) {
        print("TASKCEIL_SELFTEST: FAIL inflight bit set before anything ran\n");
        return;
    }
    kstack_inflight_selftest_set(hi);
    if (!kstack_inflight_task(hi)) {
        print("TASKCEIL_SELFTEST: FAIL inflight bit for a high task does not set\n");
        return;
    }
    /* THE ONE THAT WOULD HAVE CAUGHT THE OLD MASK. Under `1ULL << t` on one
     * word, setting the bit for task hi sets the bit for task hi-64, and the
     * [G-8] detector reports a collision for a task that is not running. */
    if (kstack_inflight_task(lo)) {
        print("TASKCEIL_SELFTEST: FAIL setting task ");
        print_decimal((uint64_t)hi);
        print(" also set task ");
        print_decimal((uint64_t)lo);
        print(" -- the witness aliases\n");
        return;
    }
    kstack_inflight_selftest_clear(hi);
    if (kstack_inflight_task(hi) || kstack_inflight_task(lo)) {
        print("TASKCEIL_SELFTEST: FAIL inflight bit did not clear\n");
        return;
    }

    /* ---- 3. cspaces exist and are distinct ------------------------------- */
    /* create_task allocates the cspace; it also marks the slot runnable, so the
     * state is put back afterwards -- this test must not leave two tasks the
     * scheduler will try to run with no image behind them. */
    create_task(hi, 0, 0, USER_AREA_BASE, 0);
    create_task(lo, 0, 0, USER_AREA_BASE, 0);
    tasks[hi].state = 0;
    tasks[lo].state = 0;
    if (!tasks[hi].cspace || !tasks[lo].cspace) {
        print("TASKCEIL_SELFTEST: FAIL a high task id got no cspace\n");
        return;
    }
    if (tasks[hi].cspace == tasks[lo].cspace) {
        print("TASKCEIL_SELFTEST: FAIL the alias pair shares one cspace\n");
        return;
    }

    print("TASKCEIL_SELFTEST: PASS tasks ");
    print_decimal((uint64_t)lo);
    print(" and ");
    print_decimal((uint64_t)hi);
    print(" have distinct stacks, cspaces and inflight bits (MAX_TASKS ");
    print_decimal((uint64_t)MAX_TASKS);
    print(")\n");
}
#endif

#ifdef CAPLOOKUP_SELFTEST
/* ---- cap_lookup fails closed (roadmap 0.3 / finding [I-7]) -----------------
 *
 * `cap_lookup` is the function every capability gate in this kernel resolves
 * through, and until 2026-08-30 it ended in an unconditional fallback:
 *
 *     if (cspace && slot < cspace_sz) { ...the caller's own cspace... }
 *     else                            { ...root_cnode...              }
 *
 * so a task with no cspace, or one asking past the end of its own, resolved
 * against the PRIMORDIAL root cnode -- CAP_TCB over task 0, the console, the
 * kernel log, the user database, the encrypted object store.
 *
 * THE POINT OF THIS TEST IS THAT NOTHING COULD REACH IT. `create_task` halts
 * rather than run a task whose cspace allocation failed, and it sets
 * `cspace_size = CNODE_SIZE` for every task, so neither branch was live. Both
 * facts are about `create_task`, in another file; neither is a property of
 * `cap_lookup`. A refusal test needs the ungated path to succeed or it witnesses
 * nothing, so this MANUFACTURES the condition -- a scratch task slot with its
 * cspace nulled, and a second with a deliberately short one -- and asks the
 * resolver directly.
 *
 * Falsified by CAP_LOOKUP_ROOT_FALLBACK=1, which restores the `else`: under it
 * both probes resolve a live primordial capability and this test FAILS naming
 * which one. Without that arm, "the lookup returned NULL" is equally consistent
 * with a slot that was simply empty.
 */
void caplookup_selftest(void)
{
    print("CAPLOOKUP_SELFTEST: begin\n");

    /* Slot 8 is CAP_CONSOLE in the root cnode -- a live primordial capability,
     * which is what makes a successful lookup here an escalation rather than a
     * lookup of nothing. Asserted rather than assumed: if the root cnode ever
     * stops holding one here, every check below would pass for the wrong
     * reason. */
    const uint32_t PRIMORDIAL_SLOT = CAPSLOT_CONSOLE;
    const capability_t *root = cap_root_cnode_ref();
    if (!root || root[PRIMORDIAL_SLOT].type == CAP_NULL) {
        print("CAPLOOKUP_SELFTEST: FAIL root cnode holds nothing at the probe slot\n");
        return;
    }

    /* A scratch slot at the top of the table: high enough that nothing the boot
     * has spawned occupies it, and never made runnable. */
    const int scratch = MAX_TASKS - 2;
    int saved_cur = get_current_task();
    struct capability *saved_cspace = tasks[scratch].cspace;
    uint32_t saved_size = tasks[scratch].cspace_size;
    /* uint32_t, matching tcb.state. It was uint8_t in the first draft, which
     * restores a TRUNCATED value -- harmless only while every state fits in a
     * byte, which is a fact about the enum rather than about this code. */
    uint32_t saved_state = tasks[scratch].state;

    /* ---- 1. no cspace at all -------------------------------------------- */
    tasks[scratch].cspace      = (struct capability *)0;
    tasks[scratch].cspace_size = 0;
    tasks[scratch].state       = 0;          /* never schedulable */
    set_current_task(scratch);
    struct capability *c1 = cap_lookup(PRIMORDIAL_SLOT, 0);
    set_current_task(saved_cur);

    if (c1 != (struct capability *)0) {
        tasks[scratch].cspace = saved_cspace;
        tasks[scratch].cspace_size = saved_size;
        tasks[scratch].state = saved_state;
        print("CAPLOOKUP_SELFTEST: FAIL cspace-less task resolved a primordial capability\n");
        return;
    }

    /* ---- 2. past the end of its own cspace ------------------------------- */
    /* The half nobody had written down. A cspace SHORTER than CNODE_SIZE and a
     * slot beyond it took the same `else`, so the caller was handed
     * root_cnode[slot] -- the identical escalation reached by arithmetic rather
     * than by a null pointer, and needing no missing cspace at all. */
    static struct capability tiny[CNODE_SIZE];
    for (int i = 0; i < CNODE_SIZE; i++) {
        tiny[i].type = CAP_NULL; tiny[i].rights = 0; tiny[i].object = 0;
        tiny[i].badge = 0; tiny[i].serial = 0; tiny[i].generation = 0;
    }
    tasks[scratch].cspace      = tiny;
    tasks[scratch].cspace_size = PRIMORDIAL_SLOT;   /* the probe slot is PAST the end */
    set_current_task(scratch);
    struct capability *c2 = cap_lookup(PRIMORDIAL_SLOT, 0);
    set_current_task(saved_cur);

    tasks[scratch].cspace      = saved_cspace;
    tasks[scratch].cspace_size = saved_size;
    tasks[scratch].state       = saved_state;

    if (c2 != (struct capability *)0) {
        print("CAPLOOKUP_SELFTEST: FAIL a slot past the caller's cspace resolved in the root cnode\n");
        return;
    }

    /* ---- 3. and the resolver still WORKS -------------------------------- */
    /* Both refusals above are satisfied by a cap_lookup that returns NULL for
     * everything, which would break every gate in the kernel while passing this
     * test. Task 0 holds no cspace of its own and legitimately resolves against
     * the root cnode -- the rule caller_has_authority() already encodes for the
     * mutating operations -- so asking as task 0 must SUCCEED. */
    set_current_task(0);
    struct capability *c3 = cap_lookup(PRIMORDIAL_SLOT, 0);
    set_current_task(saved_cur);
    if (c3 == (struct capability *)0) {
        print("CAPLOOKUP_SELFTEST: FAIL task 0 can no longer reach the root cnode\n");
        return;
    }

    print("CAPLOOKUP_SELFTEST: PASS a cspace-less task and an out-of-range slot are both refused, and task 0 still resolves\n");
}
#endif

#ifdef CSPACE_RELEASE_SELFTEST
/* ---- a dead task's capabilities stop existing (roadmap 0.3, [I-7]) --------
 *
 * `task_teardown` releases every device resource a task held -- its IRQ route,
 * its MSI route, its IOMMU domain, its port grant, the console, its pipe ends --
 * and then swept the retyped objects it was the last namer of. It did not touch
 * the cspace. The capabilities stayed in memory from the task's death until its
 * SLOT WAS NEXT USED, which may be never.
 *
 * Nothing could reach them, and that is the part worth testing rather than
 * trusting: three separate readers each avoided a dead cspace by testing
 * `state == 0` -- `mark_reachable` when deciding which objects are still named,
 * `h_cap_enumerate` when reporting, `create_task` when overwriting. The property
 * was held by three readers agreeing about a flag, not by the data. This asserts
 * it of the DATA.
 *
 * It goes through task_teardown rather than calling cap_release_cspace, because
 * the claim is about the teardown path: a witness that calls the function under
 * test proves the function works and says nothing about whether anything invokes
 * it. Falsified by CSPACE_KEEP_ON_TEARDOWN=1, which restores the pre-fix
 * behaviour and leaves the capabilities in place.
 */
void cspace_release_selftest(void)
{
    print("CSPACE_RELEASE_SELFTEST: begin\n");

    /* A scratch slot near the top of the table: never spawned into by the boot,
     * and given a cspace of its own by create_task. */
    const int scratch = MAX_TASKS - 3;
    create_task(scratch, 0, 0, USER_AREA_BASE, 0);
    if (!tasks[scratch].cspace) {
        print("CSPACE_RELEASE_SELFTEST: FAIL scratch task got no cspace\n");
        return;
    }

    /* Install real authority: the primordial CAP_CONSOLE, copied from the root
     * cnode exactly as init's delegation does. A CAP_NULL would be indetectable
     * from a released one, so the probe has to plant something that MATTERS --
     * this is the capability that owns the serial port and the framebuffer. */
    const uint32_t PROBE_SLOT = CAPSLOT_CONSOLE;
    cap_install_from_root(scratch, PROBE_SLOT, PROBE_SLOT, 0);
    if (tasks[scratch].cspace[PROBE_SLOT].type == CAP_NULL) {
        print("CSPACE_RELEASE_SELFTEST: FAIL could not plant a capability to release\n");
        return;
    }
    uint32_t planted_type = tasks[scratch].cspace[PROBE_SLOT].type;

    /* Tear it down exactly as a fault or SYS_EXIT would. state goes to 0 inside
     * teardown; the cspace pointer is deliberately kept, because the BYTES belong
     * to this slot for the life of the boot -- the arena never rewinds. */
    struct task_exit_cause cause;
    for (size_t z = 0; z < sizeof(cause); z++) ((uint8_t *)&cause)[z] = 0;
    cause.reason = TASK_EXIT_NONE;
    task_teardown(scratch, &cause);

    if (!tasks[scratch].cspace) {
        /* Returning the bytes is the one thing this must NOT do: the arena is a
         * monotonic bump allocator and the kernel reserve holds exactly
         * MAX_TASKS cspaces, so a free-then-reallocate exhausts it on the first
         * slot reuse and create_task halts the machine. */
        print("CSPACE_RELEASE_SELFTEST: FAIL teardown dropped the cspace pointer\n");
        return;
    }

    /* THE CHECK. Every slot empty, not merely the one that was planted: a
     * release that cleared the probe's slot alone would pass a narrower test
     * while leaving every other capability the task held. */
    for (uint32_t s = 0; s < CNODE_SIZE; s++) {
        struct capability *c = &tasks[scratch].cspace[s];
        if (c->type != CAP_NULL || c->serial != 0 || c->rights != 0 ||
            c->object != 0 || c->badge != 0 || c->generation != 0) {
            print("CSPACE_RELEASE_SELFTEST: FAIL a dead task still holds capability slot ");
            print_decimal((uint64_t)s);
            print(" (type ");
            print_decimal((uint64_t)c->type);
            print(")\n");
            return;
        }
    }
    if (tasks[scratch].caps_in_use != 0) {
        print("CSPACE_RELEASE_SELFTEST: FAIL caps_in_use is ");
        print_decimal((uint64_t)tasks[scratch].caps_in_use);
        print(" for a task holding nothing\n");
        return;
    }

    /* And the slot still WORKS. Both checks above are satisfied by a teardown
     * that destroyed the cspace outright, or by a create_task that can no longer
     * install anything -- either of which breaks task creation while passing.
     * Re-create into the same slot and require the same capability to install. */
    create_task(scratch, 0, 0, USER_AREA_BASE, 0);
    cap_install_from_root(scratch, PROBE_SLOT, PROBE_SLOT, 0);
    if (tasks[scratch].cspace[PROBE_SLOT].type != planted_type) {
        print("CSPACE_RELEASE_SELFTEST: FAIL the slot cannot be used again after teardown\n");
        return;
    }
    tasks[scratch].state = 0;

    print("CSPACE_RELEASE_SELFTEST: PASS a dead task holds no capability, its cspace bytes stay with the slot, and the slot is reusable\n");
}
#endif
