


#include "kernel.h"

/* Absolute symbol from linker64.ld; its ADDRESS is the linker's KERNEL_VMA. */
extern char __kernel_vma_from_linker[];
extern tcb_t tasks[MAX_TASKS];
extern int current_task;
extern void set_tss_kernel_stack(uintptr_t);
extern uint8_t gdt64_start[];
extern uint8_t tss64[];

#ifdef DEBUG_SHELL
void __attribute__((noreturn)) shell_prompt_loop(void) {
    print("> ");
    while (1) {
        char cmd[128];
        int len = 0;

        while (len < 127) {
            char ch = console_getc();

            if (ch == '\r' || ch == '\n') {
                print("\n");
                break;
            }
            if (ch == '\b' || ch == 0x7F) {
                if (len > 0) { len--; print("\b \b"); }
                continue;
            }
            if (ch < 32 || ch > 126) continue;

            print_char(ch);
            cmd[len++] = ch;
        }
        cmd[len] = 0;

        if (cmd[0] != 0) {
            process_user_command(cmd);
        }
        print("> ");
    }
}
#endif

void __attribute__((noreturn)) resume_shell_after_fault(void) {
#ifdef DEBUG_SHELL
    set_current_task(0);  
    set_tss_kernel_stack(tasks[0].kernel_stack_top);
    shell_prompt_loop();
#else
    /* Task teardown (and waiter wake) already happened on the fault path.
     * Park this CPU; there is no cooperative schedule() path any more. */
    kernel_idle();
#endif
}

/* Prove the higher-half relocation actually took, before anything depends on it.
 *
 * Three ways it can be silently wrong, all of which produce a working-looking
 * kernel that corrupts memory later rather than failing here:
 *   - linker64.ld's KERNEL_VMA and kernel_vma.h's disagree (the linker script
 *     cannot include the header, so the two are duplicated);
 *   - the kernel is somehow still executing through the low identity map;
 *   - virt_to_phys does not invert phys_to_virt, so a VA->PA conversion feeding
 *     CR3 or a page-table entry is off.
 * Checked at the top of boot, on the serial console, in the smoke-test idiom. */
static void assert_higher_half(void) {
    uint64_t vma_c  = (uint64_t)KERNEL_VMA;
    uint64_t vma_ld = (uint64_t)(uintptr_t)&__kernel_vma_from_linker;
    uint64_t here   = (uint64_t)(uintptr_t)&assert_higher_half;

    if (vma_ld != vma_c) {
        print("HIGHHALF: FAIL linker KERNEL_VMA="); print_hex64(vma_ld);
        print(" != kernel_vma.h ");                 print_hex64(vma_c);
        print("\n");
        for (;;) asm volatile("cli; hlt");
    }
    if (here < vma_c) {
        print("HIGHHALF: FAIL executing below KERNEL_VMA at ");
        print_hex64(here); print("\n");
        for (;;) asm volatile("cli; hlt");
    }
    if (virt_to_phys(phys_to_virt(0x1234)) != 0x1234) {
        print("HIGHHALF: FAIL virt_to_phys/phys_to_virt do not round-trip\n");
        for (;;) asm volatile("cli; hlt");
    }
    print("HIGHHALF: PASS kernel at "); print_hex64(here);
    print(" phys ");                    print_hex64(virt_to_phys(here));
    print("\n");
}

/* ---- Multiboot2 memory map -> physical pool size --------------------------
 * GRUB passes the multiboot2 magic in eax and a pointer to the boot-information
 * structure in ebx; _start saves both (saved_mb_magic / saved_mb_info). Walk the
 * structure's tags for the memory-map tag (type 6), find the largest available
 * (type 1) region that covers USER_PHYS_BASE, and return how many PAGE_SIZE
 * frames the pool can take from [USER_PHYS_BASE, region_top), clamped to the
 * PHYS_KVA window. Returns 0 if the map cannot be trusted (not multiboot2, no
 * pointer, no usable region), so the caller keeps the conservative default
 * rather than assuming RAM that may not exist. The info block is low physical
 * RAM, read through PHYS_KVA — valid from boot, before paging_init runs. */
#define MB2_BOOT_MAGIC     0x36d76289u
#define MB2_TAG_END        0u
#define MB2_TAG_MMAP       6u
#define MB2_MEM_AVAILABLE  1u

struct mb2_tag        { uint32_t type; uint32_t size; };
struct mb2_mmap_entry { uint64_t base; uint64_t len; uint32_t type; uint32_t reserved; };

static uint32_t e820_detect_pool_pages(void) {
    if (saved_mb_magic != MB2_BOOT_MAGIC || saved_mb_info == 0) return 0;

    const uint8_t *info = (const uint8_t *)PHYS_KVA((uint64_t)saved_mb_info);
    uint32_t total = *(const uint32_t *)info;
    if (total < 8 || total > (1u << 20)) return 0;   /* sanity: <= 1 MiB of tags */

    uint64_t region_top = 0;
    uint32_t off = 8;   /* skip total_size + reserved */
    while ((uint64_t)off + sizeof(struct mb2_tag) <= total) {
        const struct mb2_tag *tag = (const struct mb2_tag *)(info + off);
        if (tag->type == MB2_TAG_END) break;
        if (tag->size < sizeof(struct mb2_tag) || (uint64_t)off + tag->size > total) break;

        if (tag->type == MB2_TAG_MMAP) {
            uint32_t entry_size = *(const uint32_t *)(info + off + 8);
            if (entry_size >= sizeof(struct mb2_mmap_entry)) {
                for (uint32_t e = off + 16; (uint64_t)e + entry_size <= (uint64_t)off + tag->size;
                     e += entry_size) {
                    const struct mb2_mmap_entry *m = (const struct mb2_mmap_entry *)(info + e);
                    if (m->type != MB2_MEM_AVAILABLE) continue;
                    uint64_t end = m->base + m->len;
                    /* The region spanning USER_PHYS_BASE (16 MiB) is where the pool lives. */
                    if (m->base <= (uint64_t)USER_PHYS_BASE && end > (uint64_t)USER_PHYS_BASE
                        && end > region_top)
                        region_top = end;
                }
            }
        }
        off += (tag->size + 7u) & ~7u;   /* tags are 8-byte aligned */
    }

    if (region_top <= (uint64_t)USER_PHYS_BASE) return 0;
    if (region_top > PHYS_POOL_CEIL) region_top = PHYS_POOL_CEIL;   /* PHYS_KVA window */
    return (uint32_t)((region_top - (uint64_t)USER_PHYS_BASE) / PAGE_SIZE);
}

void kernel_main(uint32_t mb_info) {
    (void)mb_info;   /* the pointer is taken from saved_mb_info (see _start) */

    asm volatile(
        "xor %%rax,%%rax\n mov %%rax,%%dr0\n mov %%rax,%%dr1\n mov %%rax,%%dr2\n"
        "mov %%rax,%%dr3\n mov %%rax,%%dr6\n mov %%rax,%%dr7\n"
        "pushfq\n andq $~0x100,(%%rsp)\n popfq\n" ::: "rax","memory");

    terminal_init();
    assert_higher_half();

    idt_init64();
    pic_init();

    /* Size the physical page pool from the E820 memory map before paging_init
     * builds its free list. On a boot we cannot parse, keep the conservative
     * 64 MiB default (unchanged behaviour) rather than assume RAM. */
    uint32_t e820_pages = e820_detect_pool_pages();
    if (e820_pages) phys_set_pool_pages(e820_pages);
    {
        uint32_t used = e820_pages ? e820_pages : USER_PHYS_DEFAULT_PAGES;
        print("[mem] physical pool: ");
        print_decimal(used / 256);        /* frames * 4 KiB / 1 MiB */
        print(" MiB (");
        print_decimal(used);
        print(e820_pages ? " frames, from E820)\n" : " frames, default: no E820)\n");
    }

    paging_init();
#ifdef E820_SELFTEST
    /* Boot continues; make smoke-e820 asserts on the marker. Proves the pool
     * grew past the pre-E820 default from the parsed memory map. */
    e820_selftest();
#endif
    fpu_init_template();   /* the x87/SSE image every new task starts from */
    cap_init();
    cpu_detect_features();
    cpu_enable_protections();
#ifdef CPU_SELFTEST
    cpu_protections_selftest();   /* boot continues; make smoke-cpu asserts on it */
#endif
#ifdef WX_SELFTEST
    /* After paging_init (which installs the W^X tables) and after
     * cpu_enable_protections, so CR0.WP is set and the bits it inspects are the
     * ones actually in force. Boot continues; make smoke-wx asserts on it. */
    wx_selftest();
#endif   /* SMEP/SMAP — must follow feature detection */
    entropy_init();
    /* Must follow entropy_init (needs the CSPRNG) and must run from a frame
     * that never returns — kernel_main is both. See stack_protector_init. */
    stack_protector_init();
    init_syscall_instruction_path();
#ifndef MINIMAL_SECURE
    ramfs_init();   /* -> storage_init(): probes for an ATA disk (persistent) and
                     * falls back to the ephemeral RAM vdisk when none is present */
#endif
    scheduler_init();
#ifdef ASPACE_SELFTEST
    /* After scheduler_init: it zeroes tasks[], which would wipe the cr3 the test
     * installs. Boot continues; make smoke-aspace asserts on the marker. */
    aspace_selftest();
#endif
    smp_bringup();
    __asm__ volatile ("sti" ::: "memory");
    aslr_init_seed();
    set_current_task(0);
    /* Note: the 64-bit boot reaches userspace via smp_bringup() above, which
     * spawns the shell and never returns; the ELF_SELFTEST hook lives there.
     * This branch is the fallback path. */
#ifdef DEBUG_SHELL
    shell_prompt_loop();
#else
    /* Normal boot never reaches here: smp_bringup() already dropped into
     * ring 3 via sched_enter_user. This is only the fallback if that path
     * returned (e.g. embed missing). Idle — do not cooperative-schedule. */
    spawn_initial_userspace_init();
    kernel_idle();
#endif
}
