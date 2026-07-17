


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

void kernel_main(uint32_t mb_info) {
    (void)mb_info;

    asm volatile(
        "xor %%rax,%%rax\n mov %%rax,%%dr0\n mov %%rax,%%dr1\n mov %%rax,%%dr2\n"
        "mov %%rax,%%dr3\n mov %%rax,%%dr6\n mov %%rax,%%dr7\n"
        "pushfq\n andq $~0x100,(%%rsp)\n popfq\n" ::: "rax","memory");

    terminal_init();
    assert_higher_half();

    idt_init64();
    pic_init();
    paging_init();
    fpu_init_template();   /* the x87/SSE image every new task starts from */
    cap_init();
    cpu_detect_features();
    cpu_enable_protections();
#ifdef CPU_SELFTEST
    cpu_protections_selftest();   /* boot continues; make smoke-cpu asserts on it */
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
