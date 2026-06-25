


#include "kernel.h"

extern uint32_t kernel_page_directory[];
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
    int t = get_current_task();
    if (t > 0 && t < MAX_TASKS) tasks[t].state = 0;
    schedule();
    for(;;) { asm volatile("cli; hlt"); }
#endif
}

void kernel_main(uint32_t mb_info) {
    (void)mb_info;

#if defined(__x86_64__)
    asm volatile(
        "xor %%rax,%%rax\n mov %%rax,%%dr0\n mov %%rax,%%dr1\n mov %%rax,%%dr2\n"
        "mov %%rax,%%dr3\n mov %%rax,%%dr6\n mov %%rax,%%dr7\n"
        "pushfq\n andq $~0x100,(%%rsp)\n popfq\n" ::: "rax","memory");
#else
    asm volatile(
        "xor %%eax,%%eax\n mov %%eax,%%dr0\n mov %%eax,%%dr1\n mov %%eax,%%dr2\n"
        "mov %%eax,%%dr3\n mov %%eax,%%dr6\n mov %%eax,%%dr7\n"
        "pushf\n andl $~0x100,(%%esp)\n popf\n" ::: "eax","memory");
#endif

    terminal_init();

#if defined(__x86_64__)
    idt_init64();
    pic_init();
    paging_init();
    cap_init();
    cpu_detect_features();
    entropy_init();
    init_syscall_instruction_path();
#ifndef MINIMAL_SECURE
    ramfs_init();
    ata_init();
#endif
    scheduler_init();
    smp_bringup();
    __asm__ volatile ("sti" ::: "memory");
    aslr_init_seed();
    set_current_task(0);
#ifdef DEBUG_SHELL
    shell_prompt_loop();
#else
    spawn_initial_userspace_shell();
    set_current_task(0);
    for(;;) schedule();
#endif
#else
    gdt_init();
    idt_init();
    paging_init();
    cap_init();
    cpu_detect_features();
    entropy_init();
#ifndef MINIMAL_SECURE
    ramfs_init();
    ata_init();
#endif
    scheduler_init();
    aslr_init_seed();
    __asm__ volatile("sti");
    set_current_task(0);
    for(;;) schedule();
#endif
}
