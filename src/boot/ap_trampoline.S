/* src/boot/ap_trampoline.S — Application-Processor startup trampoline.
 *
 * A SIPI starts each AP in 16-bit real mode at CS:IP = (vector<<8):0, i.e. at
 * physical 0x8000 for vector 0x08.  This code walks the AP up through the same
 * three CPU modes the BSP boot code does — real -> protected -> long — and then
 * hands control to the 64-bit C entry point ap_entry64().
 *
 * It is assembled and linked at its load address (0x8000) and copied there by
 * the BSP (smp_start_aps).  Because it is linked at 0x8000, absolute data
 * references resolve correctly once the data segments are flat/zero-based, and
 * the far-jump targets (which are linear addresses under the flat GDT below)
 * are the linker-provided absolute addresses.  The only rule the 16-bit stage
 * must obey is: no absolute near jumps before the far jump — only short
 * PC-relative branches — since real-mode IP is offset-from-CS-base (0), not the
 * absolute link address.
 *
 * The BSP fills three qword cells in low memory before sending the SIPI:
 *   AP_STACK_BASE_CELL = base of the per-CPU idle kernel-stack array
 *   AP_CR3_CELL        = kernel CR3 (identity-maps low memory + the LAPIC)
 *   AP_ENTRY_CELL      = &ap_entry64
 * Every AP runs this code concurrently after a broadcast SIPI, so each indexes
 * its own idle stack by LAPIC id — the stacks never collide.
 *
 * These constants MUST match the AP_* defines in src/kernel/scheduler.c.
 */

#define AP_STACK_BASE_CELL 0x8FD8
#define AP_CR3_CELL        0x8FE0
#define AP_ENTRY_CELL      0x8FE8
#define AP_IDLE_STACK_SIZE 0x4000
#define LAPIC_BASE         0xFEE00000
#define LAPIC_ID_REG       0x20
#define COM1               0x3F8

.section .text
.code16
.global ap_trampoline_start
ap_trampoline_start:
    cli
    cld
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    /* Progress marker: '1' == reached 16-bit real mode. */
    movw $COM1, %dx
    movb $'1', %al
    outb %al, %dx

    /* Flat GDT for the mode transitions (32-bit + 64-bit code/data). */
    lgdtl ap_gdtr

    /* Enter protected mode. */
    movl %cr0, %eax
    orl  $1, %eax
    movl %eax, %cr0

    /* Reload CS into the 32-bit code segment.  The offset is the absolute
     * linear address of prot_mode (flat base 0), supplied by the linker. */
    ljmpl $0x08, $prot_mode

.code32
prot_mode:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    movw $COM1, %dx
    movb $'2', %al
    outb %al, %dx

    /* Enable PAE (CR4.PAE). */
    movl %cr4, %eax
    orl  $(1 << 5), %eax
    movl %eax, %cr4

    /* Load the kernel CR3 the BSP published. */
    movl $AP_CR3_CELL, %edi
    movl (%edi), %eax
    movl %eax, %cr3

    /* EFER.LME | EFER.NXE. */
    movl $0xC0000080, %ecx
    rdmsr
    orl  $((1 << 8) | (1 << 11)), %eax
    wrmsr

    /* Enable paging -> activates long mode. */
    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    /* Reload CS into the 64-bit code segment. */
    ljmpl $0x18, $long_mode

.code64
long_mode:
    movw $0x20, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    /* Enable SSE, matching the BSP (long_mode_entry): the kernel is compiled
     * with SSE codegen, so an AP that skips this #UDs on the first xmm op. */
    movq %cr0, %rax
    andq $~(1 << 2), %rax             /* clear CR0.EM */
    orq  $(1 << 1), %rax              /* set CR0.MP  */
    movq %rax, %cr0
    movq %cr4, %rax
    orq  $((1 << 9) | (1 << 10)), %rax  /* CR4.OSFXSR | CR4.OSXMMEXCPT */
    movq %rax, %cr4
    fninit

    movw $COM1, %dx
    movb $'3', %al
    outb %al, %dx

    /* This AP's idle stack = base + (apic_id + 1) * AP_IDLE_STACK_SIZE, i.e. the
     * exclusive top of slot[apic_id].  APs have apic_id >= 1, so slots never
     * overlap the BSP's and never collide with each other. */
    movl $LAPIC_BASE, %ebx
    movl LAPIC_ID_REG(%rbx), %eax
    shrl $24, %eax
    andl $0xFF, %eax
    incl %eax                        /* (apic_id + 1) */
    movl $AP_IDLE_STACK_SIZE, %ecx
    imulq %rcx, %rax                 /* (apic_id + 1) * size */
    movl $AP_STACK_BASE_CELL, %edi
    movq (%rdi), %rdx                /* idle-stack array base */
    addq %rdx, %rax                  /* stack top for this AP */
    movq %rax, %rsp

    /* Into 64-bit C.  ap_entry64 never returns. */
    movl $AP_ENTRY_CELL, %edi
    movq (%rdi), %rax
    jmp  *%rax

.align 16
ap_gdt:
    .quad 0x0000000000000000        /* 0x00: null */
    .quad 0x00CF9A000000FFFF        /* 0x08: 32-bit code, base 0, limit 4G */
    .quad 0x00CF92000000FFFF        /* 0x10: 32-bit data, base 0, limit 4G */
    .quad 0x00209A0000000000        /* 0x18: 64-bit code (L=1) */
    .quad 0x0000920000000000        /* 0x20: 64-bit data */
ap_gdt_end:

ap_gdtr:
    .word ap_gdt_end - ap_gdt - 1
    .long ap_gdt

.global ap_trampoline_end
ap_trampoline_end:
