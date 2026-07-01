.code64
.section .text

.global idt_load64
idt_load64:
    lidt (%rdi)
    ret

.global isr_common_stub64
isr_common_stub64:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq %rsp, %rdi
    call interrupt_handler64
    /* interrupt_handler64 returns (in %rax) the kernel %rsp to resume on: the
     * same frame pointer for the common no-switch case, or a preempted/fresh
     * task's saved_ksp when the timer decided to switch tasks. Loading it here
     * makes the epilogue below pop *that* task's registers and iretq into it. */
    movq %rax, %rsp

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax

    
    addq $16, %rsp
    iretq

.macro ISR_NOERRCODE64 num
.global isr\num
isr\num:
    pushq $0
    pushq $\num
    jmp isr_common_stub64
.endm

.macro ISR_ERRCODE64 num
.global isr\num
isr\num:
    pushq $\num
    jmp isr_common_stub64
.endm

ISR_NOERRCODE64 0
ISR_NOERRCODE64 1
ISR_NOERRCODE64 2
ISR_NOERRCODE64 3
ISR_NOERRCODE64 4
ISR_NOERRCODE64 5
ISR_NOERRCODE64 6
ISR_NOERRCODE64 7
ISR_ERRCODE64   8
ISR_NOERRCODE64 9
ISR_ERRCODE64  10
ISR_ERRCODE64  11
ISR_ERRCODE64  12
ISR_ERRCODE64  13
ISR_ERRCODE64  14
ISR_NOERRCODE64 15
ISR_NOERRCODE64 16
ISR_ERRCODE64  17
ISR_NOERRCODE64 18
ISR_NOERRCODE64 19
ISR_NOERRCODE64 20
ISR_ERRCODE64  21
ISR_NOERRCODE64 22
ISR_NOERRCODE64 23
ISR_NOERRCODE64 24
ISR_NOERRCODE64 25
ISR_NOERRCODE64 26
ISR_NOERRCODE64 27
ISR_NOERRCODE64 28
ISR_NOERRCODE64 29
ISR_ERRCODE64  30
ISR_NOERRCODE64 31

ISR_NOERRCODE64 32
ISR_NOERRCODE64 33

.global isr128
isr128:
    pushq $0
    pushq $0x80
    jmp isr_common_stub64

.global gdt_flush
gdt_flush:
    lgdt (%rdi)
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss
    pushq $0x08
    pushq $.flush2
    lretq
.flush2:
    ret

.global tss_flush
tss_flush:
    movw $0x28, %ax
    ltr %ax
    ret

.global idt_load
idt_load:
    lidt (%rdi)
    ret

.global isr34
.global isr35
.global isr36
.global isr37
.global isr38
.global isr39
.global isr40
.global isr41
.global isr42
.global isr43
.global isr44
.global isr45
.global isr46
.global isr47

isr34: pushq $0; pushq $34; jmp isr_common_stub64
isr35: pushq $0; pushq $35; jmp isr_common_stub64
isr36: pushq $0; pushq $36; jmp isr_common_stub64
isr37: pushq $0; pushq $37; jmp isr_common_stub64
isr38: pushq $0; pushq $38; jmp isr_common_stub64
isr39: pushq $0; pushq $39; jmp isr_common_stub64
isr40: pushq $0; pushq $40; jmp isr_common_stub64
isr41: pushq $0; pushq $41; jmp isr_common_stub64
isr42: pushq $0; pushq $42; jmp isr_common_stub64
isr43: pushq $0; pushq $43; jmp isr_common_stub64
isr44: pushq $0; pushq $44; jmp isr_common_stub64
isr45: pushq $0; pushq $45; jmp isr_common_stub64
isr46: pushq $0; pushq $46; jmp isr_common_stub64
isr47: pushq $0; pushq $47; jmp isr_common_stub64

.extern early_handler_stack_top

.global early_page_fault64
early_page_fault64:
    movabs $early_handler_stack_top, %rsp

    movq %cr2, %rax

    movw $0x3f8, %dx
    movq $16, %rcx

print_hex_loop:
    rolq $4, %rax
    movq %rax, %rbx
    andq $0xF, %rbx
    cmpq $10, %rbx
    jl   digit
    addq $'A'-10, %rbx
    jmp  out
digit:
    addq $'0', %rbx
out:
    movb %bl, %al
    outb %al, %dx
    loop print_hex_loop

    movb $'\r', %al
    outb %al, %dx
    movb $'\n', %al
    outb %al, %dx

    cli
    hlt
    jmp .

.global early_exception64
early_exception64:
    cli
    hlt
    jmp .

.global syscall_entry
syscall_entry:
    swapgs

    movq %rsp, %r14
    movq %rcx, %r15

    
    movabs $current_kernel_stack_top, %rax
    movq (%rax), %rsp
    testq %rsp, %rsp
    jnz 1f
    movabs $syscall_entry_kstack_top, %rsp   
1:
    subq $128, %rsp   

    call syscall_handler64

    movq %r14, %rsp
    movq %r15, %rcx

    sysretq

.section .bss
.align 16
syscall_entry_kstack_bottom:
    .space 4096
syscall_entry_kstack_top: