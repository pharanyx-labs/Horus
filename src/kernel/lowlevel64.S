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

    /* First instruction at which this CPU is provably no longer reading the
     * OUTGOING task's kernel stack -- so it is the only correct place to finish
     * handing that task to another CPU. Everything above this line, including the
     * dispatcher's own epilogue and its stack-protector check, still reads words
     * from the stack the switch decided to give up; a CPU that took the task
     * earlier resumed it to ring 3 and its next trap rewrote those words at the
     * same depth. That is finding G-8, and sched_release_deferred() is where the
     * claim is actually dropped now (scheduler.c).
     *
     * Safe to call here: interrupts are off (every gate is an interrupt gate, so
     * no re-entry), %rsp already names the INCOMING task's stack so the callee's
     * frame lands in the same unused region the ISR's own C frames occupied on
     * entry, and every register below is about to be reloaded by the pops -- so
     * there is nothing live for the SysV call clobbers to destroy.
     *
     * Unconditional, including on SMP=0 where scheduler.c compiles it to an empty
     * body: the ISR epilogue is the last code in this kernel that should have two
     * versions. */
#ifndef CLAIM_RELEASE_SKIP
    call sched_release_deferred
#else
    /* CONTROL ARM -- never ship. Skips the deferred release on the ISR epilogue,
     * so every CPU that switches tasks reaches ring 3 still owing one. This is
     * what makes the "a CPU in ring 3 owes no deferred release" invariant in
     * preempt_on_tick a falsifiable check rather than an assertion nobody has
     * seen fire: under this flag it must panic, and without it must stay silent
     * through a boot to ring 3. */
#endif

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

/* Adopt the shared kernel GDT on an application processor and reload the
 * segment registers to the kernel selectors (CS=0x08, data=0x10).  Called from
 * ap_entry64() after the trampoline hands over on the AP's own stack. No LTR
 * here: the single kernel TSS descriptor is the BSP's, so APs load a per-CPU TSS
 * separately once they take interrupts. */
.extern gdt64_ptr
.global ap_load_kernel_segments
ap_load_kernel_segments:
    lgdt (gdt64_ptr)
    pushq $0x08
    leaq 1f(%rip), %rax
    pushq %rax
    lretq
1:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs
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

/* LAPIC timer (vector 0x40): per-CPU preemption tick on the application
 * processors, where the legacy PIC IRQ0 does not reach. */
.global isr64
isr64: pushq $0; pushq $0x40; jmp isr_common_stub64

/* TLB-shootdown IPI (vector 0xFB): a remote CPU changed a shared mapping and is
 * asking this CPU to flush its TLB. */
.global isr251
isr251: pushq $0; pushq $0xFB; jmp isr_common_stub64

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

/* ---- SYSCALL/SYSRET fast path -- STAGED, NOT ENABLED ----------------------
 *
 * UNREACHABLE BY DESIGN. init_syscall_instruction_path() (src/kernel/crypto.c)
 * programs STAR/LSTAR/SFMASK, but nothing ever sets EFER.SCE (bit 0) -- the boot
 * paths set only LME|NXE (src/boot/multiboot.S, src/boot/ap_trampoline.S). With
 * SCE clear the SYSCALL instruction raises #UD, so ring 3 reaches the kernel
 * exclusively through `int $0x80` -> isr128 -> isr_common_stub64. The live
 * syscall path is the ISR one; this is staging for a future fast path.
 *
 * DO NOT set EFER.SCE without first fixing the following. Each is live here:
 *
 *   1. Per-CPU kernel stack. `current_kernel_stack_top` is a single global that
 *      the SMP scheduler updates only for CPU 0 (`if (cpu == 0) ...` in
 *      sched_yield_switch / ipc_block_switch / preempt_on_tick). An AP entering
 *      here would load CPU 0's kernel stack and two cores would execute on one
 *      stack -- the same cross-CPU corruption the claim invariant in
 *      scheduler.c exists to prevent, arriving by a path it does not watch.
 *      Needs the RSP0-equivalent to become per-CPU first.
 *
 *   2. %rcx / %r11. SYSCALL puts the return RIP in %rcx and RFLAGS in %r11, and
 *      SYSRET restores them from there. This stub saves %rcx but never preserves
 *      %r11 across the C call, so RFLAGS returns to ring 3 as whatever the
 *      compiler left in a caller-saved register.
 *
 *   3. Non-canonical %rcx. SYSRET #GPs in ring 0 if %rcx is non-canonical, which
 *      ring 3 controls. Needs the canonical check (or IRET fallback) every
 *      x86-64 kernel carries here.
 *
 * The `swapgs` pair below is symmetric but currently inert: this kernel keeps no
 * per-CPU GS base (this_cpu() derives the CPU id from TR via `str` -- see the
 * note on this_cpu() in scheduler.c), so both GS bases are 0 and the swap is a
 * no-op. It is kept balanced rather than deleted so that whoever does introduce
 * a GS base inherits a correct entry/exit pair instead of a one-sided swap that
 * hands the kernel's per-CPU pointer to ring 3 on the first syscall. Note the
 * ordering on exit: the swap must come AFTER any load of a user selector into
 * %gs (loading a selector zeroes the GS base in long mode) and immediately
 * before SYSRET. */
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

    swapgs

    sysretq

.section .bss
.align 16
syscall_entry_kstack_bottom:
    .space 4096
syscall_entry_kstack_top: