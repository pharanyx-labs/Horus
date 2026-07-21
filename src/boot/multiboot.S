#include "kernel_vma.h"   /* KERNEL_VMA — shared with the C side */

.section .multiboot, "a"
.align 8

multiboot_header_start:
    .long 0xe85250d6
    .long 0
    .long multiboot_header_end - multiboot_header_start
    .long -(0xe85250d6 + 0 + (multiboot_header_end - multiboot_header_start))
    .word 0
    .word 0
    .long 8
multiboot_header_end:

/* ---- Low boot stage (.boot: VA == PA at 1 MiB) ------------------------------
 *
 * The kernel is linked at KERNEL_VMA (-2 GiB) but LOADS at 1 MiB. GRUB enters
 * here in 32-bit protected mode with paging off, so this stage runs at its
 * physical address and cannot name a high symbol: `movl $sym, %edi` has a
 * 32-bit immediate. Every kernel symbol referenced here is therefore written
 * `sym - KERNEL_VMA`, which the linker folds to the low physical address.
 *
 * Nothing here may assume the high mapping exists — it does not, until CR0.PG
 * is set below. */
.section .boot, "ax"
.code32
.global _start
.extern kernel_main

_start:
    /* GRUB hands us the multiboot2 magic in eax and a pointer to the boot
     * information structure in ebx. Save both NOW, before ebx is reused as a
     * scratch counter below and before paging is on: write through each global's
     * physical address (VA - KERNEL_VMA), which is where it is loaded while we
     * still run identity-mapped. kernel_main reads them (via PHYS_KVA) to parse
     * the E820 memory map and size the physical allocator from real RAM. */
    movl %eax, (saved_mb_magic - KERNEL_VMA)
    movl %ebx, (saved_mb_info  - KERNEL_VMA)

    movl $boot_stack_top, %esp     /* low scratch stack; the real one is high */

    movl %cr4, %eax
    orl  $(1 << 5), %eax
    movl %eax, %cr4

    movl $(pml4 - KERNEL_VMA), %edi
    movl %edi, %cr3

    /* Zero the four boot page tables: [boot_tables_start, boot_tables_end).
     * stosl stores a DWORD per iteration, so ecx is a dword count, not a byte
     * count — this read $12288 (a byte count for three tables), which both
     * zeroed 48 KiB instead of 16 KiB, scribbling 32 KiB past the tables into
     * per_task_kstacks, and would have missed high_pdpt had it been right. */
    xorl %eax, %eax
    movl $(boot_tables_start - KERNEL_VMA), %edi
    movl $(boot_tables_end - boot_tables_start) / 4, %ecx
    rep stosl

    /* pml4[0] -> pdpt: the low identity map, needed while this boot stage runs
     * with VA == PA. paging_init later replaces pdpt[0] with a directory that
     * maps ONE page — 0x8000, read-only + executable — because the AP trampoline
     * far-jumps there *after* enabling paging on this CR3. Nothing else survives:
     * VGA and the LAPIC are reached through PHYS_KVA and pdpt[3] respectively,
     * not through this map. pml4[0] itself stays (the LAPIC hangs off it). */
    movl $(pdpt - KERNEL_VMA), %eax
    orl  $0x3, %eax
    movl %eax, pml4 - KERNEL_VMA

    movl $(pd - KERNEL_VMA), %eax
    orl  $0x3, %eax
    movl %eax, pdpt - KERNEL_VMA

    /* pd[k] = k*2MiB | P|W|PS -> identity-map physical [0, 1 GiB). One `pd` is
     * aliased by all three of the entries below; a write here is visible
     * through every view. That aliasing is why the kernel's own .text was
     * writable and its .bss executable — tightening any view tightened all
     * three, so none could be. paging_init (kernel_remap_init) gives each of the
     * three consumers a directory of its own and retires this one; `pd` is only
     * the bootstrap view now, live between here and the end of paging_init. */
    movl $(pd - KERNEL_VMA), %edi
    movl $0x00000000, %ebx
    movl $512, %ecx

1:
    movl %ebx, %eax
    andl $0xFFE00000, %eax
    orl  $0x00000083, %eax
    movl $0x00000000, %edx
    movl %eax, 0(%edi)
    movl %edx, 4(%edi)
    addl $0x200000, %ebx
    addl $8, %edi
    loop 1b

    movl $(high_pdpt - KERNEL_VMA), %eax
    orl  $0x3, %eax
    movl %eax, pml4 - KERNEL_VMA + (511 * 8)

    /* high_pdpt[2] -> pd: the PHYS_KVA window at 0xFFFFFF8080000000, i.e.
     * physical [0, 1 GiB) readable from every address space. */
    movl $(pd - KERNEL_VMA), %eax
    orl  $0x3, %eax
    movl %eax, high_pdpt - KERNEL_VMA + (2 * 8)

    /* high_pdpt[510] -> pd: THE KERNEL'S OWN MAPPING. 0xFFFFFFFF80000000 is
     * PML4[511], PDPT[510], so the kernel image at physical 1 MiB appears at
     * 0xFFFFFFFF80100000 — the address it is linked for. This one entry is what
     * moves the kernel to the higher half. */
    movl $(pd - KERNEL_VMA), %eax
    orl  $0x3, %eax
    movl %eax, high_pdpt - KERNEL_VMA + (510 * 8)

    movl $0xC0000080, %ecx
    rdmsr
    orl  $((1 << 8) | (1 << 11)), %eax   /* EFER.LME | EFER.NXE (honor NX bit) */
    wrmsr

    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0                      /* paging on: both views now live */

    /* The far jump below is absolute and executes with paging enabled, so its
     * target must be mapped at the address encoded in the instruction — a
     * 32-bit one. It therefore cannot go straight to the high kernel; it lands
     * in the low stub, which then escapes via a 64-bit register.
     *
     * boot_gdt is a minimal GDT living down here for the same reason: `lgdt` in
     * 32-bit mode loads a 32-bit base, and the real GDT is high. The real one is
     * loaded on the far side of the jump. */
    lgdt boot_gdt_ptr32
    ljmp $0x08, $long_mode_low

.code64
long_mode_low:
    /* 64-bit now, but still executing through the low identity map. Escape to
     * the kernel's linked addresses: movabs takes a full 64-bit immediate, and
     * the high mapping went live with CR0.PG above. Everything after this runs
     * at KERNEL_VMA + phys. */
    movabs $long_mode_entry, %rax
    jmp *%rax

.section .text
.code64
long_mode_entry:
    lgdt (gdt64_ptr)                     /* the real GDT, at its high address */

    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movabs $stack_top, %rsp

    movq %cr4, %rax
    orq  $(1 << 9), %rax
    movq %rax, %cr4

    movq %cr0, %rax
    andq $~(1 << 2), %rax
    orq  $(1 << 1), %rax
    movq %rax, %cr0

    fninit

    /* Load a valid 64-bit TSS so ring3->ring0 transitions (int $0x80,
     * faults via IST) can fetch RSP0/IST stacks. Without this the first
     * userspace syscall triple-faults. */
    call setup_tss64

    cli
    call kernel_main

    cli
    hlt

/* Build the 64-bit TSS descriptor in the GDT (selector 0x38), populate the
 * TSS RSP0 + IST stack pointers, and load it with ltr. */
.code64
.global setup_tss64
setup_tss64:
    /* IST1/2/3 stack tops (used by #DF/#GP/#PF/#SS/NMI gates). */
    lea ist1_stack_top(%rip), %rax
    movq %rax, tss64 + 36
    lea ist2_stack_top(%rip), %rax
    movq %rax, tss64 + 44
    lea ist3_stack_top(%rip), %rax
    movq %rax, tss64 + 52

    /* Initial RSP0 (overwritten per-task by set_tss_kernel_stack later). */
    lea stack_top(%rip), %rax
    movq %rax, tss64 + 4

    /* Encode the 16-byte TSS descriptor at gdt64 offset 56 (selector 0x38). */
    lea gdt64_start(%rip), %rdi
    lea tss64(%rip), %rax
    movw $103, 56(%rdi)        /* limit[15:0] = sizeof(TSS)-1 */
    movw %ax, 58(%rdi)         /* base[15:0] */
    movb $0x89, 61(%rdi)       /* access: present, type=9 (avail 64-bit TSS) */
    movb $0x00, 62(%rdi)       /* limit[19:16]=0, flags=0 */
    shrq $16, %rax
    movb %al, 60(%rdi)         /* base[23:16] */
    movb %ah, 63(%rdi)         /* base[31:24] */
    shrq $16, %rax
    movl %eax, 64(%rdi)        /* base[63:32] */
    movl $0, 68(%rdi)          /* reserved */

    movw $0x38, %ax
    ltr %ax
    ret

.section .text
.code64
.global setup_full_early_64bit_env
setup_full_early_64bit_env:

    lea ist1_stack_top(%rip), %rax
    movq %rax, tss64 + 36
    lea ist2_stack_top(%rip), %rax
    movq %rax, tss64 + 44
    lea ist3_stack_top(%rip), %rax
    movq %rax, tss64 + 52

    lea gdt64_start(%rip), %rdi
    lea tss64(%rip), %rax
    movw %ax, 24(%rdi)
    shrq $16, %rax
    movb %al, 28(%rdi)
    movb %ah, 29(%rdi)
    shrq $32, %rax
    movl %eax, 32(%rdi)
    movw $103, 26(%rdi)
    movb $0x89, 30(%rdi)
    movb $0x00, 31(%rdi)

    movw $0x18, %ax
    ltr %ax

    lea early_idt64_table(%rip), %rdi
    lea early_page_fault64(%rip), %rax
    lea early_generic_halt64(%rip), %rbx

    mov $0, %rcx
1:
    cmp $32, %rcx
    jge 2f

    movq %rbx, %rdx
    movb $1, %r8b

    cmp $14, %rcx
    jne 3f
    movq %rax, %rdx
3:
    movw %dx, 0(%rdi)
    movw $0x08, 2(%rdi)
    movb %r8b, 4(%rdi)
    movb $0x8E, 5(%rdi)
    shrq $16, %rdx
    movw %dx, 6(%rdi)
    shrq $16, %rdx
    movl %edx, 8(%rdi)
    movl $0, 12(%rdi)

    add $16, %rdi
    inc %rcx
    jmp 1b
2:
    lea early_idt64_ptr(%rip), %rax
    lidt (%rax)
    ret

.section .data
.align 16
early_idt64_table:
    .skip 32 * 16

early_idt64_ptr:
    .word (32 * 16) - 1
    .quad early_idt64_table

.global early_generic_halt64
early_generic_halt64:
    cli
    hlt
    jmp .

.section .data
/* Saved by _start from the boot registers. Read by kernel_main to locate and
 * parse the multiboot2 boot-information structure (magic 0x36d76289). */
.global saved_mb_magic
.align 4
saved_mb_magic:
    .long 0
.global saved_mb_info
saved_mb_info:
    .long 0

.section .data
.global gdt64_start
.align 16
gdt64_start:
    .quad 0x0000000000000000
    .quad 0x00209A0000000000
    .quad 0x0000920000000000
    .quad 0x0000F20000000000
    .quad 0x0020FB0000000000
    .quad 0x00CFFB000000FFFF
    .quad 0x00CFF3000000FFFF
    .quad 0x0000000000000000   /* 0x38: 64-bit TSS descriptor (low),  filled at runtime */
    .quad 0x0000000000000000   /* 0x40: 64-bit TSS descriptor (high), filled at runtime */
#ifdef SMP
    /* Per-CPU (application-processor) 64-bit TSS descriptors, filled at runtime
     * by setup_ap_tss(). Each 64-bit TSS descriptor occupies two 8-byte GDT
     * slots, so these are selectors 0x48 / 0x58 / 0x68 for CPUs 1..MAX_CPUS-1. */
    .quad 0x0000000000000000   /* 0x48: AP cpu 1 (low)  */
    .quad 0x0000000000000000   /* 0x50: AP cpu 1 (high) */
    .quad 0x0000000000000000   /* 0x58: AP cpu 2 (low)  */
    .quad 0x0000000000000000   /* 0x60: AP cpu 2 (high) */
    .quad 0x0000000000000000   /* 0x68: AP cpu 3 (low)  */
    .quad 0x0000000000000000   /* 0x70: AP cpu 3 (high) */
#endif
gdt64_end:

.global gdt64_ptr
gdt64_ptr:
    .word gdt64_end - gdt64_start - 1
    .quad gdt64_start

.global tss64
.align 16
tss64:
    .long 0, 0
    .quad 0
    .quad 0, 0, 0
    .quad 0, 0, 0, 0, 0, 0, 0
    .quad 0
    .word 0
    .word 0

/* Each IST fault stack (IST1: #DF/#GP/#PF, IST2: NMI, IST3: #SS) sits above a
 * page-aligned guard page that kern_fixed_stack_guards_init() unmaps at boot, so
 * an overflow of a fault handler's own stack faults on the guard instead of
 * silently running into the TSS or the adjacent IST stack. Page-aligned because
 * the guard is unmapped a whole 4 KiB page at a time. */
.align 4096
.global ist1_stack_guard
ist1_stack_guard:
    .space 4096
ist1_stack_bottom:
    .space 4096
ist1_stack_top:

.align 4096
.global ist2_stack_guard
ist2_stack_guard:
    .space 4096
ist2_stack_bottom:
    .space 4096
ist2_stack_top:

.align 4096
.global ist3_stack_guard
ist3_stack_guard:
    .space 4096
ist3_stack_bottom:
    .space 4096
ist3_stack_top:

/* ---- Low boot data (.boot.data: VA == PA) -----------------------------------
 * Reachable by the 32-bit stage and by the far jump. Dead after long_mode_low.
 * Separate section from the .boot code because it is writable (the stack) —
 * one section cannot be both "ax" and "aw". linker64.ld collects .boot.* here. */
.section .boot.data, "aw"
.align 16
boot_gdt:
    .quad 0x0000000000000000   /* 0x00 null                                    */
    .quad 0x00209A0000000000   /* 0x08 kernel code, L=1 — the ljmp target      */
    .quad 0x0000920000000000   /* 0x10 kernel data                             */
boot_gdt_end:

/* 32-bit GDT pointer: `lgdt` in 32-bit mode takes a 32-bit base, so it can only
 * name a GDT down here. Selectors 0x08/0x10 are byte-identical to the real
 * GDT's, so CS/DS stay valid across the switch to it in long_mode_entry. */
boot_gdt_ptr32:
    .word boot_gdt_end - boot_gdt - 1
    .long boot_gdt

.align 16
boot_stack_bottom:
    .space 4096
boot_stack_top:

.section .bss
/* Keep the very first .bss page present. __bss_start lands here, and the W^X
 * per-section spot check reads it expecting a present rw- page; the BSP stack's
 * guard below is unmapped, so it must not be the first .bss page. (rust
 * contributes no .bss, so multiboot's is first in the image.) */
.align 16
bss_head_anchor:
    .space 16

/* The BSP's kernel stack (RSP0 for the boot CPU, and the stack kernel_main and
 * all early init run on). It sits above a page-aligned guard page unmapped by
 * kern_fixed_stack_guards_init() at boot; the stack is 16 KiB and boot-time use
 * stays near the top, so unmapping the guard far below the live rsp is safe. An
 * overflow now faults on the guard instead of running into whatever .bss
 * precedes it. */
.align 4096
.global bsp_stack_guard
bsp_stack_guard:
    .space 4096
stack_bottom:
    .space 16384
.global stack_top
stack_top:

    .align 16
early_handler_stack_bottom:
    .space 4096
.global early_handler_stack_top
early_handler_stack_top:

/* The four boot page tables. _start zeroes exactly [boot_tables_start,
 * boot_tables_end) before filling them, so they must stay contiguous and this
 * block must hold nothing else. high_pdpt is part of the range: it is aliased
 * into pml4[511] and MUST be zeroed, or its unwritten entries are garbage. */
.align 4096
.global boot_tables_start
boot_tables_start:
.global pml4
pml4:
    .space 4096
pdpt:
    .space 4096
/* Exported for kernel_remap_init (paging.c), which reads `pd` to inherit the
 * 2 MiB mappings above the kernel image and rewrites high_pdpt[510] to point at
 * a private page directory instead of this shared one. */
.global pd
pd:
    .space 4096
.global high_pdpt
high_pdpt:
    .space 4096
.global boot_tables_end
boot_tables_end:

.section .rodata
#ifdef SMP
/* Real-mode AP startup trampoline (src/boot/ap_trampoline.S), linked flat at
 * 0x8000 and copied there by smp_start_aps before the broadcast SIPI. Only
 * embedded in the SMP build. */
.align 16
.global ap_trampoline_start
ap_trampoline_start:
.incbin "src/boot/ap_trampoline.bin"
.global ap_trampoline_end
ap_trampoline_end:
#endif

.align 16
.global embedded_shell_bin_start
embedded_shell_bin_start:
.incbin "userspace/shell.bin"
.global embedded_shell_bin_end
embedded_shell_bin_end:

/* init: the ring-3 PID-1 process the kernel launches first; it spawns and
 * supervises the shell. Always embedded (it is the boot userspace entry). */
.align 16
.global embedded_init_bin_start
embedded_init_bin_start:
.incbin "userspace/init.bin"
.global embedded_init_bin_end
embedded_init_bin_end:

/* hello and captest are always embedded so 'spawn hello'/'spawn captest' work
 * without a serial-port upload. */
.align 16
.global embedded_hello_bin_start
embedded_hello_bin_start:
.incbin "userspace/hello.bin"
.global embedded_hello_bin_end
embedded_hello_bin_end:

.align 16
.global embedded_captest_bin_start
embedded_captest_bin_start:
.incbin "userspace/captest.bin"
.global embedded_captest_bin_end
embedded_captest_bin_end:

/* fs_server is also always embedded.  The FS_SELFTEST build embeds it under the
 * same symbol names in the block below; this guard prevents duplicate definitions. */
#ifndef FS_SELFTEST
.align 16
.global embedded_fsserver_bin_start
embedded_fsserver_bin_start:
.incbin "userspace/fs_server.bin"
.global embedded_fsserver_bin_end
embedded_fsserver_bin_end:
#endif

#if defined(ELF_SELFTEST)
/* Real multi-segment ELF used by the in-kernel ELF-loader self-test
 * (elf_loader_selftest). ELF_SELFTEST build only. */
.align 16
.global embedded_elftest_start
embedded_elftest_start:
.incbin "userspace/elftest.elf"
.global embedded_elftest_end
embedded_elftest_end:
#endif

#if defined(ELF64_SELFTEST) || defined(ASLR_SELFTEST)
/* The same image linked as a 64-bit static-PIE. Used by the ELF64 loader
 * self-test to exercise the x86-64 RELA path, and by the image-base ASLR test,
 * which needs a 64-bit image because only those take the high ASLR window. */
.align 16
.global embedded_elftest64_start
embedded_elftest64_start:
.incbin "userspace/elftest64.elf"
.global embedded_elftest64_end
embedded_elftest64_end:
#endif

#if defined(PREEMPT_SELFTEST) || defined(SMP_SELFTEST) || defined(PROC_SELFTEST)
/* Flat userspace tracer used by the preemptive-scheduling self-test
 * (preempt_selftest), reused as the worker payload by the SMP self-test
 * (smp_selftest) and as the "looper" kill target by the process-control
 * self-test (proc_selftest). Only embedded in those gated builds. */
.align 16
.global embedded_preempttest_bin_start
embedded_preempttest_bin_start:
.incbin "userspace/preempttest.bin"
.global embedded_preempttest_bin_end
embedded_preempttest_bin_end:
#endif

#ifdef PROC_SELFTEST
/* Flat userspace driver for the process-control self-test (proc_selftest):
 * spawns children and exercises SYS_EXIT / SYS_KILL. Only in PROC_SELFTEST. */
.align 16
.global embedded_proctest_bin_start
embedded_proctest_bin_start:
.incbin "userspace/proctest.bin"
.global embedded_proctest_bin_end
embedded_proctest_bin_end:

/* exectest: a child the proctest driver spawns to exercise SYS_EXEC_NAMED — it
 * execs itself into "hello" in place. Only in PROC_SELFTEST. */
.align 16
.global embedded_exectest_bin_start
embedded_exectest_bin_start:
.incbin "userspace/exectest.bin"
.global embedded_exectest_bin_end
embedded_exectest_bin_end:

/* grantee: a child the proctest driver spawns to exercise SYS_CAP_GRANT — it
 * uses a delegated CAP_AUDIT and checks that unauthorised grants fail. Only in
 * PROC_SELFTEST. */
.align 16
.global embedded_grantee_bin_start
embedded_grantee_bin_start:
.incbin "userspace/grantee.bin"
.global embedded_grantee_bin_end
embedded_grantee_bin_end:

/* sigtarget: a child the proctest driver signals to exercise SYS_SIGNAL — it
 * registers a handler that fires on delivery. Only in PROC_SELFTEST. */
.align 16
.global embedded_sigtarget_bin_start
embedded_sigtarget_bin_start:
.incbin "userspace/sigtarget.bin"
.global embedded_sigtarget_bin_end
embedded_sigtarget_bin_end:

/* faulter: a child that takes an unhandled #UD fault, to exercise the fault-kill
 * wake path (SYS_WAIT waiter woken on a *fault* death). Only in PROC_SELFTEST. */
.align 16
.global embedded_faulter_bin_start
embedded_faulter_bin_start:
.incbin "userspace/faulter.bin"
.global embedded_faulter_bin_end
embedded_faulter_bin_end:

/* sigwaiter: blocks in SYS_WAIT on an immortal target, to exercise async signal
 * delivery interrupting a blocked wait. Only in PROC_SELFTEST. */
.align 16
.global embedded_sigwaiter_bin_start
embedded_sigwaiter_bin_start:
.incbin "userspace/sigwaiter.bin"
.global embedded_sigwaiter_bin_end
embedded_sigwaiter_bin_end:

/* argtest: spawned with a known argument vector to exercise full argv passing;
 * reads its args back and checks them. Only in PROC_SELFTEST. */
.align 16
.global embedded_argtest_bin_start
embedded_argtest_bin_start:
.incbin "userspace/argtest.bin"
.global embedded_argtest_bin_end
embedded_argtest_bin_end:
#endif

#ifdef SIGNAL_SELFTEST
/* Flat userspace payload for the signal-handling self-test (signal_selftest):
 * registers a fault handler, then faults on purpose. Only in SIGNAL_SELFTEST. */
.align 16
.global embedded_sigtest_bin_start
embedded_sigtest_bin_start:
.incbin "userspace/sigtest.bin"
.global embedded_sigtest_bin_end
embedded_sigtest_bin_end:
#endif

#ifdef TSD_SELFTEST
/* Flat userspace payload for the RDTSC/TSD self-test (tsd_selftest): registers a
 * fault handler, then executes RDTSC, which #GPs under CR4.TSD. Only in
 * TSD_SELFTEST. */
.align 16
.global embedded_tsdtest_bin_start
embedded_tsdtest_bin_start:
.incbin "userspace/tsdtest.bin"
.global embedded_tsdtest_bin_end
embedded_tsdtest_bin_end:
#endif

#ifdef NEWLIB_SELFTEST
/* PIE hello_newlib binary: newlib printf/malloc/string smoke test. */
.align 16
.global embedded_hello_newlib_bin_start
embedded_hello_newlib_bin_start:
.incbin "userspace/hello_newlib.bin"
.global embedded_hello_newlib_bin_end
embedded_hello_newlib_bin_end:
#endif

/* The vendored GNU coreutils utilities are no longer embedded in the kernel
 * image. They are shipped as GRUB multiboot2 modules (grub.cfg `module2` lines),
 * which GRUB loads into RAM outside the image, so they cost nothing against the
 * 16 MiB budget and all of them fit at once. The fs_server provisions each module
 * into /bin at boot, and the shell runs them from there. See the boot.iso rule in
 * the Makefile and provision_boot_modules() in userspace/fs_server.c. */


#ifdef NOTIFY_SELFTEST
/* PIE notifytest binary: spawned twice (waiter + sender) to exercise the
 * async SYS_NOTIFY / SYS_WAIT_NOTIFY badge round-trip. */
.align 16
.global embedded_notifytest_bin_start
embedded_notifytest_bin_start:
.incbin "userspace/notifytest.bin"
.global embedded_notifytest_bin_end
embedded_notifytest_bin_end:
#endif

#ifdef MAPPHYS_SELFTEST
/* PIE mapphystest binary: endowed with CAP_IO_DEVICE, it maps the allowlisted
 * VGA framebuffer via SYS_MAP_PHYS and round-trips a cell through the mapping. */
.align 16
.global embedded_mapphystest_bin_start
embedded_mapphystest_bin_start:
.incbin "userspace/mapphystest.bin"
.global embedded_mapphystest_bin_end
embedded_mapphystest_bin_end:
#endif

#ifdef COW_SELFTEST
/* PIE cowtest binary: reads two fresh heap pages (shared zero page) then writes
 * one, proving copy-on-write hands out a private page without disturbing the
 * sibling. */
.align 16
.global embedded_cowtest_bin_start
embedded_cowtest_bin_start:
.incbin "userspace/cowtest.bin"
.global embedded_cowtest_bin_end
embedded_cowtest_bin_end:
#endif

#ifdef FS_SELFTEST
/* PIE userspace fs_server + a client that drives it over IPC, used by the
 * filesystem self-test (fs_selftest). Only embedded in the FS_SELFTEST build. */
.align 16
.global embedded_fsserver_bin_start
embedded_fsserver_bin_start:
.incbin "userspace/fs_server.bin"
.global embedded_fsserver_bin_end
embedded_fsserver_bin_end:
.align 16
.global embedded_fsclient_bin_start
embedded_fsclient_bin_start:
.incbin "userspace/fsclient.bin"
.global embedded_fsclient_bin_end
embedded_fsclient_bin_end:
#endif

#if defined(INIT_FS_SELFTEST) && !defined(FS_SELFTEST)
/* fsclient for the init-delegated FS integration test (INIT_FS_SELFTEST). The
 * fs_server is already embedded above (the #ifndef FS_SELFTEST block); only the
 * client needs adding here. */
.align 16
.global embedded_fsclient_bin_start
embedded_fsclient_bin_start:
.incbin "userspace/fsclient.bin"
.global embedded_fsclient_bin_end
embedded_fsclient_bin_end:
#endif