ENTRY(_start)

/* The kernel runs at -2 GiB. This is not a free choice: CFLAGS use
 * -mcmodel=kernel, which lets GCC materialise symbol addresses as 32-bit
 * *sign-extended* immediates (R_X86_64_32S), valid only in [-2 GiB, +2 GiB).
 * 0xFFFFFFFF80000000 is the top half of that range. (The old 1 MiB link
 * address satisfied -mcmodel=kernel only by accident: the signed-32 range is
 * symmetric about zero, so the *low* 2 GiB also fits. The flag's contract was
 * being violated while its implementation tolerated it.) A "canonical
 * higher-half" base like 0xFFFF800000000000 would blow every R_X86_64_32S and
 * force -mcmodel=large.
 *
 * 0xFFFFFFFF80000000 decodes to PML4[511], PDPT[510] — the same high_pdpt that
 * multiboot.S already builds for the PHYS_KVA window at PDPT[2]. So the kernel
 * mapping is one more entry in a table that already exists, aliasing the same
 * `pd`. See src/boot/multiboot.S.
 *
 * Physical placement is unchanged: the kernel still LOADS at 1 MiB. Each high
 * section carries AT(vma - KERNEL_VMA), so p_paddr stays low while p_vaddr is
 * high. GRUB honours p_paddr (verified).
 *
 * A linker script cannot #include a header, so this value is duplicated in
 * src/include/kernel_vma.h (which the C and the boot assembly share). The two
 * are cross-checked rather than trusted: __kernel_vma_from_linker below is
 * exported for kernel_main to compare against the C-side KERNEL_VMA at boot. */
KERNEL_VMA = 0xFFFFFFFF80000000;

SECTIONS
{
    /* Exported so the C side can prove the two definitions agree. */
    __kernel_vma_from_linker = KERNEL_VMA;

    /* ---- Low boot stage: VA == PA ------------------------------------------
     * GRUB enters _start in 32-bit protected mode with paging off, so e_entry
     * must be a low physical address and every symbol this stage names must be
     * encodable in 32 bits. That is why .boot is linked flat at 1 MiB rather
     * than at KERNEL_VMA + 1 MiB: `movl $sym, %edi` cannot hold a high address.
     * Keep this section minimal — it is the only code that runs un-relocated. */
    . = 0x100000;
    _boot_lma_start = .;
    .boot : ALIGN(4K)
    {
        *(.multiboot)
        *(.boot)
        *(.boot.*)
    }
    _boot_lma_end = .;

    /* ---- Everything else: linked high, loaded low --------------------------- */
    . += KERNEL_VMA;

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VMA)
    {
        *(.text)
        *(.text.*)
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VMA)
    {
        *(.rodata)
        *(.rodata.*)
        /* Placed explicitly: these were orphan sections, and orphan placement
         * puts them wherever the linker likes — which, with two address views
         * in play, is not necessarily the view we want them in. */
        *(.eh_frame)
        *(.eh_frame.*)
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VMA)
    {
        *(.data)
        *(.data.*)
        *(.got)
        *(.got.plt)
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VMA)
    {
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /DISCARD/ : { *(.comment) *(.note.*) }
}
