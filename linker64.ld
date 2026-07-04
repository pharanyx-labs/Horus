ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    .text : ALIGN(4K)
    {
        *(.multiboot)
        *(.text)
        *(.text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
    }

    .data : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
    }

    .bss : ALIGN(4K)
    {
        /* Floor of the kernel's writable globals. The kernel is linked low and
         * its BSS extends above USER_AREA_BASE, so user image ASLR must never
         * place a premap window at or above this address, or a task's page tables
         * would shadow tasks[]/scheduler state (see choose_image_placement). */
        PROVIDE(kernel_bss_floor = .);
        *(COMMON)
        *(.bss)
        *(.bss.*)
    }

    /DISCARD/ : { *(.comment) *(.note.*) }
}