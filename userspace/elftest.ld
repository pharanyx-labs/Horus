/*
 * Linker script for the ELF-loader W^X self-test program (userspace/elftest.c).
 *
 * Forces three page-aligned PT_LOAD segments with distinct permission flags so
 * the kernel self-test can inspect each page's PTE and confirm try_elf_load
 * honours p_flags:
 *
 *   .text   @ 0x400000  FLAGS(5) = R+X
 *   .data   @ 0x401000  FLAGS(6) = R+W
 *   .rodata @ 0x402000  FLAGS(4) = R
 *
 * (FLAGS bits: 1=X, 2=W, 4=R — i.e. ELF PF_X/PF_W/PF_R.)
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);   /* R + X */
    data   PT_LOAD FLAGS(6);   /* R + W */
    rodata PT_LOAD FLAGS(4);   /* R     */
}

SECTIONS
{
    . = 0x400000;
    .text   : { *(.text) *(.text.*) } :text

    . = ALIGN(0x1000);
    .data   : { *(.data) *(.data.*) } :data

    . = ALIGN(0x1000);
    .rodata : { *(.rodata) *(.rodata.*) } :rodata

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame.*)
        *(.note) *(.note.*)
        *(.comment)
        *(.bss) *(.bss.*)
    }
}
