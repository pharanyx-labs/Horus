/*
 * Static-PIE (ET_DYN) linker script for the ELF-loader self-test image.
 *
 * Three page-aligned PT_LOAD segments with distinct permission flags, linked at
 * base 0 so the kernel loads it at a randomized base and applies relocations:
 *
 *   .text   FLAGS(5) = R + X
 *   .rodata FLAGS(4) = R
 *   .data   FLAGS(6) = R + W
 *
 * The marker sections are pinned to the START of their segment so the kernel
 * self-test can find them at (base + segment vaddr):
 *   .rodata.marker -> first byte of .rodata  (0x5A)
 *   .data.selfptr  -> first word of .data     (&rodata_marker, relocated)
 *   .data.marker   -> next byte of .data      (0xD2)
 * (FLAGS bits: 1=X, 2=W, 4=R = ELF PF_X/PF_W/PF_R.)
 */
ENTRY(_start)

PHDRS
{
    text   PT_LOAD    FLAGS(5);   /* R + X */
    rodata PT_LOAD    FLAGS(4);   /* R     */
    data   PT_LOAD    FLAGS(6);   /* R + W */
    dyn    PT_DYNAMIC FLAGS(4);
}

SECTIONS
{
    . = 0;
    .text : { *(.text) *(.text.*) } :text

    . = ALIGN(0x1000);
    .rodata  : { KEEP(*(.rodata.marker)) *(.rodata) *(.rodata.*) } :rodata
    .dynamic : { *(.dynamic) }             :rodata :dyn
    /* Both reloc-table spellings: i386 emits REL (.rel.dyn), x86-64 emits RELA
     * (.rela.dyn). This one script links the image for both (see the elftest.elf
     * and elftest64.elf rules in the Makefile), and the names do not overlap --
     * the glob `.rel.*` does NOT match `.rela.dyn` ("rela" is not "rel" + "."),
     * so an unlisted .rela.dyn would be orphan-placed outside every PT_LOAD and
     * the loader could not map its vaddr to a file offset. */
    .rel.dyn  : { *(.rel.dyn) *(.rel.*) }    :rodata
    .rela.dyn : { *(.rela.dyn) *(.rela.*) }  :rodata
    .dynsym  : { *(.dynsym) }              :rodata
    .dynstr  : { *(.dynstr) }              :rodata
    .hash    : { *(.hash) *(.gnu.hash) }   :rodata

    . = ALIGN(0x1000);
    .data : { KEEP(*(.data.selfptr)) KEEP(*(.data.marker)) *(.data) *(.data.*) } :data
    .got  : { *(.got) *(.got.plt) }        :data
    .bss  : { *(.bss) *(.bss.*) *(COMMON) } :data

    /DISCARD/ : {
        *(.eh_frame) *(.eh_frame.*)
        *(.note) *(.note.*)
        *(.comment) *(.gnu.version*) *(.interp)
    }
}
